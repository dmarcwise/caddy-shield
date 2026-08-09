package shield

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"reflect"
	"testing"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
	"go4.org/netipx"
)

func TestServeHTTPDecisionMatrix(t *testing.T) {
	tests := []struct {
		name       string
		clientIP   string
		allow      []string
		deny       []string
		feed       []string
		ready      bool
		failOpen   bool
		wantNext   bool
		wantStatus int
		wantMetric decisionMetric
	}{
		{name: "static deny", clientIP: "192.0.2.1", deny: []string{"192.0.2.0/24"}, ready: true, failOpen: true, wantStatus: 403, wantMetric: decisionBlockStaticDeny},
		{name: "feed deny", clientIP: "192.0.2.1", feed: []string{"192.0.2.0/24"}, ready: true, failOpen: true, wantStatus: 403, wantMetric: decisionBlockSource},
		{name: "allow overrides all denies", clientIP: "192.0.2.1", allow: []string{"192.0.2.1"}, deny: []string{"192.0.2.0/24"}, feed: []string{"192.0.2.0/24"}, ready: true, failOpen: true, wantNext: true, wantStatus: 204, wantMetric: decisionAllowAllowlist},
		{name: "miss", clientIP: "203.0.113.1", deny: []string{"192.0.2.0/24"}, ready: true, failOpen: true, wantNext: true, wantStatus: 204, wantMetric: decisionAllowNotListed},
		{name: "unavailable fail open", clientIP: "203.0.113.1", ready: false, failOpen: true, wantNext: true, wantStatus: 204, wantMetric: decisionAllowUnavailable},
		{name: "unavailable fail closed", clientIP: "203.0.113.1", ready: false, failOpen: false, wantStatus: 403, wantMetric: decisionBlockUnavailable},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newRequestTestHandler(t, tt.allow, tt.deny, tt.feed, tt.ready, tt.failOpen)
			metricBefore := prometheusCounterValue(t, h.app.metrics.decisionCounts[tt.wantMetric])
			recorder := httptest.NewRecorder()
			nextCalled := false
			err := h.ServeHTTP(recorder, requestWithClientIP(tt.clientIP), caddyhttp.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) error {
				nextCalled = true
				w.WriteHeader(http.StatusNoContent)
				return nil
			}))
			if err != nil {
				t.Fatalf("ServeHTTP() error = %v", err)
			}
			if nextCalled != tt.wantNext || recorder.Code != tt.wantStatus {
				t.Errorf("next=%t status=%d, want next=%t status=%d", nextCalled, recorder.Code, tt.wantNext, tt.wantStatus)
			}
			if !tt.wantNext && recorder.Body.String() != "Request blocked\n" {
				t.Errorf("body = %q, want default denial body", recorder.Body.String())
			}
			if got := prometheusCounterValue(t, h.app.metrics.decisionCounts[tt.wantMetric]); got != metricBefore+1 {
				t.Errorf("decision metric = %v, want %v", got, metricBefore+1)
			}
		})
	}
}

func TestBlockedResponseUsesSiteOverrides(t *testing.T) {
	globalBody := "global"
	siteBody := "blocked {shield.client_ip} via {http.request.method} ({shield.reason})"
	h := newRequestTestHandler(t, nil, []string{"192.0.2.0/24"}, nil, true, true)
	h.app.Response = Response{
		StatusCode: http.StatusForbidden,
		Headers: map[string][]string{
			"Content-Type": {"text/plain"},
			"X-Global":     {"kept"},
		},
		Body: &globalBody,
	}
	h.Response = Response{
		StatusCode: http.StatusUnavailableForLegalReasons,
		Headers: map[string][]string{
			"content-type": {"application/json"},
			"X-Blocked-IP": {"{client_ip}"},
		},
		Body: &siteBody,
	}
	h.effectiveResponse = mergeResponse(h.app.Response, h.Response)

	recorder := httptest.NewRecorder()
	err := h.ServeHTTP(recorder, requestWithClientIP("192.0.2.42"), caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error {
		t.Fatal("next handler called for blocked client")
		return nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	if recorder.Code != 451 || recorder.Header().Get("Content-Type") != "application/json" ||
		recorder.Header().Get("X-Global") != "kept" || recorder.Header().Get("X-Blocked-IP") != "192.0.2.42" ||
		recorder.Body.String() != "blocked 192.0.2.42 via GET (blocklist)" {
		t.Errorf("response = status:%d headers:%v body:%q", recorder.Code, recorder.Header(), recorder.Body.String())
	}
}

func TestFeedBlockReportsAllMatchingSources(t *testing.T) {
	h := newRequestTestHandler(t, nil, nil, nil, true, true)
	first, err := buildIPSet([]netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")})
	if err != nil {
		t.Fatal(err)
	}
	second, err := buildIPSet([]netip.Prefix{netip.MustParsePrefix("192.0.2.42/32")})
	if err != nil {
		t.Fatal(err)
	}
	var builder netipx.IPSetBuilder
	builder.AddSet(first)
	builder.AddSet(second)
	merged, err := builder.IPSet()
	if err != nil {
		t.Fatal(err)
	}
	h.app.manager.current.Store(&feedSnapshot{
		blocked: merged,
		sources: []feedSourceSnapshot{
			{name: "first", set: first},
			{name: "second", set: second},
		},
		ready: true,
	})
	h.app.metrics = newRequestTestMetrics(t, "first", "second")
	decisionBefore := prometheusCounterValue(t, h.app.metrics.decisionCounts[decisionBlockSource])
	sourceBefore := map[string]float64{
		"first":  prometheusCounterValue(t, h.app.metrics.sourceCounts["first"]),
		"second": prometheusCounterValue(t, h.app.metrics.sourceCounts["second"]),
	}
	body := "blocked by {shield.sources}"
	h.effectiveResponse.Body = &body
	core, logs := observer.New(zap.DebugLevel)
	h.logger = zap.New(core)

	recorder := httptest.NewRecorder()
	if err := h.ServeHTTP(recorder, requestWithClientIP("192.0.2.42"), caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error {
		t.Fatal("next handler called for blocked client")
		return nil
	})); err != nil {
		t.Fatal(err)
	}
	if recorder.Body.String() != "blocked by first,second" {
		t.Errorf("body = %q, want attributed sources", recorder.Body.String())
	}
	entries := logs.All()
	if len(entries) != 1 || !reflect.DeepEqual(entries[0].ContextMap()["sources"], []any{"first", "second"}) {
		t.Fatalf("block log entries = %#v, want both sources", entries)
	}
	if got := prometheusCounterValue(t, h.app.metrics.decisionCounts[decisionBlockSource]); got != decisionBefore+1 {
		t.Errorf("source decision metric = %v, want %v", got, decisionBefore+1)
	}
	for _, source := range []string{"first", "second"} {
		if got := prometheusCounterValue(t, h.app.metrics.sourceCounts[source]); got != sourceBefore[source]+1 {
			t.Errorf("source %q metric = %v, want %v", source, got, sourceBefore[source]+1)
		}
	}
}

func TestClientIPTrustBoundary(t *testing.T) {
	t.Run("Caddy resolved client IP wins", func(t *testing.T) {
		h := newRequestTestHandler(t, nil, []string{"192.0.2.1"}, nil, true, true)
		req := requestWithClientIP("192.0.2.1")
		req.RemoteAddr = "198.51.100.1:1234"
		err := h.ServeHTTP(httptest.NewRecorder(), req, caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error {
			t.Fatal("next handler called")
			return nil
		}))
		if err != nil {
			t.Fatal(err)
		}
	})

	t.Run("raw forwarded header is ignored", func(t *testing.T) {
		h := newRequestTestHandler(t, nil, []string{"192.0.2.1"}, nil, true, true)
		req := requestWithClientIP("198.51.100.1")
		req.Header.Set("X-Forwarded-For", "192.0.2.1")
		nextCalled := false
		if err := h.ServeHTTP(httptest.NewRecorder(), req, caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error {
			nextCalled = true
			return nil
		})); err != nil {
			t.Fatal(err)
		}
		if !nextCalled {
			t.Fatal("forged X-Forwarded-For affected the lookup")
		}
	})

	t.Run("socket peer fallback", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
		req.RemoteAddr = "192.0.2.10:54321"
		got, err := clientIPFromRequest(req)
		if err != nil || got != netip.MustParseAddr("192.0.2.10") {
			t.Fatalf("clientIPFromRequest() = %s, %v", got, err)
		}
	})

	t.Run("invalid resolved IP is an internal error", func(t *testing.T) {
		h := newRequestTestHandler(t, nil, nil, nil, true, true)
		err := h.ServeHTTP(httptest.NewRecorder(), requestWithClientIP("invalid"), caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error {
			t.Fatal("next handler called")
			return nil
		}))
		handlerErr, ok := err.(caddyhttp.HandlerError)
		if !ok || handlerErr.StatusCode != http.StatusInternalServerError {
			t.Fatalf("ServeHTTP() error = %#v, want HTTP 500 HandlerError", err)
		}
	})
}

func TestServeHTTPRejectsUnverifiedEarlyData(t *testing.T) {
	h := newRequestTestHandler(t, nil, []string{"192.0.2.1"}, nil, true, true)
	req := requestWithClientIP("192.0.2.1")
	req.TLS = &tls.ConnectionState{HandshakeComplete: false}

	err := h.ServeHTTP(httptest.NewRecorder(), req, caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error {
		t.Fatal("next handler called for unverified early data")
		return nil
	}))
	handlerErr, ok := err.(caddyhttp.HandlerError)
	if !ok || handlerErr.StatusCode != http.StatusTooEarly {
		t.Fatalf("ServeHTTP() error = %#v, want HTTP 425 HandlerError", err)
	}
}

func TestGlobalAppToHandlerFlow(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("192.0.2.0/24\n"))
	}))
	defer server.Close()

	app := &App{
		Sources: []Source{{Name: "test", URL: server.URL}},
		logger:  zap.NewNop(),
	}
	app.setDefaults()
	var err error
	app.static, err = newSnapshot(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	app.manager, err = newRefreshManager(context.Background(), app)
	if err != nil {
		t.Fatal(err)
	}
	if err := app.Start(); err != nil {
		t.Fatal(err)
	}
	defer app.Stop()
	waitForAddress(t, app.manager, "192.0.2.42")
	if sources := app.manager.Snapshot().matchingSources(netip.MustParseAddr("192.0.2.42")); !reflect.DeepEqual(sources, []string{"test"}) {
		t.Fatalf("matching sources = %v, want [test]", sources)
	}

	handler := &Handler{app: app}
	if err := handler.configureFromApp(app); err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	if err := handler.ServeHTTP(recorder, requestWithClientIP("192.0.2.42"), caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error {
		t.Fatal("next handler called for feed-blocked client")
		return nil
	})); err != nil {
		t.Fatal(err)
	}
	if recorder.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", recorder.Code)
	}
}

func newRequestTestHandler(t *testing.T, allow, deny, feed []string, ready, failOpen bool) *Handler {
	t.Helper()
	allowed, err := parseConfiguredPrefixes(allow)
	if err != nil {
		t.Fatal(err)
	}
	blocked, err := parseConfiguredPrefixes(deny)
	if err != nil {
		t.Fatal(err)
	}
	static, err := newSnapshot(allowed, blocked)
	if err != nil {
		t.Fatal(err)
	}
	feedPrefixes, err := parseConfiguredPrefixes(feed)
	if err != nil {
		t.Fatal(err)
	}
	feedSet, err := buildIPSet(feedPrefixes)
	if err != nil {
		t.Fatal(err)
	}
	app := &App{FailOpen: &failOpen}
	app.setDefaults()
	app.metrics = newRequestTestMetrics(t, "test")
	app.manager = new(refreshManager)
	app.manager.current.Store(&feedSnapshot{
		blocked: feedSet,
		sources: []feedSourceSnapshot{{name: "test", set: feedSet}},
		ready:   ready,
	})
	return &Handler{
		FailOpen:          &failOpen,
		app:               app,
		static:            static,
		effectiveResponse: app.Response,
		effectiveFailOpen: failOpen,
	}
}

func newRequestTestMetrics(t *testing.T, sources ...string) *shieldMetrics {
	t.Helper()
	configured := make([]Source, len(sources))
	for i, source := range sources {
		configured[i].Name = source
	}
	metrics, err := newShieldMetrics(prometheus.NewPedanticRegistry(), configured)
	if err != nil {
		t.Fatal(err)
	}
	return metrics
}

func prometheusCounterValue(t *testing.T, counter prometheus.Counter) float64 {
	t.Helper()
	metric := new(dto.Metric)
	if err := counter.Write(metric); err != nil {
		t.Fatal(err)
	}
	return metric.GetCounter().GetValue()
}

func requestWithClientIP(clientIP string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "http://example.test/resource", nil)
	ctx := context.WithValue(req.Context(), caddyhttp.VarsCtxKey, map[string]any{
		caddyhttp.ClientIPVarKey: clientIP,
	})
	req = req.WithContext(ctx)
	caddyhttp.NewTestReplacer(req)
	return req
}
