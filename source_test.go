package shield

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestSourceFetchConditional(t *testing.T) {
	var requests atomic.Int32
	conditional := make(chan [2]string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requests.Add(1) == 1 {
			w.Header().Set("ETag", `"revision-1"`)
			w.Header().Set("Last-Modified", "Wed, 21 Oct 2015 07:28:00 GMT")
			_, _ = w.Write([]byte("192.0.2.1\n198.51.100.0/24\n"))
			return
		}
		conditional <- [2]string{r.Header.Get("If-None-Match"), r.Header.Get("If-Modified-Since")}
		w.WriteHeader(http.StatusNotModified)
	}))
	defer server.Close()

	source := &sourceRuntime{name: "test", url: server.URL, interval: time.Hour}
	result, changed, err := source.fetch(context.Background(), server.Client(), 1024, 100)
	if err != nil || !changed {
		t.Fatalf("first fetch: changed=%t error=%v", changed, err)
	}
	if result.statusCode != http.StatusOK || !result.set.Contains(netip.MustParseAddr("198.51.100.42")) {
		t.Fatalf("first result = %+v", result)
	}

	result, changed, err = source.fetch(context.Background(), server.Client(), 1024, 100)
	if err != nil || changed || result.statusCode != http.StatusNotModified {
		t.Fatalf("conditional fetch: result=%+v changed=%t error=%v", result, changed, err)
	}
	if got := <-conditional; got != [2]string{`"revision-1"`, "Wed, 21 Oct 2015 07:28:00 GMT"} {
		t.Errorf("conditional headers = %q", got)
	}
}

func TestSourceFetchRejectsInvalidResponses(t *testing.T) {
	tests := []struct {
		name       string
		status     int
		body       string
		maxSize    int64
		maxEntries int
		wantError  string
	}{
		{name: "body size", body: "192.0.2.1\n", maxSize: 4, maxEntries: 100, wantError: "exceeds maximum"},
		{name: "entry count", body: "192.0.2.1\n192.0.2.2\n", maxSize: 1024, maxEntries: 1, wantError: "maximum of 1 entries"},
		{name: "no valid entries", body: "not-an-ip\n", maxSize: 1024, maxEntries: 100, wantError: "no valid entries"},
		{name: "HTTP status", status: http.StatusServiceUnavailable, body: "unavailable", maxSize: 1024, maxEntries: 100, wantError: "503"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if tt.status != 0 {
					w.WriteHeader(tt.status)
				}
				_, _ = w.Write([]byte(tt.body))
			}))
			defer server.Close()

			source := &sourceRuntime{name: tt.name, url: server.URL}
			_, _, err := source.fetch(context.Background(), server.Client(), tt.maxSize, tt.maxEntries)
			if err == nil || !strings.Contains(err.Error(), tt.wantError) {
				t.Fatalf("fetch error = %v, want %q", err, tt.wantError)
			}
		})
	}
}
