package shield

import (
	"encoding/json"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
)

func TestCaddyfileAdaptAndValidate(t *testing.T) {
	input := `{
		shield {
			source ipsum_3
			source custom {
				url https://example.test/list.txt
				refresh_interval 30m
			}
			refresh_interval 6h
			timeout 20s
			max_size 16MB
			max_entries 500000
			allow 203.0.113.10
			deny 198.51.100.0/24
			fail_open false
			response {
				status 451
				header Content-Type application/json
				body "{\"blocked\":true}"
			}
		}
	}
	example.test {
		shield {
			allow 192.0.2.42
			deny 192.0.2.0/24
			response {
				header X-Site custom
			}
		}
		respond "ok"
	}`

	adapted, err := adaptAndValidate(input)
	if err != nil {
		t.Fatalf("adapt and validate: %v", err)
	}
	var config struct {
		Apps map[string]json.RawMessage `json:"apps"`
	}
	if err := json.Unmarshal(adapted, &config); err != nil {
		t.Fatal(err)
	}
	var app App
	if err := json.Unmarshal(config.Apps["shield"], &app); err != nil {
		t.Fatal(err)
	}
	if len(app.Sources) != 2 || app.Sources[0].Name != "ipsum_3" ||
		app.Sources[1].URL != "https://example.test/list.txt" ||
		time.Duration(app.Sources[1].RefreshInterval) != 30*time.Minute {
		t.Errorf("adapted sources = %+v", app.Sources)
	}
	if app.MaxSize != 16_000_000 || app.MaxEntries != 500_000 || app.FailOpen == nil || *app.FailOpen {
		t.Errorf("adapted global options = %+v", app)
	}
	httpJSON := string(config.Apps["http"])
	for _, want := range []string{`"handler":"shield"`, `"allow":["192.0.2.42"]`, `"X-Site":["custom"]`} {
		if !strings.Contains(httpJSON, want) {
			t.Errorf("adapted HTTP config missing %s:\n%s", want, httpJSON)
		}
	}
}

func TestCaddyfileInvalidConfigurations(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{name: "missing global app", input: `example.test { shield }`},
		{name: "site source", input: `{
			shield { deny 192.0.2.1 }
		}
		example.test {
			shield { source ipsum_3 }
		}`},
		{name: "unknown preset", input: `{
			shield { source missing }
		}`},
		{name: "preset URL override", input: `{
			shield {
				source ipsum_3 { url https://example.test/mirror }
			}
		}`},
		{name: "non HTTP URL", input: `{
			shield {
				source custom { url file:///tmp/list }
			}
		}`},
		{name: "duplicate source", input: `{
			shield {
				source ipsum_3
				source ipsum_3
			}
		}`},
		{name: "invalid prefix", input: `{
			shield { deny not-an-ip }
		}`},
		{name: "invalid response status", input: `{
			shield {
				deny 192.0.2.1
				response { status 200 }
			}
		}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := adaptAndValidate(tt.input); err == nil {
				t.Fatal("configuration was accepted")
			}
		})
	}
}

func TestPolicyInheritanceAndDefaults(t *testing.T) {
	globalBody := "global"
	localBody := "local"
	app := &App{
		Allow: []string{"192.0.2.10"},
		Deny:  []string{"198.51.100.0/24"},
		Response: Response{
			Headers: map[string][]string{"X-Global": {"kept"}, "X-Mode": {"global"}},
			Body:    &globalBody,
		},
	}
	app.setDefaults()
	allowed, _ := parseConfiguredPrefixes(app.Allow)
	blocked, _ := parseConfiguredPrefixes(app.Deny)
	var err error
	app.static, err = newSnapshot(allowed, blocked)
	if err != nil {
		t.Fatal(err)
	}

	failClosed := false
	handler := &Handler{
		Allow:    []string{"198.51.100.5"},
		Deny:     []string{"192.0.2.0/24"},
		FailOpen: &failClosed,
		Response: Response{
			StatusCode: http.StatusUnavailableForLegalReasons,
			Headers:    map[string][]string{"x-mode": {"site"}},
			Body:       &localBody,
		},
	}
	if err := handler.configureFromApp(app); err != nil {
		t.Fatal(err)
	}

	if time.Duration(app.RefreshInterval) != time.Hour || time.Duration(app.Timeout) != 30*time.Second ||
		app.MaxSize != 32*1024*1024 || app.MaxEntries != 2_000_000 || app.FailOpen == nil || !*app.FailOpen {
		t.Errorf("defaults not applied: %+v", app)
	}
	for address, wantBlocked := range map[string]bool{
		"192.0.2.10":   false,
		"192.0.2.11":   true,
		"198.51.100.5": false,
		"198.51.100.6": true,
		"203.0.113.10": false,
	} {
		if got := handler.static.containsBlocked(netip.MustParseAddr(address)); got != wantBlocked {
			t.Errorf("address %s blocked = %t, want %t", address, got, wantBlocked)
		}
	}
	if handler.effectiveFailOpen || handler.effectiveResponse.StatusCode != 451 ||
		handler.effectiveResponse.Body == nil || *handler.effectiveResponse.Body != "local" ||
		http.Header(handler.effectiveResponse.Headers).Get("X-Global") != "kept" ||
		http.Header(handler.effectiveResponse.Headers).Get("X-Mode") != "site" {
		t.Errorf("effective overrides = fail_open:%t response:%+v", handler.effectiveFailOpen, handler.effectiveResponse)
	}
}

func adaptAndValidate(input string) ([]byte, error) {
	adapter := caddyconfig.GetAdapter("caddyfile")
	adapted, _, err := adapter.Adapt([]byte(input), nil)
	if err != nil {
		return nil, err
	}
	var config caddy.Config
	if err := json.Unmarshal(adapted, &config); err != nil {
		return nil, err
	}
	if err := caddy.Validate(&config); err != nil {
		return nil, err
	}
	return adapted, nil
}
