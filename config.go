package shield

import (
	"fmt"
	"net/http"
	"net/netip"
	"net/textproto"
	"net/url"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
)

const (
	defaultRefreshInterval = caddy.Duration(time.Hour)
	defaultTimeout         = caddy.Duration(30 * time.Second)
	defaultMaxSize         = int64(32 * 1024 * 1024)
	defaultMaxEntries      = 2_000_000
	defaultStatusCode      = http.StatusForbidden
	defaultResponseBody    = "Request blocked\n"
)

// Source describes a blocklist feed. A source may reference a built-in preset
// by name or provide its own HTTP(S) URL.
type Source struct {
	Name            string         `json:"name"`
	URL             string         `json:"url,omitempty"`
	RefreshInterval caddy.Duration `json:"refresh_interval,omitempty"`
}

// Response configures the response returned for a blocked request.
type Response struct {
	StatusCode int                 `json:"status_code,omitempty"`
	Headers    map[string][]string `json:"headers,omitempty"`
	Body       *string             `json:"body,omitempty"`
}

func (app *App) setDefaults() {
	if app.RefreshInterval == 0 {
		app.RefreshInterval = defaultRefreshInterval
	}
	if app.Timeout == 0 {
		app.Timeout = defaultTimeout
	}
	if app.MaxSize == 0 {
		app.MaxSize = defaultMaxSize
	}
	if app.MaxEntries == 0 {
		app.MaxEntries = defaultMaxEntries
	}
	if app.FailOpen == nil {
		failOpen := true
		app.FailOpen = &failOpen
	}
	if app.Response.StatusCode == 0 {
		app.Response.StatusCode = defaultStatusCode
	}
	if app.Response.Body == nil {
		body := defaultResponseBody
		app.Response.Body = &body
	}
	if app.Response.Headers == nil {
		app.Response.Headers = map[string][]string{
			"Content-Type": {"text/plain; charset=utf-8"},
		}
	}
}

// Validate validates the global app configuration.
func (app App) Validate() error {
	if len(app.Sources) == 0 && len(app.Deny) == 0 {
		return fmt.Errorf("at least one source or deny entry is required")
	}
	if app.RefreshInterval <= 0 {
		return fmt.Errorf("refresh_interval must be positive")
	}
	if app.Timeout <= 0 {
		return fmt.Errorf("timeout must be positive")
	}
	if app.MaxSize <= 0 {
		return fmt.Errorf("max_size must be positive")
	}
	if app.MaxEntries <= 0 {
		return fmt.Errorf("max_entries must be positive")
	}
	if err := validateResponse(app.Response, true); err != nil {
		return err
	}

	seen := make(map[string]struct{}, len(app.Sources))
	for i, source := range app.Sources {
		if err := validateSource(source); err != nil {
			return fmt.Errorf("source %d: %w", i, err)
		}
		if _, ok := seen[source.Name]; ok {
			return fmt.Errorf("source %q is configured more than once", source.Name)
		}
		seen[source.Name] = struct{}{}
	}

	if err := validatePrefixes("allow", app.Allow); err != nil {
		return err
	}
	return validatePrefixes("deny", app.Deny)
}

// Validate validates site-local policy overrides.
func (h Handler) Validate() error {
	if err := validatePrefixes("allow", h.Allow); err != nil {
		return err
	}
	if err := validatePrefixes("deny", h.Deny); err != nil {
		return err
	}
	return validateResponse(h.Response, false)
}

func validateResponse(response Response, requiredStatus bool) error {
	if requiredStatus && (response.StatusCode < 400 || response.StatusCode > 599) {
		return fmt.Errorf("response status_code must be between 400 and 599")
	}
	if !requiredStatus && response.StatusCode != 0 && (response.StatusCode < 400 || response.StatusCode > 599) {
		return fmt.Errorf("response status_code must be between 400 and 599")
	}
	for field, values := range response.Headers {
		if textproto.TrimString(field) == "" || textproto.CanonicalMIMEHeaderKey(field) == "" {
			return fmt.Errorf("invalid response header name %q", field)
		}
		for _, value := range values {
			if strings.ContainsAny(value, "\r\n") {
				return fmt.Errorf("response header %q contains a newline", field)
			}
		}
	}

	return nil
}

func validateSource(source Source) error {
	if strings.TrimSpace(source.Name) == "" {
		return fmt.Errorf("name is required")
	}
	if source.RefreshInterval < 0 {
		return fmt.Errorf("refresh_interval must be positive")
	}
	_, isPreset := presets[source.Name]
	if source.URL == "" {
		if !isPreset {
			return fmt.Errorf("unknown preset %q; a url is required", source.Name)
		}
		return nil
	}
	if isPreset {
		return fmt.Errorf("preset %q cannot override its url; use a custom source name", source.Name)
	}

	parsed, err := url.ParseRequestURI(source.URL)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return fmt.Errorf("url must be an absolute HTTP(S) URL")
	}
	return nil
}

func validatePrefixes(kind string, values []string) error {
	for i, value := range values {
		if _, err := netip.ParsePrefix(value); err == nil {
			continue
		}
		if _, err := netip.ParseAddr(value); err != nil {
			return fmt.Errorf("%s entry %d (%q) is not an IP address or CIDR prefix", kind, i, value)
		}
	}
	return nil
}
