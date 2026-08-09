// Package shield implements a Caddy HTTP middleware that blocks requests from
// addresses found in configured IP reputation feeds.
package shield

import (
	"fmt"
	"net/http"
	"net/netip"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(App{})
	caddy.RegisterModule(Handler{})
	httpcaddyfile.RegisterGlobalOption("shield", parseGlobalShield)
	httpcaddyfile.RegisterHandlerDirective("shield", parseCaddyfile)
	httpcaddyfile.RegisterDirectiveOrder("shield", httpcaddyfile.Before, "request_body")
}

// Handler blocks requests whose client address is present in a configured
// source or explicit deny entry.
type Handler struct {
	Allow    []string `json:"allow,omitempty"`
	Deny     []string `json:"deny,omitempty"`
	Response Response `json:"response,omitempty"`
	FailOpen *bool    `json:"fail_open,omitempty"`

	logger            *zap.Logger
	app               *App
	static            *snapshot
	effectiveResponse Response
	effectiveFailOpen bool
}

// CaddyModule returns the Caddy module information.
func (Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.shield",
		New: func() caddy.Module { return new(Handler) },
	}
}

// Provision resolves the global Shield app and compiles additive site policy.
func (h *Handler) Provision(ctx caddy.Context) error {
	h.logger = ctx.Logger()
	if err := h.Validate(); err != nil {
		return err
	}

	appModule, err := ctx.App("shield")
	if err != nil {
		return fmt.Errorf("getting global shield app: %w", err)
	}
	app, ok := appModule.(*App)
	if !ok {
		return fmt.Errorf("global shield app has unexpected type %T", appModule)
	}
	h.app = app
	return h.configureFromApp(app)
}

func (h *Handler) configureFromApp(app *App) error {
	localAllowed, err := parseConfiguredPrefixes(h.Allow)
	if err != nil {
		return fmt.Errorf("site allow entries: %w", err)
	}
	localBlocked, err := parseConfiguredPrefixes(h.Deny)
	if err != nil {
		return fmt.Errorf("site deny entries: %w", err)
	}
	h.static, err = extendSnapshot(app.static, localAllowed, localBlocked)
	if err != nil {
		return err
	}
	h.effectiveResponse = mergeResponse(app.Response, h.Response)
	h.effectiveFailOpen = *app.FailOpen
	if h.FailOpen != nil {
		h.effectiveFailOpen = *h.FailOpen
	}
	return nil
}

// ServeHTTP resolves Caddy's trusted client IP and either rejects the request
// or invokes the next handler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	if r.TLS != nil && !r.TLS.HandshakeComplete {
		return caddyhttp.Error(http.StatusTooEarly, fmt.Errorf("TLS handshake not complete; client IP cannot be verified"))
	}

	clientIP, err := clientIPFromRequest(r)
	if err != nil {
		return caddyhttp.Error(http.StatusInternalServerError, fmt.Errorf("resolving trusted client IP: %w", err))
	}

	if h.static != nil && h.static.containsAllowed(clientIP) {
		return next.ServeHTTP(w, r)
	}
	if h.static != nil && h.static.containsBlocked(clientIP) {
		return h.writeBlockedResponse(w, r, clientIP, "blocklist", nil)
	}

	var feeds *feedSnapshot
	if h.app != nil && h.app.manager != nil {
		feeds = h.app.manager.Snapshot()
	}
	if feeds != nil && feeds.blocked.Contains(clientIP) {
		return h.writeBlockedResponse(w, r, clientIP, "blocklist", feeds.matchingSources(clientIP))
	}
	if (feeds == nil || !feeds.ready) && !h.isFailOpen() {
		return h.writeBlockedResponse(w, r, clientIP, "unavailable", nil)
	}
	return next.ServeHTTP(w, r)
}

func (h *Handler) isFailOpen() bool {
	if h.app == nil {
		return h.FailOpen == nil || *h.FailOpen
	}
	return h.effectiveFailOpen
}

func clientIPFromRequest(r *http.Request) (netip.Addr, error) {
	address, _ := caddyhttp.GetVar(r.Context(), caddyhttp.ClientIPVarKey).(string)
	if address == "" {
		address = r.RemoteAddr
	}
	if addr, err := netip.ParseAddr(address); err == nil {
		return addr.Unmap().WithZone(""), nil
	}
	if addrPort, err := netip.ParseAddrPort(address); err == nil {
		return addrPort.Addr().Unmap().WithZone(""), nil
	}
	return netip.Addr{}, fmt.Errorf("parse client IP %q", address)
}

func (h *Handler) writeBlockedResponse(w http.ResponseWriter, r *http.Request, clientIP netip.Addr, reason string, sources []string) error {
	repl, _ := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	if repl == nil {
		repl = caddy.NewReplacer()
	}
	ipText := ""
	if clientIP.IsValid() {
		ipText = clientIP.String()
	}
	repl.Set("client_ip", ipText)
	repl.Set("shield.client_ip", ipText)
	repl.Set("shield.reason", reason)
	repl.Set("shield.sources", strings.Join(sources, ","))

	response := h.effectiveResponse
	if h.app == nil {
		response = h.Response
	}
	for field, values := range response.Headers {
		field = http.CanonicalHeaderKey(field)
		expanded := make([]string, len(values))
		for i, value := range values {
			expanded[i] = repl.ReplaceAll(value, "")
		}
		w.Header()[field] = expanded
	}
	body := ""
	if response.Body != nil {
		body = repl.ReplaceAll(*response.Body, "")
	}
	statusCode := response.StatusCode
	if statusCode == 0 {
		statusCode = defaultStatusCode
	}
	if h.logger != nil {
		h.logger.Debug("request blocked",
			zap.String("client_ip", ipText),
			zap.String("reason", reason),
			zap.Strings("sources", sources),
			zap.String("host", r.Host),
			zap.String("uri", r.URL.RequestURI()),
			zap.Int("status", statusCode),
		)
	}
	w.WriteHeader(statusCode)
	if body != "" {
		_, _ = fmt.Fprint(w, body)
	}
	return nil
}

var (
	_ caddy.Module                = (*Handler)(nil)
	_ caddy.Provisioner           = (*Handler)(nil)
	_ caddy.Validator             = (*Handler)(nil)
	_ caddyhttp.MiddlewareHandler = (*Handler)(nil)
)
