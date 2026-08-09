package shield

import (
	"fmt"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"
)

// App owns the server-wide Shield policy, feed refresh workers, and dynamic
// blocklist snapshot.
type App struct {
	Sources         []Source       `json:"sources,omitempty"`
	RefreshInterval caddy.Duration `json:"refresh_interval,omitempty"`
	Timeout         caddy.Duration `json:"timeout,omitempty"`
	MaxSize         int64          `json:"max_size,omitempty"`
	MaxEntries      int            `json:"max_entries,omitempty"`
	Allow           []string       `json:"allow,omitempty"`
	Deny            []string       `json:"deny,omitempty"`
	Response        Response       `json:"response,omitempty"`
	FailOpen        *bool          `json:"fail_open,omitempty"`

	logger  *zap.Logger
	static  *snapshot
	manager *refreshManager
}

// CaddyModule returns the Caddy module information.
func (App) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "shield",
		New: func() caddy.Module { return new(App) },
	}
}

// Provision prepares immutable static policy and the refresh manager without
// starting network activity.
func (app *App) Provision(ctx caddy.Context) error {
	app.setDefaults()
	app.logger = ctx.Logger()
	if err := app.Validate(); err != nil {
		return err
	}

	allowed, err := parseConfiguredPrefixes(app.Allow)
	if err != nil {
		return fmt.Errorf("global allow entries: %w", err)
	}
	blocked, err := parseConfiguredPrefixes(app.Deny)
	if err != nil {
		return fmt.Errorf("global deny entries: %w", err)
	}
	app.static, err = newSnapshot(allowed, blocked)
	if err != nil {
		return err
	}
	app.manager, err = newRefreshManager(ctx.Context, app)
	return err
}

// Start launches all feed refresh workers asynchronously.
func (app *App) Start() error {
	if app.manager != nil {
		app.manager.Start()
	}
	return nil
}

// Stop cancels downloads, stops workers, and closes idle HTTP connections.
func (app *App) Stop() error {
	if app.manager != nil {
		app.manager.Stop()
	}
	return nil
}

// Cleanup also handles configurations which were provisioned for validation
// but never started.
func (app *App) Cleanup() error {
	return app.Stop()
}

var (
	_ caddy.Module       = (*App)(nil)
	_ caddy.App          = (*App)(nil)
	_ caddy.Provisioner  = (*App)(nil)
	_ caddy.Validator    = (*App)(nil)
	_ caddy.CleanerUpper = (*App)(nil)
)
