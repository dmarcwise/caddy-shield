package shield

import (
	"strconv"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/dustin/go-humanize"
)

func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var handler Handler
	if err := handler.UnmarshalCaddyfile(h.Dispenser); err != nil {
		return nil, err
	}
	return &handler, nil
}

func parseGlobalShield(d *caddyfile.Dispenser, existingVal any) (any, error) {
	if existingVal != nil {
		return nil, d.Err("shield global option is configured more than once")
	}
	var app App
	if err := app.UnmarshalCaddyfile(d); err != nil {
		return nil, err
	}
	return httpcaddyfile.App{Name: "shield", Value: caddyconfig.JSON(app, nil)}, nil
}

// UnmarshalCaddyfile parses the global shield app configuration.
func (app *App) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next()
	if d.NextArg() {
		return d.ArgErr()
	}

	for nesting := d.Nesting(); d.NextBlock(nesting); {
		switch d.Val() {
		case "source":
			source, err := unmarshalSource(d)
			if err != nil {
				return err
			}
			app.Sources = append(app.Sources, source)
		case "refresh_interval":
			duration, err := unmarshalDuration(d)
			if err != nil {
				return err
			}
			app.RefreshInterval = duration
		case "timeout":
			duration, err := unmarshalDuration(d)
			if err != nil {
				return err
			}
			app.Timeout = duration
		case "max_size":
			args := d.RemainingArgs()
			if len(args) != 1 {
				return d.ArgErr()
			}
			size, err := humanize.ParseBytes(args[0])
			if err != nil || size > uint64(^uint64(0)>>1) {
				return d.Errf("invalid max_size %q", args[0])
			}
			app.MaxSize = int64(size)
		case "max_entries":
			args := d.RemainingArgs()
			if len(args) != 1 {
				return d.ArgErr()
			}
			count, err := strconv.Atoi(args[0])
			if err != nil {
				return d.Errf("invalid max_entries %q: %v", args[0], err)
			}
			app.MaxEntries = count
		case "allow":
			values := d.RemainingArgs()
			if len(values) == 0 {
				return d.ArgErr()
			}
			app.Allow = append(app.Allow, values...)
		case "deny":
			values := d.RemainingArgs()
			if len(values) == 0 {
				return d.ArgErr()
			}
			app.Deny = append(app.Deny, values...)
		case "fail_open":
			value, err := unmarshalBool(d)
			if err != nil {
				return err
			}
			app.FailOpen = &value
		case "response":
			if len(d.RemainingArgs()) != 0 {
				return d.ArgErr()
			}
			if err := app.Response.unmarshalCaddyfile(d); err != nil {
				return err
			}
		default:
			return d.Errf("unrecognized global shield option %q", d.Val())
		}
	}
	return nil
}

// UnmarshalCaddyfile parses the shield directive.
func (h *Handler) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next()
	if d.NextArg() {
		return d.ArgErr()
	}

	for nesting := d.Nesting(); d.NextBlock(nesting); {
		switch d.Val() {
		case "allow":
			values := d.RemainingArgs()
			if len(values) == 0 {
				return d.ArgErr()
			}
			h.Allow = append(h.Allow, values...)
		case "deny":
			values := d.RemainingArgs()
			if len(values) == 0 {
				return d.ArgErr()
			}
			h.Deny = append(h.Deny, values...)
		case "fail_open":
			value, err := unmarshalBool(d)
			if err != nil {
				return err
			}
			h.FailOpen = &value
		case "response":
			if len(d.RemainingArgs()) != 0 {
				return d.ArgErr()
			}
			if err := h.Response.unmarshalCaddyfile(d); err != nil {
				return err
			}
		default:
			return d.Errf("unrecognized shield option %q", d.Val())
		}
	}

	return nil
}

func unmarshalBool(d *caddyfile.Dispenser) (bool, error) {
	args := d.RemainingArgs()
	if len(args) != 1 {
		return false, d.ArgErr()
	}
	value, err := strconv.ParseBool(args[0])
	if err != nil {
		return false, d.Errf("invalid boolean value %q: %v", args[0], err)
	}
	return value, nil
}

func unmarshalSource(d *caddyfile.Dispenser) (Source, error) {
	args := d.RemainingArgs()
	if len(args) != 1 {
		return Source{}, d.ArgErr()
	}
	source := Source{Name: args[0]}
	for nesting := d.Nesting(); d.NextBlock(nesting); {
		switch d.Val() {
		case "url":
			args := d.RemainingArgs()
			if len(args) != 1 {
				return Source{}, d.ArgErr()
			}
			source.URL = args[0]
		case "refresh_interval":
			duration, err := unmarshalDuration(d)
			if err != nil {
				return Source{}, err
			}
			source.RefreshInterval = duration
		default:
			return Source{}, d.Errf("unrecognized source option %q", d.Val())
		}
	}
	return source, nil
}

func (r *Response) unmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for nesting := d.Nesting(); d.NextBlock(nesting); {
		switch d.Val() {
		case "status":
			args := d.RemainingArgs()
			if len(args) != 1 {
				return d.ArgErr()
			}
			status, err := strconv.Atoi(args[0])
			if err != nil {
				return d.Errf("invalid response status %q: %v", args[0], err)
			}
			r.StatusCode = status
		case "header":
			args := d.RemainingArgs()
			if len(args) != 2 {
				return d.ArgErr()
			}
			if r.Headers == nil {
				r.Headers = make(map[string][]string)
			}
			r.Headers[args[0]] = append(r.Headers[args[0]], args[1])
		case "body":
			args := d.RemainingArgs()
			if len(args) != 1 {
				return d.ArgErr()
			}
			r.Body = &args[0]
		default:
			return d.Errf("unrecognized response option %q", d.Val())
		}
	}
	return nil
}

func unmarshalDuration(d *caddyfile.Dispenser) (caddy.Duration, error) {
	args := d.RemainingArgs()
	if len(args) != 1 {
		return 0, d.ArgErr()
	}
	duration, err := caddy.ParseDuration(args[0])
	if err != nil {
		return 0, d.Errf("invalid duration %q: %v", args[0], err)
	}
	return caddy.Duration(duration), nil
}

var (
	_ caddyfile.Unmarshaler = (*App)(nil)
	_ caddyfile.Unmarshaler = (*Handler)(nil)
)
