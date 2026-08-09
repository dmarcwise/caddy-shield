# Caddy Shield

A Caddy module to block requests received from remote clients listed in IP blocklists. It supports multiple feeds, automatic background refresh, static allow and deny entries, IPv4 and IPv6 addresses, and configurable responses for blocked requests.

## Build

Build Caddy with [`xcaddy`](https://github.com/caddyserver/xcaddy):

```sh
xcaddy build --with github.com/dmarcwise/caddy-shield
```

To build a local copy of the module, clone this repository and run:

```sh
xcaddy build --with github.com/dmarcwise/caddy-shield=.
```

## Configuration

```caddyfile
{
	shield {
		source ipsum_3
		source firehol_level1
		source borestad_abuseipdb_7d

		refresh_interval 1h
		timeout 30s

		allow 203.0.113.10
		deny 198.51.100.20

		response {
			status 403
			header Content-Type "text/plain; charset=utf-8"
			body "Access denied\n"
		}
	}
}

example.com {
	shield
	reverse_proxy localhost:8080
}
```

The global `shield` block defines shared feeds and policy but does not enable the middleware by itself. Add `shield` to
each site that should use it.

Site policy is additive. An allow entry always wins over a deny entry, regardless of whether it was declared globally
or on the site:

```caddyfile
example.com {
	shield {
		allow 192.0.2.42
		deny 192.0.2.0/24

		response {
			status 451
			header X-Blocked-IP "{shield.client_ip}"
			body "Blocked: {shield.client_ip}\n"
		}
	}

	reverse_proxy localhost:8080
}
```

Site response fields replace their global counterparts. Headers with different names are retained.

## Sources

No source is enabled automatically. Sources are configured in the global `shield` block and names must be unique.

### Built-in presets

Enable a preset by name:

```caddyfile
source ipsum_3
```

Customize the refresh interval with:

```caddyfile
source firehol_level1 {
	refresh_interval 15m
}
```

The available presets are:

| Name | Description                                                                                                           |
| --- |-----------------------------------------------------------------------------------------------------------------------|
| `ipsum_1` | [IPsum](https://github.com/stamparm/ipsum), present on at least 1 source list                                         |
| `ipsum_2` | [IPsum](https://github.com/stamparm/ipsum), present on at least 2 source lists                                        |
| `ipsum_3` | [IPsum](https://github.com/stamparm/ipsum), present on at least 3 source lists                                        |
| `firehol_level1` | [FireHOL level 1](https://iplists.firehol.org/?ipset=firehol_level1), safe to block, lowest false-positive risk       |
| `firehol_level2` | [FireHOL level 2](https://iplists.firehol.org/?ipset=firehol_level2), recent attackers from roughly the last 48 hours |
| `firehol_level3` | [FireHOL level 3](https://iplists.firehol.org/?ipset=firehol_level3), attacks, spyware, and malware                   |
| `firehol_level4` | [FireHOL level 4](https://iplists.firehol.org/?ipset=firehol_level4), wider coverage with greater false-positive risk |
| `borestad_abuseipdb_1d` | [Borestad AbuseIPDB](https://github.com/borestad/blocklist-abuseipdb), score ~100 reported within 1 day               |
| `borestad_abuseipdb_7d` | [Borestad AbuseIPDB](https://github.com/borestad/blocklist-abuseipdb), score ~100 reported within 7 days              |
| `borestad_abuseipdb_30d` | [Borestad AbuseIPDB](https://github.com/borestad/blocklist-abuseipdb), score ~100 reported within 30 days             |

Preset URLs cannot be overridden. To use a mirror or different URL, configure a custom source with a different name.

### Custom sources

A custom source requires a unique name and an absolute HTTP or HTTPS URL:

```caddyfile
source company_blocklist {
	url https://example.com/blocklist.txt
	refresh_interval 30m
}
```

The `refresh_interval` field is optional for both preset and custom sources. When omitted, the global interval is used.

Source files may contain IP addresses or CIDR prefixes, one per line. Blank lines, `#` comments, and columns after the
first whitespace-delimited field are ignored.

## Recommended starting point

For a conservative initial configuration with low risk of false positives, enable the following lists:

```caddyfile
shield {
	source ipsum_3
	source firehol_level1
	source borestad_abuseipdb_7d
}
```

## Client IPs and proxies

Shield uses the client IP resolved by Caddy. It does not read `X-Forwarded-For` directly. If Caddy runs behind another
proxy, configure Caddy's trusted proxies so the resolved address represents the original client:

```caddyfile
{
	servers {
		trusted_proxies static private_ranges
		trusted_proxies_strict
	}

	shield {
		source ipsum_3
	}
}
```

A direct internet-facing Caddy instance does not need this configuration. See Caddy's [trusted proxy documentation](https://caddyserver.com/docs/caddyfile/options#trusted-proxies) for deployments with CDNs or load balancers.

## Reference

Options in the global `shield` block:

| Option                        | Default   | Description                                                                             |
|-------------------------------|-----------|-----------------------------------------------------------------------------------------|
| `source <name>`               | none      | Enables a built-in preset or defines a custom source. May be repeated.                  |
| `refresh_interval <duration>` | `1h`      | Default refresh interval for sources.                                                   |
| `timeout <duration>`          | `30s`     | HTTP timeout for each download.                                                         |
| `max_size <size>`             | `32 MiB`  | Maximum downloaded body size. Values such as `16MB` are accepted.                       |
| `max_entries <count>`         | `2000000` | Maximum accepted entries per source.                                                    |
| `allow <IP/CIDR...>`          | none      | Adds static allow entries.                                                              |
| `deny <IP/CIDR...>`           | none      | Adds static deny entries.                                                               |
| `fail_open <bool>`            | `true`    | Allows requests when no feed snapshot is available or the client IP cannot be resolved. |
| `response`                    | HTTP 403  | Configures the blocked status, headers, and body.                                       |

At least one global source or deny entry is required. Site-level `shield` blocks accept `allow`, `deny`, `fail_open`,
and `response`; sources and download settings remain global.

The `response` block accepts:

```caddyfile
response {
	status 403
	header Content-Type application/json
	body "{\"error\":\"blocked\"}"
}
```

Status codes must be between 400 and 599. Header values and bodies support Caddy placeholders, including:

- `{shield.client_ip}` or `{client_ip}`: the resolved address
- `{shield.reason}`: `blocklist`, `unavailable`, or `client_ip_error`
- Standard Caddy request placeholders such as `{http.request.method}`

## Refresh behavior

Each source refreshes independently. Successful results are published atomically; a failed refresh keeps that
source's last-known-good entries while the other sources continue normally. Conditional requests use `ETag` and
`Last-Modified` when provided by the server, and retries use bounded exponential backoff with jitter.

Downloads begin asynchronously when Caddy starts. Until the first source succeeds, requests not covered by static
allow or deny entries follow `fail_open`.

## Development

```sh
go test ./...
go test -race ./...
go test -run '^$' -bench '^BenchmarkIPLookup$' -benchmem ./...
```
