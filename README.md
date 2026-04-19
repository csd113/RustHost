# RustHost

RustHost is a single-binary static file server written in Rust. It serves public static content over HTTP, can add HTTPS with self-signed, manual, or ACME-managed certificates, and can expose the same site through an in-process Tor onion service powered by Arti.

## Overview

RustHost is designed for small, explicit static hosting deployments where the server should be easy to run, easy to inspect, and conservative by default. It can run interactively with a terminal dashboard, or headlessly for service, CI, and remote-shell environments.

RustHost is intentionally not a web framework or application server. It does not provide users, sessions, logins, uploads, private routes, a CMS, or an admin authorization layer. If you need private or operator-only access, put RustHost behind a reverse proxy or another authenticated service.

## Features

**Static file serving**

- HTTP/1.1 server using `hyper` with keep-alive support.
- `GET`, `HEAD`, and `OPTIONS` handling, with `405 Method Not Allowed` for unsupported methods.
- ETag and `Last-Modified` revalidation.
- Single-range byte requests for seekable media and large files.
- Brotli and Gzip compression negotiated with `Accept-Encoding`.
- Precompressed sidecar support for `.br` and `.gz` files.
- Optional directory listings, SPA fallback routing, custom `404` and `503` pages, and URL redirects.
- Dotfiles are hidden unless explicitly enabled.

**HTTPS and TLS**

- HTTP-only by default.
- Self-signed localhost certificate generation for local HTTPS testing.
- Manual certificate loading from paths inside the configured data directory.
- ACME / Let's Encrypt support through `rustls-acme`.
- Optional HTTP-to-HTTPS redirect listener.

**Tor onion service**

- Built-in onion service support through Arti.
- No external Tor daemon or binary required.
- Tor state and cache are stored under the runtime data directory.
- The same static site is served over clearnet HTTP/HTTPS and onion access.

**Operations and safety**

- Strict TOML config deserialization and validation.
- Global and per-IP connection limits.
- Configurable graceful shutdown windows.
- Security headers on responses, with configurable CSP presets for HTML.
- Structured access log in Combined Log Format when logging is enabled.
- Interactive dashboard with reload and log views, plus headless mode for services.

**Development quality**

- `unsafe` Rust is forbidden by crate lints.
- Strict Clippy configuration is checked by the documented quality gate.
- Integration tests exercise the real server with keep-alive, range requests, directory listings, percent-encoded paths, and mixed static assets.

## When to Use It

RustHost is a good fit for:

- previewing a local static site from a single binary
- hosting a small public static site
- serving lightweight internal documentation
- publishing static content with optional onion access
- testing HTTPS behavior without adding a separate web server

RustHost is not intended for:

- dynamic application hosting
- authenticated user workflows
- file uploads
- operator dashboards exposed directly to the public internet
- replacing a full reverse proxy when you need complex ingress policy

## Quick Start

RustHost requires Rust 1.90 or newer.

```bash
cargo build --release
```

The release binary is written to:

```bash
./target/release/rusthost-cli
```

### One-shot directory serving

Use `--serve` when you want to serve a directory directly without creating a persistent `settings.toml`.

```bash
./target/release/rusthost-cli --serve ./public
```

Useful variants:

```bash
./target/release/rusthost-cli --serve ./public --port 3000
./target/release/rusthost-cli --serve ./public --no-tor
./target/release/rusthost-cli --serve ./public --headless
```

In one-shot mode, RustHost binds to `127.0.0.1`, enables directory listings, disables file logging, and uses the default static-file behavior. Tor is enabled unless `--no-tor` is supplied.

### Managed data directory

Use managed mode when you want persistent configuration, logs, certificates, and Tor state.

```bash
./target/release/rusthost-cli --data-dir ./rusthost-data
```

On first run, RustHost creates:

```text
rusthost-data/
  settings.toml
  site/
  runtime/
```

Put your static files in `rusthost-data/site/`. In interactive mode, press `R` in the dashboard to reload site state after changing files. On Unix, sending `SIGHUP` also triggers the reload path.

## Configuration

The generated `settings.toml` is the main control surface. The most important defaults are:

- HTTP listens on `127.0.0.1:8080`.
- HTTPS is disabled.
- Tor is enabled in generated configs.
- The interactive dashboard is enabled.
- The site directory is `site`, relative to the data directory.
- Logging writes under `runtime/logs/` when enabled.

Common sections:

| Section | Purpose |
|---------|---------|
| `[server]` | bind address, port, connection limits, CSP preset, trusted proxies, browser opening |
| `[site]` | site directory, index file, directory listing, dotfile exposure, SPA fallback, custom error pages |
| `[tls]` | HTTPS listener, redirect behavior, ACME, manual certificates |
| `[tor]` | onion service enablement and Tor shutdown grace period |
| `[logging]` | application log level, log file, dependency log filtering |
| `[console]` | interactive dashboard behavior |
| `[identity]` | dashboard instance name |
| `[[redirects]]` | exact-path HTTP redirects evaluated before filesystem resolution |

Minimal local HTTP configuration:

```toml
[server]
port = 8080
bind = "127.0.0.1"

[site]
directory = "site"
index_file = "index.html"
```

Network exposure is explicit. Use `bind = "0.0.0.0"` only when you intend RustHost to listen on all IPv4 interfaces.

```toml
[server]
bind = "0.0.0.0"
port = 8080
max_connections = 256
max_connections_per_ip = 16
```

SPA routing and custom error pages:

```toml
[site]
spa_routing = true
error_404 = "404.html"
error_503 = "503.html"
```

Redirects:

```toml
[[redirects]]
from = "/old-page"
to = "/new-page"
status = 301
```

Redirect status must be `301` or `302`. Redirect targets must be safe to emit in an HTTP `Location` header.

## Static File Behavior

RustHost resolves every requested path against the canonical site root and rejects escapes outside that root. Direct dotfile requests and dotfile entries in directory listings are blocked unless `site.expose_dotfiles = true`.

Directory requests are normalized with trailing slash redirects. If a directory contains the configured `index_file`, that file is served. If it does not and directory listings are enabled, RustHost returns a generated listing capped at 512 entries. Otherwise, it returns the fallback or not-found response.

For cache and transfer behavior:

- HTML responses use `Cache-Control: no-cache`.
- Filenames with an 8 to 16 character hexadecimal hash segment are treated as immutable assets.
- Other assets default to `Cache-Control: no-cache`.
- Compressible responses over 1024 bytes can be streamed with Brotli or Gzip.
- Existing `.br` and `.gz` sidecars are preferred when they match the requested representation.
- Range requests are served only for identity responses.

Security-related response headers include:

- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: SAMEORIGIN`
- `Referrer-Policy: no-referrer`
- `Permissions-Policy: camera=(), microphone=(), geolocation=()`
- `Strict-Transport-Security` on HTTPS responses
- `Content-Security-Policy` for HTML when `[server] csp_level` is not `off`

When HTTPS and Tor are both active, RustHost can add an `Onion-Location` header on clearnet HTTPS responses after the onion address is available.

## HTTPS and Certificates

Enable HTTPS with:

```toml
[tls]
enabled = true
port = 8443
```

If no manual certificate or ACME config is enabled, RustHost generates or reuses a self-signed development certificate under:

```text
runtime/tls/dev/
```

The generated certificate covers:

- `localhost`
- `127.0.0.1`
- `::1`

This mode is for local development and testing.

### Manual certificates

```toml
[tls]
enabled = true
port = 443

[tls.manual_cert]
cert_path = "runtime/tls/manual/fullchain.pem"
key_path = "runtime/tls/manual/privkey.pem"
```

Manual certificate paths are relative to the data directory. Absolute paths, parent directory traversal, and symlink escapes outside the data directory are rejected.

### ACME / Let's Encrypt

```toml
[tls]
enabled = true
port = 443
redirect_http = true
http_port = 80

[tls.acme]
enabled = true
domains = ["example.com", "www.example.com"]
email = "ops@example.com"
staging = true
cache_dir = "runtime/tls/acme"
```

Start with `staging = true`, verify DNS and public reachability, then switch to `staging = false` only after the staging flow works. RustHost validates ACME domains before startup: domains must be lowercase ASCII fully qualified domain names, not IP addresses, bare hostnames, duplicates, or wildcards.

ACME uses TLS-ALPN-01 through the HTTPS listener. The cache directory is relative to the data directory.

## Tor Onion Service

When `[tor] enabled = true`, RustHost starts Arti in-process and publishes an onion service for the same static site.

```toml
[tor]
enabled = true
shutdown_grace_secs = 5
```

What to expect:

- The first bootstrap needs outbound network access.
- Arti downloads Tor directory data on first run.
- The full onion address appears in the dashboard and logs once available.
- Tor private state and cache live under `runtime/tor/`.
- Preserve the Tor state directory if onion address continuity matters.

For public or sensitive deployments, run RustHost under a dedicated OS account and keep the data directory private.

## Operations and Security Notes

- Keep `bind = "127.0.0.1"` for local-only use.
- Use `bind = "0.0.0.0"` or a public interface only when the host firewall and deployment model are intentional.
- Use `--headless` or `[console] interactive = false` for services, containers, CI, and remote shells.
- Put authentication, private routes, IP allowlists, and advanced rate limiting in a reverse proxy or separate service.
- Only set `[server] trusted_proxies` to proxy IPs you control. Otherwise, RustHost ignores `X-Forwarded-For` and uses the TCP peer address.
- Back up certificate state and Tor state if continuity matters.
- Review the site directory before exposing it. RustHost serves static files; it does not know which files are sensitive.

## CLI Reference

```text
rusthost-cli [OPTIONS]

OPTIONS:
    --config   <path>   Override the path to settings.toml
    --data-dir <path>   Override the data-directory root
    --serve    <dir>    Serve a directory directly, with no first-run setup
    --port     <n>      Port for --serve mode, default 8080
    --no-tor            Disable Tor in --serve mode
    --headless          Disable the interactive console
    -V, --version       Print version and exit
    -h, --help          Print help and exit
```

Both `--flag value` and `--flag=value` forms are accepted.

## Development

Run the binary from source:

```bash
cargo run -- --help
cargo run -- --serve ./public
```

Quality gates:

```bash
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets
```

The test suite includes unit tests for config, TLS, path handling, and Tor helpers, plus integration tests that start the real HTTP server and inspect raw HTTP responses.

## Project Layout

```text
src/main.rs              CLI entry point
src/runtime/            startup, reload, shutdown, shared state
src/config/             TOML schema, defaults, validation
src/server/             HTTP, HTTPS, redirects, static file handling
src/tls/                self-signed, manual, and ACME certificate support
src/tor/                Arti onion service integration
src/console/            terminal dashboard and input handling
src/logging/            application and access logging
tests/                  integration and stress tests
docs/                   architecture diagrams and design notes
```

## Documentation

- [Setup guide](./SETUP.md)
- [Change history](./CHANGELOG.md)
- [Contributing guide](./CONTRIBUTING.md)
- [Module architecture diagram](./docs/rusthost_module_architecture.svg)
- [Directory structure diagram](./docs/rusthost_directory_structure.svg)
- [Lifecycle diagram](./docs/rusthost_lifecycle.svg)

## License

RustHost is licensed under the [MIT License](./LICENSE).
