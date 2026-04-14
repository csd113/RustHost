# RustHost

RustHost is a single-binary static file server written in Rust with built-in HTTPS and optional Tor onion service support.

It is designed for serving static content safely with a small operational surface:

- HTTP and HTTPS listeners
- self-signed, manual, or ACME-managed TLS
- built-in Tor onion service support through Arti
- terminal dashboard for local interactive use
- headless mode for service or CI environments
- strong default response hardening and strict config validation

RustHost is intentionally a **static public content server**. It does not provide users, sessions, logins, uploads, or admin authorization. If you need private or operator-only routes, put those behind a separate authenticated service or reverse proxy.

## Highlights

- Single Rust binary, no OpenSSL dependency
- Cross-platform support for macOS, Linux, and Windows
- IPv4 and IPv6 listener support
- Static-file features including ETag, range requests, gzip and Brotli, cache-control policy, and optional directory listings
- Built-in security headers with configurable CSP level
- Per-IP and global connection limits
- Optional HTTP to HTTPS redirect server
- Custom `404` and `503` pages
- Strict Clippy and test coverage in the repo itself, including a real HTTP stress suite for mixed static assets

## Project Scope

RustHost is a good fit for:

- local static site development
- self-hosted static sites
- lightweight internal documentation hosting
- public static publishing with optional onion access

RustHost is not trying to be:

- a general web framework
- an authenticated admin panel
- a dynamic app server
- a file upload or content management system

## Quick Start

### Build

RustHost currently requires **Rust 1.90 or newer**.

```bash
cargo build --release
```

The binary is:

```bash
./target/release/rusthost-cli
```

### Serve a directory immediately

```bash
./target/release/rusthost-cli --serve ./public
```

Useful one-shot variants:

```bash
./target/release/rusthost-cli --serve ./public --port 3000
./target/release/rusthost-cli --serve ./public --no-tor
./target/release/rusthost-cli --serve ./public --headless
```

### First-run managed mode

```bash
./target/release/rusthost-cli --data-dir ./rusthost-data
```

On first run RustHost creates:

- `rusthost-data/settings.toml`
- `rusthost-data/site/`
- `rusthost-data/runtime/`

Drop your static files into `rusthost-data/site/` and restart.

## Configuration Overview

The generated `settings.toml` is the main control surface. Common areas:

- `[server]` for bind address, port, connection limits, CSP, trusted proxies, and browser auto-open
- `[site]` for the site directory, SPA fallback, directory listings, dotfile behavior, and custom `404` / `503` pages
- `[tls]` for HTTPS, redirect behavior, ACME, and manual certificates
- `[tor]` for onion service enablement
- `[console]` for interactive dashboard behavior
- `[logging]` for log file and level policy

Important defaults:

- HTTP listens on `127.0.0.1:8080`
- HTTPS is off by default
- Tor is on by default in generated config
- interactive dashboard is on by default

## HTTPS Modes

### Self-signed development certificate

```toml
[tls]
enabled = true
port = 8443
```

RustHost generates and reuses a local dev certificate covering:

- `localhost`
- `127.0.0.1`
- `::1`

### Manual certificate files

```toml
[tls]
enabled = true
port = 443

[tls.manual_cert]
cert_path = "runtime/tls/manual/fullchain.pem"
key_path = "runtime/tls/manual/privkey.pem"
```

Manual cert paths must stay inside the configured data directory.

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

Recommended rollout:

1. Start with `staging = true`
2. Verify DNS, port reachability, and HTTPS startup
3. Switch to `staging = false` only after the staging flow succeeds

ACME is intended for real public domain names. IP literals and `localhost` are rejected.

## Tor / Arti

RustHost can expose the same static site over a Tor onion service using Arti in-process.

Operational notes:

- the first startup needs outbound network access so Arti can bootstrap
- Tor private state is stored under `runtime/tor/`
- if you want to preserve the same onion address, back up the Tor state directory
- for sensitive deployments, run the process under a dedicated OS account

## Reverse Proxy and Public Deployment

RustHost can run directly on the network edge, but many deployments will benefit from a reverse proxy or load balancer in front of it for:

- centralized TLS policy
- IP allowlists or auth in front of operator-only surfaces
- rate limiting beyond the built-in connection controls
- access logging aggregation
- header normalization

If you enable `trusted_proxies`, only list addresses you actually control.

## Cross-Platform Notes

- macOS, Linux, and Windows are all supported build targets
- browser launching is best-effort convenience, not a guaranteed service feature
- local interactive terminal spawning is also best-effort and environment-dependent
- headless mode is the recommended production/service mode

## CLI

```text
rusthost-cli [OPTIONS]

  --config <path>    Override the path to settings.toml
  --data-dir <path>  Override the data directory root
  --serve <dir>      Serve a directory directly
  --port <n>         Port to use with --serve
  --no-tor           Disable Tor when using --serve
  --headless         Disable the interactive console
  -V, --version      Print version and exit
  -h, --help         Print help and exit
```

## Development Quality Gates

The project uses strict linting and tests:

```bash
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets
```

The integration test suite includes `tests/html_stress.rs`, which serves the
fixture tree under `tests/fixtures/html_stress/` through the real server and
checks bursty keep-alive traffic, concurrent clients, range requests, directory
listings, percent-encoded paths, and mixed HTML/CSS/JS/SVG assets.

`unsafe` Rust is forbidden in this project.

## Documentation

- Setup guide: [SETUP.md](./SETUP.md)
- Change history: [CHANGELOG.md](./CHANGELOG.md)

## Production Readiness Notes

Before public deployment, make sure you have:

- validated the final bind address and exposed ports
- tested the exact HTTPS mode you intend to run
- backed up Tor state if onion address continuity matters
- reviewed custom error pages and static content for anything sensitive
- decided whether to run directly or behind a reverse proxy
- confirmed logs, certificates, and data directories are stored where you expect

## License

MIT
