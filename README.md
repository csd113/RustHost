# RustHost

> Single-binary static hosting for HTTP, HTTPS, and optional Tor onion service delivery.

[![CI](https://github.com/csd113/RustHost/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/csd113/RustHost/actions/workflows/ci.yml)
[![Dependency Audit](https://github.com/csd113/RustHost/actions/workflows/audit.yml/badge.svg)](https://github.com/csd113/RustHost/actions/workflows/audit.yml)
[![License: MIT](https://img.shields.io/github/license/csd113/RustHost)](LICENSE)
[![Rust 1.90+](https://img.shields.io/badge/rust-1.90%2B-orange)](Cargo.toml)
[![Version](https://img.shields.io/badge/version-v1.0.0-blue)](CHANGELOG.md)
[![Platforms](https://img.shields.io/badge/platforms-Linux%20%7C%20macOS%20%7C%20Windows-3b82f6)](.github/workflows/ci.yml)

RustHost is a production-focused static file server written in Rust. It serves public static content over HTTP, can add HTTPS with self-signed, manual, or ACME-managed certificates, and can expose the same site through an in-process Tor onion service powered by Arti.

RustHost is intentionally narrow in scope: it is not a web framework, CMS, reverse proxy, or authenticated admin service. The design target is explicit, inspectable static hosting with one binary, one data directory, and one configuration file.

## Feature Overview

| Area | What RustHost provides |
| --- | --- |
| Static hosting | HTTP/1.1 keep-alive, `GET` / `HEAD` / `OPTIONS`, ETag and `Last-Modified`, range requests, compression, precompressed sidecars, SPA fallback, custom error pages, optional directory listings |
| HTTPS | Self-signed localhost certificates, manual PEM loading, ACME / Let's Encrypt support, optional HTTP to HTTPS redirect listener |
| Tor | Built-in onion service support via Arti, no external Tor daemon required, Tor state kept under the runtime data directory |
| Operations | `/health`, `/ready`, headless mode, graceful shutdown, structured logging, connection limits, accurate runtime path reporting |
| Operator UX | Interactive TUI with Home, Logs, Doctor, Diagnostics, Tor, Network, Site, Settings, and Help pages |
| Diagnostics | `rusthost-cli doctor`, runtime diagnostics snapshots, build-aware `--version`, explicit readiness checks for config, paths, TLS, Tor, favicon, and logging |

## Why RustHost

- Single binary deployment
- Explicit `settings.toml` configuration
- Managed runtime directory for logs, TLS state, and Tor state
- Interactive local console when you want it, headless mode when you do not
- Built-in health and readiness endpoints for service supervision

## Terminal / TUI Preview

No repository screenshots are currently shipped. The console experience is centered around a terminal dashboard and menu-driven operator views:

```text
RustHost 1.0.0
HTTP   : http://127.0.0.1:8080
HTTPS  : disabled
Tor    : starting / ready / disabled
Site   : ./rusthost-data/site
Logs   : ./rusthost-data/runtime/logs/rusthost.log

[M] Menu  [L] Logs  [R] Rescan Site  [H] Help  [Q] Quit

Menu
  Home
  Logs
  Doctor
  Diagnostics
  Tor
  Network
  Site
  Settings
  Help
```

## Quick Start

RustHost requires Rust 1.90 or newer.

```bash
cargo build --release
./target/release/rusthost-cli --version
```

Managed mode creates a persistent data directory with `settings.toml`, `site/`, and `runtime/`:

```bash
./target/release/rusthost-cli --data-dir ./rusthost-data
```

For one-shot local serving without creating a managed config:

```bash
./target/release/rusthost-cli --serve ./public
```

## Installation and Build

### Build From Source

```bash
git clone https://github.com/csd113/RustHost.git
cd RustHost
cargo build --release
```

The release binary is written to:

```text
./target/release/rusthost-cli
```

### Release Archives

Tagged releases are packaged by the repository release workflow as platform-specific ZIP archives containing:

- `rusthost-cli`
- `README.md`
- `LICENSE`

## Basic Usage

### Version and Diagnostics

```bash
./target/release/rusthost-cli --version
./target/release/rusthost-cli doctor
./target/release/rusthost-cli doctor --data-dir ./rusthost-data
```

`--version` prints the RustHost version plus build profile, short commit, and target triple.

`doctor` validates an existing RustHost configuration. When you pass `--data-dir`, that directory is expected to already contain `settings.toml`.

### Interactive TUI Launch

```bash
./target/release/rusthost-cli
./target/release/rusthost-cli --data-dir ./rusthost-data
```

Interactive mode is enabled by default for managed runs unless disabled in config or with `--headless`.

### Headless / Server-Style Launch

```bash
./target/release/rusthost-cli --headless
./target/release/rusthost-cli --data-dir ./rusthost-data --headless
```

Headless mode is intended for service managers, CI, and remote-shell environments.

### One-Shot Directory Serving

```bash
./target/release/rusthost-cli --serve ./public
./target/release/rusthost-cli --serve ./public --port 3000
./target/release/rusthost-cli --serve ./public --headless
./target/release/rusthost-cli --serve ./public --no-tor
```

In `--serve` mode, RustHost:

- Serves the target directory directly without writing a persistent `settings.toml`
- Binds to `127.0.0.1`
- Enables directory listings
- Disables file logging
- Uses Tor unless `--no-tor` is supplied

## Configuration Overview

The generated `settings.toml` is the primary control surface. By default, RustHost creates:

```text
rusthost-data/
  settings.toml
  site/
  runtime/
```

### Key Defaults

| Area | Default behavior |
| --- | --- |
| Site root | `site`, relative to the active data directory |
| Runtime data | `runtime/` under the active data directory |
| HTTP | Enabled on `127.0.0.1:8080` |
| HTTPS / TLS | Disabled by default; optional listener on `8443` when enabled |
| Tor | Enabled by default in generated configs |
| Favicon | `/favicon.ico` serves `site/favicon.ico` by default |
| Logging | Enabled by default, file path `runtime/logs/rusthost.log` |
| Console | Interactive TUI enabled by default in managed mode |

### Main Sections

| Section | Purpose |
| --- | --- |
| `[server]` | Bind address, port, connection limits, CSP preset, trusted proxies, browser opening |
| `[site]` | Site directory, index file, favicon, directory listing, dotfile exposure, SPA fallback, custom error pages |
| `[tls]` | HTTPS listener, redirect behavior, ACME, manual certificates |
| `[tor]` | Onion service enablement and Tor shutdown grace period |
| `[logging]` | Log level, log file path, dependency log filtering |
| `[console]` | Interactive dashboard behavior |
| `[identity]` | Dashboard instance name |
| `[[redirects]]` | Exact-path redirects evaluated before filesystem resolution |

### Minimal Local HTTP Example

```toml
[server]
bind = "127.0.0.1"
port = 8080

[site]
directory = "site"
index_file = "index.html"
```

### HTTP / HTTPS / TLS

- Plain HTTP is enabled by default on the configured `[server]` bind and port.
- HTTPS is optional and supports self-signed localhost certificates, manual PEM files, and ACME-managed certificates.
- `redirect_http = true` is only valid when TLS is enabled.
- When redirect mode is active, the plain HTTP listener acts as a redirect listener instead of serving files.

### Tor Support

- RustHost uses Arti in-process for onion service hosting.
- No external Tor binary is required.
- Tor state and cache live under the runtime data directory.
- The same static site can be served over clearnet HTTP/HTTPS and `.onion` access.

### Favicon Handling

- `/favicon.ico` is served from `[site].favicon`, which defaults to `favicon.ico` under the site root.
- Favicon paths are validated to stay within the site directory.
- PNG favicons are opt-in through `[site].enable_png_favicon = true`.
- `.ico`, `.png`, and `.svg` favicon source files are supported by config validation.

### Logging and Diagnostics

- Application logging is enabled by default in managed mode.
- The default log file path is `runtime/logs/rusthost.log`.
- `rusthost-cli doctor` records its report to `doctor.log` in the active runtime log path.
- The TUI Diagnostics page provides a compact operator snapshot for troubleshooting and support handoff.

## Operational Endpoints

| Endpoint | Purpose |
| --- | --- |
| `/health` | Liveness check that returns a simple `OK` response |
| `/ready` | Readiness check that returns `READY` only after startup completes and active directories are usable |

Example:

```bash
curl -i http://127.0.0.1:8080/health
curl -i http://127.0.0.1:8080/ready
```

## Doctor and Diagnostics

`rusthost-cli doctor` is the built-in preflight check. It is designed to validate whether RustHost is ready to start and whether key runtime assumptions hold for the active configuration.

Doctor checks cover:

- Config loading and validation
- Data, site, and runtime paths
- Local listener assumptions
- TLS and redirect configuration
- Tor enablement and runtime expectations
- Favicon setup
- Logging path availability

The TUI Doctor page presents these checks as `PASS`, `WARN`, `FAIL`, and `NOT RUN`, and can run bounded deep checks without starting a public probe workflow.

## TUI Menu Overview

| Page | Purpose |
| --- | --- |
| Home | Main dashboard with current runtime status |
| Logs | Recent RustHost log output |
| Doctor | Readiness checks for config, paths, ports, TLS, Tor, favicon, and runtime safety |
| Diagnostics | Compact runtime snapshot for troubleshooting |
| Tor | Onion service status and Tor-specific runtime details |
| Network | Bind addresses, ports, HTTPS, and local reachability checks |
| Site | Configured site directory and primary served files |
| Settings | Effective runtime settings and configuration choices |
| Help | Console controls and command guidance |

Useful controls:

- `M` opens the menu from the home screen
- `L` opens the log view from Home
- `R` rescans site files and runtime state from the dashboard
- `Esc` returns to the previous page
- `Q` quits from Home or Menu

## Security and Production Notes

- RustHost is for static content serving. It does not provide users, sessions, uploads, or an admin auth layer.
- Keep `bind = "127.0.0.1"` for local-only use; expose `0.0.0.0` or a public interface only when the host firewall and deployment model are intentional.
- Review site contents before exposure. RustHost serves static files and will not classify which files are sensitive.
- `/ready` fails closed until startup completes and active directories are usable.
- Favicon paths are constrained to the site root, and redirects are validated before use.
- If you need authenticated operator access or complex ingress policy, place RustHost behind another service that provides it.

## Platform Support

Based on the current CI and release workflows, RustHost is actively checked on:

- Ubuntu 24.04 for formatting, linting, tests, and release builds
- Linux ARM64, macOS Apple Silicon, and Windows x86_64 for platform smoke builds

Release archives are built for:

- `x86_64-unknown-linux-gnu`
- `aarch64-unknown-linux-gnu`
- `aarch64-apple-darwin`
- `x86_64-pc-windows-msvc`

Other Rust-supported targets may work, but they are not covered by the repository workflows listed above.

## Development

Local validation commands:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
```

CI uses a stricter Clippy gate in `.github/workflows/ci.yml`, including `clippy::pedantic`, `clippy::nursery`, and `clippy::cargo`.

## Release Notes and Changelog

- [Changelog](CHANGELOG.md)
- [Release workflow](.github/workflows/release.yml)

## License

RustHost is licensed under the [MIT License](LICENSE).
