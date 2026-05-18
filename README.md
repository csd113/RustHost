# RustHost

> Single-binary static file server with HTTP, HTTPS, and built-in Tor onion service support.

[![CI](https://github.com/csd113/RustHost/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/csd113/RustHost/actions/workflows/ci.yml)
[![Dependency Audit](https://github.com/csd113/RustHost/actions/workflows/audit.yml/badge.svg)](https://github.com/csd113/RustHost/actions/workflows/audit.yml)
[![License: MIT](https://img.shields.io/github/license/csd113/RustHost)](LICENSE)
[![Rust 1.90+](https://img.shields.io/badge/rust-1.90%2B-orange)](Cargo.toml)
[![Version](https://img.shields.io/badge/version-v1.0.0-blue)](CHANGELOG.md)
[![Platforms](https://img.shields.io/badge/platforms-Linux%20%7C%20macOS%20%7C%20Windows-3b82f6)](.github/workflows/ci.yml)

RustHost is a production-focused static file server written in Rust. Drop in a directory, configure `settings.toml`, and get HTTP, optional HTTPS (self-signed, manual, or ACME), and an in-process Tor onion service — all from one binary.

It is intentionally narrow in scope: no web framework, no CMS, no reverse proxy, no auth layer. Just explicit, inspectable static hosting.

---

## Table of Contents

- [Features](#features)
- [Quick Start](#quick-start)
- [Installation](#installation)
- [Usage](#usage)
- [Configuration](#configuration)
- [Operational Endpoints](#operational-endpoints)
- [Doctor and Diagnostics](#doctor-and-diagnostics)
- [TUI Overview](#tui-overview)
- [Security Notes](#security-notes)
- [Platform Support](#platform-support)
- [Development](#development)
- [License](#license)

---

## Features

| Area | Details |
|---|---|
| **Static hosting** | HTTP/1.1 keep-alive, `GET` / `HEAD` / `OPTIONS`, ETag & `Last-Modified`, range requests, compression, precompressed sidecars, SPA fallback, custom error pages, optional directory listings |
| **HTTPS** | Self-signed localhost certs, manual PEM loading, ACME / Let's Encrypt, optional HTTP→HTTPS redirect |
| **Tor** | In-process onion service via [Arti](https://gitlab.torproject.org/tpo/core/arti) — no external Tor daemon required |
| **Operations** | `/health`, `/ready`, headless mode, graceful shutdown, structured logging, connection limits |
| **TUI** | Interactive terminal dashboard with Home, Logs, Doctor, Diagnostics, Tor, Network, Site, Settings, and Help pages |
| **Diagnostics** | `rusthost-cli doctor` command, runtime snapshots, build-aware `--version`, readiness checks for config, TLS, Tor, paths, and logging |

---

## Quick Start

Requires Rust 1.90+.

```bash
git clone https://github.com/csd113/RustHost.git
cd RustHost
cargo build --release
```

**Managed mode** — creates a persistent data directory with `settings.toml`, `site/`, and `runtime/`:

```bash
./target/release/rusthost-cli --data-dir ./rusthost-data
```

**One-shot mode** — serve a directory immediately, no config file written:

```bash
./target/release/rusthost-cli --serve ./public
```

---

## Installation

### Build from Source

```bash
git clone https://github.com/csd113/RustHost.git
cd RustHost
cargo build --release
# Binary at: ./target/release/rusthost-cli
```

### Release Archives

Tagged releases ship as platform-specific ZIP archives containing the `rusthost-cli` binary, `README.md`, and `LICENSE`. Available targets:

| Target | Platform |
|---|---|
| `x86_64-unknown-linux-gnu` | Linux x86_64 |
| `aarch64-unknown-linux-gnu` | Linux ARM64 |
| `aarch64-apple-darwin` | macOS Apple Silicon |
| `x86_64-pc-windows-msvc` | Windows x86_64 |

---

## Usage

### Version and Build Info

```bash
./target/release/rusthost-cli --version
```

Prints the version, build profile, short commit hash, and target triple.

### Interactive TUI

```bash
# With a managed data directory
./target/release/rusthost-cli --data-dir ./rusthost-data

# Default (no data-dir flag)
./target/release/rusthost-cli
```

### Headless / Service Mode

Disables the TUI — intended for service managers, CI, and remote-shell environments.

```bash
./target/release/rusthost-cli --headless
./target/release/rusthost-cli --data-dir ./rusthost-data --headless
```

### One-Shot Directory Serving

Serves a directory directly without writing a persistent `settings.toml`. Binds to `127.0.0.1`, enables directory listings, disables file logging, and enables Tor by default.

```bash
./target/release/rusthost-cli --serve ./public
./target/release/rusthost-cli --serve ./public --port 3000
./target/release/rusthost-cli --serve ./public --headless
./target/release/rusthost-cli --serve ./public --no-tor
```

### Validate an Existing Config

```bash
./target/release/rusthost-cli doctor
./target/release/rusthost-cli doctor --data-dir ./rusthost-data
```

---

## Configuration

In managed mode, RustHost generates the following directory structure:

```
rusthost-data/
  settings.toml   ← primary config
  site/           ← static files to serve
  runtime/        ← logs, TLS state, Tor state
```

### Defaults

| Setting | Default |
|---|---|
| Site root | `site/` (relative to data directory) |
| HTTP | `127.0.0.1:8080` |
| HTTPS | Disabled (optional listener on `8443`) |
| Tor | Enabled |
| Favicon | `site/favicon.ico` |
| Logging | Enabled — `runtime/logs/rusthost.log` |
| Console | Interactive TUI enabled |

### Configuration Sections

| Section | Purpose |
|---|---|
| `[server]` | Bind address, port, connection limits, CSP preset, trusted proxies |
| `[site]` | Site directory, index file, favicon, directory listing, dotfiles, SPA fallback, custom error pages |
| `[tls]` | HTTPS listener, redirect behavior, ACME, manual PEM certificates |
| `[tor]` | Onion service enablement and shutdown grace period |
| `[logging]` | Log level, log file path, dependency log filtering |
| `[console]` | Interactive dashboard behavior |
| `[identity]` | Dashboard instance name |
| `[[redirects]]` | Exact-path redirects evaluated before filesystem resolution |

### Minimal Example

```toml
[server]
bind = "127.0.0.1"
port = 8080

[site]
directory = "site"
index_file = "index.html"
```

### HTTPS / TLS

- HTTPS is optional. When enabled, it supports self-signed localhost certs, manual PEM files, and ACME-managed certificates.
- `redirect_http = true` requires TLS to be enabled. When active, the HTTP listener redirects rather than serves files.

### Tor

RustHost uses [Arti](https://gitlab.torproject.org/tpo/core/arti) in-process — no external `tor` binary needed. Tor state and cache are stored under `runtime/`. The same site can be accessible over HTTP/HTTPS and `.onion` simultaneously.

### Favicon

- `/favicon.ico` is served from `[site].favicon` (defaults to `favicon.ico` in the site root).
- Favicon paths are validated to stay within the site directory.
- Supported formats: `.ico`, `.png`, `.svg`. PNG serving requires `[site].enable_png_favicon = true`.

---

## Operational Endpoints

| Endpoint | Behavior |
|---|---|
| `/health` | Returns `OK` — basic liveness check |
| `/ready` | Returns `READY` only after startup completes and active directories are confirmed usable |

```bash
curl -i http://127.0.0.1:8080/health
curl -i http://127.0.0.1:8080/ready
```

---

## Doctor and Diagnostics

`rusthost-cli doctor` is a preflight validator. It checks whether RustHost is ready to start and whether runtime assumptions hold for the current configuration.

Checks include config loading, path availability, listener assumptions, TLS and redirect configuration, Tor setup, favicon resolution, and log path availability.

Results are reported as `PASS`, `WARN`, `FAIL`, or `NOT RUN`. The TUI Doctor page can also run these checks interactively without starting any public listeners.

Doctor output is logged to `doctor.log` in the active runtime log path.

---

## TUI Overview

```
RustHost 1.0.0
HTTP   : http://127.0.0.1:8080
HTTPS  : disabled
Tor    : ready
Site   : ./rusthost-data/site
Logs   : ./rusthost-data/runtime/logs/rusthost.log

[M] Menu  [L] Logs  [R] Rescan  [H] Help  [Q] Quit
```

| Page | Purpose |
|---|---|
| Home | Runtime status dashboard |
| Logs | Recent log output |
| Doctor | Readiness checks for config, paths, ports, TLS, Tor, and favicon |
| Diagnostics | Compact runtime snapshot for troubleshooting |
| Tor | Onion service status and Tor runtime details |
| Network | Bind addresses, ports, HTTPS, and local reachability |
| Site | Configured site directory and primary served files |
| Settings | Effective runtime settings |
| Help | Console controls and guidance |

**Key bindings:** `M` — menu, `L` — logs, `R` — rescan, `Esc` — back, `Q` — quit.

---

## Security Notes

- RustHost serves static files only. There are no users, sessions, file uploads, or admin auth endpoints.
- Default bind is `127.0.0.1`. Only bind to `0.0.0.0` or a public interface when your firewall and deployment model are intentional.
- `/ready` fails closed until startup completes and active directories are confirmed usable.
- Favicon paths are constrained to the site root. Redirects are validated before use.
- Review site contents before public exposure — RustHost will not classify files as sensitive.
- For authenticated operator access or complex ingress policy, place RustHost behind a service that provides it.

---

## Platform Support

Actively tested in CI on:

- **Ubuntu 24.04** — formatting, linting, tests, and release builds
- **Linux ARM64, macOS Apple Silicon, Windows x86_64** — platform smoke builds

Other Rust-supported targets may work but are not covered by the repository workflows.

---

## Development

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
```

CI enforces a stricter Clippy gate including `clippy::pedantic`, `clippy::nursery`, and `clippy::cargo`.

See [CHANGELOG.md](CHANGELOG.md) and the [release workflow](.github/workflows/release.yml) for version history and release automation.

---

## License

RustHost is released under the [MIT License](LICENSE).
