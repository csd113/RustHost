```
██████╗ ██╗   ██╗███████╗████████╗██╗  ██╗ ██████╗ ███████╗████████╗
██╔══██╗██║   ██║██╔════╝╚══██╔══╝██║  ██║██╔═══██╗██╔════╝╚══██╔══╝
██████╔╝██║   ██║███████╗   ██║   ███████║██║   ██║███████╗   ██║
██╔══██╗██║   ██║╚════██║   ██║   ██╔══██║██║   ██║╚════██║   ██║
██║  ██║╚██████╔╝███████║   ██║   ██║  ██║╚██████╔╝███████║   ██║
╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝
```

<div align="center">

**A self-contained static file server with first-class Tor onion service support — no binaries, no `torrc`, no compromise.**

[![Rust](https://img.shields.io/badge/rust-1.86%2B-orange?style=flat-square&logo=rust)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue?style=flat-square)](LICENSE)
[![Tor: Arti](https://img.shields.io/badge/tor-arti%20in--process-7d4698?style=flat-square)](https://gitlab.torproject.org/tpo/core/arti)
[![Async: Tokio](https://img.shields.io/badge/async-tokio-49a?style=flat-square)](https://tokio.rs/)
[![Security: cargo-deny](https://img.shields.io/badge/security-cargo--deny-red?style=flat-square)](https://embarkstudios.github.io/cargo-deny/)

</div>

---

## What is RustHost?

RustHost is a single-binary static file server that brings your content to the clearnet **and** the Tor network simultaneously — with zero external dependencies. Tor is embedded directly into the process via [Arti](https://gitlab.torproject.org/tpo/core/arti), the official Rust Tor implementation. No `tor` daemon, no `torrc`, no system configuration required.

Drop the binary next to your site files, run it once, and you get:

- A local HTTP server ready for immediate use
- A stable `.onion` v3 address that survives restarts
- A live terminal dashboard showing you everything at a glance

```
┌─ RustHost ─────────────────────────────────────────────────────────┐
│                                                                      │
│  STATUS        ● RUNNING   127.0.0.1:8080                           │
│  TOR           ● READY                                              │
│                                                                      │
│  ENDPOINTS     http://localhost:8080                                 │
│                abcdef1234567890abcdef1234567890abcdef12.onion        │
│                                                                      │
│  SITE          ./rusthost-data/site   ·  12 files  ·  4.2 MB        │
│  ACTIVITY      847 requests  ·  0 errors                            │
│                                                                      │
│  [L] Logs   [R] Reload   [H] Help   [Q] Quit                        │
└──────────────────────────────────────────────────────────────────────┘
```

![rystgit](https://github.com/user-attachments/assets/30752d0f-5be2-4c80-b3a2-4fa0530ff3ab)

---

## Features

### 🌐 HTTP Server
- Built directly on `tokio::net::TcpListener` — no HTTP framework dependency
- Handles `GET` and `HEAD` requests; concurrent connections via per-task Tokio workers
- **Buffered request reading** via `tokio::io::BufReader` — headers read line-by-line, not byte-by-byte
- **File streaming** via `tokio::io::copy` — memory per connection is bounded by the socket buffer (~256 KB) regardless of file size
- **30-second request timeout** (configurable via `request_timeout_secs`); slow or idle connections receive `408 Request Timeout`
- **Semaphore-based connection limit** (configurable via `max_connections`, default 256) — excess connections queue at the OS backlog level rather than spawning unbounded tasks
- Percent-decoded URL paths with correct multi-byte UTF-8 handling; null bytes (`%00`) are never decoded
- Query string & fragment stripping before path resolution
- **Path traversal protection** — every path verified as a descendant of the site root via `canonicalize` (called once at startup, not per request); escapes rejected with `403 Forbidden`
- Configurable index file, optional HTML directory listing with fully HTML-escaped and URL-encoded filenames, and a built-in fallback page
- Automatic port selection if the configured port is busy (up to 10 attempts)
- Request header cap at 8 KiB; `Content-Type`, `Content-Length`, and `Connection: close` on every response
- **Security headers on every response**: `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy: no-referrer`, `Permissions-Policy`; configurable `Content-Security-Policy` on HTML responses
- **HEAD responses** include correct `Content-Length` but no body, as required by RFC 7231 §4.3.2
- Accept loop uses **exponential backoff** on errors and distinguishes `EMFILE` (operator-level error) from transient errors (`ECONNRESET`, `ECONNABORTED`)

### 🧅 Tor Onion Service *(fully working)*
- Embedded via [Arti](https://gitlab.torproject.org/tpo/core/arti) — the official Rust Tor client — in-process, no external daemon
- Bootstraps to the Tor network in the background; never blocks your server or dashboard
- **Stable address**: the v3 service keypair is persisted to `rusthost-data/arti_state/`. Delete the directory to rotate to a new address
- First run fetches ~2 MB of directory data (~30 s); subsequent starts reuse the cache and are up in seconds
- Onion address computed fully in-process using the v3 spec (SHA3-256 + base32)
- Each inbound Tor connection is bridged to the local HTTP listener via `tokio::io::copy_bidirectional`
- **Port synchronised via `oneshot` channel** — the Tor subsystem always receives the actual bound port, eliminating a race condition that could cause silent connection failures
- **`TorStatus` reflects mid-session failures** — if the onion service stream terminates unexpectedly, the dashboard transitions to `FAILED (reason)` and clears the displayed `.onion` address
- Participates in **graceful shutdown** — the run loop watches the shutdown signal via `tokio::select!` and exits cleanly
- Can be disabled entirely with `[tor] enabled = false`

### 🖥️ Interactive Terminal Dashboard
- Full-screen raw-mode TUI built with [crossterm](https://github.com/crossterm-rs/crossterm) — no TUI framework
- Three screens, all keyboard-navigable:

  | Key | Screen |
  |-----|--------|
  | *(default)* | **Dashboard** — live status, endpoints, site stats, request/error counters |
  | `L` | **Log view** — last 40 log lines with optional timestamps |
  | `H` | **Help overlay** — key binding reference |
  | `R` | Reload site file count & size without restart |
  | `Q` | Graceful shutdown |

- **Skip-on-idle rendering** — the terminal is only written when the rendered output changes, eliminating unnecessary writes on quiet servers
- `TorStatus::Failed` displays a human-readable reason string (e.g. `FAILED (stream ended)`) rather than a bare error indicator
- Keyboard input task failure is detected and reported; the process remains killable via Ctrl-C
- **Terminal fully restored on all exit paths** — panic hook and error handler both call `console::cleanup()` before exiting, ensuring `LeaveAlternateScreen`, `cursor::Show`, and `disable_raw_mode` always run
- Configurable refresh rate (default 500 ms); headless mode available for `systemd` / piped deployments

### ⚙️ Configuration
- TOML file at `rusthost-data/settings.toml`, auto-generated with inline comments on first run
- Six sections: `[server]`, `[site]`, `[tor]`, `[logging]`, `[console]`, `[identity]`
- **`#[serde(deny_unknown_fields)]`** on all structs — typos in key names are rejected at startup with a clear error
- **Typed config fields** — `bind` is `IpAddr`, `log level` is a `LogLevel` enum; invalid values are caught at deserialisation time
- Startup validation with clear, multi-error messages — nothing starts until config is clean
- Config and data directory paths overridable via **`--config <path>`** and **`--data-dir <path>`** CLI flags

### 📝 Logging
- Custom `log::Log` implementation; dual output — append-mode log file + in-memory ring buffer (1 000 lines)
- Ring buffer feeds the dashboard log view with zero file I/O per render tick
- **Dependency log filtering** — Arti and Tokio internals at `Info` and below are suppressed by default, keeping the log focused on application events (configurable via `filter_dependencies`)
- Log file explicitly flushed on graceful shutdown
- Configurable level (`trace` → `error`) and optional full disable for minimal-overhead deployments

### 🧪 Testing & CI
- Unit tests for all security-critical functions: `percent_decode`, `resolve_path`, `validate`, `strip_timestamp`, `hsid_to_onion_address`
- Integration tests (`tests/http_integration.rs`) covering all HTTP core flows via raw `TcpStream`
- `cargo deny check` runs in CI, enforcing the SPDX license allowlist and advisory database; `audit.toml` consolidated into `deny.toml`

---

## Quick Start

### 1. Build

```bash
git clone https://github.com/yourname/rusthost
cd rusthost
cargo build --release
```

> **Minimum Rust version: 1.86** (required by `arti-client 0.40`)

### 2. First run — initialise your data directory

```bash
./target/release/rusthost
```

On first run, RustHost detects that `rusthost-data/settings.toml` is missing, scaffolds the data directory, writes a default config and a placeholder `index.html`, prints a getting-started guide, and exits. Nothing is daemonised yet.

```
rusthost-data/
├── settings.toml       ← your config (edit freely)
├── site/
│   └── index.html      ← placeholder, replace with your files
├── logs/
│   └── rusthost.log
├── arti_cache/         ← Tor directory consensus (auto-managed)
└── arti_state/         ← your stable .onion keypair (back this up!)
```

### 3. Serve

```bash
./target/release/rusthost
```

The dashboard appears. Your site is live on `http://localhost:8080`. Tor bootstraps in the background — your `.onion` address appears in the **Endpoints** panel once ready (~30 s on first run).

### CLI flags

```
rusthost [OPTIONS]

Options:
  --config <path>      Path to settings.toml (default: rusthost-data/settings.toml)
  --data-dir <path>    Path to data directory (default: rusthost-data/ next to binary)
  --version            Print version and exit
  --help               Print this help and exit
```

---

## Configuration Reference

```toml
[server]
port                   = 8080
bind                   = "127.0.0.1"          # set "0.0.0.0" to expose on LAN (logs a warning)
index_file             = "index.html"
directory_listing      = false
auto_port_fallback     = true
max_connections        = 256                   # semaphore cap on concurrent connections
request_timeout_secs   = 30                   # seconds before idle connection receives 408
content_security_policy = "default-src 'self'" # applied to HTML responses only

[site]
root = "rusthost-data/site"

[tor]
enabled = true                                 # set false to skip Tor entirely

[logging]
enabled              = true
level                = "info"                  # trace | debug | info | warn | error
path                 = "logs/rusthost.log"
filter_dependencies  = true                    # suppress Arti/Tokio noise at info and below

[console]
interactive           = true                   # false for systemd / piped deployments
refresh_ms            = 500                    # minimum 100
show_timestamps       = false
open_browser_on_start = false

[identity]
name = "RustHost"                              # 1–32 chars, shown in dashboard header
```

---

## Built-in MIME Types

No external dependency. RustHost ships with a handwritten extension map covering:

| Category | Extensions |
|----------|-----------|
| Text | `html` `htm` `css` `js` `mjs` `txt` `csv` `xml` `md` |
| Data | `json` `jsonld` `pdf` `wasm` `zip` |
| Images | `png` `jpg/jpeg` `gif` `webp` `svg` `ico` `bmp` `avif` |
| Fonts | `woff` `woff2` `ttf` `otf` |
| Audio | `mp3` `ogg` `wav` |
| Video | `mp4` `webm` |

Unknown extensions fall back to `application/octet-stream`.

---

## Architecture

```
                ┌─────────────────────────────────────┐
                │             RustHost Process         │
                │                                      │
  Browser ──────┤──► tokio TcpListener (HTTP)          │
                │         │                            │
  Tor Network ──┤──► Arti (in-process) ──► bridge ────►┤
                │                          task        │
                │         │                            │
                │    Arc<AppState>  Arc<Metrics>        │
                │         │                            │
                │    crossterm TUI (raw mode)           │
                └─────────────────────────────────────┘
```

All subsystems share state through `Arc<RwLock<AppState>>`. Hot-path request and error counters use a separate `Arc<Metrics>` backed by atomics — the HTTP handler **never acquires a lock per request**.

The HTTP server and Tor subsystem share a `tokio::sync::Semaphore` that caps concurrent connections. The bound port is communicated to Tor via a `oneshot` channel before the accept loop begins, eliminating the startup race condition present in earlier versions.

Shutdown is coordinated via a `watch` channel: `[Q]`, `SIGINT`, or `SIGTERM` signals all subsystems simultaneously. In-flight HTTP connections are tracked in a `JoinSet` and given up to 5 seconds to complete. The log file is explicitly flushed before the process exits.

---

## Security

| Concern | Mitigation |
|---------|-----------|
| Path traversal (requests) | `std::fs::canonicalize` + descendant check per request; `403` on escape |
| Path traversal (config) | `site.directory` and `logging.file` validated against `..`, absolute paths, and path separators at startup |
| Directory listing XSS | Filenames HTML-entity-escaped in link text; percent-encoded in `href` attributes |
| Header overflow | 8 KiB hard cap; oversized requests rejected immediately |
| Slow-loris DoS | 30-second request timeout; `408` sent on expiry |
| Connection exhaustion | Semaphore cap (default 256); excess connections queue at OS level |
| Memory exhaustion (large files) | Files streamed via `tokio::io::copy`; per-connection memory bounded by socket buffer |
| Bind exposure | Defaults to loopback (`127.0.0.1`); warns loudly on `0.0.0.0` |
| ANSI/terminal injection | `instance_name` validated against all control characters (`is_control`) at startup |
| Security response headers | `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy: no-referrer`, `Permissions-Policy`, configurable `Content-Security-Policy` |
| `.onion` URL leakage | `Referrer-Policy: no-referrer` prevents the `.onion` address from appearing in `Referer` headers sent to third-party resources |
| Tor port race | Bound port delivered to Tor via `oneshot` channel before accept loop starts |
| Silent Tor failure | `TorStatus` transitions to `Failed(reason)` and onion address is cleared when the service stream ends |
| Percent-decode correctness | Multi-byte UTF-8 sequences decoded correctly; null bytes (`%00`) never decoded |
| Config typos | `#[serde(deny_unknown_fields)]` on all structs |
| License compliance | `cargo-deny` enforces SPDX allowlist at CI time |
| [RUSTSEC-2023-0071](https://rustsec.org/advisories/RUSTSEC-2023-0071) | Suppressed with rationale in `deny.toml`: the `rsa` crate is a transitive dep of `arti-client` used **only** for signature *verification* on Tor directory documents — the Marvin timing attack's threat model (decryption oracle) does not apply |

---

## License

MIT — see [LICENSE](LICENSE).

---

<div align="center">
<sub>Built with Rust 🦀 · Powered by <a href="https://tokio.rs">Tokio</a> · Tor via <a href="https://gitlab.torproject.org/tpo/core/arti">Arti</a></sub>
</div>
