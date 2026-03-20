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

---

## Features

### 🌐 HTTP Server
- Built directly on `tokio::net::TcpListener` — no HTTP framework dependency
- Handles `GET` and `HEAD` requests; concurrent connections via per-task Tokio workers
- Percent-decoded URL paths, query string & fragment stripping
- **Path traversal protection** — every path verified as a descendant of the site root via `canonicalize`; escapes rejected with `403 Forbidden`
- Configurable index file, optional HTML directory listings, and a built-in fallback page
- Automatic port selection if the configured port is busy (up to 10 attempts)
- Request header cap at 8 KiB; `Content-Type`, `Content-Length`, and `Connection: close` on every response

### 🧅 Tor Onion Service *(fully working)*
- Embedded via [Arti](https://gitlab.torproject.org/tpo/core/arti) — the official Rust Tor client — in-process, no external daemon
- Bootstraps to the Tor network in the background; never blocks your server or dashboard
- **Stable address**: the v3 service keypair is persisted to `rusthost-data/arti_state/`. Delete the directory to rotate to a new address
- First run fetches ~2 MB of directory data (~30 s); subsequent starts reuse the cache and are up in seconds
- Onion address computed fully in-process using the v3 spec (SHA3-256 + base32)
- Each inbound Tor connection is bridged to the local HTTP listener via `tokio::io::copy_bidirectional`
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

- Configurable refresh rate (default 500 ms); headless mode available for `systemd` / piped deployments

### ⚙️ Configuration
- TOML file at `rusthost-data/settings.toml`, auto-generated with inline comments on first run
- Six sections: `[server]`, `[site]`, `[tor]`, `[logging]`, `[console]`, `[identity]`
- Startup validation with clear, multi-error messages — nothing starts until config is clean

### 📝 Logging
- Custom `log::Log` implementation; dual output — append-mode log file + in-memory ring buffer (1 000 lines)
- Ring buffer feeds the dashboard log view with zero file I/O per render tick
- Configurable level (`trace` → `error`) and optional full disable for minimal-overhead deployments

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

---

## Configuration Reference

```toml
[server]
port             = 8080
bind             = "127.0.0.1"   # set "0.0.0.0" to expose on LAN (logs a warning)
index_file       = "index.html"
directory_listing = false
auto_port_fallback = true

[site]
root = "rusthost-data/site"

[tor]
enabled = true                   # set false to skip Tor entirely

[logging]
enabled  = true
level    = "info"                # trace | debug | info | warn | error
path     = "logs/rusthost.log"

[console]
interactive       = true         # false for systemd / piped deployments
refresh_ms        = 500          # minimum 100
show_timestamps   = false
open_browser_on_start = false

[identity]
name = "RustHost"                # 1–32 chars, shown in dashboard header
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

Shutdown is coordinated via a `watch` channel: `[Q]`, `SIGINT`, or `SIGTERM` signals all subsystems simultaneously, waits 300 ms for in-flight connections, then exits. The Tor client is dropped naturally with the Tokio runtime — no explicit kill step needed.

---

## Security

| Concern | Mitigation |
|---------|-----------|
| Path traversal | `std::fs::canonicalize` + descendant check; returns `403` on escape |
| Header overflow | 8 KiB hard cap; oversized requests rejected immediately |
| Bind exposure | Defaults to loopback (`127.0.0.1`); warns loudly on `0.0.0.0` |
| License compliance | `cargo-deny` enforces SPDX allowlist at CI time |
| [RUSTSEC-2023-0071](https://rustsec.org/advisories/RUSTSEC-2023-0071) | Suppressed with rationale: the `rsa` crate is a transitive dep of `arti-client` used **only** for signature *verification* on Tor directory documents — the Marvin timing attack's threat model (decryption oracle) does not apply |

---

## License

MIT — see [LICENSE](LICENSE).

---

<div align="center">
<sub>Built with Rust 🦀 · Powered by <a href="https://tokio.rs">Tokio</a> · Tor via <a href="https://gitlab.torproject.org/tpo/core/arti">Arti</a></sub>
</div>
