```
██████╗ ██╗   ██╗███████╗████████╗██╗  ██╗ ██████╗ ███████╗████████╗
██╔══██╗██║   ██║██╔════╝╚══██╔══╝██║  ██║██╔═══██╗██╔════╝╚══██╔══╝
██████╔╝██║   ██║███████╗   ██║   ███████║██║   ██║███████╗   ██║
██╔══██╗██║   ██║╚════██║   ██║   ██╔══██║██║   ██║╚════██║   ██║
██║  ██║╚██████╔╝███████║   ██║   ██║  ██║╚██████╔╝███████║   ██║
╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝
```

<div align="center">

**A single-binary static file server with built-in Tor onion service support.**
No daemons. No config files outside this project. No compromise.

[![Rust](https://img.shields.io/badge/rust-1.86%2B-orange?style=flat-square&logo=rust)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue?style=flat-square)](LICENSE)
[![Tor: Arti](https://img.shields.io/badge/tor-arti%20in--process-7d4698?style=flat-square)](https://gitlab.torproject.org/tpo/core/arti)
[![Async: Tokio](https://img.shields.io/badge/async-tokio-49a?style=flat-square)](https://tokio.rs/)
[![Security: cargo-deny](https://img.shields.io/badge/security-cargo--deny-red?style=flat-square)](https://embarkstudios.github.io/cargo-deny/)

</div>

---

## What is RustHost?

RustHost is a static file server — you give it a folder of HTML, CSS, and JavaScript files, and it serves them over HTTP. What makes it different is that it also puts your site on the **Tor network** automatically, giving every site a `.onion` address right alongside the normal `localhost` one.

It's a single binary with Tor baked in. No installing a separate Tor program, no editing system config files.

**Who is it for?** Developers who want a quick local server with privacy features, self-hosters who want their sites reachable over Tor, and anyone who wants to run a personal site without touching system-level config.

---

## What it looks like

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

![rusthost screenshot](https://github.com/user-attachments/assets/30752d0f-5be2-4c80-b3a2-4fa0530ff3ab)

---

## Key Features

- **Static file server** — serves HTML, CSS, JS, images, fonts, audio, and video with correct MIME types
- **Built-in Tor support** — your site gets a stable `.onion` address automatically, no external Tor install needed
- **Live terminal dashboard** — shows your endpoints, request counts, and logs in a clean full-screen UI
- **Single binary** — no installer, no runtime dependencies, no system packages to manage
- **SPA-friendly** — supports React, Vue, and Svelte client-side routing with a fallback-to-`index.html` option
- **HTTP protocol done right** — keep-alive, `ETag`/conditional GET, range requests, Brotli/Gzip compression
- **Security headers out of the box** — CSP, HSTS, `X-Content-Type-Options`, `Referrer-Policy`, and more on every response
- **Rate limiting per IP** — lock-free connection cap prevents a single client from taking down your server
- **Per-IP connection limits**, request timeouts, path traversal protection, and header injection prevention
- **Hot reload** — press `[R]` to refresh site stats without restarting
- **Headless mode** — run it in the background under systemd without the TUI

---

## Why Arti instead of the regular Tor?

When most people think of Tor, they think of the `tor` binary — a program written in C that you install separately and talk to via a config file called `torrc`. That works fine, but it means your application depends on an external process you don't control.

**Arti** is the [official Tor Project rewrite of Tor in Rust](https://gitlab.torproject.org/tpo/core/arti). RustHost uses it as a library — Tor runs *inside* the same process as your server, with no external daemon.

Here's a plain-English comparison:

| | Classic `tor` binary | Arti (what RustHost uses) |
|---|---|---|
| Language | C | Rust |
| Memory safety | Manual (prone to CVEs) | Guaranteed by the compiler |
| Distribution | Separate install required | Compiled into the binary |
| Config | `torrc` file, separate process | Code-level API, no config file |
| Maturity | 20+ years, battle-tested | Newer, actively developed |
| Embeddability | Hard — subprocess + socket | Easy — just a library call |

**Honest tradeoffs:** Arti is still maturing. Some advanced Tor features (bridges, pluggable transports) are not yet stable in Arti. If you need those, the classic `tor` binary is the right tool. For straightforward onion hosting, Arti works well and gives you a much simpler setup.

The Rust memory-safety guarantee matters here specifically because Tor handles untrusted network traffic. A buffer overflow or use-after-free in a C-based Tor implementation is a real historical risk. With Arti in Rust, that entire class of bug is eliminated by the language.

---

## Quick Start

> **Need help with prerequisites?** See [SETUP.md](SETUP.md) for step-by-step install instructions.

```bash
# 1. Clone and build
git clone https://github.com/yourname/rusthost
cd rusthost
cargo build --release

# 2. First run — sets up the data directory and exits
./target/release/rusthost

# 3. Put your files in rusthost-data/site/, then run again
./target/release/rusthost
```

That's it. Your site is live at `http://localhost:8080`. The `.onion` address appears in the dashboard after about 30 seconds while Tor bootstraps in the background.

> **Your stable `.onion` address** is stored in `rusthost-data/arti_state/`. Back this directory up — it contains your keypair. Delete it only if you want a new address.

---

## Full Setup Reference

For detailed install instructions, OS-specific steps, common errors, and how to verify everything is working, see **[SETUP.md](SETUP.md)**.

---

## Usage Examples

### Serve a specific directory without a config file

```bash
./target/release/rusthost --serve ./my-website
```

Good for quick one-off serving. Skips first-run setup entirely.

### Run with a custom config location

```bash
./target/release/rusthost --config /etc/rusthost/settings.toml --data-dir /var/rusthost
```

Useful for running multiple instances or deploying under systemd.

### Run headless (no terminal UI)

Set `interactive = false` in `settings.toml`:

```toml
[console]
interactive = false
```

RustHost will print the URL to stdout and log everything to the log file. Perfect for running as a background service.

### Disable Tor entirely

```toml
[tor]
enabled = false
```

Useful if you just want a fast local HTTP server and don't need the `.onion` address.

### Enable SPA routing (React, Vue, Svelte)

```toml
[site]
spa_routing = true
```

Unknown paths fall back to `index.html` instead of returning 404. This is what client-side routers expect.

---

## All CLI Flags

```
rusthost [OPTIONS]

Options:
  --serve <dir>        Serve a directory directly, no settings.toml needed
  --config <path>      Path to settings.toml (default: rusthost-data/settings.toml)
  --data-dir <path>    Path to the data directory (default: ./rusthost-data/)
  --version            Print version and exit
  --help               Print this help and exit
```

---

## Configuration

The config file lives at `rusthost-data/settings.toml` and is created automatically on first run with comments explaining every option.

```toml
[server]
port                    = 8080
bind                    = "127.0.0.1"           # use "0.0.0.0" to expose on your LAN
index_file              = "index.html"
directory_listing       = false                 # show file lists for directories
auto_port_fallback      = true                  # try next port if 8080 is taken
max_connections         = 256                   # max simultaneous connections
request_timeout_secs    = 30                    # seconds before an idle connection gets 408
content_security_policy = "default-src 'self'"  # applied to HTML responses only

[site]
root         = "rusthost-data/site"
spa_routing  = false                            # set true for React/Vue/Svelte apps
error_404    = ""                               # path to a custom 404.html
error_503    = ""                               # path to a custom 503.html

[tor]
enabled = true                                  # set false to skip Tor entirely

[logging]
enabled             = true
level               = "info"                    # trace | debug | info | warn | error
path                = "logs/rusthost.log"
filter_dependencies = true                      # suppress Arti/Tokio noise at info level

[console]
interactive           = true                    # false for systemd / background use
refresh_ms            = 500
show_timestamps       = false
open_browser_on_start = false

[identity]
name = "RustHost"                               # shown in the dashboard header (max 32 chars)
```

> Typos in key names are caught at startup. If you write `bund = "127.0.0.1"` instead of `bind`, RustHost will tell you exactly which field is unknown and exit before starting.

---

## Project Structure

After first run, your directory will look like this:

```
rusthost-data/
├── settings.toml       Your config file — edit this freely
├── site/               Drop your website files here
│   └── index.html      Placeholder — replace with your own
├── logs/
│   └── rusthost.log    Rotating access and event log (owner-read only)
├── arti_cache/         Tor directory data — auto-managed, safe to delete
└── arti_state/         Your .onion keypair — BACK THIS UP
```

And in the repo:

```
src/
├── config/             Config loading and validation
├── console/            Terminal dashboard (crossterm)
├── logging/            Log file + in-memory ring buffer
├── runtime/            Startup, shutdown, and event loop
├── server/             HTTP server (handler, MIME types, path resolution)
└── tor/                Arti integration and onion service bridge
```

---

## Built-in MIME Types

RustHost ships a handwritten MIME map — no external lookup or database.

| Category | Extensions |
|----------|------------|
| Text | `html` `htm` `css` `js` `mjs` `txt` `csv` `xml` `md` |
| Data | `json` `jsonld` `pdf` `wasm` `zip` `ndjson` |
| Images | `png` `jpg` `jpeg` `gif` `webp` `svg` `ico` `bmp` `avif` |
| Fonts | `woff` `woff2` `ttf` `otf` |
| Audio | `mp3` `ogg` `wav` `opus` `flac` |
| Video | `mp4` `webm` |
| 3D | `glb` |
| PWA | `webmanifest` |

Anything not in this list gets `application/octet-stream`.

---

## Security

A quick summary of what RustHost does to keep things safe:

| Threat | What RustHost does |
|--------|-------------------|
| Path traversal (e.g. `/../etc/passwd`) | Every path is resolved with `canonicalize` and checked against the site root. Escapes get a `403`. |
| XSS via crafted filenames in directory listings | Filenames are HTML-escaped in link text and percent-encoded in `href` attributes. |
| Slow-loris DoS (deliberately slow clients) | 30-second request timeout — connections that don't send headers in time get a `408`. |
| Connection exhaustion | Semaphore cap at 256 concurrent connections by default. |
| Header injection | `sanitize_header_value` strips all control characters from values (not just CR/LF). |
| Large file memory exhaustion | Files are streamed with `tokio::io::copy` — memory per connection is bounded by the socket buffer. |
| `.onion` address leakage | `Referrer-Policy: no-referrer` prevents your `.onion` URL from appearing in `Referer` headers. |
| Config typos silently using defaults | `#[serde(deny_unknown_fields)]` on all config structs — unknown keys are a hard startup error. |
| Terminal injection via instance name | The `name` field is validated against all control characters at startup. |

**Note on RUSTSEC-2023-0071 (RSA Marvin timing attack):** This advisory is acknowledged and suppressed in `deny.toml` with a documented rationale. The `rsa` crate comes in as a transitive dependency of `arti-client` and is used only for *verifying* RSA signatures on Tor directory documents — not for decryption. The Marvin attack requires a decryption oracle, which is not present here.

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

All subsystems share state through `Arc<RwLock<AppState>>`. Hot-path counters (request counts, error counts) live in a separate `Arc<Metrics>` backed by atomics, so the HTTP handler never acquires a lock per request.

Shutdown is coordinated via a `watch` channel. `[Q]`, `SIGINT`, and `SIGTERM` all signal every subsystem at the same time. In-flight connections are tracked in a `JoinSet` and given up to 5 seconds to finish before the process exits.

---

## Contributing

Contributions are welcome. A few things worth knowing before you start:

- The lint gates are strict: `clippy::all`, `clippy::pedantic`, and `clippy::nursery`. Run `cargo clippy --all-targets -- -D warnings` before opening a PR.
- Run the full test suite with `cargo test --all`.
- All code paths should be covered by the existing tests, or new tests added for anything new.
- See [CONTRIBUTING.md](CONTRIBUTING.md) for the full workflow, architecture notes, and PR checklist.
- To report a security issue privately, see [SECURITY.md](SECURITY.md).

---

## License

MIT — see [LICENSE](LICENSE).

---

<div align="center">
<sub>Built with Rust 🦀 · Powered by <a href="https://tokio.rs">Tokio</a> · Tor via <a href="https://gitlab.torproject.org/tpo/core/arti">Arti</a></sub>
</div>
