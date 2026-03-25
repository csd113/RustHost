<div align="center">

<pre>
██████╗ ██╗   ██╗███████╗████████╗██╗  ██╗ ██████╗ ███████╗████████╗
██╔══██╗██║   ██║██╔════╝╚══██╔══╝██║  ██║██╔═══██╗██╔════╝╚══██╔══╝
██████╔╝██║   ██║███████╗   ██║   ███████║██║   ██║███████╗   ██║
██╔══██╗██║   ██║╚════██║   ██║   ██╔══██║██║   ██║╚════██║   ██║
██║  ██║╚██████╔╝███████║   ██║   ██║  ██║╚██████╔╝███████║   ██║
╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝
</pre>

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

RustHost is your no-fuss static file server. Drop in a folder full of HTML, CSS, JS — whatever — and it'll serve it up over HTTP. The cool part? It also spins up a Tor onion service automatically, so your site gets a `.onion` address next to the regular localhost one.

One binary, Tor included. No separate installs, no messing with torrc files.

**Perfect for:** Devs testing locally with privacy, self-hosters wanting Tor access, or anyone running a personal site without system tweaks.

---

## What it looks like

```
┌─ RustHost ─────────────────────────────────────────────────────────┐
│                                                                    │
│  STATUS        ● RUNNING   127.0.0.1:8080                         │
│  TOR           ● READY                                            │
│                                                                    │
│  ENDPOINTS     http://localhost:8080                               │
│                abcdef1234567890abcdef1234567890abcdef12.onion      │
│                                                                    │
│  SITE          ./rusthost-data/site   ·  12 files  ·  4.2 MB      │
│  ACTIVITY      847 requests  ·  0 errors                          │
│                                                                    │
│  [L] Logs   [R] Reload   [H] Help   [Q] Quit                      │
└────────────────────────────────────────────────────────────────────┘
```

![rusthost screenshot](https://github.com/user-attachments/assets/30752d0f-5be2-4c80-b3a2-4fa0530ff3ab)

---

## Key Features

- **Static files done right** — HTML, CSS, JS, images, fonts, audio/video, with proper MIME types
- **Tor baked in** — Stable `.onion` address, no extra setup
- **Live dashboard** — Full-screen terminal UI with endpoints, stats, and logs
- **One binary** — Grab, run, done. No deps.
- **SPA support** — React/Vue/Svelte friendly with index.html fallback
- **HTTP smarts** — Keep-alive, ETags, ranges, Brotli/Gzip compression
- **Security first** — CSP, HSTS, and more headers by default
- **Rate limits** — Caps connections per IP to stop DoS
- **Connection limits, timeouts, path protection** — No surprises
- **Hot reload** — Hit `[R]` to refresh stats
- **Headless mode** — Great for systemd

---

## Why Arti over classic Tor?

Most folks know Tor as that C-based `tor` binary you install separately. It works, but it's a whole extra process.

Arti is the Tor Project's fresh Rust rewrite. RustHost links it right in — Tor runs in the same process, zero hassle.

Quick compare:

|                | Old-school `tor`       | Arti (in RustHost)     |
|----------------|------------------------|------------------------|
| Language       | C (bug-prone)          | Rust (memory-safe)     |
| Setup          | Install + config file  | Built-in library       |
| Config         | torrc + sockets        | Just code              |
| Maturity       | Old & proven           | Newer, but solid for onions |

**Tradeoffs:** Arti's young — no bridges or fancy transports yet. Stick to classic Tor if you need those. For basic onion hosting? Arti's simpler and safer against memory bugs.

Rust matters here: Tor sees sketchy traffic. No more C overflows.

---

## Quick Start

> Struggling with setup? Check [SETUP.md](SETUP.md) for OS-specific steps.

```bash
# Clone & build
git clone https://github.com/yourname/rusthost
cd rusthost
cargo build --release

# First run makes the data dir
./target/release/rusthost

# Drop files in rusthost-data/site/, run again
./target/release/rusthost
```

Boom. `localhost:8080` and `.onion` ready in ~30s (Tor bootstrap).

> **Backup `rusthost-data/arti_state/`** — that's your onion keys. Nuke it for a fresh address.

---

## Full Setup Reference

OS tweaks, errors, verification? All in **[SETUP.md](SETUP.md)**.

---

## Usage Examples

**Quick serve:**

```bash
./target/release/rusthost --serve ./my-site
```

**Custom config/data:**

```bash
./target/release/rusthost --config /etc/rusthost.toml --data-dir /var/rusthost
```

**Headless (systemd-friendly):**

```toml
[console]
interactive = false
```

Prints URLs to stdout, logs to file.

**No Tor:**

```toml
[tor]
enabled = false
```

**SPA mode:**

```toml
[site]
spa_routing = true
```

---

## All CLI Flags

```
rusthost [OPTIONS]

  --serve <dir>     Serve dir directly
  --config <path>   Settings.toml path
  --data-dir <path> Data dir
  --version         Version info
  --help            This help
```

---

## Configuration

`rusthost-data/settings.toml` auto-generates with comments. Edit away.

```toml
[server]
port = 8080
bind = "127.0.0.1"  # "0.0.0.0" for LAN
# ... more with explanations
```

Typos? Startup yells and quits — no silent fails.

---

## Project Structure

Post-first-run:

```
rusthost-data/
├── settings.toml    ← Edit me
├── site/            ← Your files
├── logs/            Access log
├── arti_cache/      Tor data (delete OK)
└── arti_state/      Onion keys (backup!)
```

Repo:

```
src/
├── config/    TOML loader
├── console/   TUI magic
├── logging/   Files + buffer
├── runtime/   Startup/shutdown
├── server/    HTTP core
└── tor/       Arti hookup
```

---

## MIME Types

Hand-curated list — fast, no deps:

| Category    | Extensions              |
|-------------|-------------------------|
| Text        | html, css, js, txt, md… |
| Data        | json, pdf, wasm, zip    |
| Images      | png, jpg, webp, svg…    |
| Fonts       | woff2, ttf              |
| Audio/Video | mp3, mp4, webm…         |

Else: `application/octet-stream`.

---

## Security

Built-in defenses:

| Threat          | How we block it                      |
|-----------------|--------------------------------------|
| Path traversal  | Canonicalize + root check (403)      |
| XSS in listings | HTML-escape + URL-encode             |
| Slowloris       | 30s header timeout (408)             |
| Conn flood      | 256 limit semaphore                  |
| Header junk     | Strip controls                       |
| Big files       | Streamed, no full loads              |
| Onion leaks     | `Referrer-Policy: no-referrer`       |
| Config typos    | Deny unknown fields                  |
| TUI hacks       | Validate name chars                  |

**RUSTSEC note:** RSA dep from Arti is pinned/suppressed — we only verify sigs, no decrypt.

---

## Architecture

```
Browser ───► HTTP (Tokio TcpListener)
Tor ─────► Arti (in-process) ──► Onion bridge
                   │
       AppState (Arc<RwLock>) + Metrics (atomics)
                   │
              Crossterm TUI
```

Shared state, atomic counters (no locks on hot path). Clean shutdown via signals/watch.

---

## Contributing

Pull requests welcome! Quick tips:

- `cargo clippy --all-targets -- -D warnings`
- `cargo test --all`
- Add tests for new stuff
- Full guide: [CONTRIBUTING.md](CONTRIBUTING.md)
- Security bugs: [SECURITY.md](SECURITY.md)

---

## License

MIT — [LICENSE](LICENSE).

---

<div align="center">
<sub>Built with Rust 🦀 · Tokio-powered · Arti for Tor</sub>
</div>