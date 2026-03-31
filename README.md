Here's your updated README with the HTTPS/TLS changes integrated:

---

<div align="center">

<pre>
██████╗ ██╗   ██╗███████╗████████╗██╗  ██╗ ██████╗ ███████╗████████╗
██╔══██╗██║   ██║██╔════╝╚══██╔══╝██║  ██║██╔═══██╗██╔════╝╚══██╔══╝
██████╔╝██║   ██║███████╗   ██║   ███████║██║   ██║███████╗   ██║
██╔══██╗██║   ██║╚════██║   ██║   ██╔══██║██║   ██║╚════██║   ██║
██║  ██║╚██████╔╝███████║   ██║   ██║  ██║╚██████╔╝███████║   ██║
╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝
</pre>

**A single-binary static file server with built-in HTTPS and Tor onion service support.**  
No daemons. No config files outside this project. No compromise.

[![Rust](https://img.shields.io/badge/rust-1.86%2B-orange?style=flat-square&logo=rust)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue?style=flat-square)](LICENSE)
[![Tor: Arti](https://img.shields.io/badge/tor-arti%20in--process-7d4698?style=flat-square)](https://gitlab.torproject.org/tpo/core/arti)
[![TLS: rustls](https://img.shields.io/badge/tls-rustls-green?style=flat-square)](https://github.com/rustls/rustls)
[![Async: Tokio](https://img.shields.io/badge/async-tokio-49a?style=flat-square)](https://tokio.rs/)
[![Security: cargo-deny](https://img.shields.io/badge/security-cargo--deny-red?style=flat-square)](https://embarkstudios.github.io/cargo-deny/)

</div>

---

## What is RustHost?

RustHost is your no-fuss static file server. Drop in a folder full of HTML, CSS, JS — whatever — and it'll serve it up over HTTP or HTTPS. The cool part? It also spins up a Tor onion service automatically, so your site gets a `.onion` address next to the regular localhost one.

One binary, TLS and Tor included. No separate installs, no messing with torrc files, no OpenSSL.

**Perfect for:** Devs testing locally with privacy, self-hosters wanting HTTPS + Tor access, or anyone running a personal site without system tweaks.

**Scope note:** RustHost is a public static-file server, not an authenticated admin panel. It does not implement users, sessions, or authorization. If you expose it beyond localhost, treat every served path as public and put any private/operator-only surface behind a separate authenticated reverse proxy or service.

---

## What it looks like

```
┌─ RustHost ─────────────────────────────────────────────────────────┐
│                                                                    │
│  STATUS        ● RUNNING   127.0.0.1:8080                         │
│  HTTPS         ● RUNNING   127.0.0.1:8443  (self-signed)          │
│  TOR           ● READY                                            │
│                                                                    │
│  ENDPOINTS     http://localhost:8080                               │
│                https://localhost:8443                               │
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
- **Native HTTPS** — Self-signed dev certs, Let's Encrypt via ACME, or bring your own. Pure Rust TLS — no OpenSSL, no FFI
- **Tor baked in** — Stable `.onion` address, no extra setup
- **Live dashboard** — Full-screen terminal UI with endpoints, stats, TLS status, and logs
- **One binary** — Grab, run, done. No deps.
- **SPA support** — React/Vue/Svelte friendly with index.html fallback
- **HTTP smarts** — Keep-alive, ETags, ranges, Brotli/Gzip compression
- **Security first** — CSP, HSTS, X-Content-Type-Options, X-Frame-Options, and more headers by default
- **Rate limits** — Caps connections per IP to stop DoS
- **Connection limits, timeouts, path protection** — No surprises
- **HTTP → HTTPS redirect** — Optional automatic redirect server
- **Hot reload** — Hit `[R]` to refresh stats
- **Headless mode** — Great for systemd

---

## Why Arti over classic Tor?

Most know Tor as that C-based `tor` binary you install separately. It works, but it's a whole extra process.

Arti is the Tor Project's fresh Rust rewrite. RustHost links it right in — Tor runs in the same process, zero hassle.

Quick compare:

|                | Old-school `tor`       | Arti (in RustHost)     |
|----------------|------------------------|------------------------|
| Language       | C (bug-prone)          | Rust (memory-safe)     |
| Setup          | Install + config file  | Built-in library       |
| Config         | torrc + sockets        | Just code              |
| Maturity       | Old & proven           | Newer, but solid for onions |

Rust matters here: Tor sees sketchy traffic. No more C overflows.

---

## Why rustls over OpenSSL?

RustHost uses **rustls** for TLS — the same pure-Rust implementation used by Cloudflare, the Rust compiler's download infrastructure, and many others.

|                | OpenSSL                | rustls (in RustHost)   |
|----------------|------------------------|------------------------|
| Language       | C (CVE history)        | Rust (memory-safe)     |
| Setup          | System library + headers | Built-in, compiled in |
| Config         | Complex tuning needed  | Safe defaults out of the box |
| Ciphers        | Everything incl. legacy | TLS 1.2+ only, modern suites |
| Binary         | Dynamic linking / FFI  | Static, single binary preserved |

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

### Quick HTTPS

Add to `rusthost-data/settings.toml`:

```toml
[tls]
enabled = true
```

Restart — HTTPS on `localhost:8443` with an auto-generated self-signed cert. No extra steps.

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

## TLS / HTTPS Configuration

The `[tls]` section is entirely optional. Omit it and RustHost runs HTTP-only, exactly as before.

**Self-signed (local dev):**
```toml
[tls]
enabled = true
port = 8443
```
A self-signed cert for `localhost` / `127.0.0.1` / `::1` is auto-generated under `rusthost-data/tls/dev/` and regenerated when it expires.

**Let's Encrypt (ACME) — staging first:**
```toml
[tls]
enabled = true
port = 8443

[tls.acme]
enabled = true
domains = ["example.com"]
email = "you@example.com"
staging = true          # test against LE staging to avoid rate limits
```

**Let's Encrypt — production:**
```toml
[tls]
enabled = true
port = 443
redirect_http = true    # spin up an HTTP→HTTPS redirect server
http_port = 80

[tls.acme]
enabled = true
domains = ["example.com", "www.example.com"]
email = "you@example.com"
staging = false
```

**Bring your own cert:**
```toml
[tls]
enabled = true
port = 443

[tls.manual_cert]
cert_path = "tls/manual/fullchain.pem"
key_path  = "tls/manual/privkey.pem"
```

### Certificate priority

1. `manual_cert` — if provided, used as-is
2. `acme.enabled = true` — Let's Encrypt with automatic renewal
3. Neither — self-signed dev cert auto-generated

### HTTP → HTTPS redirect

When `redirect_http = true`, a lightweight redirect server runs on `http_port` (default 8080) and issues 301 redirects to your HTTPS port. Tor `.onion` connections are already end-to-end encrypted and always use plain HTTP — they're unaffected.

### Port 443 on Linux without root

```bash
# Option A: grant the binary permission
sudo setcap cap_net_bind_service=+ep $(which rusthost)

# Option B: firewall redirect
sudo iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-port 8443
```

### Backwards compatibility

| Existing config | Behaviour after upgrade |
|---|---|
| No `[tls]` section | HTTP only — no change |
| `[tls] enabled = false` | HTTP only — no change |
| `[tls] enabled = true` | HTTP + HTTPS on configured port |
| `[tls] enabled = true` + `redirect_http = true` | HTTPS primary; HTTP auto-redirects |

---

## Project Structure

Post-first-run:

```
rusthost-data/
├── settings.toml    ← Edit me
├── site/            ← Your files
├── logs/            Access log
├── tls/             TLS certificates
│   ├── acme/        ← Managed by ACME (Let's Encrypt)
│   └── dev/         ← Auto-generated self-signed certs
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
├── server/    HTTP + HTTPS core
├── tls/       TLS setup (ACME, self-signed, manual certs)
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

| Threat          | How we block it                       |
|-----------------|---------------------------------------|
| Plaintext sniff | HTTPS with auto or manual certs       |
| MITM            | HSTS header on HTTPS responses        |
| Path traversal  | Canonicalize + root check (403)       |
| XSS in listings | HTML-escape + URL-encode              |
| Clickjacking    | X-Frame-Options: SAMEORIGIN           |
| MIME sniffing   | X-Content-Type-Options: nosniff       |
| Slowloris       | 30s header timeout (408)              |
| Conn flood      | 256 limit semaphore                   |
| Header junk     | Strip controls                        |
| Big files       | Streamed, no full loads               |
| Onion leaks     | `Referrer-Policy: no-referrer`        |
| Config typos    | Deny unknown fields                   |
| TUI hacks       | Validate name chars                   |
| TLS handshake scanners | Logged at debug level, not warn |

**TLS note:** rustls enforces TLS 1.2+ with a safe modern cipher suite out of the box. No legacy protocol support, no unsafe renegotiation. Pure Rust — no OpenSSL CVEs apply.

**RUSTSEC note:** RSA dep from Arti is pinned/suppressed — we only verify sigs, no decrypt.

---

## Architecture

```
Browser ───► HTTP  (Tokio TcpListener :8080)
Browser ───► HTTPS (Tokio TcpListener :8443 → rustls TLS)
Tor ─────► Arti (in-process) ──► Onion bridge
                   │
       AppState (Arc<RwLock>) + Metrics (atomics)
                   │
              Crossterm TUI
```

HTTP and HTTPS listeners share the same connection limits (`per_ip_map`, `semaphore`) — constructed once, `Arc`-cloned into both. Shared state, atomic counters (no locks on hot path). Clean shutdown via signals/watch.

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
<sub>Built with Rust 🦀 · Tokio-powered · rustls for HTTPS · Arti for Tor</sub>
</div>
