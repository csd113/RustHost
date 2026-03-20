# Changelog

All notable changes to RustHost are documented here.
This project adheres to [Semantic Versioning](https://semver.org/).

---

## [0.1.0] — Initial Release

### HTTP Server

- Custom HTTP/1.1 static file server built directly on `tokio::net::TcpListener` — no third-party HTTP framework dependency.
- Serves `GET` and `HEAD` requests; all other methods return `400 Bad Request`.
- Percent-decoding of URL paths (e.g. `%20` → space) before file resolution.
- Query string and fragment stripping before path resolution.
- Path traversal protection: every resolved path is verified to be a descendant of the site root via `std::fs::canonicalize`; any attempt to escape (e.g. `/../secret`) is rejected with `HTTP 403 Forbidden`.
- Request header size cap of 8 KiB; oversized requests are rejected immediately.
- `Content-Type`, `Content-Length`, and `Connection: close` headers on every response.
- Configurable index file (default: `index.html`) served for directory requests.
- Optional HTML directory listing for directory requests when no index file is found, with alphabetically sorted entries.
- Built-in "No site found" fallback page (HTTP 200) when the site directory is empty and directory listing is disabled, so the browser always shows a helpful message rather than a connection error.
- Placeholder `index.html` written on first run so the server is immediately functional out of the box.
- Automatic port fallback: if the configured port is in use, the server silently tries the next free port up to 10 times before giving up (configurable via `auto_port_fallback`).
- Configurable bind address; defaults to `127.0.0.1` (loopback only) with a logged warning when set to `0.0.0.0`.
- Per-connection Tokio tasks so concurrent requests never block each other.

### MIME Types

- Built-in extension-to-MIME mapping with no external dependency, covering:
  - Text: `html`, `htm`, `css`, `js`, `mjs`, `txt`, `csv`, `xml`, `md`
  - Data: `json`, `jsonld`, `pdf`, `wasm`, `zip`
  - Images: `png`, `jpg`/`jpeg`, `gif`, `webp`, `svg`, `ico`, `bmp`, `avif`
  - Fonts: `woff`, `woff2`, `ttf`, `otf`
  - Audio: `mp3`, `ogg`, `wav`
  - Video: `mp4`, `webm`
  - Unknown extensions fall back to `application/octet-stream`.

### Tor Onion Service (Arti — in-process)

- Embedded Tor support via [Arti](https://gitlab.torproject.org/tpo/core/arti), the official Rust Tor implementation — no external `tor` binary or `torrc` file required.
- Bootstraps to the Tor network in a background Tokio task; never blocks the HTTP server or console.
- First run downloads approximately 2 MB of directory consensus data (approximately 30 seconds); subsequent runs reuse the cache and start in seconds.
- Stable `.onion` address across restarts: the service keypair is persisted to `rusthost-data/arti_state/`; deleting this directory rotates to a new address.
- Consensus cache stored in `rusthost-data/arti_cache/` for fast startup.
- Onion address encoded in-process using the v3 `.onion` spec (SHA3-256 checksum + base32) — no dependency on Arti's `DisplayRedacted` formatting.
- Each inbound Tor connection is bridged to the local HTTP server via `tokio::io::copy_bidirectional` in its own Tokio task.
- Tor subsystem can be disabled entirely with `[tor] enabled = false`; the dashboard onion section reflects this immediately.
- Graceful shutdown: the `TorClient` is dropped naturally when the Tokio runtime exits, closing all circuits cleanly — no explicit kill step needed.
- `.onion` address displayed in the dashboard and logged in a prominent banner once the service is active.

### Interactive Terminal Dashboard

- Full-screen raw-mode terminal UI built with [crossterm](https://github.com/crossterm-rs/crossterm); no external TUI framework.
- Three screens navigable with single-key bindings:
  - **Dashboard** (default) — live status overview.
  - **Log view** — last 40 log lines, toggled with `[L]`.
  - **Help overlay** — key binding reference, toggled with `[H]`; any other key dismisses it.
- Dashboard sections:
  - **Status** — local server state (RUNNING with bind address and port, or STARTING) and Tor state (DISABLED / STARTING / READY / FAILED with exit code).
  - **Endpoints** — local `http://localhost:<port>` URL and Tor `.onion` URL (or a dim status hint if Tor is not yet ready).
  - **Site** — directory path, file count, and total size (auto-scaled to B / KB / MB / GB).
  - **Activity** — total request count and error count (errors highlighted in red when non-zero).
  - **Key bar** — persistent one-line reminder of available key bindings.
- Dashboard redraws at a configurable interval (default: 500 ms).
- Log view supports optional `HH:MM:SS` timestamp display, toggled via `show_timestamps` in config.
- Customisable instance name shown in the dashboard header (max 32 characters).
- Headless / non-interactive mode: set `[console] interactive = false` for systemd or piped deployments; the server prints a plain `http://…` line to stdout instead.
- Graceful terminal restore on fatal crash: raw mode is disabled and the cursor is shown even if the process exits unexpectedly.

### Configuration

- TOML configuration file (`rusthost-data/settings.toml`) with six sections: `[server]`, `[site]`, `[tor]`, `[logging]`, `[console]`, `[identity]`.
- Configuration validated at startup with clear, multi-error messages before any subsystem is started.
- Validated fields include port range, bind IP address format, index file name (no path separators), log level, console refresh rate minimum (100 ms), instance name length (1–32 chars), and absence of control characters in the name.
- Full default config written automatically on first run with inline comments explaining every option.
- Reloading site stats (file count and total size) without restart via `[R]` in the dashboard.

### Logging

- Custom `log::Log` implementation; all modules use the standard `log` facade macros (`log::info!`, `log::warn!`, etc.).
- Dual output: log file on disk (append mode, parent directories created automatically) and an in-memory ring buffer.
- Ring buffer holds the most recent 1 000 lines and feeds the console log view without any file I/O on each render tick.
- Log file path configurable relative to `rusthost-data/`; defaults to `logs/rusthost.log`.
- Configurable log level: `trace`, `debug`, `info`, `warn`, `error`.
- Timestamped entries in `[LEVEL] [HH:MM:SS] message` format.
- Logging can be disabled entirely (`[logging] enabled = false`) for minimal-overhead deployments.

### Lifecycle and Startup

- **First-run detection**: if `rusthost-data/settings.toml` does not exist, RustHost initialises the data directory (`site/`, `logs/`), writes defaults, drops a placeholder `index.html`, prints a short getting-started guide, and exits cleanly — no daemon started.
- **Normal run** startup sequence: load and validate config → initialise logging → build shared state → scan site directory → bind HTTP server → start Tor (if enabled) → start console → open browser (if configured) → enter event loop.
- Shutdown triggered by `[Q]` keypress or `SIGINT`/`SIGTERM` (via `ctrlc`); sends a watch-channel signal to the HTTP server and console, then waits 300 ms for in-flight connections before exiting.
- Optional browser launch at startup (`open_browser_on_start`); uses `open` (macOS), `explorer` (Windows), or `xdg-open` (Linux/other).
- All subsystems share state through an `Arc<RwLock<AppState>>`; hot-path request and error counters use separate `Arc<Metrics>` backed by atomics so the HTTP handler never acquires a lock per request.

### Project and Build

- Single binary; no installer, no runtime dependencies beyond the binary itself (Tor included via Arti).
- Data directory co-located with the binary at `./rusthost-data/`; entirely self-contained.
- Minimum supported Rust version: 1.86 (required by `arti-client 0.40`).
- Release profile: `opt-level = 3`, LTO enabled, debug symbols stripped.
- `cargo-deny` configuration (`deny.toml`) enforcing allowed SPDX licenses (MIT, Apache-2.0, Apache-2.0 WITH LLVM-exception, Zlib, Unicode-3.0) and advisory database checks; known transitive duplicate crates (`mio`, `windows-sys`) skipped with comments.
- Advisory `RUSTSEC-2023-0071` (RSA Marvin timing attack) acknowledged and suppressed with a documented rationale: the `rsa` crate is a transitive dependency of `arti-client` used exclusively for RSA *signature verification* on Tor directory consensus documents, not decryption; the attack's threat model does not apply.
