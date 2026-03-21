# Changelog

All notable changes to RustHost are documented here.
This project adheres to [Semantic Versioning](https://semver.org/).

---

## [0.2.0] — Remediation Release

This release resolves all 40 issues identified in the 2026-03-20 comprehensive security and reliability audit. Changes are grouped by the audit's five severity phases.

---

### Phase 1 — Critical Security & Correctness

#### 1.1 — Config Path Traversal: `site.directory` and `logging.file` Validated

`src/config/loader.rs` — `validate()` now rejects any `site.directory` or `logging.file` value that is an absolute path, contains a `..` component, or contains a platform path separator. The process exits with a clear validation error before binding any port. Previously, a value such as `directory = "../../etc"` caused the HTTP server to serve the entire `/etc` tree, and a value such as `../../.ssh/authorized_keys` for `logging.file` caused log lines to be appended to the SSH authorized keys file.

#### 1.2 — Race Condition: Tor Captures Bound Port via `oneshot` Channel

`src/runtime/lifecycle.rs`, `src/server/mod.rs` — The 50 ms sleep that was the sole synchronisation barrier between the HTTP server binding its port and the Tor subsystem reading that port has been replaced with a `tokio::sync::oneshot` channel. The server sends the actual bound port through the channel before entering the accept loop; `tor::init` awaits that value (with a 10-second timeout) rather than reading a potentially-zero value out of `SharedState`. Previously, on a loaded system the race could be lost silently, causing every inbound Tor connection to fail with `ECONNREFUSED` to port 0 while the dashboard displayed a healthy green `TorStatus::Ready`.

#### 1.3 — XSS in Directory Listing via Unsanitised Filenames

`src/server/handler.rs` — `build_directory_listing()` now HTML-entity-escapes all filenames before interpolating them into link text (`&` → `&amp;`, `<` → `&lt;`, `>` → `&gt;`, `"` → `&quot;`, `'` → `&#x27;`) and percent-encodes filenames in `href` attribute values. Previously, a file named `"><script>alert(1)</script>` produced an executable XSS payload in any directory listing page.

#### 1.4 — HEAD Requests No Longer Receive a Response Body

`src/server/handler.rs` — `parse_path()` now returns `(method, path)` instead of only the path. The method is threaded through to `write_response()` via a `suppress_body: bool` parameter. For `HEAD` requests, response headers (including `Content-Length` reflecting the full body size, as required by RFC 7231 §4.3.2) are written, but the body is not sent.

#### 1.5 — Request Timeout Prevents Slow-Loris DoS

`src/server/handler.rs` — The call to `read_request()` is now wrapped in `tokio::time::timeout(Duration::from_secs(30))`. Connections that fail to deliver a complete request header within 30 seconds receive a `408 Request Timeout` response and are closed. The timeout is also configurable via `[server] request_timeout_secs` in `settings.toml`. Timeout events are logged at `debug` level to avoid log flooding under attack.

#### 1.6 — Unbounded Connection Spawning Replaced with Semaphore

`src/server/mod.rs`, `src/tor/mod.rs` — Both the HTTP accept loop and the Tor stream request loop now use a `tokio::sync::Semaphore` to cap concurrent connections. The limit is configurable via `[server] max_connections` (default: 256). The semaphore `OwnedPermit` is held for the lifetime of each connection task and released on drop. When the limit is reached, the accept loop suspends naturally, providing backpressure; a `warn`-level log entry is emitted. Previously, unlimited concurrent connections could exhaust task stack memory and file descriptors.

#### 1.7 — Files Streamed Instead of Read Entirely Into Memory

`src/server/handler.rs` — `tokio::fs::read` (which loads the entire file into a `Vec<u8>`) has been replaced with `tokio::fs::File::open` followed by `tokio::io::copy(&mut file, &mut stream)`. File size is obtained via `file.metadata().await?.len()` for the `Content-Length` header. Memory consumption per connection is now bounded by the kernel socket buffer (~128–256 KB) regardless of file size. For `HEAD` requests, the file is opened only to read its size; the `copy` step is skipped.

#### 1.8 — `strip_timestamp` No Longer Panics on Non-ASCII Log Lines

`src/console/dashboard.rs` — `strip_timestamp()` previously used a byte index derived from iterating `.bytes()` to slice a `&str`, which panicked when the index fell inside a multi-byte UTF-8 character. The implementation now uses `splitn(3, ']')` to strip the leading `[LEVEL]` and `[HH:MM:SS]` tokens, which is both panic-safe and simpler. Any log line containing Unicode characters (Arti relay names, internationalized filenames, `.onion` addresses) is handled correctly.

#### 1.9 — `TorStatus` Updated to `Failed` When Onion Service Terminates

`src/tor/mod.rs` — When `stream_requests.next()` returns `None` (the onion service stream ends unexpectedly), the status is now set to `TorStatus::Failed("stream ended".to_string())` and the `onion_address` field is cleared from `AppState`. Previously, the dashboard permanently displayed a healthy green badge and the `.onion` address after the service had silently stopped serving traffic.

#### 1.10 — Terminal Fully Restored on All Exit Paths; Panic Hook Registered

`src/main.rs`, `src/console/mod.rs` — The error handler in `main.rs` now calls `console::cleanup()` (which issues `cursor::Show` and `terminal::LeaveAlternateScreen` before `disable_raw_mode`) on all failure paths. A `std::panic::set_hook` registered at startup ensures the same cleanup runs even when a panic occurs on an async executor thread. `console::cleanup()` is idempotent (guarded by a `RAW_MODE_ACTIVE` atomic swap), so calling it from multiple paths is safe.

---

### Phase 2 — High Priority Reliability

#### 2.1 — HTTP Request Reading Buffered with `BufReader`

`src/server/handler.rs` — `read_request()` previously read one byte at a time, issuing up to 8,192 individual `read` syscalls per request. The stream is now wrapped in `tokio::io::BufReader<TcpStream>` and reads headers line-by-line with `read_line()`. The 8 KiB header size limit is enforced by accumulating total bytes read. This also correctly handles `\r\n\r\n` split across TCP segments.

#### 2.2 — `scan_site` is Now Recursive, Error-Propagating, and Non-Blocking

`src/server/mod.rs`, `src/runtime/lifecycle.rs`, `src/runtime/events.rs` — `scan_site` now performs a breadth-first traversal using a `VecDeque<PathBuf>` work queue, counting files and sizes in all subdirectories. The return type is now `Result<(u32, u64)>`; errors from `read_dir` are propagated and logged at `warn` level rather than silently returning `(0, 0)`. All call sites wrap the function in `tokio::task::spawn_blocking` to avoid blocking the async executor on directory I/O.

#### 2.3 — `canonicalize()` Called Once at Startup, Not Per Request

`src/server/mod.rs`, `src/server/handler.rs` — The site root is now canonicalized once in `server::run()` and passed as a pre-computed `PathBuf` into each connection handler. The per-request `site_root.canonicalize()` call in `resolve_path()` has been removed, eliminating a `realpath()` syscall on every request.

#### 2.4 — `open_browser` Deduplicated

`src/runtime/lifecycle.rs`, `src/runtime/events.rs`, `src/runtime/mod.rs` — The `open_browser` function was duplicated in `lifecycle.rs` and `events.rs`. It now lives in a single location (`src/runtime/mod.rs`) and both call sites use the shared implementation.

#### 2.5 — `#[serde(deny_unknown_fields)]` on All Config Structs

`src/config/mod.rs` — All `#[derive(Deserialize)]` config structs (`Config`, `ServerConfig`, `SiteConfig`, `TorConfig`, `LoggingConfig`, `ConsoleConfig`, `IdentityConfig`) now carry `#[serde(deny_unknown_fields)]`. A misspelled key such as `bund = "127.0.0.1"` now causes a startup error naming the unknown field rather than silently using the compiled-in default.

#### 2.6 — `auto_reload` Removed (Was Unimplemented)

`src/config/mod.rs`, `src/config/defaults.rs` — The `auto_reload` field was present in the config struct and advertised in the default `settings.toml` but had no implementation. It has been removed entirely. The `[R]` key for manual site stat reloads is unaffected.

#### 2.7 — ANSI Terminal Injection Prevention Documented and Tested

`src/config/loader.rs` — The existing `char::is_control` check on `instance_name` (which covers ESC `\x1b`, NUL `\x00`, BEL `\x07`, and BS `\x08`) is confirmed to prevent terminal injection. An explicit comment now documents the security intent, and dedicated test cases cover each injection vector.

#### 2.8 — Keyboard Input Task Failure Now Detected and Reported

`src/runtime/lifecycle.rs` — If the `spawn_blocking` input task exits (causing `key_rx` to close), `recv().await` returning `None` is now detected. A `warn`-level log entry is emitted ("Console input task exited — keyboard input disabled. Use Ctrl-C to quit.") and subsequent iterations no longer attempt to receive from the closed channel. Previously, input task death was completely silent.

#### 2.9 — `TorStatus::Failed` Now Carries a Reason String

`src/runtime/state.rs`, `src/console/dashboard.rs` — `TorStatus::Failed(Option<i32>)` (the exit code variant, which was never constructed) has been replaced with `TorStatus::Failed(String)`. Construction sites pass a brief reason string (`"bootstrap failed"`, `"stream ended"`, `"launch failed"`). The dashboard now renders `FAILED (reason) — see log for details` instead of a bare `FAILED`.

#### 2.10 — Graceful Shutdown Uses `JoinSet` and Proper Signalling

`src/runtime/lifecycle.rs`, `src/server/mod.rs`, `src/tor/mod.rs` — The 300 ms fixed sleep that gated shutdown has been replaced with proper task completion signalling. A clone of `shutdown_rx` is passed into `tor::init()`; the Tor run loop watches it via `tokio::select!` and exits cleanly on shutdown. In-flight HTTP connection tasks are tracked in a `JoinSet`; after the accept loop exits, `join_set.join_all()` is awaited with a 5-second timeout, allowing in-progress transfers to complete before the process exits.

#### 2.11 — Log File Flushed on Graceful Shutdown

`src/logging/mod.rs`, `src/runtime/lifecycle.rs` — A `pub fn flush()` function has been added to the logging module. The shutdown sequence calls it explicitly after the connection drain wait, ensuring all buffered log entries (including the `"RustHost shut down cleanly."` sentinel) are written to disk before the process exits.

---

### Phase 3 — Performance

#### 3.1 — `data_dir()` Computed Once at Startup

`src/runtime/lifecycle.rs` — `data_dir()` (which calls `std::env::current_exe()` internally) was previously called on every key event dispatch inside `event_loop`. It is now computed exactly once at the top of `normal_run()`, stored in a local variable, and passed as a parameter to all functions that need it.

#### 3.2 — `Arc<Path>` and `Arc<str>` Eliminate Per-Connection Heap Allocations

`src/server/mod.rs`, `src/server/handler.rs` — `site_root` and `index_file` are now wrapped in `Arc<Path>` and `Arc<str>` respectively before the accept loop. Each connection task receives a cheap `Arc` clone (reference-count increment) rather than a full heap allocation.

#### 3.3 — Dashboard Render Task Skips Redraws When Output Is Unchanged

`src/console/mod.rs` — The render task now compares the rendered output string against the previously written string. If identical, the `execute!` and `write_all` calls are skipped entirely. This eliminates terminal writes on idle ticks, which is the common case for a server with no active traffic.

#### 3.4 — MIME Lookup No Longer Allocates a `String` Per Request

`src/server/mime.rs` — The `for_extension` function previously called `ext.to_ascii_lowercase()`, allocating a heap `String` on every request. The comparison now uses `str::eq_ignore_ascii_case` directly against the extension string, with no allocation.

#### 3.5 — Log Ring Buffer Lock Not Held During `String` Clone

`src/logging/mod.rs` — The log line string is now cloned before acquiring the ring buffer mutex. The mutex is held only for the `push_back` of the already-allocated string, reducing lock contention from Arti's multi-threaded internal logging.

#### 3.6 — Tokio Feature Flags Made Explicit

`Cargo.toml` — `tokio = { features = ["full"] }` has been replaced with an explicit feature list: `rt-multi-thread`, `net`, `io-util`, `fs`, `sync`, `time`, `macros`, `signal`. Unused features (`process`, `io-std`) are no longer compiled, reducing binary size and build time.

---

### Phase 4 — Architecture & Design

#### 4.1 — Typed `AppError` Enum Introduced

`src/error.rs` (new), `src/main.rs`, all modules — The global `Box<dyn Error>` result alias has been replaced with a typed `AppError` enum using `thiserror`. Variants: `ConfigLoad`, `ConfigValidation`, `LogInit`, `ServerBind { port, source }`, `Tor`, `Io`, `Console`. Error messages now preserve structured context at the type level.

#### 4.2 — Config Structs Use Typed Fields

`src/config/mod.rs`, `src/config/loader.rs` — `LoggingConfig.level` is now a `LogLevel` enum (`Trace` | `Debug` | `Info` | `Warn` | `Error`) with `#[serde(rename_all = "lowercase")]`; the duplicate validation in `loader.rs` and `logging/mod.rs` has been removed. `ServerConfig.bind` is now `std::net::IpAddr` via `#[serde(try_from = "String")]`. The parse-then-validate pattern is eliminated in favour of deserialisation-time typing.

#### 4.3 — Dependency Log Noise Filtered by Default

`src/logging/mod.rs` — `RustHostLogger::enabled()` now suppresses `Info`-and-below records from non-`rusthost` targets (Arti, Tokio internals). Warnings and errors from all crates are still passed through. This prevents the ring buffer and log file from being flooded with Tor bootstrap noise. Configurable via `[logging] filter_dependencies = true` (default `true`); set `false` to pass all crate logs at the configured level.

#### 4.4 — `data_dir()` Free Function Eliminated; Path Injected

`src/runtime/lifecycle.rs` and all callers — The `data_dir()` free function (which called `current_exe()` as a hidden dependency) has been removed. The data directory `PathBuf` is now a first-class parameter threaded through the call chain from `normal_run`, enabling test injection of temporary directories.

#### 4.5 — `percent_decode` Correctly Handles Multi-Byte UTF-8 and Null Bytes

`src/server/handler.rs` — The previous implementation decoded each `%XX` token as a standalone `char` cast from a `u8`, producing incorrect output for multi-byte sequences (e.g., `%C3%A9` was decoded as two garbage characters instead of `é`). The function now accumulates consecutive decoded bytes into a `Vec<u8>` buffer and flushes via `String::from_utf8_lossy` when a literal character is encountered, correctly reassembling multi-byte sequences. Null bytes (`%00`) are left as the literal string `%00` in the output rather than being decoded.

#### 4.6 — `deny.toml` Updated with All Duplicate Crate Skip Entries

`deny.toml` — Five duplicate crate version pairs that were absent from `bans.skip` but present in the lock file have been added with comments identifying the dependency trees that pull each version: `foldhash`, `hashbrown`, `indexmap`, `redox_syscall`, and `schemars`. `cargo deny check` now passes cleanly.

#### 4.7 — `ctrlc` Crate Replaced with `tokio::signal`

`Cargo.toml`, `src/runtime/lifecycle.rs` — The `ctrlc = "3"` dependency has been removed. Signal handling is now done via `tokio::signal::ctrl_c()` (cross-platform) and `tokio::signal::unix::signal(SignalKind::interrupt())` (Unix), integrated directly into the `select!` inside `event_loop`. This eliminates threading concerns between the `ctrlc` crate's signal handler and Tokio's internal signal infrastructure.

---

### Phase 5 — Testing, Observability & Hardening

#### 5.1 — Unit Tests Added for All Security-Critical Functions

`src/server/handler.rs`, `src/server/mod.rs`, `src/config/loader.rs`, `src/console/dashboard.rs`, `src/tor/mod.rs` — `#[cfg(test)]` modules added to each file. Coverage includes: `percent_decode` (ASCII, spaces, multi-byte UTF-8, null bytes, incomplete sequences, invalid hex); `resolve_path` (normal file, directory traversal, encoded-slash traversal, missing file, missing root); `validate` (valid config, `site.directory` path traversal, absolute path, `logging.file` traversal, port 0, invalid IP, unknown field); `strip_timestamp` (ASCII line, multi-byte UTF-8 line, line with no brackets); `hsid_to_onion_address` (known test vector against reference implementation).

#### 5.2 — Integration Tests Added for HTTP Server Core Flows

`tests/http_integration.rs` (new) — Integration tests using `tokio::net::TcpStream` against a test server bound on port 0. Covers: `GET /index.html` → 200; `HEAD /index.html` → correct `Content-Length`, no body; `GET /` with `index_file` configured; `GET /../etc/passwd` → 403; request header > 8 KiB → 400; `GET /nonexistent.txt` → 404; `POST /index.html` → 400.

#### 5.3 — Security Response Headers Added to All Responses

`src/server/handler.rs` — All responses now include `X-Content-Type-Options: nosniff`, `X-Frame-Options: SAMEORIGIN`, `Referrer-Policy: no-referrer`, and `Permissions-Policy: camera=(), microphone=(), geolocation=()`. HTML responses additionally include `Content-Security-Policy: default-src 'self'` (configurable via `[server] content_security_policy` in `settings.toml`). The `Referrer-Policy: no-referrer` header is especially relevant for the Tor onion service: it prevents the `.onion` URL from leaking in the `Referer` header to any third-party resources loaded by served HTML.

#### 5.4 — Accept Loop Error Handling Uses Exponential Backoff

`src/server/mod.rs` — The accept loop previously retried immediately on error, producing thousands of log entries per second on persistent errors such as `EMFILE`. Errors now trigger exponential backoff (starting at 1 ms, doubling up to 1 second). `EMFILE` is logged at `error` level (operator intervention required); transient errors (`ECONNRESET`, `ECONNABORTED`) are logged at `debug`. The backoff counter resets on successful accept.

#### 5.5 — CLI Arguments Added (`--config`, `--data-dir`, `--version`, `--help`)

`src/main.rs`, `src/runtime/lifecycle.rs` — The binary now accepts `--config <path>` and `--data-dir <path>` to override the default config and data directory paths (previously inferred from `current_exe()`). `--version` prints the crate version and exits. `--help` prints a usage summary. These flags enable multi-instance deployments, systemd unit files with explicit paths, and CI test runs without relying on the working directory.

#### 5.6 — `cargo deny check` Passes Cleanly; `audit.toml` Consolidated

`deny.toml`, CI — `audit.toml` (which suppressed `RUSTSEC-2023-0071` without a documented rationale) has been removed. Advisory suppression is now managed exclusively in `deny.toml`, which carries the full justification. CI now runs `cargo deny check` as a required step, subsuming the advisory check. The existing rationale for `RUSTSEC-2023-0071` is unchanged: the `rsa` crate is used only for signature verification on Tor directory documents, not for decryption; the Marvin timing attack's threat model does not apply.

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
