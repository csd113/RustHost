# Changelog

All notable changes to RustHost are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
RustHost uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [v0.1.3]

### Simplified updates

- Added stronger static-file delivery polish with `Last-Modified` revalidation, precompressed asset sidecar support (`.br` / `.gz`), and a lighter-weight identity streaming path for common uncompressed responses.
- Moved the initial site scan off the startup critical path, skipping it in headless mode so the server can begin accepting traffic sooner.
- Added a shared reload path that also responds to `SIGHUP`, making headless deployments easier to operate without relying on the interactive dashboard.
- Improved headless runtime output so startup summarizes HTTP/HTTPS/site/Tor state, and Tor now logs the full onion address explicitly when it becomes ready.
- Removed a small hot-path allocation from `Accept-Encoding` parsing by switching quality-value parsing to a fixed-width stack-only loop.
- Reworked listener lifecycle management so HTTP, HTTPS, and redirect servers continuously reap completed connection tasks instead of retaining them until shutdown.
- Moved access-log disk writes onto a bounded background worker, preventing request handling from blocking on synchronous access-log I/O and surfacing dropped-log backpressure when the queue overflows.
- Hardened HTTPS redirect startup by validating redirect configs up front and requiring the redirect listener to bind successfully before startup continues.
- Switched generated defaults to safer production behavior by disabling automatic port fallback and built-in Tor until an operator explicitly enables them.
- Made graceful shutdown budgets configurable and applied them consistently to HTTP, HTTPS, redirect, and Tor drain behavior so normal restarts are less likely to cut off slow transfers.
- Made HTTPS startup fail closed so TLS configuration or HTTPS bind failures now stop startup instead of silently falling back to insecure HTTP-only serving.
- Fixed Tor's internal upstream address selection so onion traffic always connects back through loopback when the public listener is bound to `0.0.0.0` or `::`.
- Moved per-request filesystem path resolution onto Tokio's blocking pool to avoid starving the async runtime under slow-disk or hostile request load.
- Tightened connection admission so HTTP, HTTPS, and redirect listeners reject overflow immediately instead of holding accepted sockets open while waiting for permits.
- Completed the shared response hardening path so redirects, `OPTIONS`, `405`, `304`, and other non-file responses now receive the full security-header set consistently.
- Added automatic `Onion-Location` headers on clearnet HTTPS responses when the built-in Tor onion service is ready, so supporting browsers can surface the `.onion` version of the current page.
- Wired `site.error_503` into runtime serving and preload custom error pages at startup with size limits, removing per-request reloads and dead config.
- Improved access-log accuracy by recording real `Content-Length` values when known and `-` when a streamed/compressed size is not known ahead of time.
- Made compression more production-friendly by honoring `Accept-Encoding` quality values and skipping obviously poor candidates such as tiny or already-compressed assets.
- Hardened private filesystem creation further by validating directory chains, rejecting symlink hops, and keeping restrictive permissions in place for Tor and TLS state.
- Cleaned up startup and shutdown reliability by draining failed startup tasks, allowing structured access-log reinitialization after shutdown, and holding ACME lifecycle ownership in runtime state instead of a permanent one-shot global.
- Fixed IPv6 listener binding and local URL rendering so HTTP, HTTPS, redirect, dashboard, and localhost flows all handle bracketed IPv6 addresses correctly.
- Corrected the Arti relay timeout behavior so active long-lived transfers are limited by idle time instead of a mistaken full-session wall clock.
- Bounded directory listings during traversal instead of collecting and sorting an entire hostile directory before truncation.
- Expanded test coverage with HTTPS handshake tests, IPv6 HTTP tests, ACME restart lifecycle coverage, redirect handling, proxy IP resolution, custom `503` pages, and connection-limit rejection.
- Added top-of-file file/location reference headers across the codebase, removed stale issue-fix annotations, and continued splitting logic into smaller focused modules.
- Rewrote the README and setup guide to better document production scope, cross-platform behavior, HTTPS/Tor setup, headless operation, and static-hosting-only expectations.
- Removed duplicate setup filename variants so the repository stays clean on case-insensitive macOS and Windows filesystems.

---

## [v0.1.2]

### Added
- **HTTPS support** — RustHost can now serve your site over a secure, encrypted connection (the padlock icon in your browser). Works out of the box with no extra software needed.
- **Automatic self-signed certificates** — when you turn on HTTPS with no other setup, RustHost creates its own certificate for local development. Great for testing on your own machine.
- **Let's Encrypt integration** — RustHost can automatically get and renew a free, trusted certificate from Let's Encrypt so browsers won't show any warnings for your real domain.
- **Bring-your-own certificate** — if you already have certificate files from another provider, you can point RustHost at them directly.
- **HTTP-to-HTTPS redirect** — optionally sends visitors who arrive on the plain HTTP address over to the secure HTTPS address automatically.
- **`[tls]` config section** — new settings in `settings.toml` to control all of the above. If you don't add this section, everything works exactly as before — nothing breaks.
- **Security headers on HTTPS** — secure connections automatically include headers that tell browsers to always use HTTPS for your site in the future.

### Changed
- **Connection handler is now flexible** — the part of RustHost that talks to browsers was updated so it can handle both regular and encrypted connections. Existing HTTP behavior is unchanged.

---

## [v0.1.1]

### Added
- **Depth-bounded `scan_site` BFS** — the directory scanner now stops at 64 levels deep and emits a warning instead of running indefinitely on adversarially deep directory trees.
- **Multiple log rotation backups** — `LogFile::rotate` now keeps up to five numbered backup files (`.log.1`–`.log.5`) instead of one, matching what operators expect from tools like `logrotate`.

### Changed
- **`lib.rs` visibility audit** — items only used in integration tests (`percent_decode`, `ByteRange`, `Encoding`, `onion_address_from_pubkey`) are now re-exported under `#[cfg(test)]` rather than unconditionally, reducing the public API surface.
- **Comment hygiene** — all internal `fix X.Y` tags have been replaced with descriptive prose so the rationale for each decision is clear to contributors.

---

## [0.1.0] — 2025-07-01

This release resolves all 40 issues identified in the 2026-03-20 security and reliability audit. Every fix is listed below, grouped by the phase it belongs to.

---

### Added

#### Repository & CI (Phase 0)

- **`rust-toolchain.toml`** — pins the nightly channel so every contributor and CI run uses the same compiler. No more "works on my machine" build failures.
- **GitHub Actions CI** — runs build, test, clippy, rustfmt, `cargo-audit`, and `cargo-deny` on Ubuntu, macOS, and Windows on every push and PR.
- **`Cargo.toml` profile tuning** — `opt-level = 1` for dev dependencies speeds up debug builds; the release profile uses `lto = true`, `strip = true`, and `codegen-units = 1` for a smaller, faster binary.

#### HTTP Server

- **Keep-alive via `hyper` 1.x** — migrated from a hand-rolled single-shot HTTP/1.1 parser to `hyper`. Eliminates the 30–45 second Tor page-load penalty that was caused by `Connection: close` on every response.
- **Brotli and Gzip compression** — negotiated via `Accept-Encoding`. Brotli is preferred over Gzip for Tor users since they pay in latency for every byte.
- **`ETag` / conditional GET** — weak ETags computed from file modification time and size. Returns `304 Not Modified` when `If-None-Match` matches, saving a round-trip.
- **Range requests** — supports `bytes=N-M`, `bytes=N-`, and `bytes=-N` suffix forms. Returns `206 Partial Content` or `416 Range Not Satisfiable` as appropriate. Enables audio and video seeking.
- **Per-IP rate limiting** — `DashMap`-backed lock-free CAS loop. Connections beyond `max_connections_per_ip` are dropped at accept time with a TCP RST.
- **Smart `Cache-Control`** — HTML responses get `no-store`; content-hashed assets (8–16 hex characters in the filename stem) get `max-age=31536000, immutable`; everything else gets `no-cache`.
- **Security headers on every response** — `X-Content-Type-Options: nosniff`, `X-Frame-Options: SAMEORIGIN`, `Referrer-Policy: no-referrer`, and `Permissions-Policy: camera=(), microphone=(), geolocation=()`. HTML responses additionally include a configurable `Content-Security-Policy`.
- **`--serve <dir>` one-shot mode** — serve a directory directly without a `settings.toml`. Skips first-run setup entirely.
- **Extended MIME types** — added `.webmanifest`, `.opus`, `.flac`, `.glb`, and `.ndjson`.
- **Combined Log Format access log** — written to `logs/access.log` with owner-only `0600` permissions.

#### Tor / Onion Service

- **Idle timeout fix** (`copy_with_idle_timeout`) — replaced the wall-clock cap (which disconnected active large downloads after 60 seconds) with a true per-side idle deadline that resets on every read or write.
- **`reference_onion` test** — replaced the tautological self-referencing test with an external test vector computed independently using Python's standard library.

#### Configuration

- **URL redirect and rewrite rules** — `[[redirects]]` table in `settings.toml`, checked before filesystem resolution. Supports 301 and 302.
- **Custom error pages** — `site.error_404` and `site.error_503` config keys resolve to HTML files served with the correct status codes.
- **`--config` and `--data-dir` CLI flags** — override the default config and data directory paths. Enables multi-instance deployments and systemd unit files with explicit paths.
- **`--version` and `--help` CLI flags**.
- **`#[serde(deny_unknown_fields)]` on all config structs** — a misspelled key like `bund = "127.0.0.1"` causes a clear startup error instead of silently using the default.
- **Typed config fields** — `bind` is `std::net::IpAddr`; `log level` is a `LogLevel` enum. Invalid values are caught at deserialisation time, not after the server starts.

#### Features

- **SPA fallback routing** — unknown paths fall back to `index.html` when `site.spa_routing = true`, enabling React, Vue, and Svelte client-side routing.
- **`canonical_root` hot reload** — the `[R]` keypress pushes a new canonicalised root to the accept loop over a `watch` channel without restarting the server.
- **Dependency log filtering** — Arti and Tokio internals at `Info` and below are suppressed by default, keeping the log focused on application events. Configurable via `filter_dependencies`.

#### Reliability

- **Exponential backoff for Tor retries** — re-bootstrap retries now use exponential backoff (30 s, 60 s, 120 s, …, capped at 300 s) instead of a fixed linear delay.
- **Shutdown drain per subsystem** — HTTP and Tor drains each have their own independently-bounded timeout (5 s for HTTP, 10 s for Tor) so a slow HTTP drain doesn't steal time from Tor circuit teardown.
- **`percent-encoding` crate** — replaced the hand-rolled `percent_decode` function with the audited upstream crate. Added a null-byte guard specific to filesystem path use.
- **`scan_site` partial failure** — unreadable subdirectories are skipped with a warning instead of aborting the entire scan.
- **`fstat` batching** — `LogFile::write_line` calls `fstat` every 100 writes (instead of on every record) to reduce syscall overhead on active servers.

#### Testing & CI

- **Unit tests for all security-critical functions** — `percent_decode`, `resolve_path`, `validate`, `strip_timestamp`, and `hsid_to_onion_address` all have `#[cfg(test)]` coverage.
- **Integration tests** (`tests/http_integration.rs`) — covers all HTTP core flows using raw `TcpStream`: 200, HEAD, 304, 403, 404, 400, range requests, and oversized headers.

---

### Fixed

#### Critical (Phase 1)

- **Config path traversal** — `validate()` now rejects any `site.directory` or `logging.file` value that is an absolute path, contains `..`, or contains a platform path separator. Previously, `directory = "../../etc"` would cause the server to serve the entire `/etc` tree.
- **Tor port race condition** — replaced the 50 ms sleep used to synchronise the HTTP server's bound port with the Tor subsystem with a `tokio::sync::oneshot` channel. The server sends the actual bound port through the channel before entering the accept loop. Previously, on a loaded system, the race could be lost silently, causing every inbound Tor connection to fail with `ECONNREFUSED` to port 0 while the dashboard showed a healthy green status.
- **XSS in directory listings** — `build_directory_listing()` now HTML-entity-escapes all filenames before interpolating them into link text, and percent-encodes filenames in `href` attributes. Previously, a file named `"><script>alert(1)</script>` produced an executable XSS payload in any directory listing page.
- **HEAD requests sent a response body** — `HEAD` requests now send the correct headers (including `Content-Length` reflecting the full body size) but no body, as required by RFC 7231 §4.3.2. Previously, the full file was sent.
- **Slow-loris DoS** — `read_request()` is now wrapped in a 30-second timeout. Connections that don't deliver a complete request header in time receive a `408 Request Timeout`. Configurable via `request_timeout_secs`.
- **Unbounded connection spawning** — both the HTTP accept loop and the Tor stream loop now use a `tokio::sync::Semaphore` to cap concurrent connections (default: 256). Previously, unlimited concurrent connections could exhaust file descriptors and task stack memory.
- **Files loaded entirely into memory** — replaced `tokio::fs::read` (which loaded the entire file into a `Vec<u8>`) with `tokio::fs::File::open` + `tokio::io::copy`. Memory per connection is now bounded by the kernel socket buffer (~128–256 KB) regardless of file size.
- **`strip_timestamp` panic on non-ASCII log lines** — the old implementation used a byte index derived from `.bytes()` to slice a `&str`, which panicked when the index fell inside a multi-byte UTF-8 character. Now uses `splitn(3, ']')`, which is both panic-safe and handles Unicode correctly.
- **`TorStatus` not updated when onion service terminates** — when the onion service stream ends unexpectedly, the status is now set to `TorStatus::Failed("stream ended")` and the `.onion` address is cleared. Previously, the dashboard permanently showed a healthy green badge after the service had silently stopped.
- **Terminal not restored on panic or crash** — a `std::panic::set_hook` is registered at startup to call `console::cleanup()` (which issues `LeaveAlternateScreen`, `cursor::Show`, and `disable_raw_mode`) on all exit paths. The cleanup function is idempotent, so calling it from multiple paths is safe.

#### High — Reliability (Phase 2)

- **HTTP request reading done byte-by-byte** — `read_request()` previously issued up to 8,192 individual `read` syscalls per request. The stream is now wrapped in `tokio::io::BufReader` and headers are read line-by-line. Also correctly handles `\r\n\r\n` split across multiple TCP segments.
- **`scan_site` only scanned the top-level directory** — now performs a full breadth-first traversal using a work queue, counting files and sizes in all subdirectories. Unreadable directories are skipped with a warning instead of propagating an error.
- **`canonicalize()` called on every request** — the site root is now canonicalised once at startup and passed into each connection handler. Eliminates a `realpath()` syscall on every single request.
- **`open_browser` duplicated** — the function existed in two separate source files. Now lives in one place (`src/runtime/mod.rs`).
- **`auto_reload` config field was unimplemented** — removed entirely. It was present in the config struct and advertised in the default `settings.toml` but had no effect.
- **Keyboard input task failure was silent** — if the input task exits unexpectedly (causing `key_rx` to close), a warning is now logged ("Console input task exited — keyboard input disabled. Use Ctrl-C to quit."). Previously, this failure was completely invisible.
- **`TorStatus::Failed` carried an exit code that was never set** — replaced `TorStatus::Failed(Option<i32>)` with `TorStatus::Failed(String)`. The dashboard now shows `FAILED (reason) — see log for details` with a human-readable reason string.
- **Graceful shutdown used a fixed 300 ms sleep** — replaced with proper task completion signalling. In-flight HTTP connections are tracked in a `JoinSet` and given 5 seconds to finish. The Tor run loop watches the shutdown signal via `tokio::select!` and exits cleanly.
- **Log file not flushed on shutdown** — added `pub fn flush()` to the logging module. The shutdown sequence calls it explicitly after the connection drain, ensuring the final log entries (including the shutdown sentinel) reach disk.

#### Medium (Phase 3–5)

- **`data_dir()` recomputed on every key event** — now computed once at startup and passed as a parameter. Removes the hidden `current_exe()` call from the hot event loop.
- **Per-connection heap allocations for `site_root` and `index_file`** — both are now wrapped in `Arc<Path>` and `Arc<str>` before the accept loop. Each connection task gets a cheap reference-count increment instead of a full heap allocation.
- **Dashboard redrawn on every tick even when unchanged** — the render task now compares the new output against the previous one and skips writing to the terminal if they're identical. Eliminates unnecessary terminal writes on idle servers.
- **MIME lookup allocated a heap `String` per request** — replaced `ext.to_ascii_lowercase()` with `str::eq_ignore_ascii_case`. No allocation.
- **Log ring buffer lock held during `String` clone** — the log line is now cloned before acquiring the mutex. The lock is held only for the `push_back`, reducing contention from Arti's multi-threaded logging.
- **`tokio = { features = ["full"] }` compiled unused features** — replaced with an explicit feature list (`rt-multi-thread`, `net`, `io-util`, `fs`, `sync`, `time`, `macros`, `signal`). Reduces binary size and build time.
- **`sanitize_header_value` only stripped CR/LF** — now strips all C0 control characters (NUL, ESC, TAB, DEL), preventing header injection via crafted filenames or redirect targets.
- **`expose_dotfiles` checked on URL path instead of resolved path components** — the guard now inspects each path component after `canonicalize`, blocking escapes like `/normal/../.git/config`.
- **`render()` acquired the `AppState` lock twice per tick** — now acquires it once per tick, eliminating the TOCTOU race between two sequential acquisitions.
- **Stale "polling" message in dashboard** — Arti is event-driven, not polled. The message implying periodic polling has been removed.
- **`percent_decode` produced garbage for multi-byte UTF-8 sequences** — the old implementation decoded each `%XX` token as a standalone `char` cast from a `u8`. It now accumulates decoded bytes into a buffer and flushes via `String::from_utf8_lossy`, correctly reassembling multi-byte sequences. Null bytes (`%00`) are left as the literal string `%00`.
- **`deny.toml` missing five duplicate crate skip entries** — `foldhash`, `hashbrown`, `indexmap`, `redox_syscall`, and `schemars` were absent from `bans.skip` but present in the lock file. `cargo deny check` now passes cleanly.
- **`ctrlc` crate conflicted with Tokio's signal handling** — replaced with `tokio::signal::ctrl_c()` and `tokio::signal::unix::signal(SignalKind::interrupt())` integrated directly into `event_loop`. Eliminates the threading concerns between the two signal handling mechanisms.
- **`open_browser` silently swallowed spawn errors** — spawn errors are now logged at `warn` level.

---

### Changed

- **`Box<dyn Error>` replaced with typed `AppError` enum** — uses `thiserror`. Variants: `ConfigLoad`, `ConfigValidation`, `LogInit`, `ServerBind { port, source }`, `Tor`, `Io`, `Console`. Error messages now preserve structured context.
- **Single `write_headers` path** — all security headers (CSP, HSTS, `X-Content-Type-Options`, etc.) are emitted from one function. Redirect responses delegate here instead of duplicating the header list, eliminating the risk of the two diverging.
- **`audit.toml` consolidated into `deny.toml`** — advisory suppression is managed in one place with documented rationale. CI now runs `cargo deny check` as a required step.

---

### Removed

- **`auto_reload` config field** — was documented but never implemented. Removed to avoid confusion. The `[R]` key for manual site stat reload is unaffected.
- **`ctrlc` crate dependency** — replaced by `tokio::signal` (see above).
