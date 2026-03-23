# RustHost — Full Project Audit

> Audited from source archive (Archive.zip) and https://github.com/csd113/RustHost  
> Rust edition 2021 · MSRV 1.90 · Arti 0.40 · Tokio 1

---

## Preamble

This is a thoughtful, iteratively-improved codebase. The internal "fix X.Y" comments reveal at least two full self-review passes, and the results show: `unsafe` is forbidden at the workspace level, the Tor integration migrated from subprocess to Arti in-process, `NonZeroU16`/`IpAddr` push validation to serde, and the path-resolution security model is correct. The developer clearly knows Rust.

That said, the project is **not elite**. The gaps listed below are not style nits — they are functional blockers that would stop real users from relying on it, or that represent genuine attack surface. Read this as: "here's exactly what it would take to make this worth deploying."

---

## 1. Architecture & Design

### 🔴 CRITICAL — No HTTP/1.1 keep-alive or HTTP/2

Every response carries `Connection: close`. The server handles exactly one request per TCP connection and drops the socket. For clearnet this is merely slow; **for Tor this is a project-killing design flaw.** Each Tor circuit requires a multi-RTT rendezvous handshake (~1–3 s on a typical path). A page with 15 assets (HTML + CSS + JS + images) forces 15 sequential rendezvous handshakes. A typical page load over this server will take **15–45 seconds** on Tor.

**Fix:** Add HTTP/1.1 keep-alive in the request loop inside `handler.rs`. Parse the `Connection:` request header and re-enter `receive_request` on the same stream. Long-term, HTTP/2 via `h2` or `hyper` eliminates head-of-line blocking entirely.

### 🟠 HIGH — `canonical_root` is never refreshed after startup

In `server/mod.rs`, `canonical_root` is canonicalized once at server start. If the `site/` directory is deleted and recreated while the server is running (e.g., during a content deployment), `canonical_root` points to the now-dead inode. All requests return `Resolved::Fallback`. Pressing `[R]` updates `site_file_count` but **does not update `canonical_root`**. Recovery requires a full process restart.

**Fix:** Re-resolve `canonical_root` inside the `Reload` event handler in `events.rs` and push the new value to the server via a `watch` channel.

### 🟠 HIGH — Tor and HTTP semaphores are sized identically but compete for different resources

The T-2 fix correctly sizes both semaphores to `max_connections`. However, a Tor stream + its proxied HTTP connection occupy **two** file descriptors simultaneously. Under max load, the process holds `2 × max_connections` open sockets, but the OS `ulimit` and `EMFILE` guard only knows about the Tor semaphore. The effective capacity is half what the operator configured.

**Fix:** Document this clearly. Consider sizing the Tor semaphore to `max_connections / 2` or adding a dedicated Tor connection limit to the config.

### 🟡 MEDIUM — No `[profile.dev]` optimization

First `cargo build` (dev) with vendored OpenSSL and the full Arti tree takes 90–120 seconds on a modern machine. There's no `[profile.dev]` section in `Cargo.toml` to set `opt-level = 1` for dependencies, which would dramatically reduce compile time without the debug-info cost of a full release build.

```toml
[profile.dev.package."*"]
opt-level = 1
```

### 🟡 MEDIUM — Module boundary between `tor` and `server` is leaky

`tor/mod.rs` calls `TcpStream::connect(local_addr)` directly against the HTTP server. This creates an implicit contract (the HTTP server must be listening on a specific `IpAddr:port`) that bypasses all the `SharedState` machinery. A refactor that changes how the HTTP server exposes its address would silently break Tor proxying.

**Fix:** Pass the bound address through `SharedState.actual_port` + `config.server.bind` (which already happens in lifecycle), and have `tor::init` receive a `SocketAddr` rather than separate `IpAddr`/`u16` arguments.

### 🟡 MEDIUM — Single log file + simplistic rotation

`logging/mod.rs` rotates `rusthost.log` → `rusthost.log.1` at 100 MB. Only one backup is kept. There's no timestamp in the rotated filename, no gzip, and no hook to signal an external log manager. On a server running at DEBUG level with Arti noise enabled, 100 MB fills in hours.

---

## 2. Code Quality

### 🔴 CRITICAL — `onion_address_from_pubkey` test is a tautology

The `reference_onion` function in `tor/mod.rs` tests uses the **same algorithm** as the production function. It tests determinism and format, but a consistent implementation bug in both would pass. There is no cross-check against a known external test vector.

The Tor Rendezvous Specification defines exact test vectors. One should be hardcoded:

```rust
// Known vector from the Tor spec, independently computed:
// All-zero key → "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa3.onion"
// (compute the exact value offline and assert it here)
#[test]
fn hsid_to_onion_address_known_vector() {
    let pubkey = [0u8; 32];
    assert_eq!(onion_address_from_pubkey(&pubkey), "aaaa...aaa3.onion");
}
```

### 🔴 CRITICAL — `copy_with_idle_timeout` is not actually an idle timeout

In `tor/mod.rs`, `copy_with_idle_timeout` uses `tokio::time::sleep(IDLE_TIMEOUT)` alongside `copy_bidirectional`. **`sleep` starts when the call begins, not when I/O stalls.** A legitimate large file download (say, a 50 MB video) that takes 65 seconds of continuous data transfer is killed at second 60 even though the connection was never idle. The variable name and doc comment say "idle" but the implementation is a wall-clock cap.

**Fix:** Use a proper idle timeout that resets on each read/write. This requires a custom bidirectional copy loop that arms a `tokio::time::Sleep` and resets it on each successful I/O operation, or wraps each read/write in `tokio::time::timeout`.

### 🟠 HIGH — `write_redirect` duplicates all security headers

`write_redirect` in `handler.rs` manually re-lists every security header that `write_headers` also emits. Any future header addition (e.g., `Cross-Origin-Opener-Policy`) must be applied in two places. This is already a bug: `write_redirect` emits CSP on all redirects regardless of content-type, while `write_headers` correctly gates CSP to HTML responses.

**Fix:** Remove `write_redirect` and call `write_headers` with `status: 301, reason: "Moved Permanently"`, adding a `Location` header via a new optional parameter or a pre-call `stream.write_all`.

### 🟠 HIGH — No per-IP request rate limiting

The `Semaphore` limits total *concurrent* connections, but a single IP can consume all 256 slots simultaneously and DoS every other user. There's no per-IP connection limit, no request-rate limit, and no backpressure signal to the caller. On Tor, adversarial clients share exit nodes with legitimate users, making this more exploitable, not less.

**Fix:** Add a `HashMap<IpAddr, AtomicU32>` of active connections per peer, checked at accept time. This fits naturally in the accept loop in `server/mod.rs`.

### 🟡 MEDIUM — `receive_request` ignores all headers after the request line

The function reads all headers into a `String` for the 8 KiB check but never parses them. `Host`, `Content-Length`, `Transfer-Encoding`, `If-None-Match`, `Range`, `Accept-Encoding` are all silently discarded. This isn't a bug today, but it makes adding any feature that requires inspecting request headers a large refactor.

**Fix:** Parse headers into a lightweight `HashMap<&str, &str>` (or a dedicated struct) after reading them. This enables conditional GET, range requests, compression negotiation, and keep-alive without touching the read logic.

### 🟡 MEDIUM — Dashboard TorStatus message says "polling"

`dashboard.rs` line: `TorStatus::Starting => yellow("STARTING — polling for .onion address…")`.  
The Arti integration is fully event-driven — there is no polling. Stale copy-paste from the old C-Tor subprocess implementation.

### 🟡 MEDIUM — `sanitize_header_value` is incomplete

The function strips `\r` and `\n` from header values. It does not strip:
- Null bytes (`\x00`) — rejected by RFC 9110 but some parsers accept them
- Other C0 control characters (`\x01`–`\x1f`, `\x7f`) — legal in filenames on Linux

For the `Location` header, a filename containing `\x00` after CR/LF stripping could still produce an anomalous URL. Add a broader control-character strip:

```rust
.filter(|&c| !c.is_control())
```

### 🟡 MEDIUM — `default_data_dir` warning string has a stray whitespace

In `lifecycle.rs`, the fallback `eprintln!` warning in `default_data_dir` contains a multi-line string with a leading run of spaces at the line join:
```
"Warning: cannot determine executable path ({e});                  using ./rusthost-data…"
```
This renders as a very long single line with ~18 spaces mid-sentence. Use `\n` + indentation instead.

### 🟡 MEDIUM — `tor/mod.rs`: the log message for "resetting retry counter" contains leading whitespace

```rust
log::info!(
    "Tor: resetting retry counter — last disruption was                                  over an hour ago."
)
```
Same issue as above — line continuation whitespace is included in the string.

### 🟡 MEDIUM — `open_browser` spawns a child process without logging the outcome

In `runtime/mod.rs`, `open_browser` ignores the `Result` from `Command::spawn()` on all platforms. If `xdg-open` isn't installed (common on headless Linux servers), the user gets no feedback. The `[O]` key silently does nothing.

**Fix:** Log a `warn!` when the spawn fails.

### 🟡 MEDIUM — `percent_decode` reinvents `percent-encoding`

The custom percent-decoder in `handler.rs` is 60 lines long, covers null-byte injection, and handles multi-byte UTF-8 correctly. All of this is already provided by the `percent-encoding` crate (3 lines). The custom implementation is a maintenance liability: if a bug is found in `percent_decode`, it won't be caught by an upstream security advisory.

### 🟡 MEDIUM — `LogFile::write_line` checks file size on every write

```rust
if let Ok(meta) = self.file.metadata() {
    if meta.len() >= MAX_LOG_BYTES {
```

This is a `fstat` syscall on every log record. At DEBUG level with Arti noise, this could be thousands of syscalls per second. Cache the size and only re-stat after every N writes (or increment an internal counter).

### 🟡 MEDIUM — `AppState` fields are not reset between test runs (integration tests)

The integration tests in `tests/http_integration.rs` create a fresh `AppState::new()` per test, which is correct. However, `LOG_BUFFER` is a `OnceLock` global in `logging/mod.rs`. If `logging::init` is called in one test run and the test binary is reused, the second call silently returns an error (the logger is already set). The tests currently skip logging, which avoids this, but it means the logging path is not integration-tested.

### 🟡 MEDIUM — `scan_site` returns `(u32, u64)` but file count could theoretically overflow

`count = count.saturating_add(1)` wraps at 4 billion files. Practically not an issue, but returning `u64` for both would be consistent.

---

## 3. Performance

### 🔴 CRITICAL — No HTTP keep-alive (see Architecture §1)

Covered above. The single largest performance issue in the codebase by an order of magnitude.

### 🟠 HIGH — No response compression (gzip/brotli)

All files are served raw. For Tor users on a ~100–500 kbps effective circuit, a 200 KB minified JavaScript file takes 3–16 seconds. Brotli compression typically achieves 70–85% reduction on text assets. Without compression, the Tor user experience is extremely poor.

**Fix:** Check `Accept-Encoding` request header (once header parsing is added), and compress responses with the `async-compression` crate. Pre-compress files at startup to avoid per-request CPU overhead.

### 🟠 HIGH — No conditional GET (ETag / Last-Modified)

All responses carry `Cache-Control: no-store`. There is no `ETag`, `Last-Modified`, `If-None-Match`, or `If-Modified-Since` support. Every browser reload re-fetches every asset, regardless of whether it changed. This is anti-caching by design, which is appropriate for Tor (you don't want assets cached with the onion address in the referrer), but it should be a conscious per-resource policy, not a blanket prohibition. At minimum, `Cache-Control: no-store` should only apply to HTML and not to immutable assets.

### 🟠 HIGH — No `sendfile` / zero-copy file transfer

`tokio::io::copy` reads file data into a userspace buffer then writes it to the socket. On Linux, `sendfile(2)` skips the userspace copy entirely, halving the CPU cost for large file transfers. The `tokio-uring` crate (or the `sendfile` feature in `nix`) enables this.

### 🟡 MEDIUM — `write_headers` allocates a `String` per response

Every call to `write_headers` creates a heap-allocated `String` via `format!`. For static sites under load, this is many small allocations per second. Using a stack-allocated `ArrayString` or writing directly to the `TcpStream` in multiple `write_all` calls would eliminate this.

### 🟡 MEDIUM — `build_directory_listing` buffers the entire HTML response

The directory listing HTML is built in a single `String` before sending. For directories with thousands of entries this is slow. A streaming approach (write HTML head, iterate entries line-by-line) would reduce peak memory and time-to-first-byte.

### 🟡 MEDIUM — `render` acquires the `AppState` lock twice per tick

In `console/mod.rs`:
```rust
let mode = state.read().await.console_mode.clone(); // lock 1
// ...
let s = state.read().await; // lock 2
```

A single `read()` that extracts both mode and the full state would halve the lock acquisitions per render tick.

### 🟡 MEDIUM — No Range request support

Large media files (video, audio) cannot be seeked. Streaming players and download managers depend on `Range: bytes=N-M` requests, which this server rejects with 400 (the method is GET, which the server allows, but range headers are silently ignored and the full file is sent). The client sees the full response instead of the range, which some clients reject entirely.

### 🟡 MEDIUM — `scan_site` BFS traversal is not depth-bounded

A deeply nested directory tree (or a symlink cycle that somehow slips through the inode check on Windows) could consume unbounded stack space. The `queue` grows proportionally to directory count. Consider adding a depth limit.

---

## 4. Security

### 🔴 CRITICAL — No per-IP rate limiting (see Code Quality §2)

A single client can open 256 simultaneous connections (the full pool) and deny service to every other user. This is especially dangerous on a Tor hidden service because:
1. Tor clients share exit nodes, so an IP-level ban catches innocent users
2. The attacker pays very little (Tor circuit setup is cheap for the attacker)

### 🔴 CRITICAL — `Cache-Control: no-store` prevents Tor Browser's first-party isolation from working correctly

Tor Browser applies first-party isolation per-origin. With `no-store` on all resources, the browser cannot serve cached assets even on the same page load. Every sub-resource request goes over a separate Tor circuit. This is **functionally broken** for multi-asset pages. The intention to prevent caching (good) is implemented too broadly (bad).

**Fix:** Apply `no-store` only to HTML documents. Immutable assets (hashed filenames, images, fonts) should use `Cache-Control: max-age=31536000, immutable`.

### 🟠 HIGH — Tor keypair directory is fixed at `arti_state/`; no key backup/export path

`ensure_private_dir` correctly sets `0o700` on Unix, but:
1. On **Windows**, directory permissions are not set at all. The keypair is world-readable to any local user.
2. There is no mechanism to **back up** the keypair. If `arti_state/` is accidentally deleted, the `.onion` address is permanently lost.
3. There is no documented way to **import** an existing keypair (e.g., migrate from another host).

### 🟠 HIGH — Log file leaks the `.onion` address

`tor/mod.rs` logs the onion address at `INFO` level in a prominent banner. The log file is created with `0o600` (owner read-only), which is correct. However:
1. If the operator runs `rusthost-cli > output.txt`, the onion address appears in a world-readable file
2. If the operator shares logs for debugging, the onion address is in the paste

**Fix:** Hash or truncate the address in the log line. Show only the first 8 characters plus `…` to identify it while not fully exposing it.

### 🟠 HIGH — `open_browser` passes the URL to a shell command without explicit sanitization

In `runtime/mod.rs`, the Windows path does:
```rust
std::process::Command::new("cmd").args(["/c", "start", "", url])
```

The URL is constructed from `IpAddr` + `u16`, so the values are safe today. But `open_browser` is `pub` in `crate::runtime`, callable from anywhere with an arbitrary string. If a future caller passes an attacker-influenced URL (e.g., from the onion address or a config field), the empty-string third argument to `start` doesn't fully protect against shell expansion on Windows. Document or enforce that only internal URLs may be passed.

### 🟠 HIGH — No HTTPS option for the clearnet server

When `bind = "0.0.0.0"`, the server listens on all interfaces with plaintext HTTP. There is no TLS termination, no self-signed certificate generation, and no ACME integration. A user who exposes the server to a local network (e.g., home lab) has no way to get HTTPS without a reverse proxy.

### 🟡 MEDIUM — `expose_dotfiles` check happens before URL decode

In `resolve_path`, the dot-file check iterates `Path::new(url_path).components()` where `url_path` is already percent-decoded. This is correct. However, the check runs on the URL path, not on the final resolved filesystem path. A symlink named `safe-name` that points to `.git/` inside the site root would bypass the dot-file filter (the symlink's own name doesn't start with `.`, but the target is a dot-directory).

**Fix:** After resolving the canonical path, check whether any component of the path **relative to `canonical_root`** starts with `.`.

### 🟡 MEDIUM — `build_directory_listing` generates URLs with percent-encoded components but no `<base>` tag

The directory listing uses `percent_encode_path(name)` for hrefs. If the current URL path contains a trailing `/` from a redirect, the relative href `base/encoded_name` may resolve incorrectly on some browser/proxy combinations. Use absolute paths (`/path/to/dir/file`) to eliminate ambiguity.

### 🟡 MEDIUM — No `Strict-Transport-Security` header

Even though TLS isn't supported, the HSTS header should be documented as a TODO. Adding HTTPS later without HSTS means browsers will silently downgrade connections.

### 🟡 MEDIUM — `--config` and `--data-dir` CLI flags accept absolute paths with no restriction

A user who passes `--config /etc/passwd` will get a likely TOML parse error, but `--data-dir /tmp/attacker-controlled` could be used to point the server at attacker-controlled content. This is a misconfiguration concern, not a true security issue, but it's worth documenting.

---

## 5. Reliability & Stability

### 🟠 HIGH — Tor reconnect loop uses linear backoff, not exponential

`RETRY_BASE_SECS = 30` and the delay is `30 * attempt`. After 5 attempts: 30 s, 60 s, 90 s, 120 s, 150 s. This is linear. True exponential backoff (`30 * 2^attempt`, capped at e.g. 600 s) is more respectful of the Tor network under outage conditions and is the industry standard for circuit breakers.

### 🟠 HIGH — Shutdown drain timeout of 8 seconds may be insufficient

In `lifecycle.rs`, the total shutdown budget is 8 seconds split between the HTTP server drain (5 s) and Tor cleanup (whatever's left, often 3 s or less). Tor circuits with active transfers can take longer to close gracefully. On slow Tor paths, `copy_bidirectional` might still be blocked. The `_` return from `timeout` means the process continues regardless, which is correct, but the 8-second hard cap means Tor connections are abruptly terminated rather than gracefully closed.

### 🟡 MEDIUM — If `port_tx` send fails (channel dropped before use), lifecycle returns an error with no cleanup

In `server/mod.rs`, if the bind fails, `port_tx` is dropped without sending. `lifecycle.rs` catches the `Err` from the oneshot and returns `AppError::ServerStartup`. But by this point, logging may have been initialized and the async runtime is still running. The error path in `main` calls `console::cleanup()` and `eprintln!`, which is correct, but it doesn't explicitly shut down the Tor task (it was never started) or flush the log.

**Fix:** Add `logging::flush()` to the error path in `main`.

### 🟡 MEDIUM — `LOG_BUFFER` is a global `OnceLock`; `logging::init` fails silently if called twice

`log::set_logger` returns `Err` if a logger is already set, and the code maps this to `AppError::LogInit`. This is correct. However, `LOG_BUFFER.get_or_init(...)` silently no-ops on the second call. In a test binary that calls `logging::init` from multiple `#[tokio::test]` tests, only the first test gets a fresh ring buffer. This is a test isolation issue, not a production issue, but it means the logging path is not reliably tested.

### 🟡 MEDIUM — `AppState::console_mode` is read under `RwLock` then immediately read again

In `console/mod.rs`, `render()` reads `console_mode` under a read lock, releases it, then re-acquires a read lock to read the full `AppState`. Between the two acquisitions, `console_mode` could change (e.g., from `Dashboard` to `LogView`). The rendered output would then be inconsistent with the state read on the second lock. This is a TOCTOU issue in the rendering path — cosmetic only (next render tick corrects it), but worth fixing.

### 🟡 MEDIUM — `scan_site` fails loudly on the first `read_dir` error

If any subdirectory inside `site/` is unreadable (e.g., `0o000` permissions), `scan_site` returns `Err` and the file count reverts to `0`. The user sees "0 files, 0 B" in the dashboard with a log warning. The function should skip unreadable directories (logging a per-directory warning) rather than aborting the entire scan.

---

## 6. Cross-Platform Support

### 🟠 HIGH — Keypair directory permissions not enforced on Windows

`ensure_private_dir` applies `0o700` only under `#[cfg(unix)]`. On Windows, the directory is created with default ACLs (typically readable by all local users in the same session). The Tor service keypair is therefore **world-readable on Windows**. The Windows ACL equivalent (`SetNamedSecurityInfo`) should be applied via the `windows-acl` or `winapi` crates, or the limitation must be prominently documented in the README.

### 🟡 MEDIUM — `is_fd_exhaustion` returns `false` on non-Unix, non-Windows targets

On WASM, UEFI, and other exotic targets, accept errors that are actually FD exhaustion are logged at `debug` level instead of `error`. This is low-risk but worth documenting.

### 🟡 MEDIUM — `xdg-open` is not available on all Linux environments

On headless servers, Docker containers, minimal Alpine images, and WSL without a display, `xdg-open` either doesn't exist or silently fails. The `[O]` key does nothing with no user feedback.

### 🟡 MEDIUM — Log file permissions not set on Windows

`OpenOptions::mode(0o600)` is `#[cfg(unix)]` only. On Windows, the log file is created with default permissions (likely readable by all users in the group). The log contains the `.onion` address.

### 🟡 MEDIUM — No cross-compilation CI

`audit.toml` and `deny.toml` are present but there is no CI configuration. Cross-compilation to `x86_64-pc-windows-gnu` and `aarch64-unknown-linux-gnu` is claimed as working (via bundled SQLite and vendored OpenSSL), but this is untested in automation.

---

## 7. Developer Experience

### 🔴 CRITICAL — No README.md

There is no `README.md` in the repository. A new visitor to https://github.com/csd113/RustHost sees only the file list. There is no explanation of what the project does, how to build it, how to use it, or why it exists. This is the single biggest barrier to adoption and contribution.

### 🟠 HIGH — MSRV is 1.90 (unreleased as of mid-2025)

`rust-version = "1.90"` in `Cargo.toml`. Rust 1.90 is not yet stable. A new contributor who runs `cargo build` with the stable toolchain gets:

```
error: package `rusthost` cannot be built because it requires rustc 1.90.0 or later
```

There is no error message, documentation, or toolchain file (`rust-toolchain.toml`) to tell them what to do. Add a `rust-toolchain.toml` specifying `channel = "nightly"` or the correct beta channel, and document this in the README.

### 🟠 HIGH — No CI configuration

No `.github/workflows/`, no `Makefile`, no `justfile`. The `cargo-deny` (`deny.toml`) and `cargo-audit` (`audit.toml`) configurations are present but never run. A PR that introduces a yanked dependency or a RUSTSEC advisory will merge silently.

**Minimum CI matrix:**
```
cargo build --release
cargo test
cargo clippy -- -D warnings
cargo deny check
cargo audit
```

### 🟠 HIGH — `[R]` reload does not reload configuration

The dashboard says "press [R] to reload" which users will interpret as "re-read settings.toml." It only rescans the file count. Config changes (e.g., changing `csp_level` or `max_connections`) require a full restart. Document this limitation prominently or implement config hot-reload.

### 🟡 MEDIUM — Internal "fix X.Y" comments are meaningless to outside contributors

The codebase is dense with references like `// fix H-3`, `// fix T-7`, `// fix 4.5`. These are clearly from an internal issue tracker or review document that is not in the repository. To an outside contributor, these comments are noise that obscures the actual rationale.

**Fix:** Replace these with human-readable comments explaining *why* the fix was necessary, not what issue number it closes. E.g., `// fix H-3` → `// Strip CR/LF to prevent CRLF injection into Location header`.

### 🟡 MEDIUM — CLI parser doesn't support `--flag=value` syntax

`--config /path` works; `--config=/path` produces `error: unrecognised argument '--config=/path'`. Standard CLI convention supports both. Consider replacing the hand-rolled parser with `clap` to get this, plus `--help` auto-generation, `--` end-of-flags, short flags (`-c`/`-d`), and shell completion generation.

### 🟡 MEDIUM — No `--port` or `--no-tor` CLI flags for quick ad-hoc use

The most common developer workflow is "I want to quickly serve a directory on a specific port without editing a TOML file." There's no `rusthost-cli --port 3000 --no-tor ./my-site`. Every use requires the full config file setup.

### 🟡 MEDIUM — No structured access log

The server logs requests at `DEBUG` level via `log::debug!("Connection from {peer}")`, but there's no access log in Combined Log Format (or any structured format). Operators cannot pipe logs to a SIEM, run `goaccess`, or analyze traffic patterns.

---

## 8. Feature Completeness

### 🔴 CRITICAL — No SPA (Single Page Application) fallback routing

There is no option to serve `index.html` for all 404 responses. React, Vue, Svelte, and Angular apps all require this for client-side routing to work. A request to `/about` on a React SPA returns 404 from this server; only `/` works. This is table stakes for any static host.

**Fix:** Add `fallback_to_index = false` to `[site]` config. When true, return `index.html` for all 404s that don't match a file.

### 🔴 CRITICAL — No HTTPS / TLS support

The server has no TLS. For public Tor hidden service use, this doesn't matter (Tor provides its own encryption). But for clearnet access, plaintext HTTP is increasingly blocked by browsers (HSTS preloading, mixed-content errors). Providing a `--generate-cert` flag with a self-signed certificate, or ACME support, would make the tool usable for clearnet hosting.

### 🟠 HIGH — No custom error pages (404.html, 500.html)

404 responses are plain-text "Not Found". Every professional static host supports custom error pages. Add `error_404 = "404.html"` to `[site]` config.

### 🟠 HIGH — No gzip/brotli compression (see Performance §2)

### 🟠 HIGH — No Range request (206 Partial Content) support

Audio/video players, download managers, and PDF viewers depend on range requests. Without it, a 500 MB video file cannot be seeked or resumed.

### 🟡 MEDIUM — No URL redirect/rewrite rules

No `[[redirects]]` or `[[rewrites]]` configuration table. Migrating a site from another host requires the destination host to preserve all URLs. Custom redirects (e.g., `/old-page → /new-page`) are a baseline feature.

### 🟡 MEDIUM — No `--serve <dir>` one-shot mode

You cannot do `rusthost-cli --serve ./docs` to instantly serve a directory without first running through the first-run setup flow. This is the primary use case for developers.

### 🟡 MEDIUM — Missing MIME types

The MIME table is missing:
- `.webmanifest` → `application/manifest+json` (required for PWA)
- `.m4v`, `.mov` → video types
- `.flac`, `.opus` → audio types
- `.glb`, `.gltf` → 3D model types (increasingly common in modern web)
- `.ndjson` → `application/x-ndjson`
- `.ts` → `video/mp2t` (also used for TypeScript — context-dependent)

### 🟡 MEDIUM — No directory listing sort: dirs-first, newest-first options

Files are sorted alphabetically only. No option for directories-first, size-ascending, or modification-time-descending. Minor but frequently requested.

### 🟡 MEDIUM — No config hot-reload via filesystem watch

`inotify` (Linux), `kqueue` (macOS), and `ReadDirectoryChangesW` (Windows) can all trigger config reload when `settings.toml` changes. The `notify` crate provides a cross-platform API. This is especially useful for headless deployments where the dashboard is disabled.

---

## 9. Documentation & Open Source Readiness

### 🔴 CRITICAL — No README.md (see Developer Experience)

### 🟠 HIGH — No CHANGELOG or release history

### 🟠 HIGH — No CONTRIBUTING.md

No code style guide, no PR checklist, no instructions for running tests locally.

### 🟠 HIGH — `authors = []` in Cargo.toml

No author credit. Makes security contact and attribution impossible.

### 🟡 MEDIUM — No SECURITY.md

No responsible disclosure policy. For a security-sensitive tool (Tor hidden service hosting), this is particularly important.

### 🟡 MEDIUM — `lib.rs` re-exports everything as `pub`

All modules are `pub` to enable integration tests. This exposes an enormous, unstable API surface. Use `pub(crate)` for internal items and only `pub` the actual public interface. Integration tests can use `#[cfg(test)]` `pub(crate)` re-exports.

### 🟡 MEDIUM — No architecture diagram or design document

The Tor integration (Arti in-process, rendezvous, stream proxying) is non-trivial. A `ARCHITECTURE.md` with a data-flow diagram would help contributors understand the lifecycle before touching the code.

### 🟡 MEDIUM — `deny.toml` and `audit.toml` are unconfigured CI dead weight

Both files exist but are never run. Either hook them into CI or remove them to reduce confusion.

---

## 10. "Next-Level" Improvements

1. **HTTP/1.1 keep-alive + HTTP/2**: The biggest single change. Use `hyper` (mature, production-grade, supports HTTP/2) instead of the hand-rolled HTTP parser. Tor page load times drop from 30s to 3s.

2. **Brotli/gzip compression**: Add `async-compression` + pre-compression on startup. 70–85% bandwidth reduction on text assets — transformative for Tor users.

3. **Metrics/telemetry dashboard**: Real-time bytes served, connection duration histogram, P50/P95 request latency, per-path hit counts. Display in the console dashboard. Export as Prometheus metrics via a `--metrics-port` flag.

4. **SPA routing + custom error pages**: `fallback_to_index = true` + `404.html`/`500.html` support. Enables hosting React/Vue/Svelte apps without modification.

5. **Config hot-reload**: Watch `settings.toml` with the `notify` crate. Apply changes to `csp_level`, `max_connections`, `expose_dotfiles` without restart.

6. **ETag / conditional GET + smart caching headers**: `Cache-Control: immutable` for hashed assets, `no-store` only for HTML. Cut re-download traffic by 80–90% on repeat visits.

7. **`rusthost-cli --serve ./dir --port 3000 --no-tor` one-shot mode**: Zero-config local serving. This single flag would make the tool immediately useful to developers who don't need Tor.

8. **Range request (206 Partial Content) support**: Essential for audio/video. Technically straightforward: parse `Range:` header, `File::seek()`, set `Content-Range:` response header.

9. **Self-signed TLS certificate generation**: `rustls` + `rcgen` can generate a self-signed cert at startup. Enables `https://localhost:8443` with zero user configuration. Optionally add ACME (Let's Encrypt) support for production clearnet deployments.

10. **URL redirect/rewrite rules in config**:
```toml
[[redirects]]
from = "/old-page"
to = "/new-page"
status = 301
```
This alone would unblock 90% of site migrations.

---

## Top 10 Highest Impact Improvements

| Rank | Change | Effort | Impact |
|------|--------|--------|--------|
| 1 | HTTP/1.1 keep-alive (replace hand-rolled parser with `hyper`) | Large | **Removes Tor unusability** |
| 2 | README.md (installation, usage, config reference) | Small | **Enables any adoption at all** |
| 3 | gzip/brotli content compression | Medium | **3–10× faster page loads over Tor** |
| 4 | SPA routing (`fallback_to_index`) + custom 404.html | Small | **Enables hosting any modern frontend** |
| 5 | Per-IP rate limiting in accept loop | Medium | **Closes DoS attack surface** |
| 6 | CI configuration (GitHub Actions) | Small | **Prevents regressions, builds trust** |
| 7 | Fix `copy_with_idle_timeout` to be an actual idle timeout | Small | **Stops killing legitimate large file downloads** |
| 8 | ETag/conditional GET + smart `Cache-Control` | Medium | **80–90% reduction in repeated traffic** |
| 9 | External test vector for `onion_address_from_pubkey` | Trivial | **Eliminates tautological Tor address test** |
| 10 | Replace internal "fix X.Y" comments with explanatory prose | Small | **Makes code understandable to contributors** |

---

## What This Project Does Well

**Tor integration is genuinely impressive.** Embedding Arti in-process, deriving the onion address from the keypair without polling a `hostname` file, handling bootstrap timeouts, exponential retry with failure-time reset — this is well-researched and non-trivial. Most comparable projects just shell out to `tor`.

**Security fundamentals are solid.** `canonicalize` + `starts_with` for path traversal, `NonZeroU16`/`IpAddr` at the type level for config validation, `#[serde(deny_unknown_fields)]`, `unsafe_code = "forbid"`, dot-file blocking, CRLF injection stripping, XSS escaping in directory listings, 0o600/0o700 for Tor keypair files — all correct.

**Error handling is typed and explicit.** The single `AppError` enum with `thiserror`, a crate-level `Result<T>` alias, and consistent use of `?` mean errors propagate cleanly without `Box<dyn Error>` everywhere. The `AppError::ConfigValidation(Vec<String>)` pattern for bulk validation errors is particularly good.

**Async architecture is clean.** `Arc<RwLock<AppState>>` for shared state, `AtomicU64` for hot-path metrics, `JoinSet` for connection tracking, watch channels for shutdown propagation, oneshot channel for port signaling — each tool is chosen appropriately.

**The test suite is integration-focused.** The `TestServer` harness in `tests/http_integration.rs` spins up a real server on a dynamically-allocated port and sends real HTTP bytes. This catches wire-level bugs that unit tests miss.

**The config system is unusually good for a project this size.** `serde` parse-time validation for typed fields, semantic validation in a separate `validate()` pass, `#[serde(deny_unknown_fields)]` to catch typos, and excellent inline documentation in the generated TOML file.

---

## What Prevents This From Being Elite

**1. No HTTP keep-alive.** This is not a performance nit — it makes the tool genuinely unusable for its primary stated use case (Tor hosting). A static site with 20 assets takes 60 seconds to load on Tor. This single issue would drive every serious Tor user away immediately.

**2. No README.** An open-source project without a README is invisible. It cannot be discovered, evaluated, or adopted. It cannot receive contributions. Every other quality in this code is wasted without documentation.

**3. Feature gap relative to competitors.** Caddy, `miniserve`, `static-web-server`, and even Python's `http.server` support: compression, range requests, conditional GET, custom error pages, and SPA routing. This server doesn't. A developer evaluating static hosting tools will pick one of those instead.

**4. The `copy_with_idle_timeout` bug is subtle but serious.** It terminates legitimate large transfers after 60 seconds wall-clock time. A user who tries to download a 100 MB file over Tor (which takes ~10 minutes at typical Tor speeds) will see a dropped connection every 60 seconds. They will assume the server is broken — because it is.

**5. No per-IP rate limiting.** The `max_connections` semaphore is a global cap, not a per-client cap. A single client can monopolize the entire server. This isn't hardening — it's a single point of failure dressed up as one.

**6. No compression.** Tor is slow. Sending 200 KB of uncompressed JavaScript over a 200 kbps Tor circuit when brotli would compress it to 30 KB is not an acceptable tradeoff for any serious use case.

These six gaps, in order, are what stand between this project and a tool worth recommending.
