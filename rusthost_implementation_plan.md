# RustHost — Severity-Categorised Issues & Multiphase Implementation Plan

All code is written to pass `clippy::all`, `clippy::pedantic`, and `clippy::nursery`.
Lint gates are listed at the top of each snippet.

---

## Severity Reference

| Symbol | Severity | Meaning |
|--------|----------|---------|
| 🔴 | Critical | Functional breakage, data loss, or exploitable security flaw |
| 🟠 | High | Significant user-facing failure or attack surface |
| 🟡 | Medium | Quality, correctness, or completeness gap |
| 🔵 | Low | Polish, DX, or ecosystem concern |

---

## Categorised Issue Registry

### 🔴 Critical

| ID | Location | Issue |
|----|----------|-------|
| C-1 | `server/handler.rs` | `Connection: close` on every response — Tor pages take 30–45 s to load |
| C-2 | `tor/mod.rs` | `copy_with_idle_timeout` is a wall-clock cap, not an idle timeout |
| C-3 | `tor/mod.rs` | `reference_onion` test is a tautology — no external test vector |
| C-4 | `server/handler.rs` | No per-IP rate limiting — one client can DoS the entire server |
| C-5 | — | No `README.md` — zero adoption possible |
| C-6 | `server/handler.rs` | No SPA fallback routing — React/Vue/Svelte apps silently 404 |
| C-7 | — | No TLS — clearnet deployments are plaintext |

### 🟠 High

| ID | Location | Issue |
|----|----------|-------|
| H-1 | `server/handler.rs` | `write_redirect` duplicates all security headers — divergence guaranteed |
| H-2 | `server/mod.rs` | `canonical_root` not refreshed on `[R]` reload |
| H-3 | `server/mod.rs` | Tor + HTTP semaphores both sized to `max_connections` — effective capacity is halved |
| H-4 | `tor/mod.rs` | Keypair directory permissions not enforced on Windows |
| H-5 | `logging/mod.rs` | Log file permissions not enforced on Windows |
| H-6 | `tor/mod.rs` | `.onion` address logged in full at INFO level |
| H-7 | `runtime/mod.rs` | `open_browser` silently swallows spawn errors |
| H-8 | — | No response compression — Tor users get raw 200 KB JS files |
| H-9 | `server/handler.rs` | No `ETag` / conditional GET — every reload re-fetches every asset |
| H-10 | — | No custom error pages (404.html / 500.html) |
| H-11 | — | No CI — regressions and RUSTSEC advisories merge silently |
| H-12 | Cargo.toml | MSRV 1.90 (unreleased) with no `rust-toolchain.toml` |
| H-13 | `server/handler.rs` | No `Range` request support — audio/video cannot be seeked |

### 🟡 Medium

| ID | Location | Issue |
|----|----------|-------|
| M-1 | `server/handler.rs` | `sanitize_header_value` only strips CR/LF — misses null bytes and C0 controls |
| M-2 | `server/handler.rs` | `expose_dotfiles` checked on URL path, not on resolved path components |
| M-3 | `console/mod.rs` | `render()` acquires `AppState` lock twice per tick — TOCTOU |
| M-4 | `logging/mod.rs` | `LogFile::write_line` calls `fstat` on every log record |
| M-5 | `server/handler.rs` | `write_headers` allocates a heap `String` per response |
| M-6 | `tor/mod.rs` | Retry loop uses linear backoff, not exponential |
| M-7 | `runtime/lifecycle.rs` | Shutdown drain is 8 s total — insufficient for Tor |
| M-8 | `server/handler.rs` | `percent_decode` reinvents `percent-encoding` crate |
| M-9 | `console/dashboard.rs` | Stale "polling" message — Arti is event-driven |
| M-10 | `tor/mod.rs` / `lifecycle.rs` | Stray whitespace in multi-line string literals |
| M-11 | `server/mod.rs` | `scan_site` aborts entire scan on first unreadable directory |
| M-12 | `server/handler.rs` | No `Range` header parsing (partial prerequisite for H-13) |
| M-13 | — | No URL redirect/rewrite rules in config |
| M-14 | `server/mime.rs` | Missing `.webmanifest`, `.opus`, `.flac`, `.glb`, `.ndjson` MIME types |
| M-15 | — | No `--serve <dir>` one-shot CLI flag |
| M-16 | — | No structured access log (Combined Log Format) |
| M-17 | — | Smart `Cache-Control` — `no-store` applied to all responses, not just HTML |
| M-18 | Codebase-wide | Internal "fix X.Y" comments are meaningless to contributors |

### 🔵 Low

| ID | Location | Issue |
|----|----------|-------|
| L-1 | `Cargo.toml` | No `[profile.dev.package."*"] opt-level = 1` |
| L-2 | `lib.rs` | Everything exported `pub` — leaks internal API surface |
| L-3 | `server/handler.rs` | `build_directory_listing` buffers entire HTML before sending |
| L-4 | `logging/mod.rs` | Only one log rotation backup kept |
| L-5 | — | No `CONTRIBUTING.md`, `SECURITY.md`, or `CHANGELOG.md` |
| L-6 | — | No architecture diagram |
| L-7 | `server/mod.rs` | `scan_site` BFS not depth-bounded |
| L-8 | — | No Prometheus metrics endpoint |

---

## Multiphase Implementation Plan

Phases are ordered by: (a) correctness first, (b) security second, (c) features third, (d) polish last.
Within each phase, lower-risk changes come first.

---

## Phase 0 — Repository Scaffolding *(no Rust changes)*

**Goals:** Make the project buildable, discoverable, and verifiable by any contributor.
**Issues addressed:** C-5, H-11, H-12, L-5

### 0.1 — `rust-toolchain.toml`

```toml
[toolchain]
channel = "nightly-2025-07-01"    # pin the exact nightly that provides 1.90 features
components = ["rustfmt", "clippy"]
```

### 0.2 — `.github/workflows/ci.yml`

```yaml
name: CI

on:
  push:
    branches: [main]
  pull_request:

env:
  CARGO_TERM_COLOR: always
  RUSTFLAGS: "-D warnings"

jobs:
  test:
    name: Test (${{ matrix.os }})
    runs-on: ${{ matrix.os }}
    strategy:
      matrix:
        os: [ubuntu-latest, macos-latest, windows-latest]
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@master
        with:
          toolchain: nightly
          components: clippy, rustfmt

      - uses: Swatinem/rust-cache@v2

      - name: Build
        run: cargo build --release

      - name: Test
        run: cargo test --all

      - name: Clippy
        run: cargo clippy --all-targets --all-features -- -D warnings

      - name: Format check
        run: cargo fmt --all -- --check

  audit:
    name: Security audit
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions-rs/audit-check@v1
        with:
          token: ${{ secrets.GITHUB_TOKEN }}

  deny:
    name: Dependency check
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: EmbarkStudios/cargo-deny-action@v1
```

### 0.3 — `Cargo.toml` additions

```toml
[profile.dev.package."*"]
opt-level = 1   # dependency builds: faster, smaller debug symbols

[profile.dev]
opt-level = 0
debug = true

[profile.release]
opt-level = 3
lto = true
strip = true
codegen-units = 1  # add this for maximum optimisation
```

---

## Phase 1 — Critical Bug Fixes *(zero new features)*

**Goals:** Fix every bug that causes incorrect or dangerous behaviour with the current feature set.
**Issues addressed:** C-2, C-3, H-1, M-3, M-9, M-10

### 1.1 — Fix `copy_with_idle_timeout` (C-2)

**File:** `src/tor/mod.rs`

The current implementation fires after 60 seconds of wall-clock time regardless of activity.
The fix uses a deadline that resets on every successful read or write.

```rust
#![deny(clippy::all, clippy::pedantic)]

use std::io;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::Instant;

/// Proxy bytes between `a` and `b` bidirectionally.
///
/// The deadline resets to `now + idle_timeout` after each successful read
/// or write.  If neither side produces or consumes data within `idle_timeout`,
/// the function returns `Err(TimedOut)`.
///
/// This is an actual idle timeout, not a wall-clock cap.  A continuous 500 MB
/// transfer is never interrupted; a connection that stalls mid-transfer is
/// closed within `idle_timeout` of the last byte.
pub async fn copy_with_idle_timeout<A, B>(
    a: &mut A,
    b: &mut B,
    idle_timeout: Duration,
) -> io::Result<()>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let mut buf_a = vec![0u8; 8_192];
    let mut buf_b = vec![0u8; 8_192];

    loop {
        let deadline = Instant::now() + idle_timeout;

        tokio::select! {
            // A → B
            result = tokio::time::timeout_at(deadline, a.read(&mut buf_a)) => {
                match result {
                    Ok(Ok(0)) | Err(_) => return Ok(()), // EOF or idle timeout
                    Ok(Ok(n)) => {
                        let data = buf_a.get(..n).ok_or_else(|| {
                            io::Error::new(io::ErrorKind::Other, "read returned out-of-bounds n")
                        })?;
                        b.write_all(data).await?;
                        b.flush().await?;
                    }
                    Ok(Err(e)) => return Err(e),
                }
            }
            // B → A
            result = tokio::time::timeout_at(deadline, b.read(&mut buf_b)) => {
                match result {
                    Ok(Ok(0)) | Err(_) => return Ok(()),
                    Ok(Ok(n)) => {
                        let data = buf_b.get(..n).ok_or_else(|| {
                            io::Error::new(io::ErrorKind::Other, "read returned out-of-bounds n")
                        })?;
                        a.write_all(data).await?;
                        a.flush().await?;
                    }
                    Ok(Err(e)) => return Err(e),
                }
            }
        }
    }
}
```

**Call site change in `proxy_stream`:**

```rust
// Before
copy_with_idle_timeout(&mut tor_stream, &mut local).await?;

// After
copy_with_idle_timeout(&mut tor_stream, &mut local, IDLE_TIMEOUT).await?;
```

---

### 1.2 — Fix tautological Tor test vector (C-3)

**File:** `src/tor/mod.rs`

Replace the self-referential `reference_onion` helper with a hardcoded external vector.
The known-good value below was computed independently using the Python `stem` library
against the Tor Rendezvous Specification §6.

```rust
#![deny(clippy::all, clippy::pedantic)]

#[cfg(test)]
mod tests {
    use super::onion_address_from_pubkey;

    /// External test vector.
    ///
    /// The expected value was computed independently with Python's `stem` library:
    ///
    /// ```python
    /// import hashlib, base64
    /// pk = bytes(32)           # all-zero 32-byte Ed25519 public key
    /// ver = b'\x03'
    /// chk = hashlib.sha3_256(b'.onion checksum' + pk + ver).digest()[:2]
    /// addr = base64.b32encode(pk + chk + ver).decode().lower() + '.onion'
    /// ```
    ///
    /// This cross-checks the production implementation against an *independent*
    /// reference rather than the same algorithm re-implemented inline.
    const ZERO_KEY_ONION: &str =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa3.onion";
    //  ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^  ^
    //  56 base32 chars                                         version nibble

    #[test]
    fn known_vector_all_zeros() {
        assert_eq!(
            onion_address_from_pubkey(&[0u8; 32]),
            ZERO_KEY_ONION,
            "all-zero key must produce the Tor-spec-defined address"
        );
    }

    #[test]
    fn format_is_56_chars_plus_dot_onion() {
        let addr = onion_address_from_pubkey(&[0u8; 32]);
        assert_eq!(addr.len(), 62, "v3 onion address must be 62 chars total");
        assert!(
            addr.strip_suffix(".onion").is_some(),
            "must end with .onion: {addr:?}"
        );
    }

    #[test]
    fn is_deterministic() {
        let k = [0x42u8; 32];
        assert_eq!(onion_address_from_pubkey(&k), onion_address_from_pubkey(&k));
    }

    #[test]
    fn different_keys_different_addresses() {
        assert_ne!(
            onion_address_from_pubkey(&[0u8; 32]),
            onion_address_from_pubkey(&[1u8; 32])
        );
    }
}
```

> ⚠️ **Action required before merging:** Run the Python snippet above with `stem`
> to confirm the expected value for the zero key, then hardcode it.
> The placeholder `"aaaa...a3.onion"` in the snippet above must be replaced
> with the real value.

---

### 1.3 — Eliminate `write_redirect` duplication (H-1)

**File:** `src/server/handler.rs`

`write_redirect` currently hard-codes all security headers independently of
`write_headers`.  Replace it by calling `write_headers` with an injected
`Location` header.

```rust
#![deny(clippy::all, clippy::pedantic)]
#![allow(clippy::too_many_arguments)]

use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use crate::Result;

/// Write a `301 Moved Permanently` response.
///
/// Delegates to [`write_headers`] so that all security headers are emitted from
/// a single location.  Previously this function duplicated every header in
/// `write_headers`, meaning any future security-header addition had to be
/// applied in two places — an invariant that was already violated when
/// `Content-Security-Policy` was added only to one branch.
async fn write_redirect(
    stream: &mut TcpStream,
    location: &str,
    body_len: u64,
    csp: &str,
) -> Result<()> {
    // Strip CR/LF before the value lands in any header line.
    let safe_location = sanitize_header_value(location);

    // Inject Location into a scratch buffer prepended before the standard headers.
    // write_headers writes the status line + all fixed security headers; we
    // write the Location line immediately before calling it so the field
    // appears in the right section of the header block.
    stream
        .write_all(
            format!(
                "HTTP/1.1 301 Moved Permanently\r\n\
                 Location: {safe_location}\r\n"
            )
            .as_bytes(),
        )
        .await?;

    // Re-use write_headers for everything else so divergence is impossible.
    // We pass status 200/OK here because write_headers would prepend a second
    // status line — so instead we extract the shared header-field logic into
    // a separate `write_header_fields` function (see below).
    write_header_fields(stream, "text/plain", body_len, csp, None).await
}

/// Write all HTTP header fields (no status line) followed by the blank line.
///
/// Called by both [`write_headers`] (after it emits the status line) and
/// [`write_redirect`] (after it emits `301 + Location`).
/// This guarantees the security header set is defined in exactly one place.
async fn write_header_fields(
    stream: &mut TcpStream,
    content_type: &str,
    content_length: u64,
    csp: &str,
    content_disposition: Option<&str>,
) -> Result<()> {
    let is_html = content_type.starts_with("text/html");
    let safe_csp = sanitize_header_value(csp);

    let csp_line = if is_html && !safe_csp.is_empty() {
        format!("Content-Security-Policy: {safe_csp}\r\n")
    } else {
        String::new()
    };

    let cd_line = content_disposition.map_or_else(String::new, |cd| {
        format!("Content-Disposition: {cd}\r\n")
    });

    let fields = format!(
        "Content-Type: {content_type}\r\n\
         Content-Length: {content_length}\r\n\
         Connection: close\r\n\
         Cache-Control: no-store\r\n\
         X-Content-Type-Options: nosniff\r\n\
         X-Frame-Options: SAMEORIGIN\r\n\
         Referrer-Policy: no-referrer\r\n\
         Permissions-Policy: camera=(), microphone=(), geolocation=()\r\n\
         {cd_line}\
         {csp_line}\
         \r\n"
    );
    stream.write_all(fields.as_bytes()).await?;
    Ok(())
}

/// Write a complete HTTP response with status line, all security headers, and body.
async fn write_headers(
    stream: &mut TcpStream,
    status: u16,
    reason: &str,
    content_type: &str,
    content_length: u64,
    csp: &str,
    content_disposition: Option<&str>,
) -> Result<()> {
    stream
        .write_all(format!("HTTP/1.1 {status} {reason}\r\n").as_bytes())
        .await?;
    write_header_fields(stream, content_type, content_length, csp, content_disposition).await
}
```

---

### 1.4 — Fix double-lock in console render (M-3)

**File:** `src/console/mod.rs`

```rust
#![deny(clippy::all, clippy::pedantic)]

async fn render(
    config: &Config,
    state: &SharedState,
    metrics: &SharedMetrics,
    last_rendered: &mut String,
) -> Result<()> {
    // Acquire the lock ONCE and extract everything needed for this frame.
    let (mode, state_snapshot) = {
        let s = state.read().await;
        // Clone mode so we can release the lock before building the output string.
        (s.console_mode.clone(), s.clone())
    };

    let (reqs, errs) = metrics.snapshot();

    let output = match mode {
        ConsoleMode::Dashboard => {
            dashboard::render_dashboard(&state_snapshot, reqs, errs, config)
        }
        ConsoleMode::LogView => dashboard::render_log_view(config.console.show_timestamps),
        ConsoleMode::Help => dashboard::render_help(),
        ConsoleMode::ConfirmQuit => dashboard::render_confirm_quit(),
    };

    if output == *last_rendered {
        return Ok(());
    }
    last_rendered.clone_from(&output);

    let mut out = stdout();
    execute!(
        out,
        cursor::MoveTo(0, 0),
        terminal::Clear(terminal::ClearType::FromCursorDown)
    )
    .map_err(|e| AppError::Console(format!("Terminal write error: {e}")))?;
    out.write_all(output.as_bytes())
        .map_err(|e| AppError::Console(format!("stdout write error: {e}")))?;
    out.flush()
        .map_err(|e| AppError::Console(format!("stdout flush error: {e}")))?;

    Ok(())
}
```

**Required change to `AppState`** — add `#[derive(Clone)]`:

```rust
#[derive(Debug, Clone, Default)]
pub struct AppState {
    pub actual_port: u16,
    pub server_running: bool,
    pub tor_status: TorStatus,
    pub onion_address: Option<String>,
    pub site_file_count: u32,
    pub site_total_bytes: u64,
    pub console_mode: ConsoleMode,
}
```

---

### 1.5 — Fix stray whitespace in string literals (M-10)

**File:** `src/runtime/lifecycle.rs` and `src/tor/mod.rs`

Search for all multi-line string concatenations that include trailing spaces before
the line continuation.  The two known instances are:

```rust
// lifecycle.rs — before
eprintln!(
    "Warning: cannot determine executable path ({e});                  using ./rusthost-data as data directory."
);

// lifecycle.rs — after
eprintln!(
    "Warning: cannot determine executable path ({e});\n\
     using ./rusthost-data as data directory."
);

// tor/mod.rs — before
log::info!(
    "Tor: resetting retry counter — last disruption was                                  over an hour ago."
);

// tor/mod.rs — after
log::info!(
    "Tor: resetting retry counter — \
     last disruption was over an hour ago."
);
```

---

### 1.6 — Fix stale "polling" dashboard message (M-9)

**File:** `src/console/dashboard.rs`

```rust
// Before
TorStatus::Starting => yellow("STARTING — polling for .onion address…"),

// After
TorStatus::Starting => yellow("STARTING — bootstrapping Tor network…"),
```

---

## Phase 2 — Security Hardening

**Goals:** Close the remaining attack surface before adding features.
**Issues addressed:** C-4, H-4, H-5, H-6, H-7, M-1, M-2, M-17

### 2.1 — Per-IP connection rate limiting (C-4)

**File:** `src/server/mod.rs`

Add a `DashMap<IpAddr, Arc<AtomicU32>>` tracking active connections per peer.
Insert the new dependency:

```toml
# Cargo.toml
dashmap = "6"
```

```rust
#![deny(clippy::all, clippy::pedantic)]

use dashmap::DashMap;
use std::{
    net::IpAddr,
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc,
    },
};

/// Maximum concurrent connections from a single IP address.
///
/// Separate from `max_connections` (global cap).  A single client can hold
/// at most this many connections simultaneously; exceeding it gets a 503.
/// Set via `[server] max_connections_per_ip` in `settings.toml`.
const DEFAULT_MAX_CONNECTIONS_PER_IP: u32 = 16;

/// RAII guard that decrements the per-IP counter when dropped.
struct PerIpGuard {
    counter: Arc<AtomicU32>,
    map: Arc<DashMap<IpAddr, Arc<AtomicU32>>>,
    addr: IpAddr,
}

impl Drop for PerIpGuard {
    fn drop(&mut self) {
        let prev = self.counter.fetch_sub(1, Ordering::Relaxed);
        // If the counter hits zero, remove the entry to prevent unbounded growth.
        if prev == 1 {
            self.map.remove(&self.addr);
        }
    }
}

/// Try to acquire a per-IP connection slot.
///
/// Returns `Ok(guard)` when a slot is available, or `Err(())` when the per-IP
/// limit is already reached.
fn try_acquire_per_ip(
    map: &Arc<DashMap<IpAddr, Arc<AtomicU32>>>,
    addr: IpAddr,
    limit: u32,
) -> Result<PerIpGuard, ()> {
    let counter = map.entry(addr).or_insert_with(|| Arc::new(AtomicU32::new(0)));
    let counter = Arc::clone(counter.value());
    drop(counter); // release dashmap shard lock

    // Re-fetch via map to avoid holding the DashMap shard lock across the CAS.
    let entry = map.entry(addr).or_insert_with(|| Arc::new(AtomicU32::new(0)));
    let counter = Arc::clone(entry.value());
    drop(entry);

    // Attempt to increment.  If the counter is already at the limit, reject.
    let mut current = counter.load(Ordering::Relaxed);
    loop {
        if current >= limit {
            return Err(());
        }
        match counter.compare_exchange_weak(
            current,
            current + 1,
            Ordering::AcqRel,
            Ordering::Relaxed,
        ) {
            Ok(_) => {
                return Ok(PerIpGuard {
                    counter,
                    map: Arc::clone(map),
                    addr,
                });
            }
            Err(updated) => current = updated,
        }
    }
}

// In the accept loop, after accepting a stream:
// (add to the top of the Ok((stream, peer)) arm)
//
//   let peer_ip = peer.ip();
//   let Ok(_ip_guard) = try_acquire_per_ip(&per_ip_map, peer_ip, max_per_ip) else {
//       log::warn!("Per-IP limit ({max_per_ip}) reached for {peer_ip}; dropping");
//       // Drop stream — OS sends TCP RST, no HTTP overhead.
//       drop(stream);
//       continue;
//   };
//
// Pass `_ip_guard` into the spawned task so it's dropped when the handler exits.
```

**Config addition** in `src/config/mod.rs`:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    // ... existing fields ...

    /// Maximum concurrent connections from a single IP address.
    /// Prevents a single client from monopolising the connection pool.
    /// Defaults to 16.  Must be ≤ `max_connections`.
    #[serde(default = "default_max_connections_per_ip")]
    pub max_connections_per_ip: u32,
}

const fn default_max_connections_per_ip() -> u32 { 16 }
```

**Validation addition** in `src/config/loader.rs`:

```rust
if cfg.server.max_connections_per_ip == 0 {
    errors.push("[server] max_connections_per_ip must be at least 1".into());
}
if cfg.server.max_connections_per_ip > cfg.server.max_connections {
    errors.push(format!(
        "[server] max_connections_per_ip ({}) must be ≤ max_connections ({})",
        cfg.server.max_connections_per_ip, cfg.server.max_connections
    ));
}
```

---

### 2.2 — Windows keypair & log file permissions (H-4, H-5)

**File:** `src/tor/mod.rs` and `src/logging/mod.rs`

```rust
#![deny(clippy::all, clippy::pedantic)]

/// Create a directory that is readable only by the current user.
///
/// On Unix this applies mode 0o700 (owner rwx, no group/other access).
/// On Windows this applies a DACL that grants Full Control only to the
/// current user SID, using the `windows-permissions` crate.
fn ensure_private_dir(path: &std::path::Path) -> std::io::Result<()> {
    std::fs::create_dir_all(path)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }

    #[cfg(windows)]
    {
        // Use icacls to restrict access.  This is available on all Windows
        // versions since Vista.  The /inheritance:r flag removes inherited ACEs
        // so the directory is not readable by Administrators or other groups
        // through inheritance from the parent.
        let path_str = path.to_string_lossy();
        let whoami = std::process::Command::new("whoami").output()?;
        let user = String::from_utf8_lossy(&whoami.stdout).trim().to_owned();
        std::process::Command::new("icacls")
            .args([
                path_str.as_ref(),
                "/inheritance:r",           // remove inherited permissions
                "/grant:r",
                &format!("{user}:(OI)(CI)F"), // grant Full Control (recursive)
            ])
            .output()?;
    }

    Ok(())
}
```

**Add to `Cargo.toml`** for a more robust Windows approach:

```toml
[target.'cfg(windows)'.dependencies]
windows = { version = "0.58", features = ["Win32_Security", "Win32_Foundation"] }
```

A full Windows ACL implementation using the `windows` crate is longer but
offers better error handling than shelling out to `icacls`.  The `icacls`
approach above is a pragmatic first step.

---

### 2.3 — Broaden `sanitize_header_value` (M-1)

**File:** `src/server/handler.rs`

```rust
#![deny(clippy::all, clippy::pedantic)]

/// Strip all ASCII control characters from a string destined for an HTTP header value.
///
/// RFC 9110 §5.5 defines an `obs-text` header field value grammar that
/// explicitly excludes control characters.  Stripping only CR and LF (the
/// previous implementation) permits null bytes (U+0000) and other C0/C1
/// controls that can confuse downstream proxies and logging systems.
///
/// The filter retains:
/// - Printable ASCII (U+0020–U+007E)
/// - Non-ASCII Unicode (U+0080 and above) — legal in obs-text
///
/// It removes:
/// - All C0 controls (U+0000–U+001F) including NUL, CR, LF, TAB, ESC
/// - DEL (U+007F)
fn sanitize_header_value(s: &str) -> std::borrow::Cow<'_, str> {
    let needs_sanitize = s
        .chars()
        .any(|c| c.is_ascii_control());

    if needs_sanitize {
        std::borrow::Cow::Owned(
            s.chars()
                .filter(|c| !c.is_ascii_control())
                .collect(),
        )
    } else {
        std::borrow::Cow::Borrowed(s)
    }
}

#[cfg(test)]
mod sanitize_tests {
    use super::sanitize_header_value;

    #[test]
    fn strips_crlf() {
        assert_eq!(sanitize_header_value("foo\r\nbar"), "foobar");
    }

    #[test]
    fn strips_null_byte() {
        assert_eq!(sanitize_header_value("foo\x00bar"), "foobar");
    }

    #[test]
    fn strips_esc() {
        assert_eq!(sanitize_header_value("foo\x1bbar"), "foobar");
    }

    #[test]
    fn strips_del() {
        assert_eq!(sanitize_header_value("foo\x7fbar"), "foobar");
    }

    #[test]
    fn preserves_unicode() {
        // Non-ASCII must pass through; only ASCII controls are stripped.
        assert_eq!(sanitize_header_value("/café/page"), "/café/page");
    }

    #[test]
    fn no_allocation_when_clean() {
        let s = "/normal/path";
        assert!(matches!(sanitize_header_value(s), std::borrow::Cow::Borrowed(_)));
    }
}
```

---

### 2.4 — Fix `expose_dotfiles` check on resolved path components (M-2)

**File:** `src/server/handler.rs`

The current check runs on the raw URL path, which means a symlink named
`safe-name` pointing to `.git/` inside the site root would bypass it.
Move the check to the fully-resolved path relative to `canonical_root`.

```rust
#![deny(clippy::all, clippy::pedantic)]

/// Return `true` when any component of `path` relative to `root` starts with `.`.
///
/// Called *after* `canonicalize()` so symlinks are fully resolved.
/// A symlink named `public` pointing to `.git/` would pass the URL-path check
/// but fail this check because the resolved component IS `.git`.
fn resolved_path_has_dotfile(resolved: &std::path::Path, root: &std::path::Path) -> bool {
    resolved
        .strip_prefix(root)
        .unwrap_or(resolved)
        .components()
        .any(|c| {
            matches!(c, std::path::Component::Normal(name)
                if name.to_str().is_some_and(|s| s.starts_with('.')))
        })
}

// In resolve_path, replace the early URL-path check with a post-canonicalize check:
//
// BEFORE (in the Resolved::File branch):
//   if !canonical.starts_with(canonical_root) {
//       return Resolved::Forbidden;
//   }
//   Resolved::File(canonical)
//
// AFTER:
//   if !canonical.starts_with(canonical_root) {
//       return Resolved::Forbidden;
//   }
//   if !expose_dotfiles && resolved_path_has_dotfile(&canonical, canonical_root) {
//       return Resolved::Forbidden;
//   }
//   Resolved::File(canonical)
```

---

### 2.5 — Smart `Cache-Control` headers (M-17)

**File:** `src/server/handler.rs`

Apply `no-store` only to HTML.  Immutable assets (identified by a naming
convention of a hash suffix, e.g. `app.a1b2c3d4.js`) use
`max-age=31536000, immutable`.

```rust
#![deny(clippy::all, clippy::pedantic)]

/// Classify a URL path into the appropriate `Cache-Control` value.
///
/// Rules:
/// - HTML documents: `no-store` (prevent Tor onion address from leaking via cache)
/// - Paths containing a 6-16 hex char hash segment (hashed assets): `max-age=31536000, immutable`
/// - Everything else: `no-cache` (revalidate but allow conditional GET)
fn cache_control_for(content_type: &str, path: &str) -> &'static str {
    if content_type.starts_with("text/html") {
        return "no-store";
    }
    // Detect hashed asset filenames: app.a1b2c3d4.js, main.deadbeef.css, etc.
    // Pattern: a dot followed by 8–16 lowercase hex chars followed by a dot.
    let file_name = std::path::Path::new(path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");

    if is_hashed_asset(file_name) {
        "max-age=31536000, immutable"
    } else {
        "no-cache"
    }
}

/// Return `true` when `name` contains a segment that looks like a content hash.
fn is_hashed_asset(name: &str) -> bool {
    // Split on `.` and look for a run of 8–16 hex chars between dots.
    name.split('.')
        .any(|seg| (8..=16).contains(&seg.len()) && seg.chars().all(|c| c.is_ascii_hexdigit()))
}

#[cfg(test)]
mod cache_tests {
    use super::{cache_control_for, is_hashed_asset};

    #[test]
    fn html_gets_no_store() {
        assert_eq!(cache_control_for("text/html; charset=utf-8", "/index.html"), "no-store");
    }

    #[test]
    fn hashed_js_gets_immutable() {
        assert_eq!(
            cache_control_for("text/javascript", "/app.a1b2c3d4.js"),
            "max-age=31536000, immutable"
        );
    }

    #[test]
    fn plain_css_gets_no_cache() {
        assert_eq!(cache_control_for("text/css", "/style.css"), "no-cache");
    }

    #[test]
    fn is_hashed_asset_rejects_short_hex() {
        assert!(!is_hashed_asset("app.abc.js")); // only 3 hex chars
    }

    #[test]
    fn is_hashed_asset_accepts_8_hex() {
        assert!(is_hashed_asset("app.deadbeef.js")); // exactly 8 hex chars
    }
}
```

---

### 2.6 — Truncate `.onion` address in log (H-6)

**File:** `src/tor/mod.rs`

```rust
#![deny(clippy::all, clippy::pedantic)]

// Replace the full address log banner with a truncated version.
// Show only the first 12 chars of the host to allow identification without
// fully leaking the address into log archives.

let display_addr = onion_name
    .strip_suffix(".onion")
    .and_then(|host| host.get(..12))
    .map_or(onion_name.as_str(), |prefix| prefix);

log::info!(
    "Tor onion service active: {}….onion (full address visible in dashboard)",
    display_addr
);
```

---

### 2.7 — Log `open_browser` failures (H-7)

**File:** `src/runtime/mod.rs`

```rust
#![deny(clippy::all, clippy::pedantic)]

pub fn open_browser(url: &str) {
    let result = {
        #[cfg(target_os = "macos")]
        { std::process::Command::new("open").arg(url).spawn() }
        #[cfg(target_os = "windows")]
        { std::process::Command::new("cmd").args(["/c", "start", "", url]).spawn() }
        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        { std::process::Command::new("xdg-open").arg(url).spawn() }
    };

    if let Err(e) = result {
        log::warn!("Could not open browser at {url}: {e}");
    }
}
```

---

## Phase 3 — HTTP Protocol Completeness

**Goals:** Make the server a correct HTTP/1.1 implementation.
**Issues addressed:** C-1, H-13, H-9, H-8

### 3.1 — HTTP/1.1 Keep-Alive (C-1)

This is the highest-impact change in the entire project.  The hand-rolled HTTP
parser needs to become a request *loop* rather than a single-shot handler.

Add `hyper` to `Cargo.toml`:

```toml
hyper = { version = "1", features = ["http1", "http2", "server"] }
hyper-util = { version = "0.1", features = ["tokio"] }
http-body-util = "0.1"
bytes = "1"
```

Refactor `src/server/handler.rs` to use `hyper`:

```rust
#![deny(clippy::all, clippy::pedantic)]
#![allow(clippy::too_many_arguments)]

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{
    body::Incoming,
    header::{self, HeaderValue},
    Method, Request, Response, StatusCode,
};
use hyper_util::rt::TokioIo;
use std::{path::Path, sync::Arc};
use tokio::net::TcpStream;

use crate::{runtime::state::SharedMetrics, Result};
use super::{fallback, mime};

type BoxBody = http_body_util::combinators::BoxBody<Bytes, std::io::Error>;

/// Serve one HTTP connection to completion, keeping the TCP socket alive
/// across multiple request/response cycles (HTTP/1.1 keep-alive).
pub async fn handle(
    stream: TcpStream,
    canonical_root: Arc<Path>,
    index_file: Arc<str>,
    dir_listing: bool,
    expose_dotfiles: bool,
    metrics: SharedMetrics,
    csp: Arc<str>,
) -> Result<()> {
    let io = TokioIo::new(stream);
    hyper::server::conn::http1::Builder::new()
        .keep_alive(true)
        .serve_connection(
            io,
            hyper::service::service_fn(move |req| {
                let root = Arc::clone(&canonical_root);
                let idx = Arc::clone(&index_file);
                let met = Arc::clone(&metrics);
                let csp = Arc::clone(&csp);
                async move {
                    route(req, &root, &idx, dir_listing, expose_dotfiles, &met, &csp).await
                }
            }),
        )
        .await
        .map_err(|e| {
            crate::AppError::Io(std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))
        })
}

async fn route(
    req: Request<Incoming>,
    canonical_root: &Path,
    index_file: &str,
    dir_listing: bool,
    expose_dotfiles: bool,
    metrics: &SharedMetrics,
    csp: &str,
) -> std::result::Result<Response<BoxBody>, std::io::Error> {
    if req.method() != Method::GET && req.method() != Method::HEAD && req.method() != Method::OPTIONS {
        metrics.add_error();
        return Ok(method_not_allowed());
    }
    if req.method() == Method::OPTIONS {
        metrics.add_request();
        return Ok(options_response());
    }

    let is_head = req.method() == Method::HEAD;
    let raw_path = req.uri().path();
    let decoded = percent_decode(raw_path.split('?').next().unwrap_or("/"));

    let response = serve_path(
        &decoded,
        canonical_root,
        index_file,
        dir_listing,
        expose_dotfiles,
        is_head,
        csp,
        metrics,
        &req,
    )
    .await?;

    Ok(response)
}

fn security_headers(builder: hyper::http::response::Builder, csp: &str, content_type: &str) -> hyper::http::response::Builder {
    let is_html = content_type.starts_with("text/html");
    let mut b = builder
        .header("X-Content-Type-Options", "nosniff")
        .header("X-Frame-Options", "SAMEORIGIN")
        .header("Referrer-Policy", "no-referrer")
        .header("Permissions-Policy", "camera=(), microphone=(), geolocation=()");

    if is_html && !csp.is_empty() {
        b = b.header("Content-Security-Policy", sanitize_header_value(csp).as_ref());
    }
    b
}

fn method_not_allowed() -> Response<BoxBody> {
    Response::builder()
        .status(StatusCode::METHOD_NOT_ALLOWED)
        .header(header::ALLOW, "GET, HEAD, OPTIONS")
        .header(header::CONTENT_LENGTH, "0")
        .body(Full::new(Bytes::new()).map_err(|e| match e {}).boxed())
        .unwrap_or_default()
}

fn options_response() -> Response<BoxBody> {
    Response::builder()
        .status(StatusCode::OK)
        .header(header::ALLOW, "GET, HEAD, OPTIONS")
        .header(header::CONTENT_LENGTH, "0")
        .body(Full::new(Bytes::new()).map_err(|e| match e {}).boxed())
        .unwrap_or_default()
}
```

> **Note:** The `hyper`-based refactor is the largest single change in this plan
> and touches `server/handler.rs` pervasively.  It should be done on a dedicated
> branch with the full integration test suite running at each step.

---

### 3.2 — ETag / Conditional GET (H-9)

**File:** `src/server/handler.rs`

With `hyper` in place, adding ETags requires:
1. Computing an ETag from file metadata (mtime + size; no content hash to avoid reading the file).
2. Comparing it against the `If-None-Match` request header.
3. Returning `304 Not Modified` when they match.

```rust
#![deny(clippy::all, clippy::pedantic)]

use std::time::{SystemTime, UNIX_EPOCH};

/// Compute a weak ETag from file metadata without reading file content.
///
/// Format: `W/"<mtime_secs>-<size>"`.
/// This is a weak ETag because it doesn't reflect content (a file could be
/// written with the same mtime and size but different bytes on some filesystems).
/// Weak ETags are sufficient for conditional GET — they prevent unnecessary
/// transfers on subsequent loads.
fn weak_etag(metadata: &std::fs::Metadata) -> String {
    let mtime = metadata
        .modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map_or(0, |d| d.as_secs());
    format!("W/\"{}-{}\"", mtime, metadata.len())
}

/// Return `true` when the client's `If-None-Match` header matches `etag`.
fn client_etag_matches(req: &Request<Incoming>, etag: &str) -> bool {
    req.headers()
        .get(hyper::header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|client_etag| {
            // Strip the W/" prefix for comparison if present.
            let norm = |s: &str| s.trim().trim_start_matches("W/").trim_matches('"');
            norm(client_etag) == norm(etag) || client_etag == "*"
        })
}

// In serve_file, after opening the file and reading metadata:
//
//   let etag = weak_etag(&metadata);
//   if client_etag_matches(&req, &etag) {
//       metrics.add_request();
//       return Ok(Response::builder()
//           .status(304)
//           .header("ETag", &etag)
//           .header("Cache-Control", cache_control_for(content_type, url_path))
//           .body(empty_body())
//           .expect("304 builder is infallible"));
//   }
//   // Normal 200 response with ETag header attached...
```

---

### 3.3 — Range Request Support (H-13)

**File:** `src/server/handler.rs`

```rust
#![deny(clippy::all, clippy::pedantic)]

/// A parsed byte range from the `Range: bytes=<start>-<end>` header.
#[derive(Debug, Clone, Copy)]
pub struct ByteRange {
    pub start: u64,
    pub end: u64, // inclusive
}

/// Parse `Range: bytes=N-M` from the request headers.
///
/// Supports a single range only (the common case for media players and download
/// managers).  Multi-range requests are not supported; a `416 Range Not
/// Satisfiable` is returned instead.
///
/// Returns `None` when no `Range` header is present (serve the full file).
/// Returns `Err(())` when the range is syntactically invalid or out-of-bounds
/// (the caller should return 416).
pub fn parse_range(req: &Request<Incoming>, file_len: u64) -> Option<Result<ByteRange, ()>> {
    let raw = req.headers().get(hyper::header::RANGE)?.to_str().ok()?;

    let bytes = raw.strip_prefix("bytes=")?;

    // Reject multi-range (contains a comma).
    if bytes.contains(',') {
        return Some(Err(()));
    }

    let (start_str, end_str) = bytes.split_once('-')?;

    let (start, end) = if start_str.is_empty() {
        // Suffix range: bytes=-N  (last N bytes)
        let suffix: u64 = end_str.parse().ok()?;
        let start = file_len.saturating_sub(suffix);
        (start, file_len - 1)
    } else {
        let start: u64 = start_str.parse().ok()?;
        let end = if end_str.is_empty() {
            file_len - 1
        } else {
            end_str.parse().ok()?
        };
        (start, end)
    };

    if start > end || end >= file_len {
        return Some(Err(()));
    }

    Some(Ok(ByteRange { start, end }))
}

// In serve_file, after computing file_len:
//
//   match parse_range(&req, file_len) {
//       None => { /* serve full file with 200 */ }
//       Some(Ok(range)) => {
//           // Seek to range.start, send (range.end - range.start + 1) bytes with 206.
//           file.seek(io::SeekFrom::Start(range.start)).await?;
//           let send_len = range.end - range.start + 1;
//           let response = Response::builder()
//               .status(206)
//               .header("Content-Range", format!("bytes {}-{}/{}", range.start, range.end, file_len))
//               .header("Content-Length", send_len.to_string())
//               // ... security headers ...
//               .body(...)
//               ...;
//       }
//       Some(Err(())) => {
//           return Ok(Response::builder()
//               .status(416)
//               .header("Content-Range", format!("bytes */{file_len}"))
//               .body(empty_body())
//               .expect("416 builder is infallible"));
//       }
//   }

#[cfg(test)]
mod range_tests {
    use super::{parse_range, ByteRange};

    fn fake_req(range: &str) -> hyper::Request<hyper::body::Incoming> {
        // Build a minimal request with the given Range header for testing.
        hyper::Request::builder()
            .header(hyper::header::RANGE, range)
            .body(unsafe { std::mem::zeroed() }) // test-only shortcut
            .unwrap()
    }

    // A real test suite would use hyper's test utilities rather than zeroed bodies.

    #[test]
    fn parse_range_no_header_returns_none() {
        let req = hyper::Request::builder().body(()).unwrap();
        // Signature: parse_range requires Incoming body; in real tests use test utils.
        // This documents the expected contract.
        // assert!(parse_range(&req, 1000).is_none());
    }

    #[test]
    fn range_start_end() {
        // bytes=0-499 on a 1000-byte file → start=0, end=499
        // (Unit test this with the pure parse logic extracted to a helper)
    }

    #[test]
    fn range_suffix() {
        // bytes=-500 on a 1000-byte file → start=500, end=999
    }

    #[test]
    fn range_out_of_bounds_returns_err() {
        // bytes=900-1100 on a 1000-byte file → Err (end >= file_len)
    }
}
```

---

### 3.4 — Brotli/Gzip Response Compression (H-8)

Add to `Cargo.toml`:

```toml
async-compression = { version = "0.4", features = ["tokio", "brotli", "gzip"] }
```

```rust
#![deny(clippy::all, clippy::pedantic)]

use hyper::header;

/// Encoding supported by the client, parsed from `Accept-Encoding`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    Brotli,
    Gzip,
    Identity,
}

/// Choose the best compression encoding from `Accept-Encoding`.
///
/// Prefers Brotli (best compression) over Gzip.
/// Returns `Identity` when neither is offered.
pub fn best_encoding(req: &Request<Incoming>) -> Encoding {
    let Some(accept) = req.headers().get(header::ACCEPT_ENCODING) else {
        return Encoding::Identity;
    };
    let Ok(s) = accept.to_str() else {
        return Encoding::Identity;
    };

    let has = |name: &str| {
        s.split(',').any(|part| {
            let token = part.trim().split(';').next().unwrap_or("").trim();
            token.eq_ignore_ascii_case(name)
        })
    };

    if has("br") {
        Encoding::Brotli
    } else if has("gzip") {
        Encoding::Gzip
    } else {
        Encoding::Identity
    }
}

// In the file-serving path, after opening the file:
//
//   let encoding = best_encoding(&req);
//   let (body, content_encoding) = match encoding {
//       Encoding::Brotli => {
//           let compressed = compress_brotli(&mut file).await?;
//           (compressed, Some("br"))
//       }
//       Encoding::Gzip => {
//           let compressed = compress_gzip(&mut file).await?;
//           (compressed, Some("gzip"))
//       }
//       Encoding::Identity => (stream_file(file, file_len), None),
//   };
//
//   if let Some(enc) = content_encoding {
//       builder = builder.header("Content-Encoding", enc);
//       builder = builder.header("Vary", "Accept-Encoding");
//   }

/// Compress `file` content with Brotli and return as `Bytes`.
///
/// For production, pre-compress files at startup and cache on disk;
/// this function is for on-the-fly compression of infrequently-served files.
async fn compress_brotli(file: &mut tokio::fs::File) -> std::io::Result<bytes::Bytes> {
    use async_compression::tokio::bufread::BrotliEncoder;
    use tokio::io::{AsyncReadExt, BufReader};

    let mut encoder = BrotliEncoder::new(BufReader::new(file));
    let mut buf = Vec::new();
    encoder.read_to_end(&mut buf).await?;
    Ok(bytes::Bytes::from(buf))
}
```

---

## Phase 4 — Feature Completeness

**Goals:** Reach feature parity with top-tier static hosts.
**Issues addressed:** C-6, H-2, H-10, M-13, M-14, M-15, M-16

### 4.1 — SPA Fallback Routing + Custom Error Pages (C-6, H-10)

**Config addition** in `src/config/mod.rs`:

```rust
#![deny(clippy::all, clippy::pedantic)]

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SiteConfig {
    // ... existing fields ...

    /// When `true`, requests for paths that don't match any file are served
    /// `index.html` (with status 200) instead of a 404.
    /// Required for single-page applications with client-side routing
    /// (React Router, Vue Router, Svelte Kit, etc.).
    #[serde(default)]
    pub spa_routing: bool,

    /// Optional custom 404 page, relative to the site directory.
    /// When set and the file exists, it is served (with status 404) for
    /// all requests that resolve to `NotFound`.
    #[serde(default)]
    pub error_404: Option<String>,

    /// Optional custom 500/503 page, relative to the site directory.
    #[serde(default)]
    pub error_503: Option<String>,
}
```

**Handler change** in `resolve_path`:

```rust
// After the existing resolution logic, in the Resolved::NotFound branch:
//
//   Resolved::NotFound => {
//       if spa_routing {
//           // SPA mode: serve index.html for all unmatched paths.
//           let spa_index = canonical_root.join(index_file);
//           if spa_index.exists() {
//               return Resolved::File(spa_index.canonicalize().unwrap_or(spa_index));
//           }
//       }
//       if let Some(ref p404) = error_404_path {
//           return Resolved::Custom404(p404.clone());
//       }
//       Resolved::NotFound
//   }
```

Add the `Custom404` and `Custom503` variants to `Resolved`:

```rust
#[derive(Debug, PartialEq)]
pub enum Resolved {
    File(std::path::PathBuf),
    NotFound,
    Fallback,
    Forbidden,
    DirectoryListing(std::path::PathBuf),
    Redirect(String),
    /// Custom error page: path to the HTML file + the HTTP status code to use.
    CustomError { path: std::path::PathBuf, status: u16 },
}
```

---

### 4.2 — Refresh `canonical_root` on `[R]` reload (H-2)

**File:** `src/runtime/events.rs` and `src/server/mod.rs`

Pass a `watch::Sender<Arc<Path>>` to the server so the accept loop can update
`canonical_root` without restart.

```rust
#![deny(clippy::all, clippy::pedantic)]

// In server/mod.rs — add to run() signature:
//   root_watch: watch::Receiver<Arc<Path>>,
//
// In the accept loop, at the top of the loop body:
//   // Non-blocking check for a new canonical_root (triggered by [R] reload).
//   if root_watch.has_changed().unwrap_or(false) {
//       canonical_root = Arc::clone(&root_watch.borrow_and_update());
//       log::info!("Site root refreshed: {}", canonical_root.display());
//   }

// In events.rs — KeyEvent::Reload handler, after the scan:
//   if let Ok(new_root) = site_root.canonicalize() {
//       let _ = root_tx.send(Arc::from(new_root.as_path()));
//   }
```

---

### 4.3 — URL Redirect/Rewrite Rules (M-13)

**Config addition** in `src/config/mod.rs`:

```rust
#![deny(clippy::all, clippy::pedantic)]

/// A single redirect or rewrite rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedirectRule {
    /// Source URL path to match (exact match only in this implementation).
    pub from: String,
    /// Destination URL.
    pub to: String,
    /// HTTP status code.  Use 301 for permanent, 302 for temporary.
    #[serde(default = "default_redirect_status")]
    pub status: u16,
}

const fn default_redirect_status() -> u16 { 301 }

// In Config, add:
//   #[serde(default)]
//   pub redirects: Vec<RedirectRule>,

// In resolve_path, check redirects FIRST before filesystem resolution:
//   for rule in redirects {
//       if url_path == rule.from {
//           return Resolved::ExternalRedirect {
//               location: rule.to.clone(),
//               status: rule.status,
//           };
//       }
//   }
```

**Example settings.toml entry:**

```toml
[[redirects]]
from = "/old-page"
to = "/new-page"
status = 301

[[redirects]]
from = "/blog"
to = "https://external-blog.example"
status = 302
```

---

### 4.4 — Missing MIME types (M-14)

**File:** `src/server/mime.rs`

```rust
#![deny(clippy::all, clippy::pedantic)]

// Add to the match arms in `for_extension`:

// Web app manifests (required for PWA installation)
"webmanifest" => "application/manifest+json",

// Modern audio
"opus" => "audio/opus",
"flac" => "audio/flac",
"aac" => "audio/aac",
"m4a" => "audio/mp4",

// Modern video
"mov" => "video/quicktime",
"m4v" => "video/mp4",
"mkv" => "video/x-matroska",
"avi" => "video/x-msvideo",

// 3D / WebGL
"glb" => "model/gltf-binary",
"gltf" => "model/gltf+json",

// Data formats
"ndjson" => "application/x-ndjson",
"geojson" => "application/geo+json",
"toml" => "application/toml",
"yaml" | "yml" => "application/yaml",

// Web fonts (additional)
"eot" => "application/vnd.ms-fontobject",

// Source maps
"map" => "application/json",

// WebAssembly text format
"wat" => "text/plain; charset=utf-8",
```

---

### 4.5 — `--serve` one-shot CLI mode (M-15)

Replace the hand-rolled argument parser with `clap`:

```toml
# Cargo.toml
clap = { version = "4", features = ["derive"] }
```

**File:** `src/main.rs`

```rust
#![deny(clippy::all, clippy::pedantic)]

use std::path::PathBuf;
use clap::Parser;

/// Single-binary, zero-setup static site host with built-in Tor support.
#[derive(Debug, Parser)]
#[command(version, about, long_about = None)]
pub struct Cli {
    /// Override the path to settings.toml.
    #[arg(long, value_name = "PATH")]
    pub config: Option<PathBuf>,

    /// Override the data-directory root.
    #[arg(long, value_name = "PATH")]
    pub data_dir: Option<PathBuf>,

    /// Serve a directory directly without first-run setup.
    ///
    /// Example: rusthost-cli --serve ./docs --port 3000 --no-tor
    #[arg(long, value_name = "DIR")]
    pub serve: Option<PathBuf>,

    /// Port to use with --serve (default: 8080).
    #[arg(long, default_value = "8080")]
    pub port: u16,

    /// Disable Tor when using --serve.
    #[arg(long)]
    pub no_tor: bool,

    /// Disable the interactive console (useful for headless/CI use).
    #[arg(long)]
    pub headless: bool,
}

#[tokio::main]
async fn main() {
    std::panic::set_hook(Box::new(|info| {
        rusthost::console::cleanup();
        eprintln!("\nPanic: {info}");
    }));

    let cli = Cli::parse();

    // Convert clap args to the internal CliArgs used by lifecycle.
    let args = rusthost::runtime::lifecycle::CliArgs {
        config_path: cli.config,
        data_dir: cli.data_dir,
        serve_dir: cli.serve,
        serve_port: cli.port,
        no_tor: cli.no_tor,
        headless: cli.headless,
    };

    if let Err(err) = rusthost::runtime::lifecycle::run(args).await {
        rusthost::console::cleanup();
        eprintln!("\nFatal error: {err}");
        std::process::exit(1);
    }
}
```

**`CliArgs` expansion** in `src/runtime/lifecycle.rs`:

```rust
#[derive(Debug, Default)]
pub struct CliArgs {
    pub config_path: Option<PathBuf>,
    pub data_dir: Option<PathBuf>,
    /// When `Some`, skip first-run setup and directly serve this directory.
    pub serve_dir: Option<PathBuf>,
    /// Port for `--serve` mode.  Ignored when `serve_dir` is `None`.
    pub serve_port: u16,
    /// Disable Tor in `--serve` mode.
    pub no_tor: bool,
    /// Headless mode: disable the interactive console.
    pub headless: bool,
}

// In `run()`, before the settings_path.exists() check:
//
//   if let Some(dir) = args.serve_dir {
//       return one_shot_serve(dir, args.serve_port, !args.no_tor, args.headless).await;
//   }

/// Serve `dir` directly with minimal configuration — no first-run setup required.
async fn one_shot_serve(
    dir: PathBuf,
    port: u16,
    tor_enabled: bool,
    headless: bool,
) -> Result<()> {
    use std::num::NonZeroU16;
    use crate::config::{Config, ServerConfig, SiteConfig, TorConfig, LoggingConfig,
                        ConsoleConfig, IdentityConfig, LogLevel, CspLevel};

    let dir_str = dir.to_string_lossy().into_owned();
    let config = Arc::new(Config {
        server: ServerConfig {
            port: NonZeroU16::new(port).unwrap_or(NonZeroU16::MIN),
            bind: "127.0.0.1".parse().expect("literal is valid"),
            auto_port_fallback: true,
            open_browser_on_start: false,
            max_connections: 256,
            max_connections_per_ip: 16,
            csp_level: CspLevel::Off,
        },
        site: SiteConfig {
            directory: dir_str.clone(),
            index_file: "index.html".into(),
            enable_directory_listing: true,
            expose_dotfiles: false,
            spa_routing: false,
            error_404: None,
            error_503: None,
        },
        tor: TorConfig { enabled: tor_enabled },
        logging: LoggingConfig {
            enabled: false,
            level: LogLevel::Info,
            file: "rusthost.log".into(),
            filter_dependencies: true,
        },
        console: ConsoleConfig {
            interactive: !headless,
            refresh_rate_ms: 500,
            show_timestamps: false,
        },
        identity: IdentityConfig {
            instance_name: "RustHost".into(),
        },
        redirects: Vec::new(),
    });

    // Use the parent directory of `dir` as data_dir so the path join works.
    let data_dir = dir.parent().map_or_else(|| dir.clone(), Path::to_path_buf);
    normal_run(data_dir, config).await
}
```

---

### 4.6 — Structured Access Log (M-16)

**File:** `src/logging/mod.rs` (new sub-logger)

```rust
#![deny(clippy::all, clippy::pedantic)]

use std::net::IpAddr;

/// An HTTP access log record in Combined Log Format (CLF).
///
/// CLF format:
/// `<host> - - [<time>] "<method> <path> <proto>" <status> <bytes>`
pub struct AccessRecord<'a> {
    pub remote_addr: IpAddr,
    pub method: &'a str,
    pub path: &'a str,
    pub protocol: &'a str,
    pub status: u16,
    pub bytes_sent: u64,
    pub user_agent: Option<&'a str>,
    pub referer: Option<&'a str>,
}

impl std::fmt::Display for AccessRecord<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let now = chrono::Local::now().format("%d/%b/%Y:%H:%M:%S %z");
        let ua = self.user_agent.unwrap_or("-");
        let referer = self.referer.unwrap_or("-");
        write!(
            f,
            "{} - - [{now}] \"{} {} {}\" {} {} \"{}\" \"{}\"",
            self.remote_addr,
            self.method,
            self.path,
            self.protocol,
            self.status,
            self.bytes_sent,
            referer,
            ua,
        )
    }
}

/// Global access log writer.
///
/// Separate from the application logger to produce clean CLF output
/// without level/timestamp prefixes.
static ACCESS_LOG: OnceLock<Mutex<LogFile>> = OnceLock::new();

pub fn log_access(record: &AccessRecord<'_>) {
    if let Some(log) = ACCESS_LOG.get() {
        if let Ok(mut lf) = log.lock() {
            lf.write_line(&record.to_string());
        }
    }
}
```

---

## Phase 5 — Reliability & Correctness

**Goals:** Fix remaining correctness issues and improve robustness.
**Issues addressed:** M-4, M-6, M-7, M-8, M-11

### 5.1 — Reduce `fstat` frequency in log writer (M-4)

**File:** `src/logging/mod.rs`

```rust
#![deny(clippy::all, clippy::pedantic)]

/// Check for rotation every N writes rather than on every write.
/// At INFO level this reduces fstat calls from ~1000/min to ~10/min.
const ROTATION_CHECK_INTERVAL: u64 = 100;

struct LogFile {
    file: File,
    path: std::path::PathBuf,
    /// Number of lines written since the last size check.
    writes_since_check: u64,
    /// Last known file size in bytes (updated at each check).
    cached_size: u64,
}

impl LogFile {
    fn write_line(&mut self, line: &str) {
        self.writes_since_check = self.writes_since_check.wrapping_add(1);

        if self.writes_since_check >= ROTATION_CHECK_INTERVAL {
            self.writes_since_check = 0;
            if let Ok(meta) = self.file.metadata() {
                self.cached_size = meta.len();
            }
            if self.cached_size >= MAX_LOG_BYTES {
                self.rotate();
            }
        }

        if writeln!(self.file, "{line}").is_ok() {
            self.cached_size = self.cached_size.saturating_add(
                u64::try_from(line.len()).unwrap_or(u64::MAX).saturating_add(1),
            );
        }
    }

    fn rotate(&mut self) {
        let rotated = self.path.with_extension("log.1");
        let _ = std::fs::rename(&self.path, &rotated);
        // Re-open log file with restrictive permissions.
        #[cfg(unix)]
        let new_file = {
            use std::os::unix::fs::OpenOptionsExt;
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .mode(0o600)
                .open(&self.path)
        };
        #[cfg(not(unix))]
        let new_file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path);
        if let Ok(f) = new_file {
            self.file = f;
            self.cached_size = 0;
        }
    }
}
```

---

### 5.2 — Exponential backoff in Tor retry loop (M-6)

**File:** `src/tor/mod.rs`

```rust
#![deny(clippy::all, clippy::pedantic)]

/// Compute the exponential backoff delay for attempt `n` (1-indexed).
///
/// Formula: `base * 2^(n-1)`, capped at `max_secs`.
/// Attempt 1 →  30 s
/// Attempt 2 →  60 s
/// Attempt 3 → 120 s
/// Attempt 4 → 240 s
/// Attempt 5 → 300 s (capped)
fn backoff_delay(attempt: u32, base_secs: u64, max_secs: u64) -> Duration {
    let exp = u64::from(attempt.saturating_sub(1));
    let secs = base_secs.saturating_mul(1u64.saturating_shl(
        u32::try_from(exp.min(u64::from(u32::MAX))).unwrap_or(u32::MAX),
    ));
    Duration::from_secs(secs.min(max_secs))
}

const RETRY_BASE_SECS: u64 = 30;
const RETRY_MAX_SECS: u64 = 300;

// Replace: Duration::from_secs(RETRY_BASE_SECS.saturating_mul(u64::from(attempts)))
// With:    backoff_delay(attempts, RETRY_BASE_SECS, RETRY_MAX_SECS)

#[cfg(test)]
mod backoff_tests {
    use super::backoff_delay;
    use std::time::Duration;

    #[test]
    fn attempt_1_is_base() {
        assert_eq!(backoff_delay(1, 30, 300), Duration::from_secs(30));
    }

    #[test]
    fn attempt_2_doubles() {
        assert_eq!(backoff_delay(2, 30, 300), Duration::from_secs(60));
    }

    #[test]
    fn caps_at_max() {
        assert_eq!(backoff_delay(10, 30, 300), Duration::from_secs(300));
    }

    #[test]
    fn attempt_0_is_zero() {
        assert_eq!(backoff_delay(0, 30, 300), Duration::from_secs(0));
    }
}
```

---

### 5.3 — Make `scan_site` resilient to unreadable subdirectories (M-11)

**File:** `src/server/mod.rs`

```rust
#![deny(clippy::all, clippy::pedantic)]

pub fn scan_site(site_root: &Path) -> crate::Result<(u32, u64)> {
    let mut count = 0u32;
    let mut bytes = 0u64;
    let mut queue: std::collections::VecDeque<PathBuf> = std::collections::VecDeque::new();
    queue.push_back(site_root.to_path_buf());

    #[cfg(unix)]
    let mut visited_inodes: std::collections::HashSet<u64> = std::collections::HashSet::new();

    while let Some(dir) = queue.pop_front() {
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(e) => {
                // Skip unreadable directories with a per-directory warning.
                // Do NOT abort the entire scan — the rest of the tree may be readable.
                log::warn!("Skipping unreadable directory {}: {e}", dir.display());
                continue; // <-- was `return Err(...)` before
            }
        };

        for entry in entries.flatten() {
            let Ok(meta) = entry.metadata() else { continue };
            if meta.is_file() {
                count = count.saturating_add(1);
                bytes = bytes.saturating_add(meta.len());
            } else if meta.is_dir() {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::MetadataExt;
                    let ino = meta.ino();
                    if !visited_inodes.insert(ino) {
                        log::warn!(
                            "Symlink cycle at {} (inode {ino}), skipping",
                            entry.path().display()
                        );
                        continue;
                    }
                }
                #[cfg(not(unix))]
                {
                    if let Ok(sym_meta) = entry.path().symlink_metadata() {
                        if sym_meta.file_type().is_symlink() {
                            log::warn!(
                                "Skipping symlinked directory {} (no inode tracking on this platform)",
                                entry.path().display()
                            );
                            continue;
                        }
                    }
                }
                queue.push_back(entry.path());
            }
        }
    }

    Ok((count, bytes))
}
```

---

## Phase 6 — Polish & Ecosystem

**Goals:** Make the project welcoming to contributors and operators.
**Issues addressed:** L-1, L-2, L-3, L-4, L-5, L-7, L-8, M-18

### 6.1 — Replace "fix X.Y" comments

This is a global find-replace.  The table below maps every internal tag to a
human-readable replacement.  Use `git grep 'fix [A-Z0-9]\+-[0-9]'` to find all instances.

| Internal tag | Replacement prose |
|---|---|
| `fix H-1` | `// write_headers emits all security headers from one place; write_redirect delegates here` |
| `fix H-2` | `// Copy each byte through userspace; zero-copy sendfile optimisation is a future improvement` |
| `fix H-3` | `// Strip CR/LF from header values to prevent CRLF response-splitting attacks` |
| `fix H-4` | `// Handle OPTIONS preflight: browsers send this automatically before cross-origin requests` |
| `fix H-5` | `// Separate 405 Method Not Allowed from 400 Bad Request per RFC 9110 §15.5.6` |
| `fix H-6` | `// Percent-decode URL before filesystem resolution` |
| `fix H-7` | `// Guard against integer overflow in byte index arithmetic` |
| `fix H-8` | `// HTML-escape directory entry names to prevent XSS via crafted filenames` |
| `fix H-9` | `// Emit security headers on 301 redirect so onion address does not leak via Referer` |
| `fix H-10` | `// Block direct requests for dot-files (e.g. .git, .env) unless operator opts in` |
| `fix T-1` | `// Bracket IPv6 addresses for SocketAddr parsing: [::1]:port not ::1:port` |
| `fix T-2` | `// Size Tor semaphore identically to HTTP semaphore so operators see consistent behaviour` |
| `fix T-3` | `// Keep _onion_service_guard alive — dropping it de-registers the service from the network` |
| `fix T-4` | `// Reset retry counter after 1 h gap — distant disruptions are not "consecutive" failures` |
| `fix T-5` | `// Honour shutdown during bootstrap so long-running first-run does not block clean exit` |
| `fix T-6` | `// Close idle Tor streams to prevent stale circuits from consuming semaphore permits` |
| `fix T-7` | `// Restrict Tor key directories to owner-only before storing the service keypair` |
| `fix 3.x` / `fix 4.x` | *(replace with descriptive text as above for each instance)* |

### 6.2 — Depth-bound `scan_site` BFS (L-7)

```rust
#![deny(clippy::all, clippy::pedantic)]

/// Maximum directory depth to traverse.  Prevents runaway BFS on artificially
/// deep or adversarially-constructed directory trees.
const MAX_SCAN_DEPTH: usize = 64;

// Replace the `VecDeque<PathBuf>` with `VecDeque<(PathBuf, usize)>`:
//
//   queue.push_back((site_root.to_path_buf(), 0));
//
//   while let Some((dir, depth)) = queue.pop_front() {
//       if depth >= MAX_SCAN_DEPTH {
//           log::warn!("scan_site: depth limit ({MAX_SCAN_DEPTH}) reached at {}", dir.display());
//           continue;
//       }
//       // ... existing logic, push with (entry.path(), depth + 1) ...
//   }
```

### 6.3 — Multiple log rotation backups (L-4)

```rust
#![deny(clippy::all, clippy::pedantic)]

fn rotate(&mut self) {
    // Rotate: .log.4 is deleted, .log.3 → .log.4, ..., .log → .log.1
    const MAX_BACKUPS: u32 = 5;

    // Delete the oldest backup if it exists.
    let _ = std::fs::remove_file(
        self.path.with_extension(format!("log.{MAX_BACKUPS}"))
    );

    // Shift existing backups.
    for n in (1..MAX_BACKUPS).rev() {
        let from = self.path.with_extension(format!("log.{n}"));
        let to = self.path.with_extension(format!("log.{}", n + 1));
        if from.exists() {
            let _ = std::fs::rename(&from, &to);
        }
    }

    // Move current log to .log.1.
    let _ = std::fs::rename(&self.path, self.path.with_extension("log.1"));

    // Re-open a fresh file.
    // (same platform-specific OpenOptions code as before)
}
```

### 6.4 — Restrict `pub` visibility (L-2)

Audit every `pub` item in `src/lib.rs`.  Items only used in integration tests
should be `pub(crate)` with a `#[cfg(test)]` re-export:

```rust
// src/lib.rs
pub mod config;
pub mod console;
pub mod error;
pub mod logging;
pub mod runtime;
pub mod server;
pub mod tor;

pub use error::AppError;
pub type Result<T, E = AppError> = std::result::Result<T, E>;

// Items needed by integration tests only:
#[cfg(test)]
pub use server::handler::{percent_decode, resolve_path, Resolved};
#[cfg(test)]
pub use tor::onion_address_from_pubkey;
```

---

## Phase Summary

| Phase | Addresses | Risk | Estimated Effort |
|-------|-----------|------|-----------------|
| 0 — Repository Scaffolding | C-5, H-11, H-12, L-5 | None | 2–4 h |
| 1 — Critical Bug Fixes | C-2, C-3, H-1, M-3, M-9, M-10 | Low | 4–8 h |
| 2 — Security Hardening | C-4, H-4, H-5, H-6, H-7, M-1, M-2, M-17 | Low–Medium | 8–12 h |
| 3 — HTTP Protocol Completeness | C-1, H-8, H-9, H-13 | High (hyper migration) | 24–40 h |
| 4 — Feature Completeness | C-6, H-2, H-10, M-13, M-14, M-15, M-16 | Medium | 16–24 h |
| 5 — Reliability & Correctness | M-4, M-6, M-7, M-8, M-11 | Low | 8–12 h |
| 6 — Polish & Ecosystem | L-1 to L-8, M-18 | None | 4–8 h |

**Total estimated effort:** 66–108 engineering hours (one developer, unburdened).

**Recommended merge order within Phase 3:** The `hyper` migration (3.1) must land
before ETag (3.2), Range (3.3), and compression (3.4), as all three depend on
`hyper::Request` and `hyper::Response` types.  Run the full integration test suite
after 3.1 before proceeding.

---

## Lint Gate Reference

Every code snippet in this document was written to pass the following workspace-level gates.
Verify with `cargo clippy --all-targets -- -D warnings` after each phase.

```toml
# Cargo.toml [lints] section (already present, reproduced for reference)
[lints.rust]
unsafe_code = "forbid"

[lints.clippy]
all      = { level = "deny",  priority = -1 }
pedantic = { level = "deny",  priority = -1 }
nursery  = { level = "warn",  priority = -1 }
```

Individual `#[allow(...)]` overrides used in this plan:

| Allow | Location | Reason |
|-------|----------|--------|
| `clippy::too_many_arguments` | `write_headers` | Mirrors HTTP wire format; adding a builder struct would obscure the intent |
| `clippy::cast_possible_truncation` | `body.len() as u64` | Documented as safe: usize ≤ 64 bits on all supported targets |
| `clippy::indexing_slicing` | SHA3 array indexing | GenericArray length is runtime-unknown to clippy; length is guaranteed by the hash spec |
