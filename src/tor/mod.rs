//! # Tor Module — Arti (in-process)
//!
//! **Directory:** `src/tor/`
//!
//! Replaces the old subprocess + torrc approach with Arti, the official
//! Tor implementation in Rust, running entirely in-process.
//!
//! ## What changed vs. the old implementation
//!
//! | Old (C Tor subprocess)               | New (Arti in-process)                  |
//! |--------------------------------------|----------------------------------------|
//! | Searches for `tor` binary in PATH    | No external binary needed              |
//! | Writes a `torrc` file to disk        | Config is built in Rust code           |
//! | Polls `hostname` file to get address | Address available on launch            |
//! | Subprocess killed on shutdown        | Dropped automatically with task exit   |
//!
//! ## Flow
//!
//! 1. `init()` spawns a Tokio task and returns its `JoinHandle`.
//!    The handle is awaited by lifecycle during graceful shutdown so active
//!    Tor circuits get a chance to close cleanly (fix 3.1).
//! 2. `TorClient::create_bootstrapped()` connects to the Tor network.
//!    A 120-second timeout prevents an indefinite hang on firewalled networks
//!    (fix 3.3).  First run downloads ~2 MB of directory consensus (~30 s).
//!    Subsequent runs reuse the cache in `rusthost-data/arti_cache/` and are fast.
//! 3. `tor_client.launch_onion_service()` registers the hidden service.
//!    The address is derived from the keypair and is available immediately.
//!    The keypair is persisted in `rusthost-data/arti_state/keys/` so the
//!    same `.onion` address is used on every restart.
//! 4. `handle_rend_requests()` converts incoming `RendRequest`s into
//!    `StreamRequest`s (the Arti equivalent of each new TCP connection
//!    arriving on `HiddenServicePort 80 127.0.0.1:{port}`).
//! 5. Each `StreamRequest` is accepted and bridged to the local HTTP server
//!    with `tokio::io::copy_bidirectional` in its own Tokio task.
//!    Both the local connect and the bidirectional copy carry timeouts to
//!    bound the lifetime of stalled connections (fix 3.1, fix 3.2).
//! 6. When the `stream_requests` stream ends unexpectedly (transient network
//!    disruption, Arti circuit reset) the module re-bootstraps with
//!    exponential backoff up to `MAX_RETRIES` times before giving up
//!    (fix 3.4).
//! 7. `kill()` is a no-op — the `TorClient` is dropped when the task exits
//!    during normal Tokio runtime shutdown, which closes all circuits cleanly.

use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

use arti_client::config::TorClientConfigBuilder;
use arti_client::TorClient;
use futures::StreamExt;
use tokio::{net::TcpStream, sync::watch, task::JoinHandle};
use tor_cell::relaycell::msg::Connected;
use tor_hsservice::{config::OnionServiceConfigBuilder, handle_rend_requests, HsId, StreamRequest};

use crate::runtime::state::{SharedState, TorStatus};

// ─── Timeout / retry constants ────────────────────────────────────────────────

/// How long to wait for Arti to complete the initial directory bootstrap.
/// Covers first-run consensus download plus circuit establishment.
const BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(120);

/// How long to wait for the local HTTP server to accept a proxied connection.
/// A hung local server should not hold a semaphore permit indefinitely.
const LOCAL_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Idle timeout for a single proxied Tor stream.
///
/// If no bytes flow in either direction for this long the stream is closed
/// and the semaphore permit is released.  Using an idle timeout rather than
/// a wall-clock cap avoids disconnecting legitimate large downloads while
/// still evicting adversarially-idle connections that hold permits without
/// sending data.  (fix T-6)
const IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// Base delay between re-bootstrap attempts.
const RETRY_BASE_SECS: u64 = 30;

/// Maximum delay between re-bootstrap attempts.
///
/// Caps the exponential growth so a long-running server with repeated failures
/// never waits more than 5 minutes between attempts.
const RETRY_MAX_SECS: u64 = 300;

/// Maximum number of automatic re-bootstrap attempts after an unexpected
/// stream-end before the module sets `TorStatus::Failed` permanently.
const MAX_RETRIES: u32 = 5;

// ─── Public entry point ───────────────────────────────────────────────────────

/// Initialise Tor using the embedded Arti client.
///
/// Spawns a Tokio task and returns its [`JoinHandle`].  The caller **must**
/// await the handle (with a timeout) during graceful shutdown so active Tor
/// circuits can close cleanly before the runtime exits (fix 3.1).
///
/// Tor status and the onion address are written into `state` as things
/// progress.  `shutdown` is a watch channel whose `true` value triggers a
/// clean exit from the stream-request loop.
///
/// `bind_addr` must match `config.server.bind` so the local proxy connect
/// uses the correct loopback address even when the server is bound to `::1`
/// rather than `127.0.0.1` (fix 3.6).
/// Initialise Tor using the embedded Arti client.
///
/// `max_connections` must match `config.server.max_connections` so the Tor
/// semaphore is sized identically to the HTTP server's connection limit (fix T-2).
pub fn init(
    data_dir: PathBuf,
    bind_port: u16,
    bind_addr: IpAddr,
    max_connections: usize,
    state: SharedState,
    shutdown: watch::Receiver<bool>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut attempts = 0u32;
        // fix T-4 — track when the last failure occurred so we can reset the
        // consecutive-failure counter after a sufficiently long stable period.
        let mut last_failure_time: Option<std::time::Instant> = None;

        loop {
            match run(
                data_dir.clone(),
                bind_port,
                bind_addr,
                max_connections,
                state.clone(),
                shutdown.clone(),
            )
            .await
            {
                Ok(false) => {
                    // Shutdown signal — exit cleanly without touching status.
                    log::info!("Tor: task exiting cleanly.");
                    break;
                }
                Ok(true) => {
                    // Stream ended unexpectedly (transient network disruption).
                    // fix T-4 — reset consecutive failure counter if last failure was
                    // more than an hour ago (disruptions spaced far apart are not
                    // truly "consecutive" and should not permanently fail the service).
                    let now = std::time::Instant::now();
                    if let Some(last) = last_failure_time {
                        if now.duration_since(last) > Duration::from_secs(3600) {
                            log::info!(
                                "Tor: resetting retry counter — \
                                 last disruption was over an hour ago."
                            );
                            attempts = 0;
                        }
                    }
                    last_failure_time = Some(now);

                    attempts = attempts.saturating_add(1);
                    if attempts > MAX_RETRIES {
                        log::error!(
                            "Tor: stream ended {MAX_RETRIES} consecutive times; giving up."
                        );
                        set_status(
                            &state,
                            TorStatus::Failed("too many reconnect attempts".into()),
                        )
                        .await;
                        break;
                    }

                    let delay = backoff_delay(attempts, RETRY_BASE_SECS, RETRY_MAX_SECS);
                    log::warn!(
                        "Tor: stream ended; re-bootstrapping in {delay:?} \
                         (attempt {attempts}/{MAX_RETRIES})"
                    );

                    // Clear the displayed address while reconnecting.
                    state.write().await.onion_address = None;
                    set_status(&state, TorStatus::Starting).await;

                    // Honour shutdown signals that arrive during the backoff sleep.
                    // The cloned receiver must be bound to a local variable so it
                    // lives for the full duration of the select! borrow (E0716).
                    let mut backoff_shutdown = shutdown.clone();
                    tokio::select! {
                        () = tokio::time::sleep(delay) => {}
                        _ = backoff_shutdown.changed() => {
                            if *backoff_shutdown.borrow() {
                                log::info!("Tor: shutdown during backoff — exiting.");
                                break;
                            }
                        }
                    }
                }
                Err(e) => {
                    log::error!("Tor: fatal error: {e}");
                    set_status(&state, TorStatus::Failed(e.to_string())).await;
                    break;
                }
            }
        }
    })
}

// `kill()` has been removed (fix 2.10): the `TorClient` is owned by the task
// spawned in `init()` and is dropped when that task exits, which closes all
// Tor circuits cleanly.  Graceful shutdown is now signalled through the
// `shutdown` watch channel passed to `init()`.

// ─── Core async logic ─────────────────────────────────────────────────────────

/// Outcome of a successful bootstrap and onion-service launch.
///
/// Kept as a named struct so `run` can destructure it without a large tuple.
struct TorSession {
    /// Must be kept alive — dropping de-registers the service from Tor (fix T-3).
    /// `launch_onion_service` returns `Arc<RunningOnionService>`, so we store that.
    _onion_service_guard: std::sync::Arc<tor_hsservice::RunningOnionService>,
    stream_requests: futures::stream::BoxStream<'static, StreamRequest>,
    onion_name: String,
}

/// Bootstrap the Arti client and launch the onion service.
///
/// Extracted from [`run`] to keep that function under the 100-line limit.
/// Returns `Ok(None)` on clean shutdown during bootstrap, `Ok(Some(session))`
/// on success, or `Err` on an unrecoverable error.
async fn bootstrap_and_launch(
    data_dir: &std::path::Path,
    shutdown: watch::Receiver<bool>,
) -> Result<Option<TorSession>, Box<dyn std::error::Error + Send + Sync>> {
    ensure_private_dir(&data_dir.join("arti_state"))
        .map_err(|e| format!("Cannot create secure state directory: {e}"))?;
    ensure_private_dir(&data_dir.join("arti_cache"))
        .map_err(|e| format!("Cannot create secure cache directory: {e}"))?;

    let config = TorClientConfigBuilder::from_directories(
        data_dir.join("arti_state"),
        data_dir.join("arti_cache"),
    )
    .build()?;

    log::info!("Tor: bootstrapping — first run downloads ~2 MB of directory data (~30 s)");

    // Honour shutdown during the up-to-120 s bootstrap window (fix T-5).
    let tor_client = {
        let mut sd = shutdown.clone();
        tokio::select! {
            result = tokio::time::timeout(BOOTSTRAP_TIMEOUT, TorClient::create_bootstrapped(config)) => {
                result
                    .map_err(|_| format!(
                        "Tor bootstrap timed out after {}s — check network connectivity",
                        BOOTSTRAP_TIMEOUT.as_secs()
                    ))?
                    .map_err(|e| format!("Tor bootstrap failed: {e}"))?
            }
            _ = sd.changed() => {
                if *sd.borrow() {
                    log::info!("Tor: shutdown received during bootstrap — exiting.");
                    return Ok(None);
                }
                return Err("shutdown channel closed during bootstrap".into());
            }
        }
    };

    log::info!("Tor: connected to the Tor network");

    let svc_config = OnionServiceConfigBuilder::default()
        .nickname("rusthost".parse()?)
        .build()?;

    // Keep onion_service_guard alive for the session lifetime — dropping it
    // de-registers the service from the Tor network (fix T-3).
    let (onion_service_guard, rend_requests) = tor_client
        .launch_onion_service(svc_config)?
        .ok_or("Tor: onion service returned None (should not happen with in-code config)")?;

    let hsid = onion_service_guard
        .onion_address()
        .ok_or("Tor: onion address not yet available (key generation incomplete)")?;
    let onion_name = hsid_to_onion_address(hsid);
    let stream_requests = Box::pin(handle_rend_requests(rend_requests));

    Ok(Some(TorSession {
        _onion_service_guard: onion_service_guard,
        stream_requests,
        onion_name,
    }))
}

/// Run the full Tor lifecycle (bootstrap → launch service → proxy streams).
///
/// Returns:
/// - `Ok(false)` — shutdown signal received; caller should exit.
/// - `Ok(true)`  — stream ended unexpectedly; caller should retry.
/// - `Err(e)`    — unrecoverable error; caller should set `Failed` and exit.
async fn run(
    data_dir: PathBuf,
    bind_port: u16,
    bind_addr: IpAddr,
    max_connections: usize,
    state: SharedState,
    mut shutdown: watch::Receiver<bool>,
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
    set_status(&state, TorStatus::Starting).await;

    let Some(TorSession {
        _onion_service_guard,
        mut stream_requests,
        onion_name,
    }) = bootstrap_and_launch(&data_dir, shutdown.clone()).await?
    else {
        return Ok(false); // clean shutdown during bootstrap
    };

    // Phase 2 (H-6) — log only the first 12 characters of the onion host.
    let display_prefix = onion_name
        .strip_suffix(".onion")
        .and_then(|host| host.get(..12))
        .unwrap_or(&onion_name);

    log::info!(
        "\n  ╔═══════════════════════════════════════════════════╗\n  \
           ║   TOR ONION SERVICE ACTIVE                        ║\n  \
           ╠═══════════════════════════════════════════════════╣\n  \
           ║   {display_prefix}….onion (full address in dashboard)  ║\n  \
           ╚═══════════════════════════════════════════════════╝"
    );
    log::info!(
        "Tor onion service active: {display_prefix}….onion (full address visible in dashboard)"
    );

    set_onion(&state, onion_name).await;

    // Size the Tor semaphore to match the HTTP server's connection limit (fix T-2).
    let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(max_connections));

    loop {
        tokio::select! {
            next = stream_requests.next() => {
                if let Some(stream_req) = next {
                    let local_addr = format_local_addr(bind_addr, bind_port);
                    let Ok(permit) = std::sync::Arc::clone(&semaphore).try_acquire_owned() else {
                        log::warn!("Tor: at capacity ({max_connections}), dropping stream");
                        drop(stream_req);
                        continue;
                    };
                    tokio::spawn(async move {
                        let _permit = permit;
                        if let Err(e) = proxy_stream(stream_req, &local_addr).await {
                            log::debug!("Tor: stream closed: {e}");
                        }
                    });
                } else {
                    log::warn!("Tor: stream_requests stream ended — will attempt re-bootstrap");
                    state.write().await.onion_address = None;
                    return Ok(true); // signal: retry
                }
            }
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    log::info!("Tor: shutdown signal received — stopping stream loop");
                    semaphore.close();
                    break;
                }
            }
        }
    }

    state.write().await.onion_address = None;
    Ok(false) // signal: do not retry
}

// ─── Stream proxying ─────────────────────────────────────────────────────────

/// Accept one `StreamRequest` and proxy it bidirectionally to the local HTTP
/// server.
///
/// `stream_req.accept(Connected::new_empty())` sends back the `RELAY_CONNECTED`
/// cell to the client (indicating the connection succeeded) and returns the
/// `DataStream` we then bridge to our local HTTP server.
///
/// `Connected::new_empty()` is the correct form for hidden services: we don't
/// report an exit IP to the client (there isn't one — we're the service).
///
/// `DataStream` implements `tokio::io::AsyncRead + AsyncWrite` when the
/// `tokio` feature is enabled on `arti-client`, so `copy_bidirectional`
/// works with no adapter needed.
///
/// fix 3.1 — both the local connect and the bidirectional copy are wrapped in
/// timeouts to prevent stalled connections from holding semaphore permits
/// indefinitely and exhausting the connection pool.
async fn proxy_stream(
    stream_req: StreamRequest,
    local_addr: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut tor_stream = stream_req.accept(Connected::new_empty()).await?;

    // fix 3.1a — bound the time spent waiting for the local server to accept.
    // If the HTTP server is wedged or still starting, we release the permit
    // quickly rather than holding it until the OS TCP timeout fires.
    let mut local = tokio::time::timeout(LOCAL_CONNECT_TIMEOUT, TcpStream::connect(local_addr))
        .await
        .map_err(|_| {
            format!(
                "timed out connecting to local server at {local_addr} \
                 after {}s",
                LOCAL_CONNECT_TIMEOUT.as_secs()
            )
        })?
        .map_err(|e| format!("local connect to {local_addr} failed: {e}"))?;

    // fix T-6 — idle timeout instead of wall-clock cap (see copy_with_idle_timeout)
    copy_with_idle_timeout(&mut tor_stream, &mut local)
        .await
        .map_err(|e| format!("stream proxy error: {e}"))?;

    Ok(())
}

/// Proxy bytes between `a` and `b` bidirectionally.
///
/// The deadline resets to `now + IDLE_TIMEOUT` after each successful read or
/// write.  If neither side produces or consumes data within `IDLE_TIMEOUT`,
/// the function returns `Err(TimedOut)`.
///
/// This is a true idle timeout, not a wall-clock cap.  A continuous large
/// transfer is never interrupted; a connection that stalls mid-transfer is
/// closed within `IDLE_TIMEOUT` of the last byte.  The previous
/// implementation used `copy_bidirectional` racing a single `sleep`, which
/// fired `IDLE_TIMEOUT` after the *connection opened*, disconnecting active
/// large downloads (fix C-2).
async fn copy_with_idle_timeout<A, B>(a: &mut A, b: &mut B) -> std::io::Result<()>
where
    A: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    B: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut buf_a = vec![0u8; 8_192];
    let mut buf_b = vec![0u8; 8_192];

    loop {
        // Deadline resets on every iteration — after every successful read/write.
        // checked_add avoids clippy::arithmetic_side_effects; the fallback to
        // now() causes an immediate timeout rather than a panic on overflow
        // (practically impossible, but required by pedantic lints).
        let deadline = tokio::time::Instant::now()
            .checked_add(IDLE_TIMEOUT)
            .unwrap_or_else(tokio::time::Instant::now);

        tokio::select! {
            // A → B
            result = tokio::time::timeout_at(deadline, a.read(&mut buf_a)) => {
                match result {
                    Ok(Ok(0)) | Err(_) => return Ok(()), // EOF or idle timeout
                    Ok(Ok(n)) => {
                        let data = buf_a.get(..n).ok_or_else(|| {
                            std::io::Error::other("read returned out-of-bounds n")
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
                            std::io::Error::other("read returned out-of-bounds n")
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

// ─── Onion address encoding ───────────────────────────────────────────────────

/// Encode an `HsId` (ed25519 public key) as a v3 `.onion` domain name.
///
/// Delegates to [`onion_address_from_pubkey`] which is separately unit-tested.
fn hsid_to_onion_address(hsid: HsId) -> String {
    onion_address_from_pubkey(hsid.as_ref())
}

/// Encode a raw 32-byte ed25519 public key as a v3 `.onion` domain name.
///
/// Implements the encoding defined in the Tor Rendezvous Specification:
///
/// ```text
/// onion_address = base32(PUBKEY | CHECKSUM | VERSION) + ".onion"
/// CHECKSUM      = SHA3-256(".onion checksum" | PUBKEY | VERSION)[:2]
/// VERSION       = 0x03
/// ```
///
/// The output is always exactly 62 characters: 56 lowercase base32 characters
/// followed by `".onion"`.
///
/// Separated from [`hsid_to_onion_address`] so that tests can supply an
/// arbitrary 32-byte key without constructing an `HsId`.
#[must_use]
pub(crate) fn onion_address_from_pubkey(pubkey: &[u8; 32]) -> String {
    use sha3::{Digest, Sha3_256};

    let version: u8 = 3;

    // CHECKSUM = SHA3-256(".onion checksum" || PUBKEY || VERSION) truncated to 2 bytes
    let mut hasher = Sha3_256::new();
    hasher.update(b".onion checksum");
    hasher.update(pubkey);
    hasher.update([version]);
    let hash = hasher.finalize();

    // ADDRESS_BYTES = PUBKEY (32) || CHECKSUM (2) || VERSION (1) = 35 bytes
    let mut address_bytes = [0u8; 35];
    address_bytes[..32].copy_from_slice(pubkey);

    // fix 3.8 — index hash directly rather than via a fallible iterator.
    // SHA3-256 always produces exactly 32 bytes; the GenericArray is
    // guaranteed to have indices 0 and 1.  The `indexing_slicing` lint
    // fires here because clippy cannot prove the length at compile time for
    // GenericArray, so we suppress it with a targeted allow.
    #[allow(clippy::indexing_slicing)]
    {
        address_bytes[32] = hash[0];
        address_bytes[33] = hash[1];
    }
    address_bytes[34] = version;

    // RFC 4648 base32, no padding, lowercase → 56 characters
    let encoded = data_encoding::BASE32_NOPAD
        .encode(&address_bytes)
        .to_ascii_lowercase();

    format!("{encoded}.onion")
}

// ─── Backoff helper ───────────────────────────────────────────────────────────

/// Compute the exponential backoff delay for attempt `n` (1-indexed).
///
/// Formula: `base * 2^(n-1)`, capped at `max_secs`.
/// ```text
/// Attempt 1 →  30 s
/// Attempt 2 →  60 s
/// Attempt 3 → 120 s
/// Attempt 4 → 240 s
/// Attempt 5 → 300 s (capped)
/// ```
///
/// Uses saturating arithmetic throughout so extreme values of `attempt` do not
/// panic under `clippy::pedantic`.
fn backoff_delay(attempt: u32, base_secs: u64, max_secs: u64) -> Duration {
    // Attempt 0 means "no previous failures" — no delay.
    let Some(exp) = attempt.checked_sub(1) else {
        return Duration::ZERO;
    };
    // `checked_shl` returns None when the shift count is >= 64; cap at 63 so
    // we always get a valid power-of-two.  Any exponent >= 63 already exceeds
    // `max_secs` after the multiply, so the `.min(max_secs)` cap handles it.
    let multiplier = 1u64.checked_shl(exp.min(63)).unwrap_or(u64::MAX);
    let secs = base_secs.saturating_mul(multiplier);
    Duration::from_secs(secs.min(max_secs))
}

// ─── State helpers ────────────────────────────────────────────────────────────
//
// These must appear BEFORE the #[cfg(test)] module; items after a test module
// trigger the `clippy::items_after_test_module` lint.

/// Format a bind address as a valid socket-address string (fix T-1).
/// IPv6 addresses need square brackets: `[::1]:8080`, not `::1:8080`.
fn format_local_addr(addr: IpAddr, port: u16) -> String {
    match addr {
        IpAddr::V4(a) => format!("{a}:{port}"),
        IpAddr::V6(a) => format!("[{a}]:{port}"),
    }
}

/// Create a directory that is readable only by the current user (fix T-7, H-4).
///
/// On Unix this applies mode 0o700 (owner rwx, no group/other access).
/// On Windows this shells out to `icacls` to apply a DACL that grants Full
/// Control only to the current user, removing all inherited permissions.
/// Using `icacls` avoids pulling in the `windows` crate for this single call;
/// it is available on all Windows versions since Vista.
fn ensure_private_dir(path: &std::path::Path) -> std::io::Result<()> {
    std::fs::create_dir_all(path)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }

    #[cfg(windows)]
    {
        // Determine the current user via `whoami` so the DACL grant is
        // user-specific.  `icacls /inheritance:r` removes inherited ACEs from
        // parent directories so the directory is not readable by Administrators
        // or other groups through inheritance.
        let whoami_out = std::process::Command::new("whoami").output()?;
        let user = String::from_utf8_lossy(&whoami_out.stdout)
            .trim()
            .to_owned();
        let path_str = path.to_string_lossy();
        std::process::Command::new("icacls")
            .args([
                path_str.as_ref(),
                "/inheritance:r", // remove inherited permissions
                "/grant:r",
                &format!("{user}:(OI)(CI)F"), // Full Control (recursive)
            ])
            .output()?;
    }

    Ok(())
}

async fn set_status(state: &SharedState, status: TorStatus) {
    state.write().await.tor_status = status;
}

async fn set_onion(state: &SharedState, addr: String) {
    let mut s = state.write().await;
    s.tor_status = TorStatus::Ready;
    s.onion_address = Some(addr);
}

// ─── Unit tests ───────────────────────────────────────────────────────────────

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
    fn attempt_3_doubles_again() {
        assert_eq!(backoff_delay(3, 30, 300), Duration::from_secs(120));
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

#[cfg(test)]
mod tests {
    use super::onion_address_from_pubkey;

    /// External test vector for the all-zero 32-byte Ed25519 public key.
    ///
    /// Computed independently with Python's standard library (no `stem` needed):
    ///
    /// ```python
    /// import hashlib, base64
    /// pk  = bytes(32)          # all-zero 32-byte Ed25519 public key
    /// ver = b'\x03'
    /// chk = hashlib.sha3_256(b'.onion checksum' + pk + ver).digest()[:2]
    /// addr = base64.b32encode(pk + chk + ver).decode().lower() + '.onion'
    /// # → 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaam2dqd.onion'
    /// ```
    ///
    /// This cross-checks the production implementation against an *independent*
    /// reference rather than the same algorithm re-implemented inline (fix C-3).
    const ZERO_KEY_ONION: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaam2dqd.onion";

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
        let host = addr.strip_suffix(".onion").unwrap_or(&addr);
        assert!(
            host.chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()),
            "host contains non-base32 characters: {host:?}"
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
