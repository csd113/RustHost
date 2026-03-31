//! # Tor Module — Arti (in-process)
//!
//! **File:** `mod.rs`
//! **Location:** `src/tor/mod.rs`
//!
//! Replaces the old subprocess + torrc approach with Arti, the official
//! Tor implementation in Rust, running entirely in-process.
//!
//! ## Flow
//!
//! 1. `init()` spawns a Tokio task and returns its `JoinHandle`.
//! 2. `TorClient::create_bootstrapped()` connects to the Tor network.
//! 3. `launch_onion_service()` registers the hidden service.
//! 4. Incoming `RendRequest`s are converted into `StreamRequest`s.
//! 5. Each `StreamRequest` is proxied to the local HTTP server.
//! 6. If the request stream ends unexpectedly, the module re-bootstraps
//!    with exponential backoff.
//!
//! ## Security note on state/cache directory creation
//!
//! `ensure_private_dir()` hardens permissions and rejects obvious symlinks,
//! but directory creation and post-creation verification are not fully atomic
//! with only the Rust standard library. On hostile multi-user systems, a local
//! attacker who can race filesystem operations may still be able to swap paths
//! between checks. For Tor state material this is a real concern.
//!
//! For strongest protection, use platform-native secure directory creation APIs
//! (`openat`-style directory traversal on Linux, `SetNamedSecurityInfoW` via
//! `windows-sys` on Windows) or run the service as a dedicated user account
//! with a private home directory.

mod fs;

use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use arti_client::config::TorClientConfigBuilder;
use arti_client::TorClient;
use futures::StreamExt;
use tokio::{
    net::TcpStream,
    sync::watch,
    task::{JoinHandle, JoinSet},
};
use tor_cell::relaycell::msg::Connected;
use tor_hsservice::{config::OnionServiceConfigBuilder, handle_rend_requests, HsId, StreamRequest};

use crate::runtime::state::{SharedState, TorStatus};
use fs::ensure_private_dir;

// ─── Timeout / retry constants ────────────────────────────────────────────────

const BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(120);
const LOCAL_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const SHUTDOWN_DRAIN_TIMEOUT: Duration = Duration::from_secs(10);
const RECONNECT_DRAIN_TIMEOUT: Duration = Duration::from_secs(10);
const RETRY_BASE_SECS: u64 = 30;
const RETRY_MAX_SECS: u64 = 300;
const MAX_RETRIES: u32 = 5;
const TOR_RELAY_BUFFER_BYTES: usize = 32 * 1024;

// ─── Public entry point ───────────────────────────────────────────────────────

pub fn init(
    data_dir: PathBuf,
    bind_port: u16,
    bind_addr: IpAddr,
    max_connections: usize,
    state: SharedState,
    shutdown: watch::Receiver<bool>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        if max_connections == 0 {
            let msg = "Tor: max_connections must be >= 1".to_string();
            log::error!("{msg}");
            set_failed_and_clear_onion(&state, msg).await;
            return;
        }

        let mut attempts = 0u32;
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
                    log::info!("Tor: task exiting cleanly.");
                    break;
                }
                Ok(true) => {
                    let now = std::time::Instant::now();
                    if let Some(last) = last_failure_time {
                        if now.duration_since(last) > Duration::from_secs(3600) {
                            log::info!(
                                "Tor: resetting retry counter — last disruption was over an hour ago."
                            );
                            attempts = 0;
                        }
                    }
                    last_failure_time = Some(now);

                    attempts = attempts.saturating_add(1);
                    if attempts > MAX_RETRIES {
                        log::error!(
                            "Tor: stream ended too many consecutive times; giving up after \
                             {attempts} attempts."
                        );
                        set_failed_and_clear_onion(&state, "too many reconnect attempts".into())
                            .await;
                        break;
                    }

                    let delay = backoff_delay(attempts, RETRY_BASE_SECS, RETRY_MAX_SECS);
                    log::warn!(
                        "Tor: stream ended; re-bootstrapping in {delay:?} \
                         (attempt {attempts}/{MAX_RETRIES})"
                    );

                    // Show Starting state *during* the backoff sleep so the UI
                    // reflects that we are actively retrying. run() also calls
                    // this at its top, which is a benign no-op double-set.
                    set_starting_and_clear_onion(&state).await;

                    let mut backoff_shutdown = shutdown.clone();
                    tokio::select! {
                        () = tokio::time::sleep(delay) => {}
                        () = wait_for_shutdown_signal(&mut backoff_shutdown) => {
                            log::info!("Tor: shutdown during backoff — exiting.");
                            break;
                        }
                    }
                }
                Err(e) => {
                    // {e:#} prints the full anyhow chain (source causes included).
                    log::error!("Tor: fatal error: {e:#}");
                    set_failed_and_clear_onion(&state, format!("{e:#}")).await;
                    break;
                }
            }
        }
    })
}

// ─── Core async logic ─────────────────────────────────────────────────────────

struct TorSession {
    /// Must be kept alive for the session lifetime — dropping it de-registers
    /// the onion service from the Tor network.
    onion_service_guard: Arc<tor_hsservice::RunningOnionService>,
    stream_requests: futures::stream::BoxStream<'static, StreamRequest>,
    onion_name: String,
}

async fn bootstrap_and_launch(
    data_dir: &std::path::Path,
    shutdown: watch::Receiver<bool>,
) -> anyhow::Result<Option<TorSession>> {
    ensure_private_dir(&data_dir.join("arti_state"))
        .context("cannot create secure Tor state directory")?;
    ensure_private_dir(&data_dir.join("arti_cache"))
        .context("cannot create secure Tor cache directory")?;

    let config = TorClientConfigBuilder::from_directories(
        data_dir.join("arti_state"),
        data_dir.join("arti_cache"),
    )
    .build()
    .context("failed to build Tor client configuration")?;

    log::info!("Tor: bootstrapping — first run downloads ~2 MB of directory data (~30 s)");

    let tor_client = {
        let mut sd = shutdown.clone();
        tokio::select! {
            result = tokio::time::timeout(
                BOOTSTRAP_TIMEOUT,
                TorClient::create_bootstrapped(config)
            ) => {
                result
                    .map_err(|_| anyhow::anyhow!(
                        "Tor bootstrap timed out after {}s — check network connectivity",
                        BOOTSTRAP_TIMEOUT.as_secs()
                    ))?
                    .context("Tor bootstrap failed")?
            }
            () = wait_for_shutdown_signal(&mut sd) => {
                log::info!("Tor: shutdown received during bootstrap — exiting.");
                return Ok(None);
            }
        }
    };

    log::info!("Tor: connected to the Tor network");

    let svc_config = OnionServiceConfigBuilder::default()
        .nickname(
            "rusthost"
                .parse()
                .context("invalid onion service nickname")?,
        )
        .build()
        .context("failed to build onion service configuration")?;

    let launched = tor_client
        .launch_onion_service(svc_config)
        .context("failed to launch onion service")?;
    let Some((onion_service_guard, rend_requests)) = launched else {
        anyhow::bail!("Tor: onion service returned None — possible key generation failure");
    };

    let hsid = onion_service_guard.onion_address().ok_or_else(|| {
        anyhow::anyhow!("Tor: onion address not yet available (key generation incomplete)")
    })?;
    let onion_name = hsid_to_onion_address(hsid);
    let stream_requests = Box::pin(handle_rend_requests(rend_requests));

    Ok(Some(TorSession {
        onion_service_guard,
        stream_requests,
        onion_name,
    }))
}

async fn run(
    data_dir: PathBuf,
    bind_port: u16,
    bind_addr: IpAddr,
    max_connections: usize,
    state: SharedState,
    shutdown: watch::Receiver<bool>,
) -> anyhow::Result<bool> {
    // The init() loop also sets this during backoff so the UI reflects that a
    // reconnect is already underway while the retry delay is running.
    set_starting_and_clear_onion(&state).await;

    let Some(session) = bootstrap_and_launch(&data_dir, shutdown.clone()).await? else {
        return Ok(false);
    };

    log_onion_banner(&session.onion_name);
    set_onion(&state, session.onion_name.clone()).await;

    let local_addr = format_local_addr(bind_addr, bind_port);
    process_streams(session, local_addr, max_connections, state, shutdown).await
}

fn log_onion_banner(onion_name: &str) {
    // Fall back to the stripped *host* portion, not the full "host.onion"
    // string. If .onion is absent, use the raw name. If the host is shorter
    // than 12 chars, show all of it.
    let display_prefix = onion_name
        .strip_suffix(".onion")
        .map_or(onion_name, |host| host.get(..12).unwrap_or(host));

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
    log::info!("Tor onion service address: {onion_name}");
}

async fn process_streams(
    session: TorSession,
    local_addr: String,
    max_connections: usize,
    state: SharedState,
    mut shutdown: watch::Receiver<bool>,
) -> anyhow::Result<bool> {
    let TorSession {
        onion_service_guard,
        mut stream_requests,
        onion_name: _,
    } = session;

    let _keep_onion_service_alive = onion_service_guard;
    let semaphore = Arc::new(tokio::sync::Semaphore::new(max_connections));
    let mut active_tasks = JoinSet::new();

    loop {
        tokio::select! {
            next = stream_requests.next() => {
                if let Some(stream_req) = next {
                    handle_stream_request(
                        stream_req,
                        &local_addr,
                        max_connections,
                        &semaphore,
                        &mut active_tasks,
                    );
                } else {
                    // Close the semaphore BEFORE draining so no new
                    // acquisitions can succeed during the drain window.
                    semaphore.close();
                    return reconnect_after_stream_end(&state, &mut active_tasks).await;
                }
            }

            Some(result) = active_tasks.join_next(), if !active_tasks.is_empty() => {
                if let Err(e) = result {
                    log::debug!("Tor: stream task error: {e}");
                }
            }

            () = wait_for_shutdown_signal(&mut shutdown) => {
                log::info!("Tor: shutdown signal received — stopping stream loop");
                semaphore.close();
                drain_tasks_with_timeout(
                    &mut active_tasks,
                    SHUTDOWN_DRAIN_TIMEOUT,
                    "shutdown",
                )
                .await;
                break;
            }
        }
    }

    clear_onion_only(&state).await;
    Ok(false)
}

fn handle_stream_request(
    stream_req: StreamRequest,
    local_addr: &str,
    max_connections: usize,
    semaphore: &Arc<tokio::sync::Semaphore>,
    active_tasks: &mut JoinSet<()>,
) {
    let Ok(permit) = Arc::clone(semaphore).try_acquire_owned() else {
        log::warn!("Tor: at capacity ({max_connections}), dropping stream");
        drop(stream_req);
        return;
    };

    let local_addr = local_addr.to_owned();
    active_tasks.spawn(async move {
        let _permit = permit;
        if let Err(e) = Box::pin(proxy_stream(stream_req, &local_addr)).await {
            log::debug!("Tor: stream closed: {e:#}");
        }
    });
}

async fn reconnect_after_stream_end(
    _state: &SharedState,
    active_tasks: &mut JoinSet<()>,
) -> anyhow::Result<bool> {
    log::warn!("Tor: stream_requests stream ended — will attempt re-bootstrap");
    drain_tasks_with_timeout(active_tasks, RECONNECT_DRAIN_TIMEOUT, "reconnect").await;
    // Signal the init() loop to re-bootstrap (Ok(true) = retry).
    // set_starting_and_clear_onion is NOT called here — run() handles it.
    Ok(true)
}

async fn drain_tasks_with_timeout(active_tasks: &mut JoinSet<()>, timeout: Duration, phase: &str) {
    // If checked_add overflows (impossible for the short timeouts used in
    // practice), fall back to `now` so the sleep fires immediately and tasks
    // are aborted rather than waited on indefinitely.
    let now = tokio::time::Instant::now();
    let deadline = now.checked_add(timeout).unwrap_or(now);

    loop {
        tokio::select! {
            joined = active_tasks.join_next() => {
                match joined {
                    Some(Ok(())) => {}
                    Some(Err(e)) => {
                        log::debug!("Tor: stream task join error during {phase}: {e}");
                    }
                    None => break,
                }
            }
            () = tokio::time::sleep_until(deadline) => {
                log::warn!(
                    "Tor: timed out waiting for active stream tasks during {phase}"
                );
                active_tasks.abort_all();
                while let Some(joined) = active_tasks.join_next().await {
                    if let Err(e) = joined {
                        log::debug!(
                            "Tor: aborted stream task join error during {phase}: {e}"
                        );
                    }
                }
                break;
            }
        }
    }
}

// ─── Stream proxying ─────────────────────────────────────────────────────────

async fn proxy_stream(stream_req: StreamRequest, local_addr: &str) -> anyhow::Result<()> {
    // Attempt the local TCP connection BEFORE accepting the Tor stream.
    //
    // On failure the StreamRequest must be explicitly dropped so that Arti
    // sends a RELAY_END cell to the remote Tor client. Silently returning
    // with stream_req still live relies on an undocumented drop-time side
    // effect and leaves the client hanging until its own circuit timeout.
    //
    // NOTE: if a future arti release stabilises StreamRequest::reject() with
    // an explicit EndReason, prefer it over drop() here to send a typed error
    // code (e.g. EXITPOLICY for refused, TIMEOUT for timed-out connections).
    let local_result =
        tokio::time::timeout(LOCAL_CONNECT_TIMEOUT, TcpStream::connect(local_addr)).await;

    let local = match local_result {
        Ok(Ok(stream)) => stream,
        Ok(Err(e)) => {
            // drop(stream_req) sends RELAY_END to the Tor client.
            drop(stream_req);
            return Err(
                anyhow::Error::new(e).context(format!("local connect to {local_addr} failed"))
            );
        }
        Err(_elapsed) => {
            drop(stream_req);
            anyhow::bail!(
                "timed out connecting to local server at {local_addr} after {}s",
                LOCAL_CONNECT_TIMEOUT.as_secs()
            );
        }
    };
    if let Err(e) = local.set_nodelay(true) {
        log::debug!("Tor: could not enable TCP_NODELAY on local proxy socket: {e}");
    }

    let tor_stream = stream_req
        .accept(Connected::new_empty())
        .await
        .context("failed to accept Tor stream")?;

    Box::pin(proxy_bidirectional_with_idle_timeout(
        tor_stream,
        local,
        IDLE_TIMEOUT,
    ))
    .await
    .context("bidirectional proxy error")?;
    Ok(())
}

async fn proxy_bidirectional_with_idle_timeout<A, B>(
    stream_a: A,
    stream_b: B,
    idle_timeout: Duration,
) -> std::io::Result<()>
where
    A: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    B: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (reader_a, writer_a) = tokio::io::split(stream_a);
    let (reader_b, writer_b) = tokio::io::split(stream_b);

    let client_to_local = relay_with_idle_timeout(reader_a, writer_b, idle_timeout);
    let local_to_client = relay_with_idle_timeout(reader_b, writer_a, idle_timeout);

    let (_uplink, _downlink) = tokio::try_join!(client_to_local, local_to_client)?;
    Ok(())
}

async fn relay_with_idle_timeout<R, W>(
    mut reader: R,
    mut writer: W,
    idle_timeout: Duration,
) -> std::io::Result<u64>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let mut transferred = 0u64;
    let mut buffer = vec![0u8; TOR_RELAY_BUFFER_BYTES].into_boxed_slice();

    loop {
        let read = tokio::time::timeout(
            idle_timeout,
            tokio::io::AsyncReadExt::read(&mut reader, &mut buffer),
        )
        .await
        .map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("stream idle timeout after {}s", idle_timeout.as_secs()),
            )
        })??;

        if read == 0 {
            tokio::io::AsyncWriteExt::shutdown(&mut writer).await?;
            return Ok(transferred);
        }

        tokio::io::AsyncWriteExt::write_all(&mut writer, &buffer[..read]).await?;
        transferred = transferred.saturating_add(u64::try_from(read).unwrap_or(u64::MAX));
    }
}

// ─── Onion address encoding ───────────────────────────────────────────────────

fn hsid_to_onion_address(hsid: HsId) -> String {
    onion_address_from_pubkey(hsid.as_ref())
}

#[must_use]
pub fn onion_address_from_pubkey(pubkey: &[u8; 32]) -> String {
    use sha3::{Digest, Sha3_256};

    let version: u8 = 3;

    let mut hasher = Sha3_256::new();
    hasher.update(b".onion checksum");
    hasher.update(pubkey);
    hasher.update([version]);
    let hash = hasher.finalize();

    // All indices are provably in-bounds at compile time:
    //   address_bytes: [0u8; 35]  — indices 32, 33, 34 are valid.
    //   hash: GenericArray<u8, U32> — indices 0, 1 are valid.
    #[allow(clippy::indexing_slicing)]
    {
        let mut address_bytes = [0u8; 35];
        address_bytes[..32].copy_from_slice(pubkey);
        address_bytes[32] = hash[0];
        address_bytes[33] = hash[1];
        address_bytes[34] = version;

        let encoded = data_encoding::BASE32_NOPAD
            .encode(&address_bytes)
            .to_ascii_lowercase();

        format!("{encoded}.onion")
    }
}

// ─── Backoff helper ───────────────────────────────────────────────────────────

fn backoff_delay(attempt: u32, base_secs: u64, max_secs: u64) -> Duration {
    let Some(exp) = attempt.checked_sub(1) else {
        return Duration::ZERO;
    };

    let multiplier = 1u64 << exp.min(63); // exp ≤ 63, shift is always valid
    let secs = base_secs.saturating_mul(multiplier);
    Duration::from_secs(secs.min(max_secs))
}

// ─── State / shutdown / filesystem helpers ────────────────────────────────────

fn format_local_addr(addr: IpAddr, port: u16) -> String {
    match addr {
        IpAddr::V4(a) if a.is_unspecified() => format!("127.0.0.1:{port}"),
        IpAddr::V4(a) => format!("{a}:{port}"),
        IpAddr::V6(a) if a.is_unspecified() => format!("[::1]:{port}"),
        IpAddr::V6(a) => format!("[{a}]:{port}"),
    }
}

/// Wait until the shutdown channel carries `true` or the sender is dropped.
///
/// ## Why `wait_for` and not `changed`
///
/// `changed()` blocks until the value *changes relative to the receiver's
/// last-seen mark*. That has two failure modes:
///
/// 1. **Pre-set signal**: if the sender already wrote `true` before this call,
///    `changed()` blocks forever waiting for a *subsequent* mutation; the
///    shutdown is silently missed.
///
/// 2. **Sender drop**: `changed()` returns `Err(RecvError)` when the sender
///    is dropped, which should also be treated as a stop signal.
///
/// `wait_for(|&v| v)` returns immediately if the current value is already
/// `true` (no missed pre-set), and returns `Err(RecvError)` on sender drop
/// (which we discard intentionally — both outcomes mean "stop").
async fn wait_for_shutdown_signal(shutdown: &mut watch::Receiver<bool>) {
    // Discard Ok(()) (value became true) and Err(RecvError) (sender dropped)
    // — both indicate the task should stop.
    let _ = shutdown.wait_for(|&v| v).await;
}

async fn set_onion(state: &SharedState, addr: String) {
    let mut s = state.write().await;
    s.tor_status = TorStatus::Ready;
    s.onion_address = Some(addr);
}

async fn set_starting_and_clear_onion(state: &SharedState) {
    let mut s = state.write().await;
    s.tor_status = TorStatus::Starting;
    s.onion_address = None;
}

async fn set_failed_and_clear_onion(state: &SharedState, msg: String) {
    let mut s = state.write().await;
    s.tor_status = TorStatus::Failed(msg);
    s.onion_address = None;
}

async fn clear_onion_only(state: &SharedState) {
    state.write().await.onion_address = None;
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
    use super::{format_local_addr, onion_address_from_pubkey};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    const ZERO_KEY_ONION: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaam2dqd.onion";

    #[test]
    fn known_vector_all_zeros() {
        assert_eq!(onion_address_from_pubkey(&[0u8; 32]), ZERO_KEY_ONION);
    }

    #[test]
    fn format_is_56_chars_plus_dot_onion() {
        let addr = onion_address_from_pubkey(&[0u8; 32]);
        assert_eq!(addr.len(), 62);
        assert!(
            addr.strip_suffix(".onion").is_some(),
            "onion address always ends with '.onion'"
        );
        let host = addr.strip_suffix(".onion").unwrap_or("");
        assert!(host
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()));
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

    #[test]
    fn unspecified_ipv4_formats_as_loopback_for_local_proxying() {
        assert_eq!(
            format_local_addr(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 8080),
            "127.0.0.1:8080"
        );
    }

    #[test]
    fn unspecified_ipv6_formats_as_loopback_for_local_proxying() {
        assert_eq!(
            format_local_addr(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 8080),
            "[::1]:8080"
        );
    }
}
