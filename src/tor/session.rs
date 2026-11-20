//! Arti bootstrap, onion identity, and session supervision.

use std::{net::IpAddr, path::PathBuf, sync::Arc, time::Duration};

use anyhow::Context as _;
use arti_client::{config::TorClientConfigBuilder, TorClient};
use tokio::{sync::watch, task::JoinHandle};
use tor_hsservice::{config::OnionServiceConfigBuilder, handle_rend_requests, HsId, StreamRequest};
use tor_rtcompat::PreferredRuntime;

use super::{relay::process_streams, state_dirs::ensure_private_dir};
use crate::runtime::state::{SharedState, TorStatus};

const BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(120);
const RETRY_BASE_SECS: u64 = 30;
const RETRY_MAX_SECS: u64 = 300;
const MAX_RETRIES: u32 = 5;

type SharedTorClient = Arc<TorClient<PreferredRuntime>>;

fn format_startup_failure(err: &anyhow::Error) -> String {
    let detail = format!("{err:#}");
    if detail.contains("refusing to use symlink in private directory path") {
        return "Tor onion service did not start: secure Tor state directory check failed because the path contains a symlink. HTTP/HTTPS serving will continue. Use a non-symlinked data directory or configure a suitable Tor state directory; set tor.enabled=false to disable onion support.".to_owned();
    }
    format!("Tor onion service did not start: {detail}. HTTP/HTTPS serving will continue.")
}

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
            let msg = "Tor: max_connections must be >= 1".to_owned();
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
                Arc::clone(&state),
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
                    let message = format_startup_failure(&e);
                    log::warn!("{message}");
                    set_failed_and_clear_onion(&state, message).await;
                    break;
                }
            }
        }
    })
}

// ─── Core async logic ─────────────────────────────────────────────────────────

pub(super) struct TorSession {
    /// Kept alive with the onion service so Arti client ownership remains
    /// explicit when the client is shared internally by Arti components.
    pub(super) tor_client: SharedTorClient,
    /// Must be kept alive for the session lifetime — dropping it de-registers
    /// the onion service from the Tor network.
    pub(super) onion_service_guard: Arc<tor_hsservice::RunningOnionService>,
    pub(super) stream_requests: futures::stream::BoxStream<'static, StreamRequest>,
    pub(super) onion_name: String,
}

async fn bootstrap_and_launch(
    data_dir: &std::path::Path,
    shutdown: watch::Receiver<bool>,
) -> anyhow::Result<Option<TorSession>> {
    ensure_private_dir(&data_dir.join("runtime/tor/arti_state"))
        .context("cannot create secure Tor state directory")?;
    ensure_private_dir(&data_dir.join("runtime/tor/arti_cache"))
        .context("cannot create secure Tor cache directory")?;

    let config = TorClientConfigBuilder::from_directories(
        data_dir.join("runtime/tor/arti_state"),
        data_dir.join("runtime/tor/arti_cache"),
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
                    .map_err(|_elapsed| anyhow::anyhow!(
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
        tor_client,
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
        "Tor onion service active: {display_prefix}….onion (full address visible in dashboard)"
    );
    log::info!("Tor onion service address: {onion_name}");
}

// ─── Onion address encoding ───────────────────────────────────────────────────

fn hsid_to_onion_address(hsid: HsId) -> String {
    onion_address_from_pubkey(hsid.as_ref())
}

#[must_use]
pub fn onion_address_from_pubkey(pubkey: &[u8; 32]) -> String {
    use sha3::{Digest as _, Sha3_256};

    let version: u8 = 3;

    let mut hasher = Sha3_256::new();
    hasher.update(b".onion checksum");
    hasher.update(pubkey);
    hasher.update([version]);
    let hash = hasher.finalize();

    // All indices are provably in-bounds at compile time:
    //   address_bytes: [0u8; 35]  — indices 32, 33, 34 are valid.
    //   hash: GenericArray<u8, U32> — indices 0, 1 are valid.
    let checksum = hash
        .get(..2)
        .ok_or(())
        .and_then(|bytes| <[u8; 2]>::try_from(bytes).map_err(|_invalid_len| ()))
        .unwrap_or([0, 0]);
    let mut address_bytes = [0u8; 35];
    address_bytes[..32].copy_from_slice(pubkey);
    address_bytes[32..34].copy_from_slice(&checksum);
    address_bytes[34] = version;

    let encoded = data_encoding::BASE32_NOPAD
        .encode(&address_bytes)
        .to_ascii_lowercase();

    format!("{encoded}.onion")
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
pub(super) async fn wait_for_shutdown_signal(shutdown: &mut watch::Receiver<bool>) {
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

pub(super) async fn clear_onion_only(state: &SharedState) {
    state.write().await.onion_address = None;
}
