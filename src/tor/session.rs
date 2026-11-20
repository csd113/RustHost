//! Arti bootstrap, onion identity, and session supervision.

use std::{
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

use anyhow::Context as _;
use arti_client::{config::TorClientConfigBuilder, TorClient};
use tokio::{sync::watch, task::JoinHandle};
use tor_hsservice::{config::OnionServiceConfigBuilder, handle_rend_requests, HsId, StreamRequest};
use tor_rtcompat::PreferredRuntime;

use super::{
    relay::{Relay, RelayEnd},
    state_dirs::ensure_private_dir,
};
use crate::runtime::{
    shutdown::{deadline, ServiceOutcome, Shutdown},
    state::{SharedState, TorStatus},
};

const BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(120);
const RETRY_BASE_SECS: u64 = 30;
const RETRY_MAX_SECS: u64 = 300;
const MAX_RETRIES: u32 = 5;
const RECONNECT_DRAIN: Duration = Duration::from_secs(10);

type SharedTorClient = Arc<TorClient<PreferredRuntime>>;

fn format_startup_failure(err: &anyhow::Error) -> String {
    let detail = format!("{err:#}");
    if detail.contains("refusing to use symlink in private directory path") {
        return "Tor onion service did not start: secure Tor state directory check failed because the path contains a symlink. HTTP/HTTPS serving will continue. Use a data directory whose path contains no symlinks; set tor.enabled=false to disable onion support.".to_owned();
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
        let local_addr = SocketAddr::new(
            if bind_addr.is_unspecified() {
                crate::server::tor_loopback_addr(bind_addr)
            } else {
                bind_addr
            },
            bind_port,
        );
        let _ = serve(
            data_dir,
            local_addr,
            max_connections,
            state,
            Shutdown::from_receiver(shutdown),
            Duration::from_secs(10),
        )
        .await;
    })
}

pub async fn serve(
    data_dir: PathBuf,
    local_addr: SocketAddr,
    max_connections: usize,
    state: SharedState,
    mut shutdown: Shutdown,
    grace: Duration,
) -> ServiceOutcome {
    if max_connections == 0 {
        return failed(&state, "Tor: max_connections must be >= 1".to_owned()).await;
    }

    let mut attempts = 0u32;
    let mut last_disruption: Option<tokio::time::Instant> = None;
    loop {
        match run_session(
            &data_dir,
            local_addr,
            max_connections,
            &state,
            shutdown.clone(),
            grace,
        )
        .await
        {
            SessionEnd::Stopped(outcome) => return outcome,
            SessionEnd::Failed(error) => {
                return failed(&state, format_startup_failure(&error)).await
            }
            SessionEnd::Reconnect => {}
        }

        let now = tokio::time::Instant::now();
        if last_disruption.is_some_and(|last| now.duration_since(last) > Duration::from_secs(3600))
        {
            attempts = 0;
        }
        last_disruption = Some(now);
        attempts = attempts.saturating_add(1);
        if attempts > MAX_RETRIES {
            return failed(&state, "Tor: too many reconnect attempts".to_owned()).await;
        }

        let delay = backoff_delay(attempts, RETRY_BASE_SECS, RETRY_MAX_SECS);
        log::warn!(
            "Tor: stream ended; re-bootstrapping in {delay:?} (attempt {attempts}/{MAX_RETRIES})"
        );
        tokio::select! {
            biased;
            _ = shutdown.wait() => {
                publish(&state, TorStatus::Stopped, None).await;
                return ServiceOutcome::Drained;
            }
            () = tokio::time::sleep(delay) => {}
        }
    }
}

async fn failed(state: &SharedState, message: String) -> ServiceOutcome {
    log::warn!("{message}");
    publish(state, TorStatus::Failed(message.clone()), None).await;
    ServiceOutcome::Failed(message)
}

struct TorSession {
    /// The relay needs the client and running service guard for its entire session.
    tor_client: SharedTorClient,
    onion_service_guard: Arc<tor_hsservice::RunningOnionService>,
    stream_requests: futures::stream::BoxStream<'static, StreamRequest>,
    onion_name: String,
}

enum SessionEnd {
    Stopped(ServiceOutcome),
    Reconnect,
    Failed(anyhow::Error),
}

async fn bootstrap_and_launch(
    data_dir: &std::path::Path,
    mut shutdown: Shutdown,
) -> anyhow::Result<Option<TorSession>> {
    if shutdown.is_requested() {
        return Ok(None);
    }
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

    let Some(tor_client) =
        await_bootstrap(TorClient::create_bootstrapped(config), &mut shutdown).await?
    else {
        return Ok(None);
    };
    if shutdown.is_requested() {
        return Ok(None);
    }
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

async fn await_bootstrap<T>(
    bootstrap: impl std::future::Future<Output = arti_client::Result<T>>,
    shutdown: &mut Shutdown,
) -> anyhow::Result<Option<T>> {
    tokio::select! {
        biased;
        _ = shutdown.wait() => {
            log::info!("Tor: shutdown received during bootstrap — exiting.");
            Ok(None)
        }
        result = tokio::time::timeout(BOOTSTRAP_TIMEOUT, bootstrap) => {
            let client = result.map_err(|_elapsed| anyhow::anyhow!(
                "Tor bootstrap timed out after {}s — check network connectivity",
                BOOTSTRAP_TIMEOUT.as_secs()
            ))?.context("Tor bootstrap failed")?;
            Ok(Some(client))
        }
    }
}

async fn run_session(
    data_dir: &std::path::Path,
    local_addr: SocketAddr,
    max_connections: usize,
    state: &SharedState,
    mut shutdown: Shutdown,
    grace: Duration,
) -> SessionEnd {
    publish(state, TorStatus::Starting, None).await;
    let TorSession {
        tor_client: _client,
        onion_service_guard: _service,
        stream_requests,
        onion_name,
    } = match bootstrap_and_launch(data_dir, shutdown.clone()).await {
        Ok(Some(session)) => session,
        Ok(None) => {
            publish(state, TorStatus::Stopped, None).await;
            return SessionEnd::Stopped(ServiceOutcome::Drained);
        }
        Err(error) => return SessionEnd::Failed(error),
    };
    log_onion_banner(&onion_name);
    publish(state, TorStatus::Ready, Some(onion_name)).await;

    forward_session(
        &mut Relay::new(max_connections),
        stream_requests,
        local_addr,
        state,
        &mut shutdown,
        grace,
    )
    .await
}

async fn forward_session(
    relay: &mut Relay,
    mut requests: impl futures::Stream<Item = StreamRequest> + Unpin,
    local_addr: SocketAddr,
    state: &SharedState,
    shutdown: &mut Shutdown,
    grace: Duration,
) -> SessionEnd {
    let end = relay.forward(&mut requests, local_addr, shutdown).await;
    // Arti's incoming stream owns rendezvous request sources used by active
    // transfers. Keep it alive without polling it until those transfers drain.
    let outcome = finish_forwarding(relay, end, state, shutdown, grace).await;
    drop(requests);
    outcome
}

async fn finish_forwarding(
    relay: &mut Relay,
    end: RelayEnd,
    state: &SharedState,
    shutdown: &mut Shutdown,
    grace: Duration,
) -> SessionEnd {
    let started = match end {
        RelayEnd::Shutdown(started) => started,
        RelayEnd::StreamEnded => {
            publish(state, TorStatus::Reconnecting, None).await;
            let reconnect_deadline = deadline(tokio::time::Instant::now(), RECONNECT_DRAIN);
            tokio::select! {
                biased;
                started = shutdown.wait() => {
                    return stop_forwarding(relay, state, deadline(started, grace).min(reconnect_deadline)).await;
                },
                _ = relay.drain(reconnect_deadline, "Tor reconnect") => return SessionEnd::Reconnect,
            }
        }
    };
    stop_forwarding(relay, state, deadline(started, grace)).await
}

async fn stop_forwarding(
    relay: &mut Relay,
    state: &SharedState,
    deadline: tokio::time::Instant,
) -> SessionEnd {
    publish(state, TorStatus::Draining, None).await;
    let outcome = relay.drain(deadline, "Tor service").await;
    publish(state, TorStatus::Stopped, None).await;
    SessionEnd::Stopped(outcome)
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

pub async fn publish(state: &SharedState, status: TorStatus, address: Option<String>) {
    let mut state = state.write().await;
    state.tor_status = status;
    state.onion_address = address;
}
