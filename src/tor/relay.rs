//! Onion stream admission, forwarding, transfer limits, and drain.

use std::{sync::Arc, time::Duration};

use anyhow::Context as _;
use futures::StreamExt as _;
use tokio::{net::TcpStream, sync::watch, task::JoinSet};
use tor_cell::relaycell::msg::Connected;
use tor_hsservice::StreamRequest;

use super::session::{clear_onion_only, wait_for_shutdown_signal, TorSession};
use crate::runtime::state::SharedState;

const LOCAL_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const SHUTDOWN_DRAIN_TIMEOUT: Duration = Duration::from_secs(10);
const RECONNECT_DRAIN_TIMEOUT: Duration = Duration::from_secs(10);
const TOR_RELAY_BUFFER_BYTES: usize = 32 * 1024;

pub(super) async fn process_streams(
    session: TorSession,
    local_addr: String,
    max_connections: usize,
    state: SharedState,
    mut shutdown: watch::Receiver<bool>,
) -> anyhow::Result<bool> {
    let TorSession {
        tor_client,
        onion_service_guard,
        mut stream_requests,
        onion_name: _,
    } = session;

    let _keep_tor_client_alive = tor_client;
    let _keep_onion_service_alive = onion_service_guard;
    let semaphore = Arc::new(tokio::sync::Semaphore::new(max_connections));
    let mut active_tasks = JoinSet::new();

    loop {
        while let Some(result) = active_tasks.try_join_next() {
            if let Err(e) = result {
                log::debug!("Tor stream task ended: {e}");
            }
        }
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

    let tor_stream = tokio::time::timeout(
        Duration::from_secs(10),
        stream_req.accept(Connected::new_empty()),
    )
    .await
    .context("Tor stream acceptance timed out")?
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
    let progress = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let mut stream_a =
        crate::io_timeout::ProgressStream::new(stream_a, Arc::clone(&progress), idle_timeout);
    let mut stream_b =
        crate::io_timeout::ProgressStream::new(stream_b, Arc::clone(&progress), idle_timeout);
    let transfer = tokio::io::copy_bidirectional_with_sizes(
        &mut stream_a,
        &mut stream_b,
        TOR_RELAY_BUFFER_BYTES,
        TOR_RELAY_BUFFER_BYTES,
    );
    tokio::time::timeout(
        crate::io_timeout::MAX_CONNECTION_AGE,
        crate::io_timeout::with_idle_timeout(transfer, progress, idle_timeout),
    )
    .await
    .map_err(|e| std::io::Error::new(std::io::ErrorKind::TimedOut, e))???;
    Ok(())
}
