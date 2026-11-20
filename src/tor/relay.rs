//! Onion stream admission, forwarding, transfer limits, and drain.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use anyhow::Context as _;
use futures::StreamExt as _;
use tokio::{net::TcpStream, sync::Semaphore, task::JoinSet, time::Instant};
use tor_cell::relaycell::msg::Connected;
use tor_hsservice::StreamRequest;

use crate::runtime::shutdown::{drain_tasks, ServiceOutcome, Shutdown};

const LOCAL_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const TOR_RELAY_BUFFER_BYTES: usize = 32 * 1024;

pub(super) enum RelayEnd {
    Shutdown(Instant),
    StreamEnded,
}

pub(super) struct Relay {
    max_connections: usize,
    permits: Arc<Semaphore>,
    tasks: JoinSet<()>,
}

impl Relay {
    pub(super) fn new(max_connections: usize) -> Self {
        Self {
            max_connections,
            permits: Arc::new(Semaphore::new(max_connections)),
            tasks: JoinSet::new(),
        }
    }

    pub(super) async fn forward(
        &mut self,
        mut requests: impl futures::Stream<Item = StreamRequest> + Unpin,
        local_addr: SocketAddr,
        shutdown: &mut Shutdown,
    ) -> RelayEnd {
        let end = loop {
            tokio::select! {
                biased;
                started = shutdown.wait() => break RelayEnd::Shutdown(started),
                Some(result) = self.tasks.join_next(), if !self.tasks.is_empty() => {
                    if let Err(error) = result {
                        log::warn!("Tor stream task failed: {error}");
                    }
                }
                next = requests.next() => match next {
                    Some(request) => self.spawn(request, local_addr),
                    None => break RelayEnd::StreamEnded,
                }
            }
        };
        self.permits.close();
        end
    }

    fn spawn(&mut self, request: StreamRequest, local_addr: SocketAddr) {
        let Ok(permit) = Arc::clone(&self.permits).try_acquire_owned() else {
            log::warn!(
                "Tor: at capacity ({}), dropping stream",
                self.max_connections
            );
            return;
        };
        self.tasks.spawn(async move {
            let _permit = permit;
            if let Err(error) = Box::pin(proxy_stream(request, local_addr)).await {
                log::debug!("Tor: stream closed: {error:#}");
            }
        });
    }

    pub(super) async fn drain(&mut self, deadline: Instant, phase: &str) -> ServiceOutcome {
        drain_tasks(&mut self.tasks, deadline, phase).await
    }
}

async fn proxy_stream(stream_req: StreamRequest, local_addr: SocketAddr) -> anyhow::Result<()> {
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
