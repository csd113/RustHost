//! Initial request headers and the Hyper HTTP/1.1 connection driver.

use std::{
    io::Cursor,
    sync::{atomic::AtomicU64, Arc},
    time::Duration,
};

use hyper::StatusCode;
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite};

use super::{
    routes::{route, RouteConfig},
    HandlerConfig, RequestIngress,
};
use crate::{
    runtime::{shutdown::Shutdown, state::SharedMetrics},
    Result,
};

const MAX_REQUEST_BUFFER_BYTES: usize = 16 * 1024;
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(5);
const REJECTED_HEADER_DRAIN_TIMEOUT: Duration = Duration::from_millis(100);
const MAX_REJECTED_HEADER_DRAIN_BYTES: usize = 64 * 1024;

/// Serve one HTTP connection to completion.
///
/// Uses [`hyper`]'s HTTP/1.1 connection loop with keep-alive enabled.
///
/// # Errors
///
/// Propagates I/O errors from hyper's connection driver.
pub async fn handle<S>(
    stream: S,
    config: HandlerConfig,
    metrics: SharedMetrics,
    mut shutdown: Shutdown,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let idle_timeout = if config.ingress == RequestIngress::Tor {
        crate::io_timeout::TRANSFER_IDLE
    } else {
        Duration::from_secs(5)
    };
    let peer_addr = config.peer_addr;
    let progress = Arc::new(AtomicU64::new(0));
    let mut stream = crate::io_timeout::ProgressStream::new(
        stream,
        Arc::clone(&progress),
        crate::io_timeout::TRANSFER_IDLE,
    );
    let prefetched = tokio::select! {
        biased;
        _ = shutdown.wait() => return Ok(()),
        result = preflight_initial_headers(&mut stream, peer_addr) => result?,
    };
    let Some(prefetched) = prefetched else {
        return Ok(());
    };
    let cfg = Arc::new(config);

    let io = TokioIo::new(PrefixedStream::new(prefetched, stream));

    let mut builder = hyper::server::conn::http1::Builder::new();
    let connection = builder
        .keep_alive(cfg.flags.keep_alive)
        .header_read_timeout(HEADER_READ_TIMEOUT)
        .timer(TokioTimer::new())
        .max_buf_size(MAX_REQUEST_BUFFER_BYTES)
        .serve_connection(
            io,
            hyper::service::service_fn(move |req| {
                let cfg = RouteConfig::for_request(&cfg);
                let met = Arc::clone(&metrics);
                async move { route(req, &cfg, &met).await }
            }),
        );
    let connection = async {
        tokio::pin!(connection);
        tokio::select! {
            biased;
            _ = shutdown.wait() => {
                connection.as_mut().graceful_shutdown();
                connection.await
            }
            result = connection.as_mut() => result,
        }
    };
    let result = tokio::time::timeout(
        crate::io_timeout::MAX_CONNECTION_AGE,
        crate::io_timeout::with_idle_timeout(connection, progress, idle_timeout),
    )
    .await
    .map_err(|e| std::io::Error::new(std::io::ErrorKind::TimedOut, e))??;

    match result {
        Ok(()) => Ok(()),
        Err(error) if error.is_parse_too_large() => {
            log::warn!(
                "Rejected request with oversized headers from {peer_addr} \
                 (limit: {MAX_REQUEST_BUFFER_BYTES} bytes)"
            );
            Ok(())
        }
        Err(error) => Err(crate::AppError::Io(std::io::Error::other(
            error.to_string(),
        ))),
    }
}

struct PrefixedStream<S> {
    prefix: Cursor<Vec<u8>>,
    inner: S,
}

impl<S> PrefixedStream<S> {
    const fn new(prefix: Vec<u8>, inner: S) -> Self {
        Self {
            prefix: Cursor::new(prefix),
            inner,
        }
    }
}

impl<S> AsyncRead for PrefixedStream<S>
where
    S: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.as_mut().get_mut();
        let prefix_len = this.prefix.get_ref().len();
        let pos = usize::try_from(this.prefix.position()).unwrap_or(prefix_len);

        if pos < prefix_len {
            let remaining = &this.prefix.get_ref()[pos..];
            let to_copy = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..to_copy]);
            this.prefix
                .set_position(u64::try_from(pos.saturating_add(to_copy)).unwrap_or(u64::MAX));
            return std::task::Poll::Ready(Ok(()));
        }

        // Prefix fully consumed: release the up-to-16 KB pre-read buffer so it
        // is not pinned for the lifetime of a keep-alive connection.
        if prefix_len != 0 {
            this.prefix = Cursor::new(Vec::new());
        }

        std::pin::Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S> AsyncWrite for PrefixedStream<S>
where
    S: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.as_mut().get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.as_mut().get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.as_mut().get_mut().inner).poll_shutdown(cx)
    }
}

async fn preflight_initial_headers<S>(
    stream: &mut S,
    peer_addr: std::net::SocketAddr,
) -> std::io::Result<Option<Vec<u8>>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if let Ok(result) = tokio::time::timeout(
        HEADER_READ_TIMEOUT,
        preflight_initial_headers_inner(stream, peer_addr),
    )
    .await
    {
        result
    } else {
        log::warn!("Timed out reading initial request headers from {peer_addr}");
        write_simple_response(stream, StatusCode::REQUEST_TIMEOUT, "Request Timeout").await?;
        Ok(None)
    }
}

async fn preflight_initial_headers_inner<S>(
    stream: &mut S,
    peer_addr: std::net::SocketAddr,
) -> std::io::Result<Option<Vec<u8>>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut buffered = Vec::with_capacity(4096);
    let mut staging = [0_u8; 4096];

    loop {
        let n = stream.read(&mut staging).await?;
        if n == 0 {
            return Ok(None);
        }
        buffered.extend_from_slice(&staging[..n]);

        if let Some(header_end) = find_header_end(&buffered) {
            if header_end > MAX_REQUEST_BUFFER_BYTES {
                log::warn!(
                    "Rejected request with oversized headers from {peer_addr} \
                     (limit: {MAX_REQUEST_BUFFER_BYTES} bytes)"
                );
                write_simple_response(
                    stream,
                    StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
                    "Request Header Fields Too Large",
                )
                .await?;
                return Ok(None);
            }
            return Ok(Some(buffered));
        }

        if buffered.len() > MAX_REQUEST_BUFFER_BYTES {
            log::warn!(
                "Rejected request with oversized headers from {peer_addr} \
                 (limit: {MAX_REQUEST_BUFFER_BYTES} bytes)"
            );
            write_simple_response(
                stream,
                StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
                "Request Header Fields Too Large",
            )
            .await?;
            drain_rejected_headers(stream, &buffered).await;
            return Ok(None);
        }
    }
}

/// Briefly consume the rest of a rejected header block after sending the 431.
///
/// Closing a Winsock connection with unread inbound bytes produces a TCP reset,
/// which can discard the response before the client observes it. The strict
/// time and byte bounds keep this best-effort drain from becoming a slow-client
/// resource sink.
async fn drain_rejected_headers<S>(stream: &mut S, buffered: &[u8])
where
    S: AsyncRead + Unpin,
{
    let tail_start = buffered.len().saturating_sub(3);
    let mut scan = buffered[tail_start..].to_vec();
    let mut staging = [0_u8; 4096];
    let mut drained = 0_usize;

    let drain = async {
        while drained < MAX_REJECTED_HEADER_DRAIN_BYTES {
            let remaining = MAX_REJECTED_HEADER_DRAIN_BYTES.saturating_sub(drained);
            let read_len = remaining.min(staging.len());
            let n = match stream.read(&mut staging[..read_len]).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            drained = drained.saturating_add(n);
            scan.extend_from_slice(&staging[..n]);
            if find_header_end(&scan).is_some() {
                break;
            }
            if scan.len() > 3 {
                scan.drain(..scan.len() - 3);
            }
        }
    };

    let _ = tokio::time::timeout(REJECTED_HEADER_DRAIN_TIMEOUT, drain).await;
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|idx| idx.saturating_add(4))
}

async fn write_simple_response<S>(
    stream: &mut S,
    status: StatusCode,
    reason: &str,
) -> std::io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    let response = format!(
        "HTTP/1.1 {} {}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        status.as_u16(),
        reason
    );
    tokio::io::AsyncWriteExt::write_all(stream, response.as_bytes()).await?;
    tokio::io::AsyncWriteExt::flush(stream).await
}
