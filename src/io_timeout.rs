//! Connection-wide progress and independent blocked-write deadlines.
use std::{
    future::Future,
    io,
    pin::Pin,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    time::{Instant, Sleep},
};

/// Long downloads are allowed, but trickle traffic cannot retain a slot forever.
pub const MAX_CONNECTION_AGE: Duration = Duration::from_secs(24 * 60 * 60);
pub const TRANSFER_IDLE: Duration = Duration::from_secs(60);

pub struct ProgressStream<S> {
    inner: S,
    progress: Arc<AtomicU64>,
    write_timeout: Duration,
    write_deadlines: [Option<Pin<Box<Sleep>>>; 3],
}

impl<S> ProgressStream<S> {
    pub const fn new(inner: S, progress: Arc<AtomicU64>, write_timeout: Duration) -> Self {
        Self {
            inner,
            progress,
            write_timeout,
            write_deadlines: [None, None, None],
        }
    }

    fn write_result<T>(
        &mut self,
        operation: usize,
        cx: &mut Context<'_>,
        result: Poll<io::Result<T>>,
    ) -> Poll<io::Result<T>> {
        if result.is_ready() {
            self.write_deadlines[operation] = None;
            return result;
        }
        let timer = self.write_deadlines[operation]
            .get_or_insert_with(|| Box::pin(tokio::time::sleep(self.write_timeout)));
        if timer.as_mut().poll(cx).is_ready() {
            // Clear the spent timer so a caller that retries after a transient
            // timeout gets a fresh deadline instead of failing immediately.
            self.write_deadlines[operation] = None;
            Poll::Ready(Err(timed_out()))
        } else {
            Poll::Pending
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for ProgressStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(cx, buf);
        if buf.filled().len() > before {
            self.progress.fetch_add(1, Ordering::Relaxed);
        }
        result
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for ProgressStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write(cx, buf);
        if matches!(result, Poll::Ready(Ok(n)) if n > 0) {
            self.progress.fetch_add(1, Ordering::Relaxed);
        }
        self.write_result(0, cx, result)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let result = Pin::new(&mut self.inner).poll_flush(cx);
        self.write_result(1, cx, result)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let result = Pin::new(&mut self.inner).poll_shutdown(cx);
        self.write_result(2, cx, result)
    }
}

fn timed_out() -> io::Error {
    io::Error::new(
        io::ErrorKind::TimedOut,
        "connection made no progress before deadline",
    )
}

/// Poll both directions as one operation: active downloads do not require any
/// additional upload bytes. The timer lives outside the I/O polls, so it also
/// wakes a driver that is blocked on a response body or socket backpressure.
pub async fn with_idle_timeout<F: Future>(
    future: F,
    progress: Arc<AtomicU64>,
    idle: Duration,
) -> io::Result<F::Output> {
    let future = std::pin::pin!(future);
    let mut future = future;
    let mut last = progress.load(Ordering::Relaxed);
    let timer = tokio::time::sleep(idle);
    let mut timer = std::pin::pin!(timer);
    std::future::poll_fn(|cx| {
        let result = future.as_mut().poll(cx);
        if let Poll::Ready(output) = result {
            return Poll::Ready(Ok(output));
        }
        let current = progress.load(Ordering::Relaxed);
        if current != last {
            last = current;
            timer.as_mut().reset(Instant::now() + idle);
        }
        if timer.as_mut().poll(cx).is_ready() {
            Poll::Ready(Err(timed_out()))
        } else {
            Poll::Pending
        }
    })
    .await
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]
    use super::*;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    #[tokio::test(start_paused = true)]
    async fn stalled_write_times_out_even_with_incoming_progress() -> io::Result<()> {
        let (stream, mut peer) = tokio::io::duplex(1);
        let progress = Arc::new(AtomicU64::new(0));
        let mut stream =
            ProgressStream::new(stream, Arc::clone(&progress), Duration::from_millis(30));
        stream.write_all(b"x").await?;
        peer.write_all(b"y").await?;
        assert_eq!(stream.read_u8().await?, b'y');
        let error = tokio::time::timeout(Duration::from_secs(2), stream.write_all(b"blocked"))
            .await
            .map_err(io::Error::other)?
            .expect_err("stalled writer must time out");
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn idle_driver_is_woken_without_io_polls() {
        let result = with_idle_timeout(
            std::future::pending::<()>(),
            Arc::new(AtomicU64::new(0)),
            Duration::from_millis(10),
        )
        .await;
        assert_eq!(
            result.expect_err("idle deadline").kind(),
            io::ErrorKind::TimedOut
        );
    }
}
