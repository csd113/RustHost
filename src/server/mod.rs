//! # Server Module
//!
//! **Directory:** `src/server/`
//!
//! Provides a minimal, safe HTTP/1.1 static-file server built directly
//! on [`tokio::net::TcpListener`] — no third-party HTTP framework.
//!
//! Sub-modules:
//! - [`handler`]  — per-connection request handling and file serving
//! - [`mime`]     — file-extension → MIME type mapping
//! - [`fallback`] — built-in "No site found" page

pub mod fallback;
pub mod handler;
pub mod mime;

use std::{
    net::TcpListener as StdTcpListener, path::Path, path::PathBuf, sync::Arc, time::Duration,
};

use tokio::{
    net::TcpListener,
    sync::{oneshot, watch, Semaphore},
    task::JoinSet,
};

use crate::{
    config::Config,
    runtime::state::{SharedMetrics, SharedState},
    Result,
};

// ─── Public API ─────────────────────────────────────────────────────────────

/// Start the HTTP server.
///
/// Binds the port (with optional fallback), updates `SharedState.actual_port`,
/// sends the bound port through `port_tx` so Tor can start without a sleep,
/// then accepts connections until the shutdown watch fires.
pub async fn run(
    config: Arc<Config>,
    state: SharedState,
    metrics: SharedMetrics,
    data_dir: PathBuf,
    mut shutdown: watch::Receiver<bool>,
    port_tx: oneshot::Sender<u16>,
) {
    let bind_addr = &config.server.bind;
    let base_port = config.server.port;
    let fallback = config.server.auto_port_fallback;
    let max_conns = config.server.max_connections as usize;

    let (listener, bound_port) = match bind_with_fallback(bind_addr, base_port, fallback) {
        Ok(v) => v,
        Err(e) => {
            log::error!("Server failed to bind: {e}");
            // port_tx is dropped here, which closes the channel; lifecycle
            // will receive an Err from the oneshot receiver.
            return;
        }
    };

    if bound_port != base_port {
        log::warn!("Configured port {base_port} was in use; bound to {bound_port} instead.");
    }

    {
        let mut s = state.write().await;
        s.actual_port = bound_port;
        s.server_running = true;
    }

    // Signal the bound port to lifecycle so Tor can start immediately.
    // If the receiver has already gone away, we continue serving anyway.
    let _ = port_tx.send(bound_port);

    log::info!("HTTP server listening on {bind_addr}:{bound_port}");

    let site_root = data_dir.join(&config.site.directory);
    // 2.3 — canonicalize once here so resolve_path never calls canonicalize()
    // per-request. If the root is missing or inaccessible, fail fast before
    // binding any port.
    let canonical_root = match site_root.canonicalize() {
        Ok(p) => p,
        Err(e) => {
            log::error!(
                "Site root {} cannot be resolved: {e}. Check that [site] directory exists.",
                site_root.display()
            );
            return;
        }
    };
    let index_file = config.site.index_file.clone();
    let dir_list = config.site.enable_directory_listing;

    let semaphore = Arc::new(Semaphore::new(max_conns));
    // 2.10 — JoinSet tracks in-flight handler tasks so shutdown can drain them.
    let mut join_set: JoinSet<()> = JoinSet::new();

    loop {
        tokio::select! {
            result = listener.accept() => {
                match result {
                    Ok((stream, peer)) => {
                        log::debug!("Connection from {peer}");
                        let Ok(permit) = Arc::clone(&semaphore).acquire_owned().await else {
                            break; // semaphore closed — shutting down
                        };
                        if semaphore.available_permits() == 0 {
                            log::warn!(
                                "Connection limit ({max_conns}) reached; \
                                 further connections will queue"
                            );
                        }
                        let site = canonical_root.clone();
                        let idx  = index_file.clone();
                        let met  = Arc::clone(&metrics);
                        join_set.spawn(async move {
                            let _permit = permit;
                            if let Err(e) = handler::handle(
                                stream, &site, &idx, dir_list, met
                            ).await {
                                log::debug!("Handler error: {e}");
                            }
                        });
                    }
                    Err(e) => log::warn!("Accept error: {e}"),
                }
            }

            _ = shutdown.changed() => {
                if *shutdown.borrow() { break; }
            }
        }
    }

    state.write().await.server_running = false;
    log::info!("HTTP server stopped accepting; draining in-flight connections…");

    // 2.10 — wait up to 5 seconds for in-flight handlers to complete so
    // responses that were already being written are not truncated mid-stream.
    let drain = async { while join_set.join_next().await.is_some() {} };
    let _ = tokio::time::timeout(Duration::from_secs(5), drain).await;
    log::info!("HTTP server drained.");
}

// ─── Port binding ────────────────────────────────────────────────────────────

/// Try to bind to `addr:port`. When `fallback` is true, increments the port
/// up to 10 times before giving up.
fn bind_with_fallback(addr: &str, port: u16, fallback: bool) -> Result<(TcpListener, u16)> {
    let max_attempts: u16 = if fallback { 10 } else { 1 };

    for attempt in 0..max_attempts {
        let try_port = port.saturating_add(attempt);
        let addr_str = format!("{addr}:{try_port}");

        match StdTcpListener::bind(&addr_str) {
            Ok(std_listener) => {
                std_listener.set_nonblocking(true)?;
                let listener = TcpListener::from_std(std_listener)?;
                return Ok((listener, try_port));
            }
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse && fallback => {
                // Try the next port.
            }
            Err(e) => {
                return Err(format!(
                    "Port {try_port} is already in use. \
                     Change [server].port in settings.toml or set \
                     auto_port_fallback = true.\n  OS error: {e}"
                )
                .into());
            }
        }
    }

    Err(format!(
        "Could not find a free port after {max_attempts} attempts \
         starting from {port}."
    )
    .into())
}

// ─── Site scanner ─────────────────────────────────────────────────────────────

/// Recursively count files and total bytes in `site_root` (BFS traversal).
///
/// Returns `Err` if any `read_dir` call fails so callers can log a warning
/// instead of silently reporting zeros.
///
/// **Must be called from a blocking context** (e.g. `tokio::task::spawn_blocking`)
/// because `std::fs::read_dir` is a blocking syscall.
pub fn scan_site(site_root: &Path) -> crate::Result<(u32, u64)> {
    let mut count = 0u32;
    let mut bytes = 0u64;

    let mut queue: std::collections::VecDeque<PathBuf> = std::collections::VecDeque::new();
    queue.push_back(site_root.to_path_buf());

    while let Some(dir) = queue.pop_front() {
        let entries = std::fs::read_dir(&dir)
            .map_err(|e| format!("Cannot read directory {}: {e}", dir.display()))?;

        for entry in entries.flatten() {
            match entry.metadata() {
                Ok(m) if m.is_file() => {
                    count = count.saturating_add(1);
                    bytes = bytes.saturating_add(m.len());
                }
                Ok(m) if m.is_dir() => {
                    queue.push_back(entry.path());
                }
                _ => {}
            }
        }
    }

    Ok((count, bytes))
}
