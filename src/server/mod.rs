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

use std::{net::TcpListener as StdTcpListener, path::Path, path::PathBuf, sync::Arc};

use tokio::{net::TcpListener, sync::watch};

use crate::{
    config::Config,
    runtime::state::{SharedMetrics, SharedState},
    Result,
};

// ─── Public API ─────────────────────────────────────────────────────────────

/// Start the HTTP server.
///
/// Binds the port (with optional fallback), updates `SharedState.actual_port`,
/// then accepts connections until the shutdown watch fires.
pub async fn run(
    config: Arc<Config>,
    state: SharedState,
    metrics: SharedMetrics,
    data_dir: PathBuf,
    mut shutdown: watch::Receiver<bool>,
) {
    let bind_addr = &config.server.bind;
    let base_port = config.server.port;
    let fallback = config.server.auto_port_fallback;

    let (listener, bound_port) = match bind_with_fallback(bind_addr, base_port, fallback) {
        Ok(v) => v,
        Err(e) => {
            log::error!("Server failed to bind: {e}");
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

    log::info!("HTTP server listening on {bind_addr}:{bound_port}");

    let site_root = data_dir.join(&config.site.directory);
    let index_file = config.site.index_file.clone();
    let dir_list = config.site.enable_directory_listing;

    loop {
        tokio::select! {
            result = listener.accept() => {
                match result {
                    Ok((stream, peer)) => {
                        log::debug!("Connection from {peer}");
                        let site = site_root.clone();
                        let idx  = index_file.clone();
                        let met  = Arc::clone(&metrics);
                        tokio::spawn(async move {
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
    log::info!("HTTP server stopped.");
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

/// Count files and total bytes in the site directory (non-recursive).
pub fn scan_site(site_root: &Path) -> (u32, u64) {
    let mut count = 0u32;
    let mut bytes = 0u64;

    if let Ok(entries) = std::fs::read_dir(site_root) {
        for entry in entries.flatten() {
            if let Ok(meta) = entry.metadata() {
                if meta.is_file() {
                    count = count.saturating_add(1);
                    bytes = bytes.saturating_add(meta.len());
                }
            }
        }
    }

    (count, bytes)
}
