//! # Key Event Dispatch
//!
//! **File:** `events.rs`
//! **Location:** `src/runtime/events.rs`

use std::path::PathBuf;
use std::sync::Arc;

use crate::{
    config::Config,
    runtime::state::{ConsoleMode, SharedMetrics, SharedState},
    server, Result,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyEvent {
    Help,
    Reload,
    Open,
    ToggleLogs,
    /// Q or Esc — request quit, shows confirm prompt.
    Quit,
    /// Y — confirm the quit prompt.
    Confirm,
    /// N — cancel the quit prompt.
    Cancel,
    /// Ctrl+C — immediate quit, no prompt.
    ForceQuit,
    Other,
}

/// Dispatch a single key event, mutating shared state as needed.
///
/// Returns `true` when the event is [`KeyEvent::Quit`] (the caller should
/// begin graceful shutdown), or `false` for all other events.
///
/// `root_tx` is the watch sender: on `[R]` reload the handler sends the
/// newly-canonicalized site root so the HTTP accept loop can update
/// `canonical_root` without a server restart.
///
/// # Errors
///
/// Returns [`AppError`] if a site rescan (`KeyEvent::Reload`) fails to spawn
/// a blocking task or if a browser-open (`KeyEvent::Open`) returns an I/O
/// error.
pub async fn handle(
    event: KeyEvent,
    config: &Config,
    state: SharedState,
    _metrics: SharedMetrics,
    data_dir: PathBuf,
    root_tx: &tokio::sync::watch::Sender<std::sync::Arc<std::path::Path>>,
) -> Result<bool> {
    match event {
        KeyEvent::ForceQuit => return Ok(true),

        KeyEvent::Quit => {
            let mut s = state.write().await;
            s.console_mode = ConsoleMode::ConfirmQuit;
        }

        KeyEvent::Confirm => {
            if state.read().await.console_mode == ConsoleMode::ConfirmQuit {
                return Ok(true);
            }
        }

        KeyEvent::Cancel => {
            let mut s = state.write().await;
            if s.console_mode == ConsoleMode::ConfirmQuit {
                s.console_mode = ConsoleMode::Dashboard;
            }
        }

        KeyEvent::Help => {
            let mut s = state.write().await;
            s.console_mode = if s.console_mode == ConsoleMode::Help {
                ConsoleMode::Dashboard
            } else {
                ConsoleMode::Help
            };
        }

        KeyEvent::ToggleLogs => {
            let mut s = state.write().await;
            s.console_mode = match s.console_mode {
                ConsoleMode::Dashboard | ConsoleMode::Help | ConsoleMode::ConfirmQuit => {
                    ConsoleMode::LogView
                }
                ConsoleMode::LogView => ConsoleMode::Dashboard,
            };
        }

        KeyEvent::Reload => {
            let site_root = data_dir.join(&config.site.directory);
            // scan_site now returns Result and must run on a blocking
            // thread (read_dir is not async-safe).
            let scan_root = site_root.clone();
            let (count, bytes) =
                match tokio::task::spawn_blocking(move || server::scan_site(&scan_root)).await {
                    Ok(Ok(v)) => v,
                    Ok(Err(e)) => {
                        log::warn!("Site rescan failed: {e}");
                        return Ok(false);
                    }
                    Err(e) => {
                        log::warn!("Site rescan task panicked: {e}");
                        return Ok(false);
                    }
                };
            {
                let mut s = state.write().await;
                s.site_file_count = count;
                s.site_total_bytes = bytes;
            }
            // push the newly-canonicalized site root to the server accept
            // loop so it picks up any directory change without a restart.
            if let Ok(new_root) = site_root.canonicalize() {
                let _ = root_tx.send(Arc::from(new_root.as_path()));
            }
            log::info!(
                "Site reloaded — {} files, {}",
                count,
                crate::runtime::state::format_bytes(bytes)
            );
        }

        KeyEvent::Open => {
            let port = state.read().await.actual_port;
            // use the actual bind address, not hardcoded "localhost".
            // If bind = "::1", localhost may resolve to 127.0.0.1 and miss the listener.
            let url = match config.server.bind {
                std::net::IpAddr::V4(a) if a.is_unspecified() => {
                    format!("http://127.0.0.1:{port}")
                }
                std::net::IpAddr::V6(a) if a.is_unspecified() => {
                    format!("http://[::1]:{port}")
                }
                std::net::IpAddr::V6(a) => format!("http://[{a}]:{port}"),
                std::net::IpAddr::V4(a) => format!("http://{a}:{port}"),
            };
            super::open_browser(&url);
        }

        KeyEvent::Other => {
            let mut s = state.write().await;
            if s.console_mode == ConsoleMode::Help || s.console_mode == ConsoleMode::ConfirmQuit {
                s.console_mode = ConsoleMode::Dashboard;
            }
        }
    }

    Ok(false)
}
// open_browser removed — canonical definition lives in crate::runtime (mod.rs)
