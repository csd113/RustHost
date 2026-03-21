//! # Key Event Dispatch
//!
//! **Directory:** `src/runtime/`

use std::path::PathBuf;

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
    Quit,
    Other,
}

/// Dispatch a single key event, mutating shared state as needed.
///
/// Returns `true` when the event is [`KeyEvent::Quit`] (the caller should
/// begin graceful shutdown), or `false` for all other events.
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
) -> Result<bool> {
    match event {
        KeyEvent::Quit => return Ok(true),

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
                ConsoleMode::Dashboard | ConsoleMode::Help => ConsoleMode::LogView,
                ConsoleMode::LogView => ConsoleMode::Dashboard,
            };
        }

        KeyEvent::Reload => {
            let site_root = data_dir.join(&config.site.directory);
            // 2.2 — scan_site now returns Result and must run on a blocking
            // thread (read_dir is not async-safe).
            let (count, bytes) =
                match tokio::task::spawn_blocking(move || server::scan_site(&site_root)).await {
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
            log::info!(
                "Site reloaded — {} files, {}",
                count,
                crate::runtime::state::format_bytes(bytes)
            );
        }

        KeyEvent::Open => {
            let port = state.read().await.actual_port;
            // 2.4 — use the canonical definition in crate::runtime
            super::open_browser(&format!("http://localhost:{port}"));
        }

        KeyEvent::Other => {
            let mut s = state.write().await;
            if s.console_mode == ConsoleMode::Help {
                s.console_mode = ConsoleMode::Dashboard;
            }
        }
    }

    Ok(false)
}
// open_browser removed — canonical definition lives in crate::runtime (mod.rs) (fix 2.4)
