//! # Key Event Dispatch

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use crate::{
    config::Config,
    runtime::state::{ConsoleMode, SharedMetrics, SharedState, StatusMessage},
    server, Result,
};

const RELOAD_STATUS_DURATION: Duration = Duration::from_secs(3);

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

/// Reload site stats and refresh the canonical site root used by listeners.
///
/// # Errors
///
/// Returns [`AppError`] only if spawning the blocking rescan task fails at the
/// Tokio task level. Filesystem scan failures are logged and degraded to a
/// no-op so operators can retry reload without crashing the service.
pub async fn reload_site(
    config: &Config,
    state: SharedState,
    data_dir: PathBuf,
    root_tx: &tokio::sync::watch::Sender<std::sync::Arc<std::path::Path>>,
) -> Result<()> {
    let site_root = data_dir.join(&config.site.directory);
    let scan_root = site_root.clone();
    let (count, bytes) =
        match tokio::task::spawn_blocking(move || server::scan_site(&scan_root)).await {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => {
                log::warn!("Site rescan failed: {e}");
                state.write().await.status_message =
                    Some(StatusMessage::persistent(format!("Reload failed: {e}")));
                return Ok(());
            }
            Err(e) => {
                log::warn!("Site rescan task panicked: {e}");
                state.write().await.status_message = Some(StatusMessage::persistent(
                    "Reload failed: scan task stopped",
                ));
                return Ok(());
            }
        };
    {
        let mut s = state.write().await;
        s.site_file_count = count;
        s.site_total_bytes = bytes;
        s.status_message = Some(StatusMessage::temporary(
            format!(
                "Reload complete: {} files, {}",
                count,
                crate::runtime::state::format_bytes(bytes)
            ),
            RELOAD_STATUS_DURATION,
        ));
    }
    if let Ok(new_root) = site_root.canonicalize() {
        let _ = root_tx.send(Arc::from(new_root.as_path()));
    }
    log::info!(
        "Site reloaded — {} files, {}",
        count,
        crate::runtime::state::format_bytes(bytes)
    );
    Ok(())
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
            let confirming_quit = {
                let s = state.read().await;
                s.console_mode == ConsoleMode::ConfirmQuit
            };
            if confirming_quit {
                let mut s = state.write().await;
                s.console_mode = ConsoleMode::ShuttingDown;
                s.status_message = Some(StatusMessage::persistent(
                    "Shutdown requested — stopping web server and Tor background services...",
                ));
                drop(s);
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
                ConsoleMode::LogView | ConsoleMode::ShuttingDown => ConsoleMode::Dashboard,
            };
        }

        KeyEvent::Reload => {
            reload_site(config, Arc::clone(&state), data_dir.clone(), root_tx).await?;
        }

        KeyEvent::Open => {
            let port = state.read().await.actual_port;
            // Use the actual bind address so IPv6-only listeners still open correctly.
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

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::{handle, KeyEvent};
    use crate::{
        config::Config,
        runtime::state::{ConsoleMode, Metrics, SharedState},
    };
    use std::sync::Arc;
    use tokio::sync::{watch, RwLock};

    #[tokio::test]
    async fn reload_sets_visible_status_message() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let data_dir = tmp.path().to_path_buf();
        std::fs::create_dir_all(data_dir.join("site")).expect("create site");
        std::fs::write(data_dir.join("site/index.html"), b"hello").expect("write file");
        let config = Config::default();
        let state: SharedState = Arc::new(RwLock::new(crate::runtime::state::AppState::new()));
        let metrics = Arc::new(Metrics::new());
        let (root_tx, _root_rx) = watch::channel(Arc::from(data_dir.join("site").as_path()));

        let quit = handle(
            KeyEvent::Reload,
            &config,
            Arc::clone(&state),
            metrics,
            data_dir,
            &root_tx,
        )
        .await
        .expect("reload");

        let status_message = {
            let snapshot = state.read().await;
            snapshot.visible_status_message().map(str::to_owned)
        };
        assert!(!quit);
        assert!(status_message
            .as_deref()
            .is_some_and(|message| message.contains("Reload complete")));
    }

    #[tokio::test]
    async fn confirmed_quit_sets_shutdown_state() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let config = Config::default();
        let state: SharedState = Arc::new(RwLock::new(crate::runtime::state::AppState::new()));
        state.write().await.console_mode = ConsoleMode::ConfirmQuit;
        let metrics = Arc::new(Metrics::new());
        let (root_tx, _root_rx) = watch::channel(Arc::from(tmp.path()));

        let quit = handle(
            KeyEvent::Confirm,
            &config,
            Arc::clone(&state),
            metrics,
            tmp.path().to_path_buf(),
            &root_tx,
        )
        .await
        .expect("confirm");

        let (console_mode, status_message) = {
            let snapshot = state.read().await;
            (
                snapshot.console_mode.clone(),
                snapshot.visible_status_message().map(str::to_owned),
            )
        };
        assert!(quit);
        assert_eq!(console_mode, ConsoleMode::ShuttingDown);
        assert!(status_message
            .as_deref()
            .is_some_and(|message| message.contains("Shutdown requested")));
    }
}
