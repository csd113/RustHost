//! # Key Event Dispatch

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use crate::{
    config::Config,
    runtime::state::{AppState, ConsoleMode, Page, SharedMetrics, SharedState, StatusMessage},
    server, Result,
};

const RELOAD_STATUS_DURATION: Duration = Duration::from_secs(3);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyEvent {
    Help,
    Menu,
    Reload,
    Open,
    ToggleLogs,
    NavigateUp,
    NavigateDown,
    OpenSelected,
    Back,
    /// Q — request quit, shows confirm prompt.
    Quit,
    /// Y — confirm the quit prompt.
    Confirm,
    /// N — cancel the quit prompt.
    Cancel,
    /// Ctrl+C — immediate quit, no prompt.
    ForceQuit,
    Other,
}

const fn select_previous(selected: usize) -> usize {
    if selected == 0 {
        Page::MENU_ITEMS.len() - 1
    } else {
        selected - 1
    }
}

const fn select_next(selected: usize) -> usize {
    (selected + 1) % Page::MENU_ITEMS.len()
}

fn selected_page(selected: usize) -> Page {
    Page::MENU_ITEMS
        .get(selected)
        .copied()
        .unwrap_or(Page::Doctor)
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

fn handle_console_state(event: KeyEvent, state: &mut AppState) -> bool {
    match event {
        KeyEvent::Quit => {
            state.console_mode = ConsoleMode::ConfirmQuit;
        }
        KeyEvent::Back => {
            state.console_mode = match state.console_mode {
                ConsoleMode::Menu | ConsoleMode::Help | ConsoleMode::LogView => {
                    ConsoleMode::Dashboard
                }
                ConsoleMode::Placeholder(_) => ConsoleMode::Menu,
                ConsoleMode::ConfirmQuit => ConsoleMode::Dashboard,
                ConsoleMode::Dashboard => ConsoleMode::ConfirmQuit,
                ConsoleMode::ShuttingDown => ConsoleMode::ShuttingDown,
            };
        }
        KeyEvent::Menu => {
            if state.console_mode == ConsoleMode::Dashboard {
                state.console_mode = ConsoleMode::Menu;
            }
        }
        KeyEvent::NavigateUp => {
            if state.console_mode == ConsoleMode::Menu {
                state.menu_selected = select_previous(state.menu_selected);
            }
        }
        KeyEvent::NavigateDown => {
            if state.console_mode == ConsoleMode::Menu {
                state.menu_selected = select_next(state.menu_selected);
            }
        }
        KeyEvent::OpenSelected => {
            if state.console_mode == ConsoleMode::Menu {
                state.console_mode = ConsoleMode::Placeholder(selected_page(state.menu_selected));
            }
        }
        KeyEvent::Confirm => {
            if state.console_mode == ConsoleMode::ConfirmQuit {
                state.console_mode = ConsoleMode::ShuttingDown;
                state.status_message = Some(StatusMessage::persistent(
                    "Shutdown requested — stopping web server and Tor background services...",
                ));
                return true;
            }
        }
        KeyEvent::Cancel => {
            if state.console_mode == ConsoleMode::ConfirmQuit {
                state.console_mode = ConsoleMode::Dashboard;
            }
        }
        KeyEvent::Help => {
            state.console_mode = if state.console_mode == ConsoleMode::Help {
                ConsoleMode::Dashboard
            } else {
                ConsoleMode::Help
            };
        }
        KeyEvent::ToggleLogs => {
            state.console_mode = match state.console_mode {
                ConsoleMode::Dashboard
                | ConsoleMode::Menu
                | ConsoleMode::Placeholder(_)
                | ConsoleMode::Help
                | ConsoleMode::ConfirmQuit => ConsoleMode::LogView,
                ConsoleMode::LogView | ConsoleMode::ShuttingDown => ConsoleMode::Dashboard,
            };
        }
        KeyEvent::Other => {
            if state.console_mode == ConsoleMode::Help
                || state.console_mode == ConsoleMode::ConfirmQuit
            {
                state.console_mode = ConsoleMode::Dashboard;
            }
        }
        KeyEvent::ForceQuit | KeyEvent::Reload | KeyEvent::Open => {}
    }

    false
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
        state_event => {
            let mut snapshot = state.write().await;
            return Ok(handle_console_state(state_event, &mut snapshot));
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
        runtime::state::{ConsoleMode, Metrics, Page, SharedState},
    };
    use std::sync::Arc;
    use tokio::sync::{watch, RwLock};

    async fn handle_key(
        event: KeyEvent,
        state: SharedState,
        data_dir: std::path::PathBuf,
        root_tx: &watch::Sender<Arc<std::path::Path>>,
    ) -> bool {
        handle(
            event,
            &Config::default(),
            state,
            Arc::new(Metrics::new()),
            data_dir,
            root_tx,
        )
        .await
        .expect("handle key")
    }

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

    #[tokio::test]
    async fn menu_opens_from_dashboard_and_navigation_updates_selection() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let state: SharedState = Arc::new(RwLock::new(crate::runtime::state::AppState::new()));
        let (root_tx, _root_rx) = watch::channel(Arc::from(tmp.path()));

        let quit = handle_key(
            KeyEvent::Menu,
            Arc::clone(&state),
            tmp.path().to_path_buf(),
            &root_tx,
        )
        .await;
        assert!(!quit);
        assert_eq!(state.read().await.console_mode, ConsoleMode::Menu);

        handle_key(
            KeyEvent::NavigateDown,
            Arc::clone(&state),
            tmp.path().to_path_buf(),
            &root_tx,
        )
        .await;
        assert_eq!(state.read().await.menu_selected, 1);

        handle_key(
            KeyEvent::NavigateUp,
            Arc::clone(&state),
            tmp.path().to_path_buf(),
            &root_tx,
        )
        .await;
        assert_eq!(state.read().await.menu_selected, 0);
    }

    #[tokio::test]
    async fn enter_opens_selected_menu_page_and_escape_returns() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let state: SharedState = Arc::new(RwLock::new(crate::runtime::state::AppState::new()));
        let (root_tx, _root_rx) = watch::channel(Arc::from(tmp.path()));

        handle_key(
            KeyEvent::Menu,
            Arc::clone(&state),
            tmp.path().to_path_buf(),
            &root_tx,
        )
        .await;
        handle_key(
            KeyEvent::OpenSelected,
            Arc::clone(&state),
            tmp.path().to_path_buf(),
            &root_tx,
        )
        .await;
        assert_eq!(
            state.read().await.console_mode,
            ConsoleMode::Placeholder(Page::Doctor)
        );

        handle_key(
            KeyEvent::Back,
            Arc::clone(&state),
            tmp.path().to_path_buf(),
            &root_tx,
        )
        .await;
        assert_eq!(state.read().await.console_mode, ConsoleMode::Menu);

        handle_key(
            KeyEvent::Back,
            Arc::clone(&state),
            tmp.path().to_path_buf(),
            &root_tx,
        )
        .await;
        assert_eq!(state.read().await.console_mode, ConsoleMode::Dashboard);
    }

    #[tokio::test]
    async fn logs_key_still_opens_existing_log_view() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let state: SharedState = Arc::new(RwLock::new(crate::runtime::state::AppState::new()));
        let (root_tx, _root_rx) = watch::channel(Arc::from(tmp.path()));

        handle_key(
            KeyEvent::ToggleLogs,
            Arc::clone(&state),
            tmp.path().to_path_buf(),
            &root_tx,
        )
        .await;
        assert_eq!(state.read().await.console_mode, ConsoleMode::LogView);
    }

    #[tokio::test]
    async fn menu_placeholder_items_open_matching_placeholder_pages() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let state: SharedState = Arc::new(RwLock::new(crate::runtime::state::AppState::new()));
        let (root_tx, _root_rx) = watch::channel(Arc::from(tmp.path()));

        for (selected, page) in Page::MENU_ITEMS.iter().copied().enumerate() {
            {
                let mut snapshot = state.write().await;
                snapshot.console_mode = ConsoleMode::Menu;
                snapshot.menu_selected = selected;
            }
            handle_key(
                KeyEvent::OpenSelected,
                Arc::clone(&state),
                tmp.path().to_path_buf(),
                &root_tx,
            )
            .await;
            assert_eq!(
                state.read().await.console_mode,
                ConsoleMode::Placeholder(page)
            );
        }
    }
}
