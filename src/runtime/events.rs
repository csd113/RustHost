//! # Key Event Dispatch

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use crate::{
    config::Config,
    console::menu::MenuOpenTarget,
    console::menu::{self, DoctorContext, DoctorLiveState, Page},
    runtime::state::{AppState, ConsoleMode, SharedMetrics, SharedState, StatusMessage},
    server, Result,
};

const RELOAD_STATUS_DURATION: Duration = Duration::from_secs(3);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyEvent {
    Help,
    Menu,
    CopyDiagnostics,
    Reload,
    ClearStatus,
    RunDoctorDeep,
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
            if state.console_mode == ConsoleMode::Dashboard {
                state.console_mode = ConsoleMode::ConfirmQuit;
            } else if state.console_mode == ConsoleMode::Menu && !state.menu.has_active_page() {
                state.menu.leave();
                state.console_mode = ConsoleMode::ConfirmQuit;
            }
        }
        KeyEvent::Back => {
            state.console_mode = match state.console_mode {
                ConsoleMode::Menu => {
                    if state.menu.back() {
                        ConsoleMode::Menu
                    } else {
                        state.menu.leave();
                        ConsoleMode::Dashboard
                    }
                }
                ConsoleMode::Help | ConsoleMode::LogView | ConsoleMode::ConfirmQuit => {
                    ConsoleMode::Dashboard
                }
                ConsoleMode::Dashboard => ConsoleMode::ConfirmQuit,
                ConsoleMode::ShuttingDown => ConsoleMode::ShuttingDown,
            };
        }
        KeyEvent::Menu => {
            if state.console_mode == ConsoleMode::Dashboard {
                state.menu.enter();
                state.console_mode = ConsoleMode::Menu;
            }
        }
        KeyEvent::NavigateUp => {
            if state.console_mode == ConsoleMode::Menu {
                state.menu.move_up();
            }
        }
        KeyEvent::NavigateDown => {
            if state.console_mode == ConsoleMode::Menu {
                state.menu.move_down();
            }
        }
        KeyEvent::OpenSelected => {
            if state.console_mode == ConsoleMode::Menu {
                handle_menu_open_selected(state);
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
            if state.console_mode == ConsoleMode::Menu {
                state.menu.leave();
            }
            state.console_mode = if state.console_mode == ConsoleMode::Help {
                ConsoleMode::Dashboard
            } else {
                ConsoleMode::Help
            };
        }
        KeyEvent::ToggleLogs => {
            if state.console_mode == ConsoleMode::Menu {
                state.menu.leave();
            }
            state.console_mode = match state.console_mode {
                ConsoleMode::Dashboard
                | ConsoleMode::Menu
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
        KeyEvent::ForceQuit
        | KeyEvent::CopyDiagnostics
        | KeyEvent::Reload
        | KeyEvent::ClearStatus
        | KeyEvent::RunDoctorDeep
        | KeyEvent::Open => {}
    }

    false
}

fn handle_menu_open_selected(state: &mut AppState) {
    if state.menu.active_page() == Some(Page::Doctor) {
        state.menu.toggle_doctor_section();
        return;
    }
    match state.menu.open_selected() {
        MenuOpenTarget::Dashboard => {
            state.menu.leave();
            state.console_mode = ConsoleMode::Dashboard;
        }
        MenuOpenTarget::LogView => {
            state.menu.leave();
            state.console_mode = ConsoleMode::LogView;
        }
        MenuOpenTarget::Page(_page) => {}
    }
}

const fn live_doctor_state(state: &AppState) -> DoctorLiveState {
    DoctorLiveState {
        server_running: state.server_running,
        actual_port: state.actual_port,
        tls_running: state.tls_running,
        tls_port: state.tls_port,
    }
}

fn run_tui_fast_doctor(
    config: &Config,
    data_dir: &std::path::Path,
    settings_path: Option<&std::path::Path>,
    live: DoctorLiveState,
) -> menu::DoctorReport {
    let mut report = menu::doctor::run_fast_doctor_for_loaded_config(
        data_dir,
        settings_path,
        config,
        DoctorContext::TuiLive(live),
    );
    menu::doctor::append_deep_checks(&mut report, menu::doctor::deep_checks_not_run_section());
    menu::doctor::write_doctor_log(&mut report);
    report
}

async fn handle_doctor_page_event(
    event: KeyEvent,
    config: &Config,
    state: SharedState,
    data_dir: &std::path::Path,
    settings_path: Option<&std::path::Path>,
) -> Option<bool> {
    let live = {
        let snapshot = state.read().await;
        if snapshot.console_mode != ConsoleMode::Menu
            || snapshot.menu.active_page() != Some(Page::Doctor)
        {
            return None;
        }
        let live = live_doctor_state(&snapshot);
        drop(snapshot);
        live
    };

    match event {
        KeyEvent::Reload => {
            let report = run_tui_fast_doctor(config, data_dir, settings_path, live);
            state.write().await.menu.set_doctor_report(report);
            Some(false)
        }
        KeyEvent::RunDoctorDeep => {
            let deep = menu::doctor::run_deep_checks(config, data_dir, live);
            let needs_report = {
                let snapshot = state.read().await;
                let needs_report = snapshot.menu.doctor().report().is_none();
                drop(snapshot);
                needs_report
            };
            let seed_report = if needs_report {
                Some(run_tui_fast_doctor(config, data_dir, settings_path, live))
            } else {
                None
            };
            let mut snapshot = state.write().await;
            if let Some(report) = seed_report {
                snapshot.menu.set_doctor_report(report);
            }
            if let Some(existing) = snapshot.menu.doctor().report().cloned() {
                let mut report = existing;
                menu::doctor::append_deep_checks(&mut report, deep);
                snapshot.menu.set_doctor_report(report);
            }
            drop(snapshot);
            Some(false)
        }
        KeyEvent::OpenSelected => {
            state.write().await.menu.toggle_doctor_section();
            Some(false)
        }
        _ => None,
    }
}

async fn handle_diagnostics_page_event(
    event: KeyEvent,
    config: &Config,
    state: SharedState,
    data_dir: &std::path::Path,
    settings_path: Option<&std::path::Path>,
) -> Option<bool> {
    let snapshot = {
        let snapshot = state.read().await;
        if snapshot.console_mode != ConsoleMode::Menu
            || snapshot.menu.active_page() != Some(Page::Diagnostics)
        {
            return None;
        }
        snapshot.clone()
    };

    match event {
        KeyEvent::CopyDiagnostics => {
            state.write().await.menu.set_diagnostics_status(
                "Clipboard support unavailable; select and copy the diagnostics text.",
            );
            Some(false)
        }
        KeyEvent::Reload => {
            let report =
                menu::diagnostics::build_report(config, &snapshot, data_dir, settings_path);
            let mut snapshot = state.write().await;
            snapshot.menu.set_diagnostics_report(report);
            snapshot
                .menu
                .set_diagnostics_status("Diagnostics refreshed.");
            drop(snapshot);
            Some(false)
        }
        KeyEvent::ClearStatus => {
            state.write().await.menu.clear_diagnostics_status();
            Some(false)
        }
        KeyEvent::Quit => Some(false),
        _ => None,
    }
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
    settings_path: Option<PathBuf>,
    root_tx: &tokio::sync::watch::Sender<std::sync::Arc<std::path::Path>>,
) -> Result<bool> {
    if let Some(quit) = handle_diagnostics_page_event(
        event,
        config,
        Arc::clone(&state),
        &data_dir,
        settings_path.as_deref(),
    )
    .await
    {
        return Ok(quit);
    }

    if let Some(quit) = handle_doctor_page_event(
        event,
        config,
        Arc::clone(&state),
        &data_dir,
        settings_path.as_deref(),
    )
    .await
    {
        return Ok(quit);
    }

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
            let quit = handle_console_state(state_event, &mut snapshot);
            let should_initialize_doctor = snapshot.console_mode == ConsoleMode::Menu
                && snapshot.menu.active_page() == Some(Page::Doctor)
                && snapshot.menu.doctor().report().is_none();
            let should_initialize_diagnostics = snapshot.console_mode == ConsoleMode::Menu
                && snapshot.menu.active_page() == Some(Page::Diagnostics)
                && snapshot.menu.diagnostics().report().is_none();
            let live = live_doctor_state(&snapshot);
            let diagnostics_snapshot = if should_initialize_diagnostics {
                Some(snapshot.clone())
            } else {
                None
            };
            drop(snapshot);
            if should_initialize_doctor {
                let report = run_tui_fast_doctor(config, &data_dir, settings_path.as_deref(), live);
                state.write().await.menu.set_doctor_report(report);
            }
            if let Some(snapshot) = diagnostics_snapshot {
                let report = menu::diagnostics::build_report(
                    config,
                    &snapshot,
                    &data_dir,
                    settings_path.as_deref(),
                );
                state.write().await.menu.set_diagnostics_report(report);
            }
            return Ok(quit);
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
        console::menu::Page,
        runtime::state::{ConsoleMode, Metrics, SharedState},
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
            None,
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
            None,
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
            None,
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
        assert_eq!(state.read().await.menu.selected_index(), 1);

        handle_key(
            KeyEvent::NavigateUp,
            Arc::clone(&state),
            tmp.path().to_path_buf(),
            &root_tx,
        )
        .await;
        assert_eq!(state.read().await.menu.selected_index(), 0);
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
            KeyEvent::NavigateDown,
            Arc::clone(&state),
            tmp.path().to_path_buf(),
            &root_tx,
        )
        .await;
        handle_key(
            KeyEvent::NavigateDown,
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
        assert_eq!(state.read().await.menu.active_page(), Some(Page::Doctor));
        assert_eq!(state.read().await.console_mode, ConsoleMode::Menu);

        handle_key(
            KeyEvent::Back,
            Arc::clone(&state),
            tmp.path().to_path_buf(),
            &root_tx,
        )
        .await;
        let snapshot = state.read().await;
        assert_eq!(snapshot.console_mode, ConsoleMode::Menu);
        assert_eq!(snapshot.menu.active_page(), None);
        drop(snapshot);

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
    async fn quit_is_limited_to_dashboard_and_top_level_menu() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let state: SharedState = Arc::new(RwLock::new(crate::runtime::state::AppState::new()));
        let (root_tx, _root_rx) = watch::channel(Arc::from(tmp.path()));

        let quit = handle_key(
            KeyEvent::Quit,
            Arc::clone(&state),
            tmp.path().to_path_buf(),
            &root_tx,
        )
        .await;
        assert!(!quit);
        assert_eq!(state.read().await.console_mode, ConsoleMode::ConfirmQuit);

        state.write().await.console_mode = ConsoleMode::Dashboard;
        handle_key(
            KeyEvent::Menu,
            Arc::clone(&state),
            tmp.path().to_path_buf(),
            &root_tx,
        )
        .await;
        handle_key(
            KeyEvent::Quit,
            Arc::clone(&state),
            tmp.path().to_path_buf(),
            &root_tx,
        )
        .await;
        assert_eq!(state.read().await.console_mode, ConsoleMode::ConfirmQuit);

        {
            let mut snapshot = state.write().await;
            snapshot.console_mode = ConsoleMode::Menu;
            snapshot.menu.enter();
            while snapshot.menu.selected_page() != Page::Doctor {
                snapshot.menu.move_down();
            }
            drop(snapshot);
        }
        handle_key(
            KeyEvent::OpenSelected,
            Arc::clone(&state),
            tmp.path().to_path_buf(),
            &root_tx,
        )
        .await;
        let quit = handle_key(
            KeyEvent::Quit,
            Arc::clone(&state),
            tmp.path().to_path_buf(),
            &root_tx,
        )
        .await;
        let snapshot = state.read().await;
        assert!(!quit);
        assert_eq!(snapshot.console_mode, ConsoleMode::Menu);
        assert_eq!(snapshot.menu.active_page(), Some(Page::Doctor));
        drop(snapshot);

        {
            let mut snapshot = state.write().await;
            let _ = snapshot.menu.back();
            while snapshot.menu.selected_page() != Page::Diagnostics {
                snapshot.menu.move_down();
            }
            drop(snapshot);
        }
        handle_key(
            KeyEvent::OpenSelected,
            Arc::clone(&state),
            tmp.path().to_path_buf(),
            &root_tx,
        )
        .await;
        let quit = handle_key(
            KeyEvent::Quit,
            Arc::clone(&state),
            tmp.path().to_path_buf(),
            &root_tx,
        )
        .await;
        let snapshot = state.read().await;
        assert!(!quit);
        assert_eq!(snapshot.console_mode, ConsoleMode::Menu);
        assert_eq!(snapshot.menu.active_page(), Some(Page::Diagnostics));
        drop(snapshot);

        state.write().await.console_mode = ConsoleMode::LogView;
        let quit = handle_key(
            KeyEvent::Quit,
            Arc::clone(&state),
            tmp.path().to_path_buf(),
            &root_tx,
        )
        .await;
        assert!(!quit);
        assert_eq!(state.read().await.console_mode, ConsoleMode::LogView);
    }

    #[tokio::test]
    async fn diagnostics_page_controls_are_page_local() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let state: SharedState = Arc::new(RwLock::new(crate::runtime::state::AppState::new()));
        let (root_tx, _root_rx) = watch::channel(Arc::from(tmp.path()));

        {
            let mut snapshot = state.write().await;
            snapshot.console_mode = ConsoleMode::Menu;
            snapshot.menu.enter();
            while snapshot.menu.selected_page() != Page::Diagnostics {
                snapshot.menu.move_down();
            }
            drop(snapshot);
        }
        handle_key(
            KeyEvent::OpenSelected,
            Arc::clone(&state),
            tmp.path().to_path_buf(),
            &root_tx,
        )
        .await;
        assert!(state.read().await.menu.diagnostics().report().is_some());

        handle_key(
            KeyEvent::CopyDiagnostics,
            Arc::clone(&state),
            tmp.path().to_path_buf(),
            &root_tx,
        )
        .await;
        assert!(state
            .read()
            .await
            .menu
            .diagnostics()
            .status()
            .is_some_and(|status| status.contains("Clipboard support unavailable")));

        handle_key(
            KeyEvent::ClearStatus,
            Arc::clone(&state),
            tmp.path().to_path_buf(),
            &root_tx,
        )
        .await;
        assert!(state.read().await.menu.diagnostics().status().is_none());
    }

    #[tokio::test]
    async fn menu_placeholder_items_open_matching_placeholder_pages() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let state: SharedState = Arc::new(RwLock::new(crate::runtime::state::AppState::new()));
        let (root_tx, _root_rx) = watch::channel(Arc::from(tmp.path()));

        for (selected, page) in Page::ALL.iter().copied().enumerate() {
            {
                let mut snapshot = state.write().await;
                snapshot.console_mode = ConsoleMode::Menu;
                snapshot.menu.enter();
                while snapshot.menu.selected_index() != selected {
                    snapshot.menu.move_down();
                }
                drop(snapshot);
            }
            handle_key(
                KeyEvent::OpenSelected,
                Arc::clone(&state),
                tmp.path().to_path_buf(),
                &root_tx,
            )
            .await;
            let (console_mode, active_page) = {
                let snapshot = state.read().await;
                (snapshot.console_mode.clone(), snapshot.menu.active_page())
            };
            match page {
                Page::Home => {
                    assert_eq!(console_mode, ConsoleMode::Dashboard);
                    assert_eq!(active_page, None);
                }
                Page::Logs => {
                    assert_eq!(console_mode, ConsoleMode::LogView);
                    assert_eq!(active_page, None);
                }
                _ => {
                    assert_eq!(console_mode, ConsoleMode::Menu);
                    assert_eq!(active_page, Some(page));
                }
            }
        }
    }
}
