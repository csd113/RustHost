//! # Key Event Dispatch

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use crate::{
    config::Config,
    console::menu::MenuOpenTarget,
    console::menu::{self, tor::TorAction, DoctorContext, DoctorLiveState, Page},
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

/// Prepare and publish one site generation shared by all listeners.
///
/// # Errors
///
/// Preparation failures are reported through logs and status; the active site
/// is preserved. The result remains `Ok(())` so operators can retry without
/// terminating the service.
pub async fn reload_site(
    config: &Config,
    state: SharedState,
    data_dir: PathBuf,
    root_tx: &tokio::sync::watch::Sender<std::sync::Arc<crate::server::SiteSnapshot>>,
) -> Result<()> {
    let previous = Arc::clone(&root_tx.borrow());
    let config = config.clone();
    let prepared =
        tokio::task::spawn_blocking(move || server::SiteSnapshot::prepare(&config, &data_dir))
            .await
            .map_err(|e| e.to_string())
            .and_then(|result| result.map_err(|e| e.to_string()));
    let next = match prepared {
        Ok(next) => next,
        Err(message) => {
            log::warn!("Site reload failed: {message}");
            state.write().await.status_message = Some(StatusMessage::persistent(format!(
                "Reload failed: {message}"
            )));
            return Ok(());
        }
    };
    let mut state = state.write().await;
    // A concurrently completed reload must not be overwritten by older work.
    // Cancellation before this synchronous publication leaves the old site intact.
    let published = root_tx.send_if_modified(|current| {
        if !Arc::ptr_eq(current, &previous) {
            return false;
        }
        *current = Arc::clone(&next);
        true
    });
    if published {
        state.site_file_count = next.file_count;
        state.site_total_bytes = next.total_bytes;
        state.status_message = Some(StatusMessage::temporary(
            format!(
                "Reload complete: {} files, {}",
                next.file_count,
                crate::runtime::state::format_bytes(next.total_bytes)
            ),
            RELOAD_STATUS_DURATION,
        ));
    } else {
        state.status_message = Some(StatusMessage::persistent(
            "Reload superseded by another completed reload",
        ));
    }
    drop(state);
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
    if state.menu.active_page() == Some(Page::Help) {
        state.menu.open_help_topic();
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

/// Return the active menu page if it still needs its cached report built.
fn page_needing_initialization(snapshot: &AppState) -> Option<Page> {
    let page = snapshot.menu.active_page()?;
    let needs_report = match page {
        Page::Doctor => snapshot.menu.doctor().report().is_none(),
        Page::Diagnostics => snapshot.menu.diagnostics().report().is_none(),
        Page::Network => snapshot.menu.network().report().is_none(),
        Page::Site => snapshot.menu.site().report().is_none(),
        Page::Home | Page::Logs | Page::Tor | Page::Settings | Page::Help => false,
    };
    needs_report.then_some(page)
}

/// Build the cached report for `page`.
///
/// These checks perform synchronous filesystem scans and bounded TCP probes, so
/// callers run this on the blocking pool rather than an async worker.
fn build_page_initialization(
    page: Page,
    config: &Config,
    snapshot: &AppState,
    data_dir: &std::path::Path,
    settings_path: Option<&std::path::Path>,
) -> Option<PageInitialization> {
    match page {
        Page::Doctor => Some(PageInitialization::Doctor(run_tui_fast_doctor(
            config,
            data_dir,
            settings_path,
            live_doctor_state(snapshot),
        ))),
        Page::Diagnostics => Some(PageInitialization::Diagnostics(
            menu::diagnostics::build_report(config, snapshot, data_dir, settings_path),
        )),
        Page::Network => Some(PageInitialization::Network(menu::network::collect_report(
            config, snapshot, data_dir,
        ))),
        Page::Site => Some(PageInitialization::Site(menu::site::collect_report(
            data_dir, config,
        ))),
        Page::Home | Page::Logs | Page::Tor | Page::Settings | Page::Help => None,
    }
}

enum PageInitialization {
    Doctor(menu::DoctorReport),
    Diagnostics(menu::diagnostics::DiagnosticsReport),
    Network(menu::network::NetworkReport),
    Site(menu::site::SiteReport),
}

fn apply_page_initialization(state: &mut AppState, initialization: PageInitialization) {
    match initialization {
        PageInitialization::Doctor(report) => state.menu.set_doctor_report(report),
        PageInitialization::Diagnostics(report) => state.menu.set_diagnostics_report(report),
        PageInitialization::Network(report) => state.menu.set_network_report(report),
        PageInitialization::Site(report) => state.menu.set_site_report(report),
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
            let config = config.clone();
            let data_dir = data_dir.to_path_buf();
            let settings_path = settings_path.map(std::path::Path::to_path_buf);
            let report = match tokio::task::spawn_blocking(move || {
                run_tui_fast_doctor(&config, &data_dir, settings_path.as_deref(), live)
            })
            .await
            {
                Ok(report) => report,
                Err(e) => {
                    log::warn!("Doctor report task failed: {e}");
                    return Some(false);
                }
            };
            state.write().await.menu.set_doctor_report(report);
            Some(false)
        }
        KeyEvent::RunDoctorDeep => {
            let needs_report = state.read().await.menu.doctor().report().is_none();
            let config = config.clone();
            let data_dir = data_dir.to_path_buf();
            let settings_path = settings_path.map(std::path::Path::to_path_buf);
            let (deep, seed_report) = match tokio::task::spawn_blocking(move || {
                let deep = menu::doctor::run_deep_checks(&config, &data_dir, live);
                let seed = needs_report.then(|| {
                    run_tui_fast_doctor(&config, &data_dir, settings_path.as_deref(), live)
                });
                (deep, seed)
            })
            .await
            {
                Ok(result) => result,
                Err(e) => {
                    log::warn!("Deep doctor task failed: {e}");
                    return Some(false);
                }
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
            let config = config.clone();
            let data_dir = data_dir.to_path_buf();
            let settings_path = settings_path.map(std::path::Path::to_path_buf);
            let report = match tokio::task::spawn_blocking(move || {
                menu::diagnostics::build_report(
                    &config,
                    &snapshot,
                    &data_dir,
                    settings_path.as_deref(),
                )
            })
            .await
            {
                Ok(report) => report,
                Err(e) => {
                    log::warn!("Diagnostics report task failed: {e}");
                    return Some(false);
                }
            };
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

async fn handle_extra_menu_page_event(
    event: KeyEvent,
    config: &Config,
    state: SharedState,
    data_dir: &std::path::Path,
    settings_path: Option<&std::path::Path>,
) -> Option<bool> {
    let page = {
        let snapshot = state.read().await;
        if snapshot.console_mode != ConsoleMode::Menu {
            return None;
        }
        snapshot.menu.active_page()?
    };

    // Pages handled by the dedicated dispatchers above; do not clone the whole
    // AppState for them.
    if matches!(
        page,
        Page::Home | Page::Logs | Page::Doctor | Page::Diagnostics
    ) {
        return None;
    }

    let snapshot = state.read().await.clone();
    match page {
        Page::Tor => {
            handle_tor_page_event(event, config, state, snapshot, data_dir, settings_path).await
        }
        Page::Network => handle_network_page_event(event, config, state, snapshot, data_dir).await,
        Page::Site => handle_site_page_event(event, config, state, data_dir).await,
        Page::Settings => {
            handle_settings_page_event(event, config, state, snapshot, data_dir, settings_path)
                .await
        }
        Page::Help => handle_help_page_event(event, state).await,
        Page::Home | Page::Logs | Page::Doctor | Page::Diagnostics => None,
    }
}

async fn handle_tor_page_event(
    event: KeyEvent,
    config: &Config,
    state: SharedState,
    snapshot: AppState,
    data_dir: &std::path::Path,
    settings_path: Option<&std::path::Path>,
) -> Option<bool> {
    if event == KeyEvent::Reload {
        return Some(false);
    }
    if event != KeyEvent::OpenSelected {
        return None;
    }

    let action = snapshot.menu.tor().selected_action();
    match action {
        TorAction::Restart => {
            state
                .write()
                .await
                .menu
                .tor_mut()
                .set_status("Restart Tor: not supported yet");
        }
        TorAction::CopyOnion => {
            let status = menu::tor::copy_onion_status(&snapshot);
            state.write().await.menu.tor_mut().set_status(status);
        }
        TorAction::Diagnostics => {
            let config = config.clone();
            let data_dir = data_dir.to_path_buf();
            let settings_path = settings_path.map(std::path::Path::to_path_buf);
            let report = match tokio::task::spawn_blocking(move || {
                menu::diagnostics::build_report(
                    &config,
                    &snapshot,
                    &data_dir,
                    settings_path.as_deref(),
                )
            })
            .await
            {
                Ok(report) => report,
                Err(e) => {
                    log::warn!("Diagnostics report task failed: {e}");
                    return Some(false);
                }
            };
            let mut snapshot = state.write().await;
            snapshot.menu.set_diagnostics_report(report);
            snapshot.menu.open_page(Page::Diagnostics);
        }
        TorAction::BootstrapLog => {
            state.write().await.menu.tor_mut().show_bootstrap_log();
        }
        TorAction::Back => {
            let _ = state.write().await.menu.back();
        }
    }
    Some(false)
}

async fn handle_network_page_event(
    event: KeyEvent,
    config: &Config,
    state: SharedState,
    snapshot: AppState,
    data_dir: &std::path::Path,
) -> Option<bool> {
    if event != KeyEvent::Reload {
        return None;
    }
    let config = config.clone();
    let data_dir = data_dir.to_path_buf();
    let report = match tokio::task::spawn_blocking(move || {
        menu::network::collect_report(&config, &snapshot, &data_dir)
    })
    .await
    {
        Ok(report) => report,
        Err(e) => {
            log::warn!("Network report task failed: {e}");
            return Some(false);
        }
    };
    state.write().await.menu.set_network_report(report);
    Some(false)
}

async fn handle_site_page_event(
    event: KeyEvent,
    config: &Config,
    state: SharedState,
    data_dir: &std::path::Path,
) -> Option<bool> {
    if event != KeyEvent::Reload {
        return None;
    }
    let config = config.clone();
    let data_dir = data_dir.to_path_buf();
    let report =
        match tokio::task::spawn_blocking(move || menu::site::collect_report(&data_dir, &config))
            .await
        {
            Ok(report) => report,
            Err(e) => {
                log::warn!("Site report task failed: {e}");
                return Some(false);
            }
        };
    state.write().await.menu.set_site_report(report);
    Some(false)
}

async fn handle_settings_page_event(
    event: KeyEvent,
    config: &Config,
    state: SharedState,
    snapshot: AppState,
    data_dir: &std::path::Path,
    settings_path: Option<&std::path::Path>,
) -> Option<bool> {
    if event == KeyEvent::Reload {
        return Some(false);
    }
    if event != KeyEvent::CopyDiagnostics {
        return None;
    }
    let config = config.clone();
    let data_dir = data_dir.to_path_buf();
    let settings_path = settings_path.map(std::path::Path::to_path_buf);
    let report = match tokio::task::spawn_blocking(move || {
        menu::diagnostics::build_report(&config, &snapshot, &data_dir, settings_path.as_deref())
    })
    .await
    {
        Ok(report) => report,
        Err(e) => {
            log::warn!("Diagnostics report task failed: {e}");
            return Some(false);
        }
    };
    state
        .write()
        .await
        .menu
        .settings_mut()
        .set_diagnostics_text(report.text().to_owned());
    Some(false)
}

async fn handle_help_page_event(event: KeyEvent, state: SharedState) -> Option<bool> {
    if event == KeyEvent::Reload {
        return Some(false);
    }
    if event != KeyEvent::OpenSelected {
        return None;
    }
    state.write().await.menu.open_help_topic();
    Some(false)
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
    root_tx: &tokio::sync::watch::Sender<std::sync::Arc<crate::server::SiteSnapshot>>,
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

    if let Some(quit) = handle_extra_menu_page_event(
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
            // Match the active bind address so IPv6-only listeners still open.
            let url = crate::console::ui::local_http_url(config.server.bind, port);
            super::open_browser(&url);
        }
        state_event => {
            // Apply the console-mode transition under a short write lock.
            let quit = {
                let mut snapshot = state.write().await;
                handle_console_state(state_event, &mut snapshot)
            };

            // Opening a menu page may need a report built from synchronous
            // filesystem/network probes. Decide that under a short read lock,
            // then build it on the blocking pool — never while holding the
            // state lock, which would stall rendering and event handling.
            let pending = {
                let snapshot = state.read().await;
                if snapshot.console_mode == ConsoleMode::Menu {
                    page_needing_initialization(&snapshot).map(|page| (page, snapshot.clone()))
                } else {
                    None
                }
            };

            if let Some((page, snapshot)) = pending {
                let config = config.clone();
                let data_dir = data_dir.clone();
                let settings_path = settings_path.clone();
                let initialization = tokio::task::spawn_blocking(move || {
                    build_page_initialization(
                        page,
                        &config,
                        &snapshot,
                        &data_dir,
                        settings_path.as_deref(),
                    )
                })
                .await
                .map_err(|e| {
                    crate::AppError::ConfigLoad(format!("page initialization task failed: {e}"))
                })?;
                if let Some(initialization) = initialization {
                    let mut snapshot = state.write().await;
                    apply_page_initialization(&mut snapshot, initialization);
                }
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

    fn test_site(root: &std::path::Path) -> Arc<crate::server::SiteSnapshot> {
        let mut config = Config::default();
        config.site.directory = ".".into();
        crate::server::SiteSnapshot::prepare(&config, root).expect("test site snapshot")
    }

    async fn handle_key(
        event: KeyEvent,
        state: SharedState,
        data_dir: std::path::PathBuf,
        root_tx: &watch::Sender<Arc<crate::server::SiteSnapshot>>,
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

    async fn open_menu_page(
        page: Page,
        state: SharedState,
        data_dir: std::path::PathBuf,
        root_tx: &watch::Sender<Arc<crate::server::SiteSnapshot>>,
    ) {
        {
            let mut snapshot = state.write().await;
            snapshot.console_mode = ConsoleMode::Menu;
            snapshot.menu.enter();
            while snapshot.menu.selected_page() != page {
                snapshot.menu.move_down();
            }
            drop(snapshot);
        }
        handle_key(KeyEvent::OpenSelected, state, data_dir, root_tx).await;
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
        let (root_tx, _root_rx) = watch::channel(
            crate::server::SiteSnapshot::prepare(&config, &data_dir).expect("site snapshot"),
        );

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
        let (root_tx, _root_rx) = watch::channel(test_site(tmp.path()));

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
        let (root_tx, _root_rx) = watch::channel(test_site(tmp.path()));

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
        let (root_tx, _root_rx) = watch::channel(test_site(tmp.path()));

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
        let (root_tx, _root_rx) = watch::channel(test_site(tmp.path()));

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
        let (root_tx, _root_rx) = watch::channel(test_site(tmp.path()));

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
        let (root_tx, _root_rx) = watch::channel(test_site(tmp.path()));

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
        let (root_tx, _root_rx) = watch::channel(test_site(tmp.path()));

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

    #[tokio::test]
    async fn new_nested_menu_pages_escape_back_and_do_not_quit() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let state: SharedState = Arc::new(RwLock::new(crate::runtime::state::AppState::new()));
        let (root_tx, _root_rx) = watch::channel(test_site(tmp.path()));

        for page in [
            Page::Tor,
            Page::Network,
            Page::Site,
            Page::Settings,
            Page::Help,
        ] {
            open_menu_page(page, Arc::clone(&state), tmp.path().to_path_buf(), &root_tx).await;
            assert_eq!(state.read().await.menu.active_page(), Some(page));

            let quit = handle_key(
                KeyEvent::Quit,
                Arc::clone(&state),
                tmp.path().to_path_buf(),
                &root_tx,
            )
            .await;
            assert!(!quit);
            assert_eq!(state.read().await.menu.active_page(), Some(page));

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
        }
    }

    #[tokio::test]
    async fn tor_restart_action_is_non_mutating() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let state: SharedState = Arc::new(RwLock::new(crate::runtime::state::AppState::new()));
        let (root_tx, _root_rx) = watch::channel(test_site(tmp.path()));

        {
            let mut snapshot = state.write().await;
            snapshot.tor_status = crate::runtime::state::TorStatus::Ready;
            snapshot.onion_address = Some("abcdefghijklmnop.onion".to_owned());
        }

        open_menu_page(
            Page::Tor,
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

        let snapshot = state.read().await;
        assert_eq!(snapshot.tor_status, crate::runtime::state::TorStatus::Ready);
        assert_eq!(
            snapshot.onion_address.as_deref(),
            Some("abcdefghijklmnop.onion")
        );
        assert_eq!(snapshot.menu.active_page(), Some(Page::Tor));
        drop(snapshot);
    }
}
