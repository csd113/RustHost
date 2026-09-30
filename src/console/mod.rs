//! # Console Module
//! Manages the interactive terminal UI: raw-mode setup, render loop, and
//! key input.
//!
//! Sub-modules:
//! - [`dashboard`] — formats the dashboard and help screen strings
//! - [`input`]     — spawns the key-reading task
//!
//! # Architecture
//!
//! Two concurrent tasks are spawned:
//! 1. **Render task** — wakes on a `tokio::time::interval` tick, reads
//!    [`SharedState`] under a brief lock, formats the appropriate screen,
//!    and writes it to stdout in a single flush.
//! 2. **Input task** — runs in `tokio::task::spawn_blocking` (since
//!    crossterm key reading is blocking), polls for key events, and sends
//!    them over a bounded channel to the event dispatch loop in
//!    [`crate::runtime::lifecycle`].

pub mod dashboard;
pub mod input;
pub mod menu;
pub mod ui;

use std::{
    io::{stdout, Write as _},
    path::PathBuf,
    sync::Arc,
};

use crossterm::{cursor, execute, terminal};
use tokio::sync::watch;

use crate::{
    config::Config,
    runtime::{
        events::KeyEvent,
        state::{ConsoleMode, SharedMetrics, SharedState},
    },
    AppError, Result,
};

// ─── Global raw-mode flag ────────────────────────────────────────────────────

/// Set to `true` after raw mode is enabled so [`cleanup`] can safely
/// restore the terminal even from the panic handler in `main`.
static RAW_MODE_ACTIVE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

// ─── Entry point ─────────────────────────────────────────────────────────────

/// Enter raw mode and spawn the render + input tasks.
///
/// Returns the receiver end of the key-event channel. The lifecycle loop
/// reads from this channel to dispatch events.
///
/// Note: not `async` — all awaits live inside the spawned tasks.
///
/// # Errors
///
/// Returns [`AppError::Console`] if the terminal cannot be put into raw mode
/// or the alternate screen cannot be entered.
pub fn start(
    config: Arc<Config>,
    state: SharedState,
    metrics: SharedMetrics,
    mut shutdown: watch::Receiver<bool>,
    data_dir: PathBuf,
) -> Result<(
    tokio::sync::mpsc::Receiver<KeyEvent>,
    Arc<tokio::sync::Notify>,
)> {
    // crossterm 0.27+ enables Windows VT (Virtual Terminal) processing
    // automatically — no manual call needed.

    terminal::enable_raw_mode()
        .map_err(|e| AppError::Console(format!("Failed to enable raw mode: {e}")))?;
    // Mark raw mode active before any fallible terminal escape so `cleanup`
    // can always restore the terminal if we bail out below.
    RAW_MODE_ACTIVE.store(true, std::sync::atomic::Ordering::SeqCst);
    if let Err(e) = execute!(stdout(), terminal::EnterAlternateScreen, cursor::Hide) {
        let _ = execute!(stdout(), cursor::Show);
        let _ = terminal::disable_raw_mode();
        RAW_MODE_ACTIVE.store(false, std::sync::atomic::Ordering::SeqCst);
        return Err(AppError::Console(format!(
            "Failed to enter alternate screen: {e}"
        )));
    }

    execute!(
        stdout(),
        terminal::Clear(terminal::ClearType::All),
        cursor::MoveTo(0, 0)
    )
    .map_err(|e| AppError::Console(format!("Failed to clear screen: {e}")))?;

    // ── Key event channel ─────────────────────────────────────────────────────
    let (key_tx, key_rx) = tokio::sync::mpsc::channel::<KeyEvent>(64);

    // Render wake-up: pulsed after a handled key event and on terminal resize
    // so the screen reflects input immediately instead of waiting for the tick.
    let render_notify = Arc::new(tokio::sync::Notify::new());

    // ── Input task (blocking thread) ──────────────────────────────────────────
    input::spawn(key_tx, shutdown.clone(), Arc::clone(&render_notify));

    // ── Render task ───────────────────────────────────────────────────────────
    let rate = config.console.refresh_rate_ms;
    let task_notify = Arc::clone(&render_notify);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_millis(rate));
        let mut last_rendered = String::new();
        let mut last_size: Option<(u16, u16)> = None;

        loop {
            tokio::select! {
                _ = interval.tick() => {}
                () = task_notify.notified() => {}
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() { break; }
                    continue;
                }
            }
            if let Err(e) = render(
                &config,
                &state,
                &metrics,
                &data_dir,
                &mut last_rendered,
                &mut last_size,
            )
            .await
            {
                log::debug!("Render error: {e}");
            }
        }
    });

    Ok((key_rx, render_notify))
}

// ─── Render ───────────────────────────────────────────────────────────────────

async fn render(
    config: &Config,
    state: &SharedState,
    metrics: &SharedMetrics,
    data_dir: &std::path::Path,
    last_rendered: &mut String,
    last_size: &mut Option<(u16, u16)>,
) -> Result<()> {
    // Format the frame while holding a single read guard, then release it
    // before any terminal I/O. Cloning the whole `AppState` (including cached
    // page reports) per frame is wasteful, and holding the lock across stdout
    // writes would block key handling behind terminal I/O.
    let output = {
        let snapshot = state.read().await;
        match &snapshot.console_mode {
            ConsoleMode::Dashboard => {
                let metrics = metrics.snapshot();
                dashboard::render_dashboard(&snapshot, metrics, config, data_dir)
            }
            ConsoleMode::Menu => menu::render(&snapshot.menu, config, &snapshot, data_dir),
            ConsoleMode::LogView => dashboard::render_log_view(config.console.show_timestamps),
            ConsoleMode::Help => dashboard::render_help(),
            ConsoleMode::ConfirmQuit => dashboard::render_confirm_quit(),
            ConsoleMode::ShuttingDown => dashboard::render_shutdown(config.tor.enabled),
        }
    };

    // A cleanup racing this tick must not write escape sequences over the
    // restored terminal.
    if !RAW_MODE_ACTIVE.load(std::sync::atomic::Ordering::SeqCst) {
        return Ok(());
    }

    // Force a repaint when the terminal size changed: the frame string may be
    // identical, but previously drawn content can be reflowed or stale.
    let size = terminal::size().ok();
    let resized = size.is_some() && *last_size != size;
    *last_size = size;

    // Skip terminal I/O when the frame is unchanged to avoid needless redraws.
    if !resized && output == *last_rendered {
        return Ok(());
    }
    last_rendered.clone_from(&output);

    let mut out = stdout();
    execute!(
        out,
        cursor::MoveTo(0, 0),
        terminal::Clear(terminal::ClearType::FromCursorDown)
    )
    .map_err(|e| AppError::Console(format!("Terminal write error: {e}")))?;
    out.write_all(output.as_bytes())
        .map_err(|e| AppError::Console(format!("stdout write error: {e}")))?;
    out.flush()
        .map_err(|e| AppError::Console(format!("stdout flush error: {e}")))?;

    Ok(())
}
// ─── Cleanup ──────────────────────────────────────────────────────────────────

/// Restore the terminal to its original state.
///
/// Safe to call multiple times. Called from the lifecycle shutdown sequence
/// and from `main`'s panic handler.
pub fn cleanup() {
    if RAW_MODE_ACTIVE.swap(false, std::sync::atomic::Ordering::SeqCst) {
        let _ = execute!(stdout(), cursor::Show, terminal::LeaveAlternateScreen);
        let _ = terminal::disable_raw_mode();
        let _ = writeln!(stdout());
    }
}

/// Replace the current frame with an explicit shutdown-in-progress message.
pub fn show_shutdown_message(tor_enabled: bool) {
    if !RAW_MODE_ACTIVE.load(std::sync::atomic::Ordering::SeqCst) {
        return;
    }

    let output = dashboard::render_shutdown(tor_enabled);
    let mut out = stdout();
    let _ = execute!(
        out,
        cursor::MoveTo(0, 0),
        terminal::Clear(terminal::ClearType::FromCursorDown)
    );
    let _ = out.write_all(output.as_bytes());
    let _ = out.flush();
}
