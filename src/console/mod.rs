//! # Console Module
//!
//! **Directory:** `src/console/`
//!
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
//!    them over an unbounded channel to the event dispatch loop in
//!    [`crate::runtime::lifecycle`].

pub mod dashboard;
pub mod input;

use std::{
    io::{stdout, Write},
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
) -> Result<tokio::sync::mpsc::UnboundedReceiver<KeyEvent>> {
    // crossterm 0.27+ enables Windows VT (Virtual Terminal) processing
    // automatically — no manual call needed.

    // 4.1 — map crossterm io errors to AppError::Console.
    terminal::enable_raw_mode()
        .map_err(|e| AppError::Console(format!("Failed to enable raw mode: {e}")))?;
    execute!(stdout(), terminal::EnterAlternateScreen, cursor::Hide)
        .map_err(|e| AppError::Console(format!("Failed to enter alternate screen: {e}")))?;
    RAW_MODE_ACTIVE.store(true, std::sync::atomic::Ordering::SeqCst);

    execute!(
        stdout(),
        terminal::Clear(terminal::ClearType::All),
        cursor::MoveTo(0, 0)
    )
    .map_err(|e| AppError::Console(format!("Failed to clear screen: {e}")))?;

    // ── Key event channel ─────────────────────────────────────────────────────
    let (key_tx, key_rx) = tokio::sync::mpsc::unbounded_channel::<KeyEvent>();

    // ── Input task (blocking thread) ──────────────────────────────────────────
    input::spawn(key_tx, shutdown.clone());

    // ── Render task ───────────────────────────────────────────────────────────
    let rate = config.console.refresh_rate_ms;
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_millis(rate));
        let mut last_rendered = String::new(); // 3.3 — change-detection state

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    if let Err(e) = render(&config, &state, &metrics, &mut last_rendered).await {
                        log::debug!("Render error: {e}");
                    }
                }
                _ = shutdown.changed() => {
                    if *shutdown.borrow() { break; }
                }
            }
        }
    });

    Ok(key_rx)
}

// ─── Render ───────────────────────────────────────────────────────────────────

async fn render(
    config: &Config,
    state: &SharedState,
    metrics: &SharedMetrics,
    last_rendered: &mut String, // 3.3 — previous frame for change-detection
) -> Result<()> {
    // Acquire the lock ONCE and extract everything needed for this frame.
    // Previously this function locked twice: once to read `console_mode`, then
    // a second time inside the Dashboard branch to read the full state snapshot.
    // The two-lock pattern is a TOCTOU hazard — `console_mode` could change
    // between the first and second acquire — and also holds the lock for longer
    // than necessary.
    let (mode, state_snapshot) = {
        let s = state.read().await;
        (s.console_mode.clone(), s.clone())
    };

    let output = match mode {
        ConsoleMode::Dashboard => {
            let (reqs, errs) = metrics.snapshot();
            dashboard::render_dashboard(&state_snapshot, reqs, errs, config)
        }
        ConsoleMode::LogView => dashboard::render_log_view(config.console.show_timestamps),
        ConsoleMode::Help => dashboard::render_help(),
        ConsoleMode::ConfirmQuit => dashboard::render_confirm_quit(),
    };

    // 3.3 — Skip all terminal I/O when the frame is identical to the previous
    // one. At 100 ms ticks this eliminates nearly every write during idle periods
    // (no traffic, no state change).
    if output == *last_rendered {
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
        println!();
    }
}
