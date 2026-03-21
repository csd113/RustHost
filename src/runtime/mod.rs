//! # Runtime Module
//!
//! **Directory:** `src/runtime/`
//!
//! Owns the application lifecycle, shared state, and top-level event
//! dispatch.  Sub-modules:
//!
//! - [`state`]     — [`AppState`] struct and [`TorStatus`] / [`ConsoleMode`] enums
//! - [`lifecycle`] — first-run setup and normal startup sequence
//! - [`events`]    — key-event dispatch (H / R / T / O / L / Q)

pub mod events;
pub mod lifecycle;
pub mod state;

/// Open `url` in the system default browser.
///
/// Single canonical definition extracted from `lifecycle.rs` and `events.rs`
/// to eliminate the duplicated function (fix 2.4). Any future fix — URL
/// sanitisation, logging, sandboxing — needs to be applied here only.
pub fn open_browser(url: &str) {
    #[cfg(target_os = "macos")]
    let _ = std::process::Command::new("open").arg(url).spawn();
    #[cfg(target_os = "windows")]
    let _ = std::process::Command::new("explorer").arg(url).spawn();
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    let _ = std::process::Command::new("xdg-open").arg(url).spawn();
}
