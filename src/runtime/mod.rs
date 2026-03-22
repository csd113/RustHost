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
    // `explorer.exe <url>` is unreliable — on some Windows configurations it
    // opens File Explorer instead of the default browser.  `cmd /c start`
    // delegates to the Windows shell association table, which always picks the
    // correct handler.  The empty-string third argument is required to prevent
    // `start` from treating the URL (which may contain special chars) as the
    // window title.
    #[cfg(target_os = "windows")]
    let _ = std::process::Command::new("cmd")
        .args(["/c", "start", "", url])
        .spawn();
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    let _ = std::process::Command::new("xdg-open").arg(url).spawn();
}
