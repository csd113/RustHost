//! # Runtime Module
//! Owns the application lifecycle, shared state, and top-level event
//! dispatch.  Sub-modules:
//!
//! - [`state`]     — [`AppState`] struct and [`TorStatus`] / [`ConsoleMode`] enums
//! - [`lifecycle`] — first-run setup and normal startup sequence
//! - [`events`]    — key-event dispatch (H / R / T / O / L / Q)

pub mod events;
pub mod lifecycle;
pub mod state;

use std::path::{Path, PathBuf};

/// Open `url` in the system default browser.
pub fn open_browser(url: &str) {
    let result = {
        #[cfg(target_os = "macos")]
        {
            std::process::Command::new("open").arg(url).spawn()
        }
        // `explorer.exe <url>` is unreliable — on some Windows configurations it
        // opens File Explorer instead of the default browser.  `cmd /c start`
        // delegates to the Windows shell association table, which always picks the
        // correct handler.  The empty-string third argument is required to prevent
        // `start` from treating the URL (which may contain special chars) as the
        // window title.
        #[cfg(target_os = "windows")]
        {
            std::process::Command::new("cmd")
                .args(["/c", "start", "", url])
                .spawn()
        }
        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        {
            std::process::Command::new("xdg-open").arg(url).spawn()
        }
    };

    if let Err(e) = result {
        log::warn!("Could not open browser at {url}: {e}");
    }
}

/// Return the runtime-owned directory root inside a data directory.
///
/// The generated on-disk layout keeps user content at `site/` and all
/// RustHost-managed state under `runtime/`.
#[must_use]
pub fn runtime_root(data_dir: &Path) -> PathBuf {
    data_dir.join("runtime")
}
