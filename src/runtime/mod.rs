//! # Runtime Module
//! Owns the application lifecycle, shared state, and top-level event
//! dispatch.  Sub-modules:
//!
//! - [`state`]     — [`AppState`] struct and [`TorStatus`] / [`ConsoleMode`] enums
//! - [`lifecycle`] — first-run setup and normal startup sequence
//! - [`events`]    — key-event dispatch (H / R / T / O / L / Q)

pub mod events;
pub mod lifecycle;
pub(crate) mod shutdown;
pub(crate) mod site_reload;
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

    match result {
        Ok(mut child) => {
            // Reap the short-lived launcher so Unix does not accumulate a
            // zombie; the browser process itself outlives it.
            std::thread::spawn(move || {
                let _ = child.wait();
            });
        }
        Err(e) => log::warn!("Could not open browser at {url}: {e}"),
    }
}

pub(crate) async fn open_local_site(state: &state::SharedState) {
    let url = {
        let state = state.read().await;
        state.public_http.bound_addr().map_or_else(
            || {
                state.https.bound_addr().map(|address| {
                    crate::console::ui::local_https_url(address.ip(), address.port())
                })
            },
            |address| {
                Some(crate::console::ui::local_http_url(
                    address.ip(),
                    address.port(),
                ))
            },
        )
    };
    if let Some(url) = url {
        open_browser(&url);
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
