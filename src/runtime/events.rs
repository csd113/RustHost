//! # Key Event Dispatch
//!
//! **Directory:** `src/runtime/`

use std::path::PathBuf;

use crate::{
    config::Config,
    runtime::state::{ConsoleMode, SharedMetrics, SharedState},
    server, Result,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyEvent {
    Help,
    Reload,
    Open,
    ToggleLogs,
    Quit,
    Other,
}

pub async fn handle(
    event: KeyEvent,
    config: &Config,
    state: SharedState,
    _metrics: SharedMetrics,
    data_dir: PathBuf,
) -> Result<bool> {
    match event {
        KeyEvent::Quit => return Ok(true),

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
                ConsoleMode::Dashboard | ConsoleMode::Help => ConsoleMode::LogView,
                ConsoleMode::LogView => ConsoleMode::Dashboard,
            };
        }

        KeyEvent::Reload => {
            let site_root = data_dir.join(&config.site.directory);
            let (count, bytes) = server::scan_site(&site_root);
            {
                let mut s = state.write().await;
                s.site_file_count = count;
                s.site_total_bytes = bytes;
            }
            log::info!(
                "Site reloaded — {} files, {}",
                count,
                crate::runtime::state::format_bytes(bytes)
            );
        }

        KeyEvent::Open => {
            let port = state.read().await.actual_port;
            open_browser(&format!("http://localhost:{port}"));
        }

        KeyEvent::Other => {
            let mut s = state.write().await;
            if s.console_mode == ConsoleMode::Help {
                s.console_mode = ConsoleMode::Dashboard;
            }
        }
    }

    Ok(false)
}

fn open_browser(url: &str) {
    #[cfg(target_os = "macos")]
    let _ = std::process::Command::new("open").arg(url).spawn();
    #[cfg(target_os = "windows")]
    let _ = std::process::Command::new("explorer").arg(url).spawn();
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    let _ = std::process::Command::new("xdg-open").arg(url).spawn();
}
