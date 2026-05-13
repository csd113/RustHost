use std::{fmt::Write as _, net::SocketAddr, path::Path};

use crate::{
    config::Config,
    console::{menu::diagnostics, ui},
    path_display::display_path,
    runtime::state::AppState,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettingsPageState {
    scroll: usize,
    diagnostics_text: Option<String>,
    status: Option<String>,
}

impl SettingsPageState {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            scroll: 0,
            diagnostics_text: None,
            status: None,
        }
    }

    pub const fn scroll_up(&mut self) {
        self.scroll = self.scroll.saturating_sub(1);
    }

    pub const fn scroll_down(&mut self) {
        self.scroll = self.scroll.saturating_add(1);
    }

    pub fn set_diagnostics_text(&mut self, text: String) {
        self.diagnostics_text = Some(text);
        self.status =
            Some("Clipboard support unavailable; diagnostics text is shown below.".to_owned());
    }
}

impl Default for SettingsPageState {
    fn default() -> Self {
        Self::new()
    }
}

#[must_use]
pub fn render(
    page: &SettingsPageState,
    config: &Config,
    state: &AppState,
    data_dir: &Path,
) -> String {
    let mut out = String::with_capacity(1_536);
    ui::push_header(&mut out, "RustHost Menu / Settings");
    out.push_str("\r\n");
    let _ = writeln!(out, "{}\r", ui::bold("Runtime Settings"));
    out.push_str("\r\n");

    let _ = writeln!(out, "{}\r", ui::bold("Mode"));
    let _ = writeln!(out, "Console:        {}\r", console_mode_label(config));
    let _ = writeln!(out, "Headless:       {}\r", !config.console.interactive);
    let _ = writeln!(out, "Data dir:       {}\r", display_path(data_dir));
    out.push_str("\r\n");

    let _ = writeln!(out, "{}\r", ui::bold("Server"));
    let _ = writeln!(out, "HTTP bind:      {}\r", http_bind_label(config, state));
    let _ = writeln!(
        out,
        "HTTPS:          {}\r",
        enabled_label(config.tls.enabled)
    );
    let _ = writeln!(
        out,
        "Redirect HTTP:  {}\r",
        enabled_label(config.tls.enabled && config.tls.redirect_http)
    );
    out.push_str("\r\n");

    let _ = writeln!(out, "{}\r", ui::bold("Site"));
    let site_root = data_dir.join(&config.site.directory);
    let _ = writeln!(out, "Site root:      {}\r", display_path(&site_root));
    let _ = writeln!(
        out,
        "Favicon:        {}\r",
        favicon_label(config, &site_root)
    );
    out.push_str("\r\n");

    let _ = writeln!(out, "{}\r", ui::bold("Tor"));
    let _ = writeln!(out, "Enabled:        {}\r", config.tor.enabled);
    let _ = writeln!(out, "Tor only:       unavailable\r");
    out.push_str("\r\n");

    let _ = writeln!(out, "{}\r", ui::bold("Logging"));
    let log_dir = data_dir
        .join(&config.logging.file)
        .parent()
        .map_or_else(|| data_dir.to_path_buf(), Path::to_path_buf);
    let _ = writeln!(out, "Log dir:        {}\r", display_path(&log_dir));
    let _ = writeln!(
        out,
        "Access log:     {}\r",
        enabled_label(config.logging.enabled)
    );

    if let Some(status) = &page.status {
        out.push_str("\r\n");
        let _ = writeln!(out, "{}\r", ui::dim(status));
    }

    if let Some(text) = &page.diagnostics_text {
        out.push_str("\r\n");
        let _ = writeln!(out, "{}\r", ui::bold("Diagnostics"));
        for line in text.lines() {
            let _ = writeln!(out, "{line}\r");
        }
    }

    out.push_str("\r\n");
    ui::push_controls_footer(&mut out, "[↑↓/jk] Scroll  [C] Copy diagnostics  [Esc] Back");
    out
}

pub fn copy_diagnostics(
    page: &mut SettingsPageState,
    config: &Config,
    state: &AppState,
    data_dir: &Path,
    settings_path: Option<&Path>,
) {
    let report = diagnostics::build_report(config, state, data_dir, settings_path);
    page.set_diagnostics_text(report.text().to_owned());
}

const fn console_mode_label(config: &Config) -> &'static str {
    if config.console.interactive {
        "interactive"
    } else {
        "headless"
    }
}

const fn enabled_label(enabled: bool) -> &'static str {
    if enabled {
        "enabled"
    } else {
        "disabled"
    }
}

fn http_bind_label(config: &Config, state: &AppState) -> String {
    let port = if state.actual_port == 0 {
        config.server.port.get()
    } else {
        state.actual_port
    };
    SocketAddr::new(config.server.bind, port).to_string()
}

fn favicon_label(config: &Config, site_root: &Path) -> String {
    if config.site.favicon.trim().is_empty() {
        return "not configured".to_owned();
    }

    let path = site_root.join(&config.site.favicon);
    if path.is_file() {
        config.site.favicon.clone()
    } else {
        format!("missing ({})", path.display())
    }
}

#[cfg(test)]
mod tests {
    use super::{copy_diagnostics, render, SettingsPageState};
    use crate::{config::Config, runtime::state::AppState};

    #[test]
    fn settings_page_is_read_only_and_handles_missing_favicon() {
        let page = SettingsPageState::new();
        let output = render(
            &page,
            &Config::default(),
            &AppState::new(),
            std::path::Path::new("/tmp/rusthost-missing"),
        );

        assert!(output.contains("Runtime Settings"));
        assert!(output.contains("Favicon:"));
        assert!(!output.contains("[Enter]"));
        assert!(!output.contains("[Q] Quit"));
    }

    #[test]
    fn copy_diagnostics_shows_text_when_clipboard_is_unavailable() {
        let mut page = SettingsPageState::new();
        copy_diagnostics(
            &mut page,
            &Config::default(),
            &AppState::new(),
            std::path::Path::new("."),
            None,
        );
        let output = render(
            &page,
            &Config::default(),
            &AppState::new(),
            std::path::Path::new("."),
        );

        assert!(output.contains("Clipboard support unavailable"));
        assert!(output.contains("RustHost"));
    }
}
