use std::{
    fmt::Write as _,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
};

use crate::{
    config::Config,
    runtime::state::{AppState, TorStatus},
    version,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiagnosticsReport {
    text: String,
}

impl DiagnosticsReport {
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }
}

#[must_use]
pub fn build_report(
    config: &Config,
    state: &AppState,
    data_dir: &Path,
    settings_path: Option<&Path>,
) -> DiagnosticsReport {
    let site_root = data_dir.join(&config.site.directory);
    let runtime_path = data_dir.join("runtime");
    let logs = logs_label(config, data_dir);
    let favicon = favicon_label(config, &site_root);

    let mut text = String::with_capacity(512);
    let _ = writeln!(text, "{}", version::product_version_line());
    let _ = writeln!(text, "Mode: {}", mode_label(config));
    let _ = writeln!(text, "HTTP: {}", http_label(config, state));
    let _ = writeln!(text, "HTTPS: {}", enabled_label(config.tls.enabled));
    let _ = writeln!(
        text,
        "Redirect HTTP: {}",
        enabled_label(config.tls.enabled && config.tls.redirect_http)
    );
    let _ = writeln!(text, "Site root: {}", site_root.display());
    let _ = writeln!(text, "Runtime path: {}", runtime_path.display());
    let _ = writeln!(text, "Logs: {logs}");
    let _ = writeln!(text, "Tor: {}", tor_label(config, state));
    let _ = writeln!(text, "Favicon: {favicon}");
    if let Some(settings_path) = settings_path {
        let _ = writeln!(text, "Settings: {}", settings_path.display());
    }

    DiagnosticsReport { text }
}

const fn enabled_label(enabled: bool) -> &'static str {
    if enabled {
        "enabled"
    } else {
        "disabled"
    }
}

const fn mode_label(config: &Config) -> &'static str {
    if config.console.interactive {
        "interactive"
    } else {
        "headless"
    }
}

fn http_label(config: &Config, state: &AppState) -> String {
    let port = if state.actual_port == 0 {
        config.server.port.get()
    } else {
        state.actual_port
    };
    SocketAddr::new(display_bind_addr(config.server.bind), port).to_string()
}

const fn display_bind_addr(bind: IpAddr) -> IpAddr {
    match bind {
        IpAddr::V4(addr) if addr.is_unspecified() => IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        IpAddr::V6(addr) if addr.is_unspecified() => IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
        addr => addr,
    }
}

fn logs_label(config: &Config, data_dir: &Path) -> String {
    let log_path = data_dir.join(&config.logging.file);
    if config.logging.enabled {
        log_path.display().to_string()
    } else {
        format!("disabled ({})", log_path.display())
    }
}

fn tor_label(config: &Config, state: &AppState) -> String {
    if !config.tor.enabled {
        return "disabled".to_owned();
    }

    match &state.tor_status {
        TorStatus::Disabled => "disabled".to_owned(),
        TorStatus::Starting => "starting".to_owned(),
        TorStatus::Ready => "enabled".to_owned(),
        TorStatus::Failed(reason) => format!("enabled (failed: {})", single_line(reason)),
    }
}

fn favicon_label(config: &Config, site_root: &Path) -> String {
    if config.site.favicon.trim().is_empty() {
        return "disabled".to_owned();
    }

    let favicon_path = site_root.join(&config.site.favicon);
    if !favicon_path.is_file() {
        return format!("missing ({})", favicon_path.display());
    }

    if config.site.favicon == "favicon.ico" {
        "site/favicon.ico".to_owned()
    } else {
        format!("custom ({})", display_relative_or_absolute(&favicon_path))
    }
}

fn display_relative_or_absolute(path: &Path) -> String {
    path.strip_prefix(current_dir_fallback()).map_or_else(
        |_| path.display().to_string(),
        |path| path.display().to_string(),
    )
}

fn current_dir_fallback() -> PathBuf {
    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}

fn single_line(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::build_report;
    use crate::{config::Config, runtime::state::AppState};

    #[test]
    fn diagnostics_contains_requested_fields() {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(tmp.path().join("site")).expect("site dir");
        std::fs::write(tmp.path().join("site/favicon.ico"), b"ico").expect("favicon");

        let mut state = AppState::new();
        state.actual_port = 8080;
        let report = build_report(&Config::default(), &state, tmp.path(), None);
        let text = report.text();

        assert!(text.contains("RustHost 1.0.0"));
        assert!(text.contains("Mode: interactive"));
        assert!(text.contains("HTTP: 127.0.0.1:8080"));
        assert!(text.contains("HTTPS: disabled"));
        assert!(text.contains("Redirect HTTP: disabled"));
        assert!(text.contains("Site root:"));
        assert!(text.contains("Runtime path:"));
        assert!(text.contains("Logs:"));
        assert!(text.contains("Tor: starting"));
        assert!(text.contains("Favicon: site/favicon.ico"));
    }
}
