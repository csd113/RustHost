use std::{
    fmt::Write as _,
    net::{IpAddr, SocketAddr, TcpStream},
    path::Path,
    time::Duration,
};

use crate::{
    config::Config,
    console::{
        menu::doctor::{status_style_label, DoctorStatus},
        ui,
    },
    runtime::state::AppState,
};

const CONNECT_TIMEOUT: Duration = Duration::from_millis(200);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkPageState {
    report: Option<NetworkReport>,
}

impl NetworkPageState {
    #[must_use]
    pub const fn new() -> Self {
        Self { report: None }
    }

    #[must_use]
    pub const fn report(&self) -> Option<&NetworkReport> {
        self.report.as_ref()
    }

    pub fn set_report(&mut self, report: NetworkReport) {
        self.report = Some(report);
    }
}

impl Default for NetworkPageState {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkReport {
    listeners: Vec<ListenerRow>,
    checks: Vec<NetworkCheck>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ListenerRow {
    protocol: &'static str,
    bind: String,
    port: String,
    tls: &'static str,
    status: ListenerStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ListenerStatus {
    Pass,
    Warn,
    Off,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NetworkCheck {
    status: DoctorStatus,
    message: String,
}

#[must_use]
pub fn collect_report(config: &Config, state: &AppState, data_dir: &Path) -> NetworkReport {
    let http_port = runtime_http_port(config, state);
    let redirect_enabled = config.tls.enabled && config.tls.redirect_http;
    let mut listeners = Vec::with_capacity(3);
    let mut checks = Vec::with_capacity(6);

    if redirect_enabled {
        listeners.push(disabled_listener("HTTP", "No"));
    } else {
        let probe_addr = SocketAddr::new(local_probe_addr(config.server.bind), http_port);
        let status = listener_status(state.server_running, probe_addr);
        listeners.push(listener_row(
            "HTTP",
            config.server.bind,
            http_port,
            "No",
            status,
        ));
        push_listener_check(
            &mut checks,
            "HTTP listener accepts local connections",
            state.server_running,
            probe_addr,
        );
    }

    if config.tls.enabled {
        let tls_port = state.tls_port.unwrap_or_else(|| config.tls.port.get());
        let probe_addr = SocketAddr::new(local_probe_addr(config.server.bind), tls_port);
        let status = listener_status(state.tls_running, probe_addr);
        listeners.push(listener_row(
            "HTTPS",
            config.server.bind,
            tls_port,
            "Yes",
            status,
        ));
        push_listener_check(
            &mut checks,
            "HTTPS listener accepts local connections",
            state.tls_running,
            probe_addr,
        );
        push_tls_config_check(&mut checks, config, data_dir);
    } else {
        listeners.push(disabled_listener("HTTPS", "Yes"));
        checks.push(NetworkCheck {
            status: DoctorStatus::NotRun,
            message: "HTTPS listener disabled in settings".to_owned(),
        });
    }

    if redirect_enabled {
        let redirect_port = config.tls.http_port.get();
        let probe_addr = SocketAddr::new(local_probe_addr(config.server.bind), redirect_port);
        let status = listener_status(state.server_running, probe_addr);
        listeners.push(listener_row(
            "Redirect",
            config.server.bind,
            redirect_port,
            "-",
            status,
        ));
        push_listener_check(
            &mut checks,
            "HTTP redirect listener accepts local connections",
            state.server_running,
            probe_addr,
        );
    } else {
        listeners.push(disabled_listener("Redirect", "-"));
        checks.push(NetworkCheck {
            status: DoctorStatus::NotRun,
            message: "HTTP redirect disabled in settings".to_owned(),
        });
    }

    checks.push(NetworkCheck {
        status: DoctorStatus::Pass,
        message: "Configured bind address is valid".to_owned(),
    });

    push_acme_domain_check(&mut checks, config);
    checks.push(NetworkCheck {
        status: DoctorStatus::NotRun,
        message: "Public reachability is not inferred from ACME domains; verify DNS, firewall, NAT, and public HTTP/HTTPS access separately".to_owned(),
    });

    NetworkReport { listeners, checks }
}

#[must_use]
pub fn render(page: &NetworkPageState) -> String {
    let mut out = String::with_capacity(1_024);
    ui::push_header(&mut out, "RustHost Menu / Network");
    out.push_str("\r\n");

    let Some(report) = page.report() else {
        out.push_str("Network snapshot has not been collected yet.\r\n");
        out.push_str("\r\n");
        ui::push_controls_footer(&mut out, "[R] Refresh  [Esc] Back");
        return out;
    };

    let _ = writeln!(out, "{}\r", ui::bold("Listeners"));
    out.push_str("\r\n");
    out.push_str("Protocol   Config bind  Port   TLS   Local check\r\n");
    for listener in &report.listeners {
        let _ = writeln!(
            out,
            "{:<10} {:<12} {:<6} {:<5} {}\r",
            listener.protocol,
            listener.bind,
            listener.port,
            listener.tls,
            listener_status_label(listener.status)
        );
    }

    out.push_str("\r\n");
    let _ = writeln!(out, "{}\r", ui::bold("Checks"));
    out.push_str("\r\n");
    for check in &report.checks {
        let _ = writeln!(out, "{:<7} {}\r", color_status(check.status), check.message);
    }

    out.push_str("\r\n");
    ui::push_controls_footer(&mut out, "[R] Refresh  [Esc] Back");
    out
}

const fn runtime_http_port(config: &Config, state: &AppState) -> u16 {
    if state.actual_port == 0 {
        if config.tls.enabled && config.tls.redirect_http {
            config.tls.http_port.get()
        } else {
            config.server.port.get()
        }
    } else {
        state.actual_port
    }
}

fn disabled_listener(protocol: &'static str, tls: &'static str) -> ListenerRow {
    ListenerRow {
        protocol,
        bind: "disabled".to_owned(),
        port: "-".to_owned(),
        tls,
        status: ListenerStatus::Off,
    }
}

fn listener_row(
    protocol: &'static str,
    bind: IpAddr,
    port: u16,
    tls: &'static str,
    status: ListenerStatus,
) -> ListenerRow {
    ListenerRow {
        protocol,
        bind: bind.to_string(),
        port: port.to_string(),
        tls,
        status,
    }
}

fn listener_status(running: bool, addr: SocketAddr) -> ListenerStatus {
    if !running {
        return ListenerStatus::Warn;
    }
    TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT).map_or(ListenerStatus::Warn, |stream| {
        drop(stream);
        ListenerStatus::Pass
    })
}

fn push_listener_check(
    checks: &mut Vec<NetworkCheck>,
    message: &'static str,
    running: bool,
    addr: SocketAddr,
) {
    let status = if running && TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT).is_ok() {
        DoctorStatus::Pass
    } else {
        DoctorStatus::Warn
    };
    checks.push(NetworkCheck {
        status,
        message: format!("{message} at {addr}"),
    });
}

fn push_acme_domain_check(checks: &mut Vec<NetworkCheck>, config: &Config) {
    if config.tls.acme.enabled {
        checks.push(NetworkCheck {
            status: if config.tls.acme.domains.is_empty() {
                DoctorStatus::Fail
            } else {
                DoctorStatus::Pass
            },
            message: if config.tls.acme.domains.is_empty() {
                "ACME enabled but no certificate domains are configured".to_owned()
            } else {
                format!(
                    "ACME certificate domains configured: {}",
                    domain_summary(&config.tls.acme.domains)
                )
            },
        });
    } else {
        checks.push(NetworkCheck {
            status: DoctorStatus::NotRun,
            message: if config.tls.acme.domains.is_empty() {
                "ACME disabled; no certificate domains configured".to_owned()
            } else {
                format!(
                    "ACME disabled; configured domains are inactive: {}",
                    domain_summary(&config.tls.acme.domains)
                )
            },
        });
    }
}

fn domain_summary(domains: &[String]) -> String {
    const MAX_DISPLAYED_DOMAINS: usize = 3;

    let mut summary = domains
        .iter()
        .take(MAX_DISPLAYED_DOMAINS)
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join(", ");
    let remaining = domains.len().saturating_sub(MAX_DISPLAYED_DOMAINS);
    if remaining > 0 {
        let _ = write!(summary, " (+{remaining} more)");
    }
    summary
}

fn push_tls_config_check(checks: &mut Vec<NetworkCheck>, config: &Config, data_dir: &Path) {
    if config.tls.acme.enabled {
        let status = if config.tls.acme.domains.is_empty() {
            DoctorStatus::Fail
        } else {
            DoctorStatus::Pass
        };
        checks.push(NetworkCheck {
            status,
            message: "ACME TLS configuration has at least one domain".to_owned(),
        });
    } else if let Some(manual) = &config.tls.manual_cert {
        let cert_exists = data_dir.join(&manual.cert_path).is_file();
        let key_exists = data_dir.join(&manual.key_path).is_file();
        checks.push(NetworkCheck {
            status: if cert_exists && key_exists {
                DoctorStatus::Pass
            } else {
                DoctorStatus::Fail
            },
            message: "Manual TLS certificate and key files are present".to_owned(),
        });
    } else {
        checks.push(NetworkCheck {
            status: DoctorStatus::Warn,
            message: "TLS will use a self-signed development certificate".to_owned(),
        });
    }
}

const fn local_probe_addr(bind: IpAddr) -> IpAddr {
    match bind {
        IpAddr::V4(addr) if addr.is_unspecified() => IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        IpAddr::V6(addr) if addr.is_unspecified() => IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
        addr => addr,
    }
}

fn listener_status_label(status: ListenerStatus) -> String {
    match status {
        ListenerStatus::Pass => ui::green("PASS"),
        ListenerStatus::Warn => ui::yellow("WARN"),
        ListenerStatus::Off => ui::dim("OFF"),
    }
}

fn color_status(status: DoctorStatus) -> String {
    let (label, color) = status_style_label(status);
    format!("{color}{label}\x1b[0m")
}

#[cfg(test)]
mod tests {
    use super::{collect_report, render, ListenerStatus, NetworkPageState};
    use crate::{config::Config, runtime::state::AppState};

    #[test]
    fn tls_and_redirect_disabled_are_off_not_warn_listener_states() {
        let report = collect_report(
            &Config::default(),
            &AppState::new(),
            std::path::Path::new("."),
        );

        assert!(report
            .listeners
            .iter()
            .any(|row| { row.protocol == "HTTPS" && row.status == ListenerStatus::Off }));
        assert!(report
            .listeners
            .iter()
            .any(|row| { row.protocol == "Redirect" && row.status == ListenerStatus::Off }));
    }

    #[test]
    fn render_network_page_has_refresh_not_quit() {
        let mut page = NetworkPageState::new();
        page.set_report(collect_report(
            &Config::default(),
            &AppState::new(),
            std::path::Path::new("."),
        ));

        let output = render(&page);

        assert!(output.contains("[R] Refresh"));
        assert!(!output.contains("[Q] Quit"));
    }

    #[test]
    fn acme_domains_are_not_presented_as_public_reachability() {
        let mut config = Config::default();
        config.tls.enabled = true;
        config.tls.acme.enabled = true;
        config.tls.acme.domains = vec!["example.com".to_owned()];

        let mut page = NetworkPageState::new();
        page.set_report(collect_report(
            &config,
            &AppState::new(),
            std::path::Path::new("."),
        ));

        let output = render(&page);

        assert!(output.contains("ACME certificate domains configured: example.com"));
        assert!(output.contains("Public reachability is not inferred from ACME domains"));
        assert!(!output.contains("Public hosts"));
    }

    #[test]
    fn unspecified_bind_is_displayed_separately_from_loopback_probe() {
        let mut config = Config::default();
        config.server.bind = std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED);

        let mut page = NetworkPageState::new();
        page.set_report(collect_report(
            &config,
            &AppState::new(),
            std::path::Path::new("."),
        ));

        let output = render(&page);

        assert!(output.contains("0.0.0.0"));
        assert!(output.contains("at 127.0.0.1:8080"));
    }
}
