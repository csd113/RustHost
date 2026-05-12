//! # Dashboard Renderer
use crate::{
    config::Config,
    logging,
    runtime::state::{
        format_bytes, format_uptime, AppState, CertStatus, MetricsSnapshot, Page, TorStatus,
    },
};
use std::fmt::Write as _;
// ─── ANSI helpers ────────────────────────────────────────────────────────────
fn green(s: &str) -> String {
    format!("\x1b[32m{s}\x1b[0m")
}
fn yellow(s: &str) -> String {
    format!("\x1b[33m{s}\x1b[0m")
}
fn red(s: &str) -> String {
    format!("\x1b[31m{s}\x1b[0m")
}
fn dim(s: &str) -> String {
    format!("\x1b[2m{s}\x1b[0m")
}
fn bold(s: &str) -> String {
    format!("\x1b[1m{s}\x1b[0m")
}

fn local_http_url(bind_addr: std::net::IpAddr, port: u16) -> String {
    match bind_addr {
        std::net::IpAddr::V4(addr) if addr.is_unspecified() => {
            format!("http://127.0.0.1:{port}")
        }
        std::net::IpAddr::V6(addr) if addr.is_unspecified() => {
            format!("http://[::1]:{port}")
        }
        std::net::IpAddr::V6(addr) => format!("http://[{addr}]:{port}"),
        std::net::IpAddr::V4(addr) => format!("http://{addr}:{port}"),
    }
}

fn local_https_url(bind_addr: std::net::IpAddr, port: u16) -> String {
    match bind_addr {
        std::net::IpAddr::V4(addr) if addr.is_unspecified() => {
            if port == 443 {
                "https://127.0.0.1".to_owned()
            } else {
                format!("https://127.0.0.1:{port}")
            }
        }
        std::net::IpAddr::V6(addr) if addr.is_unspecified() => {
            if port == 443 {
                "https://[::1]".to_owned()
            } else {
                format!("https://[::1]:{port}")
            }
        }
        std::net::IpAddr::V6(addr) => {
            if port == 443 {
                format!("https://[{addr}]")
            } else {
                format!("https://[{addr}]:{port}")
            }
        }
        std::net::IpAddr::V4(addr) => {
            if port == 443 {
                format!("https://{addr}")
            } else {
                format!("https://{addr}:{port}")
            }
        }
    }
}

const RULE: &str = "──────────────────────────────────────────────────────────";

fn push_controls_footer(out: &mut String, controls: &str) {
    let _ = writeln!(out, "{RULE}\r");
    out.push_str(controls);
    out.push_str("\r\n");
    let _ = writeln!(out, "{RULE}\r");
}

// ─── Dashboard ───────────────────────────────────────────────────────────────
#[must_use]
pub fn render_dashboard(state: &AppState, metrics: MetricsSnapshot, config: &Config) -> String {
    let mut out = String::with_capacity(1_024);
    let _ = writeln!(out, "{RULE}\r");
    let _ = writeln!(out, " {}\r", bold(&config.identity.instance_name));
    let _ = writeln!(out, "{RULE}\r");
    out.push_str("\r\n");
    // ── Status ───────────────────────────────────────────────────────────────
    let _ = writeln!(out, "{}\r", bold("Status"));
    let server_str = if state.server_running {
        green(&format!(
            "RUNNING ({}:{})",
            config.server.bind, state.actual_port
        ))
    } else {
        yellow("STARTING...")
    };
    let _ = writeln!(out, " Local Server : {server_str}\r");
    // HTTPS status row — always shown so the user knows at a glance whether
    // TLS is active or has been left disabled in settings.toml.
    if config.tls.enabled {
        let tls_str = if state.tls_running {
            let cert_label = match &state.tls_cert_status {
                CertStatus::Unknown => String::new(),
                CertStatus::SelfSigned => " \u{00b7} self-signed".into(),
                CertStatus::Acme { domain } if domain.is_empty() => {
                    " \u{00b7} Let\u{2019}s Encrypt".into()
                }
                CertStatus::Acme { domain } => format!(" \u{00b7} Let\u{2019}s Encrypt ({domain})"),
                CertStatus::Manual => " \u{00b7} manual cert".into(),
            };
            green(&format!(
                "RUNNING (port {}{})",
                state.tls_port.unwrap_or(0),
                cert_label
            ))
        } else {
            yellow("STARTING\u{2026}")
        };
        let _ = writeln!(out, " HTTPS : {tls_str}\r");
    } else {
        let _ = writeln!(out, " HTTPS : {}\r", dim("DISABLED"));
    }
    let tor_str = match &state.tor_status {
        TorStatus::Disabled => dim("DISABLED"),
        TorStatus::Starting => yellow("STARTING — bootstrapping Tor network…"),
        TorStatus::Ready => green("READY"),
        TorStatus::Failed(reason) => red(&format!("FAILED ({reason}) — see log for details")),
    };
    let _ = writeln!(out, " Tor : {tor_str}\r");
    if let Some(message) = state.visible_status_message() {
        let _ = writeln!(out, " Status : {}\r", yellow(message));
    }
    out.push_str("\r\n");
    // ── Endpoints ────────────────────────────────────────────────────────────
    let _ = writeln!(out, "{}\r", bold("Endpoints"));
    let local_url = local_http_url(config.server.bind, state.actual_port);
    let _ = writeln!(out, " Local : {local_url}\r");
    // HTTPS endpoint — only shown when the TLS server is up.
    if state.tls_running {
        if let Some(tls_port) = state.tls_port {
            let https_url = local_https_url(config.server.bind, tls_port);
            let _ = writeln!(out, " HTTPS : {}\r", green(&https_url));
        }
    }
    let onion_str = state.onion_address.as_deref().map_or_else(
        || match &state.tor_status {
            TorStatus::Disabled => dim("(disabled)"),
            TorStatus::Starting => dim("(bootstrapping…)"),
            // This branch is unreachable in practice because set_onion() sets
            // Ready and Some(addr) atomically. If it fires an invariant has been
            // violated; the honest label is "unavailable".
            TorStatus::Ready => {
                debug_assert!(
                    false,
                    "TorStatus::Ready with no onion_address — invariant violated"
                );
                dim("(address unavailable)")
            }
            TorStatus::Failed(_) => dim("(unavailable)"),
        },
        |addr| format!("http://{addr}"),
    );
    let _ = writeln!(out, " Onion : {onion_str}\r");
    out.push_str("\r\n");
    // ── Site ─────────────────────────────────────────────────────────────────
    let _ = writeln!(out, "{}\r", bold("Site"));
    let _ = writeln!(
        out,
        " Directory : ./rusthost-data/{}\r",
        config.site.directory
    );
    let _ = writeln!(out, " Files : {}\r", state.site_file_count);
    let _ = writeln!(out, " Size : {}\r", format_bytes(state.site_total_bytes));
    out.push_str("\r\n");
    // ── Activity ─────────────────────────────────────────────────────────────
    let _ = writeln!(out, "{}\r", bold("Activity"));
    let _ = writeln!(out, " Uptime : {}\r", format_uptime(metrics.uptime));
    let _ = writeln!(out, " Requests : {}\r", metrics.requests);
    let _ = writeln!(out, " Unique visitors : {}\r", metrics.unique_visitors);
    let err_str = if metrics.errors > 0 {
        red(&metrics.errors.to_string())
    } else {
        metrics.errors.to_string()
    };
    let _ = writeln!(out, " Errors : {err_str}\r");
    out.push_str("\r\n");
    // ── Key bar ───────────────────────────────────────────────────────────────
    push_controls_footer(
        &mut out,
        "[H] Help [R] Reload [O] Open [L] Logs [M] Menu [Q] Quit",
    );
    out
}

// ─── Menu ───────────────────────────────────────────────────────────────────
#[must_use]
pub fn render_menu(selected: usize, pulse_visible: bool) -> String {
    let selected_page = Page::MENU_ITEMS
        .get(selected)
        .copied()
        .unwrap_or(Page::Doctor);
    let mut out = String::with_capacity(512);
    let _ = writeln!(out, "RustHost Menu\r");
    out.push_str("\r\n");

    for (index, page) in Page::MENU_ITEMS.iter().enumerate() {
        let marker = if index == selected {
            if pulse_visible {
                bold(">")
            } else {
                dim(">")
            }
        } else {
            " ".to_owned()
        };
        let _ = writeln!(out, "{marker} {}\r", page.title());
    }

    out.push_str("\r\n");
    let _ = writeln!(out, "{}\r", selected_page.purpose());
    out.push_str("\r\n");
    out.push_str("[↑↓] Navigate  [Enter] Open  [Esc] Back  [Q] Quit\r\n");
    out
}

// ─── Placeholder Pages ──────────────────────────────────────────────────────
#[must_use]
pub fn render_placeholder_page(page: Page) -> String {
    let mut out = String::with_capacity(512);
    let _ = writeln!(out, "{RULE}\r");
    let _ = writeln!(out, " {}\r", bold(page.title()));
    let _ = writeln!(out, "{RULE}\r");
    out.push_str("\r\n");
    let _ = writeln!(out, "{}\r", page.purpose());
    out.push_str("\r\n");
    out.push_str("This page is not implemented yet.\r\n");
    out.push_str("\r\n");
    push_controls_footer(&mut out, "[Esc] Back");
    out
}

// ─── Log view ────────────────────────────────────────────────────────────────
#[must_use]
pub fn render_log_view(show_timestamps: bool) -> String {
    let lines = logging::recent_lines(40);
    let mut out = String::with_capacity(2_048);
    let _ = writeln!(out, "{RULE}\r");
    let _ = writeln!(out, " {} — Log View\r", bold("RustHost"));
    let _ = writeln!(out, "{RULE}\r");
    for line in &lines {
        let display = if show_timestamps {
            line.as_str()
        } else {
            strip_timestamp(line)
        };
        let _ = writeln!(out, "{}\r", clean_log_line(display));
    }
    out.push_str("\r\n");
    push_controls_footer(&mut out, "[L] Back to dashboard");
    out
}
// ─── Help ────────────────────────────────────────────────────────────────────
#[must_use]
pub fn render_help() -> String {
    let mut out = String::with_capacity(512);
    let _ = writeln!(out, "{RULE}\r");
    let _ = writeln!(out, " {} — Help\r", bold("RustHost"));
    let _ = writeln!(out, "{RULE}\r");
    out.push_str("\r\n");
    let _ = writeln!(out, " {} Show this help screen\r", bold("[H]"));
    let _ = writeln!(
        out,
        " {} Rescan site directory and update stats\r",
        bold("[R]")
    );
    let _ = writeln!(out, " {} Open local URL in system browser\r", bold("[O]"));
    let _ = writeln!(out, " {} Toggle log view\r", bold("[L]"));
    out.push_str("\r\n");
    let _ = writeln!(
        out,
        "{}\r",
        dim("Press any key to return to the dashboard.")
    );
    let _ = writeln!(out, "{RULE}\r");
    out
}
// ─── Confirm quit ─────────────────────────────────────────────────────────────
#[must_use]
pub fn render_confirm_quit() -> String {
    let mut out = String::with_capacity(256);
    let _ = writeln!(out, "{RULE}\r");
    let _ = writeln!(out, " {}\r", bold("Quit RustHost?"));
    let _ = writeln!(out, "{RULE}\r");
    out.push_str("\r\n");
    let _ = writeln!(
        out,
        " The server will stop accepting connections and background services.\r"
    );
    out.push_str("\r\n");
    let _ = writeln!(out, " {} Quit {} Cancel\r", bold("[Y]"), bold("[N]"));
    out.push_str("\r\n");
    let _ = writeln!(out, "{RULE}\r");
    out
}
#[must_use]
pub fn render_shutdown(tor_enabled: bool) -> String {
    let mut out = String::with_capacity(512);
    let _ = writeln!(out, "{RULE}\r");
    let _ = writeln!(out, " {}\r", bold("Shutdown requested"));
    let _ = writeln!(out, "{RULE}\r");
    out.push_str("\r\n");
    let _ = writeln!(out, " Stopping web server and background services...\r");
    if tor_enabled {
        let _ = writeln!(
            out,
            " Tor cleanup may take a few seconds while active streams close.\r"
        );
    }
    out.push_str("\r\n");
    let _ = writeln!(out, " RustHost will exit when cleanup is complete.\r");
    let _ = writeln!(out, "{RULE}\r");
    out
}
// ─── Helpers ─────────────────────────────────────────────────────────────────
fn strip_timestamp(line: &str) -> &str {
    let mut parts = line.splitn(3, ']');
    parts.next();
    parts.next();
    parts.next().map_or(line, str::trim_start)
}

fn clean_log_line(line: &str) -> String {
    line.replace("╔═══════════════════════════════════════════════════╗", "")
        .replace("╠═══════════════════════════════════════════════════╣", "")
        .replace("╚═══════════════════════════════════════════════════╝", "")
        .replace('║', "")
        .trim()
        .to_owned()
}
// ─── Unit tests ───────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::{
        clean_log_line, render_dashboard, render_menu, render_placeholder_page, render_shutdown,
        strip_timestamp,
    };
    use crate::{
        config::Config,
        runtime::state::{AppState, MetricsSnapshot, Page},
    };
    use std::time::Duration;
    #[test]
    fn strip_timestamp_ascii_log_line() {
        let line = "[INFO][2024-01-01 12:00:00] message body";
        assert_eq!(strip_timestamp(line), "message body");
    }
    #[test]
    fn strip_timestamp_multibyte_utf8_does_not_panic() {
        let line = "[INFO][2024-01-01 12:00:00] café au lait";
        let result = strip_timestamp(line);
        assert_eq!(result, "café au lait");
    }
    #[test]
    fn strip_timestamp_no_brackets_returns_original() {
        let line = "bare message without any brackets";
        assert_eq!(strip_timestamp(line), line);
    }
    #[test]
    fn strip_timestamp_only_one_bracket_pair_returns_original() {
        let line = "[INFO] single bracket only";
        assert_eq!(strip_timestamp(line), line);
    }

    #[test]
    fn clean_log_line_removes_box_drawing_noise() {
        let line = "║   TOR ONION SERVICE ACTIVE                        ║";
        assert_eq!(clean_log_line(line), "TOR ONION SERVICE ACTIVE");
    }

    #[test]
    fn shutdown_message_mentions_tor_when_enabled() {
        let message = render_shutdown(true);
        assert!(message.contains("Shutdown requested"));
        assert!(message.contains("Tor cleanup may take a few seconds"));
    }

    #[test]
    fn dashboard_activity_shows_unique_visitors_without_raw_visitor_ip() {
        let metrics = MetricsSnapshot {
            requests: 4,
            errors: 0,
            unique_visitors: 1,
            uptime: Duration::from_secs(65),
        };
        let output = render_dashboard(&AppState::new(), metrics, &Config::default());

        assert!(output.contains("Unique visitors : 1"));
        assert!(output.contains("Uptime : 1m 05s"));
        assert!(!output.contains("203.0.113.10"));
    }

    #[test]
    fn dashboard_footer_includes_menu_hint() {
        let output = render_dashboard(
            &AppState::new(),
            MetricsSnapshot {
                requests: 0,
                errors: 0,
                unique_visitors: 0,
                uptime: Duration::ZERO,
            },
            &Config::default(),
        );

        assert!(output.contains("[M] Menu"));
    }

    #[test]
    fn menu_renders_selected_marker_and_selected_description() {
        let output = render_menu(0, true);

        assert!(output.contains("\x1b[1m>\x1b[0m Doctor"));
        assert!(!output.contains("  Logs"));
        assert!(!output.contains("  Home"));
        assert!(
            output.contains("Check config, paths, ports, TLS, Tor, favicon, and runtime safety.")
        );
        assert!(output.contains("[↑↓] Navigate  [Enter] Open  [Esc] Back  [Q] Quit"));
    }

    #[test]
    fn placeholder_page_renders_minimal_not_implemented_state() {
        let output = render_placeholder_page(Page::Doctor);

        assert!(output.contains("Doctor"));
        assert!(
            output.contains("Check config, paths, ports, TLS, Tor, favicon, and runtime safety.")
        );
        assert!(output.contains("This page is not implemented yet."));
        assert!(output.contains("[Esc] Back"));
        assert!(!output.contains("[Q] Quit"));
    }

    #[test]
    fn all_placeholder_pages_render_their_title_and_purpose() {
        for page in [
            Page::Doctor,
            Page::Tor,
            Page::Network,
            Page::Site,
            Page::Settings,
            Page::Diagnostics,
            Page::Help,
        ] {
            let output = render_placeholder_page(page);

            assert!(output.contains(page.title()));
            assert!(output.contains(page.purpose()));
            assert!(output.contains("This page is not implemented yet."));
        }
    }
}
