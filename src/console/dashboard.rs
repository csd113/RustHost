//! # Dashboard Renderer
use crate::{
    config::Config,
    console::ui,
    logging,
    runtime::state::{
        format_bytes, format_uptime, AppState, CertStatus, MetricsSnapshot, TorStatus,
    },
};
use std::fmt::Write as _;

// ─── Dashboard ───────────────────────────────────────────────────────────────
#[must_use]
pub fn render_dashboard(state: &AppState, metrics: MetricsSnapshot, config: &Config) -> String {
    let mut out = String::with_capacity(1_024);
    ui::push_header(&mut out, &config.identity.instance_name);
    out.push_str("\r\n");
    // ── Status ───────────────────────────────────────────────────────────────
    let _ = writeln!(out, "{}\r", ui::bold("Status"));
    let server_str = if state.server_running {
        ui::green(&format!(
            "RUNNING ({}:{})",
            config.server.bind, state.actual_port
        ))
    } else {
        ui::yellow("STARTING...")
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
            ui::green(&format!(
                "RUNNING (port {}{})",
                state.tls_port.unwrap_or(0),
                cert_label
            ))
        } else {
            ui::yellow("STARTING\u{2026}")
        };
        let _ = writeln!(out, " HTTPS : {tls_str}\r");
    } else {
        let _ = writeln!(out, " HTTPS : {}\r", ui::dim("DISABLED"));
    }
    let tor_str = match &state.tor_status {
        TorStatus::Disabled => ui::dim("DISABLED"),
        TorStatus::Starting => ui::yellow("STARTING — bootstrapping Tor network…"),
        TorStatus::Ready => ui::green("READY"),
        TorStatus::Failed(reason) => ui::red(&format!("FAILED ({reason}) — see log for details")),
    };
    let _ = writeln!(out, " Tor : {tor_str}\r");
    if let Some(message) = state.visible_status_message() {
        let _ = writeln!(out, " Status : {}\r", ui::yellow(message));
    }
    out.push_str("\r\n");
    // ── Endpoints ────────────────────────────────────────────────────────────
    let _ = writeln!(out, "{}\r", ui::bold("Endpoints"));
    let local_url = ui::local_http_url(config.server.bind, state.actual_port);
    let _ = writeln!(out, " Local : {local_url}\r");
    // HTTPS endpoint — only shown when the TLS server is up.
    if state.tls_running {
        if let Some(tls_port) = state.tls_port {
            let https_url = ui::local_https_url(config.server.bind, tls_port);
            let _ = writeln!(out, " HTTPS : {}\r", ui::green(&https_url));
        }
    }
    let onion_str = state.onion_address.as_deref().map_or_else(
        || match &state.tor_status {
            TorStatus::Disabled => ui::dim("(disabled)"),
            TorStatus::Starting => ui::dim("(bootstrapping…)"),
            // This branch is unreachable in practice because set_onion() sets
            // Ready and Some(addr) atomically. If it fires an invariant has been
            // violated; the honest label is "unavailable".
            TorStatus::Ready => {
                debug_assert!(
                    false,
                    "TorStatus::Ready with no onion_address — invariant violated"
                );
                ui::dim("(address unavailable)")
            }
            TorStatus::Failed(_) => ui::dim("(unavailable)"),
        },
        |addr| format!("http://{addr}"),
    );
    let _ = writeln!(out, " Onion : {onion_str}\r");
    out.push_str("\r\n");
    // ── Site ─────────────────────────────────────────────────────────────────
    let _ = writeln!(out, "{}\r", ui::bold("Site"));
    let _ = writeln!(
        out,
        " Directory : ./rusthost-data/{}\r",
        config.site.directory
    );
    let _ = writeln!(out, " Files : {}\r", state.site_file_count);
    let _ = writeln!(out, " Size : {}\r", format_bytes(state.site_total_bytes));
    out.push_str("\r\n");
    // ── Activity ─────────────────────────────────────────────────────────────
    let _ = writeln!(out, "{}\r", ui::bold("Activity"));
    let _ = writeln!(out, " Uptime : {}\r", format_uptime(metrics.uptime));
    let _ = writeln!(out, " Requests : {}\r", metrics.requests);
    let _ = writeln!(out, " Unique visitors : {}\r", metrics.unique_visitors);
    let err_str = if metrics.errors > 0 {
        ui::red(&metrics.errors.to_string())
    } else {
        metrics.errors.to_string()
    };
    let _ = writeln!(out, " Errors : {err_str}\r");
    out.push_str("\r\n");
    // ── Key bar ───────────────────────────────────────────────────────────────
    ui::push_controls_footer(
        &mut out,
        "[H] Help [R] Reload [O] Open [L] Logs [M] Menu [Q] Quit",
    );
    out
}

// ─── Log view ────────────────────────────────────────────────────────────────
#[must_use]
pub fn render_log_view(show_timestamps: bool) -> String {
    let lines = logging::recent_lines(40);
    let mut out = String::with_capacity(2_048);
    ui::push_header(&mut out, "RustHost — Log View");
    for line in &lines {
        let display = if show_timestamps {
            line.as_str()
        } else {
            strip_timestamp(line)
        };
        let _ = writeln!(out, "{}\r", clean_log_line(display));
    }
    out.push_str("\r\n");
    ui::push_controls_footer(&mut out, "[L] Back to dashboard");
    out
}
// ─── Help ────────────────────────────────────────────────────────────────────
#[must_use]
pub fn render_help() -> String {
    let mut out = String::with_capacity(512);
    ui::push_header(&mut out, "RustHost — Help");
    out.push_str("\r\n");
    let _ = writeln!(out, " {} Show this help screen\r", ui::bold("[H]"));
    let _ = writeln!(
        out,
        " {} Rescan site directory and update stats\r",
        ui::bold("[R]")
    );
    let _ = writeln!(
        out,
        " {} Open local URL in system browser\r",
        ui::bold("[O]")
    );
    let _ = writeln!(out, " {} Toggle log view\r", ui::bold("[L]"));
    out.push_str("\r\n");
    let _ = writeln!(
        out,
        "{}\r",
        ui::dim("Press any key to return to the dashboard.")
    );
    let _ = writeln!(out, "{}\r", ui::RULE);
    out
}
// ─── Confirm quit ─────────────────────────────────────────────────────────────
#[must_use]
pub fn render_confirm_quit() -> String {
    let mut out = String::with_capacity(256);
    ui::push_header(&mut out, "Quit RustHost?");
    out.push_str("\r\n");
    let _ = writeln!(
        out,
        " The server will stop accepting connections and background services.\r"
    );
    out.push_str("\r\n");
    let _ = writeln!(
        out,
        " {} Quit {} Cancel\r",
        ui::bold("[Y]"),
        ui::bold("[N]")
    );
    out.push_str("\r\n");
    let _ = writeln!(out, "{}\r", ui::RULE);
    out
}
#[must_use]
pub fn render_shutdown(tor_enabled: bool) -> String {
    let mut out = String::with_capacity(512);
    ui::push_header(&mut out, "Shutdown requested");
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
    let _ = writeln!(out, "{}\r", ui::RULE);
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
    use super::{clean_log_line, render_dashboard, render_shutdown, strip_timestamp};
    use crate::{
        config::Config,
        runtime::state::{AppState, MetricsSnapshot},
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
}
