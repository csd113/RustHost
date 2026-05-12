//! # Dashboard Renderer
use crate::{
    config::Config,
    logging,
    runtime::state::{format_bytes, AppState, CertStatus, TorStatus},
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

const RULE: &str = "────────────────────────────────";
// ─── Dashboard ───────────────────────────────────────────────────────────────
#[must_use]
pub fn render_dashboard(state: &AppState, requests: u64, errors: u64, config: &Config) -> String {
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
    if let Some(message) = state.status_message.as_deref() {
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
    let _ = writeln!(out, " Requests : {requests}\r");
    let err_str = if errors > 0 {
        red(&errors.to_string())
    } else {
        errors.to_string()
    };
    let _ = writeln!(out, " Errors : {err_str}\r");
    out.push_str("\r\n");
    // ── Key bar ───────────────────────────────────────────────────────────────
    let _ = writeln!(out, "{RULE}\r");
    out.push_str("[H] Help [R] Reload [O] Open [L] Logs [Q] Quit\r\n");
    let _ = writeln!(out, "{RULE}\r");
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
    let _ = writeln!(out, "{RULE}\r");
    out.push_str("[L] Back to dashboard [Q] Quit\r\n");
    let _ = writeln!(out, "{RULE}\r");
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
    let _ = writeln!(out, " {} Graceful shutdown\r", bold("[Q]"));
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
    use super::{clean_log_line, render_shutdown, strip_timestamp};
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
}
