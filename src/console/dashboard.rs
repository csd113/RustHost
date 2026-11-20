//! # Dashboard Renderer
use crate::{
    config::Config,
    console::ui,
    logging,
    path_display::display_path,
    runtime::{
        service_status::{AcmeStatus, ListenerStatus, RuntimeStatus, TorPhase},
        state::{format_bytes, format_uptime, AppState, CertStatus, MetricsSnapshot},
    },
};
use std::fmt::Write as _;
use std::path::Path;

// ─── Dashboard ───────────────────────────────────────────────────────────────
#[must_use]
pub fn render_dashboard(
    state: &AppState,
    metrics: MetricsSnapshot,
    config: &Config,
    data_dir: &Path,
) -> String {
    let status = RuntimeStatus::from_legacy(state, config);
    render_dashboard_with_status(state, &status, metrics, config, data_dir)
}

pub(super) fn render_dashboard_with_status(
    state: &AppState,
    status: &RuntimeStatus,
    metrics: MetricsSnapshot,
    config: &Config,
    data_dir: &Path,
) -> String {
    let mut out = String::with_capacity(1_024);
    ui::push_header(&mut out, &config.identity.instance_name);
    out.push_str("\r\n");
    // ── Status ───────────────────────────────────────────────────────────────
    let _ = writeln!(out, "{}\r", ui::bold("Status"));
    render_listener_status(&mut out, state, status);
    let tor_str = match &status.tor {
        TorPhase::Disabled => ui::dim("DISABLED"),
        TorPhase::Starting => ui::yellow("STARTING — bootstrapping Tor network…"),
        TorPhase::Ready => ui::green("READY — forwarding locally"),
        TorPhase::Reconnecting => ui::yellow("RECONNECTING"),
        TorPhase::Draining => ui::yellow("DRAINING"),
        TorPhase::Stopped => ui::dim("STOPPED"),
        TorPhase::Failed(reason) => ui::red(&format!("FAILED ({reason}) — see log for details")),
    };
    let _ = writeln!(out, " Tor : {tor_str}\r");
    if let Some(message) = state.visible_status_message() {
        let _ = writeln!(out, " Status : {}\r", ui::yellow(message));
    }
    out.push_str("\r\n");
    // ── Endpoints ────────────────────────────────────────────────────────────
    let _ = writeln!(out, "{}\r", ui::bold("Endpoints"));
    if let Some(address) = status.public_http.bound_addr() {
        let url = ui::local_http_url(address.ip(), address.port());
        let _ = writeln!(out, " {} : {url}\r", status.public_http_role.label());
    }
    if let Some(address) = status.https.bound_addr() {
        let url = ui::local_https_url(address.ip(), address.port());
        let _ = writeln!(out, " HTTPS : {}\r", ui::green(&url));
    }
    let onion_str = state.onion_address.as_deref().map_or_else(
        || match &status.tor {
            TorPhase::Disabled => ui::dim("(disabled)"),
            TorPhase::Starting => ui::dim("(bootstrapping…)"),
            TorPhase::Ready => ui::dim("(address unavailable)"),
            TorPhase::Reconnecting => ui::dim("(reconnecting…)"),
            TorPhase::Draining | TorPhase::Stopped | TorPhase::Failed(_) => {
                ui::dim("(unavailable)")
            }
        },
        |addr| format!("http://{addr}"),
    );
    let _ = writeln!(out, " Onion : {onion_str}\r");
    out.push_str("\r\n");
    // ── Site ─────────────────────────────────────────────────────────────────
    let _ = writeln!(out, "{}\r", ui::bold("Site"));
    let _ = writeln!(
        out,
        " Directory : {}\r",
        display_path(&data_dir.join(&config.site.directory))
    );
    let _ = writeln!(out, " Files : {}\r", state.site_file_count);
    let _ = writeln!(out, " Size : {}\r", format_bytes(state.site_total_bytes));
    out.push_str("\r\n");
    // ── Activity ─────────────────────────────────────────────────────────────
    let _ = writeln!(out, "{}\r", ui::bold("Activity"));
    let _ = writeln!(out, " Uptime : {}\r", format_uptime(metrics.uptime));
    let _ = writeln!(out, " Requests : {}\r", metrics.requests);
    render_visitors(&mut out, metrics.unique_visitors);
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

fn render_listener_status(out: &mut String, state: &AppState, status: &RuntimeStatus) {
    let _ = writeln!(
        out,
        " {} : {}\r",
        status.public_http_role.label(),
        listener_status(&status.public_http)
    );
    let https = listener_status(&status.https);
    let cert = match &state.tls_cert_status {
        CertStatus::Unknown => String::new(),
        CertStatus::SelfSigned => " · self-signed".into(),
        CertStatus::Acme { domain } if domain.is_empty() => " · Let's Encrypt".into(),
        CertStatus::Acme { domain } => format!(" · Let's Encrypt ({domain})"),
        CertStatus::Manual => " · manual cert".into(),
    };
    let _ = writeln!(out, " HTTPS : {https}{cert}\r");
    if status.tor_ingress != ListenerStatus::Inactive {
        let _ = writeln!(
            out,
            " Tor ingress : {}\r",
            listener_status(&status.tor_ingress)
        );
    }
    let acme = match &status.acme {
        AcmeStatus::Inactive => return,
        AcmeStatus::Starting => ui::yellow("STARTING"),
        AcmeStatus::Available => ui::green("CERTIFICATE AVAILABLE"),
        AcmeStatus::Retrying(reason) => ui::yellow(&format!("RETRYING ({reason})")),
        AcmeStatus::Failed(reason) => ui::red(&format!("FAILED ({reason})")),
        AcmeStatus::Stopped => ui::dim("STOPPED"),
    };
    let _ = writeln!(out, " ACME : {acme}\r");
}

fn listener_status(status: &ListenerStatus) -> String {
    match status {
        ListenerStatus::Inactive => ui::dim("DISABLED"),
        ListenerStatus::Starting => ui::yellow("STARTING…"),
        ListenerStatus::Listening(address) => ui::green(&format!("LISTENING ({address})")),
        ListenerStatus::Draining => ui::yellow("DRAINING"),
        ListenerStatus::Stopped => ui::dim("STOPPED"),
        ListenerStatus::Failed(reason) => ui::red(&format!("FAILED ({reason})")),
    }
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
    let _ = writeln!(out, " {} Open the menu\r", ui::bold("[M]"));
    let _ = writeln!(out, " {} Quit RustHost\r", ui::bold("[Q]"));
    out.push_str("\r\n");
    let _ = writeln!(
        out,
        "{}\r",
        ui::dim("Press Esc to return to the dashboard.")
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
    // Single pass: drop box-drawing border characters, then trim. Avoids the
    // four intermediate `String::replace` allocations per line per frame.
    let filtered: String = line
        .chars()
        .filter(|c| !matches!(c, '╔' | '═' | '╗' | '╠' | '╣' | '╚' | '╝' | '║'))
        .collect();
    filtered.trim().to_owned()
}
// ─── Unit tests ───────────────────────────────────────────────────────────────
fn render_visitors(out: &mut String, count: usize) {
    let _ = writeln!(out, " Unique visitors : {}\r", visitor_count_label(count));
}

fn visitor_count_label(count: usize) -> String {
    let suffix = if count >= crate::runtime::state::MAX_TRACKED_VISITORS {
        "+"
    } else {
        ""
    };
    format!("{count}{suffix}")
}
