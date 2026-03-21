//! # Dashboard Renderer
//!
//! **Directory:** `src/console/`

use std::fmt::Write as _;

use crate::{
    config::Config,
    logging,
    runtime::state::{format_bytes, AppState, TorStatus},
};

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

const RULE: &str = "────────────────────────────────";

// ─── Dashboard ───────────────────────────────────────────────────────────────

pub fn render_dashboard(state: &AppState, requests: u64, errors: u64, config: &Config) -> String {
    let mut out = String::with_capacity(1_024);

    let _ = writeln!(out, "{RULE}\r");
    let _ = writeln!(out, "  {}\r", bold(&config.identity.instance_name));
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
    let _ = writeln!(out, "  Local Server : {server_str}\r");

    let tor_str = match &state.tor_status {
        TorStatus::Disabled => dim("DISABLED"),
        TorStatus::Starting => yellow("STARTING — polling for .onion address…"),
        TorStatus::Ready => green("READY"),
        TorStatus::Failed(reason) => red(&format!("FAILED ({reason}) — see log for details")),
    };
    let _ = writeln!(out, "  Tor          : {tor_str}\r");
    out.push_str("\r\n");

    // ── Endpoints ────────────────────────────────────────────────────────────
    let _ = writeln!(out, "{}\r", bold("Endpoints"));
    let _ = writeln!(out, "  Local : http://localhost:{}\r", state.actual_port);

    let onion_str = state.onion_address.as_deref().map_or_else(
        || match &state.tor_status {
            TorStatus::Disabled => dim("(disabled)"),
            TorStatus::Starting => dim("(bootstrapping…)"),
            TorStatus::Ready => dim("(reading…)"),
            TorStatus::Failed(_) => dim("(unavailable)"),
        },
        |addr| format!("http://{addr}"),
    );
    let _ = writeln!(out, "  Onion : {onion_str}\r");
    out.push_str("\r\n");

    // ── Site ─────────────────────────────────────────────────────────────────
    let _ = writeln!(out, "{}\r", bold("Site"));
    let _ = writeln!(
        out,
        "  Directory : ./rusthost-data/{}\r",
        config.site.directory
    );
    let _ = writeln!(out, "  Files     : {}\r", state.site_file_count);
    let _ = writeln!(
        out,
        "  Size      : {}\r",
        format_bytes(state.site_total_bytes)
    );
    out.push_str("\r\n");

    // ── Activity ─────────────────────────────────────────────────────────────
    let _ = writeln!(out, "{}\r", bold("Activity"));
    let _ = writeln!(out, "  Requests  : {requests}\r");

    let err_str = if errors > 0 {
        red(&errors.to_string())
    } else {
        errors.to_string()
    };
    let _ = writeln!(out, "  Errors    : {err_str}\r");
    out.push_str("\r\n");

    // ── Key bar ───────────────────────────────────────────────────────────────
    let _ = writeln!(out, "{RULE}\r");
    out.push_str("[H] Help   [R] Reload   [O] Open   [L] Logs   [Q] Quit\r\n");
    let _ = writeln!(out, "{RULE}\r");

    out
}

// ─── Log view ────────────────────────────────────────────────────────────────

pub fn render_log_view(show_timestamps: bool) -> String {
    let lines = logging::recent_lines(40);

    let mut out = String::with_capacity(2_048);
    let _ = writeln!(out, "{RULE}\r");
    let _ = writeln!(out, "  {} — Log View\r", bold("RustHost"));
    let _ = writeln!(out, "{RULE}\r");

    for line in &lines {
        let display = if show_timestamps {
            line.as_str()
        } else {
            strip_timestamp(line)
        };
        let _ = writeln!(out, "{display}\r");
    }

    out.push_str("\r\n");
    let _ = writeln!(out, "{RULE}\r");
    out.push_str("[L] Back to dashboard   [Q] Quit\r\n");
    let _ = writeln!(out, "{RULE}\r");

    out
}

// ─── Help ────────────────────────────────────────────────────────────────────

pub fn render_help() -> String {
    let mut out = String::with_capacity(512);
    let _ = writeln!(out, "{RULE}\r");
    let _ = writeln!(out, "  {} — Help\r", bold("RustHost"));
    let _ = writeln!(out, "{RULE}\r");
    out.push_str("\r\n");
    let _ = writeln!(out, "  {}  Show this help screen\r", bold("[H]"));
    let _ = writeln!(
        out,
        "  {}  Rescan site directory and update stats\r",
        bold("[R]")
    );
    let _ = writeln!(out, "  {}  Open local URL in system browser\r", bold("[O]"));
    let _ = writeln!(out, "  {}  Toggle log view\r", bold("[L]"));
    let _ = writeln!(out, "  {}  Graceful shutdown\r", bold("[Q]"));
    out.push_str("\r\n");
    let _ = writeln!(
        out,
        "{}\r",
        dim("Press any key to return to the dashboard.")
    );
    let _ = writeln!(out, "{RULE}\r");
    out
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn strip_timestamp(line: &str) -> &str {
    // Split on ']', skip the first two tokens ([level] and [timestamp]),
    // return the remainder trimmed. Uses splitn so we stop after the third
    // piece and never slice at a non-character boundary.
    let mut parts = line.splitn(3, ']');
    parts.next(); // consume "[level"
    parts.next(); // consume "[timestamp"
    parts.next().map_or(line, str::trim_start)
}
