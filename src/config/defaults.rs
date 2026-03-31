//! # Config Defaults
//!
//! **File:** `defaults.rs`
//! **Location:** `src/config/defaults.rs`

use crate::Result;
use std::path::Path;

const DEFAULT_SETTINGS: &str = r#"# ─── RustHost Configuration ──────────────────────────────────────────────────
# Automatically generated on first run. Edit freely; RustHost reloads this
# file when you press [R] in the dashboard.
# ─── [server] ─────────────────────────────────────────────────────────────────

[server]
# TCP port for the local HTTP server.
port = 8080

# Network interface to bind to.
# "127.0.0.1" — localhost only (default, recommended)
# "0.0.0.0"   — reachable from LAN (use with care)
bind = "127.0.0.1"

# Silently try the next free port on conflict (up to 10 attempts).
auto_port_fallback = true

# Open the system default browser at startup.
open_browser_on_start = false

# Maximum concurrent HTTP connections.
max_connections = 256

# Content-Security-Policy preset: "off" | "relaxed" | "strict"
# (see full explanation below)
csp_level = "off"

# ─── [site] ───────────────────────────────────────────────────────────────────

[site]
# Site root relative to ./rusthost-data/
directory = "site"

# File served for directory requests.
index_file = "index.html"

# Show directory listing instead of index_file.
enable_directory_listing = false

# ─── [tor] ────────────────────────────────────────────────────────────────────

[tor]
# Enable built-in Tor onion service (Arti client, no external binary needed).
# First run downloads ~2 MB consensus (~30 s). Later runs are instant.
enabled = true

# ─── [logging] ────────────────────────────────────────────────────────────────

[logging]
enabled = true
# One of: trace, debug, info, warn, error
level = "info"

# Log file relative to ./rusthost-data/
file = "logs/rusthost.log"

# Hide noisy third-party logs (Arti, Tokio, etc.) by default.
filter_dependencies = true

# ─── [console] ────────────────────────────────────────────────────────────────

[console]
# Interactive dashboard (set false for headless/systemd).
interactive = true

# Dashboard refresh rate (ms, minimum 100).
refresh_rate_ms = 500

# Show HH:MM:SS timestamps in the log view.
show_timestamps = false

# ─── [identity] ───────────────────────────────────────────────────────────────

[identity]
# Dashboard header name (max 32 characters).
instance_name = "RustHost"

# ─── [tls] ────────────────────────────────────────────────────────────────────

[tls]
# Enable HTTPS listener (plain HTTP continues unless redirect_http = true).
enabled = false

# HTTPS port (default 8443; use 443 for production).
port = 8443

# Redirect every HTTP request to HTTPS (301).
redirect_http = false

# ── IMPORTANT: Port conflict warning ───────────────────────────────────────
# When redirect_http = true the redirect listener binds to http_port.
# The main HTTP listener (when active) uses [server].port.
# Both defaults are currently 8080 — change one of them before enabling
# both TLS + redirect_http or the server will fail to bind.
http_port = 8080

# ── Let's Encrypt / ACME ─────────────────────────────────────────────────────

[tls.acme]
enabled = false
# Domains to request cert for (required if ACME enabled).
domains = []
# Contact email for expiry notices.
email = ""
# true = staging (recommended for testing), false = production.
staging = true
# Cache directory relative to data dir.
cache_dir = "tls/acme"

# ── Manual certificate (uncomment to use your own cert) ───────────────────────

# [tls.manual_cert]
# cert_path = "tls/cert.pem"
# key_path = "tls/key.pem"
"#;

/// Write the default `settings.toml` **only if it does not already exist**.
/// This prevents accidentally destroying a user's custom configuration.
///
/// Parent directories are created automatically.
/// Uses a simple, atomic-enough write for a one-time default file.
///
/// # Errors
///
/// Returns [`crate::AppError::Io`] on any filesystem error.
pub fn write_default_config(path: &Path) -> Result<()> {
    // ←←← NEVER overwrite an existing config (critical safety improvement)
    if path.exists() {
        return Ok(());
    }

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    std::fs::write(path, DEFAULT_SETTINGS)?;
    Ok(())
}
