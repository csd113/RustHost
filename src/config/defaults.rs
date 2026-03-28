//! # Config Defaults
//!
//! **Directory:** `src/config/`

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
# "127.0.0.1" — reachable only from this machine (default, recommended).
# "0.0.0.0"   — reachable from the local network (use with care).
bind = "127.0.0.1"

# Silently try the next free port on conflict (up to 10 attempts).
auto_port_fallback = true

# Open the system default browser at http://localhost:<port> on startup.
open_browser_on_start = false

# Maximum number of concurrent HTTP connections. Excess connections queue
# at the OS TCP backlog level rather than spawning unbounded tasks.
max_connections = 256

# Content-Security-Policy level.
#
# Controls the Content-Security-Policy header sent with every HTML response.
# Three presets are available:
#
#   "off"     — No CSP header is sent (default). The browser uses its own
#               defaults, which allow same-origin and most cross-origin
#               resources. Start here; tighten once your site is working.
#
#   "relaxed" — Sends: default-src * 'unsafe-inline' 'unsafe-eval' data: blob:
#               Allows resources from any origin plus inline scripts/styles,
#               eval, data: URIs, and blob URLs. Use when loading assets from
#               external CDNs or third-party services.
#
#   "strict"  — Sends a same-origin-only policy:
#               default-src 'self'; script-src 'self' 'unsafe-inline';
#               style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:;
#               font-src 'self' data:
#               Suitable for self-contained sites with no external assets.
#
# Note: Referrer-Policy: no-referrer is always sent regardless of this setting,
# so the .onion address never leaks to third-party origins via the Referer header.
csp_level = "off"

# ─── [site] ───────────────────────────────────────────────────────────────────

[site]

# Path to the site root, relative to ./rusthost-data/.
directory = "site"

# File served when a request targets a directory.
index_file = "index.html"

# Return an HTML file listing for directory requests instead of index_file.
enable_directory_listing = false

# ─── [tor] ────────────────────────────────────────────────────────────────────

[tor]

# Enable Tor onion service.
#
# When true, RustHost uses the embedded Arti Tor client — no external binary
# or installation required. On first run, Arti downloads ~2 MB of directory
# data (~30 s). Subsequent runs reuse the cached consensus and start fast.
#
# Arti stores its state and cache under:
#   rusthost-data/arti_state/   — service keypair (determines your .onion address)
#   rusthost-data/arti_cache/   — consensus cache (speeds up future startups)
#
# To rotate your .onion address, delete rusthost-data/arti_state/ before
# starting RustHost. The new address will be shown in the dashboard.
enabled = true

# ─── [logging] ────────────────────────────────────────────────────────────────

[logging]

enabled = true

# One of: trace, debug, info, warn, error.
level = "info"

# Log file path relative to ./rusthost-data/.
file = "logs/rusthost.log"

# When true (default), suppress Info/Debug/Trace records from third-party
# crates (Arti, Tokio, TLS internals) so the log file stays focused on
# application events. Warnings and errors from all crates are always shown.
# Set false to see full dependency tracing (useful for debugging Tor issues).
filter_dependencies = true

# ─── [console] ────────────────────────────────────────────────────────────────

[console]

# Enable the interactive terminal dashboard.
# Set false for headless / systemd deployments.
interactive = true

# Dashboard redraw interval in milliseconds (minimum: 100).
refresh_rate_ms = 500

# Prepend HH:MM:SS to each line in the log view.
show_timestamps = false

# ─── [identity] ───────────────────────────────────────────────────────────────

[identity]

# Display name shown in the dashboard header. Maximum 32 characters.
instance_name = "RustHost"

# ─── [tls] ────────────────────────────────────────────────────────────────────

[tls]

# Enable HTTPS / TLS.
#
# When enabled, RustHost starts an HTTPS listener in addition to the plain HTTP
# one. Three certificate modes are available, tried in this order:
#
#   1. [tls.manual_cert]  — you supply your own PEM certificate and key files.
#   2. [tls.acme]         — Let's Encrypt issues and auto-renews a certificate
#                           (requires a public domain name and port 443).
#   3. (fallback)         — a self-signed localhost certificate is generated
#                           automatically for local development.
#
# Set to true to activate. HTTP continues to work alongside HTTPS unless you
# also set redirect_http = true below.
enabled = false

# TCP port for the HTTPS listener (default: 8443).
# Use 443 for production (may require elevated privileges on Linux).
port = 8443

# When true, the plain HTTP listener redirects every request to the HTTPS URL
# with a 301. Requires enabled = true.
redirect_http = false

# Plain-HTTP port used when redirect_http = true (default: 8080).
# This is separate from [server].port — both listeners run simultaneously.
http_port = 8080

# ── Let's Encrypt / ACME (automatic certificate) ─────────────────────────────
#
# Requires a publicly reachable domain name pointing at this server and
# port 443 open (set [tls] port = 443 above).
#
# Always test with staging = true first — Let's Encrypt rate-limits production
# issuance. Flip staging = false only once the full flow works in staging.

[tls.acme]
enabled = false

# Domain(s) to request a certificate for.
# Example: domains = ["example.com", "www.example.com"]
domains = []

# Contact email for expiry notices (recommended but not required).
# Example: email = "admin@example.com"

# true = Let's Encrypt staging (not browser-trusted, high rate limits).
# false = production (browser-trusted, strict rate limits).
staging = true

# ACME certificate cache directory, relative to the data directory.
cache_dir = "tls/acme"

# ── Manual certificate ────────────────────────────────────────────────────────
#
# Paths are relative to the data directory (rusthost-data/).
# Uncomment both lines to activate.
#
# [tls.manual_cert]
# cert_path = "tls/cert.pem"
# key_path  = "tls/key.pem"
"#;

/// Write the default `settings.toml` to `path`, creating parent directories
/// as needed.
///
/// # Errors
///
/// Returns [`crate::AppError::Io`] if the parent directory cannot be created
/// or the file cannot be written.
pub fn write_default_config(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, DEFAULT_SETTINGS)?;
    Ok(())
}
