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
"#;

pub fn write_default_config(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, DEFAULT_SETTINGS)?;
    Ok(())
}
