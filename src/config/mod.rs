//! # Config Module
//!
//! **Directory:** `src/config/`

pub mod defaults;
pub mod loader;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub site: SiteConfig,
    pub tor: TorConfig,
    pub logging: LoggingConfig,
    pub console: ConsoleConfig,
    pub identity: IdentityConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub port: u16,
    pub bind: String,
    pub auto_port_fallback: bool,
    pub open_browser_on_start: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiteConfig {
    pub directory: String,
    pub index_file: String,
    pub enable_directory_listing: bool,
    pub auto_reload: bool,
}

/// Controls Tor integration.
///
/// All paths (`tor_data/`, `tor_hidden_service/`, `torrc`) are derived
/// automatically from the binary's data directory — no user configuration
/// needed. The only knob is whether Tor is enabled at all.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TorConfig {
    /// Master on/off switch. When `false`, Tor is never started and the
    /// onion address section of the dashboard is hidden.
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    pub enabled: bool,
    pub level: String,
    pub file: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsoleConfig {
    pub interactive: bool,
    pub refresh_rate_ms: u64,
    pub show_timestamps: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityConfig {
    pub instance_name: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: ServerConfig {
                port: 8080,
                bind: "127.0.0.1".into(),
                auto_port_fallback: true,
                open_browser_on_start: false,
            },
            site: SiteConfig {
                directory: "site".into(),
                index_file: "index.html".into(),
                enable_directory_listing: false,
                auto_reload: false,
            },
            tor: TorConfig { enabled: true },
            logging: LoggingConfig {
                enabled: true,
                level: "info".into(),
                file: "logs/rusthost.log".into(),
            },
            console: ConsoleConfig {
                interactive: true,
                refresh_rate_ms: 500,
                show_timestamps: false,
            },
            identity: IdentityConfig {
                instance_name: "RustHost".into(),
            },
        }
    }
}
