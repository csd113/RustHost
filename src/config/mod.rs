//! # Config Module
//!
//! **Directory:** `src/config/`

pub mod defaults;
pub mod loader;

use std::net::IpAddr;
use std::num::NonZeroU16;

use log::LevelFilter;
use serde::{Deserialize, Deserializer, Serialize};

// ─── Log level ───────────────────────────────────────────────────────────────

/// Typed log-level value that serde deserialises directly from the TOML string.
///
/// Replaces the `level: String` field + the duplicate `parse_level` /
/// validation logic that previously existed in both `loader.rs` and
/// `logging/mod.rs` (fix 4.2).  An invalid value (e.g. `level = "verbose"`)
/// is now rejected at parse time with a clear serde error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

impl From<LogLevel> for LevelFilter {
    fn from(level: LogLevel) -> Self {
        match level {
            LogLevel::Trace => Self::Trace,
            LogLevel::Debug => Self::Debug,
            LogLevel::Info => Self::Info,
            LogLevel::Warn => Self::Warn,
            LogLevel::Error => Self::Error,
        }
    }
}

// ─── Serde helpers ────────────────────────────────────────────────────────────

/// Deserialise `bind` from a TOML string directly into `IpAddr`.
///
/// Replaces the post-parse `.parse::<IpAddr>()` check in `loader.rs` with a
/// parse-time error so an invalid IP is caught the moment the file is read
/// (fix 4.2).
fn deserialize_ip_addr<'de, D: Deserializer<'de>>(d: D) -> Result<IpAddr, D::Error> {
    let s = String::deserialize(d)?;
    s.parse().map_err(serde::de::Error::custom)
}

/// Serialise `IpAddr` back to a string for round-trip TOML serialisation.
fn serialize_ip_addr<S: serde::Serializer>(addr: &IpAddr, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&addr.to_string())
}

// ─── Config structs ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub server: ServerConfig,
    pub site: SiteConfig,
    pub tor: TorConfig,
    pub logging: LoggingConfig,
    pub console: ConsoleConfig,
    pub identity: IdentityConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// Non-zero port number.  `NonZeroU16` prevents port 0 at the type level:
    /// serde rejects a zero value during deserialisation (fix 4.2).
    pub port: NonZeroU16,

    /// Network interface to bind to.  Parsed from TOML string at load time;
    /// an invalid IP address is rejected immediately (fix 4.2).
    #[serde(
        deserialize_with = "deserialize_ip_addr",
        serialize_with = "serialize_ip_addr"
    )]
    pub bind: IpAddr,

    pub auto_port_fallback: bool,
    pub open_browser_on_start: bool,
    pub max_connections: u32,

    /// Value of the `Content-Security-Policy` header sent with every HTML
    /// response (task 5.3).  The default `"default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'"` restricts all
    /// content to the same origin.
    ///
    /// Operators serving CDN fonts, analytics scripts, or other third-party
    /// resources can relax this without touching source code, e.g.:
    ///
    /// ```toml
    /// [server]
    /// content_security_policy = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; script-src 'self' cdn.example.com"
    /// ```
    ///
    /// **Tor note:** `Referrer-Policy: no-referrer` is always sent regardless
    /// of this setting, preventing the `.onion` URL from leaking to any
    /// third-party origin referenced in served HTML.
    pub content_security_policy: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SiteConfig {
    pub directory: String,
    pub index_file: String,
    pub enable_directory_listing: bool,
    // `auto_reload` has been removed: the field was advertised in the default
    // config but never implemented. Old config files containing `auto_reload`
    // will now be rejected at startup with a clear "unknown field" error,
    // prompting the operator to remove the obsolete key (fix 2.6).
}

/// Controls Tor integration.
///
/// All paths (`tor_data/`, `tor_hidden_service/`, `torrc`) are derived
/// automatically from the binary's data directory — no user configuration
/// needed.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TorConfig {
    /// Master on/off switch. When `false`, Tor is never started and the
    /// onion address section of the dashboard is hidden.
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoggingConfig {
    pub enabled: bool,

    /// Log level, parsed from a lowercase string (`"trace"` … `"error"`).
    /// Invalid values are rejected at config-load time (fix 4.2).
    pub level: LogLevel,

    pub file: String,

    /// When `true` (default), suppress `Info`-and-below records from
    /// third-party crates (Arti, Tokio, TLS internals) so the log file stays
    /// focused on application events.  Warnings and errors from all crates are
    /// always passed through.  Set `false` for full dependency tracing (fix 4.3).
    #[serde(default = "default_true")]
    pub filter_dependencies: bool,
}

const fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsoleConfig {
    pub interactive: bool,
    pub refresh_rate_ms: u64,
    pub show_timestamps: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityConfig {
    pub instance_name: String,
}

// ─── Default config ──────────────────────────────────────────────────────────

impl Default for Config {
    fn default() -> Self {
        Self {
            server: ServerConfig {
                port: NonZeroU16::new(8080).unwrap_or(NonZeroU16::MIN),
                bind: "127.0.0.1"
                    .parse()
                    .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
                auto_port_fallback: true,
                open_browser_on_start: false,
                max_connections: 256,
                content_security_policy: "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'".into(),
            },
            site: SiteConfig {
                directory: "site".into(),
                index_file: "index.html".into(),
                enable_directory_listing: false,
            },
            tor: TorConfig { enabled: true },
            logging: LoggingConfig {
                enabled: true,
                level: LogLevel::Info,
                file: "logs/rusthost.log".into(),
                filter_dependencies: true,
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
