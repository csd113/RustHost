//! # Config Module
//!
//! **Directory:** `src/config/`
pub mod defaults;
pub mod loader;
use log::LevelFilter;
use serde::{Deserialize, Deserializer, Serialize};
use std::net::IpAddr;
use std::num::NonZeroU16;

// ─── Log level ───────────────────────────────────────────────────────────────
/// Typed log-level value that serde deserialises directly from the TOML string.
///
/// Replaces the `level: String` field + the duplicate `parse_level` /
/// validation logic that previously existed in both `loader.rs` and
/// `logging/mod.rs` (fix 4.2). An invalid value (e.g. `level = "verbose"`)
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
fn deserialize_ip_addr<'de, D: Deserializer<'de>>(d: D) -> Result<IpAddr, D::Error> {
    let s = String::deserialize(d)?;
    s.parse().map_err(serde::de::Error::custom)
}

/// Serialise `IpAddr` back to a string for round-trip TOML serialisation.
fn serialize_ip_addr<S: serde::Serializer>(addr: &IpAddr, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&addr.to_string())
}

// ─── Default value helpers (for serde + Config::default) ─────────────────────
// Numeric / bool / enum helpers are `const fn` (compile-time evaluable).
// String helpers are ordinary `fn` for maximum Rust version compatibility
// (`String::from` is not `const` in all MSRV versions).

const fn default_https_port() -> NonZeroU16 {
    match NonZeroU16::new(8443) {
        Some(v) => v,
        None => NonZeroU16::MIN,
    }
}
const fn default_http_port() -> NonZeroU16 {
    match NonZeroU16::new(8080) {
        Some(v) => v,
        None => NonZeroU16::MIN,
    }
}
fn default_acme_dir() -> String {
    String::from("tls/acme")
}
const fn default_redirect_status() -> u16 {
    301
}
const fn default_max_connections_per_ip() -> u32 {
    16
}
const fn default_true() -> bool {
    true
}

/// Server defaults
const fn default_server_port() -> NonZeroU16 {
    match NonZeroU16::new(8080) {
        Some(v) => v,
        None => NonZeroU16::MIN,
    }
}
const fn default_bind() -> IpAddr {
    IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
}
const fn default_max_connections() -> u32 {
    256
}

/// Site defaults
fn default_site_directory() -> String {
    String::from("site")
}
fn default_index_file() -> String {
    String::from("index.html")
}

/// Logging defaults
const fn default_logging_enabled() -> bool {
    true
}
const fn default_logging_level() -> LogLevel {
    LogLevel::Info
}
fn default_logging_file() -> String {
    String::from("logs/rusthost.log")
}

/// Console defaults
const fn default_console_interactive() -> bool {
    true
}
const fn default_console_refresh_rate() -> u64 {
    500
}
const fn default_console_timestamps() -> bool {
    false
}

/// Identity default
fn default_instance_name() -> String {
    String::from("RustHost")
}

// ─── CSP level ───────────────────────────────────────────────────────────────
/// Preset Content-Security-Policy levels selectable in `settings.toml`.
///
/// | Level | CSP header sent | Use case |
/// |-----------|-----------------------------------------------------------|-------------------------------|
/// | `off` | *(none)* | Dev / any site, zero friction |
/// | `relaxed` | `default-src * 'unsafe-inline' 'unsafe-eval' data: blob:` | Sites with external CDNs |
/// | `strict` | same-origin only + inline scripts/styles | High-security deployments |
///
/// The default is `off` so pages render correctly out of the box.
/// Tighten once you know which external origins your site actually needs.
///
/// **Tor note:** `Referrer-Policy: no-referrer` is always sent regardless of
/// this setting, preventing the `.onion` address from leaking to third parties.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum CspLevel {
    /// No `Content-Security-Policy` header is sent. The browser applies its
    /// own defaults. Recommended starting point — tighten once the site works.
    #[default]
    Off,
    /// Sends `default-src * 'unsafe-inline' 'unsafe-eval' data: blob:`.
    ///
    /// Permits resources from any origin, inline scripts/styles, `eval`,
    /// `data:` URIs, and blob URLs. Use when loading assets from external CDNs.
    Relaxed,
    /// Sends a same-origin-only policy with inline scripts and styles permitted.
    ///
    /// Policy: `default-src 'self'; script-src 'self' 'unsafe-inline';
    /// style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:;
    /// font-src 'self' data:`
    ///
    /// Suitable for self-contained sites that serve all assets locally.
    Strict,
}
impl CspLevel {
    /// Return the literal CSP header value for this level, or an empty string
    /// when the level is [`CspLevel::Off`] (no header should be sent).
    #[must_use]
    pub const fn as_header_value(self) -> &'static str {
        match self {
            Self::Off => "",
            Self::Relaxed => "default-src * 'unsafe-inline' 'unsafe-eval' data: blob:",
            Self::Strict => {
                "default-src 'self'; \
                 script-src 'self' 'unsafe-inline'; \
                 style-src 'self' 'unsafe-inline'; \
                 img-src 'self' data: blob:; \
                 font-src 'self' data:"
            }
        }
    }
}

// ─── TLS config ──────────────────────────────────────────────────────────────
/// Top-level TLS configuration block (`[tls]` in `settings.toml`).
///
/// All fields default to off/safe values so existing configs with no `[tls]`
/// section continue to work identically (`TlsConfig::default()` → HTTP-only).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TlsConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_https_port")]
    pub port: NonZeroU16,
    #[serde(default)]
    pub redirect_http: bool,
    #[serde(default = "default_http_port")]
    pub http_port: NonZeroU16,
    #[serde(default)]
    pub acme: AcmeConfig,
    pub manual_cert: Option<ManualCertConfig>,
}
impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            port: default_https_port(),
            redirect_http: false,
            http_port: default_http_port(),
            acme: AcmeConfig::default(),
            manual_cert: None,
        }
    }
}

/// Let's Encrypt / ACME configuration (`[tls.acme]` in `settings.toml`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct AcmeConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub domains: Vec<String>,
    pub email: Option<String>,
    /// When `true` (the default), use Let's Encrypt's staging environment.
    /// Staging certs are not trusted by browsers but have much higher rate
    /// limits — always test with `staging = true` before flipping to `false`.
    #[serde(default = "default_true")]
    pub staging: bool,
    /// Directory for the ACME [`DirCache`] (relative to the data dir).
    #[serde(default = "default_acme_dir")]
    pub cache_dir: String,
}

/// Paths to a manually-managed certificate chain and private key
/// (`[tls.manual_cert]` in `settings.toml`).
///
/// Both paths are resolved relative to the data directory at runtime.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManualCertConfig {
    pub cert_path: String,
    pub key_path: String,
}

/// A single URL redirect or rewrite rule, matched before filesystem resolution.
///
/// Example `settings.toml` entry:
/// ```toml
/// [[redirects]]
/// from = "/old-page"
/// to = "/new-page"
/// status = 301
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedirectRule {
    /// Source URL path to match (exact match).
    pub from: String,
    /// Destination URL (may be a relative path or absolute URL).
    pub to: String,
    /// HTTP status code — 301 for permanent, 302 for temporary.
    #[serde(default = "default_redirect_status")]
    pub status: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub server: ServerConfig,
    pub site: SiteConfig,
    pub tor: TorConfig,
    pub logging: LoggingConfig,
    pub console: ConsoleConfig,
    pub identity: IdentityConfig,
    /// URL redirect/rewrite rules evaluated before filesystem resolution.
    /// Declared as `[[redirects]]` array-of-tables in `settings.toml`.
    /// Addresses M-13.
    #[serde(default)]
    pub redirects: Vec<RedirectRule>,
    /// TLS / HTTPS configuration. All fields default to disabled so existing
    /// configs without a `[tls]` section are unaffected.
    #[serde(default)]
    pub tls: TlsConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// Non-zero port number. `NonZeroU16` prevents port 0 at the type level:
    /// serde rejects a zero value during deserialisation.
    #[serde(default = "default_server_port")]
    pub port: NonZeroU16,

    /// Network interface to bind to. Parsed from TOML string at load time;
    /// an invalid IP address is rejected immediately.
    #[serde(
        default = "default_bind",
        deserialize_with = "deserialize_ip_addr",
        serialize_with = "serialize_ip_addr"
    )]
    pub bind: IpAddr,

    #[serde(default)]
    pub auto_port_fallback: bool,

    #[serde(default)]
    pub open_browser_on_start: bool,

    #[serde(default = "default_max_connections")]
    pub max_connections: u32,

    /// Maximum concurrent connections from a single IP address.
    ///
    /// Prevents a single client from monopolising the connection pool.
    /// When the limit is reached the connection is dropped at the TCP level —
    /// the OS sends a RST so no HTTP overhead is incurred.
    ///
    /// Must be ≥ 1 and ≤ `max_connections`. Validated in `loader.rs`.
    /// Defaults to 16, which is generous for browsers (typically 6–8 parallel
    /// connections) while preventing trivial single-client exhaustion attacks.
    #[serde(default = "default_max_connections_per_ip")]
    pub max_connections_per_ip: u32,

    /// Content-Security-Policy preset. See [`CspLevel`] for available values
    /// (`"off"`, `"relaxed"`, `"strict"`) and the header each one sends.
    /// Defaults to `"off"` — no CSP header, maximum browser compatibility.
    #[serde(default)]
    pub csp_level: CspLevel,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SiteConfig {
    #[serde(default = "default_site_directory")]
    pub directory: String,

    #[serde(default = "default_index_file")]
    pub index_file: String,

    #[serde(default)]
    pub enable_directory_listing: bool,

    /// When `true`, directory listings and direct requests expose dot-files
    /// (e.g. `.git/`, `.env`). Defaults to `false` so hidden files are not
    /// accidentally served.
    #[serde(default)]
    pub expose_dotfiles: bool,

    /// When `true`, requests for paths that don't match any file are served
    /// `index.html` (with status 200) instead of a 404.
    /// Required for single-page applications with client-side routing
    /// (`React Router`, `Vue Router`, `SvelteKit`, etc.).
    /// Addresses C-6 — React/Vue/Svelte apps silently 404 without this.
    #[serde(default)]
    pub spa_routing: bool,

    /// Optional custom 404 page path, relative to the site directory.
    /// When set and the file exists, it is served with status 404 for all
    /// requests that resolve to `NotFound`. Addresses H-10.
    #[serde(default)]
    pub error_404: Option<String>,

    /// Optional custom 500/503 page path, relative to the site directory.
    /// Served with status 503 when the server cannot fulfil the request due
    /// to internal errors.
    #[serde(default)]
    pub error_503: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TorConfig {
    /// Master on/off switch. When `false`, Tor is never started and the
    /// onion address section of the dashboard is hidden.
    #[serde(default = "default_true")]
    pub enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoggingConfig {
    #[serde(default = "default_logging_enabled")]
    pub enabled: bool,

    /// Log level, parsed from a lowercase string (`"trace"` … `"error"`).
    /// Invalid values are rejected at config-load time (fix 4.2).
    #[serde(default = "default_logging_level")]
    pub level: LogLevel,

    #[serde(default = "default_logging_file")]
    pub file: String,

    /// When `true` (default), suppress `Info`-and-below records from
    /// third-party crates (Arti, Tokio, TLS internals) so the log file stays
    /// focused on application events. Warnings and errors from all crates are
    /// always passed through. Set `false` for full dependency tracing (fix 4.3).
    #[serde(default = "default_true")]
    pub filter_dependencies: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsoleConfig {
    #[serde(default = "default_console_interactive")]
    pub interactive: bool,

    #[serde(default = "default_console_refresh_rate")]
    pub refresh_rate_ms: u64,

    #[serde(default = "default_console_timestamps")]
    pub show_timestamps: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityConfig {
    #[serde(default = "default_instance_name")]
    pub instance_name: String,
}

// ─── Default config ──────────────────────────────────────────────────────────
impl Default for Config {
    fn default() -> Self {
        Self {
            server: ServerConfig {
                port: default_server_port(),
                bind: default_bind(),
                auto_port_fallback: true,
                open_browser_on_start: false,
                max_connections: default_max_connections(),
                max_connections_per_ip: default_max_connections_per_ip(),
                csp_level: CspLevel::Off,
            },
            site: SiteConfig {
                directory: default_site_directory(),
                index_file: default_index_file(),
                enable_directory_listing: false,
                expose_dotfiles: false,
                spa_routing: false,
                error_404: None,
                error_503: None,
            },
            tor: TorConfig { enabled: true },
            logging: LoggingConfig {
                enabled: default_logging_enabled(),
                level: default_logging_level(),
                file: default_logging_file(),
                filter_dependencies: true,
            },
            console: ConsoleConfig {
                interactive: default_console_interactive(),
                refresh_rate_ms: default_console_refresh_rate(),
                show_timestamps: default_console_timestamps(),
            },
            identity: IdentityConfig {
                instance_name: default_instance_name(),
            },
            redirects: Vec::new(),
            tls: TlsConfig::default(),
        }
    }
}
