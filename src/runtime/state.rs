//! # Application State
//! Defines [`AppState`] — the single source of truth for all runtime values.
//! Wrapped in [`SharedState`] (`Arc<RwLock<AppState>>`) so every subsystem
//! can read and write it safely across async tasks and std threads.
//!
//! Hot-path counters (request / error counts) live on [`Metrics`] behind
//! atomics so the server never acquires a lock per request.

use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use std::{
    collections::hash_map::RandomState,
    hash::{BuildHasher as _, Hash},
    time::{Duration, Instant},
};
use tokio::sync::RwLock;

// ─── Type aliases ───────────────────────────────────────────────────────────

/// Thread- and task-safe handle to the shared application state.
pub type SharedState = Arc<RwLock<AppState>>;

/// Thread- and task-safe handle to the hot-path request metrics.
pub type SharedMetrics = Arc<Metrics>;

/// Runtime visitor identity used only to derive an in-memory counter key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VisitorIdentity {
    /// A clearnet visitor represented by the best available remote IP.
    Clearnet(std::net::IpAddr),
    /// Tor ingress does not expose a stable client identity without invasive tracking.
    TorAnonymous,
}

// ─── Enums ──────────────────────────────────────────────────────────────────

/// Current state of the Tor subsystem.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TorStatus {
    /// `[tor] enabled = false` in config.
    Disabled,
    /// Tor bootstrapping; waiting to connect to the network.
    Starting,
    /// `hostname` file read; `.onion` address available in `onion_address`.
    Ready,
    /// Tor failed; the inner `String` is a brief human-readable reason
    /// (e.g. `"bootstrap failed"`, `"stream ended"`) shown in the dashboard.
    Failed(String),
}

/// Describes the active TLS certificate type for the dashboard.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertStatus {
    /// TLS not yet initialised or disabled.
    Unknown,
    /// Auto-generated self-signed certificate (local dev).
    SelfSigned,
    /// Let's Encrypt certificate managed by `rustls-acme`.
    Acme { domain: String },
    /// Manually supplied PEM certificate.
    Manual,
}

/// Which screen the console is currently showing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsoleMode {
    /// Main status dashboard (default).
    Dashboard,
    /// Scrolling log view (toggled by L).
    LogView,
    /// Key-binding help overlay (toggled by H).
    Help,
    /// Quit confirmation prompt (shown after pressing Q).
    ConfirmQuit,
    /// Shutdown is underway after the quit prompt was confirmed.
    ShuttingDown,
}

// ─── AppState ───────────────────────────────────────────────────────────────

/// All mutable runtime values that the console and subsystems share.
///
/// Read-heavy; guarded by a [`tokio::sync::RwLock`] so multiple readers
/// (render loop, key handler) never block each other.
#[derive(Debug, Clone)]
pub struct AppState {
    /// Port the HTTP server is actually listening on (may differ from config
    /// if `auto_port_fallback` kicked in).
    pub actual_port: u16,

    /// Whether the HTTP server is accepting connections.
    pub server_running: bool,

    /// Current phase of the Tor lifecycle.
    pub tor_status: TorStatus,

    /// `.onion` hostname (present only when `tor_status == Ready`).
    pub onion_address: Option<String>,

    /// Number of files found in the site directory.
    pub site_file_count: u32,

    /// Total size of all files in the site directory, in bytes.
    pub site_total_bytes: u64,

    /// Which console screen is active.
    pub console_mode: ConsoleMode,

    /// Whether the HTTPS server is currently accepting connections.
    pub tls_running: bool,

    /// Port the HTTPS server is listening on (set after TLS bind succeeds).
    pub tls_port: Option<u16>,

    /// Describes the active certificate type for the dashboard.
    pub tls_cert_status: CertStatus,

    /// Short operator-facing status line shown in the dashboard.
    pub status_message: Option<String>,
}

impl AppState {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            actual_port: 0,
            server_running: false,
            tor_status: TorStatus::Starting,
            onion_address: None,
            site_file_count: 0,
            site_total_bytes: 0,
            console_mode: ConsoleMode::Dashboard,
            tls_running: false,
            tls_port: None,
            tls_cert_status: CertStatus::Unknown,
            status_message: None,
        }
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Metrics ────────────────────────────────────────────────────────────────

/// Hot-path request counters. Updated via atomics so the HTTP handler
/// never needs to acquire a lock on [`AppState`].
pub struct Metrics {
    started_at: Instant,
    pub requests: AtomicU64,
    pub errors: AtomicU64,
    visitor_hasher: RandomState,
    visitor_keys: dashmap::DashSet<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MetricsSnapshot {
    pub requests: u64,
    pub errors: u64,
    pub unique_visitors: usize,
    pub uptime: Duration,
}

impl Metrics {
    #[must_use]
    pub fn new() -> Self {
        Self {
            started_at: Instant::now(),
            requests: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            visitor_hasher: RandomState::new(),
            visitor_keys: dashmap::DashSet::new(),
        }
    }

    pub fn add_request(&self) {
        self.requests.fetch_add(1, Ordering::Relaxed);
    }

    pub fn add_error(&self) {
        self.errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn add_unique_visitor(&self, identity: VisitorIdentity) {
        let key = self.visitor_hasher.hash_one(identity);
        self.visitor_keys.insert(key);
    }

    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            requests: self.requests.load(Ordering::Relaxed),
            errors: self.errors.load(Ordering::Relaxed),
            unique_visitors: self.visitor_keys.len(),
            uptime: self.started_at.elapsed(),
        }
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Helpers ────────────────────────────────────────────────────────────────

#[expect(
    clippy::cast_precision_loss,
    reason = "Human-readable byte formatting intentionally converts to f64 for decimal units."
)]
#[must_use]
pub fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1_024;
    const MB: u64 = 1_024 * KB;
    const GB: u64 = 1_024 * MB;

    if bytes >= GB {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{bytes} B")
    }
}

#[must_use]
pub fn format_uptime(duration: Duration) -> String {
    const SECS_PER_MINUTE: u64 = 60;
    const SECS_PER_HOUR: u64 = 60 * SECS_PER_MINUTE;
    const SECS_PER_DAY: u64 = 24 * SECS_PER_HOUR;

    let total = duration.as_secs();
    let days = total / SECS_PER_DAY;
    let hours = (total % SECS_PER_DAY) / SECS_PER_HOUR;
    let minutes = (total % SECS_PER_HOUR) / SECS_PER_MINUTE;
    let seconds = total % SECS_PER_MINUTE;

    if days > 0 {
        format!("{days}d {hours:02}h {minutes:02}m {seconds:02}s")
    } else if hours > 0 {
        format!("{hours}h {minutes:02}m {seconds:02}s")
    } else if minutes > 0 {
        format!("{minutes}m {seconds:02}s")
    } else {
        format!("{seconds:02}s")
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::{format_uptime, Metrics, VisitorIdentity};
    use std::{
        net::{IpAddr, Ipv4Addr, Ipv6Addr},
        time::Duration,
    };

    #[test]
    fn same_visitor_counted_once() {
        let metrics = Metrics::new();
        let visitor = VisitorIdentity::Clearnet(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)));

        metrics.add_unique_visitor(visitor);
        metrics.add_unique_visitor(visitor);

        assert_eq!(metrics.snapshot().unique_visitors, 1);
    }

    #[test]
    fn different_visitors_counted_separately() {
        let metrics = Metrics::new();

        metrics.add_unique_visitor(VisitorIdentity::Clearnet(IpAddr::V4(Ipv4Addr::new(
            203, 0, 113, 10,
        ))));
        metrics.add_unique_visitor(VisitorIdentity::Clearnet(IpAddr::V6(Ipv6Addr::LOCALHOST)));

        assert_eq!(metrics.snapshot().unique_visitors, 2);
    }

    #[test]
    fn tor_anonymous_bucket_counts_once() {
        let metrics = Metrics::new();

        metrics.add_unique_visitor(VisitorIdentity::TorAnonymous);
        metrics.add_unique_visitor(VisitorIdentity::TorAnonymous);

        assert_eq!(metrics.snapshot().unique_visitors, 1);
    }

    #[test]
    fn uptime_under_one_minute() {
        assert_eq!(format_uptime(Duration::from_secs(9)), "09s");
    }

    #[test]
    fn uptime_minutes() {
        assert_eq!(format_uptime(Duration::from_secs(125)), "2m 05s");
    }

    #[test]
    fn uptime_hours() {
        assert_eq!(format_uptime(Duration::from_secs(7_265)), "2h 01m 05s");
    }

    #[test]
    fn uptime_days() {
        assert_eq!(
            format_uptime(Duration::from_secs(176_461)),
            "2d 01h 01m 01s"
        );
    }
}
