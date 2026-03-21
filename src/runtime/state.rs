//! # Application State
//!
//! **Directory:** `src/runtime/`
//!
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
use tokio::sync::RwLock;

// ─── Type aliases ───────────────────────────────────────────────────────────

/// Thread- and task-safe handle to the shared application state.
pub type SharedState = Arc<RwLock<AppState>>;

/// Thread- and task-safe handle to the hot-path request metrics.
pub type SharedMetrics = Arc<Metrics>;

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

/// Which screen the console is currently showing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsoleMode {
    /// Main status dashboard (default).
    Dashboard,
    /// Scrolling log view (toggled by L).
    LogView,
    /// Key-binding help overlay (toggled by H).
    Help,
}

// ─── AppState ───────────────────────────────────────────────────────────────

/// All mutable runtime values that the console and subsystems share.
///
/// Read-heavy; guarded by a [`tokio::sync::RwLock`] so multiple readers
/// (render loop, key handler) never block each other.
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
    pub requests: AtomicU64,
    pub errors: AtomicU64,
}

impl Metrics {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            requests: AtomicU64::new(0),
            errors: AtomicU64::new(0),
        }
    }

    pub fn add_request(&self) {
        self.requests.fetch_add(1, Ordering::Relaxed);
    }

    pub fn add_error(&self) {
        self.errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> (u64, u64) {
        (
            self.requests.load(Ordering::Relaxed),
            self.errors.load(Ordering::Relaxed),
        )
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Helpers ────────────────────────────────────────────────────────────────

#[allow(clippy::cast_precision_loss)]
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
