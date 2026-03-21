//! # Application Error Types
//!
//! **Directory:** `src/`
//!
//! Defines [`AppError`], the single typed error enum for the entire application.
//! All public functions returning `Result<T>` use `Result<T, AppError>` via the
//! crate-level alias in `main.rs`.
//!
//! Variants are scoped to the subsystem that produces them so callers can match
//! on the specific failure kind rather than inspecting a `Box<dyn Error>` string.

use thiserror::Error;

/// Typed application error.
#[derive(Debug, Error)]
pub enum AppError {
    /// Config file could not be read or TOML-parsed.
    #[error("Config load error: {0}")]
    ConfigLoad(String),

    /// Config was parsed successfully but failed semantic validation.
    ///
    /// The inner `Vec` contains one human-readable message per violated rule.
    #[error("settings.toml has {} error(s):\n  • {}", .0.len(), .0.join("\n  • "))]
    ConfigValidation(Vec<String>),

    /// The global `log` logger could not be initialised.
    #[error("Log init error: {0}")]
    LogInit(String),

    /// TCP bind failed for a specific port.
    #[error("Could not bind port {port}: {source}")]
    ServerBind { port: u16, source: std::io::Error },

    /// The HTTP server task exited before signalling its bound port, or the
    /// bind-port handshake timed out.
    #[error("Server startup error: {0}")]
    ServerStartup(String),

    /// An error originating in the Tor / Arti subsystem.
    #[error("Tor error: {0}")]
    Tor(String),

    /// Console / terminal I/O error (crossterm or raw-mode operations).
    #[error("Console error: {0}")]
    Console(String),

    /// Transparent wrapper for any `std::io::Error` not covered by a more
    /// specific variant.  The `#[from]` attribute means `?` on any
    /// `io::Result` in the codebase converts automatically.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}
