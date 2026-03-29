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
//!
//! # Error-chain note
//!
//! Several variants (`ConfigLoad`, `LogInit`, `ServerStartup`, `Console`, `Tls`)
//! store a pre-formatted `String` rather than a typed source error. This is
//! intentional — the originating error types span many heterogeneous crates and
//! are not part of the public API. As a consequence,
//! [`std::error::Error::source`] returns `None` for those variants, severing the
//! error chain for structured loggers and `anyhow` displays. If richer chain
//! information is needed, those variants should be migrated to
//! `Box<dyn std::error::Error + Send + Sync>` annotated with `#[source]`.

use thiserror::Error;

/// Typed application error.
///
/// `#[non_exhaustive]` prevents downstream code from exhaustively matching on
/// this enum, allowing new variants to be added without a semver break.
#[non_exhaustive]
#[derive(Debug, Error)]
pub enum AppError {
    /// Config file could not be read or TOML-parsed.
    ///
    /// The string carries the human-readable reason; the original source error
    /// is not preserved in the chain (see module-level note).
    #[error("Config load error: {0}")]
    ConfigLoad(String),

    /// Config was parsed successfully but failed semantic validation.
    ///
    /// The inner `Vec` contains one human-readable message per violated rule.
    ///
    /// **Invariant:** the vector must be non-empty. Use
    /// [`AppError::config_validation`] to construct this variant safely;
    /// direct construction is permitted but must uphold the invariant. An
    /// empty vector would render as `"has 0 error(s):\n  • "` (orphan bullet).
    #[error("settings.toml has {} error(s):\n  • {}", .0.len(), .0.join("\n  • "))]
    ConfigValidation(Vec<String>),

    /// The global `log` logger could not be initialised.
    #[error("Log init error: {0}")]
    LogInit(String),

    /// TCP bind failed for a specific port.
    #[error("Could not bind port {port}: {source}")]
    ServerBind {
        /// The port that could not be bound.
        port: u16,
        /// The underlying I/O error.
        ///
        /// The explicit `#[source]` attribute (rather than relying on the
        /// implicit `source`-field naming convention) makes the contract
        /// visible to refactoring tools and prevents accidental silent removal
        /// if the field is ever renamed.
        #[source]
        source: std::io::Error,
    },

    /// The HTTP server task exited before signalling its bound port, or the
    /// bind-port handshake timed out.
    #[error("Server startup error: {0}")]
    ServerStartup(String),

    /// Console / terminal I/O error (crossterm or raw-mode operations).
    #[error("Console error: {0}")]
    Console(String),

    /// TLS configuration or certificate error (self-signed generation, PEM
    /// parsing, ACME provisioning, or `rustls` config construction).
    #[error("TLS error: {0}")]
    Tls(String),

    /// Transparent wrapper for any [`std::io::Error`] not covered by a more
    /// specific variant.
    ///
    /// # Warning — loss of context
    ///
    /// The `#[from]` blanket conversion means `?` on *any* `io::Result`
    /// anywhere in the codebase silently becomes `AppError::Io`, discarding
    /// information about which operation failed. Prefer constructing a
    /// specific variant (e.g. [`AppError::ServerBind`]) at each call site
    /// where the extra context is meaningful. This variant exists as a
    /// convenience fallback of last resort.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl AppError {
    /// Construct an [`AppError::ConfigValidation`] variant, enforcing the
    /// non-empty invariant.
    ///
    /// # Panics
    ///
    /// Panics in debug builds when `errors` is empty, since an empty vector
    /// produces a malformed display string. Release builds do not panic but
    /// will render the orphan-bullet form — callers are expected to uphold the
    /// invariant in all builds.
    #[must_use]
    pub fn config_validation(errors: Vec<String>) -> Self {
        debug_assert!(
            !errors.is_empty(),
            "`AppError::config_validation` requires at least one error message; \
             an empty Vec produces a malformed display string"
        );
        Self::ConfigValidation(errors)
    }
}
