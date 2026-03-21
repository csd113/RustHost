//! # rusthost — library crate
//!
//! Exposes all subsystem modules so that integration tests in `tests/` can
//! import them directly.  The binary entry point (`src/main.rs`) is a thin
//! wrapper that calls [`runtime::lifecycle::run`].

pub mod config;
pub mod console;
pub mod error;
pub mod logging;
pub mod runtime;
pub mod server;
pub mod tor;

pub use error::AppError;

/// Common `Result` alias used throughout the codebase.
///
/// The error type is [`AppError`] — a typed enum covering every failure mode.
/// All subsystems return this type so callers can match on specific variants
/// rather than inspecting an opaque `Box<dyn Error>` string.
pub type Result<T, E = AppError> = std::result::Result<T, E>;
