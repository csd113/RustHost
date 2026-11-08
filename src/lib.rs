//! # rusthost — library crate
//! Exposes the public API surface used by the binary entry point in
//! `src/main.rs` and downstream callers.

#![deny(warnings)]
#![deny(clippy::all, clippy::pedantic)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::todo,
    clippy::unimplemented
)]

// Public modules used by the CLI and library callers.
pub mod config;
pub mod console;
pub mod error;
pub(crate) mod io_timeout;
pub mod logging;
pub(crate) mod path_display;
pub(crate) mod persistence;
#[cfg(windows)]
pub(crate) mod process;
pub mod runtime;
pub mod server;
pub mod terminal;
pub mod tls;
pub mod tor;
pub mod version;
pub(crate) mod windows_identity;

pub use error::AppError;

/// Common `Result` alias used throughout the codebase.
///
/// The error type is [`AppError`] — a typed enum covering every failure mode.
/// All subsystems return this type so callers can match on specific variants
/// rather than inspecting an opaque `Box<dyn Error>` string.
pub type Result<T, E = AppError> = std::result::Result<T, E>;
