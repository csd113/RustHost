//! # rusthost — library crate
//!
//! **File:** `lib.rs`
//! **Location:** `src/lib.rs`
//!
//! Exposes the public API surface used by the binary entry point in
//! `src/main.rs`, integration tests in `tests/`, and downstream callers.

#![deny(warnings)]
#![deny(clippy::all, clippy::pedantic)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::todo,
    clippy::unimplemented
)]

// Public modules used by the CLI, integration tests, and library callers.
pub mod config;
pub mod console;
pub mod error;
pub mod logging;
pub mod runtime;
pub mod server;
pub mod terminal;
pub mod tls;
pub mod tor;

pub use error::AppError;

/// Common `Result` alias used throughout the codebase.
///
/// The error type is [`AppError`] — a typed enum covering every failure mode.
/// All subsystems return this type so callers can match on specific variants
/// rather than inspecting an opaque `Box<dyn Error>` string.
pub type Result<T, E = AppError> = std::result::Result<T, E>;
