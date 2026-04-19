//! # rusthost — library crate
//!
//! **File:** `lib.rs`
//! **Location:** `src/lib.rs`
//!
//! Exposes the public API surface used by the binary entry point in
//! `src/main.rs`, integration tests in `tests/`, and downstream callers.

#![deny(warnings)]
#![deny(clippy::all, clippy::pedantic)]
// This project depends on Arti/Tor plus TLS/proc-macro/platform ecosystems
// that intentionally carry parallel semver lines; forcing unification here is
// outside this crate's control and would make dependency upgrades brittle.
#![allow(clippy::multiple_crate_versions)]
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
