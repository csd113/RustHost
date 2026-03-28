//! # rusthost — library crate
//!
//! Exposes the public API surface used by integration tests in `tests/` and
//! by the binary entry point in `src/main.rs`.
//!
//! Internal modules are `pub(crate)` by default; only items that form part of
//! the documented operator/integration-test API are re-exported here.

// Public modules — part of the documented external API.
pub mod config;
pub mod error;
pub mod runtime;
pub mod server;

// Internal modules — exposed `pub` only so integration tests in `tests/`
// can import them.  Use `pub(crate)` within the codebase; prefer these
// re-exports for test access.
pub mod console;
pub mod logging;
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

// ─── Integration-test-only re-exports ────────────────────────────────────────
//
// These items are not part of the stable public API.  They are gated behind
// `#[cfg(test)]` so that they do not appear in `rustdoc` output or in the
// symbol table of release binaries.  Integration tests import them via the
// crate root without needing to reach into internal module paths.

#[cfg(test)]
pub use server::handler::{percent_decode, ByteRange, Encoding};
#[cfg(test)]
pub use tor::onion_address_from_pubkey;
