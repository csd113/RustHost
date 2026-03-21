//! # rusthost
//!
//! **Directory:** `src/`
//!
//! Entry point. Declares all modules and launches the Tokio async runtime.
//! All startup logic lives in [`runtime::lifecycle::run`]; this file
//! only boots the executor and propagates fatal errors to the OS.

mod config;
mod console;
mod error;
mod logging;
mod runtime;
mod server;
mod tor;

pub use error::AppError;

/// Common `Result` alias used throughout the codebase.
///
/// The error type is [`AppError`] — a typed enum covering every failure mode.
/// All subsystems return this type so callers can match on specific variants
/// rather than inspecting an opaque `Box<dyn Error>` string.
pub type Result<T, E = AppError> = std::result::Result<T, E>;

#[tokio::main]
async fn main() {
    // Register a panic hook so the terminal is always restored, even when a
    // panic fires on an async executor thread.
    std::panic::set_hook(Box::new(|info| {
        console::cleanup();
        eprintln!("\nPanic: {info}");
    }));

    if let Err(err) = runtime::lifecycle::run().await {
        // Best-effort terminal restore in case we crashed inside the console.
        console::cleanup();
        eprintln!("\nFatal error: {err}");
        std::process::exit(1);
    }
}
