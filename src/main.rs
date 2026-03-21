//! # rusthost
//!
//! **Directory:** `src/`
//!
//! Entry point. Declares all modules and launches the Tokio async runtime.
//! All startup logic lives in [`runtime::lifecycle::run`]; this file
//! only boots the executor and propagates fatal errors to the OS.

mod config;
mod console;
mod logging;
mod runtime;
mod server;
mod tor;

/// Common `Result` alias used throughout the codebase.
pub type Result<T, E = Box<dyn std::error::Error + Send + Sync>> = std::result::Result<T, E>;

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
