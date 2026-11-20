//! # Tor Module — Arti (in-process)
//! Replaces the old subprocess + torrc approach with Arti, the official
//! Tor implementation in Rust, running entirely in-process.
//!
//! ## Flow
//!
//! 1. `init()` spawns a Tokio task and returns its `JoinHandle`.
//! 2. `TorClient::create_bootstrapped()` connects to the Tor network.
//! 3. `launch_onion_service()` registers the hidden service.
//! 4. Incoming `RendRequest`s are converted into `StreamRequest`s.
//! 5. Each `StreamRequest` is proxied to the local HTTP server.
//! 6. If the request stream ends unexpectedly, the module re-bootstraps
//!    with exponential backoff.
//!
//! ## Security note on state/cache directory creation
//!
//! `ensure_private_dir()` hardens permissions and rejects obvious symlinks,
//! but directory creation and post-creation verification are not fully atomic
//! with only the Rust standard library. On hostile multi-user systems, a local
//! attacker who can race filesystem operations may still be able to swap paths
//! between checks. For Tor state material this is a real concern.
//!
//! For strongest protection, use platform-native secure directory creation APIs
//! (`openat`-style directory traversal on Linux, `SetNamedSecurityInfoW` via
//! `windows-sys` on Windows) or run the service as a dedicated user account
//! with a private home directory.

mod relay;
mod session;
mod state_dirs;

pub use session::{init, onion_address_from_pubkey};

pub(crate) use session::{publish, serve};
