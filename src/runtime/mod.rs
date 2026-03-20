//! # Runtime Module
//!
//! **Directory:** `src/runtime/`
//!
//! Owns the application lifecycle, shared state, and top-level event
//! dispatch.  Sub-modules:
//!
//! - [`state`]     — [`AppState`] struct and [`TorStatus`] / [`ConsoleMode`] enums
//! - [`lifecycle`] — first-run setup and normal startup sequence
//! - [`events`]    — key-event dispatch (H / R / T / O / L / Q)

pub mod events;
pub mod lifecycle;
pub mod state;
