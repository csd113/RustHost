//! # Server Module
//! Provides a safe HTTP/1.1 static-file server. The implementation migrated
//! per-connection handler from a hand-rolled single-shot parser to
//! [`hyper`]'s keep-alive connection loop, eliminating the large Tor
//! page-load penalty caused by `Connection: close` on every response.
//!
//! Sub-modules:
//! - [`handler`] — per-connection request handling and file serving
//! - [`mime`] — file-extension → MIME type mapping
//! - [`fallback`] — built-in "No site found" page
mod admission;
mod listeners;
mod site_snapshot;

pub mod fallback;
pub mod handler;
pub mod mime;
pub mod redirect;

pub use listeners::{run, run_https, run_tor_ingress, tor_loopback_addr};
pub use site_snapshot::{scan_site, SiteSnapshot};
