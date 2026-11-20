//! HTTP/1.1 connection and request handling.

mod connection;
mod encoding;
mod file_response;
mod routes;
mod site_paths;

use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use crate::runtime::state::SharedState;

pub(crate) use connection::handle;
pub(crate) use file_response::{load_custom_error_page, CustomErrorPage};

/// Boolean feature flags for connection/request handling.
///
/// Grouped into a struct to avoid tripping `clippy::fn_params_excessive_bools`
/// and `clippy::struct_excessive_bools`.
#[expect(
    clippy::struct_excessive_bools,
    reason = "These request-handling toggles are a closed set carried together."
)]
#[derive(Clone, Copy, Debug)]
pub struct FeatureFlags {
    pub dir_listing: bool,
    pub expose_dotfiles: bool,
    pub spa_routing: bool,
    pub is_https: bool,
    pub keep_alive: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RequestIngress {
    Http,
    Https,
    Tor,
}

#[derive(Clone)]
pub(crate) struct HandlerConfig {
    pub(crate) peer_addr: std::net::SocketAddr,
    pub(crate) site_watch: tokio::sync::watch::Receiver<Arc<super::SiteSnapshot>>,
    pub(crate) index_file: Arc<str>,
    pub(crate) flags: FeatureFlags,
    pub(crate) state: SharedState,
    pub(crate) readiness: ReadinessConfig,
    pub(crate) csp: Arc<str>,
    pub(crate) redirects: Arc<Vec<crate::config::RedirectRule>>,
    pub(crate) trusted_proxies: Arc<Vec<std::net::IpAddr>>,
    pub(crate) ingress: RequestIngress,
}

#[derive(Clone)]
pub(crate) struct ReadinessConfig {
    pub(crate) data_dir: Arc<Path>,
    pub(crate) log_dir: Arc<Path>,
}

#[derive(Clone)]
pub(crate) struct FaviconConfig {
    pub(crate) path: PathBuf,
    pub(crate) site_root: Arc<Path>,
    pub(crate) enable_png: bool,
}
