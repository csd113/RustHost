//! Request classification, filesystem dispatch, and access logging.

use std::time::{SystemTime, UNIX_EPOCH};

use hyper::{body::Incoming, header, Method, Request, Response, StatusCode};
use std::{
    fs::OpenOptions,
    io::Write as _,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

use super::super::{fallback, SiteSnapshot};
use super::file_response::{
    external_redirect_response, html_response, inject_security_headers, method_not_allowed,
    method_not_allowed_with_allow, operational_text_response, options_response, redirect_response,
    sanitize_header_value, serve_favicon, serve_file, text_response, BoxBody, FileRequest,
};
use super::site_paths::{
    build_directory_listing, percent_decode, resolve_path, ResolveOptions, Resolved,
};
use super::{FaviconConfig, FeatureFlags, HandlerConfig, ReadinessConfig, RequestIngress};
use crate::runtime::state::{SharedMetrics, SharedState, VisitorIdentity};

static READINESS_PROBE_COUNTER: AtomicU64 = AtomicU64::new(0);

enum FaviconResolution {
    NotFavicon,
    File(PathBuf),
    NotFound,
    Forbidden,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FaviconKind {
    Ico,
    Png,
    Svg,
}

/// Immutable routing policy with one site snapshot selected for this request.
pub(super) struct RouteConfig {
    site: Arc<SiteSnapshot>,
    index_file: Arc<str>,
    csp: Arc<str>,
    flags: FeatureFlags,
    state: SharedState,
    readiness: ReadinessConfig,
    /// Operator redirect or rewrite rules checked before filesystem resolution.
    redirects: Arc<Vec<crate::config::RedirectRule>>,
    /// Real socket address of the accepted TCP connection.
    /// Used as the authoritative remote-IP in access logs unless the peer is in
    /// `trusted_proxies`, in which case X-Forwarded-For is substituted.
    peer_addr: std::net::SocketAddr,
    /// Set of IPs allowed to supply X-Forwarded-For headers.
    /// An empty Vec means XFF is ignored on every connection (default).
    trusted_proxies: Arc<Vec<std::net::IpAddr>>,
    /// Listener path that accepted this request.
    ingress: RequestIngress,
}

impl RouteConfig {
    pub(super) fn for_request(config: &HandlerConfig) -> Self {
        Self {
            site: Arc::clone(&config.site_watch.borrow()),
            index_file: Arc::clone(&config.index_file),
            csp: Arc::clone(&config.csp),
            flags: config.flags,
            state: Arc::clone(&config.state),
            readiness: config.readiness.clone(),
            redirects: Arc::clone(&config.redirects),
            peer_addr: config.peer_addr,
            trusted_proxies: Arc::clone(&config.trusted_proxies),
            ingress: config.ingress,
        }
    }
}

pub(super) async fn route(
    req: Request<Incoming>,
    cfg: &RouteConfig,
    metrics: &SharedMetrics,
) -> std::io::Result<Response<BoxBody>> {
    let response = route_request(&req, cfg, metrics).await?;
    log_request(
        &req,
        response.status().as_u16(),
        response_size(&response),
        cfg.peer_addr,
        &cfg.trusted_proxies,
    );
    Ok(inject_security_headers(response, &req, cfg.flags.is_https, &cfg.csp, &cfg.state).await)
}

async fn route_request(
    req: &Request<Incoming>,
    cfg: &RouteConfig,
    metrics: &SharedMetrics,
) -> std::io::Result<Response<BoxBody>> {
    if !has_valid_host_header(req) {
        metrics.add_error();
        return Ok(text_response(
            StatusCode::BAD_REQUEST,
            "Bad Request",
            &cfg.csp,
            "",
        ));
    }
    if let Some(endpoint) = OperationalEndpoint::from_path(req.uri().path()) {
        return route_operational_endpoint(req, cfg, metrics, endpoint).await;
    }

    // Operational probes are infrastructure traffic and do not count as visitors.
    record_unique_visitor(
        req,
        cfg.peer_addr,
        &cfg.trusted_proxies,
        cfg.ingress,
        metrics,
    );
    match *req.method() {
        Method::OPTIONS => {
            metrics.add_request();
            return Ok(options_response());
        }
        Method::GET | Method::HEAD => {}
        _ => {
            metrics.add_error();
            return Ok(method_not_allowed());
        }
    }

    let decoded = percent_decode(req.uri().path());
    if let Some(rule) = cfg.redirects.iter().find(|rule| decoded == rule.from) {
        let safe = sanitize_header_value(&rule.to);
        metrics.add_request();
        return external_redirect_response(&safe, rule.status, &cfg.csp);
    }
    if let Some(response) = route_favicon(req, cfg, metrics, &decoded).await? {
        return Ok(response);
    }
    route_static(req, cfg, metrics, decoded).await
}

async fn route_favicon(
    req: &Request<Incoming>,
    cfg: &RouteConfig,
    metrics: &SharedMetrics,
    decoded: &str,
) -> std::io::Result<Option<Response<BoxBody>>> {
    if requested_favicon_kind(decoded).is_none() {
        return Ok(None);
    }
    // Filesystem resolution only needs the blocking pool for favicon requests.
    let favicon = Arc::clone(&cfg.site.favicon);
    let path = decoded.to_owned();
    let resolution = tokio::task::spawn_blocking(move || resolve_favicon_request(&path, &favicon))
        .await
        .map_err(|error| {
            std::io::Error::other(format!("favicon resolution task panicked: {error}"))
        })?;
    let response = match resolution {
        FaviconResolution::File(path) => {
            metrics.add_request();
            serve_favicon(&path, req, req.method() == Method::HEAD, &cfg.csp, decoded).await?
        }
        FaviconResolution::NotFound => {
            metrics.add_request();
            text_response(StatusCode::NOT_FOUND, "Not Found", &cfg.csp, decoded)
        }
        FaviconResolution::Forbidden => {
            metrics.add_error();
            text_response(StatusCode::FORBIDDEN, "Forbidden", &cfg.csp, decoded)
        }
        FaviconResolution::NotFavicon => return Ok(None),
    };
    Ok(Some(response))
}

async fn route_static(
    req: &Request<Incoming>,
    cfg: &RouteConfig,
    metrics: &SharedMetrics,
    decoded: String,
) -> std::io::Result<Response<BoxBody>> {
    let canonical_root = Arc::clone(&cfg.site.canonical_root);
    let index_file = Arc::clone(&cfg.index_file);
    let decoded_for_resolve = decoded.clone();
    let error_404_page = cfg.site.error_404_page.clone();
    let dir_listing = cfg.flags.dir_listing;
    let expose_dotfiles = cfg.flags.expose_dotfiles;
    let spa_routing = cfg.flags.spa_routing;

    let resolved = tokio::task::spawn_blocking(move || {
        let opts = ResolveOptions {
            canonical_root: canonical_root.as_ref(),
            url_path: &decoded_for_resolve,
            index_file: index_file.as_ref(),
            dir_listing,
            expose_dotfiles,
            spa_routing,
            error_404_page,
        };
        resolve_path(&opts)
    })
    .await
    .map_err(|e| std::io::Error::other(format!("path resolution task panicked: {e}")))?;

    dispatch_resolved(resolved, req, cfg, metrics, &decoded).await
}

#[derive(Clone, Copy)]
enum OperationalEndpoint {
    Health,
    Ready,
}

impl OperationalEndpoint {
    const fn from_path(path: &str) -> Option<Self> {
        match path.as_bytes() {
            b"/health" => Some(Self::Health),
            b"/ready" => Some(Self::Ready),
            _ => None,
        }
    }
}

async fn route_operational_endpoint(
    req: &Request<Incoming>,
    cfg: &RouteConfig,
    metrics: &SharedMetrics,
    endpoint: OperationalEndpoint,
) -> std::result::Result<Response<BoxBody>, std::io::Error> {
    if req.method() != Method::GET && req.method() != Method::HEAD {
        metrics.add_error();
        return Ok(method_not_allowed_with_allow("GET, HEAD"));
    }

    let is_head = req.method() == Method::HEAD;
    match endpoint {
        OperationalEndpoint::Health => {
            metrics.add_request();
            Ok(operational_text_response(
                StatusCode::OK,
                "OK\n",
                is_head,
                &cfg.csp,
            ))
        }
        OperationalEndpoint::Ready => {
            let readiness = cfg.readiness.clone();
            let canonical_root = Arc::clone(&cfg.site.canonical_root);
            let runtime_ready = cfg.state.read().await.runtime_ready;
            let status = tokio::task::spawn_blocking(move || {
                readiness_status(runtime_ready, canonical_root.as_ref(), &readiness)
            })
            .await
            .map_err(|e| std::io::Error::other(format!("readiness check task panicked: {e}")))?;

            match status {
                Ok(()) => {
                    metrics.add_request();
                    Ok(operational_text_response(
                        StatusCode::OK,
                        "READY\n",
                        is_head,
                        &cfg.csp,
                    ))
                }
                Err(reason) => {
                    metrics.add_error();
                    let body = format!("NOT READY: {}\n", reason.as_str());
                    Ok(operational_text_response(
                        StatusCode::SERVICE_UNAVAILABLE,
                        &body,
                        is_head,
                        &cfg.csp,
                    ))
                }
            }
        }
    }
}

#[derive(Clone, Copy)]
enum ReadinessFailure {
    StartupIncomplete,
    DataDirUnavailable,
    SiteRootUnavailable,
    LogDirUnavailable,
}

impl ReadinessFailure {
    const fn as_str(self) -> &'static str {
        match self {
            Self::StartupIncomplete => "startup incomplete",
            Self::DataDirUnavailable => "data directory unavailable",
            Self::SiteRootUnavailable => "site root unavailable",
            Self::LogDirUnavailable => "log directory unavailable",
        }
    }
}

fn readiness_status(
    runtime_ready: bool,
    canonical_root: &Path,
    readiness: &ReadinessConfig,
) -> std::result::Result<(), ReadinessFailure> {
    if !runtime_ready {
        return Err(ReadinessFailure::StartupIncomplete);
    }
    if !is_accessible_dir(readiness.data_dir.as_ref()) {
        return Err(ReadinessFailure::DataDirUnavailable);
    }
    if !is_accessible_dir(canonical_root) {
        return Err(ReadinessFailure::SiteRootUnavailable);
    }
    if !log_dir_is_writable(readiness.log_dir.as_ref()) {
        return Err(ReadinessFailure::LogDirUnavailable);
    }
    Ok(())
}

fn is_accessible_dir(path: &Path) -> bool {
    std::fs::metadata(path).is_ok_and(|metadata| metadata.is_dir())
        && std::fs::read_dir(path).is_ok()
}

fn log_dir_is_writable(path: &Path) -> bool {
    if !is_accessible_dir(path) {
        return false;
    }

    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    let counter = READINESS_PROBE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let probe = path.join(format!(
        ".rusthost-ready-check-{}-{suffix}-{counter}",
        std::process::id()
    ));
    let result = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&probe)
        .and_then(|mut file| file.write_all(b"ready\n"));

    let cleanup = std::fs::remove_file(&probe);
    let cleanup_ok = cleanup.is_ok()
        || matches!(&cleanup, Err(error) if error.kind() == std::io::ErrorKind::NotFound);
    result.is_ok() && cleanup_ok
}

fn record_unique_visitor<B>(
    req: &Request<B>,
    peer_addr: std::net::SocketAddr,
    trusted_proxies: &[std::net::IpAddr],
    ingress: RequestIngress,
    metrics: &SharedMetrics,
) {
    metrics.add_unique_visitor(visitor_identity(req, peer_addr, trusted_proxies, ingress));
}

fn visitor_identity<B>(
    req: &Request<B>,
    peer_addr: std::net::SocketAddr,
    trusted_proxies: &[std::net::IpAddr],
    ingress: RequestIngress,
) -> VisitorIdentity {
    match ingress {
        RequestIngress::Http | RequestIngress::Https => {
            VisitorIdentity::Clearnet(resolved_remote_addr(req, peer_addr, trusted_proxies))
        }
        // The in-process Tor proxy intentionally avoids adding cookies,
        // fingerprints, or circuit-level identifiers. Once Arti proxies a
        // stream into the local ingress listener, the stable identity available
        // to HTTP is just the local proxy socket, so Tor is counted as one
        // anonymous runtime bucket.
        RequestIngress::Tor => VisitorIdentity::TorAnonymous,
    }
}

/// Map a [`Resolved`] value to an HTTP response.
///
/// Extracted from [`route`] to keep that function within the 100-line limit.
async fn dispatch_resolved(
    resolved: Resolved,
    req: &Request<Incoming>,
    cfg: &RouteConfig,
    metrics: &SharedMetrics,
    decoded: &str,
) -> std::io::Result<Response<BoxBody>> {
    let is_head = req.method() == Method::HEAD;
    Ok(match resolved {
        Resolved::File(abs_path) => {
            serve_file(
                &abs_path,
                &FileRequest {
                    req,
                    is_head,
                    metrics,
                    canonical_root: &cfg.site.canonical_root,
                    csp: &cfg.csp,
                    error_503_page: cfg.site.error_503_page.as_deref(),
                },
            )
            .await?
        }
        Resolved::NotFound => {
            let decoded_for_log = sanitize_header_value(decoded);
            log::debug!("404 Not Found: {decoded_for_log}");
            metrics.add_request();
            text_response(StatusCode::NOT_FOUND, "Not Found", &cfg.csp, "")
        }
        Resolved::Redirect(mut location) => {
            if let Some(query) = req.uri().query() {
                location.push('?');
                location.push_str(query);
            }
            let safe = sanitize_header_value(&location);
            metrics.add_request();
            redirect_response(&safe, &cfg.csp)
        }
        Resolved::Fallback => {
            metrics.add_request();
            cfg.site.error_503_page.as_deref().map_or_else(
                || {
                    html_response(
                        StatusCode::SERVICE_UNAVAILABLE,
                        fallback::NO_SITE_HTML,
                        is_head,
                        &cfg.csp,
                        "",
                    )
                },
                |page| page.response(is_head, &cfg.csp, ""),
            )
        }
        Resolved::Forbidden => {
            let decoded_for_log = sanitize_header_value(decoded);
            log::warn!("403 Forbidden: {decoded_for_log}");
            metrics.add_error();
            text_response(StatusCode::FORBIDDEN, "Forbidden", &cfg.csp, "")
        }
        Resolved::DirectoryListing(dir_path) => {
            let decoded_owned = decoded.to_owned();
            let expose_dotfiles = cfg.flags.expose_dotfiles;
            let html = tokio::task::spawn_blocking(move || {
                build_directory_listing(&dir_path, &decoded_owned, expose_dotfiles)
            })
            .await
            .map_err(|e| std::io::Error::other(format!("directory listing task panicked: {e}")))?;
            metrics.add_request();
            html_response(StatusCode::OK, &html, is_head, &cfg.csp, decoded)
        }
        Resolved::CustomError(page) => {
            metrics.add_request();
            page.response(is_head, &cfg.csp, "")
        }
    })
}

/// Emit one access-log line.
///
/// The `peer_addr` parameter is the real socket address of the
/// accepted TCP connection. It is used as the authoritative remote-IP **unless**
/// `peer_addr.ip()` is in `trusted_proxies`, in which case the first entry of
/// `X-Forwarded-For` is consulted instead.
///
/// This prevents any client from forging `X-Forwarded-For: 127.0.0.1` to
/// appear as localhost in access logs on a direct-edge server where no
/// trusted proxy exists (i.e. the default empty list).
fn log_request<B>(
    req: &Request<B>,
    status: u16,
    bytes_sent: Option<u64>,
    peer_addr: std::net::SocketAddr,
    trusted_proxies: &[std::net::IpAddr],
) {
    use crate::logging::{log_access, AccessRecord};

    let remote = resolved_remote_addr(req, peer_addr, trusted_proxies);

    let ua = req
        .headers()
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok());
    let referer = req
        .headers()
        .get(header::REFERER)
        .and_then(|v| v.to_str().ok());

    log_access(&AccessRecord {
        remote_addr: remote,
        method: req.method().as_str(),
        path: req.uri().path(),
        protocol: "HTTP/1.1",
        status,
        bytes_sent,
        user_agent: ua,
        referer,
    });
}

fn resolved_remote_addr<B>(
    req: &Request<B>,
    peer_addr: std::net::SocketAddr,
    trusted_proxies: &[std::net::IpAddr],
) -> std::net::IpAddr {
    let remote = peer_addr.ip();
    if trusted_proxies.contains(&remote) {
        req.headers()
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.split(',').next())
            .and_then(|s| s.trim().parse::<std::net::IpAddr>().ok())
            .unwrap_or(remote)
    } else {
        remote
    }
}

/// Build a redirect response for operator-configured rules.
///
/// Uses the `status` from the rule (301 or 302) rather than always 301.
fn resolve_favicon_request(path: &str, cfg: &FaviconConfig) -> FaviconResolution {
    let Some(requested_kind) = requested_favicon_kind(path) else {
        return FaviconResolution::NotFavicon;
    };

    if requested_kind == FaviconKind::Png && !cfg.enable_png {
        return FaviconResolution::NotFound;
    }

    resolve_favicon_candidate(&cfg.path, requested_kind, cfg)
}

fn requested_favicon_kind(path: &str) -> Option<FaviconKind> {
    match path {
        "/favicon.ico" => Some(FaviconKind::Ico),
        "/favicon.png" => Some(FaviconKind::Png),
        "/favicon.svg" => Some(FaviconKind::Svg),
        _ => None,
    }
}

fn resolve_favicon_candidate(
    candidate: &Path,
    requested_kind: FaviconKind,
    cfg: &FaviconConfig,
) -> FaviconResolution {
    let resolved = match candidate.canonicalize() {
        Ok(path) => path,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return FaviconResolution::NotFound
        }
        Err(_) => return FaviconResolution::Forbidden,
    };

    let extension_kind =
        resolved
            .extension()
            .and_then(|ext| ext.to_str())
            .and_then(|ext| match ext.to_ascii_lowercase().as_str() {
                "ico" => Some(FaviconKind::Ico),
                "png" => Some(FaviconKind::Png),
                "svg" => Some(FaviconKind::Svg),
                _ => None,
            });
    let Some(extension_kind) = extension_kind else {
        return FaviconResolution::Forbidden;
    };

    if requested_kind != extension_kind {
        return FaviconResolution::NotFound;
    }
    if extension_kind == FaviconKind::Png && !cfg.enable_png {
        return FaviconResolution::NotFound;
    }
    if !resolved.starts_with(cfg.site_root.as_ref()) {
        return FaviconResolution::Forbidden;
    }

    match std::fs::metadata(&resolved) {
        Ok(metadata) if metadata.is_file() => FaviconResolution::File(resolved),
        Ok(_) | Err(_) => FaviconResolution::Forbidden,
    }
}

fn has_valid_host_header<B>(req: &Request<B>) -> bool {
    let mut values = req.headers().get_all(header::HOST).iter();
    let Some(value) = values.next() else {
        return false;
    };
    if values.next().is_some() {
        return false;
    }
    value.to_str().is_ok_and(is_valid_host_value)
}

fn is_valid_host_value(host: &str) -> bool {
    let host = host.trim();
    if host.is_empty()
        || !host.is_ascii()
        || host.contains('/')
        || host.contains('\\')
        || host.contains('@')
        || host.contains("://")
    {
        return false;
    }

    if let Some(remainder) = host.strip_prefix('[') {
        let Some((addr, port)) = remainder.split_once(']') else {
            return false;
        };
        return !addr.is_empty()
            && addr.contains(':')
            && (port.is_empty() || port.strip_prefix(':').is_some_and(valid_host_port));
    }

    match host.rsplit_once(':') {
        Some((name, port)) => !name.is_empty() && !name.contains(':') && valid_host_port(port),
        None => !host.contains(':'),
    }
}

fn valid_host_port(raw: &str) -> bool {
    raw.parse::<u16>().is_ok_and(|port| port != 0)
}

fn response_size(resp: &Response<BoxBody>) -> Option<u64> {
    resp.headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
}
