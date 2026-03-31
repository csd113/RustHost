//! # Request Handler
//!
//! **File:** `handler.rs`
//! **Location:** `src/server/handler.rs`
//!
//! Handles HTTP connections using [`hyper`]'s HTTP/1.1 connection loop,
//! which provides keep-alive transparently.
//!
//! Each connection is kept alive across multiple request/response cycles —
//! eliminating the 30–45 s Tor page-load penalty that the previous
//! single-shot, `Connection: close` design imposed.
//!
//! Additional features layered on top of hyper:
//! - **`ETag` / conditional `GET`** (`H-9`): weak `ETag` headers; `304` on match.
//! - **Range requests** (H-13): `bytes=N-M` single-range support; 206/416.
//! - **Brotli / Gzip compression** (H-8): negotiated via `Accept-Encoding`.
//!
//! Security: every resolved path is checked to be a descendant of the
//! configured site root via [`std::fs::canonicalize`]. Any attempt to
//! escape (e.g. `/../secret`) is rejected with HTTP 403.

#![allow(clippy::too_many_arguments)] // HTTP write_* fns mirror the wire format

mod encoding;
mod pathing;

use std::{path::Path, sync::Arc};

use bytes::Bytes;
use futures::TryStreamExt as _;
use http_body_util::{BodyExt as _, Full, StreamBody};
use httpdate::{fmt_http_date, parse_http_date};
use hyper::{body::Incoming, header, Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite};
use tokio_util::io::ReaderStream;

use super::{fallback, mime};
use crate::{
    runtime::state::{SharedMetrics, SharedState},
    Result,
};
pub use encoding::Encoding;
use encoding::{best_encoding, should_compress};
pub use pathing::percent_decode;
use pathing::{
    build_directory_listing, cache_control_for, resolve_path, sanitize_header_value,
    ResolveOptions, Resolved,
};

// ─── Body type alias ─────────────────────────────────────────────────────────

type BoxBody = http_body_util::combinators::BoxBody<Bytes, std::io::Error>;

const MAX_REQUEST_BUFFER_BYTES: usize = 16 * 1024;
const MAX_CUSTOM_ERROR_PAGE_BYTES: u64 = 64 * 1024;
const IDENTITY_STREAM_CHUNK_BYTES: usize = 128 * 1024;
fn full_body(data: impl Into<Bytes>) -> BoxBody {
    Full::new(data.into()).map_err(|e| match e {}).boxed()
}

fn empty_body() -> BoxBody {
    full_body(Bytes::new())
}

fn reader_body<R>(reader: R) -> BoxBody
where
    R: tokio::io::AsyncRead + Send + Sync + 'static,
{
    StreamBody::new(ReaderStream::new(reader).map_ok(hyper::body::Frame::data)).boxed()
}

fn identity_reader_body<R>(reader: R) -> BoxBody
where
    R: tokio::io::AsyncRead + Send + Sync + 'static,
{
    StreamBody::new(
        ReaderStream::with_capacity(reader, IDENTITY_STREAM_CHUNK_BYTES)
            .map_ok(hyper::body::Frame::data),
    )
    .boxed()
}

// ─── Feature flags ───────────────────────────────────────────────────────────

/// Boolean feature flags for connection/request handling.
///
/// Grouped into a struct to avoid tripping `clippy::fn_params_excessive_bools`
/// and `clippy::struct_excessive_bools`.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Copy, Debug)]
pub struct FeatureFlags {
    pub dir_listing: bool,
    pub expose_dotfiles: bool,
    pub spa_routing: bool,
    pub is_https: bool,
    pub keep_alive: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CustomErrorPage {
    status: StatusCode,
    body: Bytes,
}

impl CustomErrorPage {
    fn response(&self, is_head: bool, csp: &str, url_path: &str) -> Response<BoxBody> {
        let mut builder = Response::builder()
            .status(self.status)
            .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
            .header(header::CONTENT_LENGTH, self.body.len())
            .header(
                "Cache-Control",
                cache_control_for("text/html; charset=utf-8", url_path),
            );
        builder = security_headers(builder, csp, "text/html; charset=utf-8");
        let body = if is_head {
            empty_body()
        } else {
            full_body(self.body.clone())
        };
        builder.body(body).unwrap_or_default()
    }
}

pub(crate) fn load_custom_error_page(
    canonical_root: &Path,
    candidate: &Path,
    label: &str,
    status: StatusCode,
) -> Option<Arc<CustomErrorPage>> {
    let resolved = match candidate.canonicalize() {
        Ok(resolved) if resolved.starts_with(canonical_root) => resolved,
        Ok(resolved) => {
            log::warn!(
                "Ignoring [site] {label} path {} because it resolves outside the site root: {}",
                candidate.display(),
                resolved.display()
            );
            return None;
        }
        Err(e) => {
            log::warn!(
                "Ignoring [site] {label} path {} because it could not be resolved: {e}",
                candidate.display()
            );
            return None;
        }
    };

    let metadata = match std::fs::metadata(&resolved) {
        Ok(metadata) => metadata,
        Err(e) => {
            log::warn!(
                "Ignoring [site] {label} path {} because metadata could not be read: {e}",
                resolved.display()
            );
            return None;
        }
    };

    if metadata.len() > MAX_CUSTOM_ERROR_PAGE_BYTES {
        log::warn!(
            "Ignoring [site] {label} path {} because it exceeds the {} byte limit",
            resolved.display(),
            MAX_CUSTOM_ERROR_PAGE_BYTES
        );
        return None;
    }

    match std::fs::read(&resolved) {
        Ok(body) => Some(Arc::new(CustomErrorPage {
            status,
            body: Bytes::from(body),
        })),
        Err(e) => {
            log::warn!(
                "Ignoring [site] {label} path {} because it could not be read: {e}",
                resolved.display()
            );
            None
        }
    }
}

// ─── Entry point ─────────────────────────────────────────────────────────────

/// Serve one HTTP connection to completion.
///
/// Uses [`hyper`]'s HTTP/1.1 connection loop with keep-alive enabled (C-1).
/// Previously the server sent `Connection: close` on every response and
/// terminated the TCP connection immediately — this caused Tor pages to take
/// 30–45 s to load because each asset required a fresh Tor circuit setup.
///
/// # Errors
///
/// Propagates I/O errors from hyper's connection driver.
pub(crate) async fn handle<S>(
    stream: S,
    // Real socket address of the connecting client. This is used as
    // the remote-IP in access logs unless the peer is in trusted_proxies, in
    // which case X-Forwarded-For is consulted instead.
    peer_addr: std::net::SocketAddr,
    canonical_root: Arc<Path>,
    index_file: Arc<str>,
    flags: FeatureFlags,
    metrics: SharedMetrics,
    state: SharedState,
    csp: Arc<str>,
    error_404_page: Option<Arc<CustomErrorPage>>,
    error_503_page: Option<Arc<CustomErrorPage>>,
    redirects: Arc<Vec<crate::config::RedirectRule>>,
    // IPs or networks from which X-Forwarded-For may be trusted.
    // An empty slice means XFF is ignored entirely (default / safest).
    trusted_proxies: Arc<Vec<std::net::IpAddr>>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let cfg = Arc::new(RouteConfig {
        canonical_root,
        index_file,
        csp,
        flags,
        state,
        error_404_page,
        error_503_page,
        redirects,
        peer_addr,
        trusted_proxies,
    });

    let io = TokioIo::new(stream);

    hyper::server::conn::http1::Builder::new()
        .keep_alive(flags.keep_alive)
        .max_buf_size(MAX_REQUEST_BUFFER_BYTES)
        .serve_connection(
            io,
            hyper::service::service_fn(move |req| {
                let cfg = Arc::clone(&cfg);
                let met = Arc::clone(&metrics);
                async move { route(req, &cfg, &met).await }
            }),
        )
        .await
        .map_err(|e| crate::AppError::Io(std::io::Error::other(e.to_string())))
}

// ─── Router ──────────────────────────────────────────────────────────────────

/// Configuration that every request handler needs but that doesn't change
/// between requests on the same connection.
///
/// Passed into [`route`] by value so each `service_fn` closure captures one
/// `Arc<RouteConfig>` rather than many individual `Arc<str>` / `bool` fields.
#[derive(Clone)]
struct RouteConfig {
    canonical_root: Arc<Path>,
    index_file: Arc<str>,
    csp: Arc<str>,
    flags: FeatureFlags,
    state: SharedState,
    error_404_page: Option<Arc<CustomErrorPage>>,
    error_503_page: Option<Arc<CustomErrorPage>>,
    /// Operator redirect or rewrite rules checked before filesystem resolution.
    redirects: Arc<Vec<crate::config::RedirectRule>>,
    /// Real socket address of the accepted TCP connection.
    /// Used as the authoritative remote-IP in access logs unless the peer is in
    /// `trusted_proxies`, in which case X-Forwarded-For is substituted.
    peer_addr: std::net::SocketAddr,
    /// Set of IPs allowed to supply X-Forwarded-For headers.
    /// An empty Vec means XFF is ignored on every connection (default).
    trusted_proxies: Arc<Vec<std::net::IpAddr>>,
}

#[allow(clippy::too_many_lines)]
async fn route(
    req: Request<Incoming>,
    cfg: &RouteConfig,
    metrics: &SharedMetrics,
) -> std::result::Result<Response<BoxBody>, std::io::Error> {
    match req.method() {
        &Method::OPTIONS => {
            metrics.add_request();
            let resp = options_response();
            log_request(
                &req,
                resp.status().as_u16(),
                response_size(&resp),
                cfg.peer_addr,
                &cfg.trusted_proxies,
            );
            return Ok(inject_security_headers(
                resp,
                &req,
                cfg.flags.is_https,
                &cfg.csp,
                &cfg.state,
            )
            .await);
        }
        m if m != Method::GET && m != Method::HEAD => {
            metrics.add_error();
            let resp = method_not_allowed();
            log_request(
                &req,
                resp.status().as_u16(),
                response_size(&resp),
                cfg.peer_addr,
                &cfg.trusted_proxies,
            );
            return Ok(inject_security_headers(
                resp,
                &req,
                cfg.flags.is_https,
                &cfg.csp,
                &cfg.state,
            )
            .await);
        }
        _ => {}
    }

    let is_head = req.method() == Method::HEAD;
    let decoded = percent_decode(req.uri().path());

    // Check operator redirect rules before any filesystem access.
    for rule in cfg.redirects.iter() {
        if decoded == rule.from {
            let safe = sanitize_header_value(&rule.to);
            let status = rule.status;
            metrics.add_request();
            let resp = external_redirect_response(&safe, status, &cfg.csp)?;
            log_request(
                &req,
                resp.status().as_u16(),
                response_size(&resp),
                cfg.peer_addr,
                &cfg.trusted_proxies,
            );
            return Ok(inject_security_headers(
                resp,
                &req,
                cfg.flags.is_https,
                &cfg.csp,
                &cfg.state,
            )
            .await);
        }
    }

    let canonical_root = Arc::clone(&cfg.canonical_root);
    let index_file = Arc::clone(&cfg.index_file);
    let decoded_for_resolve = decoded.clone();
    let error_404_page = cfg.error_404_page.clone();
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

    let resp = dispatch_resolved(
        resolved,
        &req,
        is_head,
        metrics,
        &cfg.csp,
        &decoded,
        cfg.flags.expose_dotfiles,
        cfg.error_503_page.as_deref(),
    )
    .await?;

    // Write one Combined Log Format line per request.
    log_request(
        &req,
        resp.status().as_u16(),
        response_size(&resp),
        cfg.peer_addr,
        &cfg.trusted_proxies,
    );

    // Inject HSTS and other security headers that depend on transport.
    let resp = inject_security_headers(resp, &req, cfg.flags.is_https, &cfg.csp, &cfg.state).await;
    Ok(resp)
}

/// Map a [`Resolved`] value to an HTTP response.
///
/// Extracted from [`route`] to keep that function within the 100-line limit.
async fn dispatch_resolved(
    resolved: Resolved,
    req: &Request<Incoming>,
    is_head: bool,
    metrics: &SharedMetrics,
    csp: &str,
    decoded: &str,
    expose_dotfiles: bool,
    error_503_page: Option<&CustomErrorPage>,
) -> std::result::Result<Response<BoxBody>, std::io::Error> {
    Ok(match resolved {
        Resolved::File(abs_path) => {
            serve_file(req, &abs_path, is_head, metrics, csp, error_503_page).await?
        }
        Resolved::NotFound => {
            let decoded_for_log = sanitize_header_value(decoded);
            log::debug!("404 Not Found: {decoded_for_log}");
            metrics.add_request();
            text_response(StatusCode::NOT_FOUND, "Not Found", csp, "")
        }
        Resolved::Redirect(location) => {
            let safe = sanitize_header_value(&location);
            metrics.add_request();
            redirect_response(&safe, csp)
        }
        Resolved::Fallback => {
            metrics.add_request();
            error_503_page.map_or_else(
                || {
                    html_response(
                        StatusCode::SERVICE_UNAVAILABLE,
                        fallback::NO_SITE_HTML,
                        is_head,
                        csp,
                        "",
                    )
                },
                |page| page.response(is_head, csp, ""),
            )
        }
        Resolved::Forbidden => {
            let decoded_for_log = sanitize_header_value(decoded);
            log::warn!("403 Forbidden: {decoded_for_log}");
            metrics.add_error();
            text_response(StatusCode::FORBIDDEN, "Forbidden", csp, "")
        }
        Resolved::DirectoryListing(dir_path) => {
            let decoded_owned = decoded.to_owned();
            let html = tokio::task::spawn_blocking(move || {
                build_directory_listing(&dir_path, &decoded_owned, expose_dotfiles)
            })
            .await
            .map_err(|e| std::io::Error::other(format!("directory listing task panicked: {e}")))?;
            metrics.add_request();
            html_response(StatusCode::OK, &html, is_head, csp, decoded)
        }
        Resolved::CustomError(page) => {
            metrics.add_request();
            page.response(is_head, csp, "")
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
fn external_redirect_response(
    location: &str,
    status: u16,
    csp: &str,
) -> std::result::Result<Response<BoxBody>, std::io::Error> {
    let body = format!("Redirecting to {location}");
    let data: Bytes = Bytes::copy_from_slice(body.as_bytes());
    let sc = StatusCode::from_u16(status).unwrap_or(StatusCode::MOVED_PERMANENTLY);
    let mut builder = Response::builder()
        .status(sc)
        .header(header::LOCATION, location)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .header(header::CONTENT_LENGTH, data.len())
        .header("Cache-Control", "no-cache");
    builder = security_headers(builder, csp, "text/plain");
    finalize_response(builder, full_body(data), "operator redirect response")
}

// ─── File serving ─────────────────────────────────────────────────────────────

/// Serve a file, honouring conditional GET (H-9), Range (H-13), and
/// Accept-Encoding compression (H-8).
#[allow(clippy::too_many_lines)] // file serving intentionally centralizes validators and sidecar selection
async fn serve_file(
    req: &Request<Incoming>,
    abs_path: &std::path::Path,
    is_head: bool,
    metrics: &SharedMetrics,
    csp: &str,
    error_503_page: Option<&CustomErrorPage>,
) -> std::result::Result<Response<BoxBody>, std::io::Error> {
    let file = match tokio::fs::File::open(abs_path).await {
        Ok(file) => file,
        Err(e) => {
            return Ok(open_error_response(
                abs_path,
                &e,
                metrics,
                csp,
                is_head,
                error_503_page,
            ))
        }
    };

    let metadata = match file.metadata().await {
        Ok(metadata) => metadata,
        Err(e) => {
            log::warn!("Failed to read metadata for {}: {e}", abs_path.display());
            metrics.add_error();
            return Ok(internal_error_response(csp, is_head, error_503_page));
        }
    };

    let file_len = metadata.len();
    let ext = abs_path.extension().and_then(|e| e.to_str()).unwrap_or("");
    let content_type = mime::for_extension(ext);
    let path_str = abs_path.to_str().unwrap_or("");
    let etag = weak_etag(&metadata);
    let last_modified = last_modified_header(&metadata);

    // ── ETag / conditional GET (H-9) ─────────────────────────────────────────
    if client_etag_matches(req, &etag) {
        metrics.add_request();
        let resp = not_modified_response(&etag, last_modified.as_deref(), content_type, path_str);
        return Ok(resp);
    }
    if client_not_modified_since(req, &metadata) {
        metrics.add_request();
        let resp = not_modified_response(&etag, last_modified.as_deref(), content_type, path_str);
        return Ok(resp);
    }

    // ── Range request (H-13) ─────────────────────────────────────────────────
    if let Some(range_result) = parse_range(req, file_len) {
        return if let Ok(range) = range_result {
            let response = build_range_response(
                file,
                range,
                file_len,
                content_type,
                path_str,
                is_head,
                csp,
                &etag,
                last_modified.as_deref(),
            )
            .await?;
            metrics.add_request();
            Ok(response)
        } else {
            metrics.add_error();
            Ok(finalize_response(
                Response::builder()
                    .status(StatusCode::RANGE_NOT_SATISFIABLE)
                    .header("Content-Range", format!("bytes */{file_len}")),
                empty_body(),
                "range not satisfiable response",
            )?)
        };
    }

    let preferred_encoding = if should_compress(content_type, file_len) {
        best_encoding(req)
    } else {
        Encoding::Identity
    };

    if let Some(sidecar) =
        open_precompressed_variant(abs_path, preferred_encoding, content_type).await?
    {
        let etag = strong_variant_etag(&sidecar.metadata, sidecar.encoding_token);
        let last_modified = last_modified_header(&sidecar.metadata);
        if client_etag_matches(req, &etag) || client_not_modified_since(req, &sidecar.metadata) {
            metrics.add_request();
            return Ok(not_modified_variant_response(
                &etag,
                last_modified.as_deref(),
                content_type,
                path_str,
                sidecar.content_encoding,
            ));
        }
        metrics.add_request();
        return build_precompressed_response(sidecar, content_type, path_str, is_head, csp, &etag);
    }

    // ── Full-file response ────────────────────────────────────────────────────
    metrics.add_request();
    build_full_response(
        preferred_encoding,
        file,
        file_len,
        content_type,
        path_str,
        is_head,
        csp,
        &etag,
        last_modified.as_deref(),
    )
}

struct PrecompressedVariant {
    file: tokio::fs::File,
    metadata: std::fs::Metadata,
    content_encoding: &'static str,
    encoding_token: &'static str,
}

async fn open_precompressed_variant(
    abs_path: &std::path::Path,
    preferred: Encoding,
    content_type: &str,
) -> std::result::Result<Option<PrecompressedVariant>, std::io::Error> {
    if !should_compress(content_type, 1_024) {
        return Ok(None);
    }

    let candidates: &[(&str, &str)] = match preferred {
        Encoding::Brotli => &[("br", "br"), ("gz", "gzip")],
        Encoding::Gzip => &[("gz", "gzip")],
        Encoding::Identity => &[],
    };

    for (suffix, content_encoding) in candidates {
        let variant_path = abs_path.with_extension(format!(
            "{}.{suffix}",
            abs_path
                .extension()
                .and_then(|ext| ext.to_str())
                .unwrap_or("")
        ));
        let file = match tokio::fs::File::open(&variant_path).await {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e),
        };
        let metadata = file.metadata().await?;
        if metadata.is_file() {
            return Ok(Some(PrecompressedVariant {
                file,
                metadata,
                content_encoding,
                encoding_token: suffix,
            }));
        }
    }

    Ok(None)
}

async fn build_range_response(
    mut file: tokio::fs::File,
    range: ByteRange,
    file_len: u64,
    content_type: &str,
    path_str: &str,
    is_head: bool,
    csp: &str,
    etag: &str,
    last_modified: Option<&str>,
) -> std::result::Result<Response<BoxBody>, std::io::Error> {
    use tokio::io::AsyncSeekExt as _;

    file.seek(std::io::SeekFrom::Start(range.start)).await?;
    let send_len = range.end.saturating_sub(range.start).saturating_add(1);
    let (body, content_encoding) = if is_head {
        (empty_body(), None)
    } else {
        stream_body(file, send_len, Encoding::Identity)
    };

    let mut builder = Response::builder()
        .status(StatusCode::PARTIAL_CONTENT)
        .header(
            "Content-Range",
            format!("bytes {}-{}/{}", range.start, range.end, file_len),
        )
        .header("Accept-Ranges", "bytes")
        .header("ETag", etag)
        .header("Cache-Control", cache_control_for(content_type, path_str))
        .header(header::CONTENT_TYPE, content_type);
    if let Some(last_modified) = last_modified {
        builder = builder.header(header::LAST_MODIFIED, last_modified);
    }
    builder = security_headers(builder, csp, content_type);
    if let Some(enc) = content_encoding {
        builder = builder
            .header("Content-Encoding", enc)
            .header("Vary", "Accept-Encoding");
    } else {
        builder = builder.header(header::CONTENT_LENGTH, send_len);
    }

    finalize_response(builder, body, "range response")
}

fn build_full_response(
    encoding: Encoding,
    file: tokio::fs::File,
    file_len: u64,
    content_type: &str,
    path_str: &str,
    is_head: bool,
    csp: &str,
    etag: &str,
    last_modified: Option<&str>,
) -> std::result::Result<Response<BoxBody>, std::io::Error> {
    let (body, content_encoding) = if is_head {
        (empty_body(), None)
    } else {
        stream_body(file, file_len, encoding)
    };

    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, content_type)
        .header("ETag", etag)
        .header("Cache-Control", cache_control_for(content_type, path_str));
    if let Some(last_modified) = last_modified {
        builder = builder.header(header::LAST_MODIFIED, last_modified);
    }
    if content_encoding.is_none() {
        builder = builder.header("Accept-Ranges", "bytes");
    }
    builder = security_headers(builder, csp, content_type);
    if let Some(enc) = content_encoding {
        builder = builder
            .header("Content-Encoding", enc)
            .header("Vary", "Accept-Encoding");
    } else {
        builder = builder.header(header::CONTENT_LENGTH, file_len);
    }

    finalize_response(builder, body, "file response")
}

fn build_precompressed_response(
    variant: PrecompressedVariant,
    content_type: &str,
    path_str: &str,
    is_head: bool,
    csp: &str,
    etag: &str,
) -> std::result::Result<Response<BoxBody>, std::io::Error> {
    let last_modified = last_modified_header(&variant.metadata);
    let content_length = variant.metadata.len();
    let body = if is_head {
        empty_body()
    } else {
        identity_reader_body(variant.file.take(content_length))
    };

    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, content_type)
        .header(header::CONTENT_ENCODING, variant.content_encoding)
        .header(header::VARY, "Accept-Encoding")
        .header(header::CONTENT_LENGTH, content_length)
        .header("ETag", etag)
        .header("Cache-Control", cache_control_for(content_type, path_str));
    if let Some(last_modified) = last_modified.as_deref() {
        builder = builder.header(header::LAST_MODIFIED, last_modified);
    }
    builder = security_headers(builder, csp, content_type);
    finalize_response(builder, body, "precompressed response")
}

/// Read up to `len` bytes from `file`, compressing according to `encoding`.
///
/// Returns `(body, Some("br"|"gzip"))` when compression is applied, or
/// `(body, None)` for identity encoding.
///
/// The `len` cap respects Range requests — only the requested slice is read.
fn stream_body(
    file: tokio::fs::File,
    len: u64,
    encoding: Encoding,
) -> (BoxBody, Option<&'static str>) {
    let handle = file.take(len);

    match encoding {
        Encoding::Brotli => {
            use async_compression::tokio::bufread::BrotliEncoder;
            use tokio::io::BufReader;
            (
                reader_body(BrotliEncoder::new(BufReader::new(handle))),
                Some("br"),
            )
        }
        Encoding::Gzip => {
            use async_compression::tokio::bufread::GzipEncoder;
            use tokio::io::BufReader;
            (
                reader_body(GzipEncoder::new(BufReader::new(handle))),
                Some("gzip"),
            )
        }
        Encoding::Identity => (identity_reader_body(handle), None),
    }
}

fn finalize_response(
    builder: hyper::http::response::Builder,
    body: BoxBody,
    context: &str,
) -> std::result::Result<Response<BoxBody>, std::io::Error> {
    builder
        .body(body)
        .map_err(|e| std::io::Error::other(format!("failed to build {context}: {e}")))
}

// ─── ETag helpers (H-9) ──────────────────────────────────────────────────────

/// Compute a weak `ETag` from file metadata without reading file content.
///
/// Format: `W/"<mtime_secs>-<size>"`.
/// Weak because mtime resolution means two different writes can share a value
/// on some filesystems.  Sufficient for conditional `GET` — prevents unnecessary
/// full transfers on subsequent page loads.
fn weak_etag(metadata: &std::fs::Metadata) -> String {
    use std::time::UNIX_EPOCH;
    let mtime = metadata
        .modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map_or(0, |d| d.as_secs());
    format!("W/\"{}-{}\"", mtime, metadata.len())
}

fn strong_variant_etag(metadata: &std::fs::Metadata, suffix: &str) -> String {
    use std::time::UNIX_EPOCH;
    let mtime = metadata
        .modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map_or(0, |d| d.as_secs());
    format!("\"{}-{}-{suffix}\"", mtime, metadata.len())
}

fn last_modified_header(metadata: &std::fs::Metadata) -> Option<String> {
    metadata.modified().ok().map(fmt_http_date)
}

/// Return `true` when the client's `If-None-Match` header matches `etag`.
fn client_etag_matches<B>(req: &Request<B>, etag: &str) -> bool {
    req.headers()
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|client_etag| {
            // Promote to a plain `fn` so the compiler can express the
            // `for<'a> fn(&'a str) -> &'a str` bound that a closure cannot.
            fn strip(s: &str) -> &str {
                s.trim().trim_start_matches("W/").trim_matches('"')
            }
            strip(client_etag) == strip(etag) || client_etag == "*"
        })
}

fn client_not_modified_since<B>(req: &Request<B>, metadata: &std::fs::Metadata) -> bool {
    let Some(if_modified_since) = req.headers().get(header::IF_MODIFIED_SINCE) else {
        return false;
    };
    let Ok(if_modified_since) = if_modified_since.to_str() else {
        return false;
    };
    let Ok(client_time) = parse_http_date(if_modified_since) else {
        return false;
    };
    let Ok(modified) = metadata.modified() else {
        return false;
    };
    modified <= client_time
}

fn not_modified_response(
    etag: &str,
    last_modified: Option<&str>,
    content_type: &str,
    path_str: &str,
) -> Response<BoxBody> {
    let mut builder = Response::builder()
        .status(StatusCode::NOT_MODIFIED)
        .header("ETag", etag)
        .header("Cache-Control", cache_control_for(content_type, path_str));
    if let Some(last_modified) = last_modified {
        builder = builder.header(header::LAST_MODIFIED, last_modified);
    }
    builder.body(empty_body()).unwrap_or_default()
}

fn not_modified_variant_response(
    etag: &str,
    last_modified: Option<&str>,
    content_type: &str,
    path_str: &str,
    content_encoding: &str,
) -> Response<BoxBody> {
    let mut builder = Response::builder()
        .status(StatusCode::NOT_MODIFIED)
        .header("ETag", etag)
        .header("Cache-Control", cache_control_for(content_type, path_str))
        .header(header::CONTENT_ENCODING, content_encoding)
        .header(header::VARY, "Accept-Encoding");
    if let Some(last_modified) = last_modified {
        builder = builder.header(header::LAST_MODIFIED, last_modified);
    }
    builder.body(empty_body()).unwrap_or_default()
}

// ─── Range request parsing (H-13) ────────────────────────────────────────────

/// A parsed byte range from `Range: bytes=<start>-<end>`.
#[derive(Debug, Clone, Copy)]
pub struct ByteRange {
    pub start: u64,
    pub end: u64, // inclusive
}

/// Parse `Range: bytes=N-M` from the request.
///
/// - `None` — no `Range` header present; serve the full file.
/// - `Some(Ok(range))` — valid single range.
/// - `Some(Err(()))` — invalid / out-of-bounds / multi-range; respond with 416.
pub fn parse_range<B>(
    req: &Request<B>,
    file_len: u64,
) -> Option<std::result::Result<ByteRange, ()>> {
    let raw = req.headers().get(header::RANGE)?.to_str().ok()?;
    let bytes = raw.strip_prefix("bytes=")?;

    // Multi-range rejected — not worth the implementation cost.
    if bytes.contains(',') {
        return Some(Err(()));
    }

    let (start_str, end_str) = bytes.split_once('-')?;

    let (start, end) = if start_str.is_empty() {
        // Suffix range: bytes=-N  (last N bytes)
        let suffix: u64 = end_str.parse().ok()?;
        let start = file_len.saturating_sub(suffix);
        (start, file_len.saturating_sub(1))
    } else {
        let start: u64 = start_str.parse().ok()?;
        let end = if end_str.is_empty() {
            file_len.saturating_sub(1)
        } else {
            end_str.parse().ok()?
        };
        (start, end)
    };

    if start > end || end >= file_len {
        return Some(Err(()));
    }
    Some(Ok(ByteRange { start, end }))
}

// ─── Response builders ───────────────────────────────────────────────────────

/// Apply the full security-header set to a response builder.
///
/// Single definition of the security headers (H-1).  Every response path —
/// 200, 206, 301, 304, 400, 404, 500 — goes through here so additions never
/// need to be applied in multiple places.
/// Mutate a completed response to add transport-dependent security headers.
///
/// Called once per request in [`route`] after the full response is built so
/// that *every* response — file, directory listing, error, redirect — receives
/// the same headers regardless of which code path produced it.
///
/// | Header                     | Condition  | Value                                          |
/// |----------------------------|------------|------------------------------------------------|
/// | `Strict-Transport-Security`| HTTPS only | `max-age=63072000; includeSubDomains`          |
/// | `X-Content-Type-Options`   | always     | `nosniff`                                      |
/// | `X-Frame-Options`          | always     | `SAMEORIGIN`                                   |
///
/// `X-Content-Type-Options` and `X-Frame-Options` are also added by the lower-level
/// [`security_headers`] builder helper for most response paths, making them
/// doubly-inserted on those paths.  `insert` overwrites duplicates, so the net
/// result is always exactly one copy of each header.
async fn inject_security_headers(
    mut resp: Response<BoxBody>,
    req: &Request<Incoming>,
    is_https: bool,
    csp: &str,
    state: &SharedState,
) -> Response<BoxBody> {
    let is_html = is_html_response(&resp);
    let h = resp.headers_mut();
    if is_https {
        h.insert(
            header::STRICT_TRANSPORT_SECURITY,
            header::HeaderValue::from_static("max-age=63072000; includeSubDomains"),
        );
        if let Some(value) = onion_location_header_value(req, state).await {
            h.insert(header::HeaderName::from_static("onion-location"), value);
        }
    }
    h.insert(
        header::HeaderName::from_static("x-content-type-options"),
        header::HeaderValue::from_static("nosniff"),
    );
    h.insert(
        header::HeaderName::from_static("x-frame-options"),
        header::HeaderValue::from_static("SAMEORIGIN"),
    );
    h.insert(
        header::HeaderName::from_static("referrer-policy"),
        header::HeaderValue::from_static("no-referrer"),
    );
    h.insert(
        header::HeaderName::from_static("permissions-policy"),
        header::HeaderValue::from_static("camera=(), microphone=(), geolocation=()"),
    );
    if is_html && !h.contains_key(header::CONTENT_SECURITY_POLICY) && !csp.is_empty() {
        let safe = sanitize_header_value(csp);
        if let Ok(value) = header::HeaderValue::from_str(safe.as_ref()) {
            h.insert(header::CONTENT_SECURITY_POLICY, value);
        }
    }
    resp
}

async fn onion_location_header_value(
    req: &Request<Incoming>,
    state: &SharedState,
) -> Option<header::HeaderValue> {
    let host = req
        .headers()
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .map_or("", str::trim);
    if host.eq_ignore_ascii_case("") {
        return None;
    }
    if host.split(':').next().is_some_and(|value| {
        value.len() >= ".onion".len()
            && value[value.len() - ".onion".len()..].eq_ignore_ascii_case(".onion")
    }) {
        return None;
    }

    let onion_address = state.read().await.onion_address.clone()?;
    let path_and_query = req
        .uri()
        .path_and_query()
        .map_or("/", hyper::http::uri::PathAndQuery::as_str);
    let location = format!("https://{onion_address}{path_and_query}");
    let safe_location = sanitize_header_value(&location);
    header::HeaderValue::from_str(safe_location.as_ref()).ok()
}

fn is_html_response(resp: &Response<BoxBody>) -> bool {
    resp.headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|content_type| content_type.starts_with("text/html"))
}

fn security_headers(
    mut builder: hyper::http::response::Builder,
    csp: &str,
    content_type: &str,
) -> hyper::http::response::Builder {
    builder = builder
        .header("X-Content-Type-Options", "nosniff")
        .header("X-Frame-Options", "SAMEORIGIN")
        .header("Referrer-Policy", "no-referrer")
        .header(
            "Permissions-Policy",
            "camera=(), microphone=(), geolocation=()",
        );
    // An empty `csp` string is the sentinel value produced by `CspLevel::Off`
    // (see `CspLevel::as_header_value`).  In that case we must not emit any
    // `Content-Security-Policy` header at all — not even a "safe" default —
    // because the operator has explicitly opted out.  Emitting `default-src
    // 'self'` when `csp_level = "off"` blocks external fonts, CDN
    // stylesheets, and inline styles, visibly breaking page formatting.
    if content_type.starts_with("text/html") && !csp.is_empty() {
        let safe = sanitize_header_value(csp);
        builder = builder.header("Content-Security-Policy", safe.as_ref());
    }
    builder
}

fn text_response(
    status: StatusCode,
    body: &'static str,
    csp: &str,
    url_path: &str,
) -> Response<BoxBody> {
    let mut builder = Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .header(header::CONTENT_LENGTH, body.len())
        .header("Cache-Control", cache_control_for("text/plain", url_path));
    builder = security_headers(builder, csp, "text/plain");
    builder.body(full_body(body)).unwrap_or_default()
}

fn html_response(
    status: StatusCode,
    body: &str,
    suppress: bool,
    csp: &str,
    url_path: &str,
) -> Response<BoxBody> {
    const CT: &str = "text/html; charset=utf-8";
    let data: Bytes = Bytes::copy_from_slice(body.as_bytes());
    let mut builder = Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, CT)
        .header(header::CONTENT_LENGTH, data.len())
        .header("Cache-Control", cache_control_for(CT, url_path));
    builder = security_headers(builder, csp, CT);
    let body = if suppress {
        empty_body()
    } else {
        full_body(data)
    };
    builder.body(body).unwrap_or_default()
}

fn redirect_response(location: &str, csp: &str) -> Response<BoxBody> {
    // Emit security headers on 301 so the .onion address does not leak via
    // Referer when the browser follows the redirect (H-9 / write_headers emits
    // all security headers from one place; write_redirect delegates here).
    let body = format!("Redirecting to {location}");
    let data: Bytes = Bytes::copy_from_slice(body.as_bytes());
    let mut builder = Response::builder()
        .status(StatusCode::MOVED_PERMANENTLY)
        .header(header::LOCATION, location)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .header(header::CONTENT_LENGTH, data.len())
        .header("Cache-Control", "no-cache");
    builder = security_headers(builder, csp, "text/plain");
    builder.body(full_body(data)).unwrap_or_default()
}

fn method_not_allowed() -> Response<BoxBody> {
    Response::builder()
        .status(StatusCode::METHOD_NOT_ALLOWED)
        .header(header::ALLOW, "GET, HEAD, OPTIONS")
        .header(header::CONTENT_LENGTH, "0")
        .body(empty_body())
        .unwrap_or_default()
}

fn options_response() -> Response<BoxBody> {
    Response::builder()
        .status(StatusCode::OK)
        .header(header::ALLOW, "GET, HEAD, OPTIONS")
        .header(header::CONTENT_LENGTH, "0")
        .body(empty_body())
        .unwrap_or_default()
}

fn open_error_response(
    abs_path: &std::path::Path,
    e: &std::io::Error,
    metrics: &SharedMetrics,
    csp: &str,
    is_head: bool,
    error_503_page: Option<&CustomErrorPage>,
) -> Response<BoxBody> {
    metrics.add_error();
    match e.kind() {
        std::io::ErrorKind::PermissionDenied => {
            log::warn!("403 Forbidden (permission denied): {}", abs_path.display());
            text_response(StatusCode::FORBIDDEN, "Forbidden", csp, "")
        }
        std::io::ErrorKind::NotFound => {
            log::warn!(
                "404 Not Found (file disappeared after resolve): {}",
                abs_path.display()
            );
            text_response(StatusCode::NOT_FOUND, "Not Found", csp, "")
        }
        _ => {
            log::error!("Unexpected error opening {}: {e}", abs_path.display());
            internal_error_response(csp, is_head, error_503_page)
        }
    }
}

fn internal_error_response(
    csp: &str,
    is_head: bool,
    error_503_page: Option<&CustomErrorPage>,
) -> Response<BoxBody> {
    error_503_page.map_or_else(
        || {
            text_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal Server Error",
                csp,
                "",
            )
        },
        |page| page.response(is_head, csp, ""),
    )
}

fn response_size(resp: &Response<BoxBody>) -> Option<u64> {
    resp.headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
}

// ─── Unit tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::{percent_decode, resolve_path, CustomErrorPage, Resolved};
    use bytes::Bytes;
    use hyper::StatusCode;
    use std::path::Path;
    use std::sync::Arc;

    fn make_test_tree() -> (tempfile::TempDir, std::path::PathBuf) {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = tmp.path().join("root");
        std::fs::create_dir_all(&root).expect("create root");
        std::fs::write(root.join("index.html"), b"hello").expect("write index");
        std::fs::write(tmp.path().join("secret.txt"), b"secret").expect("write secret");
        let canonical_root = root.canonicalize().expect("canonicalize root");
        (tmp, canonical_root)
    }

    #[test]
    fn percent_decode_ascii_passthrough() {
        assert_eq!(percent_decode("/index.html"), "/index.html");
    }

    #[test]
    fn percent_decode_space() {
        assert_eq!(percent_decode("/file%20name.html"), "/file name.html");
    }

    #[test]
    fn percent_decode_multibyte_utf8() {
        assert_eq!(percent_decode("/caf%C3%A9.html"), "/café.html");
    }

    #[test]
    fn percent_decode_null_byte_not_decoded() {
        // The crate-backed implementation falls back to the raw input when a
        // null byte is detected, rather than encoding it as the literal "%00".
        // Either way the caller never sees a NUL character in the output.
        let result = percent_decode("/foo%00/../secret");
        assert!(
            !result.contains('\x00'),
            "null byte in decoded output: {result:?}"
        );
    }

    #[test]
    fn percent_decode_incomplete_percent_sequence() {
        // percent-encoding crate passes incomplete sequences through unchanged.
        assert_eq!(percent_decode("/foo%2"), "/foo%2");
    }

    #[test]
    fn percent_decode_invalid_hex() {
        assert_eq!(percent_decode("/foo%ZZ"), "/foo%ZZ");
    }

    #[test]
    fn resolve_path_happy_path() {
        let (_tmp, root) = make_test_tree();
        let result = resolve_path(&super::ResolveOptions {
            canonical_root: &root,
            url_path: "/index.html",
            index_file: "index.html",
            dir_listing: false,
            expose_dotfiles: false,
            spa_routing: false,
            error_404_page: None,
        });
        assert!(
            matches!(result, Resolved::File(_)),
            "expected Resolved::File, got {result:?}"
        );
    }

    #[test]
    fn resolve_path_directory_traversal() {
        let (tmp, root) = make_test_tree();
        let _ = tmp;
        let result = resolve_path(&super::ResolveOptions {
            canonical_root: &root,
            url_path: "/../secret.txt",
            index_file: "index.html",
            dir_listing: false,
            expose_dotfiles: false,
            spa_routing: false,
            error_404_page: None,
        });
        assert_eq!(result, Resolved::Forbidden);
    }

    #[test]
    fn resolve_path_encoded_slash_traversal() {
        let (tmp, root) = make_test_tree();
        let decoded = super::percent_decode("/../secret.txt");
        let _ = tmp;
        let result = resolve_path(&super::ResolveOptions {
            canonical_root: &root,
            url_path: &decoded,
            index_file: "index.html",
            dir_listing: false,
            expose_dotfiles: false,
            spa_routing: false,
            error_404_page: None,
        });
        assert_eq!(result, Resolved::Forbidden);
    }

    #[test]
    fn resolve_path_missing_file_returns_not_found() {
        let (_tmp, root) = make_test_tree();
        let result = resolve_path(&super::ResolveOptions {
            canonical_root: &root,
            url_path: "/does_not_exist.txt",
            index_file: "index.html",
            dir_listing: false,
            expose_dotfiles: false,
            spa_routing: false,
            error_404_page: None,
        });
        assert_eq!(result, Resolved::NotFound);
    }

    #[test]
    fn resolve_path_missing_root_returns_fallback() {
        let missing_root = Path::new("/nonexistent/root/that/does/not/exist");
        let result = resolve_path(&super::ResolveOptions {
            canonical_root: missing_root,
            url_path: "/index.html",
            index_file: "index.html",
            dir_listing: false,
            expose_dotfiles: false,
            spa_routing: false,
            error_404_page: None,
        });
        assert_eq!(result, Resolved::Fallback);
    }

    #[test]
    fn resolve_path_uses_preloaded_custom_404_page() {
        let (_tmp, root) = make_test_tree();
        let page = Arc::new(CustomErrorPage {
            status: StatusCode::NOT_FOUND,
            body: Bytes::from_static(b"custom 404"),
        });
        let result = resolve_path(&super::ResolveOptions {
            canonical_root: &root,
            url_path: "/missing.html",
            index_file: "index.html",
            dir_listing: false,
            expose_dotfiles: false,
            spa_routing: false,
            error_404_page: Some(Arc::clone(&page)),
        });
        assert_eq!(result, Resolved::CustomError(page));
    }
}

#[cfg(test)]
mod sanitize_tests {
    use super::sanitize_header_value;

    #[test]
    fn strips_crlf() {
        assert_eq!(sanitize_header_value("foo\r\nbar"), "foobar");
    }
    #[test]
    fn strips_null_byte() {
        assert_eq!(sanitize_header_value("foo\x00bar"), "foobar");
    }
    #[test]
    fn strips_esc() {
        assert_eq!(sanitize_header_value("foo\x1bbar"), "foobar");
    }
    #[test]
    fn strips_del() {
        assert_eq!(sanitize_header_value("foo\x7fbar"), "foobar");
    }
    #[test]
    fn strips_tab() {
        assert_eq!(sanitize_header_value("foo\tbar"), "foobar");
    }
    #[test]
    fn preserves_unicode() {
        let input = "/café/page";
        assert_eq!(sanitize_header_value(input), input);
    }
    #[test]
    fn no_allocation_when_clean() {
        let s = "/normal/path";
        assert!(matches!(
            sanitize_header_value(s),
            std::borrow::Cow::Borrowed(_)
        ));
    }
}

#[cfg(test)]
mod proxy_tests {
    #![allow(clippy::expect_used)]

    use super::resolved_remote_addr;
    use bytes::Bytes;
    use http_body_util::Empty;

    fn request_with_xff(value: &str) -> hyper::Request<Empty<Bytes>> {
        hyper::Request::builder()
            .header("x-forwarded-for", value)
            .body(Empty::new())
            .expect("valid request builder")
    }

    #[test]
    fn trusts_forwarded_for_from_trusted_proxy() {
        let req = request_with_xff("203.0.113.10, 127.0.0.1");
        let peer = std::net::SocketAddr::from(([127, 0, 0, 1], 8080));
        let trusted = [std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)];
        assert_eq!(
            resolved_remote_addr(&req, peer, &trusted),
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 10))
        );
    }

    #[test]
    fn ignores_forwarded_for_from_untrusted_peer() {
        let req = request_with_xff("203.0.113.10");
        let peer = std::net::SocketAddr::from(([127, 0, 0, 1], 8080));
        let trusted = [std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 1))];
        assert_eq!(
            resolved_remote_addr(&req, peer, &trusted),
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
        );
    }
}

#[cfg(test)]
mod cache_tests {
    use super::{cache_control_for, pathing::is_hashed_asset};

    #[test]
    fn html_gets_no_cache() {
        assert_eq!(
            cache_control_for("text/html; charset=utf-8", "/index.html"),
            "no-cache"
        );
    }
    #[test]
    fn hashed_js_gets_immutable() {
        assert_eq!(
            cache_control_for("text/javascript", "/app.a1b2c3d4.js"),
            "max-age=31536000, immutable"
        );
    }
    #[test]
    fn hashed_css_gets_immutable() {
        assert_eq!(
            cache_control_for("text/css", "/style.deadbeef.css"),
            "max-age=31536000, immutable"
        );
    }
    #[test]
    fn plain_css_gets_no_cache() {
        assert_eq!(cache_control_for("text/css", "/style.css"), "no-cache");
    }
    #[test]
    fn plain_js_gets_no_cache() {
        assert_eq!(cache_control_for("text/javascript", "/main.js"), "no-cache");
    }
    #[test]
    fn empty_path_gets_no_cache() {
        assert_eq!(cache_control_for("text/plain", ""), "no-cache");
    }
    #[test]
    fn is_hashed_asset_rejects_short_hex() {
        assert!(!is_hashed_asset("app.abc.js"));
    }
    #[test]
    fn is_hashed_asset_accepts_exactly_8_hex() {
        assert!(is_hashed_asset("app.deadbeef.js"));
    }
    #[test]
    fn is_hashed_asset_accepts_16_hex() {
        assert!(is_hashed_asset("app.deadbeef01234567.js"));
    }
    #[test]
    fn is_hashed_asset_rejects_17_hex() {
        assert!(!is_hashed_asset("app.deadbeef012345678.js"));
    }
    #[test]
    fn is_hashed_asset_rejects_non_hex_segment() {
        assert!(!is_hashed_asset("app.ghijklmn.js"));
    }
}

#[cfg(test)]
mod dotfile_tests {
    use super::pathing::resolved_path_has_dotfile;
    use std::path::Path;

    #[test]
    fn detects_dotfile_component() {
        assert!(resolved_path_has_dotfile(
            Path::new("/srv/site/.git/config"),
            Path::new("/srv/site")
        ));
    }
    #[test]
    fn allows_normal_component() {
        assert!(!resolved_path_has_dotfile(
            Path::new("/srv/site/assets/main.js"),
            Path::new("/srv/site")
        ));
    }
    #[test]
    fn detects_nested_dotfile() {
        assert!(resolved_path_has_dotfile(
            Path::new("/srv/site/sub/.env"),
            Path::new("/srv/site")
        ));
    }
    #[test]
    fn allows_dotfile_outside_root_prefix() {
        assert!(!resolved_path_has_dotfile(
            Path::new("/srv/.hidden/site/index.html"),
            Path::new("/srv/.hidden/site"),
        ));
    }
}

#[cfg(test)]
mod range_tests {
    #![allow(clippy::expect_used)]
    use super::parse_range;
    use bytes::Bytes;
    use http_body_util::Empty;

    fn req_with_range(range: &str) -> hyper::Request<Empty<Bytes>> {
        hyper::Request::builder()
            .header(hyper::header::RANGE, range)
            .body(Empty::new())
            .expect("valid request builder")
    }

    #[test]
    fn parse_range_start_end() {
        let req = req_with_range("bytes=0-499");
        let r = parse_range(&req, 1000).expect("Some").expect("Ok");
        assert_eq!((r.start, r.end), (0, 499));
    }

    #[test]
    fn parse_range_open_end() {
        let req = req_with_range("bytes=500-");
        let r = parse_range(&req, 1000).expect("Some").expect("Ok");
        assert_eq!((r.start, r.end), (500, 999));
    }

    #[test]
    fn parse_range_suffix() {
        let req = req_with_range("bytes=-500");
        let r = parse_range(&req, 1000).expect("Some").expect("Ok");
        assert_eq!((r.start, r.end), (500, 999));
    }

    #[test]
    fn parse_range_out_of_bounds() {
        let req = req_with_range("bytes=900-1100");
        assert!(parse_range(&req, 1000).expect("Some").is_err());
    }

    #[test]
    fn parse_range_multi_range_rejected() {
        let req = req_with_range("bytes=0-100,200-300");
        assert!(parse_range(&req, 1000).expect("Some").is_err());
    }
}

#[cfg(test)]
mod encoding_tests {
    #![allow(clippy::expect_used)]
    use super::{best_encoding, should_compress, Encoding};
    use bytes::Bytes;
    use http_body_util::Empty;

    fn req_with_ae(ae: &str) -> hyper::Request<Empty<Bytes>> {
        hyper::Request::builder()
            .header(hyper::header::ACCEPT_ENCODING, ae)
            .body(Empty::new())
            .expect("valid request builder")
    }

    #[test]
    fn prefers_brotli_over_gzip() {
        let req = req_with_ae("gzip, br");
        assert_eq!(best_encoding(&req), Encoding::Brotli);
    }

    #[test]
    fn falls_back_to_gzip() {
        let req = req_with_ae("gzip, deflate");
        assert_eq!(best_encoding(&req), Encoding::Gzip);
    }

    #[test]
    fn identity_when_no_header() {
        let req: hyper::Request<Empty<Bytes>> = hyper::Request::builder()
            .body(Empty::new())
            .expect("valid request builder");
        assert_eq!(best_encoding(&req), Encoding::Identity);
    }

    #[test]
    fn honors_quality_values() {
        let req = req_with_ae("br;q=0.2, gzip;q=0.8, identity;q=0.1");
        assert_eq!(best_encoding(&req), Encoding::Gzip);
    }

    #[test]
    fn ignores_disabled_encoding() {
        let req = req_with_ae("br;q=0, gzip;q=1");
        assert_eq!(best_encoding(&req), Encoding::Gzip);
    }

    #[test]
    fn only_compresses_large_text_assets() {
        assert!(should_compress("text/css; charset=utf-8", 4_096));
        assert!(!should_compress("image/png", 4_096));
        assert!(!should_compress("text/css; charset=utf-8", 512));
    }
}

#[cfg(test)]
mod directory_listing_tests {
    #![allow(clippy::expect_used)]

    use super::build_directory_listing;

    #[test]
    fn truncates_oversized_directory_listing() {
        let tmp = tempfile::tempdir().expect("tempdir");
        for idx in 0..600 {
            std::fs::write(tmp.path().join(format!("file-{idx}.txt")), b"x").expect("write file");
        }

        let html = build_directory_listing(tmp.path(), "/", false);
        assert!(html.contains("Directory listing truncated"));
        assert!(html.contains("file-0.txt"));
    }
}

// ─── percent_decode tests ─────────────────────────────────────────────────────

#[cfg(test)]
mod percent_decode_tests {
    use super::percent_decode;

    #[test]
    fn decodes_basic_space() {
        assert_eq!(percent_decode("hello%20world"), "hello world");
    }

    #[test]
    fn decodes_multibyte_utf8() {
        // U+00E9 LATIN SMALL LETTER E WITH ACUTE encodes as %C3%A9
        assert_eq!(percent_decode("%C3%A9"), "é");
    }

    #[test]
    fn rejects_null_byte_falls_back_to_raw() {
        // Null bytes are anomalous in filesystem paths; the function falls back
        // to the raw input so the caller sees the original percent-encoded form.
        let result = percent_decode("hello%00world");
        assert!(!result.contains('\x00'), "output must not contain NUL");
    }

    #[test]
    fn invalid_utf8_falls_back_to_raw() {
        // %80 is a continuation byte with no leading byte — invalid UTF-8.
        // The function falls back to the raw input rather than producing garbage.
        let result = percent_decode("%80");
        assert!(!result.contains('\u{FFFD}') || result == "%80");
    }

    #[test]
    fn passthrough_plain_ascii() {
        assert_eq!(percent_decode("index.html"), "index.html");
    }

    #[test]
    fn decodes_plus_as_plus_not_space() {
        // URL path segments: `+` is literal, not a space.
        // (Space in paths is always `%20`.)
        assert_eq!(percent_decode("a+b"), "a+b");
    }
}
