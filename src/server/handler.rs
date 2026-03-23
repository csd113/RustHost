//! # Request Handler
//!
//! **Directory:** `src/server/`
//!
//! Handles HTTP connections using [`hyper`]'s HTTP/1.1 connection loop,
//! which provides keep-alive transparently (Phase 3, C-1).
//!
//! Each connection is kept alive across multiple request/response cycles —
//! eliminating the 30–45 s Tor page-load penalty that the previous
//! single-shot, `Connection: close` design imposed.
//!
//! Additional Phase 3 features layered on top of hyper:
//! - **`ETag` / conditional `GET`** (`H-9`): weak `ETag` headers; `304` on match.
//! - **Range requests** (H-13): `bytes=N-M` single-range support; 206/416.
//! - **Brotli / Gzip compression** (H-8): negotiated via `Accept-Encoding`.
//!
//! Security: every resolved path is checked to be a descendant of the
//! configured site root via [`std::fs::canonicalize`]. Any attempt to
//! escape (e.g. `/../secret`) is rejected with HTTP 403.

#![allow(clippy::too_many_arguments)] // HTTP write_* fns mirror the wire format

use std::{fmt::Write as _, path::Path, sync::Arc};

use bytes::Bytes;
use http_body_util::{BodyExt as _, Full};
use hyper::{body::Incoming, header, Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;

use super::{fallback, mime};
use crate::{runtime::state::SharedMetrics, Result};

// ─── Body type alias ─────────────────────────────────────────────────────────

type BoxBody = http_body_util::combinators::BoxBody<Bytes, std::io::Error>;

fn full_body(data: impl Into<Bytes>) -> BoxBody {
    Full::new(data.into()).map_err(|e| match e {}).boxed()
}

fn empty_body() -> BoxBody {
    full_body(Bytes::new())
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
pub async fn handle(
    stream: TcpStream,
    canonical_root: Arc<Path>,
    index_file: Arc<str>,
    dir_listing: bool,
    expose_dotfiles: bool,
    metrics: SharedMetrics,
    csp: Arc<str>,
) -> Result<()> {
    let io = TokioIo::new(stream);

    hyper::server::conn::http1::Builder::new()
        .keep_alive(true)
        .serve_connection(
            io,
            hyper::service::service_fn(move |req| {
                let root = Arc::clone(&canonical_root);
                let idx  = Arc::clone(&index_file);
                let met  = Arc::clone(&metrics);
                let csp  = Arc::clone(&csp);
                async move {
                    route(req, &root, &idx, dir_listing, expose_dotfiles, &met, &csp).await
                }
            }),
        )
        .await
        .map_err(|e| {
            crate::AppError::Io(std::io::Error::other(e.to_string()))
        })
}

// ─── Router ──────────────────────────────────────────────────────────────────

async fn route(
    req: Request<Incoming>,
    canonical_root: &Path,
    index_file: &str,
    dir_listing: bool,
    expose_dotfiles: bool,
    metrics: &SharedMetrics,
    csp: &str,
) -> std::result::Result<Response<BoxBody>, std::io::Error> {
    match req.method() {
        &Method::OPTIONS => {
            metrics.add_request();
            return Ok(options_response());
        }
        m if m != Method::GET && m != Method::HEAD => {
            metrics.add_error();
            return Ok(method_not_allowed());
        }
        _ => {}
    }

    let is_head = req.method() == Method::HEAD;
    let raw_path = req.uri().path();
    let decoded = percent_decode(raw_path.split('?').next().unwrap_or("/"));

    match resolve_path(
        canonical_root,
        &decoded,
        index_file,
        dir_listing,
        expose_dotfiles,
    ) {
        Resolved::File(abs_path) => serve_file(&req, &abs_path, is_head, metrics, csp).await,
        Resolved::NotFound => {
            log::debug!("404 Not Found: {decoded}");
            metrics.add_request();
            Ok(text_response(StatusCode::NOT_FOUND, "Not Found", csp, ""))
        }
        Resolved::Redirect(location) => {
            let safe = sanitize_header_value(&location);
            metrics.add_request();
            Ok(redirect_response(&safe, csp))
        }
        Resolved::Fallback => {
            metrics.add_request();
            Ok(html_response(
                StatusCode::SERVICE_UNAVAILABLE,
                fallback::NO_SITE_HTML,
                is_head,
                csp,
                "",
            ))
        }
        Resolved::Forbidden => {
            log::warn!("403 Forbidden: {decoded}");
            metrics.add_error();
            Ok(text_response(StatusCode::FORBIDDEN, "Forbidden", csp, ""))
        }
        Resolved::DirectoryListing(dir_path) => {
            let decoded_clone = decoded.clone();
            let expose_dots_inner = expose_dotfiles;
            let html = tokio::task::spawn_blocking(move || {
                build_directory_listing(&dir_path, &decoded_clone, expose_dots_inner)
            })
            .await
            .map_err(|e| std::io::Error::other(format!("directory listing task panicked: {e}")))?;

            metrics.add_request();
            Ok(html_response(StatusCode::OK, &html, is_head, csp, &decoded))
        }
    }
}

// ─── File serving ─────────────────────────────────────────────────────────────

/// Serve a file, honouring conditional GET (H-9), Range (H-13), and
/// Accept-Encoding compression (H-8).
async fn serve_file(
    req: &Request<Incoming>,
    abs_path: &std::path::Path,
    is_head: bool,
    metrics: &SharedMetrics,
    csp: &str,
) -> std::result::Result<Response<BoxBody>, std::io::Error> {
    let mut file = match tokio::fs::File::open(abs_path).await {
        Ok(f) => f,
        Err(e) => return Ok(open_error_response(abs_path, &e, metrics, csp)),
    };

    let metadata = match file.metadata().await {
        Ok(m) => m,
        Err(e) => {
            log::warn!("Failed to read metadata for {}: {e}", abs_path.display());
            metrics.add_error();
            return Ok(text_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal Server Error",
                csp,
                "",
            ));
        }
    };

    let file_len = metadata.len();
    let ext = abs_path.extension().and_then(|e| e.to_str()).unwrap_or("");
    let content_type = mime::for_extension(ext);
    let path_str = abs_path.to_str().unwrap_or("");
    let etag = weak_etag(&metadata);

    // ── ETag / conditional GET (H-9) ─────────────────────────────────────────
    if client_etag_matches(req, &etag) {
        metrics.add_request();
        let resp = Response::builder()
            .status(StatusCode::NOT_MODIFIED)
            .header("ETag", &etag)
            .header("Cache-Control", cache_control_for(content_type, path_str))
            .body(empty_body())
            .unwrap_or_default();
        return Ok(resp);
    }

    // ── Range request (H-13) ─────────────────────────────────────────────────
    if let Some(range_result) = parse_range(req, file_len) {
        return if let Ok(range) = range_result {
            use tokio::io::AsyncSeekExt as _;
            file.seek(std::io::SeekFrom::Start(range.start)).await?;
            // saturating_add(1): end is guaranteed < file_len by parse_range,
            // so end - start + 1 cannot actually overflow, but pedantic requires
            // every arithmetic operation to be explicitly overflow-safe.
            let send_len = range.end.saturating_sub(range.start).saturating_add(1);

            let encoding = best_encoding(req);
            let (body, content_encoding) = if is_head {
                (empty_body(), None)
            } else {
                compress_body(file, send_len, encoding).await?
            };

            let mut builder = Response::builder()
                .status(StatusCode::PARTIAL_CONTENT)
                .header(
                    "Content-Range",
                    format!("bytes {}-{}/{}", range.start, range.end, file_len),
                )
                .header("Accept-Ranges", "bytes")
                .header("ETag", &etag)
                .header("Cache-Control", cache_control_for(content_type, path_str))
                .header(header::CONTENT_TYPE, content_type);
            builder = security_headers(builder, csp, content_type);
            if let Some(enc) = content_encoding {
                builder = builder
                    .header("Content-Encoding", enc)
                    .header("Vary", "Accept-Encoding");
            } else {
                builder = builder.header(header::CONTENT_LENGTH, send_len);
            }
            metrics.add_request();
            Ok(builder.body(body).unwrap_or_default())
        } else {
            metrics.add_error();
            Ok(Response::builder()
                .status(StatusCode::RANGE_NOT_SATISFIABLE)
                .header("Content-Range", format!("bytes */{file_len}"))
                .body(empty_body())
                .unwrap_or_default())
        };
    }

    // ── Full-file response ────────────────────────────────────────────────────
    let encoding = best_encoding(req);
    let (body, content_encoding) = if is_head {
        (empty_body(), None)
    } else {
        compress_body(file, file_len, encoding).await?
    };

    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, content_type)
        .header("Accept-Ranges", "bytes")
        .header("ETag", &etag)
        .header("Cache-Control", cache_control_for(content_type, path_str));
    builder = security_headers(builder, csp, content_type);
    if let Some(enc) = content_encoding {
        builder = builder
            .header("Content-Encoding", enc)
            .header("Vary", "Accept-Encoding");
    } else {
        builder = builder.header(header::CONTENT_LENGTH, file_len);
    }

    metrics.add_request();
    Ok(builder.body(body).unwrap_or_default())
}

// ─── Compression (H-8) ───────────────────────────────────────────────────────

/// Encoding negotiated from `Accept-Encoding`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    Brotli,
    Gzip,
    Identity,
}

/// Choose the best encoding the client accepts.
///
/// Prefers Brotli (superior compression ratio) over Gzip.
/// Returns `Identity` when neither is offered or the header is absent.
pub fn best_encoding<B>(req: &Request<B>) -> Encoding {
    let Some(accept) = req.headers().get(header::ACCEPT_ENCODING) else {
        return Encoding::Identity;
    };
    let Ok(s) = accept.to_str() else {
        return Encoding::Identity;
    };
    let has = |name: &str| {
        s.split(',').any(|part| {
            part.trim()
                .split(';')
                .next()
                .unwrap_or("")
                .trim()
                .eq_ignore_ascii_case(name)
        })
    };
    if has("br") {
        Encoding::Brotli
    } else if has("gzip") {
        Encoding::Gzip
    } else {
        Encoding::Identity
    }
}

/// Read up to `len` bytes from `file`, compressing according to `encoding`.
///
/// Returns `(body, Some("br"|"gzip"))` when compression is applied, or
/// `(body, None)` for identity encoding.
///
/// The `len` cap respects Range requests — only the requested slice is read.
async fn compress_body(
    mut file: tokio::fs::File,
    len: u64,
    encoding: Encoding,
) -> std::io::Result<(BoxBody, Option<&'static str>)> {
    use tokio::io::AsyncReadExt as _;

    let mut handle = (&mut file).take(len);

    match encoding {
        Encoding::Brotli => {
            use async_compression::tokio::bufread::BrotliEncoder;
            use tokio::io::BufReader;
            let mut enc = BrotliEncoder::new(BufReader::new(handle));
            let mut buf = Vec::new();
            enc.read_to_end(&mut buf).await?;
            Ok((full_body(buf), Some("br")))
        }
        Encoding::Gzip => {
            use async_compression::tokio::bufread::GzipEncoder;
            use tokio::io::BufReader;
            let mut enc = GzipEncoder::new(BufReader::new(handle));
            let mut buf = Vec::new();
            enc.read_to_end(&mut buf).await?;
            Ok((full_body(buf), Some("gzip")))
        }
        Encoding::Identity => {
            let mut buf = Vec::new();
            handle.read_to_end(&mut buf).await?;
            Ok((full_body(buf), None))
        }
    }
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
            text_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal Server Error",
                csp,
                "",
            )
        }
    }
}

// ─── Cache-Control classification (M-17) ─────────────────────────────────────

/// Classify a URL path into the appropriate `Cache-Control` value.
///
/// - HTML: `no-store` — prevents .onion address leaking via HTTP caches.
/// - Hashed assets (e.g. `app.a1b2c3d4.js`): `max-age=31536000, immutable`.
/// - Everything else: `no-cache` — revalidate but allow conditional GET.
fn cache_control_for(content_type: &str, path: &str) -> &'static str {
    if content_type.starts_with("text/html") {
        return "no-store";
    }
    let file_name = std::path::Path::new(path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");
    if is_hashed_asset(file_name) {
        "max-age=31536000, immutable"
    } else {
        "no-cache"
    }
}

/// Return `true` when `name` contains a dot-delimited segment of 8–16
/// lowercase hex characters (bundler content-hash pattern).
fn is_hashed_asset(name: &str) -> bool {
    name.split('.')
        .any(|seg| (8..=16).contains(&seg.len()) && seg.chars().all(|c| c.is_ascii_hexdigit()))
}

// ─── Path resolution ─────────────────────────────────────────────────────────

/// Resolve `.` and `..` in `path` lexically, without filesystem calls.
fn normalize_path(path: &std::path::Path) -> std::path::PathBuf {
    let mut stack: Vec<std::path::Component<'_>> = Vec::new();
    for component in path.components() {
        match component {
            std::path::Component::ParentDir => {
                if matches!(stack.last(), Some(std::path::Component::Normal(_))) {
                    stack.pop();
                }
            }
            std::path::Component::CurDir => {}
            c => stack.push(c),
        }
    }
    stack.iter().collect()
}

/// Return `true` when any component of `resolved` relative to `root` starts with `.`.
///
/// Called after `canonicalize()` to catch symlinks whose link name does not
/// start with `.` but whose target path does (M-2).
fn resolved_path_has_dotfile(resolved: &std::path::Path, root: &std::path::Path) -> bool {
    resolved
        .strip_prefix(root)
        .unwrap_or(resolved)
        .components()
        .any(|c| {
            matches!(c, std::path::Component::Normal(name)
                if name.to_str().is_some_and(|s| s.starts_with('.')))
        })
}

#[derive(Debug, PartialEq)]
pub(crate) enum Resolved {
    File(std::path::PathBuf),
    NotFound,
    Fallback,
    Forbidden,
    DirectoryListing(std::path::PathBuf),
    /// 301 redirect to the given Location URL.
    Redirect(String),
}

#[must_use]
pub(crate) fn resolve_path(
    canonical_root: &Path,
    url_path: &str,
    index_file: &str,
    dir_listing: bool,
    expose_dotfiles: bool,
) -> Resolved {
    // Block direct requests for dot-files unless operator opts in (H-10 / M-2).
    if !expose_dotfiles {
        for component in std::path::Path::new(url_path).components() {
            if let std::path::Component::Normal(name) = component {
                if name.to_str().is_some_and(|s| s.starts_with('.')) {
                    return Resolved::Forbidden;
                }
            }
        }
    }

    let relative = url_path.trim_start_matches('/');
    let candidate = canonical_root.join(relative);

    let target = if candidate.is_dir() {
        if !url_path.ends_with('/') {
            return Resolved::Redirect(format!("{url_path}/"));
        }
        let idx = candidate.join(index_file);
        if idx.exists() {
            idx
        } else if dir_listing {
            return Resolved::DirectoryListing(candidate);
        } else {
            return Resolved::Fallback;
        }
    } else {
        candidate
    };

    let Ok(canonical) = target.canonicalize() else {
        if !canonical_root.exists() {
            return Resolved::Fallback;
        }
        let normalized = normalize_path(&target);
        return if normalized.starts_with(canonical_root) {
            Resolved::NotFound
        } else {
            Resolved::Forbidden
        };
    };

    if !canonical.starts_with(canonical_root) {
        return Resolved::Forbidden;
    }

    // Post-canonicalize dot-file check (M-2).
    if !expose_dotfiles && resolved_path_has_dotfile(&canonical, canonical_root) {
        return Resolved::Forbidden;
    }

    Resolved::File(canonical)
}

// ─── Header value sanitisation ───────────────────────────────────────────────

/// Strip all ASCII control characters from a value destined for an HTTP header.
///
/// Retains printable ASCII (U+0020–U+007E) and non-ASCII Unicode.
/// Removes C0 controls (U+0000–U+001F, including NUL/CR/LF/TAB/ESC) and DEL.
/// Returns `Cow::Borrowed` on the common (clean) path to avoid heap allocation.
fn sanitize_header_value(s: &str) -> std::borrow::Cow<'_, str> {
    if s.chars().any(|c| c.is_ascii_control()) {
        std::borrow::Cow::Owned(s.chars().filter(|c| !c.is_ascii_control()).collect())
    } else {
        std::borrow::Cow::Borrowed(s)
    }
}

// ─── Directory listing ───────────────────────────────────────────────────────

fn build_directory_listing(dir: &Path, url_path: &str, expose_dotfiles: bool) -> String {
    let mut items = String::new();

    if let Ok(entries) = std::fs::read_dir(dir) {
        let mut names: Vec<String> = entries
            .flatten()
            .filter_map(|e| {
                let name = e.file_name().into_string().ok()?;
                // Hide dot-files (e.g. .git, .env, .htpasswd) by default (H-10).
                if expose_dotfiles || !name.starts_with('.') {
                    Some(name)
                } else {
                    None
                }
            })
            .collect();
        names.sort();

        // HTML-escape to prevent XSS via crafted directory names (H-8).
        let base = html_escape(url_path.trim_end_matches('/'));
        for name in &names {
            let encoded_name = percent_encode_path(name);
            let escaped_name = html_escape(name);
            let _ = writeln!(
                items,
                "  <li><a href=\"{base}/{encoded_name}\">{escaped_name}</a></li>"
            );
        }
    }

    let escaped_path = html_escape(url_path);
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Index of {escaped_path}</title>
  <style>
    body {{ font-family: system-ui, sans-serif; max-width: 700px;
            margin: 2rem auto; padding: 0 1rem; }}
    li   {{ line-height: 1.8; }}
  </style>
</head>
<body>
  <h2>Index of {escaped_path}</h2>
  <ul>
{items}  </ul>
</body>
</html>
"#
    )
}

fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            c => out.push(c),
        }
    }
    out
}

fn percent_encode_path(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(char::from(byte));
            }
            b => {
                let _ = write!(out, "%{b:02X}");
            }
        }
    }
    out
}

// ─── Percent decoding ────────────────────────────────────────────────────────

/// Decode percent-encoded characters in a URL path (`%20` → ` `).
///
/// Accumulates consecutive decoded bytes and converts as UTF-8 so multi-byte
/// sequences split across `%XX` tokens are handled correctly (`%C3%A9` → `é`).
/// Null bytes (`%00`) are never decoded — passed through as the literal `%00`.
#[must_use]
pub(crate) fn percent_decode(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    let mut byte_buf: Vec<u8> = Vec::new();

    let src = input.as_bytes();
    let mut i = 0;

    while i < src.len() {
        if src.get(i).copied() == Some(b'%') {
            let h1 = src.get(i.saturating_add(1)).copied().and_then(hex_digit);
            let h2 = src.get(i.saturating_add(2)).copied().and_then(hex_digit);
            if let (Some(hi), Some(lo)) = (h1, h2) {
                let byte = (hi << 4) | lo;
                if byte == 0x00 {
                    flush_byte_buf(&mut byte_buf, &mut output);
                    output.push_str("%00");
                } else {
                    byte_buf.push(byte);
                }
                i = i.saturating_add(3);
            } else {
                flush_byte_buf(&mut byte_buf, &mut output);
                output.push('%');
                i = i.saturating_add(1);
            }
        } else {
            flush_byte_buf(&mut byte_buf, &mut output);
            let ch = input
                .get(i..)
                .and_then(|s| s.chars().next())
                .unwrap_or('\u{FFFD}');
            output.push(ch);
            i = i.saturating_add(ch.len_utf8());
        }
    }
    flush_byte_buf(&mut byte_buf, &mut output);
    output
}

const fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b.wrapping_sub(b'0')),
        b'a'..=b'f' => Some(b.wrapping_sub(b'a').wrapping_add(10)),
        b'A'..=b'F' => Some(b.wrapping_sub(b'A').wrapping_add(10)),
        _ => None,
    }
}

fn flush_byte_buf(buf: &mut Vec<u8>, out: &mut String) {
    if !buf.is_empty() {
        out.push_str(&String::from_utf8_lossy(buf));
        buf.clear();
    }
}

// ─── Unit tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::{percent_decode, resolve_path, Resolved};
    use std::path::Path;

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
        let result = percent_decode("/foo%00/../secret");
        assert!(
            !result.contains('\x00'),
            "null byte in decoded output: {result:?}"
        );
        assert!(result.contains("%00"), "expected literal %00: {result:?}");
    }

    #[test]
    fn percent_decode_incomplete_percent_sequence() {
        assert_eq!(percent_decode("/foo%2"), "/foo%2");
    }

    #[test]
    fn percent_decode_invalid_hex() {
        assert_eq!(percent_decode("/foo%ZZ"), "/foo%ZZ");
    }

    #[test]
    fn resolve_path_happy_path() {
        let (_tmp, root) = make_test_tree();
        let result = resolve_path(&root, "/index.html", "index.html", false, false);
        assert!(
            matches!(result, Resolved::File(_)),
            "expected Resolved::File, got {result:?}"
        );
    }

    #[test]
    fn resolve_path_directory_traversal() {
        let (tmp, root) = make_test_tree();
        let _ = tmp;
        let result = resolve_path(&root, "/../secret.txt", "index.html", false, false);
        assert_eq!(result, Resolved::Forbidden);
    }

    #[test]
    fn resolve_path_encoded_slash_traversal() {
        let (tmp, root) = make_test_tree();
        let decoded = super::percent_decode("/../secret.txt");
        let _ = tmp;
        let result = resolve_path(&root, &decoded, "index.html", false, false);
        assert_eq!(result, Resolved::Forbidden);
    }

    #[test]
    fn resolve_path_missing_file_returns_not_found() {
        let (_tmp, root) = make_test_tree();
        let result = resolve_path(&root, "/does_not_exist.txt", "index.html", false, false);
        assert_eq!(result, Resolved::NotFound);
    }

    #[test]
    fn resolve_path_missing_root_returns_fallback() {
        let missing_root = Path::new("/nonexistent/root/that/does/not/exist");
        let result = resolve_path(missing_root, "/index.html", "index.html", false, false);
        assert_eq!(result, Resolved::Fallback);
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
mod cache_tests {
    use super::{cache_control_for, is_hashed_asset};

    #[test]
    fn html_gets_no_store() {
        assert_eq!(
            cache_control_for("text/html; charset=utf-8", "/index.html"),
            "no-store"
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
    use super::resolved_path_has_dotfile;
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
    use super::{best_encoding, Encoding};
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
}
