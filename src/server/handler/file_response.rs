//! Response bodies, headers, and file representation selection.

use std::{borrow::Cow, path::Path, sync::Arc, time::UNIX_EPOCH};

use bytes::Bytes;
use futures::TryStreamExt as _;
use http_body_util::{BodyExt as _, Full, StreamBody};
use httpdate::{fmt_http_date, parse_http_date};
use hyper::{body::Incoming, header, Method, Request, Response, StatusCode};
use tokio::io::AsyncReadExt as _;
use tokio_util::io::ReaderStream;

use super::super::mime;
use super::encoding::{best_encoding, is_compressible_content_type, should_compress, Encoding};
use super::routes::RequestContext;
use crate::runtime::state::{SharedMetrics, SharedState};

pub(super) type BoxBody = http_body_util::combinators::BoxBody<Bytes, std::io::Error>;
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CustomErrorPage {
    status: StatusCode,
    body: Bytes,
}

impl CustomErrorPage {
    pub(super) fn response(&self, is_head: bool, csp: &str, url_path: &str) -> Response<BoxBody> {
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

pub fn load_custom_error_page(
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

    if !metadata.is_file() || metadata.len() > MAX_CUSTOM_ERROR_PAGE_BYTES {
        log::warn!(
            "Ignoring [site] {label} path {} because it exceeds the {} byte limit",
            resolved.display(),
            MAX_CUSTOM_ERROR_PAGE_BYTES
        );
        return None;
    }

    match crate::persistence::read_bounded(&resolved, MAX_CUSTOM_ERROR_PAGE_BYTES) {
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

struct FileResponseContext<'a> {
    content_type: &'a str,
    path_str: &'a str,
    is_head: bool,
    csp: &'a str,
    etag: &'a str,
    last_modified: Option<&'a str>,
}
pub(super) fn external_redirect_response(
    location: &str,
    status: u16,
    csp: &str,
) -> std::result::Result<Response<BoxBody>, std::io::Error> {
    let body = format!("Redirecting to {location}");
    let data = Bytes::copy_from_slice(body.as_bytes());
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

pub(super) async fn serve_favicon(
    abs_path: &Path,
    req: &Request<Incoming>,
    is_head: bool,
    csp: &str,
    url_path: &str,
) -> std::result::Result<Response<BoxBody>, std::io::Error> {
    let (file, metadata) = open_regular_file(abs_path).await?;
    let length = metadata.len();
    let extension = abs_path
        .extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or("");
    let content_type = mime::for_extension(extension);
    let cache_control = cache_control_for(content_type, url_path);
    let etag = weak_etag(&metadata);
    let last_modified = last_modified_header(&metadata);

    // Favicons are re-requested on nearly every page load; honour conditional
    // requests so a cached copy is revalidated with a cheap 304.
    if selected_representation_not_modified(req, &etag, &metadata) {
        let mut builder = Response::builder()
            .status(StatusCode::NOT_MODIFIED)
            .header("ETag", &etag)
            .header("Cache-Control", cache_control);
        if let Some(last_modified) = last_modified.as_deref() {
            builder = builder.header(header::LAST_MODIFIED, last_modified);
        }
        builder = security_headers(builder, csp, content_type);
        return Ok(builder.body(empty_body()).unwrap_or_default());
    }

    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, content_type)
        .header(header::CONTENT_LENGTH, length)
        .header("Cache-Control", cache_control)
        .header("ETag", &etag);
    if let Some(last_modified) = last_modified.as_deref() {
        builder = builder.header(header::LAST_MODIFIED, last_modified);
    }
    builder = security_headers(builder, csp, content_type);
    let body = if is_head {
        empty_body()
    } else {
        identity_reader_body(file.take(length))
    };
    finalize_response(builder, body, "favicon response")
}

// ─── File serving ─────────────────────────────────────────────────────────────

/// Open only regular files. On Unix, `O_NONBLOCK` prevents a FIFO replacement
/// from pinning a filesystem worker; `O_NOFOLLOW` rejects a replaced leaf symlink.
/// Ancestor-directory replacement still requires platform-specific containment.
///
/// Returns the open handle together with its metadata so callers do not need a
/// second (blocking-pool) `fstat` on the same descriptor.
async fn open_regular_file(path: &Path) -> std::io::Result<(tokio::fs::File, std::fs::Metadata)> {
    let mut options = tokio::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW);
    let file = options.open(path).await?;
    let metadata = file.metadata().await?;
    if !metadata.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "only regular files can be served",
        ));
    }
    Ok((file, metadata))
}

/// Serve a file, honoring conditional requests, ranges, and compression.
#[expect(
    clippy::too_many_lines,
    reason = "File serving intentionally centralizes validators and sidecar selection."
)]
pub(super) async fn serve_file(
    abs_path: &std::path::Path,
    ctx: &RequestContext<'_>,
) -> std::result::Result<Response<BoxBody>, std::io::Error> {
    let (file, metadata) = match open_regular_file(abs_path).await {
        Ok(pair) => pair,
        Err(e) => {
            return Ok(open_error_response(
                abs_path,
                &e,
                ctx.metrics,
                ctx.csp,
                ctx.is_head,
                ctx.error_503_page,
            ))
        }
    };

    let file_len = metadata.len();
    let ext = abs_path.extension().and_then(|e| e.to_str()).unwrap_or("");
    let content_type = mime::for_extension(ext);
    let path_str = abs_path.to_str().unwrap_or("");
    let etag = weak_etag(&metadata);
    let last_modified = last_modified_header(&metadata);
    let response_ctx = FileResponseContext {
        content_type,
        path_str,
        is_head: ctx.is_head,
        csp: ctx.csp,
        etag: &etag,
        last_modified: last_modified.as_deref(),
    };

    let accepted_encoding = best_encoding(ctx.req);

    if let Some(sidecar) = open_precompressed_variant(
        abs_path,
        accepted_encoding,
        content_type,
        ctx.canonical_root,
    )
    .await?
    {
        let etag = weak_variant_etag(&sidecar.metadata, sidecar.encoding_token);
        let last_modified = last_modified_header(&sidecar.metadata);
        if selected_representation_not_modified(ctx.req, &etag, &sidecar.metadata) {
            ctx.metrics.add_request();
            return Ok(not_modified_variant_response(
                &etag,
                last_modified.as_deref(),
                content_type,
                path_str,
                sidecar.content_encoding,
            ));
        }
        ctx.metrics.add_request();
        return build_precompressed_response(
            sidecar,
            &FileResponseContext {
                content_type,
                path_str,
                is_head: ctx.is_head,
                csp: ctx.csp,
                etag: &etag,
                last_modified: last_modified.as_deref(),
            },
        );
    }

    let preferred_encoding = if should_compress(content_type, file_len) {
        accepted_encoding
    } else {
        Encoding::Identity
    };

    // ── Conditional request ──────────────────────────────────────────────────
    if selected_representation_not_modified(ctx.req, &etag, &metadata) {
        ctx.metrics.add_request();
        let resp = encoding_header(preferred_encoding).map_or_else(
            || {
                not_modified_response(
                    response_ctx.etag,
                    response_ctx.last_modified,
                    response_ctx.content_type,
                    response_ctx.path_str,
                )
            },
            |content_encoding| {
                not_modified_variant_response(
                    response_ctx.etag,
                    response_ctx.last_modified,
                    response_ctx.content_type,
                    response_ctx.path_str,
                    content_encoding,
                )
            },
        );
        return Ok(resp);
    }

    // ── Range request ────────────────────────────────────────────────────────
    if preferred_encoding == Encoding::Identity {
        if let Some(range_result) = parse_range(ctx.req, file_len) {
            return if let Ok(range) = range_result {
                let response = build_range_response(file, range, file_len, &response_ctx).await?;
                ctx.metrics.add_request();
                Ok(response)
            } else {
                ctx.metrics.add_error();
                Ok(finalize_response(
                    Response::builder()
                        .status(StatusCode::RANGE_NOT_SATISFIABLE)
                        .header("Content-Range", format!("bytes */{file_len}")),
                    empty_body(),
                    "range not satisfiable response",
                )?)
            };
        }
    }

    // ── Full-file response ────────────────────────────────────────────────────
    ctx.metrics.add_request();
    build_full_response(preferred_encoding, file, file_len, &response_ctx)
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
    canonical_root: &Path,
) -> std::result::Result<Option<PrecompressedVariant>, std::io::Error> {
    if preferred == Encoding::Identity || !is_compressible_content_type(content_type) {
        return Ok(None);
    }

    let candidates: &[(&str, &str)] = match preferred {
        Encoding::Brotli => &[("br", "br")],
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
        let canonical_variant = match variant_path.canonicalize() {
            Ok(path) if path.starts_with(canonical_root) => path,
            Ok(path) => {
                log::warn!(
                    "Ignoring precompressed sidecar outside site root: {} -> {}",
                    variant_path.display(),
                    path.display()
                );
                continue;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e),
        };
        let (file, metadata) = match open_regular_file(&canonical_variant).await {
            Ok(pair) => pair,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e),
        };
        return Ok(Some(PrecompressedVariant {
            file,
            metadata,
            content_encoding,
            encoding_token: suffix,
        }));
    }

    Ok(None)
}

async fn build_range_response(
    mut file: tokio::fs::File,
    range: ByteRange,
    file_len: u64,
    ctx: &FileResponseContext<'_>,
) -> std::result::Result<Response<BoxBody>, std::io::Error> {
    use tokio::io::AsyncSeekExt as _;

    file.seek(std::io::SeekFrom::Start(range.start)).await?;
    let send_len = range.end.saturating_sub(range.start).saturating_add(1);
    let body = if ctx.is_head {
        empty_body()
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
        .header("ETag", ctx.etag)
        .header(header::VARY, "Accept-Encoding")
        .header(
            "Cache-Control",
            cache_control_for(ctx.content_type, ctx.path_str),
        )
        .header(header::CONTENT_TYPE, ctx.content_type);
    if let Some(last_modified) = ctx.last_modified {
        builder = builder.header(header::LAST_MODIFIED, last_modified);
    }
    builder = security_headers(builder, ctx.csp, ctx.content_type);
    builder = builder.header(header::CONTENT_LENGTH, send_len);

    finalize_response(builder, body, "range response")
}

fn build_full_response(
    encoding: Encoding,
    file: tokio::fs::File,
    file_len: u64,
    ctx: &FileResponseContext<'_>,
) -> std::result::Result<Response<BoxBody>, std::io::Error> {
    let content_encoding = encoding_header(encoding);
    let body = if ctx.is_head {
        empty_body()
    } else {
        stream_body(file, file_len, encoding)
    };

    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, ctx.content_type)
        .header("ETag", ctx.etag)
        .header(header::VARY, "Accept-Encoding")
        .header(
            "Cache-Control",
            cache_control_for(ctx.content_type, ctx.path_str),
        );
    if let Some(last_modified) = ctx.last_modified {
        builder = builder.header(header::LAST_MODIFIED, last_modified);
    }
    if content_encoding.is_none() {
        builder = builder.header("Accept-Ranges", "bytes");
    }
    builder = security_headers(builder, ctx.csp, ctx.content_type);
    if let Some(enc) = content_encoding {
        builder = builder.header("Content-Encoding", enc);
    } else {
        builder = builder.header(header::CONTENT_LENGTH, file_len);
    }

    finalize_response(builder, body, "file response")
}

fn build_precompressed_response(
    variant: PrecompressedVariant,
    ctx: &FileResponseContext<'_>,
) -> std::result::Result<Response<BoxBody>, std::io::Error> {
    let content_length = variant.metadata.len();
    let body = if ctx.is_head {
        empty_body()
    } else {
        identity_reader_body(variant.file.take(content_length))
    };

    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, ctx.content_type)
        .header(header::CONTENT_ENCODING, variant.content_encoding)
        .header(header::CONTENT_LENGTH, content_length)
        .header("ETag", ctx.etag)
        .header(header::VARY, "Accept-Encoding")
        .header(
            "Cache-Control",
            cache_control_for(ctx.content_type, ctx.path_str),
        );
    if let Some(last_modified) = ctx.last_modified {
        builder = builder.header(header::LAST_MODIFIED, last_modified);
    }
    builder = security_headers(builder, ctx.csp, ctx.content_type);
    finalize_response(builder, body, "precompressed response")
}

/// Read up to `len` bytes from `file`, compressing according to `encoding`.
///
/// The `len` cap respects identity Range requests — only the requested slice is read.
fn stream_body(file: tokio::fs::File, len: u64, encoding: Encoding) -> BoxBody {
    let handle = file.take(len);

    match encoding {
        Encoding::Brotli => {
            use async_compression::tokio::bufread::BrotliEncoder;
            use tokio::io::BufReader;
            reader_body(BrotliEncoder::new(BufReader::new(handle)))
        }
        Encoding::Gzip => {
            use async_compression::tokio::bufread::GzipEncoder;
            use tokio::io::BufReader;
            reader_body(GzipEncoder::new(BufReader::new(handle)))
        }
        Encoding::Identity => identity_reader_body(handle),
    }
}

const fn encoding_header(encoding: Encoding) -> Option<&'static str> {
    match encoding {
        Encoding::Brotli => Some("br"),
        Encoding::Gzip => Some("gzip"),
        Encoding::Identity => None,
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

// ─── ETag helpers ────────────────────────────────────────────────────────────

/// Compute a weak `ETag` from file metadata without reading file content.
///
/// Format: `W/"<mtime_nanos>-<size>"`.
/// Weak because mtime resolution means two different writes can share a value
/// on some filesystems.  Sufficient for conditional `GET` — prevents unnecessary
/// full transfers on subsequent page loads.
fn weak_etag(metadata: &std::fs::Metadata) -> String {
    use std::time::UNIX_EPOCH;
    let mtime = metadata
        .modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map_or(0, |d| d.as_nanos());
    format!("W/\"{}-{}\"", mtime, metadata.len())
}

fn weak_variant_etag(metadata: &std::fs::Metadata, suffix: &str) -> String {
    use std::time::UNIX_EPOCH;
    let mtime = metadata
        .modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map_or(0, |d| d.as_nanos());
    format!("W/\"{}-{}-{suffix}\"", mtime, metadata.len())
}

fn last_modified_header(metadata: &std::fs::Metadata) -> Option<String> {
    metadata.modified().ok().map(fmt_http_date)
}

/// Return `true` when the client's `If-None-Match` header matches `etag`.
fn client_etag_matches<B>(req: &Request<B>, etag: &str) -> bool {
    req.headers()
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|client_etags| {
            // Promote to a plain `fn` so the compiler can express the
            // `for<'a> fn(&'a str) -> &'a str` bound that a closure cannot.
            fn strip(s: &str) -> &str {
                s.trim().trim_start_matches("W/").trim_matches('"')
            }
            client_etags
                .split(',')
                .map(str::trim)
                .any(|client_etag| strip(client_etag) == strip(etag) || client_etag == "*")
        })
}

fn selected_representation_not_modified<B>(
    req: &Request<B>,
    etag: &str,
    metadata: &std::fs::Metadata,
) -> bool {
    if req.headers().contains_key(header::IF_NONE_MATCH) {
        client_etag_matches(req, etag)
    } else {
        client_not_modified_since(req, metadata)
    }
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
    let Some(modified_secs) = modified
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_secs())
    else {
        return false;
    };
    let Some(client_secs) = client_time
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_secs())
    else {
        return false;
    };
    modified_secs <= client_secs
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
        .header("Cache-Control", cache_control_for(content_type, path_str))
        .header(header::VARY, "Accept-Encoding");
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

// ─── Range request parsing ───────────────────────────────────────────────────

/// A parsed byte range from `Range: bytes=<start>-<end>`.
#[derive(Debug, Clone, Copy)]
struct ByteRange {
    start: u64,
    end: u64, // inclusive
}

/// Parse `Range: bytes=N-M` from the request.
///
/// - `None` — no `Range` header present; serve the full file.
/// - `Some(Ok(range))` — valid single range.
/// - `Some(Err(()))` — invalid / out-of-bounds / multi-range; respond with 416.
fn parse_range<B>(req: &Request<B>, file_len: u64) -> Option<std::result::Result<ByteRange, ()>> {
    // Metadata-derived validators are weak: we cannot safely establish that
    // a resumed download still has identical bytes. Ignore conditional ranges
    // and send the complete representation, which HTTP explicitly permits.
    if req.method() != Method::GET || req.headers().contains_key(header::IF_RANGE) {
        return None;
    }
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
            end_str.parse::<u64>().ok()?.min(file_len.saturating_sub(1))
        };
        (start, end)
    };

    if start > end || end >= file_len {
        return Some(Err(()));
    }
    Some(Ok(ByteRange { start, end }))
}

// ─── Response builders ───────────────────────────────────────────────────────

/// Mutate a completed response to add transport-dependent security headers.
///
/// Called once per request in [`route`] after the full response is built so
/// that *every* response — file, directory listing, error, redirect — receives
/// the same headers regardless of which code path produced it.
///
/// | Header                     | Condition  | Value                                          |
/// |----------------------------|------------|------------------------------------------------|
/// | `Strict-Transport-Security`| HTTPS only | `max-age=31536000; includeSubDomains`          |
/// | `X-Content-Type-Options`   | always     | `nosniff`                                      |
/// | `X-Frame-Options`          | always     | `SAMEORIGIN`                                   |
///
/// This is the single place the transport-independent headers are inserted;
/// [`security_headers`] only handles the content-type-dependent CSP header.
pub(super) async fn inject_security_headers(
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
            header::HeaderValue::from_static("max-age=31536000; includeSubDomains"),
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

    // Clone the (short) onion address rather than holding the read guard across
    // header formatting.
    let onion_address = state.read().await.onion_address.clone()?;
    let path_and_query = req
        .uri()
        .path_and_query()
        .map_or("/", hyper::http::uri::PathAndQuery::as_str);
    let location = format!("http://{onion_address}{path_and_query}");
    let safe_location = sanitize_header_value(&location);
    header::HeaderValue::from_str(safe_location.as_ref()).ok()
}

fn is_html_response(resp: &Response<BoxBody>) -> bool {
    resp.headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|content_type| content_type.starts_with("text/html"))
}

/// Apply response headers that depend on the content type at build time.
///
/// Only the CSP header is set here; the transport-independent security headers
/// (`X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`,
/// `Permissions-Policy`) are added once by [`inject_security_headers`] after the
/// response is built, so they are not inserted twice per response.
fn security_headers(
    mut builder: hyper::http::response::Builder,
    csp: &str,
    content_type: &str,
) -> hyper::http::response::Builder {
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

pub(super) fn text_response(
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

pub(super) fn html_response(
    status: StatusCode,
    body: &str,
    suppress: bool,
    csp: &str,
    url_path: &str,
) -> Response<BoxBody> {
    const CT: &str = "text/html; charset=utf-8";
    let data = Bytes::copy_from_slice(body.as_bytes());
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

pub(super) fn redirect_response(location: &str, csp: &str) -> Response<BoxBody> {
    // Emit security headers on 301 so the .onion address does not leak via
    // Referer when the browser follows the redirect.
    let body = format!("Redirecting to {location}");
    let data = Bytes::copy_from_slice(body.as_bytes());
    let mut builder = Response::builder()
        .status(StatusCode::MOVED_PERMANENTLY)
        .header(header::LOCATION, location)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .header(header::CONTENT_LENGTH, data.len())
        .header("Cache-Control", "no-cache");
    builder = security_headers(builder, csp, "text/plain");
    builder.body(full_body(data)).unwrap_or_default()
}

pub(super) fn operational_text_response(
    status: StatusCode,
    body: &str,
    is_head: bool,
    csp: &str,
) -> Response<BoxBody> {
    let data = Bytes::copy_from_slice(body.as_bytes());
    let mut builder = Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .header(header::CONTENT_LENGTH, data.len())
        .header("Cache-Control", "no-store, no-cache, max-age=0");
    builder = security_headers(builder, csp, "text/plain");
    let body = if is_head {
        empty_body()
    } else {
        full_body(data)
    };
    builder.body(body).unwrap_or_default()
}

pub(super) fn method_not_allowed() -> Response<BoxBody> {
    method_not_allowed_with_allow("GET, HEAD, OPTIONS")
}

pub(super) fn method_not_allowed_with_allow(allow: &'static str) -> Response<BoxBody> {
    Response::builder()
        .status(StatusCode::METHOD_NOT_ALLOWED)
        .header(header::ALLOW, allow)
        .header(header::CONTENT_LENGTH, "0")
        .body(empty_body())
        .unwrap_or_default()
}

pub(super) fn options_response() -> Response<BoxBody> {
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

fn cache_control_for(content_type: &str, path: &str) -> &'static str {
    if content_type.starts_with("text/html") {
        return "no-cache";
    }
    let file_name = Path::new(path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");
    if is_hashed_asset(file_name) {
        "max-age=31536000, immutable"
    } else {
        "no-cache"
    }
}

fn is_hashed_asset(name: &str) -> bool {
    name.split('.')
        .any(|seg| (8..=16).contains(&seg.len()) && seg.chars().all(|c| c.is_ascii_hexdigit()))
}

pub(super) fn sanitize_header_value(s: &str) -> Cow<'_, str> {
    if s.chars().any(|c| c.is_ascii_control()) {
        Cow::Owned(s.chars().filter(|c| !c.is_ascii_control()).collect())
    } else {
        Cow::Borrowed(s)
    }
}
