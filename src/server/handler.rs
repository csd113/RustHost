//! # Request Handler
//!
//! **Directory:** `src/server/`
//!
//! Handles a single TCP connection: reads the HTTP/1.1 request line,
//! resolves the path safely within the site root, serves the file (or a
//! built-in fallback), and writes a complete HTTP response.
//!
//! Security: every resolved path is checked to be a descendant of the
//! configured site root via [`std::fs::canonicalize`]. Any attempt to
//! escape (e.g. `/../secret`) is rejected with HTTP 403.

#![allow(clippy::too_many_arguments)] // HTTP write_* fns mirror the wire format

use std::{fmt::Write as _, path::Path, sync::Arc};

use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::TcpStream,
    time::timeout,
};

use super::{fallback, mime};
use crate::{runtime::state::SharedMetrics, Result};

// ─── Entry point ─────────────────────────────────────────────────────────────

/// Outcome of the initial request-reading phase.
///
/// Returned by [`receive_request`] to communicate what happened to the caller
/// without requiring `handle` to inspect raw error kinds directly.
enum RequestOutcome {
    /// The request was read and parsed successfully.
    ///
    /// Carries the raw header block, the recovered stream, and the boolean
    /// `is_head` flag derived from the method.
    Ready {
        is_head: bool,
        raw_path: String,
        stream: TcpStream,
    },
    /// A complete error response has already been written to the stream.
    /// `handle` should return `Ok(())` immediately.
    Responded,
}

/// Read and parse one HTTP request from `stream`, returning [`RequestOutcome`].
///
/// Handles the 30-second slow-loris timeout, the 8 KiB header limit, and
/// method validation, writing the appropriate error response in each failure
/// case so that `handle` stays focused on routing.
///
/// # Errors
///
/// Propagates I/O errors from writing error responses (e.g. `400`, `408`).
async fn receive_request(
    stream: TcpStream,
    csp: &str,
    metrics: &SharedMetrics,
) -> Result<RequestOutcome> {
    let mut reader = BufReader::new(stream);

    // 1.5 — 30-second timeout prevents slow-loris DoS.
    let request = match timeout(
        std::time::Duration::from_secs(30),
        read_request(&mut reader),
    )
    .await
    {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => {
            // 5.2 — Send 400 on any read failure (oversized headers, reset, etc.)
            log::debug!("Failed to read request headers: {e}");
            let mut stream = reader.into_inner();
            write_response(
                &mut stream,
                400,
                "Bad Request",
                "text/plain",
                b"Bad Request",
                false,
                csp,
            )
            .await?;
            metrics.add_error();
            return Ok(RequestOutcome::Responded);
        }
        Err(_elapsed) => {
            log::debug!("Request timeout — sending 408");
            let mut stream = reader.into_inner();
            write_response(
                &mut stream,
                408,
                "Request Timeout",
                "text/plain",
                b"Request Timeout",
                false,
                csp,
            )
            .await?;
            return Ok(RequestOutcome::Responded);
        }
    };

    let mut stream = reader.into_inner();

    // 1.4 — parse_path extracts (method, path); returns None for non-GET/HEAD.
    let Some((method, raw_path_ref)) = parse_path(&request) else {
        write_response(
            &mut stream,
            400,
            "Bad Request",
            "text/plain",
            b"Bad Request",
            false,
            csp,
        )
        .await?;
        metrics.add_error();
        return Ok(RequestOutcome::Responded);
    };

    Ok(RequestOutcome::Ready {
        is_head: method == "HEAD",
        raw_path: raw_path_ref.to_owned(),
        stream,
    })
}

/// Handle one HTTP connection to completion.
///
/// # Errors
///
/// Propagates I/O errors from writing response headers or body.  Read errors
/// (e.g. connection reset during header read) are converted to a `400 Bad
/// Request` response rather than being surfaced as errors.
pub async fn handle(
    stream: TcpStream,
    canonical_root: Arc<Path>, // 3.2 — pre-canonicalized (2.3); Arc avoids per-connection alloc
    index_file: Arc<str>,      // 3.2 — Arc<str> clone is O(1)
    dir_listing: bool,
    metrics: SharedMetrics,
    csp: Arc<str>, // 5.3 — Content-Security-Policy, applied to HTML responses only
) -> Result<()> {
    let RequestOutcome::Ready {
        is_head,
        raw_path,
        mut stream,
    } = receive_request(stream, &csp, &metrics).await?
    else {
        return Ok(());
    };

    // Strip query string / fragment then percent-decode.
    let path_only = raw_path.split('?').next().unwrap_or("/");
    let decoded = percent_decode(path_only);

    match resolve_path(&canonical_root, &decoded, &index_file, dir_listing) {
        Resolved::File(abs_path) => {
            serve_file(&mut stream, &abs_path, is_head, &metrics, &csp).await?;
        }
        Resolved::NotFound => {
            write_response(
                &mut stream,
                404,
                "Not Found",
                "text/plain",
                b"Not Found",
                false,
                &csp,
            )
            .await?;
            metrics.add_error();
        }
        Resolved::Redirect(location) => {
            let body = format!("Redirecting to {location}");
            let mut hdr = String::new();
            let _ = std::fmt::write(
                &mut hdr,
                format_args!(
                    "HTTP/1.1 301 Moved Permanently\r\n                     Location: {location}\r\n                     Content-Type: text/plain\r\n                     Content-Length: {len}\r\n                     Connection: close\r\n                     \r\n",
                    len = body.len()
                ),
            );
            stream.write_all(hdr.as_bytes()).await?;
            if !is_head {
                stream.write_all(body.as_bytes()).await?;
            }
            stream.flush().await?;
            metrics.add_request();
        }
        Resolved::Fallback => {
            write_response(
                &mut stream,
                200,
                "OK",
                "text/html; charset=utf-8",
                fallback::NO_SITE_HTML.as_bytes(),
                is_head,
                &csp,
            )
            .await?;
            metrics.add_request();
        }
        Resolved::Forbidden => {
            write_response(
                &mut stream,
                403,
                "Forbidden",
                "text/plain",
                b"Forbidden",
                false,
                &csp,
            )
            .await?;
            metrics.add_error();
        }
        Resolved::DirectoryListing(dir_path) => {
            let html = build_directory_listing(&dir_path, &decoded);
            write_response(
                &mut stream,
                200,
                "OK",
                "text/html; charset=utf-8",
                html.as_bytes(),
                is_head,
                &csp,
            )
            .await?;
            metrics.add_request();
        }
    }

    Ok(())
}

// ─── File serving ─────────────────────────────────────────────────────────────

/// Open `abs_path`, send headers + streamed body (or headers only for HEAD).
///
/// # Errors
///
/// Propagates I/O errors from opening the file, reading metadata, or writing
/// the response to the stream.
async fn serve_file(
    stream: &mut TcpStream,
    abs_path: &std::path::Path,
    is_head: bool,
    metrics: &SharedMetrics,
    csp: &str,
) -> Result<()> {
    // 1.7 — Stream the file instead of reading it entirely into memory.
    if let Ok(mut file) = tokio::fs::File::open(abs_path).await {
        let file_len = match file.metadata().await {
            Ok(m) => m.len(),
            Err(e) => {
                log::debug!("Failed to read file metadata: {e}");
                write_response(
                    stream,
                    500,
                    "Internal Server Error",
                    "text/plain",
                    b"Internal Server Error",
                    false,
                    csp,
                )
                .await?;
                metrics.add_error();
                return Ok(());
            }
        };
        let ext = abs_path.extension().and_then(|e| e.to_str()).unwrap_or("");
        let content_type = mime::for_extension(ext);
        write_headers(stream, 200, "OK", content_type, file_len, csp).await?;
        if !is_head {
            tokio::io::copy(&mut file, stream).await?;
        }
        stream.flush().await?;
        metrics.add_request();
    } else {
        write_response(
            stream,
            404,
            "Not Found",
            "text/plain",
            b"Not Found",
            false,
            csp,
        )
        .await?;
        metrics.add_error();
    }
    Ok(())
}

// ─── Request reading ─────────────────────────────────────────────────────────

/// Read HTTP request headers from a buffered stream, line by line.
///
/// Stops at the blank line that terminates the HTTP header section
/// (`\r\n` or bare `\n`). Enforces an 8 KiB total limit.
///
/// # Errors
///
/// - [`std::io::ErrorKind::InvalidData`] when the total header block exceeds
///   8 KiB — the caller maps this to `400 Bad Request`.
/// - [`std::io::ErrorKind::Other`] when the connection closes before the
///   blank terminating line is received.
/// - Any underlying [`std::io::Error`] from the network layer.
async fn read_request(reader: &mut BufReader<TcpStream>) -> Result<String> {
    let mut request = String::with_capacity(512);
    let mut total = 0usize;

    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line).await?;
        if n == 0 {
            return Err(
                std::io::Error::other("Connection closed before headers were complete").into(),
            );
        }
        total = total.saturating_add(n);
        if total > 8_192 {
            // Use InvalidData so the caller can distinguish "too large" from
            // other I/O errors and respond with 400 rather than dropping the
            // connection silently.
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Request header too large (> 8 KiB)",
            )
            .into());
        }
        request.push_str(&line);
        // Both `\r\n` (CRLF, RFC 7230 §3) and bare `\n` terminate the headers.
        if line == "\r\n" || line == "\n" {
            break;
        }
    }

    Ok(request)
}

/// Extract the method and URL path from `GET /path HTTP/1.1`.
///
/// Returns `(method, path)` or `None` if the request line is malformed or
/// the method is not `GET`/`HEAD`.
fn parse_path(request: &str) -> Option<(&str, &str)> {
    let first = request.lines().next()?;
    let mut it = first.splitn(3, ' ');
    let method = it.next()?;

    if method != "GET" && method != "HEAD" {
        return None;
    }

    let path = it.next()?;
    Some((method, path))
}

// ─── Path resolution ─────────────────────────────────────────────────────────

/// Resolve `.` and `..` components in `path` lexically, without any
/// filesystem calls.  The result is an absolute path with the same prefix
/// as `path` but with all `..` hops applied to the accumulated component stack.
///
/// Unlike [`std::fs::canonicalize`] this works on paths whose final component
/// does not yet exist on disk, which is exactly what we need when checking
/// whether a requested-but-missing file would fall inside the site root.
fn normalize_path(path: &std::path::Path) -> std::path::PathBuf {
    let mut stack: Vec<std::path::Component<'_>> = Vec::new();
    for component in path.components() {
        match component {
            std::path::Component::ParentDir => {
                // Only pop a normal component; never pop a root or prefix.
                if matches!(stack.last(), Some(std::path::Component::Normal(_))) {
                    stack.pop();
                }
            }
            std::path::Component::CurDir => { /* skip — no-op */ }
            c => stack.push(c),
        }
    }
    stack.iter().collect()
}

#[derive(Debug, PartialEq)]
pub(crate) enum Resolved {
    File(std::path::PathBuf),
    NotFound,
    Fallback,
    Forbidden,
    DirectoryListing(std::path::PathBuf),
    /// 301 redirect to the given Location URL (used to append a trailing slash).
    Redirect(String),
}

#[must_use]
pub(crate) fn resolve_path(
    canonical_root: &Path,
    url_path: &str,
    index_file: &str,
    dir_listing: bool,
) -> Resolved {
    // 2.3 — `canonical_root` is already resolved by `server::run`; no
    // canonicalize() syscall needed here on every request.
    let relative = url_path.trim_start_matches('/');
    let candidate = canonical_root.join(relative);

    let target = if candidate.is_dir() {
        // If the URL has no trailing slash, redirect so that relative links
        // in the served index file resolve against the correct base URL.
        if !url_path.ends_with('/') {
            let redirect_to = format!("{url_path}/");
            return Resolved::Redirect(redirect_to);
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
        // Target does not exist on disk. Use lexical normalization (no syscalls)
        // to determine whether the path would land inside the root:
        //   - Root itself missing             → Fallback  (no site configured)
        //   - Normalized path within root     → NotFound  (404)
        //   - Normalized path escapes root    → Forbidden (403)
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

    Resolved::File(canonical)
}

// ─── Response writing ────────────────────────────────────────────────────────

/// Write a complete HTTP response, optionally suppressing the body (for HEAD).
///
/// The `Content-Length` header always reflects the full body size, even when
/// the body is suppressed, as required by RFC 7231 §4.3.2.
///
/// # Errors
///
/// Propagates any [`std::io::Error`] from writing to the stream.
async fn write_response(
    stream: &mut TcpStream,
    status: u16,
    reason: &str,
    content_type: &str,
    body: &[u8],
    suppress_body: bool,
    csp: &str,
) -> Result<()> {
    // `usize as u64`: on all supported targets usize ≤ 64 bits, so this cast
    // is always lossless.  The allow suppresses clippy::cast_possible_truncation
    // at the narrowest possible scope.
    #[allow(clippy::cast_possible_truncation)]
    let body_len: u64 = body.len() as u64;
    write_headers(stream, status, reason, content_type, body_len, csp).await?;
    if !suppress_body {
        stream.write_all(body).await?;
    }
    stream.flush().await?;
    Ok(())
}

/// Write only the response status line and all headers, followed by the blank
/// line separating headers from body.
///
/// ## Security headers (task 5.3)
///
/// The following headers are added to **every** response:
///
/// | Header                 | Value                                      |
/// |------------------------|--------------------------------------------|
/// | `X-Content-Type-Options` | `nosniff`                                |
/// | `X-Frame-Options`      | `SAMEORIGIN`                               |
/// | `Referrer-Policy`      | `no-referrer`                              |
/// | `Permissions-Policy`   | `camera=(), microphone=(), geolocation=()` |
///
/// For **HTML** responses (`content_type` starts with `"text/html"`), the
/// `Content-Security-Policy` header is also emitted using `csp` as the value.
///
/// `Referrer-Policy: no-referrer` is especially important for the Tor hidden
/// service use case: without it, the `.onion` URL leaks in the `Referer`
/// header sent to any third-party resource (CDN, fonts, analytics) embedded
/// in a served HTML page.
///
/// # Errors
///
/// Propagates any [`std::io::Error`] from writing to the stream.
async fn write_headers(
    stream: &mut TcpStream,
    status: u16,
    reason: &str,
    content_type: &str,
    content_length: u64,
    csp: &str,
) -> Result<()> {
    let is_html = content_type.starts_with("text/html");
    let csp_line = if is_html && !csp.is_empty() {
        format!("Content-Security-Policy: {csp}\r\n")
    } else {
        String::new()
    };

    let header = format!(
        "HTTP/1.1 {status} {reason}\r\n\
         Content-Type: {content_type}\r\n\
         Content-Length: {content_length}\r\n\
         Connection: close\r\n\
         X-Content-Type-Options: nosniff\r\n\
         X-Frame-Options: SAMEORIGIN\r\n\
         Referrer-Policy: no-referrer\r\n\
         Permissions-Policy: camera=(), microphone=(), geolocation=()\r\n\
         {csp_line}\
         \r\n"
    );
    stream.write_all(header.as_bytes()).await?;
    Ok(())
}

// ─── Directory listing ───────────────────────────────────────────────────────

fn build_directory_listing(dir: &Path, url_path: &str) -> String {
    let mut items = String::new();

    if let Ok(entries) = std::fs::read_dir(dir) {
        let mut names: Vec<String> = entries
            .flatten()
            .filter_map(|e| e.file_name().into_string().ok())
            .collect();
        names.sort();

        let base = url_path.trim_end_matches('/');
        for name in &names {
            // 1.3 — Percent-encode the filename for the href attribute.
            let encoded_name = percent_encode_path(name);
            // 1.3 — HTML-entity-escape the filename for the visible link text.
            let escaped_name = html_escape(name);
            let _ = writeln!(
                items,
                "  <li><a href=\"{base}/{encoded_name}\">{escaped_name}</a></li>"
            );
        }
    }

    // 1.3 — Also escape url_path when used in page title / heading.
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

/// HTML-entity-escape a string for safe insertion into HTML content or
/// attribute values.
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

/// Percent-encode a filename component for safe use in a URL path segment.
///
/// Encodes all bytes that are not unreserved URI characters (RFC 3986).
fn percent_encode_path(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for byte in s.bytes() {
        match byte {
            // Unreserved characters: ALPHA / DIGIT / "-" / "." / "_" / "~"
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                // All matched bytes are ASCII; `char::from` is the
                // clippy-pedantic-clean alternative to `byte as char`.
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

/// Decode percent-encoded characters in a URL path (e.g. `%20` → ` `).
///
/// # Correctness (fix 4.5)
///
/// Accumulates consecutive percent-decoded bytes into a buffer and converts to
/// UTF-8 via `String::from_utf8_lossy` only when a literal character (or
/// end-of-input) breaks the run.  This correctly handles multi-byte sequences
/// split across adjacent `%XX` tokens (e.g. `%C3%A9` → `é`).
///
/// Null bytes (`%00`) are never decoded — they are passed through as the
/// literal string `%00` to prevent null-byte path injection attacks.
#[must_use]
pub(crate) fn percent_decode(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    // Buffer for consecutive percent-decoded bytes that may form a multi-byte
    // UTF-8 character together.
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
                    // 4.5 — null byte: do not decode, emit literal %00.
                    flush_byte_buf(&mut byte_buf, &mut output);
                    output.push_str("%00");
                } else {
                    byte_buf.push(byte);
                }
                i = i.saturating_add(3);
            } else {
                // Incomplete or invalid %XX — pass through literal `%`.
                flush_byte_buf(&mut byte_buf, &mut output);
                output.push('%');
                i = i.saturating_add(1);
            }
        } else {
            flush_byte_buf(&mut byte_buf, &mut output);
            // Advance by one full UTF-8 character so we never split a scalar.
            let ch = input
                .get(i..)
                .and_then(|s| s.chars().next())
                .unwrap_or('\u{FFFD}');
            output.push(ch);
            i = i.saturating_add(ch.len_utf8());
        }
    }
    // Flush any trailing percent-decoded bytes at end-of-input.
    flush_byte_buf(&mut byte_buf, &mut output);
    output
}

/// Convert a single ASCII hex digit byte to its numeric value, or `None`.
const fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b.wrapping_sub(b'0')),
        b'a'..=b'f' => Some(b.wrapping_sub(b'a').wrapping_add(10)),
        b'A'..=b'F' => Some(b.wrapping_sub(b'A').wrapping_add(10)),
        _ => None,
    }
}

/// Interpret `buf` as UTF-8 (with lossy replacement for invalid sequences),
/// append to `out`, then clear `buf`.
fn flush_byte_buf(buf: &mut Vec<u8>, out: &mut String) {
    if !buf.is_empty() {
        out.push_str(&String::from_utf8_lossy(buf));
        buf.clear();
    }
}

// ─── Unit tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    // `expect()` in test helpers is idiomatic and intentional — a failure here
    // means the test environment itself is broken, not the code under test.
    #![allow(clippy::expect_used)]

    use std::path::Path;

    use super::{percent_decode, resolve_path, Resolved};

    // ── percent_decode ────────────────────────────────────────────────────────

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
        // %C3%A9 is the UTF-8 encoding of 'é' (U+00E9).
        // Regression test for fix 4.5: the old implementation decoded each
        // %XX pair as an independent u8→char cast, yielding "Ã©" instead of "é".
        assert_eq!(percent_decode("/caf%C3%A9.html"), "/café.html");
    }

    #[test]
    fn percent_decode_null_byte_not_decoded() {
        // %00 must never be decoded to a null byte (path injection attack).
        // The literal string "%00" must appear in the output unchanged.
        let result = percent_decode("/foo%00/../secret");
        assert!(
            !result.contains('\x00'),
            "null byte found in decoded output: {result:?}"
        );
        assert!(
            result.contains("%00"),
            "expected literal %00 in output, got: {result:?}"
        );
    }

    #[test]
    fn percent_decode_incomplete_percent_sequence() {
        // "/foo%2" — the `%2` is not followed by a second hex digit, so the
        // `%` is passed through literally and the `2` is re-processed.
        assert_eq!(percent_decode("/foo%2"), "/foo%2");
    }

    #[test]
    fn percent_decode_invalid_hex() {
        // "%ZZ" contains non-hex digits after `%`; output must be unchanged.
        assert_eq!(percent_decode("/foo%ZZ"), "/foo%ZZ");
    }

    // ── resolve_path ──────────────────────────────────────────────────────────
    //
    // All tests that exercise the file-system use a temporary directory so
    // they are completely self-contained and leave no side effects.

    /// Returns a canonical temp dir with the structure:
    /// ```
    /// <tmp>/
    ///   root/
    ///     index.html        ← served for happy-path tests
    ///   secret.txt          ← outside root, for traversal tests
    /// ```
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
    fn resolve_path_happy_path() {
        let (_tmp, root) = make_test_tree();
        let result = resolve_path(&root, "/index.html", "index.html", false);
        assert!(
            matches!(result, Resolved::File(_)),
            "expected Resolved::File, got {result:?}"
        );
    }

    #[test]
    fn resolve_path_directory_traversal() {
        let (tmp, root) = make_test_tree();
        // secret.txt lives one level above `root`, so "/../secret.txt" would
        // escape the root if the traversal check were absent.
        // canonicalize() resolves `<root>/../secret.txt` → `<tmp>/secret.txt`
        // which is a real file, but it does NOT start_with `root` → Forbidden.
        let _ = tmp; // keep alive so secret.txt exists for canonicalize
        let result = resolve_path(&root, "/../secret.txt", "index.html", false);
        assert_eq!(
            result,
            Resolved::Forbidden,
            "expected Resolved::Forbidden for traversal attempt"
        );
    }

    #[test]
    fn resolve_path_encoded_slash_traversal() {
        // After percent-decoding, "/..%2Fsecret.txt" becomes "/../secret.txt"
        // which is what is passed to resolve_path — same traversal as above.
        let (tmp, root) = make_test_tree();
        let decoded = super::percent_decode("/../secret.txt"); // already decoded form
        let _ = tmp;
        let result = resolve_path(&root, &decoded, "index.html", false);
        assert_eq!(result, Resolved::Forbidden);
    }

    #[test]
    fn resolve_path_missing_file_returns_not_found() {
        let (_tmp, root) = make_test_tree();
        let result = resolve_path(&root, "/does_not_exist.txt", "index.html", false);
        assert_eq!(result, Resolved::NotFound);
    }

    #[test]
    fn resolve_path_missing_root_returns_fallback() {
        // Passing a non-existent root means every canonicalize() call fails.
        let missing_root = Path::new("/nonexistent/root/that/does/not/exist");
        let result = resolve_path(missing_root, "/index.html", "index.html", false);
        assert_eq!(result, Resolved::Fallback);
    }
}
