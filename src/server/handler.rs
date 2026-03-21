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

use std::{fmt::Write as _, path::Path};

use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::TcpStream,
    time::timeout,
};

use super::{fallback, mime};
use crate::{runtime::state::SharedMetrics, Result};

// ─── Entry point ─────────────────────────────────────────────────────────────

/// Handle one HTTP connection to completion.
pub async fn handle(
    stream: TcpStream,
    canonical_root: &Path, // 2.3 — pre-canonicalized by server::run
    index_file: &str,
    dir_listing: bool,
    metrics: SharedMetrics,
) -> Result<()> {
    // 2.1 — wrap in BufReader so read_request uses read_line (one syscall per
    // line) rather than reading one byte at a time (up to 8192 syscalls).
    let mut reader = BufReader::new(stream);

    // 1.5 — Wrap read_request in a 30-second timeout to prevent slow-loris DoS.
    let request = match timeout(
        std::time::Duration::from_secs(30),
        read_request(&mut reader),
    )
    .await
    {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => return Err(e),
        Err(_elapsed) => {
            // Client held the connection open without completing a request.
            log::debug!("Request timeout — sending 408");
            // Recover the stream from the reader for writing.
            let mut stream = reader.into_inner();
            write_response(
                &mut stream,
                408,
                "Request Timeout",
                "text/plain",
                b"Request Timeout",
                false,
            )
            .await?;
            return Ok(());
        }
    };

    // Recover the TcpStream from the BufReader for writing the response.
    let mut stream = reader.into_inner();

    // 1.4 — parse_path now returns (method, path) so we can suppress the body
    // on HEAD responses.
    let Some((method, raw_path)) = parse_path(&request) else {
        write_response(
            &mut stream,
            400,
            "Bad Request",
            "text/plain",
            b"Bad Request",
            false,
        )
        .await?;
        metrics.add_error();
        return Ok(());
    };

    let is_head = method == "HEAD";

    // Strip query string / fragment then percent-decode.
    let path_only = raw_path.split('?').next().unwrap_or("/");
    let decoded = percent_decode(path_only);

    match resolve_path(canonical_root, &decoded, index_file, dir_listing) {
        Resolved::File(abs_path) => {
            serve_file(&mut stream, &abs_path, is_head, &metrics).await?;
        }

        Resolved::Fallback => {
            write_response(
                &mut stream,
                200,
                "OK",
                "text/html; charset=utf-8",
                fallback::NO_SITE_HTML.as_bytes(),
                is_head,
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
/// Extracted from `handle()` to keep that function under the line-count lint
/// threshold. All logic is unchanged from the inline version.
async fn serve_file(
    stream: &mut TcpStream,
    abs_path: &std::path::Path,
    is_head: bool,
    metrics: &SharedMetrics,
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
                )
                .await?;
                metrics.add_error();
                return Ok(());
            }
        };
        let ext = abs_path.extension().and_then(|e| e.to_str()).unwrap_or("");
        let content_type = mime::for_extension(ext);
        write_headers(stream, 200, "OK", content_type, file_len).await?;
        if !is_head {
            tokio::io::copy(&mut file, stream).await?;
        }
        stream.flush().await?;
        metrics.add_request();
    } else {
        write_response(stream, 404, "Not Found", "text/plain", b"Not Found", false).await?;
        metrics.add_error();
    }
    Ok(())
}

// ─── Request reading ─────────────────────────────────────────────────────────

/// Read HTTP request headers from a buffered stream, line by line.
///
/// Uses `read_line()` — a single system call per line regardless of how many
/// bytes arrive — instead of the previous byte-at-a-time loop that issued up
/// to 8 192 `read` syscalls per request (fix 2.1).
///
/// Stops at the blank line that terminates the HTTP header section
/// (`\r\n` or bare `\n`). Enforces an 8 KiB total limit.
async fn read_request(reader: &mut BufReader<TcpStream>) -> Result<String> {
    let mut request = String::with_capacity(512);
    let mut total = 0usize;

    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line).await?;
        if n == 0 {
            return Err("Connection closed before headers were complete".into());
        }
        total = total.saturating_add(n);
        if total > 8_192 {
            return Err("Request header too large (> 8 KiB)".into());
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
/// Returns `(method, path)` or `None` if the request line is malformed or
/// the method is not GET/HEAD.
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

enum Resolved {
    File(std::path::PathBuf),
    Fallback,
    Forbidden,
    DirectoryListing(std::path::PathBuf),
}

fn resolve_path(
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
        return Resolved::Fallback;
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
async fn write_response(
    stream: &mut TcpStream,
    status: u16,
    reason: &str,
    content_type: &str,
    body: &[u8],
    suppress_body: bool,
) -> Result<()> {
    write_headers(stream, status, reason, content_type, body.len() as u64).await?;
    if !suppress_body {
        stream.write_all(body).await?;
    }
    stream.flush().await?;
    Ok(())
}

/// Write only the response status line and headers, followed by the blank line.
/// Used by the streaming file path (1.7) and internally by `write_response`.
async fn write_headers(
    stream: &mut TcpStream,
    status: u16,
    reason: &str,
    content_type: &str,
    content_length: u64,
) -> Result<()> {
    let header = format!(
        "HTTP/1.1 {status} {reason}\r\n\
         Content-Type: {content_type}\r\n\
         Content-Length: {content_length}\r\n\
         Connection: close\r\n\
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
/// Encodes all bytes that are not unreserved URI characters (RFC 3986).
fn percent_encode_path(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for byte in s.bytes() {
        match byte {
            // Unreserved characters: ALPHA / DIGIT / "-" / "." / "_" / "~"
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(byte as char);
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
fn percent_decode(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    let mut chars = input.chars();

    while let Some(c) = chars.next() {
        if c != '%' {
            output.push(c);
            continue;
        }
        // Decode the next two hex digits.
        let h1 = chars.next().and_then(|c| c.to_digit(16));
        let h2 = chars.next().and_then(|c| c.to_digit(16));
        if let (Some(a), Some(b)) = (h1, h2) {
            // Both digits are valid 0–15, so the combined value fits in u8.
            let byte = u8::try_from((a << 4) | b).unwrap_or(b'?');
            output.push(byte as char);
        } else {
            output.push('%');
        }
    }

    output
}
