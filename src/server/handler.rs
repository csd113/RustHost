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
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

use super::{fallback, mime};
use crate::{runtime::state::SharedMetrics, Result};

// ─── Entry point ─────────────────────────────────────────────────────────────

/// Handle one HTTP connection to completion.
pub async fn handle(
    mut stream: TcpStream,
    site_root: &Path,
    index_file: &str,
    dir_listing: bool,
    metrics: SharedMetrics,
) -> Result<()> {
    let request = read_request(&mut stream).await?;

    let Some(raw_path) = parse_path(&request) else {
        write_response(
            &mut stream,
            400,
            "Bad Request",
            "text/plain",
            b"Bad Request",
        )
        .await?;
        metrics.add_error();
        return Ok(());
    };

    // Strip query string / fragment then percent-decode.
    let path_only = raw_path.split('?').next().unwrap_or("/");
    let decoded = percent_decode(path_only);

    match resolve_path(site_root, &decoded, index_file, dir_listing) {
        Resolved::File(abs_path) => {
            if let Ok(bytes) = tokio::fs::read(&abs_path).await {
                let ext = abs_path.extension().and_then(|e| e.to_str()).unwrap_or("");
                write_response(&mut stream, 200, "OK", mime::for_extension(ext), &bytes).await?;
                metrics.add_request();
            } else {
                write_response(&mut stream, 404, "Not Found", "text/plain", b"Not Found").await?;
                metrics.add_error();
            }
        }

        Resolved::Fallback => {
            write_response(
                &mut stream,
                200,
                "OK",
                "text/html; charset=utf-8",
                fallback::NO_SITE_HTML.as_bytes(),
            )
            .await?;
            metrics.add_request();
        }

        Resolved::Forbidden => {
            write_response(&mut stream, 403, "Forbidden", "text/plain", b"Forbidden").await?;
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
            )
            .await?;
            metrics.add_request();
        }
    }

    Ok(())
}

// ─── Request reading ─────────────────────────────────────────────────────────

async fn read_request(stream: &mut TcpStream) -> Result<String> {
    let mut buf = Vec::with_capacity(512);
    let mut byte = [0u8; 1];

    loop {
        stream.read_exact(&mut byte).await?;
        buf.push(byte[0]);
        if buf.ends_with(b"\r\n\r\n") {
            break;
        }
        if buf.len() > 8_192 {
            return Err("Request header too large (> 8 KiB)".into());
        }
    }

    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// Extract the URL path from `GET /path HTTP/1.1`.
fn parse_path(request: &str) -> Option<&str> {
    let first = request.lines().next()?;
    let mut it = first.splitn(3, ' ');
    let method = it.next()?;

    if method != "GET" && method != "HEAD" {
        return None;
    }

    it.next()
}

// ─── Path resolution ─────────────────────────────────────────────────────────

enum Resolved {
    File(std::path::PathBuf),
    Fallback,
    Forbidden,
    DirectoryListing(std::path::PathBuf),
}

fn resolve_path(site_root: &Path, url_path: &str, index_file: &str, dir_listing: bool) -> Resolved {
    let relative = url_path.trim_start_matches('/');
    let candidate = site_root.join(relative);

    let Ok(canonical_root) = site_root.canonicalize() else {
        return Resolved::Fallback;
    };

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

    if !canonical.starts_with(&canonical_root) {
        return Resolved::Forbidden;
    }

    Resolved::File(canonical)
}

// ─── Response writing ────────────────────────────────────────────────────────

async fn write_response(
    stream: &mut TcpStream,
    status: u16,
    reason: &str,
    content_type: &str,
    body: &[u8],
) -> Result<()> {
    let header = format!(
        "HTTP/1.1 {status} {reason}\r\n\
         Content-Type: {content_type}\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n",
        body.len()
    );
    stream.write_all(header.as_bytes()).await?;
    stream.write_all(body).await?;
    stream.flush().await?;
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
            let _ = writeln!(items, "  <li><a href=\"{base}/{name}\">{name}</a></li>");
        }
    }

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Index of {url_path}</title>
  <style>
    body {{ font-family: system-ui, sans-serif; max-width: 700px;
            margin: 2rem auto; padding: 0 1rem; }}
    li   {{ line-height: 1.8; }}
  </style>
</head>
<body>
  <h2>Index of {url_path}</h2>
  <ul>
{items}  </ul>
</body>
</html>
"#
    )
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
