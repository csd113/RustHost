//! # HTTP → HTTPS Redirect Server
//!
//! **Directory:** `src/server/`
//!
//! A lightweight HTTP/1.1 listener that issues permanent `301` redirects to
//! the HTTPS equivalent of every incoming request.  Activated when
//! `[tls] redirect_http = true` in `settings.toml`.
//!
//! This server intentionally does **no** file serving.  Its only job is to
//! send a one-line redirect and close the connection.  The implementation is
//! bare `tokio::net` + manual HTTP/1.1 to keep the binary impact minimal —
//! it never allocates a hyper connection or reads the full request body.

use std::net::IpAddr;

use tokio::{io::AsyncWriteExt as _, net::TcpListener, sync::watch};

/// Bind a plain-HTTP listener on `bind_addr:http_port` and redirect every
/// request to `https://<host>:<https_port><original-path>`.
///
/// Accepts a `shutdown` watch so it stops alongside the rest of the server.
/// Bind failures are logged and the function returns early — the main HTTPS
/// server continues regardless.
///
/// # Why manual HTTP/1.1?
///
/// A full hyper connection is overkill for a pure-redirect server.  We only
/// need to:
/// 1. Read the first line of the request (to extract the path).
/// 2. Send a `301 Moved Permanently` response with a `Location` header.
/// 3. Close the socket.
///
/// This avoids pulling the request body, keep-alive handling, or any response
/// body into what is effectively a TCP-level redirect pump.
pub async fn run_redirect_server(
    bind_addr: IpAddr,
    plain_port: u16,
    tls_port: u16,
    mut shutdown: watch::Receiver<bool>,
) {
    let listener = match TcpListener::bind(format!("{bind_addr}:{plain_port}")).await {
        Ok(l) => l,
        Err(e) => {
            log::error!("HTTP-redirect server failed to bind {bind_addr}:{plain_port}: {e}");
            return;
        }
    };
    log::info!(
        "HTTP-redirect server listening on {bind_addr}:{plain_port} \
         → HTTPS port {tls_port}"
    );

    loop {
        tokio::select! {
            result = listener.accept() => {
                match result {
                    Ok((mut stream, peer)) => {
                        log::debug!("Redirect connection from {peer}");
                        tokio::spawn(async move {
                            handle_redirect(&mut stream, bind_addr, tls_port).await;
                        });
                    }
                    Err(e) => {
                        log::debug!("Redirect accept error: {e}");
                    }
                }
            }
            _ = shutdown.changed() => {
                if *shutdown.borrow() { break; }
            }
        }
    }

    log::info!("HTTP-redirect server stopped.");
}

/// Read the `Host` header and request path from `stream`, then emit a `301`.
///
/// The function is best-effort: if the client sends a malformed request or
/// the write fails we simply drop the connection — there is no retry.
async fn handle_redirect(stream: &mut tokio::net::TcpStream, bind_addr: IpAddr, https_port: u16) {
    use tokio::io::AsyncBufReadExt as _;
    use tokio::io::BufReader;

    // Cap at 8 KiB total to defend against slow-loris-style connections.
    const MAX_HEADER_BYTES: usize = 8 * 1024;

    let mut path = String::from("/");

    // Scope the BufReader so the &mut borrow of stream is released before
    // the write below.  Rust's borrow checker requires this.
    {
        let mut reader = BufReader::new(&mut *stream);
        let mut total = 0usize;

        // --- request line ---------------------------------------------------
        let mut request_line = String::new();
        match reader.read_line(&mut request_line).await {
            Ok(n) if n > 0 => {
                total = total.saturating_add(n);
                let mut parts = request_line.split_whitespace();
                let _ = parts.next(); // method
                if let Some(p) = parts.next() {
                    path = sanitize_path(p);
                }
            }
            _ => return,
        }

        // --- headers (drain to the end of the request) ----------------------
        loop {
            let mut line = String::new();
            match reader.read_line(&mut line).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    total = total.saturating_add(n);
                    if total > MAX_HEADER_BYTES {
                        return; // too large — drop
                    }
                    let trimmed = line.trim();
                    if trimmed.is_empty() {
                        break; // end of headers
                    }
                }
            }
        }
    } // reader dropped here — &mut borrow of stream released

    // Build the target URL.
    let host = redirect_host_for(bind_addr);
    let location = if https_port == 443 {
        format!("https://{host}{path}")
    } else {
        format!("https://{host}:{https_port}{path}")
    };

    let response = format!(
        "HTTP/1.1 301 Moved Permanently\r\n\
         Location: {location}\r\n\
         Content-Length: 0\r\n\
         Connection: close\r\n\
         \r\n"
    );

    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.flush().await;
}

fn redirect_host_for(bind_addr: IpAddr) -> String {
    match bind_addr {
        IpAddr::V4(addr) if addr.is_unspecified() => "127.0.0.1".to_owned(),
        IpAddr::V4(addr) => addr.to_string(),
        IpAddr::V6(addr) if addr.is_unspecified() => "[::1]".to_owned(),
        IpAddr::V6(addr) => format!("[{addr}]"),
    }
}

/// Keep only the path+query portion of a request target.
///
/// Rejects `*` and `http://…` absolute forms — a well-behaved client behind
/// a redirect server should only send origin-form requests.
fn sanitize_path(raw: &str) -> String {
    // Only accept origin-form: starts with '/'.  Anything else becomes "/".
    if raw.starts_with('/') {
        // Reject characters that would break the `Location` header.
        raw.chars()
            .filter(|c| !matches!(c, '\r' | '\n' | ' '))
            .collect()
    } else {
        "/".into()
    }
}

#[cfg(test)]
mod tests {
    use super::{redirect_host_for, sanitize_path};

    #[test]
    fn redirect_host_for_unspecified_ipv4_uses_loopback() {
        assert_eq!(
            redirect_host_for("0.0.0.0".parse().expect("valid ip")),
            "127.0.0.1"
        );
    }

    #[test]
    fn redirect_host_for_ipv6_is_bracketed() {
        assert_eq!(
            redirect_host_for("2001:db8::1".parse().expect("valid ip")),
            "[2001:db8::1]"
        );
    }

    #[test]
    fn sanitize_path_removes_control_chars_and_spaces() {
        assert_eq!(sanitize_path("/foo bar\r\nbaz"), "/foobarbaz");
    }
}
