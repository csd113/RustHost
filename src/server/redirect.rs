//! # HTTP → HTTPS Redirect Server
//!
//! **File:** `redirect.rs`
//! **Location:** `src/server/redirect.rs`
//!
//! A lightweight HTTP/1.1 listener that issues permanent `301` redirects to
//! the HTTPS equivalent of every incoming request.  Activated when
//! `[tls] redirect_http = true` in `settings.toml`.
//!
//! This server intentionally does **no** file serving.  Its only job is to
//! send a one-line redirect and close the connection.  The implementation is
//! bare `tokio::net` + manual HTTP/1.1 to keep the binary impact minimal —
//! it never allocates a hyper connection or reads the full request body.

use std::{
    net::IpAddr,
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc,
    },
    time::Duration,
};

use dashmap::DashMap;
use tokio::{
    io::AsyncWriteExt as _,
    net::TcpListener,
    sync::{oneshot, watch, Semaphore},
    task::JoinSet,
};

const MAX_HEADER_BYTES: usize = 8 * 1024;
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(5);

pub struct RedirectServerConfig {
    pub bind_addr: IpAddr,
    pub plain_port: u16,
    pub tls_port: u16,
    pub max_per_ip: u32,
    pub drain_timeout: Duration,
}

struct PerIpGuard {
    counter: Arc<AtomicU32>,
    map: Arc<DashMap<IpAddr, Arc<AtomicU32>>>,
    addr: IpAddr,
}

impl Drop for PerIpGuard {
    fn drop(&mut self) {
        let previous = self.counter.fetch_sub(1, Ordering::Relaxed);
        if previous == 1 {
            self.map.remove(&self.addr);
        }
    }
}

fn try_acquire_per_ip(
    map: &Arc<DashMap<IpAddr, Arc<AtomicU32>>>,
    addr: IpAddr,
    limit: u32,
) -> std::result::Result<PerIpGuard, ()> {
    let counter = Arc::clone(
        map.entry(addr)
            .or_insert_with(|| Arc::new(AtomicU32::new(0)))
            .value(),
    );
    let mut current = counter.load(Ordering::Relaxed);
    loop {
        if current >= limit {
            return Err(());
        }
        match counter.compare_exchange_weak(
            current,
            current.saturating_add(1),
            Ordering::AcqRel,
            Ordering::Relaxed,
        ) {
            Ok(_) => {
                return Ok(PerIpGuard {
                    counter,
                    map: Arc::clone(map),
                    addr,
                });
            }
            Err(updated) => current = updated,
        }
    }
}

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
    config: RedirectServerConfig,
    mut shutdown: watch::Receiver<bool>,
    port_tx: oneshot::Sender<u16>,
    semaphore: Arc<Semaphore>,
    per_ip_map: Arc<DashMap<IpAddr, Arc<AtomicU32>>>,
) {
    let RedirectServerConfig {
        bind_addr,
        plain_port,
        tls_port,
        max_per_ip,
        drain_timeout,
    } = config;
    let bind_socket = std::net::SocketAddr::new(bind_addr, plain_port);
    let listener = match TcpListener::bind(bind_socket).await {
        Ok(l) => l,
        Err(e) => {
            log::error!("HTTP-redirect server failed to bind {bind_addr}:{plain_port}: {e}");
            return;
        }
    };
    let _ = port_tx.send(plain_port);
    log::info!(
        "HTTP-redirect server listening on {bind_addr}:{plain_port} \
         → HTTPS port {tls_port}"
    );
    let mut join_set: JoinSet<()> = JoinSet::new();

    loop {
        tokio::select! {
            result = listener.accept() => {
                match result {
                    Ok((mut stream, peer)) => {
                        log::debug!("Redirect connection from {peer}");
                        let peer_ip = peer.ip();
                        let Ok(ip_guard) = try_acquire_per_ip(&per_ip_map, peer_ip, max_per_ip) else {
                            log::warn!(
                                "Per-IP limit ({max_per_ip}) reached for {peer_ip}; dropping redirect connection"
                            );
                            drop(stream);
                            continue;
                        };
                        let Ok(permit) = Arc::clone(&semaphore).try_acquire_owned() else {
                            log::warn!(
                                "Connection limit reached; rejecting redirect connection from {peer_ip}"
                            );
                            drop(stream);
                            continue;
                        };
                        join_set.spawn(async move {
                            let _permit = permit;
                            let _ip_guard = ip_guard;
                            handle_redirect(&mut stream, bind_addr, tls_port).await;
                        });
                    }
                    Err(e) => {
                        log::debug!("Redirect accept error: {e}");
                    }
                }
            }
            Some(result) = join_set.join_next(), if !join_set.is_empty() => {
                if let Err(e) = result {
                    log::debug!("Redirect connection task join error: {e}");
                }
            }
            _ = shutdown.changed() => {
                if *shutdown.borrow() { break; }
            }
        }
    }

    let drain = async { while join_set.join_next().await.is_some() {} };
    let _ = tokio::time::timeout(drain_timeout, drain).await;
    log::info!("HTTP-redirect server stopped.");
}

/// Read the `Host` header and request path from `stream`, then emit a `301`.
///
/// The function is best-effort: if the client sends a malformed request or
/// the write fails we simply drop the connection — there is no retry.
async fn handle_redirect(stream: &mut tokio::net::TcpStream, bind_addr: IpAddr, https_port: u16) {
    use tokio::io::AsyncBufReadExt as _;
    use tokio::io::BufReader;

    let mut path = String::from("/");
    let mut host: Option<String> = None;

    let read_result = tokio::time::timeout(HEADER_READ_TIMEOUT, async {
        // Scope the BufReader so the &mut borrow of stream is released before
        // the write below. Rust's borrow checker requires this.
        let mut reader = BufReader::new(&mut *stream);
        let mut total = 0usize;

        let mut request_line = String::new();
        match reader.read_line(&mut request_line).await {
            Ok(n) if n > 0 => {
                total = total.saturating_add(n);
                if total > MAX_HEADER_BYTES {
                    return None;
                }
                let mut parts = request_line.split_whitespace();
                let _ = parts.next();
                if let Some(p) = parts.next() {
                    path = sanitize_path(p);
                }
            }
            _ => return None,
        }

        loop {
            let mut line = String::new();
            match reader.read_line(&mut line).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    total = total.saturating_add(n);
                    if total > MAX_HEADER_BYTES {
                        return None;
                    }
                    let trimmed = line.trim();
                    if trimmed.is_empty() {
                        break;
                    }
                    if let Some((name, value)) = trimmed.split_once(':') {
                        if name.eq_ignore_ascii_case("host") {
                            host = sanitize_host_header(value);
                        }
                    }
                }
            }
        }

        Some(())
    })
    .await;

    if !matches!(read_result, Ok(Some(()))) {
        return;
    }

    // Build the target URL.
    let host = host.unwrap_or_else(|| redirect_host_for(bind_addr));
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

fn sanitize_host_header(raw: &str) -> Option<String> {
    let host = raw.trim();
    if host.is_empty()
        || !host.is_ascii()
        || host
            .chars()
            .any(|c| c.is_ascii_control() || matches!(c, '/' | '\\' | '@'))
    {
        return None;
    }

    if host.starts_with('[') {
        let end = host.find(']')?;
        let core = &host[..=end];
        let remainder = &host[end.saturating_add(1)..];
        if !(remainder.is_empty()
            || remainder.starts_with(':')
                && remainder.get(1..).is_some_and(|port| {
                    !port.is_empty() && port.chars().all(|c| c.is_ascii_digit())
                }))
        {
            return None;
        }
        return Some(core.to_owned());
    }

    let name = match host.rsplit_once(':') {
        Some((candidate, port))
            if !candidate.contains(':')
                && !port.is_empty()
                && port.chars().all(|c| c.is_ascii_digit()) =>
        {
            candidate
        }
        _ => host,
    };

    if name.is_empty()
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-'))
    {
        return None;
    }

    Some(name.to_owned())
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::{redirect_host_for, sanitize_host_header, sanitize_path};

    #[test]
    fn redirect_host_for_unspecified_ipv4_uses_loopback() {
        assert_eq!(
            redirect_host_for(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)),
            "127.0.0.1"
        );
    }

    #[test]
    fn redirect_host_for_ipv6_is_bracketed() {
        assert_eq!(
            redirect_host_for(IpAddr::V6(std::net::Ipv6Addr::new(
                0x2001, 0x0db8, 0, 0, 0, 0, 0, 1
            ))),
            "[2001:db8::1]"
        );
    }

    #[test]
    fn sanitize_path_removes_control_chars_and_spaces() {
        assert_eq!(sanitize_path("/foo bar\r\nbaz"), "/foobarbaz");
    }

    #[test]
    fn sanitize_host_header_strips_default_port() {
        assert_eq!(
            sanitize_host_header("example.com:80"),
            Some("example.com".to_owned())
        );
    }

    #[test]
    fn sanitize_host_header_rejects_path_injection() {
        assert_eq!(sanitize_host_header("example.com/path"), None);
    }
}
