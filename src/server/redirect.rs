//! # HTTP → HTTPS Redirect Server
//! A lightweight HTTP/1.1 listener that issues permanent `301` redirects to
//! the HTTPS equivalent of every incoming request.  Activated when
//! `[tls] redirect_http = true` in `settings.toml`.
//!
//! This server intentionally does **no** file serving.  Its only job is to
//! send a one-line redirect and close the connection.  The implementation is
//! bare `tokio::net` + manual HTTP/1.1 to keep the binary impact minimal —
//! it never allocates a hyper connection or reads the full request body.

use std::{
    fmt::Write as _,
    net::IpAddr,
    sync::{atomic::AtomicU32, Arc},
    time::Duration,
};

use super::admission::{admit_connection, AdmissionRejection};
use dashmap::DashMap;
use tokio::{
    io::AsyncWriteExt as _,
    net::TcpListener,
    sync::{oneshot, watch, Semaphore},
    task::JoinSet,
};

use crate::runtime::state::SharedState;

const MAX_HEADER_BYTES: usize = 16 * 1024;
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(5);

pub struct RedirectServerConfig {
    pub bind_addr: IpAddr,
    pub plain_port: u16,
    pub tls_port: u16,
    pub allowed_hosts: Vec<String>,
    pub max_per_ip: u32,
    pub drain_timeout: Duration,
}

enum ReadOutcome {
    Ready { path: String, host: Option<String> },
    HeaderTooLarge,
    Malformed,
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
#[expect(
    clippy::too_many_lines,
    reason = "Redirect listener keeps bind, admission, and shutdown wiring together."
)]
pub async fn run_redirect_server(
    config: RedirectServerConfig,
    state: SharedState,
    mut shutdown: watch::Receiver<bool>,
    port_tx: oneshot::Sender<std::result::Result<u16, String>>,
    semaphore: Arc<Semaphore>,
    per_ip_map: Arc<DashMap<IpAddr, Arc<AtomicU32>>>,
) {
    let RedirectServerConfig {
        bind_addr,
        plain_port,
        tls_port,
        allowed_hosts,
        max_per_ip,
        drain_timeout,
    } = config;
    let allowed_hosts = Arc::new(allowed_hosts);
    let bind_socket = std::net::SocketAddr::new(bind_addr, plain_port);
    let listener = match TcpListener::bind(bind_socket).await {
        Ok(l) => l,
        Err(e) => {
            let message = crate::AppError::ServerBind {
                listener: "HTTP redirect listener",
                addr: bind_socket,
                source: e,
            }
            .to_string();
            log::error!("{message}");
            let _ = port_tx.send(Err(message));
            return;
        }
    };
    let _ = port_tx.send(Ok(plain_port));
    {
        let mut s = state.write().await;
        s.actual_port = plain_port;
        s.server_running = true;
    }
    log::info!(
        "HTTP-redirect server listening on {bind_addr}:{plain_port} \
         → HTTPS port {tls_port}"
    );
    let mut join_set: JoinSet<()> = JoinSet::new();
    let mut backoff_ms: u64 = 1;

    loop {
        tokio::select! {
            result = listener.accept() => {
                match result {
                    Ok((mut stream, peer)) => {
                        backoff_ms = 1;
                        log::debug!("Redirect connection from {peer}");
                        let peer_ip = peer.ip();
                        let admission = match admit_connection(
                            &semaphore,
                            &per_ip_map,
                            peer_ip,
                            Some(max_per_ip),
                        ) {
                            Ok(admission) => admission,
                            Err(AdmissionRejection::PerIpLimit { limit }) => {
                                log::warn!(
                                    "Per-IP limit ({limit}) reached for {peer_ip}; dropping redirect connection"
                                );
                                drop(stream);
                                continue;
                            }
                            Err(AdmissionRejection::GlobalLimit) => {
                                log::warn!(
                                    "Connection limit reached; rejecting redirect connection from {peer_ip}"
                                );
                                drop(stream);
                                continue;
                            }
                        };
                        let allowed_hosts = Arc::clone(&allowed_hosts);
                        join_set.spawn(async move {
                            let _admission = admission;
                            handle_redirect_connection(
                                &mut stream,
                                peer_ip,
                                bind_addr,
                                tls_port,
                                allowed_hosts.as_slice(),
                            )
                            .await;
                        });
                    }
                    Err(e) => {
                        log::debug!("Redirect accept error: {e}");
                        tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                        backoff_ms = backoff_ms.saturating_mul(2).min(1_000);
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
    state.write().await.server_running = false;
    log::info!("HTTP-redirect server stopped.");
}

/// Read the `Host` header and request path from `stream`, then emit a `301`.
///
/// The function is best-effort: if the client sends a malformed request or
/// the write fails we simply drop the connection — there is no retry.
async fn handle_redirect_connection(
    stream: &mut tokio::net::TcpStream,
    peer_ip: IpAddr,
    bind_addr: IpAddr,
    https_port: u16,
    allowed_hosts: &[String],
) {
    use tokio::io::AsyncBufReadExt as _;
    use tokio::io::BufReader;

    let read_result = tokio::time::timeout(HEADER_READ_TIMEOUT, async {
        // Scope the BufReader so the &mut borrow of stream is released before
        // the write below. Rust's borrow checker requires this.
        let mut reader = BufReader::new(&mut *stream);
        let mut total = 0usize;
        let mut host: Option<String> = None;

        let mut request_line = String::new();
        match reader.read_line(&mut request_line).await {
            Ok(n) if n > 0 => {
                total = total.saturating_add(n);
                if total > MAX_HEADER_BYTES {
                    return ReadOutcome::HeaderTooLarge;
                }
                if request_line.split_whitespace().nth(1).is_none() {
                    return ReadOutcome::Malformed;
                }
            }
            _ => return ReadOutcome::Malformed,
        }

        let path = request_line
            .split_whitespace()
            .nth(1)
            .map_or_else(|| "/".to_owned(), sanitize_path);

        loop {
            let mut line = String::new();
            match reader.read_line(&mut line).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    total = total.saturating_add(n);
                    if total > MAX_HEADER_BYTES {
                        return ReadOutcome::HeaderTooLarge;
                    }
                    let trimmed = line.trim();
                    if trimmed.is_empty() {
                        break;
                    }
                    if let Some((name, value)) = trimmed.split_once(':') {
                        if name.eq_ignore_ascii_case("host") {
                            host = parse_host_header(value);
                        }
                    }
                }
            }
        }

        ReadOutcome::Ready { path, host }
    })
    .await;

    let (path, host) = match read_result {
        Ok(ReadOutcome::Ready { path, host }) => (path, host),
        Ok(ReadOutcome::HeaderTooLarge) => {
            log::warn!(
                "Rejected redirect request with oversized headers from {peer_ip} \
                 (limit: {MAX_HEADER_BYTES} bytes)"
            );
            let _ =
                write_status_response(stream, 431, "Request Header Fields Too Large", None).await;
            return;
        }
        Ok(ReadOutcome::Malformed) | Err(_) => return,
    };

    let Ok(host) = validated_redirect_host(host, bind_addr, allowed_hosts) else {
        log::warn!("Rejected redirect request with invalid Host header from {peer_ip}");
        let _ = write_status_response(stream, 400, "Bad Request", None).await;
        return;
    };

    let location = if https_port == 443 {
        format!("https://{host}{path}")
    } else {
        format!("https://{host}:{https_port}{path}")
    };

    let _ = write_status_response(stream, 301, "Moved Permanently", Some(&location)).await;
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

fn parse_host_header(raw: &str) -> Option<String> {
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
        let core = &host[1..end];
        let remainder = &host[end.saturating_add(1)..];
        if !(remainder.is_empty()
            || remainder.starts_with(':')
                && remainder.get(1..).is_some_and(|port| {
                    !port.is_empty() && port.chars().all(|c| c.is_ascii_digit())
                }))
        {
            return None;
        }
        let ip = core.parse::<std::net::Ipv6Addr>().ok()?;
        return Some(format!("[{ip}]"));
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

    if let Ok(ip) = name.parse::<std::net::Ipv4Addr>() {
        return Some(ip.to_string());
    }

    Some(name.trim_end_matches('.').to_ascii_lowercase())
}

fn validated_redirect_host(
    host: Option<String>,
    bind_addr: IpAddr,
    allowed_hosts: &[String],
) -> Result<String, ()> {
    let candidate = host.unwrap_or_else(|| redirect_host_for(bind_addr));
    if allowed_hosts.iter().any(|allowed| allowed == &candidate) {
        Ok(candidate)
    } else {
        Err(())
    }
}

async fn write_status_response(
    stream: &mut tokio::net::TcpStream,
    status: u16,
    reason: &str,
    location: Option<&str>,
) -> std::io::Result<()> {
    let mut response = format!(
        "HTTP/1.1 {status} {reason}\r\n\
         Content-Length: 0\r\n\
         Connection: close\r\n"
    );
    if let Some(location) = location {
        let _ = write!(response, "Location: {location}\r\n");
    }
    response.push_str("\r\n");

    stream.write_all(response.as_bytes()).await?;
    stream.flush().await
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::{parse_host_header, redirect_host_for, sanitize_path, validated_redirect_host};

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
            parse_host_header("example.com:80"),
            Some("example.com".to_owned())
        );
    }

    #[test]
    fn sanitize_host_header_rejects_path_injection() {
        assert_eq!(parse_host_header("example.com/path"), None);
    }

    #[test]
    fn sanitize_host_header_rejects_userinfo() {
        assert_eq!(parse_host_header("evil.com@legit.com"), None);
    }

    #[test]
    fn validated_redirect_host_allows_configured_domain() {
        let allowed = vec!["example.com".to_owned()];
        assert_eq!(
            validated_redirect_host(
                Some("example.com".into()),
                IpAddr::from([127, 0, 0, 1]),
                &allowed
            ),
            Ok("example.com".into())
        );
    }

    #[test]
    fn validated_redirect_host_rejects_unknown_domain() {
        let allowed = vec!["localhost".to_owned()];
        assert_eq!(
            validated_redirect_host(
                Some("attacker.example".into()),
                IpAddr::from([127, 0, 0, 1]),
                &allowed
            ),
            Err(())
        );
    }
}
