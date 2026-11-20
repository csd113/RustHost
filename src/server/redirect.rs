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
    net::{IpAddr, SocketAddr},
    sync::{atomic::AtomicU32, Arc},
    time::Duration,
};

use super::{
    admission::{admit_connection, AdmissionRejection},
    listeners::{accept_connections, bind_failed, finish_listener, BindResult, ConnectionBudget},
};
use dashmap::DashMap;
use tokio::{
    io::AsyncWriteExt as _,
    net::TcpListener,
    sync::{oneshot, watch, Semaphore},
    task::JoinSet,
};

use crate::runtime::{
    shutdown::{deadline, ServiceOutcome, Shutdown},
    state::{ListenerRole, ListenerStatus, SharedState},
};

const MAX_HEADER_BYTES: usize = 16 * 1024;
const HEADER_READ_LIMIT: u64 = 16 * 1024 + 1;
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
    Ready { path: String, host: HostHeader },
    HeaderTooLarge,
    Malformed,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum HostHeader {
    Missing,
    Valid(String),
    Invalid,
}

/// Bind a plain-HTTP listener on `bind_addr:http_port` and redirect every
/// request to `https://<host>:<https_port><original-path>`.
///
/// Accepts a `shutdown` watch so it stops alongside the rest of the server.
/// A bind failure is sent back through the acknowledgement channel.
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
    state: SharedState,
    shutdown: watch::Receiver<bool>,
    port_tx: oneshot::Sender<std::result::Result<u16, String>>,
    semaphore: Arc<Semaphore>,
    per_ip_map: Arc<DashMap<IpAddr, Arc<AtomicU32>>>,
) {
    let outcome = serve_redirect(
        config,
        state,
        Shutdown::from_receiver(shutdown),
        ConnectionBudget {
            semaphore,
            per_ip_map,
        },
        move |result| {
            let _ = port_tx.send(result.map(|addr| addr.port()));
        },
    )
    .await;
    if let ServiceOutcome::Failed(message) = outcome {
        log::error!("{message}");
    }
}

pub(crate) async fn serve_redirect(
    config: RedirectServerConfig,
    state: SharedState,
    mut shutdown: Shutdown,
    budget: ConnectionBudget,
    ready: impl FnOnce(BindResult),
) -> ServiceOutcome {
    let role = ListenerRole::Redirect;
    state
        .write()
        .await
        .set_listener(role, ListenerStatus::Starting);
    let socket = SocketAddr::new(config.bind_addr, config.plain_port);
    let bound = match TcpListener::bind(socket).await {
        Ok(listener) => listener.local_addr().map(|address| (listener, address)),
        Err(error) => Err(error),
    };
    let (listener, address) = match bound {
        Ok(bound) => bound,
        Err(source) => {
            let message = crate::AppError::ServerBind {
                listener: "HTTP redirect listener",
                addr: socket,
                source,
            }
            .to_string();
            return bind_failed(role, &state, ready, message).await;
        }
    };
    state
        .write()
        .await
        .set_listener(role, ListenerStatus::Listening(address));
    ready(Ok(address));
    log::info!(
        "HTTP redirect listener listening on {address} → HTTPS port {}",
        config.tls_port
    );
    let mut tasks = JoinSet::new();
    let allowed_hosts: Arc<[String]> = config.allowed_hosts.into();
    let result = accept_connections(&listener, role, &mut tasks, &mut shutdown, |mut stream, peer, tasks| {
        let peer_ip = peer.ip();
        let admission = match admit_connection(
            &budget.semaphore, &budget.per_ip_map, peer_ip, Some(config.max_per_ip),
        ) {
            Ok(admission) => admission,
            Err(AdmissionRejection::PerIpLimit { limit }) => {
                log::warn!("Per-IP limit ({limit}) reached for {peer_ip}; dropping redirect connection");
                return;
            }
            Err(AdmissionRejection::GlobalLimit) => {
                log::warn!("Connection limit reached; rejecting redirect connection from {peer_ip}");
                return;
            }
        };
        let allowed_hosts = Arc::clone(&allowed_hosts);
        let bind_addr = config.bind_addr;
        let tls_port = config.tls_port;
        tasks.spawn(async move {
            let _admission = admission;
            handle_redirect_connection(&mut stream, peer_ip, bind_addr, tls_port, &allowed_hosts).await;
        });
    }).await;
    drop(listener);
    match result {
        Ok(started) => {
            finish_listener(
                role,
                &state,
                &mut tasks,
                deadline(started, config.drain_timeout),
            )
            .await
        }
        Err(error) => {
            let message = format!("HTTP redirect accept failed: {error}");
            state
                .write()
                .await
                .set_listener(role, ListenerStatus::Failed(message.clone()));
            ServiceOutcome::Failed(message)
        }
    }
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
    use tokio::io::BufReader;
    use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _};

    let read_result = tokio::time::timeout(HEADER_READ_TIMEOUT, async {
        // Scope the BufReader so the &mut borrow of stream is released before
        // the write below. Rust's borrow checker requires this.
        // Bound the underlying read before read_line can grow its String.
        let mut reader = BufReader::new((&mut *stream).take(HEADER_READ_LIMIT));
        let mut total = 0usize;
        let mut host = HostHeader::Missing;

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
                Ok(0) | Err(_) => return ReadOutcome::Malformed,
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
                            host = match (&host, parse_host_header(value)) {
                                (HostHeader::Missing, Ok(parsed)) => HostHeader::Valid(parsed),
                                _ => HostHeader::Invalid,
                            };
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

fn parse_host_header(raw: &str) -> Result<String, ()> {
    let host = raw.trim();
    if host.is_empty()
        || !host.is_ascii()
        || host
            .chars()
            .any(|c| c.is_ascii_control() || matches!(c, '/' | '\\' | '@'))
    {
        return Err(());
    }

    if host.starts_with('[') {
        let end = host.find(']').ok_or(())?;
        let core = &host[1..end];
        let remainder = &host[end.saturating_add(1)..];
        if !remainder.is_empty() {
            let Some(port) = remainder.strip_prefix(':') else {
                return Err(());
            };
            parse_host_port(port)?;
        }
        let ip = core.parse::<std::net::Ipv6Addr>().map_err(|_error| ())?;
        return Ok(format!("[{ip}]"));
    }

    let name = match host.rsplit_once(':') {
        Some((candidate, port)) if !candidate.contains(':') => {
            parse_host_port(port)?;
            candidate
        }
        _ => host,
    };

    if name.is_empty()
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-'))
    {
        return Err(());
    }

    if let Ok(ip) = name.parse::<std::net::Ipv4Addr>() {
        return Ok(ip.to_string());
    }

    Ok(name.trim_end_matches('.').to_ascii_lowercase())
}

fn parse_host_port(raw: &str) -> Result<u16, ()> {
    if raw.is_empty() || !raw.chars().all(|c| c.is_ascii_digit()) {
        return Err(());
    }
    let port = raw.parse::<u16>().map_err(|_error| ())?;
    if port == 0 {
        return Err(());
    }
    Ok(port)
}

fn validated_redirect_host(
    host: HostHeader,
    bind_addr: IpAddr,
    allowed_hosts: &[String],
) -> Result<String, ()> {
    let candidate = match host {
        HostHeader::Missing => redirect_host_for(bind_addr),
        HostHeader::Valid(host) => host,
        HostHeader::Invalid => return Err(()),
    };
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

    tokio::time::timeout(
        Duration::from_secs(10),
        stream.write_all(response.as_bytes()),
    )
    .await
    .map_err(|e| std::io::Error::new(std::io::ErrorKind::TimedOut, e))??;
    stream.flush().await
}
