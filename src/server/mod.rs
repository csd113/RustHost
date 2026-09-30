//! # Server Module
//! Provides a safe HTTP/1.1 static-file server. The implementation migrated
//! per-connection handler from a hand-rolled single-shot parser to
//! [`hyper`]'s keep-alive connection loop, eliminating the large Tor
//! page-load penalty caused by `Connection: close` on every response.
//!
//! Sub-modules:
//! - [`handler`] — per-connection request handling and file serving
//! - [`mime`] — file-extension → MIME type mapping
//! - [`fallback`] — built-in "No site found" page
mod admission;
mod site;
pub use site::SiteSnapshot;
pub mod fallback;
pub mod handler;
pub mod mime;
pub mod redirect;
use crate::{
    config::Config,
    runtime::state::{SharedMetrics, SharedState},
    tls::Acceptor,
    AppError, Result,
};
use admission::{admit_connection, AdmissionRejection};
use dashmap::DashMap;
use std::{
    net::{IpAddr, TcpListener as StdTcpListener},
    path::{Path, PathBuf},
    sync::{atomic::AtomicU32, Arc},
    time::Duration,
};
use tokio::{
    net::TcpListener,
    sync::{oneshot, watch, Semaphore},
    task::JoinSet,
};

// ─── Server context ───────────────────────────────────────────────────────────
/// Shared references prepared once before the accept loop starts.
///
/// Extracting these into a struct keeps [`run`] under the 100-line limit
/// imposed by `clippy::nursery::too_many_lines` while grouping the values
/// that every spawned handler task needs.
#[expect(
    clippy::struct_excessive_bools,
    reason = "Listener state groups related booleans used by every connection handler."
)]
struct ServerContext {
    site_watch: watch::Receiver<Arc<SiteSnapshot>>,
    data_dir: Arc<Path>,
    log_dir: Arc<Path>,
    index_file: Arc<str>,
    csp_header: Arc<str>,
    state: SharedState,
    keep_alive: bool,
    dir_list: bool,
    expose_dots: bool,
    spa_routing: bool,
    redirects: Arc<Vec<crate::config::RedirectRule>>,
    semaphore: Arc<Semaphore>,
    per_ip_map: Arc<DashMap<IpAddr, Arc<AtomicU32>>>,
    max_conns: usize,
    max_per_ip: Option<u32>,
    /// IPs whose X-Forwarded-For header is trusted.
    /// Defaults to empty (XFF ignored) for direct-edge deployments.
    trusted_proxies: Arc<Vec<IpAddr>>,
    ingress: handler::RequestIngress,
}

#[derive(Clone, Copy)]
struct ListenerOptions {
    max_per_ip: Option<u32>,
    keep_alive: bool,
    ingress: handler::RequestIngress,
}

impl ServerContext {
    /// Variant used when the HTTP and HTTPS listeners must share the same
    /// connection-budget arcs. Both servers draw from the same semaphore and
    /// per-IP counter map so the combined connection limit is enforced globally
    /// rather than per-protocol — a client cannot double its effective quota by
    /// opening connections on both ports simultaneously.
    fn with_shared(
        config: &Config,
        state: SharedState,
        data_dir: &Path,
        semaphore: Arc<Semaphore>,
        per_ip_map: Arc<DashMap<IpAddr, Arc<AtomicU32>>>,
        options: ListenerOptions,
        site_watch: watch::Receiver<Arc<SiteSnapshot>>,
    ) -> Self {
        let max_conns = config.server.max_connections as usize;
        let log_path = data_dir.join(&config.logging.file);
        let log_dir = log_path
            .parent()
            .map_or_else(|| data_dir.to_path_buf(), Path::to_path_buf);
        Self {
            site_watch,
            data_dir: Arc::from(data_dir),
            log_dir: Arc::from(log_dir.as_path()),
            index_file: Arc::from(config.site.index_file.as_str()),
            csp_header: Arc::from(config.server.csp_level.as_header_value()),
            state,
            keep_alive: options.keep_alive,
            dir_list: config.site.enable_directory_listing,
            expose_dots: config.site.expose_dotfiles,
            spa_routing: config.site.spa_routing,
            redirects: Arc::new(config.redirects.clone()),
            semaphore,
            per_ip_map,
            max_conns,
            max_per_ip: options.max_per_ip,
            // When empty, X-Forwarded-For is ignored on every connection.
            trusted_proxies: Arc::new(config.server.trusted_proxies.clone().unwrap_or_default()),
            ingress: options.ingress,
        }
    }
    /// Attempt to spawn a handler task for one accepted connection.
    ///
    /// Returns `false` when the global semaphore has been closed (shutdown),
    /// `true` in all other cases (connection accepted, rejected, or dropped).
    fn spawn_connection(
        &self,
        stream: tokio::net::TcpStream,
        peer: std::net::SocketAddr,
        metrics: &SharedMetrics,
        join_set: &mut JoinSet<()>,
    ) -> bool {
        let peer_ip = peer.ip();
        let admission =
            match admit_connection(&self.semaphore, &self.per_ip_map, peer_ip, self.max_per_ip) {
                Ok(admission) => admission,
                Err(AdmissionRejection::PerIpLimit { limit }) => {
                    log::warn!("Per-IP limit ({limit}) reached for {peer_ip}; dropping connection");
                    drop(stream);
                    return true;
                }
                Err(AdmissionRejection::GlobalLimit) => {
                    log::warn!(
                        "Connection limit ({}) reached; dropping connection from {peer_ip}",
                        self.max_conns
                    );
                    drop(stream);
                    return true;
                }
            };
        let idx = Arc::clone(&self.index_file);
        let met = Arc::clone(metrics);
        let handler_config = handler::HandlerConfig {
            peer_addr: peer,
            site_watch: self.site_watch.clone(),
            index_file: idx,
            flags: handler::FeatureFlags {
                dir_listing: self.dir_list,
                expose_dotfiles: self.expose_dots,
                spa_routing: self.spa_routing,
                is_https: false,
                keep_alive: self.keep_alive,
            },
            state: Arc::clone(&self.state),
            readiness: handler::ReadinessConfig {
                data_dir: Arc::clone(&self.data_dir),
                log_dir: Arc::clone(&self.log_dir),
            },
            csp: Arc::clone(&self.csp_header),
            redirects: Arc::clone(&self.redirects),
            trusted_proxies: Arc::clone(&self.trusted_proxies),
            ingress: self.ingress,
        };
        join_set.spawn(async move {
            let _admission = admission;
            if let Err(e) = handler::handle(stream, handler_config, met).await {
                log::debug!("Handler error: {e}");
            }
        });
        true
    }
}
// ─── Public API ──────────────────────────────────────────────────────────────
/// Start the HTTP server.
///
/// Binds the port (with optional fallback), updates `SharedState.actual_port`,
/// sends the bound port through `port_tx` so Tor can start without a sleep,
/// then accepts connections until the shutdown watch fires.
///
/// ## Accept-loop observability
///
/// Accept errors use exponential backoff (1 ms → 1 s) to prevent log storms
/// under persistent failures such as `EMFILE`. Error severity is split:
///
/// - **`EMFILE` / `ENFILE`** (file-descriptor exhaustion) → logged at `error`;
///   these require operator intervention.
/// - **Transient errors** (`ECONNRESET`, `ECONNABORTED`, etc.) → logged at
///   `debug`; they are expected under normal traffic and resolve automatically.
#[expect(
    clippy::too_many_arguments,
    reason = "Server startup requires these explicit shared resources and channels."
)]
pub async fn run(
    config: Arc<Config>,
    state: SharedState,
    metrics: SharedMetrics,
    data_dir: PathBuf,
    mut shutdown: watch::Receiver<bool>,
    port_tx: oneshot::Sender<std::result::Result<u16, String>>,
    root_watch: watch::Receiver<Arc<SiteSnapshot>>,
    shared_semaphore: Arc<Semaphore>,
    shared_per_ip_map: Arc<DashMap<IpAddr, Arc<AtomicU32>>>,
) {
    let bind_addr = config.server.bind;
    let base_port = config.server.port.get();
    let (listener, bound_port) = match bind_with_fallback(
        "HTTP listener",
        bind_addr,
        base_port,
        config.server.auto_port_fallback,
    ) {
        Ok(v) => v,
        Err(e) => {
            let message = e.to_string();
            log::error!("{message}");
            let _ = port_tx.send(Err(message));
            return;
        }
    };
    if bound_port != base_port {
        log::warn!("Configured port {base_port} was in use; bound to {bound_port} instead.");
    }
    let ctx = ServerContext::with_shared(
        &config,
        Arc::clone(&state),
        &data_dir,
        shared_semaphore,
        shared_per_ip_map,
        ListenerOptions {
            max_per_ip: Some(config.server.max_connections_per_ip),
            keep_alive: true,
            ingress: handler::RequestIngress::Http,
        },
        root_watch,
    );
    {
        let mut s = state.write().await;
        s.actual_port = bound_port;
        s.server_running = true;
    }
    let _ = port_tx.send(Ok(bound_port));
    log::info!("HTTP server listening on {bind_addr}:{bound_port}");
    let mut join_set: JoinSet<()> = JoinSet::new();
    let mut backoff_ms: u64 = 1;
    while !*shutdown.borrow() {
        while let Some(result) = join_set.try_join_next() {
            if let Err(e) = result {
                log::debug!("Connection task ended: {e}");
            }
        }
        tokio::select! {
            result = listener.accept() => {
                match result {
                    Ok((stream, peer)) => {
                        backoff_ms = 1;
                        if let Err(e) = stream.set_nodelay(true) {
                            log::debug!("Could not enable TCP_NODELAY for {peer}: {e}");
                        }
                        log::debug!("Connection from {peer}");
                        if !ctx.spawn_connection(stream, peer, &metrics, &mut join_set) {
                            break; // semaphore closed — shutting down
                        }
                    }
                    Err(e) => {
                        if is_fd_exhaustion(&e) {
                            log::error!(
                                "Accept error — file-descriptor limit reached \
                                 (EMFILE/ENFILE): {e}. Reduce max_connections or \
                                 raise the OS ulimit."
                            );
                        } else {
                            log::debug!("Accept error (transient): {e}");
                        }
                        tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                        backoff_ms = backoff_ms.saturating_mul(2).min(1_000);
                    }
                }
            }
            Some(result) = join_set.join_next(), if !join_set.is_empty() => {
                if let Err(e) = result {
                    log::debug!("HTTP connection task join error: {e}");
                }
            }
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() { break; }
            }
        }
    }
    state.write().await.server_running = false;
    log::info!("HTTP server stopped accepting; draining in-flight connections…");
    drain_connections(
        &mut join_set,
        Duration::from_secs(config.server.shutdown_grace_secs),
    )
    .await;
    log::info!("HTTP server drained.");
}
/// Start the HTTPS server.
///
/// Mirrors [`run`] exactly but wraps every accepted TCP stream in a TLS
/// handshake before handing it to the connection handler. TLS handshake
/// failures are logged at **`debug`** (not `warn`) because port-scanners,
/// load-balancer health checks, and misconfigured clients hit port 443
/// constantly and would create enormous log noise at higher severities.
///
/// The `per_ip_map` and `semaphore` are shared with the plain HTTP listener
/// so both listeners draw from a single global connection budget.
///
/// ## Shared parameters
///
/// - `shared_semaphore`: Shared connection-budget semaphore from the HTTP server.
///   Both listeners draw from the same pool so a client cannot double its
///   effective quota by connecting on both ports simultaneously.
/// - `shared_per_ip_map`: Shared per-IP connection counter map from the HTTP server.
/// - `root_watch`: Watch receiver for site-root updates pushed by the [R] reload
///   handler. Mirrors the same channel used by `run()` so both listeners always
///   serve from the same directory after a reload.
#[expect(
    clippy::too_many_arguments,
    reason = "HTTPS startup needs explicit listener, TLS, and shared budget state."
)]
#[expect(
    clippy::too_many_lines,
    reason = "HTTPS accept loop keeps handshake and admission logic together."
)]
pub async fn run_https(
    config: Arc<Config>,
    state: SharedState,
    metrics: SharedMetrics,
    data_dir: PathBuf,
    mut shutdown: watch::Receiver<bool>,
    tls_acceptor: Acceptor,
    port_tx: oneshot::Sender<std::result::Result<u16, String>>,
    shared_semaphore: Arc<Semaphore>,
    shared_per_ip_map: Arc<DashMap<IpAddr, Arc<AtomicU32>>>,
    root_watch: watch::Receiver<Arc<SiteSnapshot>>,
) {
    let bind_addr = config.server.bind;
    let port = config.tls.port.get();
    let bind_socket = std::net::SocketAddr::new(bind_addr, port);
    let std_listener = match StdTcpListener::bind(bind_socket) {
        Ok(l) => l,
        Err(e) => {
            let message = AppError::ServerBind {
                listener: "HTTPS listener",
                addr: bind_socket,
                source: e,
            }
            .to_string();
            log::error!("{message}");
            let _ = port_tx.send(Err(message));
            return;
        }
    };
    if let Err(e) = std_listener.set_nonblocking(true) {
        let message =
            format!("failed to configure HTTPS listener on {bind_socket} for nonblocking I/O: {e}");
        log::error!("{message}");
        let _ = port_tx.send(Err(message));
        return;
    }
    let listener = match TcpListener::from_std(std_listener) {
        Ok(l) => l,
        Err(e) => {
            let message = format!("failed to initialize HTTPS listener on {bind_socket}: {e}");
            log::error!("{message}");
            let _ = port_tx.send(Err(message));
            return;
        }
    };
    let ctx = ServerContext::with_shared(
        &config,
        Arc::clone(&state),
        &data_dir,
        shared_semaphore,
        shared_per_ip_map,
        ListenerOptions {
            max_per_ip: Some(config.server.max_connections_per_ip),
            keep_alive: true,
            ingress: handler::RequestIngress::Https,
        },
        root_watch,
    );
    {
        let mut s = state.write().await;
        s.tls_running = true;
        s.tls_port = Some(port);
    }
    let _ = port_tx.send(Ok(port));
    log::info!("HTTPS server listening on {bind_addr}:{port}");
    let mut join_set: JoinSet<()> = JoinSet::new();
    let mut backoff_ms: u64 = 1;
    while !*shutdown.borrow() {
        while let Some(result) = join_set.try_join_next() {
            if let Err(e) = result {
                log::debug!("Connection task ended: {e}");
            }
        }
        tokio::select! {
            result = listener.accept() => {
                match result {
                    Ok((tcp_stream, peer)) => {
                        backoff_ms = 1;
                        if let Err(e) = tcp_stream.set_nodelay(true) {
                            log::debug!("Could not enable TCP_NODELAY for TLS peer {peer}: {e}");
                        }
                        log::debug!("TLS connection from {peer}");
                        // Clone the acceptor handle cheaply — both variants are Arc-backed.
                        let acceptor = match &tls_acceptor {
                            Acceptor::Static(a) => Acceptor::Static(Arc::clone(a)),
                            Acceptor::Acme(a, cfg) => {
                                Acceptor::Acme(Arc::clone(a), Arc::clone(cfg))
                            }
                        };
                        let peer_ip = peer.ip();
                        let admission = match admit_connection(
                            &ctx.semaphore,
                            &ctx.per_ip_map,
                            peer_ip,
                            ctx.max_per_ip,
                        ) {
                            Ok(admission) => admission,
                            Err(AdmissionRejection::PerIpLimit { limit }) => {
                                log::warn!(
                                    "Per-IP limit ({limit}) reached for {peer_ip}; dropping TLS connection"
                                );
                                drop(tcp_stream);
                                continue;
                            }
                            Err(AdmissionRejection::GlobalLimit) => {
                                log::warn!(
                                    "Connection limit ({}) reached; dropping TLS connection from {peer_ip}",
                                    ctx.max_conns
                                );
                                drop(tcp_stream);
                                continue;
                            }
                        };
                        let site_watch = ctx.site_watch.clone();
                        let idx = Arc::clone(&ctx.index_file);
                        let met = Arc::clone(&metrics);
                        let state = Arc::clone(&ctx.state);
                        let readiness = handler::ReadinessConfig {
                            data_dir: Arc::clone(&ctx.data_dir),
                            log_dir: Arc::clone(&ctx.log_dir),
                        };
                        let csp = Arc::clone(&ctx.csp_header);
                        let flags = handler::FeatureFlags {
                            dir_listing: ctx.dir_list,
                            expose_dotfiles: ctx.expose_dots,
                            spa_routing: ctx.spa_routing,
                            is_https: true,
                            keep_alive: ctx.keep_alive,
                        };
                        let redirects = Arc::clone(&ctx.redirects);
                        let trusted_proxies = Arc::clone(&ctx.trusted_proxies);
                        let ingress = ctx.ingress;
                        join_set.spawn(async move {
                            let _admission = admission;
                            let tls_stream = match tokio::time::timeout(
                                TLS_HANDSHAKE_TIMEOUT,
                                accept_tls_stream(tcp_stream, acceptor, peer),
                            ).await {
                                Ok(Some(stream)) => stream,
                                Ok(None) => return,
                                Err(_) => {
                                    log::debug!("TLS handshake timed out from {peer}");
                                    return;
                                }
                            };
                            let handler_config = handler::HandlerConfig {
                                peer_addr: peer,
                                site_watch,
                                index_file: idx,
                                flags,
                                state,
                                readiness,
                                csp,
                                redirects,
                                trusted_proxies,
                                ingress,
                            };
                            if let Err(e) = handler::handle(tls_stream, handler_config, met).await {
                                log::debug!("HTTPS handler error: {e}");
                            }
                        });
                    }
                    Err(e) => {
                        if is_fd_exhaustion(&e) {
                            log::error!(
                                "HTTPS accept error — file-descriptor limit reached: {e}."
                            );
                        } else {
                            log::debug!("HTTPS accept error (transient): {e}");
                        }
                        tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                        backoff_ms = backoff_ms.saturating_mul(2).min(1_000);
                    }
                }
            }
            Some(result) = join_set.join_next(), if !join_set.is_empty() => {
                if let Err(e) = result {
                    log::debug!("HTTPS connection task join error: {e}");
                }
            }
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() { break; }
            }
        }
    }
    state.write().await.tls_running = false;
    log::info!("HTTPS server stopped accepting; draining in-flight connections…");
    drain_connections(
        &mut join_set,
        Duration::from_secs(config.server.shutdown_grace_secs),
    )
    .await;
    log::info!("HTTPS server drained.");
}

const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

trait TlsStream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> TlsStream for T {}

/// Both ACME negotiation and the subsequent TLS handshake share one deadline.
async fn accept_tls_stream(
    tcp_stream: tokio::net::TcpStream,
    acceptor: Acceptor,
    peer: std::net::SocketAddr,
) -> Option<Box<dyn TlsStream>> {
    use tokio_util::compat::{FuturesAsyncReadCompatExt as _, TokioAsyncReadCompatExt as _};
    let stream: Box<dyn TlsStream> = match acceptor {
        Acceptor::Static(a) => match a.accept(tcp_stream).await {
            Ok(s) => Box::new(s),
            Err(e) => {
                log::debug!("TLS handshake failed from {peer}: {e}");
                return None;
            }
        },
        Acceptor::Acme(a, server_cfg) => {
            // AcmeAcceptor::accept needs futures-io AsyncRead/AsyncWrite,
            // so adapt the tokio TcpStream before passing it in.
            let compat_stream = tcp_stream.compat();
            match a.accept(compat_stream).await {
                Ok(Some(handshake)) => {
                    match handshake.into_stream(server_cfg).await {
                        // compat() flips the resulting futures-io
                        // TLS stream back to tokio traits.
                        Ok(s) => Box::new(s.compat()),
                        Err(e) => {
                            log::debug!("ACME TLS handshake failed from {peer}: {e}");
                            return None;
                        }
                    }
                }
                // None means rustls-acme consumed this connection
                // internally to complete a TLS-ALPN-01 challenge.
                // No application data to serve — return cleanly.
                Ok(None) => {
                    log::debug!("ACME challenge connection handled for {peer}");
                    return None;
                }
                Err(e) => {
                    log::debug!("ACME accept error from {peer}: {e}");
                    return None;
                }
            }
        }
    };
    Some(stream)
}

/// Start a loopback-only HTTP listener used exclusively by the Tor proxy.
///
/// This listener serves the same site tree as the main HTTP server but bypasses
/// per-IP admission control because every Tor stream originates from loopback
/// once Arti proxies it into the local process. It still shares the global
/// connection semaphore so Tor traffic participates in the overall capacity
/// budget instead of becoming an unbounded side channel.
#[expect(
    clippy::too_many_arguments,
    reason = "Tor ingress shares the same explicit runtime wiring as the main listeners."
)]
pub async fn run_tor_ingress(
    config: Arc<Config>,
    state: SharedState,
    metrics: SharedMetrics,
    data_dir: PathBuf,
    mut shutdown: watch::Receiver<bool>,
    port_tx: oneshot::Sender<std::result::Result<u16, String>>,
    shared_semaphore: Arc<Semaphore>,
    root_watch: watch::Receiver<Arc<SiteSnapshot>>,
) {
    let bind_addr = tor_loopback_addr(config.server.bind);
    let bind_socket = std::net::SocketAddr::new(bind_addr, 0);
    let listener = match TcpListener::bind(bind_socket).await {
        Ok(listener) => listener,
        Err(e) => {
            let message = AppError::ServerBind {
                listener: "Tor ingress listener",
                addr: bind_socket,
                source: e,
            }
            .to_string();
            log::error!("{message}");
            let _ = port_tx.send(Err(message));
            return;
        }
    };
    let bound_port = match listener.local_addr() {
        Ok(addr) => addr.port(),
        Err(e) => {
            let message = format!(
                "Tor ingress listener bound on {bind_socket} but could not read its port: {e}"
            );
            log::error!("{message}");
            let _ = port_tx.send(Err(message));
            return;
        }
    };
    let ctx = ServerContext::with_shared(
        &config,
        state,
        &data_dir,
        shared_semaphore,
        Arc::new(DashMap::new()),
        ListenerOptions {
            max_per_ip: None,
            keep_alive: false,
            ingress: handler::RequestIngress::Tor,
        },
        root_watch,
    );
    let _ = port_tx.send(Ok(bound_port));
    log::info!("Tor ingress server listening on {bind_addr}:{bound_port}");
    let mut join_set: JoinSet<()> = JoinSet::new();
    let mut backoff_ms: u64 = 1;
    while !*shutdown.borrow() {
        while let Some(result) = join_set.try_join_next() {
            if let Err(e) = result {
                log::debug!("Connection task ended: {e}");
            }
        }
        tokio::select! {
            result = listener.accept() => {
                match result {
                    Ok((stream, peer)) => {
                        backoff_ms = 1;
                        if let Err(e) = stream.set_nodelay(true) {
                            log::debug!("Could not enable TCP_NODELAY for Tor ingress peer {peer}: {e}");
                        }
                        log::debug!("Tor ingress connection from {peer}");
                        if !ctx.spawn_connection(stream, peer, &metrics, &mut join_set) {
                            break;
                        }
                    }
                    Err(e) => {
                        if is_fd_exhaustion(&e) {
                            log::error!(
                                "Tor ingress accept error — file-descriptor limit reached \
                                 (EMFILE/ENFILE): {e}. Reduce max_connections or raise the OS ulimit."
                            );
                        } else {
                            log::debug!("Tor ingress accept error (transient): {e}");
                        }
                        tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                        backoff_ms = backoff_ms.saturating_mul(2).min(1_000);
                    }
                }
            }
            Some(result) = join_set.join_next(), if !join_set.is_empty() => {
                if let Err(e) = result {
                    log::debug!("Tor ingress connection task join error: {e}");
                }
            }
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() { break; }
            }
        }
    }
    log::info!("Tor ingress server stopped accepting; draining in-flight connections…");
    drain_connections(
        &mut join_set,
        Duration::from_secs(config.server.shutdown_grace_secs),
    )
    .await;
    log::info!("Tor ingress server drained.");
}
// ─── Port binding ─────────────────────────────────────────────────────────────
/// Try to bind to `addr:port`. When `fallback` is true, increments the port
/// up to 10 times before giving up.
fn bind_with_fallback(
    listener: &'static str,
    addr: IpAddr,
    port: u16,
    fallback: bool,
) -> Result<(TcpListener, u16)> {
    let max_attempts: u16 = if fallback { 10 } else { 1 };
    for attempt in 0..max_attempts {
        let try_port = port.saturating_add(attempt);
        let socket_addr = std::net::SocketAddr::new(addr, try_port);
        match StdTcpListener::bind(socket_addr) {
            Ok(std_listener) => {
                std_listener.set_nonblocking(true)?;
                let listener = TcpListener::from_std(std_listener)?;
                return Ok((listener, try_port));
            }
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse && fallback => {
                // Try the next port.
            }
            Err(source) => {
                let source = if source.kind() == std::io::ErrorKind::AddrInUse {
                    std::io::Error::new(
                        std::io::ErrorKind::AddrInUse,
                        format!("address already in use: {source}"),
                    )
                } else {
                    source
                };
                return Err(AppError::ServerBind {
                    listener,
                    addr: socket_addr,
                    source,
                });
            }
        }
    }
    Err(AppError::ServerBind {
        listener,
        addr: std::net::SocketAddr::new(addr, port),
        source: std::io::Error::new(
            std::io::ErrorKind::AddrInUse,
            format!(
                "Could not find a free port after {max_attempts} attempts \
                 starting from {port}. Change [server].port in settings.toml \
                 or set auto_port_fallback = true."
            ),
        ),
    })
}

#[must_use]
pub const fn tor_loopback_addr(addr: IpAddr) -> IpAddr {
    match addr {
        IpAddr::V4(_) => IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        IpAddr::V6(_) => IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
    }
}
/// Return `true` when `e` represents file-descriptor exhaustion.
///
/// On Unix this matches `EMFILE` (24, per-process FD limit) and `ENFILE`
/// (23, system-wide FD limit), both specified by POSIX and identical on
/// Linux, macOS, FreeBSD, and other POSIX-conformant systems.
///
/// On Windows this matches `WSAEMFILE` (10024), the Winsock equivalent of
/// `EMFILE` — it fires when the per-process socket descriptor table is full.
///
/// On all other targets the function always returns `false`.
fn is_fd_exhaustion(e: &std::io::Error) -> bool {
    #[cfg(unix)]
    {
        // EMFILE (24): too many open files for the process.
        // ENFILE (23): too many open files system-wide.
        matches!(e.raw_os_error(), Some(libc::EMFILE | libc::ENFILE))
    }
    #[cfg(windows)]
    {
        // WSAEMFILE (10024): per-process socket handle limit reached.
        // This is the Windows Sockets equivalent of POSIX EMFILE and fires
        // when the process has exhausted its socket descriptor table.
        matches!(e.raw_os_error(), Some(10_024))
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = e;
        false
    }
}
/// Return only after the grace period and cancellation have released all guards.
async fn drain_connections(tasks: &mut JoinSet<()>, grace: Duration) {
    let _ = tokio::time::timeout(grace, async { while tasks.join_next().await.is_some() {} }).await;
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
}

// ─── Site scanner ─────────────────────────────────────────────────────────────
/// Maximum directory depth `scan_site` will traverse.
///
/// Prevents runaway BFS on artificially deep or adversarially-constructed
/// directory trees. A legitimate site tree is extremely unlikely to exceed
/// this depth; anything beyond it is almost certainly a mistake or an attack.
const MAX_SCAN_DEPTH: usize = 64;
/// Recursively count files and total bytes in `site_root` (BFS traversal).
///
/// Symlinks are excluded. Failed reads or traversal limits fail the scan so a
/// reload cannot publish statistics from an incomplete tree.
///
/// # Errors
///
/// Returns [`AppError::Io`] for filesystem failures or traversal limits.
///
/// # Panics
///
/// Does not panic. **Must be called from a blocking context** (e.g.
/// `tokio::task::spawn_blocking`) because `std::fs::read_dir` is a blocking
/// syscall.
#[must_use = "the file count and byte total are used to populate the dashboard"]
pub fn scan_site(site_root: &Path) -> crate::Result<(u32, u64)> {
    let mut count = 0u32;
    let mut bytes = 0u64;
    // Queue entries carry a depth counter so the BFS can be bounded.
    // Using (PathBuf, usize) instead of PathBuf adds one word per queue entry —
    // negligible compared to the path allocation — and avoids a separate counter
    // map or recursive call stack.
    let mut queue: std::collections::VecDeque<(PathBuf, usize)> = std::collections::VecDeque::new();
    queue.push_back((site_root.to_path_buf(), 0));
    // Symlinks are excluded; device/inode pairs also avoid recounting aliases
    // such as bind mounts, without confusing inodes on different filesystems.
    #[cfg(unix)]
    let mut visited_inodes: std::collections::HashSet<(u64, u64)> =
        std::collections::HashSet::new();
    let mut scanned_entries = 0usize;
    while let Some((dir, depth)) = queue.pop_front() {
        if depth >= MAX_SCAN_DEPTH {
            return Err(std::io::Error::other("site scan exceeds depth limit").into());
        }
        let entries = std::fs::read_dir(&dir)?;
        for entry in entries {
            scanned_entries += 1;
            if scanned_entries > 1_000_000 {
                return Err(std::io::Error::other("site scan exceeds one million entries").into());
            }
            let path = entry?.path();
            let link_meta = std::fs::symlink_metadata(&path)?;
            if link_meta.file_type().is_symlink() {
                log::warn!("Skipping symlink during site scan: {}", path.display());
                continue;
            }
            if link_meta.is_file() {
                count = count.saturating_add(1);
                bytes = bytes.saturating_add(link_meta.len());
            } else if link_meta.is_dir() {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::MetadataExt as _;
                    let ino = link_meta.ino();
                    if !visited_inodes.insert((link_meta.dev(), ino)) {
                        log::warn!(
                            "Directory cycle detected at {} (inode {ino}), skipping",
                            path.display()
                        );
                        continue;
                    }
                }
                if queue.len() >= 4096 {
                    return Err(
                        std::io::Error::other("site scan exceeds pending directory limit").into(),
                    );
                }
                queue.push_back((path, depth.saturating_add(1)));
            }
        }
    }
    Ok((count, bytes))
}

#[cfg(test)]
mod drain_tests {
    use super::*;
    #[tokio::test(start_paused = true)]
    async fn expired_drain_joins_cancelled_tasks_and_releases_admission() -> Result<()> {
        let semaphore = Arc::new(Semaphore::new(1));
        let permit = Arc::clone(&semaphore)
            .try_acquire_owned()
            .map_err(std::io::Error::other)?;
        let mut tasks = JoinSet::new();
        tasks.spawn(async move {
            let _permit = permit;
            std::future::pending::<()>().await;
        });
        drain_connections(&mut tasks, Duration::from_secs(10)).await;
        assert!(tasks.is_empty());
        assert_eq!(semaphore.available_permits(), 1);
        Ok(())
    }
}
