//! # Server Module
//!
//! **File:** `mod.rs`
//! **Location:** `src/server/mod.rs`
//!
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
#[allow(clippy::struct_excessive_bools)]
struct ServerContext {
    canonical_root: Arc<Path>,
    index_file: Arc<str>,
    csp_header: Arc<str>,
    state: SharedState,
    keep_alive: bool,
    dir_list: bool,
    expose_dots: bool,
    spa_routing: bool,
    error_404_page: Option<Arc<handler::CustomErrorPage>>,
    error_503_page: Option<Arc<handler::CustomErrorPage>>,
    redirects: Arc<Vec<crate::config::RedirectRule>>,
    semaphore: Arc<Semaphore>,
    per_ip_map: Arc<DashMap<IpAddr, Arc<AtomicU32>>>,
    max_conns: usize,
    max_per_ip: Option<u32>,
    /// IPs whose X-Forwarded-For header is trusted.
    /// Defaults to empty (XFF ignored) for direct-edge deployments.
    trusted_proxies: Arc<Vec<IpAddr>>,
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
        max_per_ip: Option<u32>,
        keep_alive: bool,
    ) -> Option<Self> {
        let site_root = data_dir.join(&config.site.directory);
        let canonical_root: Arc<Path> = match site_root.canonicalize() {
            Ok(p) => Arc::from(p.as_path()),
            Err(e) => {
                log::error!(
                    "Site root {} cannot be resolved: {e}. \
                     Check that [site] directory exists.",
                    site_root.display()
                );
                return None;
            }
        };
        #[allow(clippy::cast_possible_truncation)]
        let max_conns = config.server.max_connections as usize;
        let site_dir = data_dir.join(&config.site.directory);
        let error_404_page = config.site.error_404.as_deref().and_then(|p| {
            handler::load_custom_error_page(
                canonical_root.as_ref(),
                &site_dir.join(p),
                "error_404",
                hyper::StatusCode::NOT_FOUND,
            )
        });
        let error_503_page = config.site.error_503.as_deref().and_then(|p| {
            handler::load_custom_error_page(
                canonical_root.as_ref(),
                &site_dir.join(p),
                "error_503",
                hyper::StatusCode::SERVICE_UNAVAILABLE,
            )
        });
        Some(Self {
            canonical_root,
            index_file: Arc::from(config.site.index_file.as_str()),
            csp_header: Arc::from(config.server.csp_level.as_header_value()),
            state,
            keep_alive,
            dir_list: config.site.enable_directory_listing,
            expose_dots: config.site.expose_dotfiles,
            spa_routing: config.site.spa_routing,
            error_404_page,
            error_503_page,
            redirects: Arc::new(config.redirects.clone()),
            semaphore,
            per_ip_map,
            max_conns,
            max_per_ip,
            // When empty, X-Forwarded-For is ignored on every connection.
            trusted_proxies: Arc::new(config.server.trusted_proxies.clone().unwrap_or_default()),
        })
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
        let site = Arc::clone(&self.canonical_root);
        let idx = Arc::clone(&self.index_file);
        let met = Arc::clone(metrics);
        let state = Arc::clone(&self.state);
        let csp = Arc::clone(&self.csp_header);
        let flags = handler::FeatureFlags {
            dir_listing: self.dir_list,
            expose_dotfiles: self.expose_dots,
            spa_routing: self.spa_routing,
            is_https: false,
            keep_alive: self.keep_alive,
        };
        let e404 = self.error_404_page.clone();
        let e503 = self.error_503_page.clone();
        let redirects = Arc::clone(&self.redirects);
        let trusted_proxies = Arc::clone(&self.trusted_proxies);
        join_set.spawn(async move {
            let _admission = admission;
            if let Err(e) = handler::handle(
                stream,
                peer,
                site,
                idx,
                flags,
                met,
                state,
                csp,
                e404,
                e503,
                redirects,
                trusted_proxies,
            )
            .await
            {
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
#[allow(clippy::too_many_arguments)]
pub async fn run(
    config: Arc<Config>,
    state: SharedState,
    metrics: SharedMetrics,
    data_dir: PathBuf,
    mut shutdown: watch::Receiver<bool>,
    port_tx: oneshot::Sender<u16>,
    mut root_watch: watch::Receiver<Arc<Path>>,
    shared_semaphore: Arc<Semaphore>,
    shared_per_ip_map: Arc<DashMap<IpAddr, Arc<AtomicU32>>>,
) {
    let bind_addr = config.server.bind;
    let base_port = config.server.port.get();
    let (listener, bound_port) =
        match bind_with_fallback(bind_addr, base_port, config.server.auto_port_fallback) {
            Ok(v) => v,
            Err(e) => {
                log::error!("Server failed to bind: {e}");
                return;
            }
        };
    if bound_port != base_port {
        log::warn!("Configured port {base_port} was in use; bound to {bound_port} instead.");
    }
    let Some(mut ctx) = ServerContext::with_shared(
        &config,
        Arc::clone(&state),
        &data_dir,
        shared_semaphore,
        shared_per_ip_map,
        Some(config.server.max_connections_per_ip),
        true,
    ) else {
        return;
    };
    {
        let mut s = state.write().await;
        s.actual_port = bound_port;
        s.server_running = true;
    }
    let _ = port_tx.send(bound_port);
    log::info!("HTTP server listening on {bind_addr}:{bound_port}");
    let mut join_set: JoinSet<()> = JoinSet::new();
    let mut backoff_ms: u64 = 1;
    loop {
        // Apply site-root updates pushed by the reload handler without blocking
        // the accept loop.
        if root_watch.has_changed().unwrap_or(false) {
            let new_root = Arc::clone(&root_watch.borrow_and_update());
            log::info!("Site root refreshed: {}", new_root.display());
            ctx.canonical_root = new_root;
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
            _ = shutdown.changed() => {
                if *shutdown.borrow() { break; }
            }
        }
    }
    state.write().await.server_running = false;
    log::info!("HTTP server stopped accepting; draining in-flight connections…");
    let drain = async { while join_set.join_next().await.is_some() {} };
    let _ = tokio::time::timeout(
        Duration::from_secs(config.server.shutdown_grace_secs),
        drain,
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
#[allow(clippy::too_many_arguments)]
#[allow(clippy::too_many_lines)]
pub async fn run_https(
    config: Arc<Config>,
    state: SharedState,
    metrics: SharedMetrics,
    data_dir: PathBuf,
    mut shutdown: watch::Receiver<bool>,
    tls_acceptor: Acceptor,
    port_tx: oneshot::Sender<u16>,
    shared_semaphore: Arc<Semaphore>,
    shared_per_ip_map: Arc<DashMap<IpAddr, Arc<AtomicU32>>>,
    mut root_watch: watch::Receiver<Arc<Path>>,
) {
    let bind_addr = config.server.bind;
    let port = config.tls.port.get();
    let bind_socket = std::net::SocketAddr::new(bind_addr, port);
    let std_listener = match StdTcpListener::bind(bind_socket) {
        Ok(l) => l,
        Err(e) => {
            log::error!("HTTPS server failed to bind {bind_addr}:{port}: {e}");
            return;
        }
    };
    if let Err(e) = std_listener.set_nonblocking(true) {
        log::error!("HTTPS listener set_nonblocking failed: {e}");
        return;
    }
    let listener = match TcpListener::from_std(std_listener) {
        Ok(l) => l,
        Err(e) => {
            log::error!("HTTPS TcpListener conversion failed: {e}");
            return;
        }
    };
    let Some(mut ctx) = ServerContext::with_shared(
        &config,
        Arc::clone(&state),
        &data_dir,
        shared_semaphore,
        shared_per_ip_map,
        Some(config.server.max_connections_per_ip),
        true,
    ) else {
        return;
    };
    {
        let mut s = state.write().await;
        s.tls_running = true;
        s.tls_port = Some(port);
    }
    let _ = port_tx.send(port);
    log::info!("HTTPS server listening on {bind_addr}:{port}");
    let mut join_set: JoinSet<()> = JoinSet::new();
    let mut backoff_ms: u64 = 1;
    loop {
        // Mirror the [R] reload path from run(): non-blocking check for a new
        // canonical_root so both listeners serve the same directory after reload.
        if root_watch.has_changed().unwrap_or(false) {
            let new_root = Arc::clone(&root_watch.borrow_and_update());
            log::info!("HTTPS: site root refreshed: {}", new_root.display());
            ctx.canonical_root = new_root;
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
                        let site = Arc::clone(&ctx.canonical_root);
                        let idx = Arc::clone(&ctx.index_file);
                        let met = Arc::clone(&metrics);
                        let state = Arc::clone(&ctx.state);
                        let csp = Arc::clone(&ctx.csp_header);
                        let flags = handler::FeatureFlags {
                            dir_listing: ctx.dir_list,
                            expose_dotfiles: ctx.expose_dots,
                            spa_routing: ctx.spa_routing,
                            is_https: true,
                            keep_alive: ctx.keep_alive,
                        };
                        let e404 = ctx.error_404_page.clone();
                        let e503 = ctx.error_503_page.clone();
                        let redirects = Arc::clone(&ctx.redirects);
                        let trusted_proxies = Arc::clone(&ctx.trusted_proxies);
                        join_set.spawn(async move {
                            // Items must appear before any statements (clippy::items_after_statements).
                            use tokio_util::compat::{
                                FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt,
                            };
                            trait TlsStream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
                            impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> TlsStream for T {}

                            let _admission = admission;
                            // Perform the TLS handshake. The two acceptor variants
                            // produce different concrete stream types, so we erase them
                            // behind a boxed trait object for the generic handler.
                            //
                            // Rust does not allow `dyn TraitA + TraitB` when both traits
                            // are non-auto traits, so we define a combined supertrait that
                            // the compiler can use as a single vtable target.
                            //
                            // The ACME acceptor uses futures-io traits (not tokio traits).
                            // We bridge in both directions with tokio-util's compat layer:
                            // • TcpStream tokio→futures via TokioAsyncReadCompatExt
                            // • TLS stream futures→tokio via FuturesAsyncReadCompatExt
                            let tls_stream: Box<dyn TlsStream> = match acceptor {
                                Acceptor::Static(a) => {
                                    match a.accept(tcp_stream).await {
                                        Ok(s) => Box::new(s),
                                        Err(e) => {
                                            log::debug!("TLS handshake failed from {peer}: {e}");
                                            return;
                                        }
                                    }
                                }
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
                                                    return;
                                                }
                                            }
                                        }
                                        // None means rustls-acme consumed this connection
                                        // internally to complete a TLS-ALPN-01 challenge.
                                        // No application data to serve — return cleanly.
                                        Ok(None) => {
                                            log::debug!("ACME challenge connection handled for {peer}");
                                            return;
                                        }
                                        Err(e) => {
                                            log::debug!("ACME accept error from {peer}: {e}");
                                            return;
                                        }
                                    }
                                }
                            };
                            if let Err(e) = handler::handle(
                                tls_stream,
                                peer,
                                site,
                                idx,
                                flags,
                                met,
                                state,
                                csp,
                                e404,
                                e503,
                                redirects,
                                trusted_proxies,
                            )
                            .await
                            {
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
            _ = shutdown.changed() => {
                if *shutdown.borrow() { break; }
            }
        }
    }
    state.write().await.tls_running = false;
    log::info!("HTTPS server stopped accepting; draining in-flight connections…");
    let drain = async { while join_set.join_next().await.is_some() {} };
    let _ = tokio::time::timeout(
        Duration::from_secs(config.server.shutdown_grace_secs),
        drain,
    )
    .await;
    log::info!("HTTPS server drained.");
}

/// Start a loopback-only HTTP listener used exclusively by the Tor proxy.
///
/// This listener serves the same site tree as the main HTTP server but bypasses
/// per-IP admission control because every Tor stream originates from loopback
/// once Arti proxies it into the local process. It still shares the global
/// connection semaphore so Tor traffic participates in the overall capacity
/// budget instead of becoming an unbounded side channel.
#[allow(clippy::too_many_arguments)]
pub async fn run_tor_ingress(
    config: Arc<Config>,
    state: SharedState,
    metrics: SharedMetrics,
    data_dir: PathBuf,
    mut shutdown: watch::Receiver<bool>,
    port_tx: oneshot::Sender<u16>,
    shared_semaphore: Arc<Semaphore>,
    root_watch: watch::Receiver<Arc<Path>>,
) {
    let bind_addr = tor_loopback_addr(config.server.bind);
    let listener = match TcpListener::bind(std::net::SocketAddr::new(bind_addr, 0)).await {
        Ok(listener) => listener,
        Err(e) => {
            log::error!("Tor ingress server failed to bind {bind_addr}:0: {e}");
            return;
        }
    };
    let bound_port = match listener.local_addr() {
        Ok(addr) => addr.port(),
        Err(e) => {
            log::error!("Tor ingress server could not read bound port: {e}");
            return;
        }
    };
    let Some(mut ctx) = ServerContext::with_shared(
        &config,
        state,
        &data_dir,
        shared_semaphore,
        Arc::new(DashMap::new()),
        None,
        false,
    ) else {
        return;
    };
    let _ = port_tx.send(bound_port);
    log::info!("Tor ingress server listening on {bind_addr}:{bound_port}");
    let mut join_set: JoinSet<()> = JoinSet::new();
    let mut root_watch = root_watch;
    let mut backoff_ms: u64 = 1;
    loop {
        if root_watch.has_changed().unwrap_or(false) {
            let new_root = Arc::clone(&root_watch.borrow_and_update());
            log::info!("Tor ingress: site root refreshed: {}", new_root.display());
            ctx.canonical_root = new_root;
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
            _ = shutdown.changed() => {
                if *shutdown.borrow() { break; }
            }
        }
    }
    log::info!("Tor ingress server stopped accepting; draining in-flight connections…");
    let drain = async { while join_set.join_next().await.is_some() {} };
    let _ = tokio::time::timeout(
        Duration::from_secs(config.server.shutdown_grace_secs),
        drain,
    )
    .await;
    log::info!("Tor ingress server drained.");
}
// ─── Port binding ─────────────────────────────────────────────────────────────
/// Try to bind to `addr:port`. When `fallback` is true, increments the port
/// up to 10 times before giving up.
fn bind_with_fallback(addr: IpAddr, port: u16, fallback: bool) -> Result<(TcpListener, u16)> {
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
                return Err(AppError::ServerBind {
                    port: try_port,
                    source,
                });
            }
        }
    }
    Err(AppError::ServerBind {
        port,
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
// ─── Site scanner ─────────────────────────────────────────────────────────────
/// Maximum directory depth `scan_site` will traverse.
///
/// Prevents runaway BFS on artificially deep or adversarially-constructed
/// directory trees. A legitimate site tree is extremely unlikely to exceed
/// this depth; anything beyond it is almost certainly a mistake or an attack.
const MAX_SCAN_DEPTH: usize = 64;
/// Recursively count files and total bytes in `site_root` (BFS traversal).
///
/// Unreadable directories are skipped with a warning so one bad subtree does
/// not prevent the rest of the site from being counted.
///
/// # Errors
///
/// Returns [`AppError::Io`] only if the initial traversal setup itself fails.
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
    // Track visited inodes to detect and break symlink cycles.
    // Without cycle detection a directory symlink loop (e.g. site/loop -> site/)
    // grows the BFS queue unboundedly and the function never returns, permanently
    // consuming a spawn_blocking thread.
    #[cfg(unix)]
    let mut visited_inodes: std::collections::HashSet<u64> = std::collections::HashSet::new();
    while let Some((dir, depth)) = queue.pop_front() {
        // Depth-bound check — emit a warning and skip rather than abort or panic.
        if depth >= MAX_SCAN_DEPTH {
            log::warn!(
                "scan_site: depth limit ({MAX_SCAN_DEPTH}) reached at {}; subdirectories below this point will not be counted",
                dir.display()
            );
            continue;
        }
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(e) => {
                // Skip unreadable directories with a per-directory warning.
                // Do NOT abort the entire scan — the rest of the tree may be readable.
                log::warn!("Skipping unreadable directory {}: {e}", dir.display());
                continue;
            }
        };
        for entry in entries.flatten() {
            let path = entry.path();
            // Inspect the link itself first so directory symlinks cannot walk
            // outside the site root during a background metrics scan.
            let Ok(link_meta) = std::fs::symlink_metadata(&path) else {
                continue;
            };
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
                    use std::os::unix::fs::MetadataExt;
                    let ino = link_meta.ino();
                    if !visited_inodes.insert(ino) {
                        log::warn!(
                            "Directory cycle detected at {} (inode {ino}), skipping",
                            path.display()
                        );
                        continue;
                    }
                }
                queue.push_back((path, depth.saturating_add(1)));
            }
        }
    }
    Ok((count, bytes))
}
