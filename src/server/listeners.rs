//! Static-site listener binding, admission, connections, and drain.

use dashmap::DashMap;
use std::{
    net::{IpAddr, SocketAddr, TcpListener as StdTcpListener},
    path::PathBuf,
    sync::{atomic::AtomicU32, Arc},
    time::Duration,
};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{oneshot, watch, Semaphore},
    task::JoinSet,
    time::Instant,
};

use super::{
    admission::{admit_connection, AdmissionRejection},
    handler, SiteSnapshot,
};
use crate::{
    config::Config,
    runtime::{
        service_status::{ListenerRole, ListenerStatus, RuntimeState},
        shutdown::{deadline, drain_tasks, ServiceOutcome, Shutdown},
        state::{SharedMetrics, SharedState},
    },
    tls::Acceptor,
    AppError, Result,
};

#[derive(Clone)]
pub struct ConnectionBudget {
    pub semaphore: Arc<Semaphore>,
    pub per_ip_map: Arc<DashMap<IpAddr, Arc<AtomicU32>>>,
}

#[derive(Clone)]
pub struct ListenerContext {
    pub config: Arc<Config>,
    pub state: RuntimeState,
    pub metrics: SharedMetrics,
    pub data_dir: PathBuf,
    pub shutdown: Shutdown,
    pub site_watch: watch::Receiver<Arc<SiteSnapshot>>,
    pub budget: ConnectionBudget,
}

pub type BindResult = std::result::Result<SocketAddr, String>;

pub async fn serve(
    role: ListenerRole,
    acceptor: Option<Acceptor>,
    context: ListenerContext,
    ready: impl FnOnce(BindResult),
) -> ServiceOutcome {
    let grace = role.shutdown_class().grace(&context.config);
    serve_with_grace(role, acceptor, context, grace, ready).await
}

async fn serve_with_grace(
    role: ListenerRole,
    acceptor: Option<Acceptor>,
    context: ListenerContext,
    grace: Duration,
    ready: impl FnOnce(BindResult),
) -> ServiceOutcome {
    context
        .state
        .set_listener(role, ListenerStatus::Starting)
        .await;
    let (listener, address) = match bind(role, &context.config).await {
        Ok(bound) => bound,
        Err(error) => return bind_failed(role, &context.state, ready, error.to_string()).await,
    };
    context
        .state
        .set_listener(role, ListenerStatus::Listening(address))
        .await;
    ready(Ok(address));
    log::info!("{} listener listening on {address}", role.label());

    let handler = handler_settings(role, &context, address);
    let mut connections = JoinSet::new();
    let connection_shutdown = context.shutdown.clone();
    let mut accepting_shutdown = context.shutdown.clone();
    let started = match accept_connections(
        &listener,
        role,
        &mut connections,
        &mut accepting_shutdown,
        |stream, peer, tasks| {
            let mut settings = handler.clone();
            settings.peer_addr = peer;
            spawn_connection(
                stream,
                settings,
                acceptor.clone(),
                &context,
                connection_shutdown.clone(),
                tasks,
            );
        },
    )
    .await
    {
        Ok(started) => started,
        Err(error) => {
            drop(listener);
            let message = format!("{} accept failed: {error}", role.label());
            context
                .state
                .set_listener(role, ListenerStatus::Failed(message.clone()))
                .await;
            return ServiceOutcome::Failed(message);
        }
    };
    drop(listener);
    finish_listener(
        role,
        &context.state,
        &mut connections,
        deadline(started, grace),
    )
    .await
}

fn handler_settings(
    role: ListenerRole,
    context: &ListenerContext,
    address: SocketAddr,
) -> handler::HandlerConfig {
    let config = &context.config;
    let log_path = context.data_dir.join(&config.logging.file);
    let log_dir = log_path.parent().unwrap_or(&context.data_dir);
    let ingress = match role {
        ListenerRole::Https => handler::RequestIngress::Https,
        ListenerRole::TorIngress => handler::RequestIngress::Tor,
        ListenerRole::Http | ListenerRole::Redirect => handler::RequestIngress::Http,
    };
    handler::HandlerConfig {
        peer_addr: address,
        site_watch: context.site_watch.clone(),
        index_file: Arc::from(config.site.index_file.as_str()),
        flags: handler::FeatureFlags {
            is_https: role == ListenerRole::Https,
            dir_listing: config.site.enable_directory_listing,
            expose_dotfiles: config.site.expose_dotfiles,
            spa_routing: config.site.spa_routing,
            keep_alive: role != ListenerRole::TorIngress,
        },
        state: Arc::clone(&context.state.app),
        readiness: handler::ReadinessConfig {
            data_dir: Arc::from(context.data_dir.as_path()),
            log_dir: Arc::from(log_dir),
        },
        csp: Arc::from(config.server.csp_level.as_header_value()),
        redirects: Arc::new(config.redirects.clone()),
        trusted_proxies: Arc::new(config.server.trusted_proxies.clone().unwrap_or_default()),
        ingress,
    }
}

fn spawn_connection(
    stream: TcpStream,
    settings: handler::HandlerConfig,
    acceptor: Option<Acceptor>,
    context: &ListenerContext,
    mut shutdown: Shutdown,
    connections: &mut JoinSet<()>,
) {
    let peer = settings.peer_addr;
    let max_per_ip = (settings.ingress != handler::RequestIngress::Tor)
        .then_some(context.config.server.max_connections_per_ip);
    let admission = match admit_connection(
        &context.budget.semaphore,
        &context.budget.per_ip_map,
        peer.ip(),
        max_per_ip,
    ) {
        Ok(admission) => admission,
        Err(AdmissionRejection::PerIpLimit { limit }) => {
            log::warn!(
                "Per-IP limit ({limit}) reached for {}; dropping connection",
                peer.ip()
            );
            return;
        }
        Err(AdmissionRejection::GlobalLimit) => {
            log::warn!(
                "Connection limit reached; dropping connection from {}",
                peer.ip()
            );
            return;
        }
    };
    let metrics = Arc::clone(&context.metrics);
    connections.spawn(async move {
        let _admission = admission;
        let result = if let Some(acceptor) = acceptor {
            let handshake = tokio::time::timeout(
                TLS_HANDSHAKE_TIMEOUT,
                accept_tls_stream(stream, acceptor, peer),
            );
            let stream = tokio::select! {
                biased;
                _ = shutdown.wait() => return,
                result = handshake => match result {
                    Ok(Some(stream)) => stream,
                    Ok(None) => return,
                    Err(_) => {
                        log::debug!("TLS handshake timed out from {peer}");
                        return;
                    }
                }
            };
            handler::handle(stream, settings, metrics, shutdown).await
        } else {
            handler::handle(stream, settings, metrics, shutdown).await
        };
        if let Err(error) = result {
            log::debug!("Handler error from {peer}: {error}");
        }
    });
}

async fn bind(role: ListenerRole, config: &Config) -> Result<(TcpListener, SocketAddr)> {
    let listener = if role == ListenerRole::Http {
        let port = config.server.port.get();
        let (listener, bound) = bind_with_fallback(
            "HTTP listener",
            config.server.bind,
            port,
            config.server.auto_port_fallback,
        )?;
        if bound != port {
            log::warn!("Configured port {port} was in use; bound to {bound} instead.");
        }
        listener
    } else {
        let (label, socket) = if role == ListenerRole::TorIngress {
            (
                "Tor ingress listener",
                SocketAddr::new(tor_loopback_addr(config.server.bind), 0),
            )
        } else {
            (
                "HTTPS listener",
                SocketAddr::new(config.server.bind, config.tls.port.get()),
            )
        };
        TcpListener::bind(socket)
            .await
            .map_err(|source| AppError::ServerBind {
                listener: label,
                addr: socket,
                source,
            })?
    };
    let address = listener.local_addr()?;
    Ok((listener, address))
}

pub(super) async fn bind_failed(
    role: ListenerRole,
    state: &RuntimeState,
    ready: impl FnOnce(BindResult),
    message: String,
) -> ServiceOutcome {
    state
        .set_listener(role, ListenerStatus::Failed(message.clone()))
        .await;
    ready(Err(message.clone()));
    ServiceOutcome::Failed(message)
}

pub(super) async fn accept_connections(
    listener: &TcpListener,
    role: ListenerRole,
    tasks: &mut JoinSet<()>,
    shutdown: &mut Shutdown,
    mut spawn: impl FnMut(TcpStream, SocketAddr, &mut JoinSet<()>),
) -> std::io::Result<Instant> {
    let mut backoff_ms = 1u64;
    loop {
        tokio::select! {
            biased;
            started = shutdown.wait() => return Ok(started),
            Some(result) = tasks.join_next(), if !tasks.is_empty() => {
                if let Err(error) = result {
                    log::warn!("{} connection task failed: {error}", role.label());
                }
            }
            result = listener.accept() => match result {
                Ok((stream, peer)) => {
                    backoff_ms = 1;
                    if let Err(error) = stream.set_nodelay(true) {
                        log::debug!("Could not enable TCP_NODELAY for {peer}: {error}");
                    }
                    log::debug!("{} connection from {peer}", role.label());
                    spawn(stream, peer, tasks);
                }
                Err(error) => {
                    use std::io::ErrorKind::{InvalidInput, NotConnected, PermissionDenied, Unsupported};
                    if matches!(error.kind(), InvalidInput | NotConnected | PermissionDenied | Unsupported) {
                        return Err(error);
                    }
                    if is_fd_exhaustion(&error) {
                        log::error!("{} accept error: file-descriptor limit reached: {error}", role.label());
                    } else {
                        log::debug!("{} transient accept error: {error}", role.label());
                    }
                    tokio::select! {
                        started = shutdown.wait() => return Ok(started),
                        () = tokio::time::sleep(Duration::from_millis(backoff_ms)) => {}
                    }
                    backoff_ms = backoff_ms.saturating_mul(2).min(1_000);
                }
            }
        }
    }
}

pub(super) async fn finish_listener(
    role: ListenerRole,
    state: &RuntimeState,
    tasks: &mut JoinSet<()>,
    deadline: Instant,
) -> ServiceOutcome {
    state.set_listener(role, ListenerStatus::Draining).await;
    log::info!("{} listener draining", role.label());
    let outcome = drain_tasks(tasks, deadline, role.label()).await;
    let status = match &outcome {
        ServiceOutcome::Drained | ServiceOutcome::Aborted => ListenerStatus::Stopped,
        ServiceOutcome::Failed(message) => ListenerStatus::Failed(message.clone()),
    };
    state.set_listener(role, status).await;
    outcome
}
/// Serve the Http listener using the legacy port acknowledgement.
///
/// This entry point retains the library API for callers with their own
/// listener wiring. The application runtime uses socket-address acknowledgements.
#[expect(
    clippy::too_many_arguments,
    reason = "Preserve the public listener signature."
)]
pub async fn run(
    config: Arc<Config>,
    state: SharedState,
    metrics: SharedMetrics,
    data_dir: PathBuf,
    shutdown: watch::Receiver<bool>,
    port_tx: oneshot::Sender<std::result::Result<u16, String>>,
    root_watch: watch::Receiver<Arc<SiteSnapshot>>,
    shared_semaphore: Arc<Semaphore>,
    shared_per_ip_map: Arc<DashMap<IpAddr, Arc<AtomicU32>>>,
) {
    let context = ListenerContext {
        config,
        state: RuntimeState::new(state),
        metrics,
        data_dir,
        shutdown: Shutdown::from_receiver(shutdown),
        site_watch: root_watch,
        budget: ConnectionBudget {
            semaphore: shared_semaphore,
            per_ip_map: shared_per_ip_map,
        },
    };
    let outcome = serve(ListenerRole::Http, None, context, move |result| {
        let _ = port_tx.send(result.map(|addr| addr.port()));
    })
    .await;
    if let ServiceOutcome::Failed(message) = outcome {
        log::error!("{message}");
    }
}

/// Serve the Https listener using the legacy port acknowledgement.
///
/// This entry point retains the library API for callers with their own
/// listener wiring. The application runtime uses socket-address acknowledgements.
#[expect(
    clippy::too_many_arguments,
    reason = "Preserve the public listener signature."
)]
pub async fn run_https(
    config: Arc<Config>,
    state: SharedState,
    metrics: SharedMetrics,
    data_dir: PathBuf,
    shutdown: watch::Receiver<bool>,
    tls_acceptor: Acceptor,
    port_tx: oneshot::Sender<std::result::Result<u16, String>>,
    shared_semaphore: Arc<Semaphore>,
    shared_per_ip_map: Arc<DashMap<IpAddr, Arc<AtomicU32>>>,
    root_watch: watch::Receiver<Arc<SiteSnapshot>>,
) {
    let context = ListenerContext {
        config,
        state: RuntimeState::new(state),
        metrics,
        data_dir,
        shutdown: Shutdown::from_receiver(shutdown),
        site_watch: root_watch,
        budget: ConnectionBudget {
            semaphore: shared_semaphore,
            per_ip_map: shared_per_ip_map,
        },
    };
    let outcome = serve(
        ListenerRole::Https,
        Some(tls_acceptor),
        context,
        move |result| {
            let _ = port_tx.send(result.map(|addr| addr.port()));
        },
    )
    .await;
    if let ServiceOutcome::Failed(message) = outcome {
        log::error!("{message}");
    }
}

/// Serve the Tor ingress listener using the legacy port acknowledgement.
///
/// This entry point retains the library API for callers with their own
/// listener wiring and uses the grace period from `[server]`.
#[expect(
    clippy::too_many_arguments,
    reason = "Preserve the public listener signature."
)]
pub async fn run_tor_ingress(
    config: Arc<Config>,
    state: SharedState,
    metrics: SharedMetrics,
    data_dir: PathBuf,
    shutdown: watch::Receiver<bool>,
    port_tx: oneshot::Sender<std::result::Result<u16, String>>,
    shared_semaphore: Arc<Semaphore>,
    root_watch: watch::Receiver<Arc<SiteSnapshot>>,
) {
    let grace = Duration::from_secs(config.server.shutdown_grace_secs);
    let context = ListenerContext {
        config,
        state: RuntimeState::new(state),
        metrics,
        data_dir,
        shutdown: Shutdown::from_receiver(shutdown),
        site_watch: root_watch,
        budget: ConnectionBudget {
            semaphore: shared_semaphore,
            per_ip_map: Arc::new(DashMap::new()),
        },
    };
    let outcome = serve_with_grace(
        ListenerRole::TorIngress,
        None,
        context,
        grace,
        move |result| {
            let _ = port_tx.send(result.map(|addr| addr.port()));
        },
    )
    .await;
    if let ServiceOutcome::Failed(message) = outcome {
        log::error!("{message}");
    }
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
