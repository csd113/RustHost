//! # HTTP Server Integration Tests
//! Each test spins up an isolated [`rusthost::server::run`] instance, connects
//! to it via [`tokio::net::TcpStream`], sends raw HTTP/1.1, and inspects the
//! raw response bytes.
//!
//! ## Port allocation
//!
//! Each test calls [`reserve_port()`], which binds `127.0.0.1:0`, reads the
//! OS-assigned port, and drops the listener.  That port number is written into
//! the test [`Config`] with `auto_port_fallback = false`, and is also sent back
//! to the test via the `port_tx` oneshot that `server::run` fires once it has
//! successfully bound.  The test blocks on `port_rx` before making any
//! connection, so it never races against the server's bind call — it simply
//! waits until the server confirms the port is open.
//!
//! The residual TOCTOU window (between the listener drop and `server::run`
//! calling `bind`) is unavoidable without modifying `server::run` to accept a
//! pre-bound listener.  On the loopback interface this window is on the order
//! of microseconds and is acceptable in practice.

#![allow(renamed_and_removed_lints)]

mod support;

use std::io::Write as _;
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::Path,
    sync::{atomic::AtomicU32, Arc, Once},
    time::Duration,
};

use dashmap::DashMap;
use rusthost::{
    config::Config,
    runtime::state::{AppState, Metrics},
};
use support::{
    build_test_config, header_value, read_headers_only, read_one_response, reserve_port,
    reserve_port_for, response_to_str, status_code,
};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::TcpStream,
    sync::{watch, RwLock, Semaphore},
};

// ─── Test harness ─────────────────────────────────────────────────────────────

/// A live server instance scoped to one test.
struct TestServer {
    addr: SocketAddr,
    shutdown_tx: watch::Sender<bool>,
    /// Keeps the root watch channel open for the lifetime of the server.
    /// Dropping this would put the receiver into a "sender gone" state, which
    /// causes any `root_rx.changed().await` inside `server::run` to return an
    /// error immediately.
    _root_tx: watch::Sender<Arc<Path>>,
    handle: Option<tokio::task::JoinHandle<()>>,
}

impl TestServer {
    async fn start_with_config(
        site_root: &Path,
        configure: impl FnOnce(&mut Config),
    ) -> Result<Self, Box<dyn std::error::Error>> {
        Self::start_with_bind_and_config(site_root, IpAddr::V4(Ipv4Addr::LOCALHOST), configure)
            .await
    }

    async fn start_with_bind_and_config(
        site_root: &Path,
        bind_addr: IpAddr,
        configure: impl FnOnce(&mut Config),
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let port = reserve_port_for(bind_addr)?;

        let mut config = build_test_config(site_root, bind_addr, port)?;
        config.server.max_connections = 16;
        config.server.csp_level = rusthost::config::CspLevel::Strict;
        config.site.enable_directory_listing = false;
        configure(&mut config);
        let config = Arc::new(config);
        let state = Arc::new(RwLock::new(AppState::new()));
        let metrics = Arc::new(Metrics::new());
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let (port_tx, port_rx) = tokio::sync::oneshot::channel::<Result<u16, String>>();

        // The server joins data_dir + config.site.directory to find files.
        // `site_root` is `<tmp>/site`; `data_dir` must therefore be `<tmp>`.
        let data_dir = site_root.parent().unwrap_or(site_root).to_path_buf();

        // Build the canonical site root path and seed the root watch channel.
        // _root_tx is stored in TestServer so the channel stays open for the
        // entire lifetime of the server task.  If it were dropped here the
        // receiver would enter a "sender gone" state and any
        // `root_rx.changed().await` inside server::run would return an error.
        let joined: std::path::PathBuf = data_dir.join(&config.site.directory);
        let site_root_arc: Arc<Path> = Arc::from(joined.as_path());
        let (root_tx, root_rx) = watch::channel(site_root_arc);

        // Connection-count limiter: capacity matches config.server.max_connections
        // so the server's internal limit and the semaphore stay in sync.
        let conn_semaphore: Arc<Semaphore> =
            Arc::new(Semaphore::new(config.server.max_connections as usize));

        // Per-IP active-connection tracker required by the rate-limiting layer.
        let ip_connections: Arc<DashMap<IpAddr, Arc<AtomicU32>>> = Arc::new(DashMap::new());

        let handle = {
            let cfg = Arc::clone(&config);
            let st = Arc::clone(&state);
            let met = Arc::clone(&metrics);
            let shut = shutdown_rx;
            tokio::spawn(async move {
                rusthost::server::run(
                    cfg,
                    st,
                    met,
                    data_dir,
                    shut,
                    port_tx,
                    root_rx,
                    conn_semaphore,
                    ip_connections,
                )
                .await;
            })
        };

        // Block until the server confirms it has successfully bound the port
        // (5 s guard).  This is the synchronisation point that makes the
        // TOCTOU window irrelevant: the test never tries to connect before the
        // server is listening.
        let bound_port = tokio::time::timeout(Duration::from_secs(5), port_rx)
            .await
            .map_err(|_elapsed| "timed out waiting for server to report its bound port")?
            .map_err(|_closed| "server port channel closed before sending")?
            .map_err(std::io::Error::other)?;

        let addr = SocketAddr::new(bind_addr, bound_port);

        Ok(Self {
            addr,
            shutdown_tx,
            _root_tx: root_tx,
            handle: Some(handle),
        })
    }

    /// Send raw `request` bytes and return the complete response as a `Vec<u8>`.
    ///
    /// Reads exactly one HTTP/1.1 response: all header lines until `\r\n\r\n`,
    /// then exactly `Content-Length` body bytes (or 0 if the header is absent).
    /// This is necessary because hyper keeps connections alive — reading until
    /// EOF would block indefinitely on a keep-alive server.
    ///
    /// Use [`send_no_body`] for HEAD requests where the server sends
    /// `Content-Length` but no body bytes.
    ///
    /// A 5-second deadline guards against a misbehaving server.
    async fn send(&self, request: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut stream = TcpStream::connect(self.addr).await?;
        stream.write_all(request).await?;

        tokio::time::timeout(Duration::from_secs(5), read_one_response(&mut stream))
            .await
            .map_err(|_elapsed| "read_one_response timed out after 5 s")?
    }

    /// Like [`send`] but does not attempt to read a response body.
    ///
    /// Use for HEAD requests: the server sends headers with `Content-Length`
    /// but zero body bytes, so reading body bytes would block forever on a
    /// keep-alive connection.
    async fn send_no_body(&self, request: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut stream = TcpStream::connect(self.addr).await?;
        stream.write_all(request).await?;

        tokio::time::timeout(Duration::from_secs(5), read_headers_only(&mut stream))
            .await
            .map_err(|_elapsed| "read_headers_only timed out after 5 s")?
    }

    /// Gracefully shut the server down and await task exit.
    async fn stop(mut self) {
        let _ = self.shutdown_tx.send(true);
        if let Some(handle) = self.handle.take() {
            match tokio::time::timeout(Duration::from_secs(5), handle).await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    let _ = writeln!(std::io::stderr(), "[TestServer] server task panicked: {e}");
                }
                Err(_) => {
                    let _ = writeln!(
                        std::io::stderr(),
                        "[TestServer] server shutdown timed out after 5 s"
                    );
                }
            }
        }
    }
}

async fn start_server_or_skip(
    site_root: &Path,
) -> Result<Option<TestServer>, Box<dyn std::error::Error>> {
    start_server_with_bind_or_skip(site_root, IpAddr::V4(Ipv4Addr::LOCALHOST), |_| {}).await
}

async fn start_server_with_bind_or_skip(
    site_root: &Path,
    bind_addr: IpAddr,
    configure: impl FnOnce(&mut Config),
) -> Result<Option<TestServer>, Box<dyn std::error::Error>> {
    match TestServer::start_with_bind_and_config(site_root, bind_addr, configure).await {
        Ok(server) => Ok(Some(server)),
        Err(err)
            if err.downcast_ref::<std::io::Error>().is_some_and(|io| {
                matches!(
                    io.kind(),
                    std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::AddrNotAvailable
                )
            }) =>
        {
            let _ = writeln!(
                std::io::stderr(),
                "[http_integration] skipping test: loopback sockets are blocked or unavailable in this environment"
            );
            Ok(None)
        }
        Err(err) => Err(err),
    }
}

async fn start_https_server_or_skip(
    site_root: &Path,
) -> Result<Option<HttpsTestServer>, Box<dyn std::error::Error>> {
    match HttpsTestServer::start(site_root).await {
        Ok(server) => Ok(Some(server)),
        Err(err)
            if err.downcast_ref::<std::io::Error>().is_some_and(|io| {
                matches!(
                    io.kind(),
                    std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::AddrNotAvailable
                )
            }) =>
        {
            let _ = writeln!(
                std::io::stderr(),
                "[http_integration] skipping test: loopback sockets are blocked or unavailable in this environment"
            );
            Ok(None)
        }
        Err(err) => Err(err),
    }
}

async fn wait_for_listener(addr: SocketAddr) -> Result<(), Box<dyn std::error::Error>> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        match TcpStream::connect(addr).await {
            Ok(stream) => {
                drop(stream);
                return Ok(());
            }
            Err(err)
                if matches!(
                    err.kind(),
                    std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::TimedOut
                ) && tokio::time::Instant::now() < deadline =>
            {
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            Err(err) => return Err(Box::new(err)),
        }
    }
}

fn ensure_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

struct HttpsTestServer {
    addr: SocketAddr,
    cert_path: std::path::PathBuf,
    shutdown_tx: watch::Sender<bool>,
    _root_tx: watch::Sender<Arc<Path>>,
    handle: Option<tokio::task::JoinHandle<()>>,
}

impl HttpsTestServer {
    async fn start(site_root: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        Self::start_with_state(site_root, |_| {}).await
    }

    async fn start_with_state(
        site_root: &Path,
        configure_state: impl FnOnce(&mut AppState),
    ) -> Result<Self, Box<dyn std::error::Error>> {
        ensure_crypto_provider();

        let port = reserve_port()?;
        let mut config = build_test_config(site_root, IpAddr::V4(Ipv4Addr::LOCALHOST), port)?;
        config.server.max_connections = 16;
        config.server.csp_level = rusthost::config::CspLevel::Strict;
        config.site.enable_directory_listing = false;
        config.tls.enabled = true;
        config.tls.port = std::num::NonZeroU16::new(port).ok_or("reserved HTTPS port was 0")?;
        config.tls.redirect_http = false;

        let mut initial_state = AppState::new();
        configure_state(&mut initial_state);
        let state = Arc::new(RwLock::new(initial_state));
        let metrics = Arc::new(Metrics::new());
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let data_dir = site_root.parent().unwrap_or(site_root).to_path_buf();
        let joined = data_dir.join(&config.site.directory);
        let site_root_arc: Arc<Path> = Arc::from(joined.as_path());
        let (root_tx, root_rx) = watch::channel(site_root_arc);

        let conn_semaphore: Arc<Semaphore> =
            Arc::new(Semaphore::new(config.server.max_connections as usize));
        let ip_connections: Arc<DashMap<IpAddr, Arc<AtomicU32>>> = Arc::new(DashMap::new());

        let tls_setup = rusthost::tls::build_acceptor(&config.tls, &data_dir)
            .await?
            .ok_or("expected TLS setup when tls.enabled = true")?;
        let rusthost::tls::TlsSetup {
            acceptor,
            acme_task: _acme_task,
            acme_guard: _acme_guard,
        } = tls_setup;

        let config = Arc::new(config);
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
        let cert_path = data_dir.join("runtime/tls/dev/self-signed.crt");
        let (tls_port_tx, _tls_port_rx) = tokio::sync::oneshot::channel::<Result<u16, String>>();
        let handle = tokio::spawn(async move {
            rusthost::server::run_https(
                config,
                state,
                metrics,
                data_dir,
                shutdown_rx,
                acceptor,
                tls_port_tx,
                conn_semaphore,
                ip_connections,
                root_rx,
            )
            .await;
        });

        wait_for_listener(addr).await?;

        Ok(Self {
            addr,
            cert_path,
            shutdown_tx,
            _root_tx: root_tx,
            handle: Some(handle),
        })
    }

    async fn send(&self, request: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let cert_pem = std::fs::read(&self.cert_path)?;
        let mut cert_reader = std::io::BufReader::new(cert_pem.as_slice());
        let certs =
            rustls_pemfile::certs(&mut cert_reader).collect::<std::result::Result<Vec<_>, _>>()?;

        let mut roots = rustls::RootCertStore::empty();
        for cert in certs {
            roots.add(cert)?;
        }

        let client_config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));

        let stream = TcpStream::connect(self.addr).await?;
        let server_name = rustls::pki_types::ServerName::try_from("localhost")
            .map_err(|_invalid_name| "invalid localhost server name")?
            .to_owned();
        let mut tls_stream = connector.connect(server_name, stream).await?;
        tls_stream.write_all(request).await?;

        tokio::time::timeout(Duration::from_secs(5), read_one_response(&mut tls_stream))
            .await
            .map_err(|_elapsed| "HTTPS read_one_response timed out after 5 s")?
    }

    async fn stop(mut self) {
        let _ = self.shutdown_tx.send(true);
        if let Some(handle) = self.handle.take() {
            match tokio::time::timeout(Duration::from_secs(5), handle).await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    let _ = writeln!(
                        std::io::stderr(),
                        "[HttpsTestServer] server task panicked: {e}"
                    );
                }
                Err(_) => {
                    let _ = writeln!(
                        std::io::stderr(),
                        "[HttpsTestServer] server shutdown timed out after 5 s"
                    );
                }
            }
        }
    }
}

impl Drop for HttpsTestServer {
    fn drop(&mut self) {
        let _ = self.shutdown_tx.send(true);
        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
    }
}

async fn start_server_with_config_or_skip(
    site_root: &Path,
    configure: impl FnOnce(&mut Config),
) -> Result<Option<TestServer>, Box<dyn std::error::Error>> {
    match TestServer::start_with_config(site_root, configure).await {
        Ok(server) => Ok(Some(server)),
        Err(err)
            if err
                .downcast_ref::<std::io::Error>()
                .is_some_and(|io| io.kind() == std::io::ErrorKind::PermissionDenied) =>
        {
            let _ = writeln!(
                std::io::stderr(),
                "[http_integration] skipping test: loopback sockets are blocked in this environment"
            );
            Ok(None)
        }
        Err(err) => Err(err),
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        // Best-effort signal if the test panics before calling `stop()`.
        let _ = self.shutdown_tx.send(true);
        // Forcibly cancel the task so it does not outlive the test runtime.
        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
    }
}

/// Create a temporary `<tmp>/site/<files…>` tree.
///
/// Returns `(TempDir, site_path)`.  The caller must keep `TempDir` alive for
/// the duration of the test.
fn make_site(
    files: &[(&str, &[u8])],
) -> Result<(tempfile::TempDir, std::path::PathBuf), Box<dyn std::error::Error>> {
    let tmp = tempfile::tempdir()?;
    let site = tmp.path().join("site");
    std::fs::create_dir_all(&site)?;
    for (name, content) in files {
        std::fs::write(site.join(name), content)?;
    }
    Ok((tmp, site))
}

fn init_test_logger() {
    static INIT: Once = Once::new();

    INIT.call_once(|| {
        let config = rusthost::config::LoggingConfig {
            enabled: false,
            level: rusthost::config::LogLevel::Debug,
            file: "runtime/logs/test.log".into(),
            filter_dependencies: false,
        };
        rusthost::logging::init(&config, Path::new(".")).expect("initialize test logger");
    });
}

fn reserve_port_or_skip() -> Result<Option<u16>, Box<dyn std::error::Error>> {
    match reserve_port() {
        Ok(port) => Ok(Some(port)),
        Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
            let _ = writeln!(
                std::io::stderr(),
                "[http_integration] skipping test: loopback sockets are blocked in this environment"
            );
            Ok(None)
        }
        Err(err) => Err(err.into()),
    }
}

async fn start_redirect_server(
    plain_port: u16,
    tls_port: u16,
    allowed_hosts: Vec<String>,
) -> Result<
    (watch::Sender<bool>, tokio::task::JoinHandle<()>, SocketAddr),
    Box<dyn std::error::Error>,
> {
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (port_tx, port_rx) = tokio::sync::oneshot::channel::<Result<u16, String>>();
    let state = Arc::new(RwLock::new(AppState::new()));
    let handle = tokio::spawn(async move {
        rusthost::server::redirect::run_redirect_server(
            rusthost::server::redirect::RedirectServerConfig {
                bind_addr: IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                plain_port,
                tls_port,
                allowed_hosts,
                max_per_ip: 8,
                drain_timeout: Duration::from_secs(5),
            },
            state,
            shutdown_rx,
            port_tx,
            Arc::new(Semaphore::new(8)),
            Arc::new(DashMap::new()),
        )
        .await;
    });

    let bound_port = tokio::time::timeout(Duration::from_secs(5), port_rx)
        .await
        .map_err(|_elapsed| "redirect server did not signal readiness within 5 s")?
        .map_err(|closed| {
            std::io::Error::other(format!("redirect server port channel closed: {closed}"))
        })?
        .map_err(std::io::Error::other)?;

    Ok((
        shutdown_tx,
        handle,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), bound_port),
    ))
}

// ─── Response assertion helpers ───────────────────────────────────────────────

/// `true` when there are no bytes after the `\r\n\r\n` header terminator.
fn body_is_empty(raw: &[u8]) -> Result<bool, Box<dyn std::error::Error>> {
    let text = response_to_str(raw)?;
    // is_none_or: true when the terminator is absent (headers-only buffer) OR
    // when nothing follows it.  Equivalent to the previous map_or but
    // expresses the "no terminator found → treat as empty" intent more
    // directly, and satisfies the clippy::map_or_then lint.
    Ok(text
        .find("\r\n\r\n")
        .is_none_or(|sep| text.len() == sep.saturating_add(4)))
}

/// `true` when `name:` (colon-terminated, case-insensitive) appears in the
/// response headers.  Matches the full header name so that e.g. searching for
/// `"x-frame"` does not accidentally match `"x-frame-options"`.
fn has_header(raw: &[u8], name: &str) -> Result<bool, Box<dyn std::error::Error>> {
    let needle = format!("{}:", name.to_ascii_lowercase());
    let text = response_to_str(raw)?;
    Ok(text
        .lines()
        .skip(1) // skip status line
        .any(|l| l.to_ascii_lowercase().starts_with(&needle)))
}

// ─── Core HTTP flow tests ─────────────────────────────────────────────────────

#[tokio::test(flavor = "current_thread")]
async fn get_index_html_returns_200() -> Result<(), Box<dyn std::error::Error>> {
    let (tmp, site) = make_site(&[("index.html", b"<h1>hello</h1>")])?;
    let Some(server) = start_server_or_skip(&site).await? else {
        return Ok(());
    };

    let response = server
        .send(b"GET /index.html HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await?;
    server.stop().await;
    let _ = tmp; // kept alive until here; explicit binding suppresses lint

    assert_eq!(
        status_code(&response)?,
        200,
        "GET /index.html must return 200:\n{}",
        response_to_str(&response)?
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn get_index_html_returns_200_over_ipv6() -> Result<(), Box<dyn std::error::Error>> {
    let (tmp, site) = make_site(&[("index.html", b"<h1>hello ipv6</h1>")])?;
    let Some(server) =
        start_server_with_bind_or_skip(&site, IpAddr::V6(Ipv6Addr::LOCALHOST), |_| {}).await?
    else {
        return Ok(());
    };

    let response = server
        .send(b"GET /index.html HTTP/1.1\r\nHost: [::1]\r\n\r\n")
        .await?;
    server.stop().await;
    let _ = tmp;

    assert_eq!(status_code(&response)?, 200);
    assert!(response_to_str(&response)?.contains("hello ipv6"));
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn https_self_signed_server_returns_200() -> Result<(), Box<dyn std::error::Error>> {
    let (tmp, site) = make_site(&[("index.html", b"<h1>secure hello</h1>")])?;
    let Some(server) = start_https_server_or_skip(&site).await? else {
        return Ok(());
    };

    let response = server
        .send(b"GET /index.html HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await?;
    server.stop().await;
    let _ = tmp;

    assert_eq!(status_code(&response)?, 200);
    assert_eq!(
        header_value(&response, "strict-transport-security")?.as_deref(),
        Some("max-age=31536000; includeSubDomains")
    );
    assert!(response_to_str(&response)?.contains("secure hello"));
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn https_response_includes_onion_location_when_onion_is_ready(
) -> Result<(), Box<dyn std::error::Error>> {
    let (tmp, site) = make_site(&[("index.html", b"<h1>secure hello</h1>")])?;
    let server = match HttpsTestServer::start_with_state(&site, |state| {
        state.onion_address =
            Some("exampleexampleexampleexampleexampleexampleexampleexample.onion".into());
    })
    .await
    {
        Ok(server) => server,
        Err(err)
            if err.downcast_ref::<std::io::Error>().is_some_and(|io| {
                matches!(
                    io.kind(),
                    std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::AddrNotAvailable
                )
            }) =>
        {
            let _ = writeln!(
                std::io::stderr(),
                "[http_integration] skipping test: loopback sockets are blocked or unavailable in this environment"
            );
            return Ok(());
        }
        Err(err) => return Err(err),
    };

    let response = server
        .send(b"GET /docs/app.js?q=1 HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await?;
    server.stop().await;
    let _ = tmp;

    assert_eq!(
        header_value(&response, "onion-location")?.as_deref(),
        Some("https://exampleexampleexampleexampleexampleexampleexampleexample.onion/docs/app.js?q=1")
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn head_request_returns_headers_no_body() -> Result<(), Box<dyn std::error::Error>> {
    let (tmp, site) = make_site(&[("index.html", b"<h1>hello</h1>")])?;
    let Some(server) = start_server_or_skip(&site).await? else {
        return Ok(());
    };

    let response = server
        .send_no_body(b"HEAD /index.html HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await?;
    server.stop().await;
    let _ = tmp;

    assert_eq!(
        status_code(&response)?,
        200,
        "HEAD must return 200:\n{}",
        response_to_str(&response)?
    );
    assert!(
        has_header(&response, "content-length")?,
        "HEAD must include Content-Length:\n{}",
        response_to_str(&response)?
    );
    assert!(
        body_is_empty(&response)?,
        "HEAD must not include a body:\n{}",
        response_to_str(&response)?
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn get_root_with_index_file_serves_200() -> Result<(), Box<dyn std::error::Error>> {
    let (tmp, site) = make_site(&[("index.html", b"<h1>root</h1>")])?;
    let Some(server) = start_server_or_skip(&site).await? else {
        return Ok(());
    };

    let response = server
        .send(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await?;
    server.stop().await;
    let _ = tmp;

    assert_eq!(
        status_code(&response)?,
        200,
        "GET / must serve index.html (200):\n{}",
        response_to_str(&response)?
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn directory_traversal_returns_403() -> Result<(), Box<dyn std::error::Error>> {
    let (tmp, site) = make_site(&[("index.html", b"safe")])?;
    let Some(server) = start_server_or_skip(&site).await? else {
        return Ok(());
    };

    // Use percent-encoded dot-segments (%2e%2e) so the traversal sequence
    // survives hyper's URI normalisation and reaches the handler intact.
    // A plain `/../` path is canonicalised to `/` before the handler sees it,
    // so the test would verify 404 (file not found) rather than 403 (traversal
    // blocked).
    let response = server
        .send(b"GET /%2e%2e/etc/passwd HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await?;
    server.stop().await;
    let _ = tmp;

    assert_eq!(
        status_code(&response)?,
        403,
        "path traversal must return 403:\n{}",
        response_to_str(&response)?
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn get_nonexistent_file_returns_404() -> Result<(), Box<dyn std::error::Error>> {
    let (tmp, site) = make_site(&[("index.html", b"ok")])?;
    let Some(server) = start_server_or_skip(&site).await? else {
        return Ok(());
    };

    let response = server
        .send(b"GET /nonexistent.txt HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await?;
    server.stop().await;
    let _ = tmp;

    assert_eq!(
        status_code(&response)?,
        404,
        "missing file must return 404:\n{}",
        response_to_str(&response)?
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn last_modified_supports_if_modified_since_revalidation(
) -> Result<(), Box<dyn std::error::Error>> {
    let (tmp, site) = make_site(&[("index.html", b"<h1>cache me</h1>")])?;
    let Some(server) = start_server_or_skip(&site).await? else {
        return Ok(());
    };

    let initial = server
        .send(b"GET /index.html HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await?;
    let last_modified = header_value(&initial, "last-modified")?
        .ok_or("expected Last-Modified header on initial response")?;

    let revalidated = server
        .send(
            format!(
                "GET /index.html HTTP/1.1\r\nHost: localhost\r\nIf-Modified-Since: {last_modified}\r\n\r\n"
            )
            .as_bytes(),
        )
        .await?;

    server.stop().await;
    let _ = tmp;

    assert_eq!(status_code(&revalidated)?, 304);
    assert!(
        body_is_empty(&revalidated)?,
        "304 response must not include a body:\n{}",
        response_to_str(&revalidated)?
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn serves_precompressed_sidecar_when_client_accepts_brotli(
) -> Result<(), Box<dyn std::error::Error>> {
    let (tmp, site) = make_site(&[
        ("app.js", b"console.log('original');"),
        ("app.js.br", b"pretend-brotli-bytes"),
    ])?;
    let Some(server) = start_server_or_skip(&site).await? else {
        return Ok(());
    };

    let response = server
        .send(b"GET /app.js HTTP/1.1\r\nHost: localhost\r\nAccept-Encoding: br, gzip\r\n\r\n")
        .await?;

    server.stop().await;
    let _ = tmp;

    assert_eq!(status_code(&response)?, 200);
    assert_eq!(
        header_value(&response, "content-encoding")?.as_deref(),
        Some("br")
    );
    assert_eq!(
        header_value(&response, "vary")?.as_deref(),
        Some("Accept-Encoding")
    );
    assert!(
        response_to_str(&response)?.contains("pretend-brotli-bytes"),
        "expected server to return sidecar contents:\n{}",
        response_to_str(&response)?
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn if_none_match_takes_precedence_over_if_modified_since(
) -> Result<(), Box<dyn std::error::Error>> {
    let (tmp, site) = make_site(&[("index.html", b"<h1>cache me</h1>")])?;
    let Some(server) = start_server_or_skip(&site).await? else {
        return Ok(());
    };

    let initial = server
        .send(b"GET /index.html HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await?;
    let last_modified = header_value(&initial, "last-modified")?
        .ok_or("expected Last-Modified header on initial response")?;

    let revalidated = server
        .send(
            format!(
                "GET /index.html HTTP/1.1\r\nHost: localhost\r\nIf-None-Match: \"not-current\"\r\nIf-Modified-Since: {last_modified}\r\n\r\n"
            )
            .as_bytes(),
        )
        .await?;

    server.stop().await;
    let _ = tmp;

    assert_eq!(
        status_code(&revalidated)?,
        200,
        "If-Modified-Since must be ignored when If-None-Match is present and does not match:\n{}",
        response_to_str(&revalidated)?
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn precompressed_revalidation_uses_selected_representation_etag(
) -> Result<(), Box<dyn std::error::Error>> {
    let (tmp, site) = make_site(&[
        ("app.js", b"console.log('original');"),
        ("app.js.br", b"pretend-brotli-bytes"),
    ])?;
    let Some(server) = start_server_or_skip(&site).await? else {
        return Ok(());
    };

    let identity = server
        .send(b"GET /app.js HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await?;
    let identity_etag =
        header_value(&identity, "etag")?.ok_or("expected ETag on identity response")?;

    let selected_brotli = server
        .send(
            format!(
                "GET /app.js HTTP/1.1\r\nHost: localhost\r\nAccept-Encoding: br\r\nIf-None-Match: {identity_etag}\r\n\r\n"
            )
            .as_bytes(),
        )
        .await?;

    let brotli = server
        .send(b"GET /app.js HTTP/1.1\r\nHost: localhost\r\nAccept-Encoding: br\r\n\r\n")
        .await?;
    let brotli_etag = header_value(&brotli, "etag")?.ok_or("expected ETag on Brotli response")?;

    let revalidated_brotli = server
        .send(
            format!(
                "GET /app.js HTTP/1.1\r\nHost: localhost\r\nAccept-Encoding: br\r\nIf-None-Match: {brotli_etag}\r\n\r\n"
            )
            .as_bytes(),
        )
        .await?;

    server.stop().await;
    let _ = tmp;

    assert_eq!(status_code(&selected_brotli)?, 200);
    assert_eq!(
        header_value(&selected_brotli, "content-encoding")?.as_deref(),
        Some("br")
    );
    assert!(
        response_to_str(&selected_brotli)?.contains("pretend-brotli-bytes"),
        "identity ETag must not validate the selected Brotli sidecar:\n{}",
        response_to_str(&selected_brotli)?
    );
    assert_eq!(status_code(&revalidated_brotli)?, 304);
    assert_eq!(
        header_value(&revalidated_brotli, "content-encoding")?.as_deref(),
        Some("br")
    );
    assert_eq!(
        header_value(&revalidated_brotli, "vary")?.as_deref(),
        Some("Accept-Encoding")
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn dynamic_compressed_revalidation_preserves_selected_representation_headers(
) -> Result<(), Box<dyn std::error::Error>> {
    let css = b"body{color:#123456;}\n".repeat(128);
    let (tmp, site) = make_site(&[("style.css", &css)])?;
    let Some(server) = start_server_or_skip(&site).await? else {
        return Ok(());
    };

    let initial = server
        .send_no_body(
            b"HEAD /style.css HTTP/1.1\r\nHost: localhost\r\nAccept-Encoding: gzip\r\n\r\n",
        )
        .await?;
    let etag = header_value(&initial, "etag")?.ok_or("expected ETag on gzip HEAD response")?;

    let revalidated = server
        .send_no_body(
            format!(
                "HEAD /style.css HTTP/1.1\r\nHost: localhost\r\nAccept-Encoding: gzip\r\nIf-None-Match: {etag}\r\n\r\n"
            )
            .as_bytes(),
        )
        .await?;

    server.stop().await;
    let _ = tmp;

    assert_eq!(
        header_value(&initial, "content-encoding")?.as_deref(),
        Some("gzip")
    );
    assert_eq!(status_code(&revalidated)?, 304);
    assert_eq!(
        header_value(&revalidated, "content-encoding")?.as_deref(),
        Some("gzip")
    );
    assert_eq!(
        header_value(&revalidated, "vary")?.as_deref(),
        Some("Accept-Encoding")
    );
    assert!(body_is_empty(&revalidated)?);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn disallowed_method_returns_405_with_allow_header() -> Result<(), Box<dyn std::error::Error>>
{
    let (tmp, site) = make_site(&[("index.html", b"ok")])?;
    let Some(server) = start_server_or_skip(&site).await? else {
        return Ok(());
    };

    let response = server
        .send(b"POST /index.html HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n")
        .await?;
    server.stop().await;
    let _ = tmp;

    assert_eq!(
        status_code(&response)?,
        405,
        "POST must return 405 Method Not Allowed (RFC 9110 §15.5.6):\n{}",
        response_to_str(&response)?
    );

    // RFC 9110 §10.2.1: the Allow header MUST be present in a 405 response
    // and MUST list every method the server supports for this resource.  For a
    // static file server the minimum required set is GET and HEAD.
    let allow = header_value(&response, "allow")?.ok_or_else(|| {
        format!(
            "405 response must include an Allow header:\n{}",
            // response_to_str is infallible for ASCII; use unwrap_or so
            // this closure itself stays panic-free.
            response_to_str(&response).unwrap_or("<non-UTF-8 response>")
        )
    })?;

    let allow_upper = allow.to_ascii_uppercase();
    assert!(
        allow_upper.contains("GET"),
        "Allow header must include GET, got: {allow}"
    );
    assert!(
        allow_upper.contains("HEAD"),
        "Allow header must include HEAD, got: {allow}"
    );
    Ok(())
}

// ─── Security header tests ────────────────────────────────────────────────────

#[tokio::test(flavor = "current_thread")]
async fn all_security_headers_present_on_html_response() -> Result<(), Box<dyn std::error::Error>> {
    let (tmp, site) = make_site(&[("index.html", b"<h1>ok</h1>")])?;
    let Some(server) = start_server_or_skip(&site).await? else {
        return Ok(());
    };

    let response = server
        .send(b"GET /index.html HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await?;
    server.stop().await;
    let _ = tmp;

    // All five headers must be present on an HTML response.
    for header in &[
        "x-content-type-options",
        "x-frame-options",
        "referrer-policy",
        "permissions-policy",
        "content-security-policy",
    ] {
        assert!(
            has_header(&response, header)?,
            "missing security header '{header}' on HTML response:\n{}",
            response_to_str(&response)?
        );
    }
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn csp_absent_and_base_headers_present_on_non_html_response(
) -> Result<(), Box<dyn std::error::Error>> {
    let (tmp, site) = make_site(&[("style.css", b"body{color:red}")])?;
    let Some(server) = start_server_or_skip(&site).await? else {
        return Ok(());
    };

    let response = server
        .send(b"GET /style.css HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await?;
    server.stop().await;
    let _ = tmp;

    // The four universal headers must be present on all response types.
    for header in &[
        "x-content-type-options",
        "x-frame-options",
        "referrer-policy",
        "permissions-policy",
    ] {
        assert!(
            has_header(&response, header)?,
            "missing security header '{header}' on CSS response:\n{}",
            response_to_str(&response)?
        );
    }
    // Content-Security-Policy must NOT appear on non-HTML responses.
    assert!(
        !has_header(&response, "content-security-policy")?,
        "CSP must not appear on CSS responses:\n{}",
        response_to_str(&response)?
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn http_response_does_not_include_onion_location() -> Result<(), Box<dyn std::error::Error>> {
    let (tmp, site) = make_site(&[("index.html", b"<h1>ok</h1>")])?;
    let Some(server) = start_server_or_skip(&site).await? else {
        return Ok(());
    };

    let response = server
        .send(b"GET /index.html HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await?;
    server.stop().await;
    let _ = tmp;

    assert_eq!(header_value(&response, "onion-location")?, None);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn custom_503_page_is_served_for_missing_index_root() -> Result<(), Box<dyn std::error::Error>>
{
    let (tmp, site) = make_site(&[("error503.html", b"<h1>offline</h1>")])?;
    let Some(server) = start_server_with_config_or_skip(&site, |config| {
        config.site.error_503 = Some("error503.html".into());
        config.site.enable_directory_listing = false;
    })
    .await?
    else {
        return Ok(());
    };

    let response = server
        .send(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await?;
    server.stop().await;
    let _ = tmp;

    assert_eq!(status_code(&response)?, 503, "expected custom 503 page");
    assert!(
        response_to_str(&response)?.contains("<h1>offline</h1>"),
        "custom 503 page body missing:\n{}",
        response_to_str(&response)?
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn connection_limit_rejects_second_socket() -> Result<(), Box<dyn std::error::Error>> {
    let (tmp, site) = make_site(&[("index.html", b"ok")])?;
    let Some(server) = start_server_with_config_or_skip(&site, |config| {
        config.server.max_connections = 1;
        config.server.max_connections_per_ip = 4;
    })
    .await?
    else {
        return Ok(());
    };

    let mut first = TcpStream::connect(server.addr).await?;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut second = TcpStream::connect(server.addr).await?;
    let write_result = second
        .write_all(b"GET /index.html HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await;

    let rejected = match write_result {
        Ok(()) => {
            let mut buf = [0u8; 256];
            match tokio::time::timeout(Duration::from_secs(2), second.read(&mut buf)).await {
                Ok(Ok(n)) if n > 0 => matches!(status_code(&buf[..n]), Ok(503)),
                Ok(Ok(0)) => true,
                Ok(Err(err))
                    if matches!(
                        err.kind(),
                        std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::BrokenPipe
                    ) =>
                {
                    true
                }
                _ => false,
            }
        }
        Err(err)
            if matches!(
                err.kind(),
                std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::BrokenPipe
            ) =>
        {
            true
        }
        Err(err) => return Err(err.into()),
    };

    first.shutdown().await?;
    server.stop().await;
    let _ = tmp;

    assert!(
        rejected,
        "expected second socket to be rejected at capacity"
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn header_under_limit_is_accepted() -> Result<(), Box<dyn std::error::Error>> {
    init_test_logger();
    let (tmp, site) = make_site(&[("index.html", b"ok")])?;
    let Some(server) = start_server_or_skip(&site).await? else {
        return Ok(());
    };

    let request = format!(
        "GET /index.html HTTP/1.1\r\nHost: localhost\r\nX-Test: {}\r\n\r\n",
        "a".repeat(14_000)
    );
    let response = server.send(request.as_bytes()).await?;

    server.stop().await;
    let _ = tmp;

    assert_eq!(status_code(&response)?, 200);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn oversized_header_returns_431_without_logging_payload(
) -> Result<(), Box<dyn std::error::Error>> {
    init_test_logger();
    let (tmp, site) = make_site(&[("index.html", b"ok")])?;
    let Some(server) = start_server_or_skip(&site).await? else {
        return Ok(());
    };

    let marker = "OVERSIZED_HEADER_MARKER_";
    let request = format!(
        "GET /index.html HTTP/1.1\r\nHost: localhost\r\nX-Test: {}\r\n\r\n",
        marker.repeat(1_000)
    );
    let response = server.send(request.as_bytes()).await?;

    tokio::time::sleep(Duration::from_millis(100)).await;
    let recent_lines = rusthost::logging::recent_lines(1_000);

    server.stop().await;
    let _ = tmp;

    assert_eq!(status_code(&response)?, 431);
    assert!(
        recent_lines
            .iter()
            .any(|line| line.contains("Rejected request with oversized headers")),
        "expected oversized-header warning in recent logs, got: {recent_lines:?}"
    );
    assert!(
        recent_lines.iter().all(|line| !line.contains(marker)),
        "oversized header payload leaked into logs: {recent_lines:?}"
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn site_root_serves_default_ico_favicon() -> Result<(), Box<dyn std::error::Error>> {
    let (tmp, site) = make_site(&[("index.html", b"ok")])?;
    std::fs::write(site.join("favicon.ico"), [0_u8, 0, 1, 0, 1, 0, 16, 16])?;

    let Some(server) = start_server_or_skip(&site).await? else {
        return Ok(());
    };
    let response = server
        .send(b"GET /favicon.ico HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await?;

    server.stop().await;
    let _ = tmp;

    assert_eq!(status_code(&response)?, 200);
    assert_eq!(
        header_value(&response, "content-type")?.as_deref(),
        Some("image/x-icon")
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn missing_favicon_returns_404() -> Result<(), Box<dyn std::error::Error>> {
    let (tmp, site) = make_site(&[("index.html", b"ok")])?;
    let Some(server) = start_server_or_skip(&site).await? else {
        return Ok(());
    };

    let response = server
        .send(b"GET /favicon.ico HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await?;

    server.stop().await;
    let _ = tmp;

    assert_eq!(status_code(&response)?, 404);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn png_favicon_is_served_when_enabled() -> Result<(), Box<dyn std::error::Error>> {
    let (tmp, site) = make_site(&[("index.html", b"ok")])?;
    std::fs::write(site.join("custom.png"), [137, 80, 78, 71])?;

    let Some(server) = start_server_with_config_or_skip(&site, |config| {
        config.site.favicon = "custom.png".into();
        config.site.enable_png_favicon = true;
    })
    .await?
    else {
        return Ok(());
    };

    let response = server
        .send_no_body(b"HEAD /favicon.png HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await?;

    server.stop().await;
    let _ = tmp;

    assert_eq!(status_code(&response)?, 200);
    assert_eq!(
        header_value(&response, "content-type")?.as_deref(),
        Some("image/png")
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn custom_favicon_cannot_expose_runtime_private_file(
) -> Result<(), Box<dyn std::error::Error>> {
    let (tmp, site) = make_site(&[("index.html", b"ok")])?;
    std::fs::create_dir_all(tmp.path().join("runtime/logs"))?;
    std::fs::write(tmp.path().join("runtime/logs/private.png"), [1, 2, 3, 4])?;

    let Some(server) = start_server_with_config_or_skip(&site, |config| {
        config.site.favicon = "../runtime/logs/private.png".into();
        config.site.enable_png_favicon = true;
    })
    .await?
    else {
        return Ok(());
    };

    let response = server
        .send(b"GET /favicon.png HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await?;

    server.stop().await;
    let _ = tmp;

    assert_eq!(status_code(&response)?, 403);
    Ok(())
}

#[cfg(unix)]
#[tokio::test(flavor = "current_thread")]
async fn custom_favicon_symlink_escape_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::symlink;

    let (tmp, site) = make_site(&[("index.html", b"ok")])?;
    let outside = tmp.path().join("outside.png");
    std::fs::write(&outside, [137, 80, 78, 71])?;
    symlink(&outside, site.join("link.png"))?;

    let Some(server) = start_server_with_config_or_skip(&site, |config| {
        config.site.favicon = "link.png".into();
        config.site.enable_png_favicon = true;
    })
    .await?
    else {
        return Ok(());
    };

    let response = server
        .send(b"GET /favicon.png HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await?;

    server.stop().await;
    let _ = tmp;

    assert_eq!(status_code(&response)?, 403);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn occupied_http_port_reports_actionable_bind_error() -> Result<(), Box<dyn std::error::Error>>
{
    let (tmp, site) = make_site(&[("index.html", b"ok")])?;
    let occupied =
        std::net::TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))?;
    let occupied_port = occupied.local_addr()?.port();

    let mut config = build_test_config(&site, IpAddr::V4(Ipv4Addr::LOCALHOST), occupied_port)?;
    config.server.max_connections = 16;
    let config = Arc::new(config);
    let state = Arc::new(RwLock::new(AppState::new()));
    let metrics = Arc::new(Metrics::new());
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (port_tx, port_rx) = tokio::sync::oneshot::channel::<Result<u16, String>>();
    let data_dir = site.parent().unwrap_or(&site).to_path_buf();
    let site_root_arc: Arc<Path> = Arc::from(data_dir.join(&config.site.directory).as_path());
    let (root_tx, root_rx) = watch::channel(site_root_arc);
    let conn_semaphore: Arc<Semaphore> =
        Arc::new(Semaphore::new(config.server.max_connections as usize));
    let ip_connections: Arc<DashMap<IpAddr, Arc<AtomicU32>>> = Arc::new(DashMap::new());

    let handle = tokio::spawn({
        let cfg = Arc::clone(&config);
        let st = Arc::clone(&state);
        let met = Arc::clone(&metrics);
        async move {
            rusthost::server::run(
                cfg,
                st,
                met,
                data_dir,
                shutdown_rx,
                port_tx,
                root_rx,
                conn_semaphore,
                ip_connections,
            )
            .await;
        }
    });

    let bind_result = tokio::time::timeout(Duration::from_secs(5), port_rx)
        .await
        .map_err(|_elapsed| "timed out waiting for occupied-port startup result")?
        .map_err(|_closed| "occupied-port startup channel closed")?;

    let _ = shutdown_tx.send(true);
    drop(root_tx);
    let _ = tokio::time::timeout(Duration::from_secs(5), handle).await;
    drop(occupied);
    let _ = tmp;

    let message = bind_result.expect_err("startup should fail when the port is occupied");
    let lower = message.to_ascii_lowercase();
    assert!(message.contains("HTTP listener"));
    assert!(message.contains(&format!("127.0.0.1:{occupied_port}")));
    assert!(
        lower.contains("already in use") || lower.contains("address in use"),
        "expected address-in-use wording, got: {message}"
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn redirect_server_returns_https_location() -> Result<(), Box<dyn std::error::Error>> {
    let Some(plain_port) = reserve_port_or_skip()? else {
        return Ok(());
    };
    let tls_port = 8443;
    let (shutdown_tx, handle, addr) =
        start_redirect_server(plain_port, tls_port, vec!["example.com".into()]).await?;
    let mut stream = match TcpStream::connect(addr).await {
        Ok(stream) => stream,
        Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
            let _ = shutdown_tx.send(true);
            let _ = tokio::time::timeout(Duration::from_secs(5), handle).await;
            let _ = writeln!(
                std::io::stderr(),
                "[http_integration] skipping test: loopback sockets are blocked in this environment"
            );
            return Ok(());
        }
        Err(err) => return Err(err.into()),
    };
    stream
        .write_all(b"GET /docs?q=1 HTTP/1.1\r\nHost: example.com:80\r\n\r\n")
        .await?;
    let response = read_headers_only(&mut stream).await?;

    let _ = shutdown_tx.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(5), handle).await;

    assert_eq!(
        status_code(&response)?,
        301,
        "redirect server must return 301"
    );
    assert_eq!(
        header_value(&response, "location")?.as_deref(),
        Some("https://example.com:8443/docs?q=1")
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn redirect_server_rejects_unconfigured_host_header() -> Result<(), Box<dyn std::error::Error>>
{
    let Some(plain_port) = reserve_port_or_skip()? else {
        return Ok(());
    };
    let (shutdown_tx, handle, addr) =
        start_redirect_server(plain_port, 8443, vec!["localhost".into()]).await?;
    let mut stream = TcpStream::connect(addr).await?;
    stream
        .write_all(b"GET /index.html HTTP/1.1\r\nHost: attacker.example\r\n\r\n")
        .await?;
    let response = read_headers_only(&mut stream).await?;

    let _ = shutdown_tx.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(5), handle).await;

    assert_eq!(status_code(&response)?, 400);
    assert_ne!(
        header_value(&response, "location")?.as_deref(),
        Some("https://attacker.example:8443/index.html")
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn redirect_server_accepts_loopback_host_and_preserves_query(
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(plain_port) = reserve_port_or_skip()? else {
        return Ok(());
    };
    let tls_port = 9443;
    let (shutdown_tx, handle, addr) = start_redirect_server(
        plain_port,
        tls_port,
        vec!["localhost".into(), "127.0.0.1".into(), "[::1]".into()],
    )
    .await?;
    let mut stream = TcpStream::connect(addr).await?;
    let request = format!("GET /index.html?x=1 HTTP/1.1\r\nHost: 127.0.0.1:{plain_port}\r\n\r\n");
    stream.write_all(request.as_bytes()).await?;
    let response = read_headers_only(&mut stream).await?;

    let _ = shutdown_tx.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(5), handle).await;

    assert_eq!(status_code(&response)?, 301);
    assert_eq!(
        header_value(&response, "location")?.as_deref(),
        Some("https://127.0.0.1:9443/index.html?x=1")
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn redirect_server_rejects_malformed_host_forms() -> Result<(), Box<dyn std::error::Error>> {
    let Some(plain_port) = reserve_port_or_skip()? else {
        return Ok(());
    };
    let (shutdown_tx, handle, addr) =
        start_redirect_server(plain_port, 8443, vec!["localhost".into(), "[::1]".into()]).await?;

    for host in [
        "evil.com@legit.com",
        "example.com:abc",
        "[::1]:bad",
        "[::1:8443",
        "http://localhost",
        "localhost/path",
        "localhost\\path",
        "localhost:65536",
        "localhost:0",
    ] {
        let mut stream = TcpStream::connect(addr).await?;
        let request = format!("GET / HTTP/1.1\r\nHost: {host}\r\n\r\n");
        stream.write_all(request.as_bytes()).await?;
        let response = read_headers_only(&mut stream).await?;
        let response_text = response_to_str(&response)?;
        assert_eq!(status_code(&response)?, 400, "host={host}");
        assert_eq!(header_value(&response, "location")?, None, "host={host}");
        assert!(
            !response_text.contains("https://127.0.0.1:8443/"),
            "host={host}; response={response_text}"
        );
        assert!(
            !response_text.contains("https://localhost:8443/"),
            "host={host}; response={response_text}"
        );
    }

    let _ = shutdown_tx.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(5), handle).await;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn redirect_server_ignores_x_forwarded_host_spoofing(
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(plain_port) = reserve_port_or_skip()? else {
        return Ok(());
    };
    let (shutdown_tx, handle, addr) =
        start_redirect_server(plain_port, 8443, vec!["localhost".into()]).await?;
    let mut stream = TcpStream::connect(addr).await?;
    stream
        .write_all(
            b"GET / HTTP/1.1\r\nHost: localhost\r\nX-Forwarded-Host: attacker.example\r\n\r\n",
        )
        .await?;
    let response = read_headers_only(&mut stream).await?;

    let _ = shutdown_tx.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(5), handle).await;

    assert_eq!(status_code(&response)?, 301);
    assert_eq!(
        header_value(&response, "location")?.as_deref(),
        Some("https://localhost:8443/")
    );
    Ok(())
}
