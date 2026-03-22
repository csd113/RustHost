//! # HTTP Server Integration Tests (task 5.2)
//!
//! Each test spins up an isolated [`rusthost::server::run`] instance, connects
//! to it via [`tokio::net::TcpStream`], sends raw HTTP/1.1, and inspects the
//! raw response bytes.
//!
//! ## Port allocation
//!
//! Each test calls [`free_port()`] which binds a `StdTcpListener` on
//! `127.0.0.1:0`, reads the OS-assigned port, and immediately closes the
//! listener.  That port is then passed to the test config with
//! `auto_port_fallback = false`, so the server binds the same (now-free) port.
//! The TOCTOU window between release and server bind is acceptable on the
//! loopback interface and eliminates the port-collision risk that would arise
//! from having every test start from port 8080.

use std::{net::SocketAddr, path::Path, sync::Arc, time::Duration};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::{watch, RwLock},
};

use rusthost::{
    config::Config,
    runtime::state::{AppState, Metrics},
};

// ─── Port helper ──────────────────────────────────────────────────────────────

/// Ask the OS for a free port by binding on `0`, then release it.
///
/// Returns the port number for immediate use as the test server's bind port.
/// `auto_port_fallback` is set to `false` in the test config so the server
/// always binds exactly this port rather than searching a range.
fn free_port() -> Result<u16, std::io::Error> {
    use std::net::TcpListener;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    Ok(listener.local_addr()?.port())
    // listener is dropped here, releasing the port
}

// ─── Test harness ─────────────────────────────────────────────────────────────

/// A live server instance scoped to one test.
struct TestServer {
    addr: SocketAddr,
    shutdown_tx: watch::Sender<bool>,
    handle: Option<tokio::task::JoinHandle<()>>,
}

impl TestServer {
    /// Spin up a server bound to the port returned by [`free_port()`].
    ///
    /// `site_root` must already contain the files the test expects to serve.
    async fn start(site_root: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let port = free_port()?;
        let config = Arc::new(build_test_config(site_root, port));
        let state = Arc::new(RwLock::new(AppState::new()));
        let metrics = Arc::new(Metrics::new());
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let (port_tx, port_rx) = tokio::sync::oneshot::channel::<u16>();

        // The server joins data_dir + config.site.directory to find files.
        // `site_root` is `<tmp>/site`; `data_dir` must therefore be `<tmp>`.
        let data_dir = site_root.parent().unwrap_or(site_root).to_path_buf();

        let handle = {
            let cfg = Arc::clone(&config);
            let st = Arc::clone(&state);
            let met = Arc::clone(&metrics);
            let shut = shutdown_rx;
            tokio::spawn(async move {
                rusthost::server::run(cfg, st, met, data_dir, shut, port_tx).await;
            })
        };

        // Wait for the server to confirm its bound port (5 s guard).
        let bound_port = tokio::time::timeout(Duration::from_secs(5), port_rx).await??;

        let addr: SocketAddr = format!("127.0.0.1:{bound_port}").parse()?;

        Ok(Self {
            addr,
            shutdown_tx,
            handle: Some(handle),
        })
    }

    /// Send raw `request` bytes and return the complete response as a `String`.
    ///
    /// A 5-second read deadline prevents a misbehaving server from hanging the
    /// test suite indefinitely.
    async fn send(&self, request: &[u8]) -> Result<String, Box<dyn std::error::Error>> {
        let mut stream = TcpStream::connect(self.addr).await?;
        stream.write_all(request).await?;

        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), async {
            let mut buf = [0u8; 4096];
            loop {
                let n = stream.read(&mut buf).await?;
                if n == 0 {
                    break;
                }
                let slice = buf
                    .get(..n)
                    .ok_or_else(|| std::io::Error::other("read returned out-of-bounds length"))?;
                response.extend_from_slice(slice);
            }
            Ok::<_, std::io::Error>(())
        })
        .await??;

        Ok(String::from_utf8_lossy(&response).into_owned())
    }

    /// Gracefully shut the server down and await task exit.
    async fn stop(mut self) {
        let _ = self.shutdown_tx.send(true);
        if let Some(handle) = self.handle.take() {
            tokio::time::timeout(Duration::from_secs(5), handle)
                .await
                .ok();
        }
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        // Best-effort signal if the test panics before calling `stop()`.
        let _ = self.shutdown_tx.send(true);
    }
}

// ─── Config + fixture helpers ─────────────────────────────────────────────────

/// Build a minimal [`Config`] whose site directory matches `site_root`.
fn build_test_config(site_root: &Path, port: u16) -> Config {
    use std::num::NonZeroU16;

    let mut config = Config::default();
    config.server.port = NonZeroU16::new(port).unwrap_or(NonZeroU16::MIN);
    // auto_port_fallback = false: the server must bind exactly `port`.
    config.server.auto_port_fallback = false;
    config.server.open_browser_on_start = false;
    config.server.max_connections = 16;
    // Use the directory basename; server joins data_dir + this name.
    config.site.directory = String::from(
        site_root
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("site"),
    );
    config.site.index_file = "index.html".into();
    config.site.enable_directory_listing = false;
    config.tor.enabled = false;
    config.console.interactive = false;
    config
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

// ─── Response assertion helpers ───────────────────────────────────────────────

/// Extract the numeric HTTP status code from the response status line.
fn status_code(response: &str) -> Option<u16> {
    response.split_whitespace().nth(1)?.parse().ok()
}

/// `true` when there are no bytes after the `\r\n\r\n` header terminator.
fn body_is_empty(response: &str) -> bool {
    response
        .find("\r\n\r\n")
        .is_none_or(|sep| response.len() == sep.saturating_add(4))
}

/// `true` when the named header appears in the response (case-insensitive).
fn has_header(response: &str, name: &str) -> bool {
    let name_lc = name.to_ascii_lowercase();
    response
        .lines()
        .skip(1) // skip status line
        .any(|l| l.to_ascii_lowercase().starts_with(&name_lc))
}

// ─── Core HTTP flow tests (task 5.2) ─────────────────────────────────────────

#[tokio::test]
async fn get_index_html_returns_200() -> Result<(), Box<dyn std::error::Error>> {
    let (tmp, site) = make_site(&[("index.html", b"<h1>hello</h1>")])?;
    let server = TestServer::start(&site).await?;

    let response = server
        .send(b"GET /index.html HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await?;
    server.stop().await;
    drop(tmp);

    assert_eq!(
        status_code(&response),
        Some(200),
        "GET /index.html must return 200:\n{response}"
    );
    Ok(())
}

#[tokio::test]
async fn head_request_returns_headers_no_body() -> Result<(), Box<dyn std::error::Error>> {
    let (tmp, site) = make_site(&[("index.html", b"<h1>hello</h1>")])?;
    let server = TestServer::start(&site).await?;

    let response = server
        .send(b"HEAD /index.html HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await?;
    server.stop().await;
    drop(tmp);

    assert_eq!(
        status_code(&response),
        Some(200),
        "HEAD must return 200:\n{response}"
    );
    assert!(
        has_header(&response, "content-length"),
        "HEAD must include Content-Length:\n{response}"
    );
    assert!(
        body_is_empty(&response),
        "HEAD must not include a body:\n{response}"
    );
    Ok(())
}

#[tokio::test]
async fn get_root_with_index_file_serves_200() -> Result<(), Box<dyn std::error::Error>> {
    let (tmp, site) = make_site(&[("index.html", b"<h1>root</h1>")])?;
    let server = TestServer::start(&site).await?;

    let response = server
        .send(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await?;
    server.stop().await;
    drop(tmp);

    assert_eq!(
        status_code(&response),
        Some(200),
        "GET / must serve index.html (200):\n{response}"
    );
    Ok(())
}

#[tokio::test]
async fn directory_traversal_returns_403() -> Result<(), Box<dyn std::error::Error>> {
    let (tmp, site) = make_site(&[("index.html", b"safe")])?;
    let server = TestServer::start(&site).await?;

    let response = server
        .send(b"GET /../etc/passwd HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await?;
    server.stop().await;
    drop(tmp);

    assert_eq!(
        status_code(&response),
        Some(403),
        "traversal must return 403:\n{response}"
    );
    Ok(())
}

#[tokio::test]
async fn oversized_request_header_returns_400() -> Result<(), Box<dyn std::error::Error>> {
    let (tmp, site) = make_site(&[("index.html", b"ok")])?;
    let server = TestServer::start(&site).await?;

    // Build headers that exceed the 8 KiB limit enforced by `read_request`.
    let padding = format!("X-Padding: {}\r\n", "A".repeat(8_300));
    let request = format!("GET / HTTP/1.1\r\nHost: localhost\r\n{padding}\r\n");

    let response = server.send(request.as_bytes()).await?;
    server.stop().await;
    drop(tmp);

    assert_eq!(
        status_code(&response),
        Some(400),
        "oversized headers must return 400:\n{response}"
    );
    Ok(())
}

#[tokio::test]
async fn get_nonexistent_file_returns_404() -> Result<(), Box<dyn std::error::Error>> {
    let (tmp, site) = make_site(&[("index.html", b"ok")])?;
    let server = TestServer::start(&site).await?;

    let response = server
        .send(b"GET /nonexistent.txt HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await?;
    server.stop().await;
    drop(tmp);

    assert_eq!(
        status_code(&response),
        Some(404),
        "missing file must return 404:\n{response}"
    );
    Ok(())
}

// fix H-11 — this test previously asserted status 400 for a POST request,
// which encoded the *incorrect* behaviour (RFC 9110 §15.5.6 requires 405 +
// Allow header for known-but-disallowed methods).  The old assertion would
// pass when the bug was present and fail when it was fixed, causing developers
// to mistakenly revert the H-4 fix to make CI green again.
#[tokio::test]
async fn disallowed_method_returns_405_with_allow_header() -> Result<(), Box<dyn std::error::Error>>
{
    let (tmp, site) = make_site(&[("index.html", b"ok")])?;
    let server = TestServer::start(&site).await?;

    let response = server
        .send(b"POST /index.html HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n")
        .await?;
    server.stop().await;
    drop(tmp);

    assert_eq!(
        status_code(&response),
        Some(405),
        "POST must return 405 Method Not Allowed (RFC 9110 §15.5.6):\n{response}"
    );
    assert!(
        has_header(&response, "allow"),
        "405 response must include Allow header:\n{response}"
    );
    Ok(())
}

// ─── Security header tests (task 5.3 — integration verification) ─────────────

#[tokio::test]
async fn all_security_headers_present_on_html_response() -> Result<(), Box<dyn std::error::Error>> {
    let (tmp, site) = make_site(&[("index.html", b"<h1>ok</h1>")])?;
    let server = TestServer::start(&site).await?;

    let response = server
        .send(b"GET /index.html HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await?;
    server.stop().await;
    drop(tmp);

    // All five headers must be present on an HTML response.
    for header in &[
        "x-content-type-options",
        "x-frame-options",
        "referrer-policy",
        "permissions-policy",
        "content-security-policy",
    ] {
        assert!(
            has_header(&response, header),
            "missing security header '{header}' on HTML:\n{response}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn csp_absent_and_base_headers_present_on_non_html_response(
) -> Result<(), Box<dyn std::error::Error>> {
    let (tmp, site) = make_site(&[("style.css", b"body{color:red}")])?;
    let server = TestServer::start(&site).await?;

    let response = server
        .send(b"GET /style.css HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await?;
    server.stop().await;
    drop(tmp);

    // The four universal headers must be present on all response types.
    for header in &[
        "x-content-type-options",
        "x-frame-options",
        "referrer-policy",
        "permissions-policy",
    ] {
        assert!(
            has_header(&response, header),
            "missing security header '{header}' on CSS:\n{response}"
        );
    }
    // Content-Security-Policy must NOT appear on non-HTML responses.
    assert!(
        !has_header(&response, "content-security-policy"),
        "CSP must not appear on CSS responses:\n{response}"
    );
    Ok(())
}
