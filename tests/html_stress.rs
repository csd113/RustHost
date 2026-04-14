//! HTML stress-test suite for `RustHost`.
//!
//! This test serves the fixture tree under `tests/fixtures/html_stress` through
//! the real HTTP server, then hammers it with a mixed workload:
//! - repeated keep-alive requests on the same connection
//! - concurrent clients
//! - HTML, CSS, JS, SVG, directory listing, and percent-encoded paths
//! - a generated large HTML page with range requests

use std::{
    fmt::Write as _,
    fs,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use dashmap::DashMap;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::{watch, RwLock, Semaphore},
};

use rusthost::{
    config::Config,
    runtime::state::{AppState, Metrics},
};

fn reserve_port() -> Result<u16, std::io::Error> {
    let listener =
        std::net::TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))?;
    Ok(listener.local_addr()?.port())
}

fn fixture_site_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("html_stress")
}

fn materialize_large_page(site_root: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let large_path = site_root.join("pages/huge.html");
    let mut body = String::from(
        "<!doctype html>\n<html lang=\"en\">\n<head>\n  <meta charset=\"utf-8\">\n  <title>Huge page</title>\n</head>\n<body>\n  <h1>Huge page</h1>\n  <pre>\n",
    );
    for i in 0..4096 {
        let _ = writeln!(body, "line {i:04}: RustHost static stress body");
    }
    body.push_str("  </pre>\n</body>\n</html>\n");
    fs::write(large_path, body)?;
    Ok(())
}

fn copy_tree(src: &Path, dst: &Path) -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        if ty.is_dir() {
            copy_tree(&src_path, &dst_path)?;
        } else if ty.is_file() {
            fs::copy(&src_path, &dst_path)?;
        }
    }
    Ok(())
}

fn build_site_copy() -> Result<(tempfile::TempDir, PathBuf), Box<dyn std::error::Error>> {
    let tmp = tempfile::tempdir()?;
    let site = tmp.path().join("site");
    copy_tree(&fixture_site_root(), &site)?;
    materialize_large_page(&site)?;
    Ok((tmp, site))
}

fn build_test_config(
    site_root: &Path,
    bind_addr: IpAddr,
    port: u16,
) -> Result<Config, Box<dyn std::error::Error>> {
    use std::num::NonZeroU16;

    let dir_name = site_root
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or("site_root must have a valid UTF-8 directory name")?
        .to_owned();

    let mut config = Config::default();
    config.server.port = NonZeroU16::new(port).ok_or("reserved port cannot be zero")?;
    config.server.bind = bind_addr;
    config.server.auto_port_fallback = false;
    config.server.open_browser_on_start = false;
    config.server.max_connections = 128;
    config.server.max_connections_per_ip = 128;
    config.server.shutdown_grace_secs = 5;
    config.site.directory = dir_name;
    config.site.index_file = "index.html".into();
    config.site.enable_directory_listing = true;
    config.site.spa_routing = false;
    config.tor.enabled = false;
    config.console.interactive = false;
    Ok(config)
}

fn response_to_str(raw: &[u8]) -> Result<&str, Box<dyn std::error::Error>> {
    std::str::from_utf8(raw)
        .map_err(|e| format!("response contained non-UTF-8 bytes (error: {e}):\n{raw:?}").into())
}

fn status_code(raw: &[u8]) -> Result<u16, Box<dyn std::error::Error>> {
    let text = response_to_str(raw)?;
    text.split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| format!("malformed status line in response:\n{text}").into())
}

fn header_value(raw: &[u8], name: &str) -> Result<Option<String>, Box<dyn std::error::Error>> {
    let needle = format!("{}:", name.to_ascii_lowercase());
    let text = response_to_str(raw)?;
    Ok(text
        .lines()
        .skip(1)
        .find(|l| l.to_ascii_lowercase().starts_with(&needle))
        .and_then(|l| l.split_once(':').map(|(_, v)| v.trim().to_owned())))
}

fn body_bytes(raw: &[u8]) -> Result<&[u8], Box<dyn std::error::Error>> {
    let text = response_to_str(raw)?;
    let sep = text
        .find("\r\n\r\n")
        .ok_or("response missing header terminator")?;
    Ok(raw
        .get(sep + 4..)
        .ok_or("response body slice out of bounds")?)
}

fn find_header_end(buf: &[u8], search_from: usize) -> Option<usize> {
    let tail = buf.get(search_from..)?;
    let pos = tail.windows(4).position(|w| w == b"\r\n\r\n")?;
    Some(search_from.saturating_add(pos).saturating_add(4))
}

async fn read_one_response<S>(stream: &mut S) -> Result<Vec<u8>, Box<dyn std::error::Error>>
where
    S: AsyncRead + Unpin,
{
    let mut buf = Vec::with_capacity(4096);
    let mut staging = [0u8; 4096];
    let header_end;

    loop {
        let search_from = buf.len().saturating_sub(3);
        let n = stream.read(&mut staging).await?;
        if n == 0 {
            return Err("connection closed before \\r\\n\\r\\n header terminator".into());
        }
        buf.extend_from_slice(
            staging
                .get(..n)
                .ok_or("read returned more bytes than the staging buffer can hold")?,
        );
        if let Some(end) = find_header_end(&buf, search_from) {
            header_end = end;
            break;
        }
    }

    let header_bytes = buf.get(..header_end).ok_or("header_end is out of bounds")?;
    let header_str = std::str::from_utf8(header_bytes)
        .map_err(|e| format!("response headers are not valid UTF-8: {e}"))?;

    let status: u16 = header_str
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    let content_length: usize = header_str
        .lines()
        .find(|l| l.to_ascii_lowercase().starts_with("content-length:"))
        .and_then(|l| l.split_once(':').map(|x| x.1))
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(0);

    let has_body = content_length > 0 && !matches!(status, 204 | 304);

    if !has_body {
        buf.truncate(header_end);
        return Ok(buf);
    }

    let already_have = buf.len().saturating_sub(header_end);
    let total_needed = header_end
        .checked_add(content_length)
        .ok_or("Content-Length value causes usize overflow")?;

    if already_have < content_length {
        buf.resize(total_needed, 0);
        let fill_start = header_end
            .checked_add(already_have)
            .ok_or("fill_start overflows usize")?;
        let body_slice = buf
            .get_mut(fill_start..total_needed)
            .ok_or("body slice range is out of bounds")?;
        stream.read_exact(body_slice).await?;
    } else {
        buf.truncate(total_needed);
    }

    Ok(buf)
}

async fn read_headers_only<S>(stream: &mut S) -> Result<Vec<u8>, Box<dyn std::error::Error>>
where
    S: AsyncRead + Unpin,
{
    let mut buf = Vec::with_capacity(4096);
    let mut staging = [0u8; 4096];

    loop {
        let search_from = buf.len().saturating_sub(3);
        let n = stream.read(&mut staging).await?;
        if n == 0 {
            return Err("connection closed before \\r\\n\\r\\n header terminator".into());
        }
        buf.extend_from_slice(
            staging
                .get(..n)
                .ok_or("read returned more bytes than the staging buffer can hold")?,
        );
        if let Some(end) = find_header_end(&buf, search_from) {
            buf.truncate(end);
            return Ok(buf);
        }
    }
}

async fn read_response(
    stream: &mut TcpStream,
    request: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    stream.write_all(request).await?;
    read_one_response(stream).await
}

struct TestServer {
    addr: SocketAddr,
    shutdown_tx: watch::Sender<bool>,
    _root_tx: watch::Sender<Arc<Path>>,
    handle: Option<tokio::task::JoinHandle<()>>,
}

impl TestServer {
    async fn start(site_root: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let port = reserve_port()?;
        let data_dir = site_root.parent().unwrap_or(site_root).to_path_buf();
        let config = Arc::new(build_test_config(
            site_root,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            port,
        )?);
        let state = Arc::new(RwLock::new(AppState::new()));
        let metrics = Arc::new(Metrics::new());
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let (port_tx, port_rx) = tokio::sync::oneshot::channel::<u16>();

        let joined = data_dir.join(&config.site.directory);
        let site_root_arc: Arc<Path> = Arc::from(joined.as_path());
        let (root_tx, root_rx) = watch::channel(site_root_arc);

        let conn_semaphore = Arc::new(Semaphore::new(config.server.max_connections as usize));
        let ip_connections = Arc::new(DashMap::new());

        let handle = {
            let cfg = Arc::clone(&config);
            let st = Arc::clone(&state);
            let met = Arc::clone(&metrics);
            tokio::spawn(async move {
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
            })
        };

        let bound_port = tokio::time::timeout(Duration::from_secs(5), port_rx)
            .await
            .map_err(|_| "timed out waiting for server to report its bound port")?
            .map_err(|_| "server port channel closed before sending")?;

        Ok(Self {
            addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), bound_port),
            shutdown_tx,
            _root_tx: root_tx,
            handle: Some(handle),
        })
    }

    async fn stop(mut self) -> Result<(), Box<dyn std::error::Error>> {
        let _ = self.shutdown_tx.send(true);
        if let Some(handle) = self.handle.take() {
            match tokio::time::timeout(Duration::from_secs(5), handle).await {
                Ok(Ok(())) => Ok(()),
                Ok(Err(e)) => Err(format!("[TestServer] server task panicked: {e}").into()),
                Err(_) => Err("server shutdown timed out after 5 s".into()),
            }
        } else {
            Ok(())
        }
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        let _ = self.shutdown_tx.send(true);
        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
    }
}

async fn request_paths_over_connection(
    addr: SocketAddr,
    requests: &[Vec<u8>],
) -> Result<(), Box<dyn std::error::Error>> {
    let mut stream = TcpStream::connect(addr).await?;
    for request in requests {
        let response = if request.starts_with(b"HEAD ") {
            stream.write_all(request).await?;
            read_headers_only(&mut stream).await?
        } else {
            read_response(&mut stream, request).await?
        };
        let status = status_code(&response)?;
        match request.as_slice() {
            req if req.starts_with(b"GET / HTTP/1.1") => {
                assert_eq!(status, 200);
                assert!(response_to_str(&response)?.contains("RustHost Stress Suite"));
            }
            req if req.starts_with(b"HEAD ") => {
                assert_eq!(status, 200);
                assert!(body_bytes(&response)?.is_empty());
            }
            req if req.starts_with(b"GET /gallery/ ") => {
                assert_eq!(status, 200);
                assert!(response_to_str(&response)?.contains("thumb-a.txt"));
            }
            req if req.starts_with(b"GET /pages/space%20name.html ") => {
                assert_eq!(status, 200);
                assert!(response_to_str(&response)?.contains("Filename with a space"));
            }
            req if req.starts_with(b"GET /assets/logo.svg ") => {
                assert_eq!(status, 200);
                assert_eq!(
                    header_value(&response, "content-type")?.as_deref(),
                    Some("image/svg+xml")
                );
            }
            req if req.starts_with(b"GET /styles/app.css ") => {
                assert_eq!(status, 200);
                assert!(response_to_str(&response)?.contains("--accent"));
            }
            req if req.starts_with(b"GET /scripts/app.js ") => {
                assert_eq!(status, 200);
                assert!(response_to_str(&response)?.contains("__rusthostStressSuite"));
            }
            req if req.starts_with(b"GET /pages/about.html ") => {
                assert_eq!(status, 200);
                assert!(response_to_str(&response)?.contains("About this fixture"));
            }
            req if req.starts_with(b"GET /pages/nested/index.html ") => {
                assert_eq!(status, 200);
                assert!(response_to_str(&response)?.contains("Nested index page"));
            }
            _ => {
                return Err(format!("unexpected request pattern: {request:?}").into());
            }
        }
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn html_fixture_survives_bursty_keep_alive_load() -> Result<(), Box<dyn std::error::Error>> {
    let (tmp, site_root) = build_site_copy()?;
    let server = TestServer::start(&site_root).await?;

    let mut root_stream = TcpStream::connect(server.addr).await?;
    let root_response = read_response(
        &mut root_stream,
        b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n",
    )
    .await?;
    assert_eq!(status_code(&root_response)?, 200);
    assert!(response_to_str(&root_response)?.contains("RustHost Stress Suite"));

    let mut head_stream = TcpStream::connect(server.addr).await?;
    head_stream
        .write_all(b"HEAD /index.html HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await?;
    let head_response = read_headers_only(&mut head_stream).await?;
    assert_eq!(status_code(&head_response)?, 200);
    assert!(body_bytes(&head_response)?.is_empty());

    let mut range_stream = TcpStream::connect(server.addr).await?;
    let huge_range = read_response(
        &mut range_stream,
        b"GET /pages/huge.html HTTP/1.1\r\nHost: localhost\r\nRange: bytes=0-255\r\n\r\n",
    )
    .await?;
    assert_eq!(status_code(&huge_range)?, 206);
    assert!(
        header_value(&huge_range, "content-range")?
            .as_deref()
            .is_some_and(|v| v.starts_with("bytes 0-255/")),
        "expected a partial-content response with a valid Content-Range header"
    );
    drop(root_stream);
    drop(head_stream);
    drop(range_stream);

    let burst_requests = vec![
        b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n".to_vec(),
        b"GET /styles/app.css HTTP/1.1\r\nHost: localhost\r\n\r\n".to_vec(),
        b"GET /scripts/app.js HTTP/1.1\r\nHost: localhost\r\n\r\n".to_vec(),
        b"GET /assets/logo.svg HTTP/1.1\r\nHost: localhost\r\n\r\n".to_vec(),
        b"GET /pages/about.html HTTP/1.1\r\nHost: localhost\r\n\r\n".to_vec(),
        b"GET /pages/nested/index.html HTTP/1.1\r\nHost: localhost\r\n\r\n".to_vec(),
        b"GET /pages/space%20name.html HTTP/1.1\r\nHost: localhost\r\n\r\n".to_vec(),
        b"GET /gallery/ HTTP/1.1\r\nHost: localhost\r\n\r\n".to_vec(),
        b"HEAD /pages/about.html HTTP/1.1\r\nHost: localhost\r\n\r\n".to_vec(),
    ];

    let mut tasks = Vec::new();
    for task_idx in 0..32usize {
        let addr = server.addr;
        let mut requests = Vec::new();
        for round in 0..16usize {
            let idx = (task_idx + round) % burst_requests.len();
            requests.push(burst_requests[idx].clone());
        }
        tasks.push(tokio::spawn(async move {
            if let Err(err) = request_paths_over_connection(addr, &requests).await {
                panic!("{err}");
            }
        }));
    }

    for task in tasks {
        task.await?;
    }

    server.stop().await?;
    let _ = tmp;
    Ok(())
}
