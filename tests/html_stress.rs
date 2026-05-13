//! HTML stress-test suite for `RustHost`.
//!
//! This test serves the fixture tree under `tests/fixtures/html_stress` through
//! the real HTTP server, then hammers it with a mixed workload:
//! - repeated keep-alive requests on the same connection
//! - concurrent clients
//! - HTML, CSS, JS, SVG, directory listing, and percent-encoded paths
//! - a generated large HTML page with range requests

#![allow(renamed_and_removed_lints)]

mod support;

use std::{
    fmt::Write as _,
    fs,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use dashmap::DashMap;
use rusthost::runtime::state::{AppState, Metrics};
use support::{
    build_test_config, header_value, read_headers_only, read_one_response, reserve_port,
    response_to_str, status_code,
};
use tokio::{
    io::AsyncWriteExt as _,
    net::TcpStream,
    sync::{watch, RwLock, Semaphore},
};

fn body_bytes(raw: &[u8]) -> Result<&[u8], Box<dyn std::error::Error>> {
    let text = response_to_str(raw)?;
    let sep = text
        .find("\r\n\r\n")
        .ok_or("response missing header terminator")?;
    Ok(raw
        .get(sep + 4..)
        .ok_or("response body slice out of bounds")?)
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

fn reserve_port_or_skip() -> Result<Option<u16>, Box<dyn std::error::Error>> {
    match reserve_port() {
        Ok(port) => Ok(Some(port)),
        Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!(
                "[html_stress] skipping test: loopback sockets are blocked in this environment"
            );
            Ok(None)
        }
        Err(err) => Err(err.into()),
    }
}

async fn start_server_or_skip(
    site_root: &Path,
) -> Result<Option<TestServer>, Box<dyn std::error::Error>> {
    let Some(port) = reserve_port_or_skip()? else {
        return Ok(None);
    };

    let data_dir = site_root.parent().unwrap_or(site_root).to_path_buf();
    let mut config = build_test_config(site_root, IpAddr::V4(Ipv4Addr::LOCALHOST), port)?;
    config.server.max_connections = 128;
    config.server.max_connections_per_ip = 128;
    config.server.shutdown_grace_secs = 5;
    config.site.enable_directory_listing = true;
    config.site.spa_routing = false;
    let config = Arc::new(config);
    let state = Arc::new(RwLock::new(AppState::new()));
    let metrics = Arc::new(Metrics::new());
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (port_tx, port_rx) = tokio::sync::oneshot::channel::<Result<u16, String>>();

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
        .map_err(|_elapsed| "timed out waiting for server to report its bound port")?
        .map_err(|_closed| "server port channel closed before sending")?
        .map_err(std::io::Error::other)?;

    Ok(Some(TestServer {
        addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), bound_port),
        shutdown_tx,
        _root_tx: root_tx,
        handle: Some(handle),
    }))
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
                assert_eq!(status, 200, "root document should return 200");
                assert!(
                    response_to_str(&response)?.contains("RustHost Stress Suite"),
                    "root document should contain the fixture heading"
                );
            }
            req if req.starts_with(b"HEAD ") => {
                assert_eq!(status, 200, "HEAD request should return 200");
                assert!(
                    body_bytes(&response)?.is_empty(),
                    "HEAD response body should be empty"
                );
            }
            req if req.starts_with(b"GET /gallery/ ") => {
                assert_eq!(status, 200, "gallery index should return 200");
                assert!(
                    response_to_str(&response)?.contains("thumb-a.txt"),
                    "gallery listing should mention thumb-a.txt"
                );
            }
            req if req.starts_with(b"GET /pages/space%20name.html ") => {
                assert_eq!(status, 200, "space-containing path should return 200");
                assert!(
                    response_to_str(&response)?.contains("Filename with a space"),
                    "space-containing page should render its heading"
                );
            }
            req if req.starts_with(b"GET /assets/logo.svg ") => {
                assert_eq!(status, 200, "SVG asset should return 200");
                assert_eq!(
                    header_value(&response, "content-type")?.as_deref(),
                    Some("image/svg+xml"),
                    "SVG asset should expose the SVG content type"
                );
            }
            req if req.starts_with(b"GET /styles/app.css ") => {
                assert_eq!(status, 200, "CSS asset should return 200");
                assert!(
                    response_to_str(&response)?.contains("--accent"),
                    "CSS asset should contain the accent variable"
                );
            }
            req if req.starts_with(b"GET /scripts/app.js ") => {
                assert_eq!(status, 200, "JS asset should return 200");
                assert!(
                    response_to_str(&response)?.contains("__rusthostStressSuite"),
                    "JS asset should contain the stress-suite marker"
                );
            }
            req if req.starts_with(b"GET /pages/about.html ") => {
                assert_eq!(status, 200, "about page should return 200");
                assert!(
                    response_to_str(&response)?.contains("About this fixture"),
                    "about page should contain its heading"
                );
            }
            req if req.starts_with(b"GET /pages/nested/index.html ") => {
                assert_eq!(status, 200, "nested index should return 200");
                assert!(
                    response_to_str(&response)?.contains("Nested index page"),
                    "nested index should contain its heading"
                );
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
    let Some(server) = start_server_or_skip(&site_root).await? else {
        return Ok(());
    };

    let mut root_stream = TcpStream::connect(server.addr).await?;
    let root_response = read_response(
        &mut root_stream,
        b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n",
    )
    .await?;
    assert_eq!(
        status_code(&root_response)?,
        200,
        "root page should return 200"
    );
    assert!(
        response_to_str(&root_response)?.contains("RustHost Stress Suite"),
        "root page should contain the stress-suite heading"
    );

    let mut head_stream = TcpStream::connect(server.addr).await?;
    head_stream
        .write_all(b"HEAD /index.html HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await?;
    let head_response = read_headers_only(&mut head_stream).await?;
    assert_eq!(
        status_code(&head_response)?,
        200,
        "HEAD request should return 200"
    );
    assert!(
        body_bytes(&head_response)?.is_empty(),
        "HEAD response body should be empty"
    );

    let mut range_stream = TcpStream::connect(server.addr).await?;
    let huge_range = read_response(
        &mut range_stream,
        b"GET /pages/huge.html HTTP/1.1\r\nHost: localhost\r\nRange: bytes=0-255\r\n\r\n",
    )
    .await?;
    assert_eq!(
        status_code(&huge_range)?,
        206,
        "range request should return partial content"
    );
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
