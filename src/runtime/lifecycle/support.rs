//! # Lifecycle Support
//!
//! **File:** `support.rs`
//! **Location:** `src/runtime/lifecycle/support.rs`

use std::{path::Path, sync::Arc, time::Duration};

use tokio::sync::{oneshot, watch};

use crate::{
    config::Config,
    console, logging,
    runtime::state::{CertStatus, SharedMetrics, SharedState},
    server, tls, AppError, Result,
};

use super::SharedConnectionBudget;

#[derive(Default)]
pub(super) struct BackgroundTasks {
    pub(super) https: Option<tokio::task::JoinHandle<()>>,
    pub(super) redirect: Option<tokio::task::JoinHandle<()>>,
    pub(super) acme: Option<tokio::task::JoinHandle<()>>,
}

pub(super) async fn wait_for_bind_port(port_rx: oneshot::Receiver<u16>) -> Result<u16> {
    match tokio::time::timeout(Duration::from_secs(10), port_rx).await {
        Ok(Ok(port)) => Ok(port),
        Ok(Err(_)) => {
            log::error!("Server port channel closed before sending — server failed to bind");
            Err(AppError::ServerStartup(
                "Server task exited before signalling its bound port".into(),
            ))
        }
        Err(_) => {
            log::error!("Timed out waiting for server to bind");
            Err(AppError::ServerStartup(
                "Timed out waiting for server to bind (10 s)".into(),
            ))
        }
    }
}

pub(super) async fn setup_tls(
    config: &Arc<Config>,
    state: &SharedState,
    metrics: &SharedMetrics,
    shutdown_rx: &watch::Receiver<bool>,
    data_dir: &Path,
    budget: &SharedConnectionBudget,
    root_tx: &watch::Sender<Arc<std::path::Path>>,
) -> BackgroundTasks {
    let mut tasks = BackgroundTasks::default();

    if !config.tls.enabled {
        return tasks;
    }

    let tls_result = tls::build_acceptor(&config.tls, data_dir).await;

    match tls_result {
        Err(e) => {
            log::error!("TLS init failed: {e}. Continuing in HTTP-only mode.");
        }
        Ok(None) => {}
        Ok(Some(tls_setup)) => {
            let crate::tls::TlsSetup {
                acceptor,
                acme_task,
            } = tls_setup;
            tasks.acme = acme_task;

            {
                let mut s = state.write().await;
                s.tls_cert_status = if config.tls.acme.enabled {
                    config.tls.acme.domains.first().map_or(
                        CertStatus::Acme {
                            domain: String::new(),
                        },
                        |d| CertStatus::Acme { domain: d.clone() },
                    )
                } else if config.tls.manual_cert.is_some() {
                    CertStatus::Manual
                } else {
                    CertStatus::SelfSigned
                };
            }

            {
                let tls_config = Arc::clone(config);
                let tls_state = Arc::clone(state);
                let tls_metrics = Arc::clone(metrics);
                let tls_shutdown = shutdown_rx.clone();
                let tls_data_dir = data_dir.to_path_buf();
                let tls_sem = std::sync::Arc::clone(&budget.semaphore);
                let tls_ip_map = std::sync::Arc::clone(&budget.per_ip_map);
                let tls_root_rx = root_tx.subscribe();
                tasks.https = Some(tokio::spawn(async move {
                    server::run_https(
                        tls_config,
                        tls_state,
                        tls_metrics,
                        tls_data_dir,
                        tls_shutdown,
                        acceptor,
                        tls_sem,
                        tls_ip_map,
                        tls_root_rx,
                    )
                    .await;
                }));
            }

            if config.tls.redirect_http {
                let bind_addr = config.server.bind;
                let redir_plain_port = config.tls.http_port.get();
                let redir_tls_port = config.tls.port.get();
                let redir_shutdown = shutdown_rx.clone();
                let redir_sem = std::sync::Arc::clone(&budget.semaphore);
                let redir_ip_map = std::sync::Arc::clone(&budget.per_ip_map);
                let redir_max_per_ip = config.server.max_connections_per_ip;
                tasks.redirect = Some(tokio::spawn(async move {
                    server::redirect::run_redirect_server(
                        bind_addr,
                        redir_plain_port,
                        redir_tls_port,
                        redir_shutdown,
                        redir_sem,
                        redir_ip_map,
                        redir_max_per_ip,
                    )
                    .await;
                }));
            }
        }
    }

    tasks
}

pub(super) async fn maybe_open_browser(config: &Config, state: &SharedState) {
    if !config.server.open_browser_on_start {
        return;
    }
    let port = state.read().await.actual_port;
    let url = match config.server.bind {
        std::net::IpAddr::V4(a) if a.is_unspecified() => {
            format!("http://127.0.0.1:{port}")
        }
        std::net::IpAddr::V6(a) if a.is_unspecified() => {
            format!("http://[::1]:{port}")
        }
        std::net::IpAddr::V6(a) => format!("http://[{a}]:{port}"),
        std::net::IpAddr::V4(a) => format!("http://{a}:{port}"),
    };
    super::super::open_browser(&url);
}

const DRAIN_HTTP_ONLY_SECS: u64 = 8;
const DRAIN_HTTP_WITH_TOR_SECS: u64 = 5;
const DRAIN_TOR_SECS: u64 = 10;

pub(super) async fn graceful_shutdown(
    shutdown_tx: watch::Sender<bool>,
    server_handle: tokio::task::JoinHandle<()>,
    tor_handle: Option<tokio::task::JoinHandle<()>>,
    background_tasks: BackgroundTasks,
) {
    log::info!("Shutting down…");
    let _ = shutdown_tx.send(true);

    let http_budget = if tor_handle.is_some() {
        Duration::from_secs(DRAIN_HTTP_WITH_TOR_SECS)
    } else {
        Duration::from_secs(DRAIN_HTTP_ONLY_SECS)
    };

    if tokio::time::timeout(http_budget, server_handle)
        .await
        .is_err()
    {
        let secs = http_budget.as_secs();
        log::warn!(
            "HTTP drain did not complete within {secs} s; \
             some connections may be abruptly closed",
        );
    }

    if let Some(handle) = tor_handle {
        if tokio::time::timeout(Duration::from_secs(DRAIN_TOR_SECS), handle)
            .await
            .is_err()
        {
            log::warn!(
                "Tor circuit teardown did not complete within {DRAIN_TOR_SECS} s; \
                 active Tor streams will be forcibly closed",
            );
        }
    }

    wait_for_background_task(
        background_tasks.redirect,
        Duration::from_secs(5),
        "HTTP redirect server",
    )
    .await;
    wait_for_background_task(
        background_tasks.https,
        Duration::from_secs(5),
        "HTTPS server",
    )
    .await;
    wait_for_background_task(
        background_tasks.acme,
        Duration::from_secs(5),
        "ACME event loop",
    )
    .await;

    log::info!("RustHost shut down cleanly.");
    logging::flush();
    console::cleanup();
}

pub(super) async fn wait_for_background_task(
    task: Option<tokio::task::JoinHandle<()>>,
    timeout: Duration,
    label: &str,
) {
    let Some(mut handle) = task else {
        return;
    };

    match tokio::time::timeout(timeout, &mut handle).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            log::warn!("{label} task ended with a join error during shutdown: {e}");
        }
        Err(_) => {
            log::warn!("{label} did not stop within {} s; aborting task", timeout.as_secs());
            handle.abort();
        }
    }
}
