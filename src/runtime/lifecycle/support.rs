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
    pub(super) tor_ingress: Option<tokio::task::JoinHandle<()>>,
    pub(super) acme: Option<tokio::task::JoinHandle<()>>,
    pub(super) acme_guard: Option<tls::acme::AcmeInitGuard>,
}

pub(super) async fn wait_for_bind_port(
    port_rx: oneshot::Receiver<u16>,
    label: &str,
) -> Result<u16> {
    match tokio::time::timeout(Duration::from_secs(10), port_rx).await {
        Ok(Ok(port)) => Ok(port),
        Ok(Err(_)) => {
            log::error!("{label} port channel closed before sending — startup failed");
            Err(AppError::ServerStartup(format!(
                "{label} task exited before signalling its bound port"
            )))
        }
        Err(_) => {
            log::error!("Timed out waiting for {label} to bind");
            Err(AppError::ServerStartup(format!(
                "Timed out waiting for {label} to bind (10 s)"
            )))
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
) -> Result<BackgroundTasks> {
    let mut tasks = BackgroundTasks::default();

    if !config.tls.enabled {
        return Ok(tasks);
    }

    let tls_result = tls::build_acceptor(&config.tls, data_dir).await;

    match tls_result {
        Err(e) => {
            log::error!("TLS init failed: {e}");
            return Err(e);
        }
        Ok(None) => {}
        Ok(Some(tls_setup)) => {
            let crate::tls::TlsSetup {
                acceptor,
                acme_task,
                acme_guard,
            } = tls_setup;
            tasks.acme = acme_task;
            tasks.acme_guard = acme_guard;

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
                let (tls_port_tx, tls_port_rx) = oneshot::channel::<u16>();
                tasks.https = Some(tokio::spawn(async move {
                    server::run_https(
                        tls_config,
                        tls_state,
                        tls_metrics,
                        tls_data_dir,
                        tls_shutdown,
                        acceptor,
                        tls_port_tx,
                        tls_sem,
                        tls_ip_map,
                        tls_root_rx,
                    )
                    .await;
                }));
                wait_for_bind_port(tls_port_rx, "HTTPS server").await?;
            }

            if config.tls.redirect_http {
                let bind_addr = config.server.bind;
                let redir_plain_port = config.tls.http_port.get();
                let redir_tls_port = config.tls.port.get();
                let redir_state = Arc::clone(state);
                let redir_shutdown = shutdown_rx.clone();
                let redir_sem = std::sync::Arc::clone(&budget.semaphore);
                let redir_ip_map = std::sync::Arc::clone(&budget.per_ip_map);
                let redir_max_per_ip = config.server.max_connections_per_ip;
                let redir_drain_timeout = Duration::from_secs(config.server.shutdown_grace_secs);
                let (redir_port_tx, redir_port_rx) = oneshot::channel::<u16>();
                tasks.redirect = Some(tokio::spawn(async move {
                    server::redirect::run_redirect_server(
                        server::redirect::RedirectServerConfig {
                            bind_addr,
                            plain_port: redir_plain_port,
                            tls_port: redir_tls_port,
                            max_per_ip: redir_max_per_ip,
                            drain_timeout: redir_drain_timeout,
                        },
                        redir_state,
                        redir_shutdown,
                        redir_port_tx,
                        redir_sem,
                        redir_ip_map,
                    )
                    .await;
                }));
                wait_for_bind_port(redir_port_rx, "HTTP redirect server").await?;
            }
        }
    }

    Ok(tasks)
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

pub(super) async fn graceful_shutdown(
    config: &Config,
    shutdown_tx: watch::Sender<bool>,
    server_handle: Option<tokio::task::JoinHandle<()>>,
    tor_handle: Option<tokio::task::JoinHandle<()>>,
    mut background_tasks: BackgroundTasks,
) {
    log::info!("Shutting down…");
    let _ = shutdown_tx.send(true);

    let http_budget = Duration::from_secs(config.server.shutdown_grace_secs);

    if let Some(server_handle) = server_handle {
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
    }

    if let Some(handle) = tor_handle {
        let tor_budget = Duration::from_secs(config.tor.shutdown_grace_secs);
        if tokio::time::timeout(tor_budget, handle).await.is_err() {
            log::warn!(
                "Tor circuit teardown did not complete within {} s; \
                 active Tor streams will be forcibly closed",
                tor_budget.as_secs(),
            );
        }
    }

    wait_for_background_task(
        background_tasks.redirect,
        Duration::from_secs(config.server.shutdown_grace_secs.saturating_add(2)),
        "HTTP redirect server",
    )
    .await;
    wait_for_background_task(
        background_tasks.tor_ingress,
        Duration::from_secs(config.server.shutdown_grace_secs.saturating_add(2)),
        "Tor ingress server",
    )
    .await;
    wait_for_background_task(
        background_tasks.https,
        Duration::from_secs(config.server.shutdown_grace_secs.saturating_add(2)),
        "HTTPS server",
    )
    .await;
    wait_for_background_task(
        background_tasks.acme,
        Duration::from_secs(5),
        "ACME event loop",
    )
    .await;
    background_tasks.acme_guard.take();
    logging::shutdown_access_log();

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
            log::warn!(
                "{label} did not stop within {} s; aborting task",
                timeout.as_secs()
            );
            handle.abort();
        }
    }
}
