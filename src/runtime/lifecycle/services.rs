//! Startup acknowledgements and supervision of network services.

use std::{collections::HashMap, future::Future, time::Duration};
use tokio::{
    sync::{oneshot, watch},
    task::{Id, JoinSet},
};

use crate::{
    config::Config,
    console, logging,
    runtime::{
        service_status::{AcmeStatus, ListenerRole, ListenerStatus, RuntimeState, TorPhase},
        shutdown::{deadline, ServiceOutcome, ShutdownClass},
        state::ConsoleMode,
    },
    server::{
        self,
        listeners::{self, BindResult, ListenerContext},
    },
    tls, tor, AppError, Result,
};

#[derive(Clone, Copy)]
enum Service {
    Listener(ListenerRole),
    Acme,
    Tor,
}

impl Service {
    const fn label(self) -> &'static str {
        match self {
            Self::Listener(role) => role.label(),
            Self::Acme => "TLS/ACME",
            Self::Tor => "Tor service",
        }
    }

    const fn grace(self, config: &Config) -> Duration {
        let class = match self {
            Self::Listener(role) => role.shutdown_class(),
            Self::Acme => ShutdownClass::Acme,
            Self::Tor => ShutdownClass::Tor,
        };
        class.grace(config)
    }
}

#[derive(Default)]
pub(super) struct Services {
    tasks: JoinSet<ServiceOutcome>,
    task_roles: HashMap<Id, Service>,
    acme_guard: Option<tls::acme::AcmeInitGuard>,
}

impl Services {
    pub(super) async fn start(&mut self, context: &ListenerContext) -> Result<()> {
        let config = &context.config;
        if !config.tls.enabled || !config.tls.redirect_http {
            self.start_listener(context, ListenerRole::Http, None)
                .await?;
        }
        if config.tls.enabled {
            let role = ListenerRole::Https;
            context
                .state
                .set_listener(role, ListenerStatus::Starting)
                .await;
            let tls = tls::prepare(&config.tls, &context.data_dir).await;
            match tls {
                Ok(Some(tls)) => self.start_https(context, tls).await?,
                Ok(None) => {}
                Err(error) => {
                    publish_failure(&context.state, Service::Listener(role), error.to_string())
                        .await;
                    return Err(error);
                }
            }
        }
        if config.tor.enabled {
            let address = self
                .start_listener(context, ListenerRole::TorIngress, None)
                .await?;
            self.spawn(
                Service::Tor,
                context,
                tor::serve(
                    context.data_dir.clone(),
                    address,
                    config.server.max_connections as usize,
                    context.state.clone(),
                    context.shutdown.clone(),
                    Service::Tor.grace(config),
                ),
            );
        }
        Ok(())
    }

    async fn start_https(
        &mut self,
        context: &ListenerContext,
        tls: tls::PreparedTls,
    ) -> Result<()> {
        context.state.app.write().await.tls_cert_status = tls.cert_status;
        if let Some((events, guard)) = tls.acme {
            context.state.set_acme(AcmeStatus::Starting).await;
            self.acme_guard = Some(guard);
            self.spawn(
                Service::Acme,
                context,
                events.run(Some((context.state.clone(), context.shutdown.clone()))),
            );
        }
        let https = self
            .start_listener(context, ListenerRole::Https, Some(tls.acceptor))
            .await?;
        if context.config.tls.redirect_http {
            self.start_redirect(context, https.port()).await?;
        }
        Ok(())
    }

    async fn start_listener(
        &mut self,
        context: &ListenerContext,
        role: ListenerRole,
        acceptor: Option<tls::Acceptor>,
    ) -> Result<std::net::SocketAddr> {
        let (tx, rx) = oneshot::channel();
        self.spawn(
            Service::Listener(role),
            context,
            listeners::serve(role, acceptor, context.clone(), |result| {
                let _ = tx.send(result);
            }),
        );
        wait_for_bind(rx, role).await
    }

    async fn start_redirect(&mut self, context: &ListenerContext, tls_port: u16) -> Result<()> {
        let config = &context.config;
        let role = ListenerRole::Redirect;
        let (tx, rx) = oneshot::channel();
        self.spawn(
            Service::Listener(role),
            context,
            server::redirect::serve_redirect(
                server::redirect::RedirectServerConfig {
                    bind_addr: config.server.bind,
                    plain_port: config.tls.http_port.get(),
                    tls_port,
                    allowed_hosts: redirect_allowed_hosts(config),
                    max_per_ip: config.server.max_connections_per_ip,
                    drain_timeout: Service::Listener(role).grace(config),
                },
                context.state.clone(),
                context.shutdown.clone(),
                context.budget.clone(),
                |result| {
                    let _ = tx.send(result);
                },
            ),
        );
        wait_for_bind(rx, role).await?;
        Ok(())
    }

    fn spawn(
        &mut self,
        service: Service,
        context: &ListenerContext,
        future: impl Future<Output = ServiceOutcome> + Send + 'static,
    ) {
        let mut shutdown = context.shutdown.clone();
        let grace = service.grace(&context.config);
        let task = self.tasks.spawn(async move {
            tokio::pin!(future);
            let started = tokio::select! {
                biased;
                outcome = &mut future => return outcome,
                started = shutdown.wait() => started,
            };
            tokio::select! {
                biased;
                outcome = &mut future => outcome,
                () = tokio::time::sleep_until(deadline(started, grace)) => ServiceOutcome::Aborted,
            }
        });
        self.task_roles.insert(task.id(), service);
    }

    async fn observe_exit(&mut self, state: &RuntimeState, stopping: bool) -> Option<Result<()>> {
        let joined = self.tasks.join_next_with_id().await?;
        let (id, outcome) = match joined {
            Ok(result) => result,
            Err(error) => (
                error.id(),
                ServiceOutcome::Failed(format!("task join failed: {error}")),
            ),
        };
        let Some(service) = self.task_roles.remove(&id) else {
            return Some(Err(AppError::ServerStartup(format!(
                "untracked service task {id} exited"
            ))));
        };
        let label = service.label();
        let failure = match outcome {
            ServiceOutcome::Drained if stopping => {
                log::info!("{label} drained");
                None
            }
            ServiceOutcome::Drained => Some(format!("{label} stopped unexpectedly")),
            ServiceOutcome::Aborted => {
                log::warn!("{label} aborted at its shutdown deadline");
                publish_aborted(state, service).await;
                None
            }
            ServiceOutcome::Failed(message) => Some(message),
        };
        if let Some(message) = failure {
            log::error!("{label} failed: {message}");
            publish_failure(state, service, message.clone()).await;
            if matches!(service, Service::Listener(_)) {
                return Some(Err(AppError::ServerStartup(message)));
            }
        }
        Some(Ok(()))
    }

    pub(super) async fn wait_for_failure(&mut self, state: &RuntimeState) -> Result<()> {
        while let Some(result) = self.observe_exit(state, false).await {
            result?;
        }
        Err(AppError::ServerStartup(
            "all service tasks exited".to_owned(),
        ))
    }

    pub(super) async fn shutdown(
        mut self,
        context: &ListenerContext,
        trigger: &watch::Sender<bool>,
    ) {
        let config = &context.config;
        context.shutdown.begin(trigger);
        {
            let mut state = context.state.app.write().await;
            state.runtime_ready = false;
            state.console_mode = ConsoleMode::ShuttingDown;
        }
        log::info!("Shutdown requested — stopping web server and background services...");
        if config.tor.enabled {
            log::info!(
                "Tor cleanup may take up to {} s while active streams close.",
                config.tor.shutdown_grace_secs
            );
        }
        console::show_shutdown_message(config.tor.enabled);
        while self.observe_exit(&context.state, true).await.is_some() {}
        drop(self.acme_guard.take());
        logging::shutdown_access_log();
        log::info!("RustHost shutdown complete.");
        logging::flush();
        console::cleanup();
    }
}

async fn wait_for_bind(
    rx: oneshot::Receiver<BindResult>,
    role: ListenerRole,
) -> Result<std::net::SocketAddr> {
    let label = role.label();
    match tokio::time::timeout(Duration::from_secs(10), rx).await {
        Ok(Ok(result)) => result.map_err(AppError::ServerStartup),
        Ok(Err(_)) => Err(AppError::ServerStartup(format!(
            "{label} exited before acknowledging its bind"
        ))),
        Err(_) => Err(AppError::ServerStartup(format!(
            "Timed out waiting for {label} to bind (10 s)"
        ))),
    }
}

async fn publish_failure(state: &RuntimeState, service: Service, message: String) {
    match service {
        Service::Listener(role) => {
            state
                .set_listener(role, ListenerStatus::Failed(message))
                .await;
        }
        Service::Acme => state.set_acme(AcmeStatus::Failed(message)).await,
        Service::Tor => state.set_tor(TorPhase::Failed(message), None).await,
    }
}

async fn publish_aborted(state: &RuntimeState, service: Service) {
    match service {
        Service::Listener(role) => state.set_listener(role, ListenerStatus::Stopped).await,
        Service::Acme => state.set_acme(AcmeStatus::Stopped).await,
        Service::Tor => state.set_tor(TorPhase::Stopped, None).await,
    }
}

pub(super) async fn maybe_open_browser(config: &Config, state: &RuntimeState) {
    if config.server.open_browser_on_start {
        super::super::open_local_site(state).await;
    }
}

fn redirect_allowed_hosts(config: &Config) -> Vec<String> {
    use std::collections::BTreeSet;

    let mut hosts = BTreeSet::from([
        "127.0.0.1".to_owned(),
        "[::1]".to_owned(),
        "localhost".to_owned(),
    ]);

    for host in &config.tls.acme.domains {
        if let Some(normalized) = normalize_redirect_host(host) {
            hosts.insert(normalized);
        } else {
            log::warn!("Ignoring invalid redirect host candidate from [tls.acme].domains: {host}");
        }
    }

    hosts.into_iter().collect()
}

fn normalize_redirect_host(raw: &str) -> Option<String> {
    let host = raw.trim().trim_end_matches('.');
    if host.is_empty() || !host.is_ascii() {
        return None;
    }
    if host.eq_ignore_ascii_case("localhost") {
        return Some("localhost".to_owned());
    }
    if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
        return Some(ip.to_string());
    }
    if let Ok(ip) = host.parse::<std::net::Ipv6Addr>() {
        return Some(format!("[{ip}]"));
    }
    if host
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-'))
    {
        Some(host.to_ascii_lowercase())
    } else {
        None
    }
}
