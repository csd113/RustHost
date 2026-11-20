//! Managed service status and its projection onto the public application state.

use std::{net::SocketAddr, sync::Arc};
use tokio::sync::{RwLock, RwLockReadGuard};

use super::{
    shutdown::ShutdownClass,
    state::{AppState, SharedState, TorStatus},
};
use crate::config::Config;

/// Role and effective address of an active listener.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListenerRole {
    Http,
    Https,
    Redirect,
    TorIngress,
}

impl ListenerRole {
    pub const fn shutdown_class(self) -> ShutdownClass {
        match self {
            Self::Http | Self::Https | Self::Redirect => ShutdownClass::Clearnet,
            Self::TorIngress => ShutdownClass::Tor,
        }
    }

    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Http => "HTTP",
            Self::Https => "HTTPS",
            Self::Redirect => "HTTP redirect",
            Self::TorIngress => "Tor ingress",
        }
    }
}

/// Runtime state of one local listener.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ListenerStatus {
    Inactive,
    Starting,
    Listening(std::net::SocketAddr),
    Draining,
    Stopped,
    Failed(String),
}

impl ListenerStatus {
    #[must_use]
    pub const fn bound_addr(&self) -> Option<std::net::SocketAddr> {
        if let Self::Listening(addr) = self {
            Some(*addr)
        } else {
            None
        }
    }
}

/// Issuance and renewal state, independent of the HTTPS listener.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcmeStatus {
    Inactive,
    Starting,
    Available,
    Retrying(String),
    Failed(String),
    Stopped,
}

/// Detailed Tor phases used by managed runtime and console code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TorPhase {
    Disabled,
    Starting,
    Ready,
    Reconnecting,
    Draining,
    Stopped,
    Failed(String),
}

impl From<&TorStatus> for TorPhase {
    fn from(status: &TorStatus) -> Self {
        match status {
            TorStatus::Disabled => Self::Disabled,
            TorStatus::Starting => Self::Starting,
            TorStatus::Ready => Self::Ready,
            TorStatus::Failed(message) => Self::Failed(message.clone()),
        }
    }
}

impl TorPhase {
    fn legacy_status(&self) -> TorStatus {
        match self {
            Self::Disabled | Self::Draining | Self::Stopped => TorStatus::Disabled,
            Self::Starting | Self::Reconnecting => TorStatus::Starting,
            Self::Ready => TorStatus::Ready,
            Self::Failed(message) => TorStatus::Failed(message.clone()),
        }
    }
}

pub struct RuntimeStatus {
    pub public_http_role: ListenerRole,
    pub public_http: ListenerStatus,
    pub https: ListenerStatus,
    pub tor_ingress: ListenerStatus,
    pub acme: AcmeStatus,
    pub tor: TorPhase,
}

impl Default for RuntimeStatus {
    fn default() -> Self {
        Self {
            public_http_role: ListenerRole::Http,
            public_http: ListenerStatus::Inactive,
            https: ListenerStatus::Inactive,
            tor_ingress: ListenerStatus::Inactive,
            acme: AcmeStatus::Inactive,
            tor: TorPhase::Starting,
        }
    }
}

impl RuntimeStatus {
    /// Describe listeners hosted by library callers using the original state API.
    pub fn from_legacy(app: &AppState, config: &Config) -> Self {
        let bind = config.server.bind;
        let public_http_role = if config.tls.enabled && config.tls.redirect_http {
            ListenerRole::Redirect
        } else {
            ListenerRole::Http
        };
        let public_http = if app.server_running {
            ListenerStatus::Listening(SocketAddr::new(bind, app.actual_port))
        } else {
            ListenerStatus::Starting
        };
        let https = match (app.tls_running, app.tls_port, config.tls.enabled) {
            (true, Some(port), _) => ListenerStatus::Listening(SocketAddr::new(bind, port)),
            (_, _, true) => ListenerStatus::Starting,
            (_, _, false) => ListenerStatus::Inactive,
        };
        Self {
            public_http_role,
            public_http,
            https,
            tor: TorPhase::from(&app.tor_status),
            ..Self::default()
        }
    }
}

#[derive(Clone)]
pub struct RuntimeState {
    pub app: SharedState,
    status: Arc<RwLock<RuntimeStatus>>,
}

impl RuntimeState {
    pub fn new(app: SharedState) -> Self {
        Self {
            app,
            status: Arc::new(RwLock::new(RuntimeStatus::default())),
        }
    }

    pub async fn status(&self) -> RwLockReadGuard<'_, RuntimeStatus> {
        self.status.read().await
    }

    pub async fn set_listener(&self, role: ListenerRole, status: ListenerStatus) {
        // Readers needing both locks take the application state first.
        let mut app = self.app.write().await;
        let mut runtime = self.status.write().await;
        let address = status.bound_addr();
        if matches!(status, ListenerStatus::Failed(_)) {
            app.runtime_ready = false;
        }
        match role {
            ListenerRole::Http | ListenerRole::Redirect => {
                runtime.public_http_role = role;
                runtime.public_http = status;
                app.server_running = address.is_some();
                if let Some(addr) = address {
                    app.actual_port = addr.port();
                }
            }
            ListenerRole::Https => {
                runtime.https = status;
                app.tls_running = address.is_some();
                if let Some(addr) = address {
                    app.tls_port = Some(addr.port());
                }
            }
            ListenerRole::TorIngress => runtime.tor_ingress = status,
        }
    }

    pub async fn refresh_readiness(&self, config: &Config) {
        let mut app = self.app.write().await;
        let status = self.status.read().await;
        app.runtime_ready = status.public_http.bound_addr().is_some()
            && (!config.tls.enabled || status.https.bound_addr().is_some())
            && (!config.tor.enabled || status.tor_ingress.bound_addr().is_some());
    }

    pub async fn set_tor(&self, phase: TorPhase, address: Option<String>) {
        let mut app = self.app.write().await;
        let mut status = self.status.write().await;
        app.onion_address = if phase == TorPhase::Ready {
            address
        } else {
            None
        };
        app.tor_status = phase.legacy_status();
        status.tor = phase;
        drop(status);
        drop(app);
    }

    pub async fn set_acme(&self, phase: AcmeStatus) {
        self.status.write().await.acme = phase;
    }
}
