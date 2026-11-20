//! A shutdown signal with one clock for every service and connection.

use std::{
    sync::{Arc, OnceLock},
    time::Duration,
};
use tokio::{sync::watch, time::Instant};

use crate::config::Config;

/// Services in one class share a grace period measured from the same signal.
#[derive(Clone, Copy)]
pub enum ShutdownClass {
    Clearnet,
    Tor,
    Acme,
}

impl ShutdownClass {
    pub const fn grace(self, config: &Config) -> Duration {
        Duration::from_secs(match self {
            Self::Clearnet => config.server.shutdown_grace_secs,
            Self::Tor => config.tor.shutdown_grace_secs,
            Self::Acme => 5,
        })
    }
}

#[derive(Clone)]
pub struct Shutdown {
    signal: watch::Receiver<bool>,
    started: Arc<OnceLock<Instant>>,
}

impl Shutdown {
    pub fn from_receiver(signal: watch::Receiver<bool>) -> Self {
        Self {
            signal,
            started: Arc::new(OnceLock::new()),
        }
    }

    pub fn begin(&self, signal: &watch::Sender<bool>) -> Instant {
        let started = *self.started.get_or_init(Instant::now);
        signal.send_replace(true);
        started
    }

    pub fn receiver(&self) -> watch::Receiver<bool> {
        self.signal.clone()
    }

    pub fn is_requested(&self) -> bool {
        *self.signal.borrow() || self.signal.has_changed().is_err()
    }

    pub async fn wait(&mut self) -> Instant {
        let _ = self.signal.wait_for(|&requested| requested).await;
        *self.started.get_or_init(Instant::now)
    }
}

pub fn deadline(start: Instant, grace: Duration) -> Instant {
    start.checked_add(grace).unwrap_or(start)
}

#[derive(Debug)]
pub enum ServiceOutcome {
    Drained,
    Aborted,
    Failed(String),
}

pub async fn drain_tasks(
    tasks: &mut tokio::task::JoinSet<()>,
    deadline: Instant,
    label: &str,
) -> ServiceOutcome {
    let mut failed = false;
    while !tasks.is_empty() {
        match tokio::time::timeout_at(deadline, tasks.join_next()).await {
            Ok(Some(Err(error))) => {
                log::warn!("{label} child task failed during drain: {error}");
                failed = true;
            }
            Ok(_) => {}
            Err(_) => {
                let remaining = tasks.len();
                tasks.shutdown().await;
                log::warn!("{label} aborted {remaining} child task(s) at its shutdown deadline");
                return ServiceOutcome::Aborted;
            }
        }
    }
    if failed {
        ServiceOutcome::Failed(format!("{label} child task failed during drain"))
    } else {
        ServiceOutcome::Drained
    }
}
