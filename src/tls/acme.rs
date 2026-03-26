use std::{path::Path, sync::Arc};

use rustls::ServerConfig;
use rustls_acme::AcmeAcceptor;

use crate::Result;
use crate::{config::AcmeConfig, error::AppError};

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Configure Let's Encrypt certificate provisioning via `rustls-acme` and
/// return a [`TlsAcceptor`] that will serve valid certificates once the ACME
/// challenge has completed.
///
/// A background task is spawned to run the ACME event loop, which handles:
///   - Initial certificate issuance
///   - TLS-ALPN-01 challenge responses (no port 80 required)
///   - Automatic renewal before expiry
///
/// **Important:** always test with `staging = true` first.  Let's Encrypt
/// rate-limits production certificate issuance; a misconfigured setup will
/// burn your quota.  Set `staging = false` only once you have confirmed the
/// full ACME flow works end-to-end in staging.
pub async fn build_acme_acceptor(
    cfg: &AcmeConfig,
    data_dir: &Path,
) -> Result<(Arc<AcmeAcceptor>, Arc<ServerConfig>)> {
    validate_acme_config(cfg)?;

    let cache_dir = data_dir.join(&cfg.cache_dir);
    std::fs::create_dir_all(&cache_dir).map_err(|e| {
        AppError::Tls(format!(
            "failed to create ACME cache directory {}: {e}",
            cache_dir.display()
        ))
    })?;

    log::info!(
        "TLS/ACME: configuring for domains {:?} (staging={})",
        cfg.domains,
        cfg.staging
    );

    let cache = rustls_acme::caches::DirCache::new(cache_dir);
    let domains: Vec<&str> = cfg.domains.iter().map(String::as_str).collect();

    let mut acme_cfg = rustls_acme::AcmeConfig::new(domains).cache(cache);

    // Contact email — Let's Encrypt uses this for expiry notices.
    if let Some(email) = &cfg.email {
        acme_cfg = acme_cfg.contact_push(format!("mailto:{email}"));
    } else {
        log::warn!(
            "TLS/ACME: no contact email configured; \
             Let's Encrypt recommends providing one for expiry notifications"
        );
    }

    // Point at staging or production directory.
    acme_cfg = acme_cfg.directory_lets_encrypt(cfg.staging);

    let state = acme_cfg.state();

    // Build a ServerConfig that uses the ACME resolver as its certificate
    // source.  This is the config we must pass to StartHandshake::into_stream
    // later — it is what makes dynamically-renewed certs visible to rustls.
    let server_cfg = Arc::new(
        ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(state.resolver()),
    );

    // `acceptor()` is the low-level handle we need to hand to the server.
    // The high-level `incoming()` alternative wraps a full TCP listener stream
    // and doesn't fit our per-acceptor architecture, so we stay on the
    // lower-level API and suppress the deprecation lint explicitly.
    #[allow(deprecated)]
    let acme_acceptor = Arc::new(state.acceptor());

    // Spawn the event loop.  This task must stay alive for the lifetime of
    // the server process — it drives ACME challenge responses and renewals.
    let env_label = if cfg.staging { "staging" } else { "production" };
    tokio::spawn(run_acme_event_loop(state, env_label.to_owned()));

    Ok((acme_acceptor, server_cfg))
}

// ---------------------------------------------------------------------------
// ACME event loop
// ---------------------------------------------------------------------------

/// Drive the `rustls-acme` state machine to completion.
///
/// Each event is either an informational notification (new cert issued,
/// renewal triggered) or a non-fatal error (e.g. temporary ACME server
/// unavailability).  Neither type should terminate the loop — the task must
/// keep running to serve subsequent challenge responses and renewals.
///
/// The loop exits only when the underlying stream closes, which normally
/// only happens when the process shuts down.
async fn run_acme_event_loop(
    mut state: rustls_acme::AcmeState<std::io::Error, std::io::Error>,
    // AcmeState<EC, EA> is parameterised on the *error* types produced by the
    // cache, not the cache type itself.  DirCache implements Cache with
    // `Error = std::io::Error`, so both EC and EA resolve to that.
    // If you switch to a custom cache, update the error types here accordingly.
    env_label: String,
) {
    use futures::StreamExt as _;

    log::info!("TLS/ACME: event loop started ({})", env_label);

    loop {
        match state.next().await {
            Some(Ok(event)) => {
                log::info!("TLS/ACME [{}]: {event:?}", env_label);
            }
            Some(Err(err)) => {
                // Log at warn — ACME errors are often transient (DNS not
                // propagated yet, rate limit briefly exceeded, etc.).  The
                // state machine will retry automatically.
                log::warn!("TLS/ACME [{}] error: {err}", env_label);
            }
            None => {
                // Stream closed — this is normal during a clean shutdown.
                log::info!("TLS/ACME [{}]: event loop terminated", env_label);
                break;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Config validation
// ---------------------------------------------------------------------------

/// Reject obviously broken configs early, before any network activity.
fn validate_acme_config(cfg: &AcmeConfig) -> Result<()> {
    if cfg.domains.is_empty() {
        return Err(AppError::Tls(
            "[tls.acme] requires at least one domain in `domains`".into(),
        ));
    }

    for domain in &cfg.domains {
        if domain.trim().is_empty() {
            return Err(AppError::Tls(
                "[tls.acme] `domains` contains an empty string".into(),
            ));
        }
        // Rudimentary check: must contain at least one dot (e.g. "example.com")
        // and must not look like a raw IP address (ACME doesn't issue for IPs).
        if !domain.contains('.') || domain.parse::<std::net::IpAddr>().is_ok() {
            return Err(AppError::Tls(format!(
                "[tls.acme] invalid domain {domain:?}: \
                 must be a fully-qualified domain name, not an IP address"
            )));
        }
    }

    if cfg.email.as_deref().map(|e| e.is_empty()).unwrap_or(false) {
        return Err(AppError::Tls(
            "[tls.acme] `email` is set but empty; provide a valid address or remove the key".into(),
        ));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AcmeConfig;

    fn valid_cfg() -> AcmeConfig {
        AcmeConfig {
            enabled: true,
            domains: vec!["example.com".into()],
            email: Some("test@example.com".into()),
            staging: true,
            cache_dir: "tls/acme".into(),
        }
    }

    #[test]
    fn rejects_empty_domains() {
        let mut cfg = valid_cfg();
        cfg.domains = vec![];
        assert!(validate_acme_config(&cfg).is_err());
    }

    #[test]
    fn rejects_ip_address_domain() {
        let mut cfg = valid_cfg();
        cfg.domains = vec!["1.2.3.4".into()];
        assert!(validate_acme_config(&cfg).is_err());
    }

    #[test]
    fn rejects_bare_hostname() {
        let mut cfg = valid_cfg();
        cfg.domains = vec!["localhost".into()];
        assert!(validate_acme_config(&cfg).is_err());
    }

    #[test]
    fn rejects_empty_email_string() {
        let mut cfg = valid_cfg();
        cfg.email = Some("".into());
        assert!(validate_acme_config(&cfg).is_err());
    }

    #[test]
    fn accepts_none_email() {
        let mut cfg = valid_cfg();
        cfg.email = None;
        // None is allowed (just a warning at runtime)
        assert!(validate_acme_config(&cfg).is_ok());
    }

    #[test]
    fn accepts_valid_config() {
        assert!(validate_acme_config(&valid_cfg()).is_ok());
    }

    #[test]
    fn accepts_multiple_domains() {
        let mut cfg = valid_cfg();
        cfg.domains = vec!["example.com".into(), "www.example.com".into()];
        assert!(validate_acme_config(&cfg).is_ok());
    }
}
