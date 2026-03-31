//! # ACME TLS Support
//!
//! **File:** `acme.rs`
//! **Location:** `src/tls/acme.rs`
use crate::Result;
use crate::{config::AcmeConfig, error::AppError};
use futures::StreamExt as _;
use rustls::ServerConfig;
use rustls_acme::AcmeAcceptor;
use std::{
    collections::HashSet,
    fmt::Debug,
    net::IpAddr,
    path::{Component, Path, PathBuf},
    sync::{Arc, OnceLock},
    time::Duration,
};
use tokio::{runtime::Handle, task::JoinHandle};

#[cfg(unix)]
use std::os::unix::fs::DirBuilderExt;

// ---------------------------------------------------------------------------
// Singleton guard — prevents multiple ACME loops racing over the same DirCache
// ---------------------------------------------------------------------------
// Two concurrent AcmeState instances sharing the same DirCache can race on
// account-key and certificate files, causing corruption and redundant issuance.
static ACME_INITIALIZED: OnceLock<()> = OnceLock::new();

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------
/// Configure Let's Encrypt certificate provisioning via rustls-acme and
/// return an [`AcmeAcceptor`], a [`ServerConfig`], and a [`JoinHandle`] for
/// the background ACME event loop.
///
/// # Shutdown
///
/// The returned [`JoinHandle`] **must** be retained for the lifetime of the
/// server process and awaited during graceful shutdown. Dropping it does not
/// cancel the task, but removes the ability to detect panics or co-ordinate
/// teardown.
///
/// The background task handles:
/// - Initial certificate issuance via TLS-ALPN-01 (no port 80 required)
/// - Automatic renewal before expiry
///
/// **Important:** always test with `staging = true` first. Let's Encrypt
/// rate-limits production certificate issuance; a misconfigured setup will
/// exhaust your quota. Set `staging = false` only once the full ACME flow
/// has been verified end-to-end in staging.
///
/// # Errors
///
/// Returns [`AppError::Tls`] if:
/// - `cfg.enabled` is `false`,
/// - `build_acme_acceptor` has already been called in this process,
/// - there is no active Tokio runtime,
/// - [`validate_acme_config`] rejects the provided [`AcmeConfig`], or
/// - the ACME cache directory cannot be created or secured on disk.
#[must_use = "the AcmeAcceptor and ServerConfig must be used to serve TLS; \
              the JoinHandle must be retained to monitor the ACME event loop"]
pub fn build_acme_acceptor(
    cfg: &AcmeConfig,
    data_dir: &Path,
) -> Result<(Arc<AcmeAcceptor>, Arc<ServerConfig>, JoinHandle<()>)> {
    if !cfg.enabled {
        return Err(AppError::Tls(
            "build_acme_acceptor called with cfg.enabled = false; \
             check the enabled flag before calling this function"
                .into(),
        ));
    }

    // The OnceLock guard is checked here but not set yet. Setting it before
    // validate_acme_config would mean
    // that if validation — or any subsequent fallible step — failed, the lock
    // was already permanently set. All future retry attempts would be silently
    // blocked, and the process had to be restarted to recover from a transient
    // failure (e.g. a momentarily non-writable cache directory).
    //
    // We set the lock only after every fallible step succeeds (see the bottom
    // of this function). A guard is still checked here so that a *second call
    // after a prior success* is rejected immediately, before doing any work.
    if ACME_INITIALIZED.get().is_some() {
        return Err(AppError::Tls(
            "build_acme_acceptor has already been called; \
             ACME may only be initialized once per process to prevent \
             concurrent state machines from racing over the shared DirCache"
                .into(),
        ));
    }

    // All config validation — domains, email, and cache_dir — is now
    // consolidated in validate_acme_config (see Issue 9).
    validate_acme_config(cfg)?;

    let cache_dir: PathBuf = data_dir.join(&cfg.cache_dir);

    // Check the resolved path length, not just the segment. The joined path
    // can silently exceed OS limits (Linux: 4096, Win: 260)
    // even when the cfg.cache_dir segment passes its own length check.
    if cache_dir.as_os_str().len() > 4096 {
        return Err(AppError::Tls(format!(
            "[tls.acme.cache_dir] resolved path exceeds 4096 bytes: {}",
            cache_dir.display()
        )));
    }

    // Create the cache directory with restrictive permissions atomically on
    // Unix using DirBuilder::mode(), eliminating the TOCTOU
    // race between create_dir_all and a subsequent set_permissions call.
    // On non-Unix platforms create_dir_all is sufficient; there is no
    // equivalent of Unix file-mode bits.
    #[cfg(unix)]
    {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&cache_dir)
            .map_err(|e| {
                AppError::Tls(format!(
                    "failed to create ACME cache directory {}: {e}",
                    cache_dir.display()
                ))
            })?;
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(&cache_dir).map_err(|e| {
            AppError::Tls(format!(
                "failed to create ACME cache directory {}: {e}",
                cache_dir.display()
            ))
        })?;
    }

    if cfg.staging {
        log::warn!(
            "TLS/ACME: staging=true — certificates will NOT be trusted by browsers. \
             Set staging = false in [tls.acme] once you have verified the ACME flow."
        );
    }

    log::info!(
        "TLS/ACME: configuring for domains {:?} (staging={})",
        cfg.domains,
        cfg.staging
    );

    let cache = rustls_acme::caches::DirCache::new(cache_dir);

    // Modern builder API (rustls-acme ≥ 0.15+).
    // Note: `directory_lets_encrypt` takes a *production* bool (true = prod).
    let mut acme_cfg = rustls_acme::AcmeConfig::new(cfg.domains.iter().map(String::as_str))
        .cache(cache)
        .directory_lets_encrypt(!cfg.staging);

    // Contact email — Let's Encrypt uses this for expiry notices.
    if let Some(email) = &cfg.email {
        acme_cfg = acme_cfg.contact_push(format!("mailto:{email}"));
    } else {
        log::warn!(
            "TLS/ACME: no contact email configured; \
             Let's Encrypt recommends providing one for expiry notifications"
        );
    }

    let state = acme_cfg.state();

    // Build a ServerConfig backed by the ACME cert resolver so that
    // dynamically-renewed certificates are visible to rustls without restart.
    let server_cfg = Arc::new(
        ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(state.resolver()),
    );

    // FIXME(rustls-acme): migrate to `axum_acceptor`, `AcmeState::incoming`,
    // or a manual CertResolver integration once `acceptor()` is removed.
    // Track: https://github.com/FlorianUekermann/rustls-acme — replace this
    // comment with the upstream issue URL when filed.
    #[allow(deprecated)]
    let acme_acceptor = Arc::new(state.acceptor());

    // The environment label is runtime-derived, so Arc<str> matches its
    // lifetime more honestly than &'static str.
    let env_label: Arc<str> = if cfg.staging { "staging" } else { "production" }.into();

    // Use try_current() to convert a missing-runtime panic into a recoverable
    // AppError.
    let rt_handle = Handle::try_current().map_err(|_| {
        AppError::Tls(
            "build_acme_acceptor must be called from within an active Tokio runtime".into(),
        )
    })?;

    let task_handle = rt_handle.spawn(run_acme_event_loop(state, env_label));

    // Mark initialization as complete only after every fallible step
    // has succeeded. If any earlier step returned Err (validation, cache dir
    // creation, runtime handle, etc.) the lock was never set, so the caller
    // can retry without restarting the process.
    //
    // set() returns Err(()) if another thread raced us here — treat that as
    // a duplicate-initialization error (same message as the early-exit guard).
    ACME_INITIALIZED.set(()).map_err(|()| {
        AppError::Tls(
            "build_acme_acceptor completed concurrently on another thread; \
             ACME may only be initialized once per process"
                .into(),
        )
    })?;

    Ok((acme_acceptor, server_cfg, task_handle))
}

// ---------------------------------------------------------------------------
// ACME event loop
// ---------------------------------------------------------------------------
/// Drive the rustls-acme state machine to completion.
///
/// Informational events (new cert issued, renewal triggered) and non-fatal
/// errors (transient network failures, brief rate-limit hits) are both
/// handled without terminating the loop.
///
/// Consecutive errors trigger a linear back-off (1 s per error, capped at
/// 60 s) to avoid busy-looping against a persistently unavailable ACME
/// server or misconfigured DNS.
///
/// The loop exits only when the underlying stream closes, which normally
/// only happens during a clean process shutdown.
async fn run_acme_event_loop<EC, EA>(
    mut state: rustls_acme::AcmeState<EC, EA>,
    env_label: Arc<str>,
) where
    EC: Debug + Send + 'static,
    EA: Debug + Send + 'static,
{
    log::info!("TLS/ACME: event loop started ({env_label})");
    let mut consecutive_errors: u32 = 0;

    loop {
        match state.next().await {
            Some(Ok(event)) => {
                consecutive_errors = 0;
                log::info!("TLS/ACME [{env_label}]: {event:?}");
            }
            Some(Err(err)) => {
                // Back off on consecutive errors instead of immediately
                // looping, which would busy-spin and flood logs
                // during persistent failures (bad DNS, rate limits, etc.).
                // The rustls-acme state machine handles retries internally;
                // the sleep here prevents us from hammering it faster than
                // it can recover.
                consecutive_errors = consecutive_errors.saturating_add(1);
                let backoff = Duration::from_secs(u64::from(consecutive_errors).min(60));
                log::warn!(
                    "TLS/ACME [{env_label}] error ({consecutive_errors} consecutive): \
                     {err:?} — backing off for {backoff:?}"
                );
                tokio::time::sleep(backoff).await;
            }
            None => {
                // Stream closed — normal during a clean shutdown.
                log::info!("TLS/ACME [{env_label}]: event loop terminated");
                break;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Config validation
// ---------------------------------------------------------------------------
/// Reject obviously broken configs early, before any filesystem or network
/// activity.
///
/// Validates, in order:
/// - `domains`: non-empty; each entry is an ASCII, lowercase, dot-containing
///   FQDN with no leading/trailing dots, no duplicate entries, no wildcards,
///   and is not an IP address.
/// - `cache_dir`: relative path with no `..` components and a reasonable
///   length for the segment (resolved-path length is checked in
///   `build_acme_acceptor` after joining with `data_dir`).
/// - `email`: if provided, non-empty and structurally plausible
///   (`local@domain`).
///
/// All `AcmeConfig` field validation is consolidated here so callers get a
/// complete picture from a single call site.
fn validate_acme_config(cfg: &AcmeConfig) -> Result<()> {
    // --- domains -------------------------------------------------------

    if cfg.domains.is_empty() {
        return Err(AppError::Tls(
            "[tls.acme] requires at least one domain in domains".into(),
        ));
    }

    // Sending the same domain twice triggers redundant challenge attempts and
    // can exhaust
    // Let's Encrypt's per-domain rate limits.
    let mut seen: HashSet<&str> = HashSet::new();

    for domain in &cfg.domains {
        let trimmed = domain.trim();

        if trimmed.is_empty() {
            return Err(AppError::Tls(
                "[tls.acme] domains contains an empty/whitespace-only string".into(),
            ));
        }
        if *domain != trimmed {
            return Err(AppError::Tls(format!(
                "[tls.acme] domain {domain:?} contains leading/trailing whitespace"
            )));
        }
        // Non-ASCII (IDN) domains must be punycode-encoded before
        // submission. rustls-acme does not perform IDN normalisation, so
        // passing "münchen.de" would produce an obscure runtime failure.
        if !trimmed.is_ascii() {
            return Err(AppError::Tls(format!(
                "[tls.acme] domain {domain:?} contains non-ASCII characters; \
                 encode internationalized domains in punycode (e.g. xn--...)"
            )));
        }
        // RFC 8555 §7.1.4 requires canonical lowercase identifiers.
        // Mixed-case domains may also fail SNI matching at the TLS layer.
        if trimmed.chars().any(|c| c.is_ascii_uppercase()) {
            return Err(AppError::Tls(format!(
                "[tls.acme] domain {domain:?} must be all-lowercase \
                 (RFC 8555 §7.1.4 canonical form)"
            )));
        }
        // Reject malformed dot placement.
        if trimmed.starts_with('.') || trimmed.ends_with('.') || trimmed.contains("..") {
            return Err(AppError::Tls(format!(
                "[tls.acme] domain {domain:?} has invalid dot placement \
                 (leading dot, trailing dot, or consecutive dots)"
            )));
        }
        // Wildcards are incompatible with TLS-ALPN-01, which is
        // what rustls-acme uses. DNS-01 is required for wildcard issuance.
        if trimmed.starts_with("*.") {
            return Err(AppError::Tls(format!(
                "[tls.acme] wildcard domain {domain:?} is not supported by \
                 TLS-ALPN-01; use DNS-01 for wildcard certificate issuance"
            )));
        }
        // Must contain at least one dot and must not be a raw IP address.
        if !trimmed.contains('.') || trimmed.parse::<IpAddr>().is_ok() {
            return Err(AppError::Tls(format!(
                "[tls.acme] invalid domain {domain:?}: must be a fully-qualified \
                 domain name, not a bare hostname or IP address"
            )));
        }
        // Duplicate check after normalization.
        if !seen.insert(trimmed) {
            return Err(AppError::Tls(format!(
                "[tls.acme] duplicate domain {domain:?} in domains list"
            )));
        }
    }

    // --- cache_dir -----------------------------------------------------
    // Keep cache-dir validation here so this function is the single
    // authoritative validation entry point for AcmeConfig.

    if Path::new(&cfg.cache_dir).is_absolute() {
        return Err(AppError::Tls(
            "[tls.acme.cache_dir] must be a relative path".into(),
        ));
    }
    // Use Path::components() instead of str::contains("..") to perform a
    // correct component-aware check. The string ".." can appear in
    // non-traversal contexts (e.g. "a/..b") while a ParentDir component is
    // unambiguously a directory traversal.
    if Path::new(&cfg.cache_dir)
        .components()
        .any(|c| c == Component::ParentDir)
    {
        return Err(AppError::Tls(
            "[tls.acme.cache_dir] must not contain '..' path traversal segments".into(),
        ));
    }
    if cfg.cache_dir.len() > 512 {
        return Err(AppError::Tls(
            "[tls.acme.cache_dir] path segment too long (max 512 chars); \
             the resolved path is checked separately in build_acme_acceptor"
                .into(),
        ));
    }

    // --- email ---------------------------------------------------------

    if let Some(email) = &cfg.email {
        let trimmed = email.trim();
        if trimmed.is_empty() {
            return Err(AppError::Tls(
                "[tls.acme] email is set but empty/whitespace-only; \
                 provide a valid address or remove the key"
                    .into(),
            ));
        }
        // Basic structural check: non-empty local part + '@' +
        // non-empty domain part. Full RFC 5321 validation is out of scope,
        // but this catches the most common typos before Let's Encrypt rejects
        // the account registration with a cryptic error.
        match trimmed.split_once('@') {
            None | Some(("", _) | (_, "")) => {
                return Err(AppError::Tls(format!(
                    "[tls.acme] email {trimmed:?} is not a plausible address; \
                     expected format: local@domain"
                )));
            }
            _ => {}
        }
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

    // --- domain validation ---

    #[test]
    fn rejects_empty_domains() {
        let mut cfg = valid_cfg();
        cfg.domains = vec![];
        assert!(validate_acme_config(&cfg).is_err());
    }

    #[test]
    fn rejects_empty_domain_string() {
        let mut cfg = valid_cfg();
        cfg.domains = vec![String::new()];
        assert!(validate_acme_config(&cfg).is_err());
    }

    #[test]
    fn rejects_whitespace_only_domain() {
        let mut cfg = valid_cfg();
        cfg.domains = vec!["   ".into()];
        assert!(validate_acme_config(&cfg).is_err());
    }

    #[test]
    fn rejects_domain_with_leading_whitespace() {
        let mut cfg = valid_cfg();
        cfg.domains = vec![" ex.com".into()];
        assert!(validate_acme_config(&cfg).is_err());
    }

    #[test]
    fn rejects_domain_with_trailing_whitespace() {
        let mut cfg = valid_cfg();
        cfg.domains = vec!["ex.com ".into()];
        assert!(validate_acme_config(&cfg).is_err());
    }

    #[test]
    fn rejects_non_ascii_domain() {
        let mut cfg = valid_cfg();
        cfg.domains = vec!["münchen.de".into()];
        assert!(validate_acme_config(&cfg).is_err());
    }

    #[test]
    fn rejects_uppercase_domain() {
        let mut cfg = valid_cfg();
        cfg.domains = vec!["Example.COM".into()];
        assert!(validate_acme_config(&cfg).is_err());
    }

    #[test]
    fn rejects_mixed_case_domain() {
        let mut cfg = valid_cfg();
        cfg.domains = vec!["Example.com".into()];
        assert!(validate_acme_config(&cfg).is_err());
    }

    #[test]
    fn rejects_leading_dot_domain() {
        let mut cfg = valid_cfg();
        cfg.domains = vec![".example.com".into()];
        assert!(validate_acme_config(&cfg).is_err());
    }

    #[test]
    fn rejects_trailing_dot_domain() {
        let mut cfg = valid_cfg();
        cfg.domains = vec!["example.com.".into()];
        assert!(validate_acme_config(&cfg).is_err());
    }

    #[test]
    fn rejects_consecutive_dots_domain() {
        let mut cfg = valid_cfg();
        cfg.domains = vec!["exam..ple.com".into()];
        assert!(validate_acme_config(&cfg).is_err());
    }

    #[test]
    fn rejects_wildcard_domain() {
        let mut cfg = valid_cfg();
        cfg.domains = vec!["*.example.com".into()];
        assert!(validate_acme_config(&cfg).is_err());
    }

    #[test]
    fn rejects_ip_address_domain() {
        let mut cfg = valid_cfg();
        cfg.domains = vec!["1.2.3.4".into()];
        assert!(validate_acme_config(&cfg).is_err());
    }

    #[test]
    fn rejects_ipv6_address_domain() {
        let mut cfg = valid_cfg();
        cfg.domains = vec!["::1".into()];
        assert!(validate_acme_config(&cfg).is_err());
    }

    #[test]
    fn rejects_bare_hostname() {
        let mut cfg = valid_cfg();
        cfg.domains = vec!["localhost".into()];
        assert!(validate_acme_config(&cfg).is_err());
    }

    #[test]
    fn rejects_duplicate_domains() {
        let mut cfg = valid_cfg();
        cfg.domains = vec!["example.com".into(), "example.com".into()];
        assert!(validate_acme_config(&cfg).is_err());
    }

    #[test]
    fn accepts_valid_single_domain() {
        assert!(validate_acme_config(&valid_cfg()).is_ok());
    }

    #[test]
    fn accepts_multiple_distinct_domains() {
        let mut cfg = valid_cfg();
        cfg.domains = vec!["example.com".into(), "www.example.com".into()];
        assert!(validate_acme_config(&cfg).is_ok());
    }

    // --- email validation ---

    #[test]
    fn rejects_empty_email_string() {
        let mut cfg = valid_cfg();
        cfg.email = Some(String::new());
        assert!(validate_acme_config(&cfg).is_err());
    }

    #[test]
    fn rejects_whitespace_only_email() {
        let mut cfg = valid_cfg();
        cfg.email = Some("   ".into());
        assert!(validate_acme_config(&cfg).is_err());
    }

    #[test]
    fn rejects_email_without_at_sign() {
        let mut cfg = valid_cfg();
        cfg.email = Some("notanemail".into());
        assert!(validate_acme_config(&cfg).is_err());
    }

    #[test]
    fn rejects_email_with_empty_local_part() {
        let mut cfg = valid_cfg();
        cfg.email = Some("@example.com".into());
        assert!(validate_acme_config(&cfg).is_err());
    }

    #[test]
    fn rejects_email_with_empty_domain_part() {
        let mut cfg = valid_cfg();
        cfg.email = Some("user@".into());
        assert!(validate_acme_config(&cfg).is_err());
    }

    #[test]
    fn accepts_none_email() {
        let mut cfg = valid_cfg();
        cfg.email = None;
        // None is valid — a warning is emitted at runtime.
        assert!(validate_acme_config(&cfg).is_ok());
    }

    #[test]
    fn accepts_valid_email() {
        assert!(validate_acme_config(&valid_cfg()).is_ok());
    }

    // --- cache_dir validation ---

    #[test]
    fn rejects_absolute_cache_dir() {
        let mut cfg = valid_cfg();
        cfg.cache_dir = "/etc/acme".into();
        assert!(validate_acme_config(&cfg).is_err());
    }

    #[test]
    fn rejects_dotdot_cache_dir_prefix() {
        let mut cfg = valid_cfg();
        cfg.cache_dir = "../outside".into();
        assert!(validate_acme_config(&cfg).is_err());
    }

    #[test]
    fn rejects_dotdot_cache_dir_in_middle() {
        // The old str::contains("..") would flag "a/..b" (false positive)
        // but miss this when the component boundary falls elsewhere.
        // Component::ParentDir is unambiguous.
        let mut cfg = valid_cfg();
        cfg.cache_dir = "tls/../../../etc/passwd".into();
        assert!(validate_acme_config(&cfg).is_err());
    }

    #[test]
    fn accepts_dotdot_in_filename_component() {
        // "a/..b" — ".." appears as a substring but there is NO ParentDir
        // component; this is a valid (if unusual) relative path.
        // Note: this is an edge case; most real configs won't use such names.
        // The component-aware check correctly accepts it.
        let mut cfg = valid_cfg();
        cfg.cache_dir = "tls/..cache".into(); // component is "..cache", not ".."
        assert!(validate_acme_config(&cfg).is_ok());
    }

    #[test]
    fn rejects_overlong_cache_dir_segment() {
        let mut cfg = valid_cfg();
        cfg.cache_dir = "a".repeat(513);
        assert!(validate_acme_config(&cfg).is_err());
    }

    #[test]
    fn accepts_valid_relative_cache_dir() {
        let cfg = valid_cfg();
        assert!(validate_acme_config(&cfg).is_ok());
    }

    #[test]
    fn accepts_nested_relative_cache_dir() {
        let mut cfg = valid_cfg();
        cfg.cache_dir = "data/tls/acme/cache".into();
        assert!(validate_acme_config(&cfg).is_ok());
    }
}
