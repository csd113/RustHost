//! `src/tls/mod.rs`
pub mod acme;
pub mod self_signed;

use std::{io::BufReader, path::Path, sync::Arc};

use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer},
    ServerConfig,
};
use rustls_pemfile::{certs, private_key};
use tokio_rustls::TlsAcceptor;

use crate::Result;
use crate::{
    config::{ManualCertConfig, TlsConfig},
    error::AppError,
};

/// Converts a borrowed `PrivateKeyDer` to an owned `'static` version.
fn private_key_der_to_static(key: &PrivateKeyDer<'_>) -> PrivateKeyDer<'static> {
    key.clone_key()
}

/// A TLS acceptor that is either a static [`TlsAcceptor`] (manual cert or
/// self-signed) or an [`AcmeAcceptor`] (Let's Encrypt / rustls-acme).
pub enum Acceptor {
    /// Static certificate — manual PEM files or a self-signed dev cert.
    Static(Arc<TlsAcceptor>),
    /// Let's Encrypt certificate managed by `rustls-acme`.
    ///
    /// The [`tokio::task::JoinHandle`] is wrapped in [`Arc`] so the
    /// `Acceptor` can be cheaply cloned for each accepted connection without
    /// transferring ownership of the handle. The handle drives the ACME event
    /// loop (challenge responses, renewals) and **must** be retained and
    /// awaited during graceful shutdown; all clones share the same underlying
    /// task — awaiting any one of them is sufficient.
    Acme(
        Arc<rustls_acme::AcmeAcceptor>,
        Arc<ServerConfig>,
        Arc<tokio::task::JoinHandle<()>>,
    ),
}

/// Construct an [`Acceptor`] from the provided [`TlsConfig`], or return
/// `None` if TLS is disabled.
///
/// Resolution order:
///   1. `tls.enabled = false`  →  `None`  (HTTP-only)
///   2. `[tls.manual_cert]`    →  load PEM files from disk
///   3. `[tls.acme]`           →  Let's Encrypt via `rustls-acme`
///   4. fallback               →  auto-generate a self-signed cert via `rcgen`
///
/// # Errors
///
/// Returns [`AppError::Tls`] if:
/// - A manual certificate path cannot be read or parsed.
/// - The ACME config is invalid (empty domain list, IP address as domain, etc.).
/// - The ACME cache directory cannot be created.
/// - The self-signed certificate cannot be generated or written to disk.
pub async fn build_acceptor(cfg: &TlsConfig, data_dir: &Path) -> Result<Option<Acceptor>> {
    if !cfg.enabled {
        return Ok(None);
    }

    if let Some(manual) = &cfg.manual_cert {
        log::info!("TLS: loading manual certificate");
        return Ok(Some(Acceptor::Static(load_manual_cert(manual, data_dir)?)));
    }

    if cfg.acme.enabled {
        log::info!(
            "TLS: starting ACME / Let's Encrypt provisioning (cache: {})",
            cfg.acme.cache_dir.as_str()
        );
        // Duplicate-initialization is now enforced by the OnceLock guard
        // inside acme::build_acme_acceptor — a second call returns an error.
        let (acme_acceptor, server_cfg, event_loop) =
            acme::build_acme_acceptor(&cfg.acme, data_dir)?;
        return Ok(Some(Acceptor::Acme(
            acme_acceptor,
            server_cfg,
            Arc::new(event_loop),
        )));
    }

    log::info!("TLS: no cert configured — generating/loading self-signed dev certificate");
    let acceptor = self_signed::generate_or_load(data_dir).await?;
    log::warn!(
        "TLS: using self-signed localhost dev cert (INSECURE FOR PROD — configure manual_cert or acme)"
    );
    Ok(Some(Acceptor::Static(acceptor)))
}

// ---------------------------------------------------------------------------
// Manual cert loader
// ---------------------------------------------------------------------------

fn load_manual_cert(cfg: &ManualCertConfig, data_dir: &Path) -> Result<Arc<TlsAcceptor>> {
    use std::path::Component;

    // Task 1.1 (belt): Reject ParentDir components before joining with data_dir.
    // A pure string/lexical starts_with check on the joined path can be fooled by
    // paths like "../outside.crt" — they pass the prefix test as a string but the
    // OS resolves them to a location entirely outside data_dir.
    // Mirror the pattern already used by validate_acme_config in acme.rs.
    if Path::new(&cfg.cert_path)
        .components()
        .any(|c| c == Component::ParentDir)
    {
        return Err(AppError::Tls(
            "cert_path must not contain parent directory components".into(),
        ));
    }
    if Path::new(&cfg.key_path)
        .components()
        .any(|c| c == Component::ParentDir)
    {
        return Err(AppError::Tls(
            "key_path must not contain parent directory components".into(),
        ));
    }

    // Absolute paths are also unconditionally rejected — cert files must live
    // inside the data directory, not be referenced by a rooted path.
    if Path::new(&cfg.cert_path).is_absolute() {
        return Err(AppError::Tls(
            "cert_path must be a relative path (no leading '/')".into(),
        ));
    }
    if Path::new(&cfg.key_path).is_absolute() {
        return Err(AppError::Tls(
            "key_path must be a relative path (no leading '/')".into(),
        ));
    }

    let cert_path = data_dir.join(&cfg.cert_path);
    let key_path = data_dir.join(&cfg.key_path);

    // Task 1.1 (suspenders): Canonicalize both the data_dir anchor and the
    // resolved paths, then verify containment on the canonical forms.
    // This catches any remaining escapes via symlinks that survive the component
    // check above (e.g. a symlink inside data_dir pointing outside it).
    let canonical_data_dir = std::fs::canonicalize(data_dir)
        .map_err(|e| AppError::Tls(format!("cannot canonicalize data_dir: {e}")))?;
    let canonical_cert = std::fs::canonicalize(&cert_path)
        .map_err(|e| AppError::Tls(format!("cannot resolve cert_path '{}': {e}", cfg.cert_path)))?;
    let canonical_key = std::fs::canonicalize(&key_path)
        .map_err(|e| AppError::Tls(format!("cannot resolve key_path '{}': {e}", cfg.key_path)))?;

    if !canonical_cert.starts_with(&canonical_data_dir) {
        return Err(AppError::Tls(format!(
            "cert_path resolves outside data_dir after canonicalization: {}",
            cfg.cert_path
        )));
    }
    if !canonical_key.starts_with(&canonical_data_dir) {
        return Err(AppError::Tls(format!(
            "key_path resolves outside data_dir after canonicalization: {}",
            cfg.key_path
        )));
    }

    log::debug!(
        "TLS: loading cert from {} and key from {}",
        canonical_cert.display(),
        canonical_key.display()
    );

    // Use the canonical paths for I/O to avoid any TOCTOU between the check
    // above and the actual read in load_pem_as_acceptor.
    load_pem_as_acceptor(&canonical_cert, &canonical_key)
}

// ---------------------------------------------------------------------------
// Shared PEM → TlsAcceptor helper
// ---------------------------------------------------------------------------

/// Parse a PEM certificate chain and a PEM private key from disk and produce
/// a [`TlsAcceptor`] backed by a [`rustls::ServerConfig`].
///
/// # Errors
///
/// Returns [`AppError::Tls`] if the certificate or key file cannot be read,
/// parsed, or if the resulting pair is invalid.
pub(super) fn load_pem_as_acceptor(cert_path: &Path, key_path: &Path) -> Result<Arc<TlsAcceptor>> {
    // --- certificate chain ---------------------------------------------------
    let cert_pem = std::fs::read(cert_path)
        .map_err(|e| AppError::Tls(format!("read cert {}: {e}", cert_path.display())))?;
    let mut cert_reader = BufReader::new(&cert_pem[..]);

    let cert_chain: Vec<CertificateDer<'static>> = certs(&mut cert_reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| AppError::Tls(format!("parse cert PEM {}: {e}", cert_path.display())))?;

    if cert_chain.is_empty() {
        return Err(AppError::Tls(format!(
            "no certificates found in {}",
            cert_path.display()
        )));
    }

    // --- private key ---------------------------------------------------------
    let key_pem = std::fs::read(key_path)
        .map_err(|e| AppError::Tls(format!("read key {}: {e}", key_path.display())))?;
    let mut key_reader = BufReader::new(&key_pem[..]);

    let key_der: PrivateKeyDer<'static> = private_key(&mut key_reader)
        .map_err(|e| AppError::Tls(format!("parse key PEM {}: {e}", key_path.display())))?
        .map(|k| private_key_der_to_static(&k))
        .ok_or_else(|| AppError::Tls(format!("no private key found in {}", key_path.display())))?;

    // --- ServerConfig --------------------------------------------------------
    let server_cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key_der)
        .map_err(|e| AppError::Tls(format!("invalid certificate/key pair: {e}")))?;

    Ok(Arc::new(TlsAcceptor::from(Arc::new(server_cfg))))
}

// ---------------------------------------------------------------------------
// Tests — Task 1.1 path traversal regression
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ManualCertConfig;
    use tempfile::TempDir;

    fn traversal_cfg(cert: &str, key: &str) -> ManualCertConfig {
        ManualCertConfig {
            cert_path: cert.into(),
            key_path: key.into(),
        }
    }

    // Helper: call load_manual_cert and check that it returns an Err whose
    // message contains `needle`.
    fn assert_rejected(cfg: &ManualCertConfig, data_dir: &Path, needle: &str) {
        match load_manual_cert(cfg, data_dir) {
            Ok(_) => panic!("expected load_manual_cert to return Err"),
            Err(err) => {
                let msg = err.to_string();
                assert!(
                    msg.contains(needle),
                    "expected error to contain {needle:?}, got: {msg:?}"
                );
            }
        }
    }

    #[test]
    fn rejects_parent_dir_in_cert_path() {
        let tmp = TempDir::new().unwrap();
        let cfg = traversal_cfg("../outside.crt", "server.key");
        assert_rejected(&cfg, tmp.path(), "parent directory");
    }

    #[test]
    fn rejects_parent_dir_in_key_path() {
        let tmp = TempDir::new().unwrap();
        let cfg = traversal_cfg("server.crt", "../outside.key");
        assert_rejected(&cfg, tmp.path(), "parent directory");
    }

    #[test]
    fn rejects_nested_traversal_in_cert_path() {
        let tmp = TempDir::new().unwrap();
        let cfg = traversal_cfg("sub/../../escape.crt", "server.key");
        assert_rejected(&cfg, tmp.path(), "parent directory");
    }

    #[test]
    fn rejects_absolute_cert_path() {
        let tmp = TempDir::new().unwrap();
        let cfg = traversal_cfg("/etc/ssl/cert.pem", "server.key");
        assert_rejected(&cfg, tmp.path(), "relative path");
    }

    #[test]
    fn rejects_absolute_key_path() {
        let tmp = TempDir::new().unwrap();
        let cfg = traversal_cfg("server.crt", "/etc/ssl/private/key.pem");
        assert_rejected(&cfg, tmp.path(), "relative path");
    }
}
