//! `src/tls/mod.rs`
pub mod acme;
pub mod self_signed;

use std::{
    io::BufReader,
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
    sync::Arc,
};

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

static ACME_INITIALIZED: AtomicBool = AtomicBool::new(false);

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
    Acme(Arc<rustls_acme::AcmeAcceptor>, Arc<ServerConfig>),
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
pub fn build_acceptor(cfg: &TlsConfig, data_dir: &Path) -> Result<Option<Acceptor>> {
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
        let already_init = ACME_INITIALIZED.swap(true, Ordering::Relaxed);
        if already_init {
            log::warn!("TLS: ACME already initialized elsewhere; skipping duplicate spawn");
        }
        let (acme_acceptor, server_cfg) = acme::build_acme_acceptor(&cfg.acme, data_dir)?;
        return Ok(Some(Acceptor::Acme(acme_acceptor, server_cfg)));
    }

    log::info!("TLS: no cert configured — generating/loading self-signed dev certificate");
    let acceptor = self_signed::generate_or_load(data_dir)?;
    log::warn!(
        "TLS: using self-signed localhost dev cert (INSECURE FOR PROD — configure manual_cert or acme)"
    );
    Ok(Some(Acceptor::Static(acceptor)))
}

// ---------------------------------------------------------------------------
// Manual cert loader
// ---------------------------------------------------------------------------

fn load_manual_cert(cfg: &ManualCertConfig, data_dir: &Path) -> Result<Arc<TlsAcceptor>> {
    let cert_path = data_dir.join(&cfg.cert_path);
    let key_path = data_dir.join(&cfg.key_path);

    if cert_path.is_absolute() || !cert_path.starts_with(data_dir) {
        return Err(AppError::Tls(format!(
            "cert path escapes data_dir: {}",
            cfg.cert_path
        )));
    }
    if key_path.is_absolute() || !key_path.starts_with(data_dir) {
        return Err(AppError::Tls(format!(
            "key path escapes data_dir: {}",
            cfg.key_path
        )));
    }

    log::debug!(
        "TLS: loading cert from {} and key from {}",
        cert_path.display(),
        key_path.display()
    );

    load_pem_as_acceptor(&cert_path, &key_path)
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
