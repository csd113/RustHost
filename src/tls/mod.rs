//! `src/tls/mod.rs`
pub mod acme;
pub mod self_signed;

use std::{path::Path, sync::Arc};

use rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;

use crate::Result;
use crate::{
    config::{ManualCertConfig, TlsConfig},
    error::AppError,
};

/// A TLS acceptor that is either a static [`TlsAcceptor`] (manual cert or
/// self-signed) or an [`AcmeAcceptor`] (Let's Encrypt / rustls-acme).
///
/// The ACME variant cannot be represented as a plain [`TlsAcceptor`] because
/// the underlying certificate is rotated dynamically by the background renewal
/// loop, which requires the `AcmeAcceptor` handle to remain live.
pub enum Acceptor {
    /// Static certificate — manual PEM files or a self-signed dev cert.
    Static(Arc<TlsAcceptor>),
    /// Let's Encrypt certificate managed by `rustls-acme`.
    ///
    /// The `ServerConfig` is stored alongside the acceptor because
    /// `futures_rustls::server::StartHandshake::into_stream` requires it to
    /// complete the handshake.  It is built with `ResolvesServerCertAcme` as
    /// the certificate resolver so that newly-issued/renewed certificates are
    /// picked up automatically without restarting the server.
    Acme(Arc<rustls_acme::AcmeAcceptor>, Arc<ServerConfig>),
}

/// Construct an [`Acceptor`] from the provided [`TlsConfig`], or return
/// `None` if TLS is disabled.
///
/// Resolution order:
///   1. `tls.enabled = false`  →  `None`  (HTTP-only, no change to existing behaviour)
///   2. `[tls.manual_cert]`    →  load PEM files from disk
///   3. `[tls.acme]`           →  Let's Encrypt via `rustls-acme` (spawns renewal loop)
///   4. fallback               →  auto-generate a `localhost` self-signed cert via `rcgen`
///
/// # Errors
///
/// Returns [`crate::AppError::Tls`] if:
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
        log::info!("TLS: starting ACME / Let's Encrypt provisioning");
        let (acme_acceptor, server_cfg) = acme::build_acme_acceptor(&cfg.acme, data_dir)?;
        return Ok(Some(Acceptor::Acme(acme_acceptor, server_cfg)));
    }

    log::info!("TLS: no cert configured — generating self-signed dev certificate");
    Ok(Some(Acceptor::Static(self_signed::generate_or_load(
        data_dir,
    )?)))
}

// ---------------------------------------------------------------------------
// Manual cert loader (shared by mod.rs; also called from tests)
// ---------------------------------------------------------------------------

/// Load a PEM certificate chain + private key from disk and wrap them in a
/// [`TlsAcceptor`].  Paths in [`ManualCertConfig`] are resolved relative to
/// `data_dir` so that configs remain portable.
fn load_manual_cert(cfg: &ManualCertConfig, data_dir: &Path) -> Result<Arc<TlsAcceptor>> {
    let cert_path = data_dir.join(&cfg.cert_path);
    let key_path = data_dir.join(&cfg.key_path);

    log::debug!(
        "TLS: loading cert from {} and key from {}",
        cert_path.display(),
        key_path.display()
    );

    load_pem_as_acceptor(&cert_path, &key_path)
}

// ---------------------------------------------------------------------------
// Shared PEM → TlsAcceptor helper
// (also used by self_signed after writing the cert files)
// ---------------------------------------------------------------------------

/// Parse a PEM certificate chain and a PEM private key from disk and produce
/// a [`TlsAcceptor`] backed by a [`rustls::ServerConfig`].
///
/// rustls defaults are intentionally left untouched — TLS 1.2+ and a safe
/// cipher list are enforced automatically; no overrides required.
pub(super) fn load_pem_as_acceptor(cert_path: &Path, key_path: &Path) -> Result<Arc<TlsAcceptor>> {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use rustls_pemfile::{certs, private_key};

    // --- certificate chain ---------------------------------------------------
    let cert_pem = std::fs::read(cert_path)
        .map_err(|e| AppError::Tls(format!("failed to read cert {}: {e}", cert_path.display())))?;

    let certs: Vec<CertificateDer<'static>> = certs(&mut cert_pem.as_slice())
        .collect::<std::io::Result<_>>()
        .map_err(|e| AppError::Tls(format!("failed to parse cert PEM: {e}")))?;

    if certs.is_empty() {
        return Err(AppError::Tls(format!(
            "no certificates found in {}",
            cert_path.display()
        )));
    }

    // --- private key ---------------------------------------------------------
    let key_pem = std::fs::read(key_path)
        .map_err(|e| AppError::Tls(format!("failed to read key {}: {e}", key_path.display())))?;

    let key: PrivateKeyDer<'static> = private_key(&mut key_pem.as_slice())
        .map_err(|e| AppError::Tls(format!("failed to parse key PEM: {e}")))?
        .ok_or_else(|| AppError::Tls(format!("no private key found in {}", key_path.display())))?;

    // --- ServerConfig --------------------------------------------------------
    let server_cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| AppError::Tls(format!("invalid certificate/key pair: {e}")))?;

    Ok(Arc::new(TlsAcceptor::from(Arc::new(server_cfg))))
}
