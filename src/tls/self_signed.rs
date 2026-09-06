//! # Self-Signed TLS Certificates
use crate::error::AppError;
use crate::Result;
use std::{path::Path, sync::Arc, time::SystemTime};
use tokio_rustls::TlsAcceptor;

/// Number of days before expiry at which the cert is considered stale and
/// will be regenerated on the next startup.
const REGENERATE_BEFORE_DAYS: u64 = 30;

/// Certificates are valid for this many days when freshly generated.
const CERT_VALIDITY_DAYS: u32 = 365;

/// Names embedded in the self-signed certificate.
const CERT_SANS: &[&str] = &["localhost", "127.0.0.1", "::1"];

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------
/// Return a [`TlsAcceptor`] backed by a self-signed `localhost` certificate.
///
/// If a valid, non-expiring cert already exists in `<data_dir>/runtime/tls/dev/` it
/// is reused. A single `self-signed.pem` bundle holds both certificate and key;
/// renewal retains a validated `self-signed.previous.pem` for recovery. Valid
/// legacy `.crt`/`.key` pairs are imported without altering the original files.
/// Files use mode `0600` on Unix. Malformed state without a usable backup fails
/// explicitly rather than silently changing the development identity.
///
/// **This is intended for local development only.** Never use a self-signed
/// cert in production — configure `[tls.acme]` or `[tls.manual_cert]`
/// instead.
///
/// # Errors
///
/// Returns [`AppError::Tls`] (wrapped in [`crate::Result`]) if directory
/// creation fails, certificate/key generation fails, the private files cannot
/// be written, or the PEM files cannot be loaded into a `TlsAcceptor`.
///
/// # Blocking behaviour
///
/// This function performs synchronous file I/O. It must be called via
/// [`tokio::task::spawn_blocking`] (or equivalent) when invoked from inside
/// an async Tokio context to avoid stalling the async runtime.
pub async fn generate_or_load(data_dir: &Path) -> Result<Arc<TlsAcceptor>> {
    // All filesystem calls in this function are blocking, so they are
    // offloaded to a dedicated thread to avoid stalling the Tokio executor.
    let data_dir = data_dir.to_path_buf();
    tokio::task::spawn_blocking(move || generate_or_load_blocking(&data_dir))
        .await
        .map_err(|e| AppError::Tls(format!("TLS setup task panicked: {e}")))?
}

const BUNDLE_NAME: &str = "self-signed.pem";
const BACKUP_NAME: &str = "self-signed.previous.pem";
const MAX_PEM_BYTES: u64 = 1024 * 1024;

fn generate_or_load_blocking(data_dir: &Path) -> Result<Arc<TlsAcceptor>> {
    let path = data_dir.join("runtime/tls/dev");
    let mut dir = crate::persistence::Directory::open(&path)?;
    let current = load_bundle(&path.join(BUNDLE_NAME));
    let existing = match current {
        Ok(Some(bundle)) => Some(bundle),
        Ok(None) => match load_bundle(&path.join(BACKUP_NAME))? {
            Some(previous) => Some(previous),
            None => load_legacy(&path)?,
        },
        Err(error) => {
            if let Some(previous) = load_bundle(&path.join(BACKUP_NAME))? {
                log::warn!(
                    "TLS: current development bundle invalid ({error}); recovering previous pair"
                );
                Some(previous)
            } else {
                return Err(AppError::Tls(format!(
                    "development TLS bundle is invalid and no valid previous pair exists: {error}"
                )));
            }
        }
    };
    if let Some(bundle) = existing {
        if remaining_validity_days(&bundle).is_some_and(|days| days >= REGENERATE_BEFORE_DAYS) {
            // Also completes a legacy import or recovery without changing identity.
            if crate::persistence::read_bounded(&path.join(BUNDLE_NAME), MAX_PEM_BYTES)
                .ok()
                .as_deref()
                != Some(bundle.as_slice())
            {
                dir.write(BUNDLE_NAME, &bundle, true)?;
            }
            return super::pem_as_acceptor(&bundle, &bundle);
        }
        // Sync a complete, validated previous pair before replacing the current one.
        dir.write(BACKUP_NAME, &bundle, true)?;
    }
    let bundle = generate_bundle()?;
    let acceptor = super::pem_as_acceptor(&bundle, &bundle)?;
    dir.write(BUNDLE_NAME, &bundle, true)?;
    Ok(acceptor)
}

fn load_bundle(path: &Path) -> Result<Option<Vec<u8>>> {
    let bundle = match crate::persistence::read_bounded(path, MAX_PEM_BYTES) {
        Ok(bundle) => bundle,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    super::pem_as_acceptor(&bundle, &bundle)?;
    Ok(Some(bundle))
}

fn load_legacy(path: &Path) -> Result<Option<Vec<u8>>> {
    let cert = path.join("self-signed.crt");
    let key = path.join("self-signed.key");
    if !cert.try_exists()? && !key.try_exists()? {
        return Ok(None);
    }
    let mut bundle = crate::persistence::read_bounded(&cert, MAX_PEM_BYTES)?;
    let key = crate::persistence::read_bounded(&key, MAX_PEM_BYTES)?;
    super::pem_as_acceptor(&bundle, &key)?;
    bundle.push(b'\n');
    bundle.extend_from_slice(&key);
    Ok(Some(bundle))
}

fn generate_bundle() -> Result<Vec<u8>> {
    log::info!("TLS: generating self-signed certificate for {CERT_SANS:?}");
    let params = build_cert_params()?;
    let key_pair = rcgen::KeyPair::generate()
        .map_err(|e| AppError::Tls(format!("rcgen key generation failed: {e}")))?;
    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| AppError::Tls(format!("rcgen self-sign failed: {e}")))?;
    Ok(format!("{}{}", cert.pem(), key_pair.serialize_pem()).into_bytes())
}

// The cast `i64::from(CERT_VALIDITY_DAYS)` is a widening u32→i64 conversion
// that cannot overflow.
fn build_cert_params() -> Result<rcgen::CertificateParams> {
    use rcgen::{
        CertificateParams, DistinguishedName, DnValue, ExtendedKeyUsagePurpose, KeyUsagePurpose,
    };
    use time::OffsetDateTime;

    let mut params = CertificateParams::default();

    // Subject
    let mut dn = DistinguishedName::new();
    dn.push(
        rcgen::DnType::CommonName,
        DnValue::Utf8String("RustHost Dev".into()),
    );
    dn.push(
        rcgen::DnType::OrganizationName,
        DnValue::Utf8String("RustHost".into()),
    );
    params.distinguished_name = dn;

    // Validity window: now → now + CERT_VALIDITY_DAYS
    // Use checked_add to satisfy clippy::arithmetic_side_effects; the duration
    // is a compile-time constant (365 days) so overflow is impossible in
    // practice, but checked_add makes that explicit.
    let now = OffsetDateTime::now_utc();
    let expiry = now
        .checked_add(time::Duration::days(i64::from(CERT_VALIDITY_DAYS)))
        .ok_or_else(|| AppError::Tls("cert validity period overflows OffsetDateTime".into()))?;
    params.not_before = now;
    params.not_after = expiry;

    // Subject Alternative Names — required for modern browsers / TLS stacks
    for san in CERT_SANS {
        // san_for returns Result so validation errors are surfaced instead of
        // panicking during startup.
        params.subject_alt_names.push(san_for(san)?);
    }

    // Mark as end-entity (not a CA)
    params.is_ca = rcgen::IsCa::NoCa;

    // === REQUIRED FOR MODERN CLIENTS ===
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];

    Ok(params)
}

/// Decide the correct [`SanType`] for a raw string: IPv4/6 literals become
/// `IpAddress`, everything else becomes `DnsName`.
///
/// # Errors
///
/// Returns [`AppError::Tls`] if `s` is not a valid IP address and rcgen
/// rejects it as a [`DnsName`].
//
// san_for is called in the production cert-generation path; a panic here
// would crash the process at startup. Errors are now surfaced as AppError::Tls.
fn san_for(s: &str) -> Result<rcgen::SanType> {
    if let Ok(ip) = s.parse::<std::net::IpAddr>() {
        Ok(rcgen::SanType::IpAddress(ip))
    } else {
        // rcgen's DnsName does not enforce all RFC 1123 constraints, so we
        // validate explicitly before delegating to it.
        if s.is_empty() {
            return Err(AppError::Tls(format!(
                "invalid SAN DNS name {s:?}: name must not be empty"
            )));
        }
        if s.split('.').any(|label| label.len() > 63) {
            return Err(AppError::Tls(format!(
                "invalid SAN DNS name {s:?}: label exceeds 63-character RFC 1123 limit"
            )));
        }
        // rcgen::DnsName implements TryFrom<&str> directly — no allocation needed.
        let dns = s
            .try_into()
            .map_err(|e| AppError::Tls(format!("invalid SAN DNS name {s:?}: {e}")))?;
        Ok(rcgen::SanType::DnsName(dns))
    }
}

// ---------------------------------------------------------------------------
// Expiry check
// ---------------------------------------------------------------------------
/// Parse the first certificate in a validated bundle to check its expiry.
fn remaining_validity_days(pem_bytes: &[u8]) -> Option<u64> {
    use x509_cert::der::Decode as _;
    let pem = rustls_pemfile::certs(&mut &*pem_bytes).next()?.ok()?;

    // Parse the DER-encoded certificate to reach the validity fields.
    let cert = x509_cert::Certificate::from_der(&pem)
        .map_err(|e| {
            log::debug!("TLS: failed to parse development certificate DER: {e}");
        })
        .ok()?;

    // `not_after` is stored as an ASN.1 Time; convert via Unix timestamp.
    let not_after = cert.tbs_certificate().validity().not_after.to_system_time();
    let remaining = not_after
        .duration_since(SystemTime::now())
        .map_err(|e| {
            log::debug!("TLS: development certificate expired or clock skew detected: {e}");
        })
        .ok()?;

    Some(remaining.as_secs() / 86_400)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]
    use super::*;
    use tempfile::TempDir;

    /// Install the `ring` crypto provider process-wide.
    /// The first call succeeds; subsequent calls from other tests in the same
    /// process return `Err` (already-installed) which is intentionally ignored.
    fn ensure_crypto_provider() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }

    #[tokio::test]
    async fn generates_cert_on_first_call() {
        ensure_crypto_provider();
        let tmp = TempDir::new().unwrap();
        let cert = tmp.path().join("runtime/tls/dev/self-signed.pem");
        assert!(!cert.exists());
        generate_or_load(tmp.path())
            .await
            .expect("generate_or_load failed");
        assert!(cert.exists(), "cert file should exist after first call");
        assert!(load_bundle(&cert).expect("read persisted pair").is_some());
    }

    #[tokio::test]
    async fn reuses_valid_cert_on_second_call() {
        ensure_crypto_provider();
        let tmp = TempDir::new().unwrap();
        generate_or_load(tmp.path()).await.unwrap();
        let cert_path = tmp.path().join("runtime/tls/dev/self-signed.pem");
        let mtime_1 = std::fs::metadata(&cert_path).unwrap().modified().unwrap();
        // Small sleep to ensure mtime would differ if the file were rewritten.
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        generate_or_load(tmp.path()).await.unwrap();
        let mtime_2 = std::fs::metadata(&cert_path).unwrap().modified().unwrap();
        assert_eq!(mtime_1, mtime_2, "valid cert should not be regenerated");
    }

    #[test]
    fn recovers_previous_bundle_without_changing_identity() -> Result<()> {
        ensure_crypto_provider();
        let tmp = TempDir::new()?;
        generate_or_load_blocking(tmp.path())?;
        let dir = tmp.path().join("runtime/tls/dev");
        let previous = std::fs::read(dir.join(BUNDLE_NAME))?;
        std::fs::write(dir.join(BACKUP_NAME), &previous)?;
        std::fs::write(dir.join(BUNDLE_NAME), b"truncated")?;
        generate_or_load_blocking(tmp.path())?;
        assert_eq!(std::fs::read(dir.join(BUNDLE_NAME))?, previous);
        Ok(())
    }

    #[test]
    fn imports_legacy_pair_and_rejects_mismatched_keys() -> Result<()> {
        ensure_crypto_provider();
        let tmp = TempDir::new()?;
        let dir = tmp.path().join("runtime/tls/dev");
        std::fs::create_dir_all(&dir)?;
        let bundle = generate_bundle()?;
        std::fs::write(dir.join("self-signed.crt"), &bundle)?;
        std::fs::write(dir.join("self-signed.key"), generate_bundle()?)?;
        assert!(generate_or_load_blocking(tmp.path()).is_err());
        assert!(!dir.join(BUNDLE_NAME).exists());
        std::fs::write(dir.join("self-signed.key"), &bundle)?;
        generate_or_load_blocking(tmp.path())?;
        let imported = std::fs::read(dir.join(BUNDLE_NAME))?;
        assert!(imported.starts_with(&bundle));
        Ok(())
    }

    #[test]
    fn san_for_parses_ipv4() {
        let san = san_for("127.0.0.1").unwrap();
        assert!(matches!(san, rcgen::SanType::IpAddress(_)));
    }

    #[test]
    fn san_for_parses_ipv6() {
        let san = san_for("::1").unwrap();
        assert!(matches!(san, rcgen::SanType::IpAddress(_)));
    }

    #[test]
    fn san_for_parses_dns() {
        let san = san_for("localhost").unwrap();
        assert!(matches!(san, rcgen::SanType::DnsName(_)));
    }

    #[test]
    fn san_for_rejects_empty_dns() {
        // Empty string is unconditionally invalid as a DNS name (RFC 1123).
        assert!(san_for("").is_err());
    }

    #[test]
    fn san_for_rejects_oversized_label() {
        // A single DNS label must not exceed 63 characters (RFC 1123 §2.1).
        let long_label = "a".repeat(64);
        assert!(san_for(&long_label).is_err());
    }
}
