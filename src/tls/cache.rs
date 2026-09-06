//! Atomic, bounded ACME cache; filenames remain compatible with rustls-acme.
use crate::persistence::{read_bounded, Directory};
use std::{
    future::Future,
    io,
    path::PathBuf,
    pin::Pin,
    sync::{Arc, Mutex},
};

const MAX_CACHE_BYTES: u64 = 1024 * 1024;
type CacheFuture<'a, T> = Pin<Box<dyn Future<Output = io::Result<T>> + Send + 'a>>;

pub(super) struct AtomicCache {
    path: PathBuf,
    directory: Arc<Mutex<Directory>>,
}

#[derive(Clone, Copy)]
enum Kind {
    Certificate,
    Account,
}

impl Kind {
    const fn label(self) -> &'static str {
        match self {
            Self::Certificate => "cert",
            Self::Account => "account",
        }
    }
    fn validate(self, bytes: &[u8]) -> io::Result<()> {
        match self {
            Self::Certificate => {
                super::pem_as_acceptor(bytes, bytes).map_err(io::Error::other)?;
            }
            Self::Account => {
                let key = rustls::pki_types::PrivatePkcs8KeyDer::from(bytes);
                rcgen::KeyPair::try_from(&key).map_err(io::Error::other)?;
            }
        }
        Ok(())
    }
}

impl AtomicCache {
    pub(super) fn new(path: PathBuf) -> io::Result<Self> {
        let directory = Arc::new(Mutex::new(Directory::open(&path)?));
        Ok(Self { path, directory })
    }

    fn filename(kind: Kind, values: &[String], url: &str) -> io::Result<String> {
        // Use the existing ring SHA-256 provider, avoiding another dependency.
        let suite = rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256;
        let suite = suite
            .tls13()
            .ok_or_else(|| io::Error::other("SHA-256 cipher suite unavailable"))?;
        let mut hash = suite.common.hash_provider.start();
        for value in values {
            hash.update(value.as_bytes());
            hash.update(&[0]);
        }
        hash.update(url.as_bytes());
        let hash = data_encoding::BASE64URL_NOPAD.encode(hash.finish().as_ref());
        Ok(format!("cached_{}_{hash}", kind.label()))
    }

    fn load(&self, kind: Kind, values: &[String], url: &str) -> CacheFuture<'_, Option<Vec<u8>>> {
        let name = Self::filename(kind, values, url);
        let path = self.path.clone();
        let directory = Arc::clone(&self.directory);
        Box::pin(async move {
            tokio::task::spawn_blocking(move || {
                let _guard = directory
                    .lock()
                    .map_err(|e| io::Error::other(e.to_string()))?;
                let name = name?;
                let read = |name: &str| -> io::Result<Vec<u8>> {
                    let bytes = read_bounded(&path.join(name), MAX_CACHE_BYTES)?;
                    kind.validate(&bytes)?;
                    Ok(bytes)
                };
                match read(&name) {
                    Ok(bytes) => Ok(Some(bytes)),
                    Err(current) => match read(&format!("{name}.previous")) {
                        Ok(bytes) => {
                            log::warn!(
                                "ACME: recovering previous {} cache generation",
                                kind.label()
                            );
                            Ok(Some(bytes))
                        }
                        Err(previous)
                            if current.kind() == io::ErrorKind::NotFound
                                && previous.kind() == io::ErrorKind::NotFound =>
                        {
                            Ok(None)
                        }
                        Err(_) => Err(current),
                    },
                }
            })
            .await
            .map_err(io::Error::other)?
        })
    }

    fn store(&self, kind: Kind, values: &[String], url: &str, bytes: &[u8]) -> CacheFuture<'_, ()> {
        let name = Self::filename(kind, values, url);
        let path = self.path.clone();
        let directory = Arc::clone(&self.directory);
        // Bound before copying; upstream normally supplies only a few KiB.
        let bytes = if bytes.len() as u64 <= MAX_CACHE_BYTES {
            Ok(bytes.to_vec())
        } else {
            Err(io::Error::other("ACME cache exceeds size limit"))
        };
        Box::pin(async move {
            tokio::task::spawn_blocking(move || {
                let name = name?;
                let bytes = bytes?;
                kind.validate(&bytes)?;
                let mut dir = directory
                    .lock()
                    .map_err(|e| io::Error::other(e.to_string()))?;
                match read_bounded(&path.join(&name), MAX_CACHE_BYTES) {
                    Ok(previous) if kind.validate(&previous).is_ok() => {
                        dir.write(format!("{name}.previous"), &previous, true)?;
                    }
                    Ok(_) => {} // Keep the valid backup when recovering malformed current state.
                    Err(e)
                        if e.kind() == io::ErrorKind::NotFound
                            || e.kind() == io::ErrorKind::InvalidData => {}
                    Err(e) => return Err(e),
                }
                dir.write(&name, &bytes, true)?;
                drop(dir);
                Ok(())
            })
            .await
            .map_err(io::Error::other)?
        })
    }
}

// Spell out async-trait's object-safe signature to use the dependency's cache
// interface without adding a direct procedural-macro dependency.
macro_rules! cache_impl {
    ($trait:ident, $error:ident, $load:ident, $store:ident, $kind:expr) => {
        impl rustls_acme::$trait for AtomicCache {
            type $error = io::Error;
            fn $load<'life0, 'life1, 'life2, 'async_trait>(
                &'life0 self,
                values: &'life1 [String],
                url: &'life2 str,
            ) -> CacheFuture<'async_trait, Option<Vec<u8>>>
            where
                'life0: 'async_trait,
                'life1: 'async_trait,
                'life2: 'async_trait,
                Self: 'async_trait,
            {
                self.load($kind, values, url)
            }
            fn $store<'life0, 'life1, 'life2, 'life3, 'async_trait>(
                &'life0 self,
                values: &'life1 [String],
                url: &'life2 str,
                bytes: &'life3 [u8],
            ) -> CacheFuture<'async_trait, ()>
            where
                'life0: 'async_trait,
                'life1: 'async_trait,
                'life2: 'async_trait,
                'life3: 'async_trait,
                Self: 'async_trait,
            {
                self.store($kind, values, url, bytes)
            }
        }
    };
}
cache_impl!(CertCache, EC, load_cert, store_cert, Kind::Certificate);
cache_impl!(AccountCache, EA, load_account, store_account, Kind::Account);

#[cfg(test)]
mod tests {
    use super::*;
    use rustls_acme::AccountCache as _;
    #[tokio::test]
    async fn cache_is_compatible_and_recovers_previous_key() -> io::Result<()> {
        let tmp = tempfile::tempdir()?;
        let cache = AtomicCache::new(tmp.path().to_owned())?;
        let key = rcgen::KeyPair::generate()
            .map_err(io::Error::other)?
            .serialize_der();
        let contact = vec!["mailto:test@example.com".into()];
        cache.store_account(&contact, "directory", &key).await?;
        let legacy = rustls_acme::caches::DirCache::new(tmp.path());
        assert_eq!(
            legacy.load_account(&contact, "directory").await?,
            Some(key.clone())
        );
        let next = rcgen::KeyPair::generate()
            .map_err(io::Error::other)?
            .serialize_der();
        cache.store_account(&contact, "directory", &next).await?;
        let name = AtomicCache::filename(Kind::Account, &contact, "directory")?;
        std::fs::write(tmp.path().join(name), b"partial")?;
        assert_eq!(cache.load_account(&contact, "directory").await?, Some(key));
        assert!(cache
            .store_account(&contact, "directory", b"invalid")
            .await
            .is_err());
        Ok(())
    }
}
