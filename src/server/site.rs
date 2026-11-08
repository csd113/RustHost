//! A prepared site generation, published once and selected afresh per request.
use super::handler::{self, CustomErrorPage, FaviconConfig};
use crate::{config::Config, Result};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

/// Immutable routing state shared by HTTP, HTTPS and Tor ingress.
///
/// Configuration itself remains restart-only. The underlying site files must
/// remain present for in-flight requests; this is not a filesystem snapshot.
pub struct SiteSnapshot {
    pub(crate) canonical_root: Arc<Path>,
    pub(crate) favicon: Arc<FaviconConfig>,
    pub(crate) error_404_page: Option<Arc<CustomErrorPage>>,
    pub(crate) error_503_page: Option<Arc<CustomErrorPage>>,
    pub(crate) file_count: u32,
    pub(crate) total_bytes: u64,
}

impl SiteSnapshot {
    /// Prepare an entire generation without modifying the active site.
    /// Must run on a blocking thread when used from async code.
    ///
    /// # Errors
    /// Returns an error if the root, scan, or a configured error page cannot
    /// be loaded. Reload must retain the previous generation on any error.
    pub fn prepare(config: &Config, data_dir: &Path) -> Result<Arc<Self>> {
        let root: PathBuf = data_dir.join(&config.site.directory).canonicalize()?;
        let (file_count, total_bytes) = super::scan_site(&root)?;
        let error_page = |path: Option<&str>, label, status| -> Result<_> {
            path.map(|path| {
                handler::load_custom_error_page(&root, &root.join(path), label, status).ok_or_else(
                    || crate::AppError::ConfigLoad(format!("cannot load configured {label}")),
                )
            })
            .transpose()
        };
        let error_404_page = error_page(
            config.site.error_404.as_deref(),
            "error_404",
            hyper::StatusCode::NOT_FOUND,
        )?;
        let error_503_page = error_page(
            config.site.error_503.as_deref(),
            "error_503",
            hyper::StatusCode::SERVICE_UNAVAILABLE,
        )?;
        let canonical_root: Arc<Path> = root.into();
        Ok(Arc::new(Self {
            favicon: Arc::new(FaviconConfig {
                path: canonical_root.join(&config.site.favicon),
                site_root: Arc::clone(&canonical_root),
                enable_png: config.site.enable_png_favicon,
            }),
            canonical_root,
            error_404_page,
            error_503_page,
            file_count,
            total_bytes,
        }))
    }
}
