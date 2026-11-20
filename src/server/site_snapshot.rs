//! A prepared site generation, published once and selected afresh per request.
use super::handler::FaviconConfig;
use crate::{config::Config, Result};
use bytes::Bytes;
use hyper::StatusCode;
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

const MAX_CUSTOM_ERROR_PAGE_BYTES: u64 = 64 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CustomErrorPage {
    pub(super) status: StatusCode,
    pub(super) body: Bytes,
}

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
        let (file_count, total_bytes) = scan_site(&root)?;
        let error_page = |path: Option<&str>, label, status| -> Result<_> {
            path.map(|path| {
                load_custom_error_page(&root, &root.join(path), label, status).ok_or_else(|| {
                    crate::AppError::ConfigLoad(format!("cannot load configured {label}"))
                })
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

fn load_custom_error_page(
    canonical_root: &Path,
    candidate: &Path,
    label: &str,
    status: StatusCode,
) -> Option<Arc<CustomErrorPage>> {
    let resolved = match candidate.canonicalize() {
        Ok(resolved) if resolved.starts_with(canonical_root) => resolved,
        Ok(resolved) => {
            log::warn!(
                "Ignoring [site] {label} path {} because it resolves outside the site root: {}",
                candidate.display(),
                resolved.display()
            );
            return None;
        }
        Err(e) => {
            log::warn!(
                "Ignoring [site] {label} path {} because it could not be resolved: {e}",
                candidate.display()
            );
            return None;
        }
    };

    let metadata = match std::fs::metadata(&resolved) {
        Ok(metadata) => metadata,
        Err(e) => {
            log::warn!(
                "Ignoring [site] {label} path {} because metadata could not be read: {e}",
                resolved.display()
            );
            return None;
        }
    };

    if !metadata.is_file() || metadata.len() > MAX_CUSTOM_ERROR_PAGE_BYTES {
        log::warn!(
            "Ignoring [site] {label} path {} because it exceeds the {} byte limit",
            resolved.display(),
            MAX_CUSTOM_ERROR_PAGE_BYTES
        );
        return None;
    }

    match crate::persistence::read_bounded(&resolved, MAX_CUSTOM_ERROR_PAGE_BYTES) {
        Ok(body) => Some(Arc::new(CustomErrorPage {
            status,
            body: Bytes::from(body),
        })),
        Err(e) => {
            log::warn!(
                "Ignoring [site] {label} path {} because it could not be read: {e}",
                resolved.display()
            );
            None
        }
    }
}

/// Maximum directory depth `scan_site` will traverse.
///
/// Prevents runaway BFS on artificially deep or adversarially-constructed
/// directory trees. A legitimate site tree is extremely unlikely to exceed
/// this depth; anything beyond it is almost certainly a mistake or an attack.
const MAX_SCAN_DEPTH: usize = 64;
/// Recursively count files and total bytes in `site_root` (BFS traversal).
///
/// Symlinks are excluded. Failed reads or traversal limits fail the scan so a
/// reload cannot publish statistics from an incomplete tree.
///
/// # Errors
///
/// Returns [`crate::AppError::Io`] for filesystem failures or traversal limits.
///
/// # Panics
///
/// Does not panic. **Must be called from a blocking context** (e.g.
/// `tokio::task::spawn_blocking`) because `std::fs::read_dir` is a blocking
/// syscall.
#[must_use = "the file count and byte total are used to populate the dashboard"]
pub fn scan_site(site_root: &Path) -> crate::Result<(u32, u64)> {
    let mut count = 0u32;
    let mut bytes = 0u64;
    // Queue entries carry a depth counter so the BFS can be bounded.
    // Using (PathBuf, usize) instead of PathBuf adds one word per queue entry —
    // negligible compared to the path allocation — and avoids a separate counter
    // map or recursive call stack.
    let mut queue: std::collections::VecDeque<(PathBuf, usize)> = std::collections::VecDeque::new();
    queue.push_back((site_root.to_path_buf(), 0));
    // Symlinks are excluded; device/inode pairs also avoid recounting aliases
    // such as bind mounts, without confusing inodes on different filesystems.
    #[cfg(unix)]
    let mut visited_inodes: std::collections::HashSet<(u64, u64)> =
        std::collections::HashSet::new();
    let mut scanned_entries = 0usize;
    while let Some((dir, depth)) = queue.pop_front() {
        if depth >= MAX_SCAN_DEPTH {
            return Err(std::io::Error::other("site scan exceeds depth limit").into());
        }
        let entries = std::fs::read_dir(&dir)?;
        for entry in entries {
            scanned_entries += 1;
            if scanned_entries > 1_000_000 {
                return Err(std::io::Error::other("site scan exceeds one million entries").into());
            }
            let path = entry?.path();
            let link_meta = std::fs::symlink_metadata(&path)?;
            if link_meta.file_type().is_symlink() {
                log::warn!("Skipping symlink during site scan: {}", path.display());
                continue;
            }
            if link_meta.is_file() {
                count = count.saturating_add(1);
                bytes = bytes.saturating_add(link_meta.len());
            } else if link_meta.is_dir() {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::MetadataExt as _;
                    let ino = link_meta.ino();
                    if !visited_inodes.insert((link_meta.dev(), ino)) {
                        log::warn!(
                            "Directory cycle detected at {} (inode {ino}), skipping",
                            path.display()
                        );
                        continue;
                    }
                }
                if queue.len() >= 4096 {
                    return Err(
                        std::io::Error::other("site scan exceeds pending directory limit").into(),
                    );
                }
                queue.push_back((path, depth.saturating_add(1)));
            }
        }
    }
    Ok((count, bytes))
}
