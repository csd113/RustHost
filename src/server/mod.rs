//! # Server Module
//!
//! **Directory:** `src/server/`
//!
//! Provides a safe HTTP/1.1 static-file server.  Phase 3 migrated the
//! per-connection handler from a hand-rolled single-shot parser to
//! [`hyper`]'s keep-alive connection loop, eliminating the 30–45 s Tor
//! page-load penalty caused by `Connection: close` on every response (C-1).
//!
//! Sub-modules:
//! - [`handler`]  — per-connection request handling and file serving
//! - [`mime`]     — file-extension → MIME type mapping
//! - [`fallback`] — built-in "No site found" page

pub mod fallback;
pub mod handler;
pub mod mime;

use std::{
    net::{IpAddr, TcpListener as StdTcpListener},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc,
    },
    time::Duration,
};

use dashmap::DashMap;
use tokio::{
    net::TcpListener,
    sync::{oneshot, watch, Semaphore},
    task::JoinSet,
};

use crate::{
    config::Config,
    runtime::state::{SharedMetrics, SharedState},
    AppError, Result,
};

// ─── Per-IP rate limiting (C-4) ───────────────────────────────────────────────

/// RAII guard that decrements the per-IP counter when dropped.
///
/// The guard is moved into each spawned handler task.  When the task
/// completes — normally or via panic — the `Drop` impl decrements the counter
/// and removes the map entry when the count reaches zero, preventing unbounded
/// map growth.
struct PerIpGuard {
    counter: Arc<AtomicU32>,
    map: Arc<DashMap<IpAddr, Arc<AtomicU32>>>,
    addr: IpAddr,
}

impl Drop for PerIpGuard {
    fn drop(&mut self) {
        let prev = self.counter.fetch_sub(1, Ordering::Relaxed);
        // If this was the last connection from this IP, remove the entry.
        // Keeping zero-count entries would let the map grow without bound on
        // servers with many distinct client IPs.
        if prev == 1 {
            self.map.remove(&self.addr);
        }
    }
}

/// Attempt to acquire a per-IP connection slot using a lock-free CAS loop.
///
/// Returns `Ok(guard)` when a slot is available.  The caller moves the guard
/// into the handler task; `Drop` releases the slot automatically.
///
/// Returns `Err(())` when `addr` already holds `limit` connections.  The
/// caller should drop the `TcpStream` without writing any HTTP response —
/// the OS-level TCP RST is intentional: it signals rejection at near-zero
/// cost compared to sending a `503 Service Unavailable` body.
fn try_acquire_per_ip(
    map: &Arc<DashMap<IpAddr, Arc<AtomicU32>>>,
    addr: IpAddr,
    limit: u32,
) -> std::result::Result<PerIpGuard, ()> {
    // `or_insert_with` holds the DashMap shard lock only for the duration of
    // the closure, which is shorter than holding it across the CAS loop.
    let counter = Arc::clone(
        map.entry(addr)
            .or_insert_with(|| Arc::new(AtomicU32::new(0)))
            .value(),
    );

    // Lock-free increment: loop until CAS succeeds or limit is exceeded.
    let mut current = counter.load(Ordering::Relaxed);
    loop {
        if current >= limit {
            return Err(());
        }
        match counter.compare_exchange_weak(
            current,
            current.saturating_add(1),
            Ordering::AcqRel,
            Ordering::Relaxed,
        ) {
            Ok(_) => {
                return Ok(PerIpGuard {
                    counter,
                    map: Arc::clone(map),
                    addr,
                });
            }
            Err(updated) => current = updated,
        }
    }
}

// ─── Server context ───────────────────────────────────────────────────────────

/// Shared references prepared once before the accept loop starts.
///
/// Extracting these into a struct keeps [`run`] under the 100-line limit
/// imposed by `clippy::nursery::too_many_lines` while grouping the values
/// that every spawned handler task needs.
struct ServerContext {
    canonical_root: Arc<Path>,
    index_file: Arc<str>,
    csp_header: Arc<str>,
    dir_list: bool,
    expose_dots: bool,
    spa_routing: bool,
    error_404_path: Option<std::path::PathBuf>,
    redirects: Arc<Vec<crate::config::RedirectRule>>,
    semaphore: Arc<Semaphore>,
    per_ip_map: Arc<DashMap<IpAddr, Arc<AtomicU32>>>,
    max_conns: usize,
    max_per_ip: u32,
}

impl ServerContext {
    /// Resolve `site_root` and build all shared state needed by the accept loop.
    ///
    /// Returns `None` and logs an error if the site root cannot be canonicalized.
    fn new(config: &Config, data_dir: &Path) -> Option<Self> {
        let site_root = data_dir.join(&config.site.directory);
        let canonical_root: Arc<Path> = match site_root.canonicalize() {
            Ok(p) => Arc::from(p.as_path()),
            Err(e) => {
                log::error!(
                    "Site root {} cannot be resolved: {e}. \
                     Check that [site] directory exists.",
                    site_root.display()
                );
                return None;
            }
        };
        #[allow(clippy::cast_possible_truncation)]
        let max_conns = config.server.max_connections as usize;

        // H-10 / C-6 — resolve custom error page paths once at startup.
        let site_dir = data_dir.join(&config.site.directory);
        let error_404_path = config.site.error_404.as_deref().map(|p| site_dir.join(p));

        Some(Self {
            canonical_root,
            index_file: Arc::from(config.site.index_file.as_str()),
            csp_header: Arc::from(config.server.csp_level.as_header_value()),
            dir_list: config.site.enable_directory_listing,
            expose_dots: config.site.expose_dotfiles,
            spa_routing: config.site.spa_routing,
            error_404_path,
            redirects: Arc::new(config.redirects.clone()),
            semaphore: Arc::new(Semaphore::new(max_conns)),
            per_ip_map: Arc::new(DashMap::new()),
            max_conns,
            max_per_ip: config.server.max_connections_per_ip,
        })
    }

    /// Attempt to spawn a handler task for one accepted connection.
    ///
    /// Returns `false` when the global semaphore has been closed (shutdown),
    /// `true` in all other cases (connection accepted, rejected, or dropped).
    async fn spawn_connection(
        &self,
        stream: tokio::net::TcpStream,
        peer: std::net::SocketAddr,
        metrics: &SharedMetrics,
        join_set: &mut JoinSet<()>,
    ) -> bool {
        let peer_ip = peer.ip();
        let Ok(ip_guard) = try_acquire_per_ip(&self.per_ip_map, peer_ip, self.max_per_ip) else {
            log::warn!(
                "Per-IP limit ({}) reached for {peer_ip}; dropping connection",
                self.max_per_ip
            );
            drop(stream);
            return true;
        };

        let Ok(permit) = Arc::clone(&self.semaphore).acquire_owned().await else {
            return false; // semaphore closed — signal shutdown to caller
        };
        if self.semaphore.available_permits() == 0 {
            log::warn!(
                "Connection limit ({}) reached; further connections will queue",
                self.max_conns
            );
        }

        let site = Arc::clone(&self.canonical_root);
        let idx = Arc::clone(&self.index_file);
        let met = Arc::clone(metrics);
        let csp = Arc::clone(&self.csp_header);
        let dir_list = self.dir_list;
        let expose_dots = self.expose_dots;
        let spa_routing = self.spa_routing;
        let e404 = self.error_404_path.clone();
        let redirects = Arc::clone(&self.redirects);
        join_set.spawn(async move {
            let _permit = permit;
            let _ip_guard = ip_guard;
            if let Err(e) = handler::handle(
                stream,
                site,
                idx,
                dir_list,
                expose_dots,
                met,
                csp,
                spa_routing,
                e404,
                redirects,
            )
            .await
            {
                log::debug!("Handler error: {e}");
            }
        });
        true
    }
}

// ─── Public API ──────────────────────────────────────────────────────────────

/// Start the HTTP server.
///
/// Binds the port (with optional fallback), updates `SharedState.actual_port`,
/// sends the bound port through `port_tx` so Tor can start without a sleep,
/// then accepts connections until the shutdown watch fires.
///
/// ## Accept-loop observability
///
/// Accept errors use exponential backoff (1 ms → 1 s) to prevent log storms
/// under persistent failures such as `EMFILE`.  Error severity is split:
///
/// - **`EMFILE` / `ENFILE`** (file-descriptor exhaustion) → logged at `error`;
///   these require operator intervention.
/// - **Transient errors** (`ECONNRESET`, `ECONNABORTED`, etc.) → logged at
///   `debug`; they are expected under normal traffic and resolve automatically.
pub async fn run(
    config: Arc<Config>,
    state: SharedState,
    metrics: SharedMetrics,
    data_dir: PathBuf,
    mut shutdown: watch::Receiver<bool>,
    port_tx: oneshot::Sender<u16>,
    mut root_watch: watch::Receiver<Arc<Path>>,
) {
    let bind_addr = config.server.bind;
    let base_port = config.server.port.get();

    let (listener, bound_port) =
        match bind_with_fallback(bind_addr, base_port, config.server.auto_port_fallback) {
            Ok(v) => v,
            Err(e) => {
                log::error!("Server failed to bind: {e}");
                return;
            }
        };
    if bound_port != base_port {
        log::warn!("Configured port {base_port} was in use; bound to {bound_port} instead.");
    }
    {
        let mut s = state.write().await;
        s.actual_port = bound_port;
        s.server_running = true;
    }
    let _ = port_tx.send(bound_port);
    log::info!("HTTP server listening on {bind_addr}:{bound_port}");

    let Some(mut ctx) = ServerContext::new(&config, &data_dir) else {
        return;
    };
    let mut join_set: JoinSet<()> = JoinSet::new();
    let mut backoff_ms: u64 = 1;

    loop {
        // H-2 — Non-blocking check for a new canonical_root sent by the [R]
        // reload handler in events.rs.  `has_changed` is true if a value was
        // sent since the last `borrow_and_update`, so we only update when there
        // is actually a new root to apply.
        if root_watch.has_changed().unwrap_or(false) {
            let new_root = Arc::clone(&root_watch.borrow_and_update());
            log::info!("Site root refreshed: {}", new_root.display());
            ctx.canonical_root = new_root;
        }

        tokio::select! {
            result = listener.accept() => {
                match result {
                    Ok((stream, peer)) => {
                        backoff_ms = 1;
                        log::debug!("Connection from {peer}");
                        if !ctx.spawn_connection(stream, peer, &metrics, &mut join_set).await {
                            break; // semaphore closed — shutting down
                        }
                    }
                    Err(e) => {
                        if is_fd_exhaustion(&e) {
                            log::error!(
                                "Accept error — file-descriptor limit reached \
                                 (EMFILE/ENFILE): {e}. Reduce max_connections or \
                                 raise the OS ulimit."
                            );
                        } else {
                            log::debug!("Accept error (transient): {e}");
                        }
                        tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                        backoff_ms = backoff_ms.saturating_mul(2).min(1_000);
                    }
                }
            }
            _ = shutdown.changed() => {
                if *shutdown.borrow() { break; }
            }
        }
    }

    state.write().await.server_running = false;
    log::info!("HTTP server stopped accepting; draining in-flight connections…");
    let drain = async { while join_set.join_next().await.is_some() {} };
    let _ = tokio::time::timeout(Duration::from_secs(5), drain).await;
    log::info!("HTTP server drained.");
}

// ─── Port binding ─────────────────────────────────────────────────────────────

/// Try to bind to `addr:port`. When `fallback` is true, increments the port
/// up to 10 times before giving up.
fn bind_with_fallback(addr: IpAddr, port: u16, fallback: bool) -> Result<(TcpListener, u16)> {
    let max_attempts: u16 = if fallback { 10 } else { 1 };

    for attempt in 0..max_attempts {
        let try_port = port.saturating_add(attempt);
        let addr_str = format!("{addr}:{try_port}");

        match StdTcpListener::bind(&addr_str) {
            Ok(std_listener) => {
                std_listener.set_nonblocking(true)?;
                let listener = TcpListener::from_std(std_listener)?;
                return Ok((listener, try_port));
            }
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse && fallback => {
                // Try the next port.
            }
            Err(source) => {
                return Err(AppError::ServerBind {
                    port: try_port,
                    source,
                });
            }
        }
    }

    Err(AppError::ServerBind {
        port,
        source: std::io::Error::new(
            std::io::ErrorKind::AddrInUse,
            format!(
                "Could not find a free port after {max_attempts} attempts \
                 starting from {port}. Change [server].port in settings.toml \
                 or set auto_port_fallback = true."
            ),
        ),
    })
}

/// Return `true` when `e` represents file-descriptor exhaustion.
///
/// On Unix this matches `EMFILE` (24, per-process FD limit) and `ENFILE`
/// (23, system-wide FD limit), both specified by POSIX and identical on
/// Linux, macOS, FreeBSD, and other POSIX-conformant systems.
///
/// On Windows this matches `WSAEMFILE` (10024), the Winsock equivalent of
/// `EMFILE` — it fires when the per-process socket descriptor table is full.
///
/// On all other targets the function always returns `false`.
fn is_fd_exhaustion(e: &std::io::Error) -> bool {
    #[cfg(unix)]
    {
        // EMFILE (24): too many open files for the process.
        // ENFILE (23): too many open files system-wide.
        matches!(e.raw_os_error(), Some(libc::EMFILE | libc::ENFILE))
    }
    #[cfg(windows)]
    {
        // WSAEMFILE (10024): per-process socket handle limit reached.
        // This is the Windows Sockets equivalent of POSIX EMFILE and fires
        // when the process has exhausted its socket descriptor table.
        matches!(e.raw_os_error(), Some(10_024))
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = e;
        false
    }
}

// ─── Site scanner ─────────────────────────────────────────────────────────────

/// Recursively count files and total bytes in `site_root` (BFS traversal).
///
/// Returns `Err` if any `read_dir` call fails so callers can log a warning
/// instead of silently reporting zeros.
///
/// # Errors
///
/// Returns [`AppError::Io`] if any directory in the tree cannot be read.
///
/// # Panics
///
/// Does not panic.  **Must be called from a blocking context** (e.g.
/// `tokio::task::spawn_blocking`) because `std::fs::read_dir` is a blocking
/// syscall.
#[must_use = "the file count and byte total are used to populate the dashboard"]
pub fn scan_site(site_root: &Path) -> crate::Result<(u32, u64)> {
    let mut count = 0u32;
    let mut bytes = 0u64;

    let mut queue: std::collections::VecDeque<PathBuf> = std::collections::VecDeque::new();
    queue.push_back(site_root.to_path_buf());

    // fix M-1 — track visited inodes to detect and break symlink cycles.
    // Without cycle detection, a symlink loop (e.g. site/loop -> site/) grows
    // the BFS queue unboundedly and the function never returns, permanently
    // consuming a spawn_blocking thread.
    #[cfg(unix)]
    let mut visited_inodes: std::collections::HashSet<u64> = std::collections::HashSet::new();

    while let Some(dir) = queue.pop_front() {
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(e) => {
                // Skip unreadable directories with a per-directory warning.
                // Do NOT abort the entire scan — the rest of the tree may be readable.
                log::warn!("Skipping unreadable directory {}: {e}", dir.display());
                continue;
            }
        };

        for entry in entries.flatten() {
            // fix M-1: use symlink_metadata (does not follow symlinks) to
            // detect symlinked directories before following them.
            let Ok(meta) = entry.metadata() else { continue };
            if meta.is_file() {
                count = count.saturating_add(1);
                bytes = bytes.saturating_add(meta.len());
            } else if meta.is_dir() {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::MetadataExt;
                    let ino = meta.ino();
                    if !visited_inodes.insert(ino) {
                        log::warn!(
                            "Symlink cycle detected at {} (inode {ino}), skipping",
                            entry.path().display()
                        );
                        continue;
                    }
                }
                #[cfg(not(unix))]
                {
                    // On non-Unix, skip symlinked directories to avoid cycles.
                    if let Ok(sym_meta) = entry.path().symlink_metadata() {
                        if sym_meta.file_type().is_symlink() {
                            log::warn!(
                                "Skipping symlinked directory {} (no inode tracking on this platform)",
                                entry.path().display()
                            );
                            continue;
                        }
                    }
                }
                queue.push_back(entry.path());
            }
        }
    }

    Ok((count, bytes))
}
