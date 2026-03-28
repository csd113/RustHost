//! # Lifecycle
//!
//! **Directory:** `src/runtime/`
//!
//! Two paths:
//! 1. **First run** — creates the directory tree, writes defaults, prints a
//!    "fresh install" notice, then continues directly into the normal run.
//! 2. **Normal run** — loads config, starts every subsystem, enters the
//!    event dispatch loop, then shuts down gracefully.
//!
//! ## CLI override support (5.5)
//!
//! [`CliArgs`] carries optional path overrides from `--config` and `--data-dir`.
//! When absent the original defaults (relative to `current_exe()`) are used,
//! preserving backward compatibility for zero-argument invocations.

use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use tokio::sync::{mpsc, oneshot, watch, RwLock};

use crate::{
    config::{self, Config},
    console, logging,
    runtime::{
        events,
        state::{AppState, CertStatus, Metrics, SharedMetrics, SharedState, TorStatus},
    },
    server, tls, tor, AppError, Result,
};

// ─── Public types ─────────────────────────────────────────────────────────────

/// CLI-supplied path overrides.  Both fields default to `None`, which causes
/// [`run`] to fall back to the standard paths relative to `current_exe()`.
#[derive(Debug, Default)]
pub struct CliArgs {
    /// Explicit path to `settings.toml`; overrides the default derived from
    /// `data_dir`.
    pub config_path: Option<PathBuf>,
    /// Explicit data-directory root; overrides `<exe-dir>/rusthost-data/`.
    pub data_dir: Option<PathBuf>,
    /// When `Some`, skip first-run setup and serve this directory directly.
    /// Addresses M-15 — `--serve <dir>` one-shot CLI mode.
    pub serve_dir: Option<PathBuf>,
    /// Port to use in `--serve` mode.  Ignored when `serve_dir` is `None`.
    pub serve_port: u16,
    /// Disable Tor in `--serve` mode.
    pub no_tor: bool,
    /// Disable the interactive console (useful for headless / CI use).
    pub headless: bool,
}

// ─── Shared connection budget ─────────────────────────────────────────────────

/// Shared connection-budget state passed to both HTTP and HTTPS listeners so
/// they enforce a single combined connection limit.
#[derive(Clone)]
struct SharedConnectionBudget {
    semaphore: std::sync::Arc<tokio::sync::Semaphore>,
    per_ip_map: std::sync::Arc<
        dashmap::DashMap<std::net::IpAddr, std::sync::Arc<std::sync::atomic::AtomicU32>>,
    >,
}

// ─── Entry point ─────────────────────────────────────────────────────────────

/// Entry point for the `rusthost-cli` binary.
///
/// Computes the data-directory and settings path (honouring any overrides in
/// `args`), then either performs first-run setup or starts the full server.
///
/// # Errors
///
/// Returns an [`AppError`] if the config cannot be loaded, logging cannot be
/// initialised, or any other fatal startup condition occurs.
/// Path overrides are supplied via [`CliArgs`].
pub async fn run(args: CliArgs) -> Result<()> {
    // M-15 — if --serve <dir> was passed, bypass settings.toml entirely and
    // spin up a minimal server pointed at the given directory.
    if let Some(dir) = args.serve_dir {
        return one_shot_serve(dir, args.serve_port, !args.no_tor, args.headless).await;
    }

    // 4.4 + 5.5 — data_dir is computed exactly once and threaded everywhere.
    // A CLI override takes precedence; the default is relative to current_exe().
    let data_dir = args.data_dir.unwrap_or_else(default_data_dir);

    let settings_path = args
        .config_path
        .unwrap_or_else(|| data_dir.join("settings.toml"));

    if !settings_path.exists() {
        first_run_setup(&data_dir, &settings_path)?;
    }
    normal_run(data_dir, &settings_path).await?;
    Ok(())
}

/// Serve `dir` directly with minimal configuration — no `settings.toml` needed.
///
/// Builds a `Config` in memory with sensible defaults, skips first-run setup,
/// and calls [`normal_run`].  Addresses M-15.
async fn one_shot_serve(dir: PathBuf, port: u16, tor_enabled: bool, headless: bool) -> Result<()> {
    use crate::config::{
        ConsoleConfig, CspLevel, IdentityConfig, LogLevel, LoggingConfig, ServerConfig, SiteConfig,
        TorConfig,
    };
    use std::num::NonZeroU16;

    let dir_str = dir.to_string_lossy().into_owned();

    // Use the parent of `dir` as the data_dir so relative paths stay sane.
    let data_dir = dir
        .canonicalize()
        .unwrap_or_else(|_| dir.clone())
        .parent()
        .map_or_else(|| dir.clone(), Path::to_path_buf);

    let config = Arc::new(crate::config::Config {
        server: ServerConfig {
            port: NonZeroU16::new(port).unwrap_or(NonZeroU16::MIN),
            bind: "127.0.0.1"
                .parse()
                .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
            auto_port_fallback: true,
            open_browser_on_start: false,
            max_connections: 256,
            max_connections_per_ip: 16,
            csp_level: CspLevel::Off,
        },
        site: SiteConfig {
            directory: dir_str,
            index_file: "index.html".into(),
            enable_directory_listing: true,
            expose_dotfiles: false,
            spa_routing: false,
            error_404: None,
            error_503: None,
        },
        tor: TorConfig {
            enabled: tor_enabled,
        },
        logging: LoggingConfig {
            enabled: false,
            level: LogLevel::Info,
            file: "rusthost.log".into(),
            filter_dependencies: true,
        },
        console: ConsoleConfig {
            interactive: !headless,
            refresh_rate_ms: 500,
            show_timestamps: false,
        },
        identity: IdentityConfig {
            instance_name: "RustHost".into(),
        },
        redirects: Vec::new(),
        tls: crate::config::TlsConfig::default(),
    });

    normal_run_with_config(data_dir, config).await
}

/// Compute the default data directory (`<exe-dir>/rusthost-data/`).
///
/// If `current_exe()` fails (deleted binary, unusual OS, restricted environment)
/// we fall back to `./rusthost-data` and emit a visible warning so operators
/// know the key material and site files may have landed somewhere unexpected.
fn default_data_dir() -> PathBuf {
    match std::env::current_exe() {
        Ok(exe) => exe.parent().map_or_else(
            || PathBuf::from("rusthost-data"),
            |p| p.join("rusthost-data"),
        ),
        Err(e) => {
            eprintln!(
                "Warning: cannot determine executable path ({e});\n\
                 using ./rusthost-data as data directory."
            );
            PathBuf::from("rusthost-data")
        }
    }
}

// ─── First Run ───────────────────────────────────────────────────────────────

fn first_run_setup(data_dir: &Path, settings_path: &Path) -> Result<()> {
    for sub in &["site", "logs"] {
        std::fs::create_dir_all(data_dir.join(sub))?;
    }

    config::defaults::write_default_config(settings_path)?;

    let placeholder = data_dir.join("site/index.html");
    if !placeholder.exists() {
        std::fs::write(&placeholder, PLACEHOLDER_HTML)?;
    }

    println!();
    println!("  RustHost — fresh install detected");
    println!("  ─────────────────────────────────────────");
    println!("  Data directories and a default config have been created.");
    println!("  You can drop your site files into:  ./rusthost-data/site/");
    println!();
    println!("  Tor onion service is built-in — no external install required.");
    println!("  On first run, Arti will download ~2 MB of directory data (~30 s).");
    println!("  Your .onion address will be shown in the dashboard once ready.");
    println!();
    println!("  Starting server now…");
    println!();

    Ok(())
}

// ─── Normal Run ──────────────────────────────────────────────────────────────

async fn normal_run(data_dir: PathBuf, settings_path: &Path) -> Result<()> {
    let config = Arc::new(config::loader::load(settings_path)?);
    normal_run_with_config(data_dir, config).await
}

// ─── Extracted helpers for normal_run_with_config ─────────────────────────────

/// Scan the site directory and populate initial file stats in shared state.
async fn init_site_scan(config: &Config, state: &SharedState, data_dir: &Path) {
    let site_root = data_dir.join(&config.site.directory);
    let scan_root = site_root.clone();
    let (count, bytes) =
        match tokio::task::spawn_blocking(move || server::scan_site(&scan_root)).await {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => {
                log::warn!("Could not scan site directory on startup: {e}");
                (0, 0)
            }
            Err(e) => {
                log::warn!("Site scan task panicked on startup: {e}");
                (0, 0)
            }
        };
    let mut s = state.write().await;
    s.site_file_count = count;
    s.site_total_bytes = bytes;
}

/// Wait for the server task to report its bound port via the oneshot channel.
async fn wait_for_bind_port(port_rx: oneshot::Receiver<u16>) -> Result<u16> {
    match tokio::time::timeout(Duration::from_secs(10), port_rx).await {
        Ok(Ok(port)) => Ok(port),
        Ok(Err(_)) => {
            log::error!("Server port channel closed before sending — server failed to bind");
            Err(AppError::ServerStartup(
                "Server task exited before signalling its bound port".into(),
            ))
        }
        Err(_) => {
            log::error!("Timed out waiting for server to bind");
            Err(AppError::ServerStartup(
                "Timed out waiting for server to bind (10 s)".into(),
            ))
        }
    }
}

/// Optionally set up TLS/HTTPS and the HTTP→HTTPS redirect server.
///
/// `build_acceptor` is synchronous and may perform blocking file I/O (reading
/// cert/key files, parsing PEM, etc.).  It is offloaded to the blocking thread
/// pool via `spawn_blocking` so it cannot stall the async runtime.
async fn setup_tls(
    config: &Arc<Config>,
    state: &SharedState,
    metrics: &SharedMetrics,
    shutdown_rx: &watch::Receiver<bool>,
    data_dir: &Path,
    budget: &SharedConnectionBudget,
    root_tx: &watch::Sender<Arc<std::path::Path>>,
) {
    if !config.tls.enabled {
        return;
    }

    // Clone owned copies so they can be moved into the 'static spawn_blocking
    // closure.
    let tls_cfg = config.tls.clone();
    let dd = data_dir.to_path_buf();

    let tls_result =
        match tokio::task::spawn_blocking(move || tls::build_acceptor(&tls_cfg, &dd)).await {
            Ok(inner) => inner,
            Err(e) => {
                log::error!("TLS initialisation task panicked: {e}. Continuing in HTTP-only mode.");
                return;
            }
        };

    match tls_result {
        Err(e) => {
            log::error!("TLS init failed: {e}. Continuing in HTTP-only mode.");
        }
        Ok(None) => { /* enabled=false handled inside build_acceptor */ }
        Ok(Some(acceptor)) => {
            // Record cert type in shared state for the dashboard.
            {
                let mut s = state.write().await;
                s.tls_cert_status = if config.tls.acme.enabled {
                    config.tls.acme.domains.first().map_or(
                        CertStatus::Acme {
                            domain: String::new(),
                        },
                        |d| CertStatus::Acme { domain: d.clone() },
                    )
                } else if config.tls.manual_cert.is_some() {
                    CertStatus::Manual
                } else {
                    CertStatus::SelfSigned
                };
            }

            // Spawn the HTTPS accept loop.
            {
                let tls_config = Arc::clone(config);
                let tls_state = Arc::clone(state);
                let tls_metrics = Arc::clone(metrics);
                let tls_shutdown = shutdown_rx.clone();
                let tls_data_dir = data_dir.to_path_buf();
                let tls_sem = std::sync::Arc::clone(&budget.semaphore);
                let tls_ip_map = std::sync::Arc::clone(&budget.per_ip_map);
                let tls_root_rx = root_tx.subscribe();
                tokio::spawn(async move {
                    server::run_https(
                        tls_config,
                        tls_state,
                        tls_metrics,
                        tls_data_dir,
                        tls_shutdown,
                        acceptor,
                        tls_sem,
                        tls_ip_map,
                        tls_root_rx,
                    )
                    .await;
                });
            }

            // Optionally spawn the HTTP→HTTPS redirect server.
            if config.tls.redirect_http {
                let bind_addr = config.server.bind;
                let redir_plain_port = config.tls.http_port.get();
                let redir_tls_port = config.tls.port.get();
                let redir_shutdown = shutdown_rx.clone();
                tokio::spawn(async move {
                    server::redirect::run_redirect_server(
                        bind_addr,
                        redir_plain_port,
                        redir_tls_port,
                        redir_shutdown,
                    )
                    .await;
                });
            }
        }
    }
}

/// Open the user's browser if `open_browser_on_start` is set.
async fn maybe_open_browser(config: &Config, state: &SharedState) {
    if !config.server.open_browser_on_start {
        return;
    }
    let port = state.read().await.actual_port;
    let url = match config.server.bind {
        std::net::IpAddr::V4(a) if a.is_unspecified() => {
            format!("http://127.0.0.1:{port}")
        }
        std::net::IpAddr::V6(a) if a.is_unspecified() => {
            format!("http://[::1]:{port}")
        }
        std::net::IpAddr::V6(a) => format!("http://[{a}]:{port}"),
        std::net::IpAddr::V4(a) => format!("http://{a}:{port}"),
    };
    super::open_browser(&url);
}

// ─── Core startup ─────────────────────────────────────────────────────────────

/// Core server startup given an already-built `Config`.
///
/// Shared by the standard settings.toml path and the `--serve` one-shot mode.
async fn normal_run_with_config(data_dir: PathBuf, config: Arc<Config>) -> Result<()> {
    // 2. Initialise logging.
    logging::init(&config.logging, &data_dir)?;
    // M-16 — initialise the structured access log (Combined Log Format).
    if let Err(e) = logging::init_access_log(&data_dir) {
        log::warn!("Could not initialise access log: {e}");
    }
    log::info!("RustHost starting — version {}", env!("CARGO_PKG_VERSION"));

    // 4.2 — config.server.bind is now IpAddr; use is_unspecified() instead of
    //        string comparison.
    if config.server.bind.is_unspecified() {
        log::warn!("[server] bind = \"0.0.0.0\" — server is reachable on all interfaces.");
    }

    // 3. Build shared state and metrics.
    let state: SharedState = Arc::new(RwLock::new(AppState::new()));
    let metrics: SharedMetrics = Arc::new(Metrics::new());

    // 4. Set Disabled status early if tor is off, so the UI is correct
    //    before the server even binds.
    if !config.tor.enabled {
        state.write().await.tor_status = TorStatus::Disabled;
    }

    // 5. Scan site directory for initial file stats.
    init_site_scan(&config, &state, &data_dir).await;

    // 6. Shutdown channels.
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // 7. Start HTTP server task.
    let (port_tx, port_rx) = oneshot::channel::<u16>();
    #[allow(clippy::cast_possible_truncation)]
    let budget = SharedConnectionBudget {
        semaphore: std::sync::Arc::new(tokio::sync::Semaphore::new(
            config.server.max_connections as usize,
        )),
        per_ip_map: std::sync::Arc::new(dashmap::DashMap::new()),
    };
    let (server_handle, root_tx) = spawn_server(
        &config,
        &state,
        &metrics,
        &shutdown_rx,
        port_tx,
        data_dir.clone(),
        budget.clone(),
    );

    // Wait for the server to signal its bound port via the oneshot channel.
    let bind_port = wait_for_bind_port(port_rx).await?;

    // 7b. TLS / HTTPS — optional, non-fatal.
    setup_tls(
        &config,
        &state,
        &metrics,
        &shutdown_rx,
        &data_dir,
        &budget,
        &root_tx,
    )
    .await;

    // 8. Start Tor (if enabled).
    //    tor::init() spawns a Tokio task and returns its JoinHandle.
    //    Pass shutdown_rx so Tor's stream loop exits on clean shutdown.
    let tor_handle = if config.tor.enabled {
        #[allow(clippy::cast_possible_truncation)]
        let max_tor = config.server.max_connections as usize;
        Some(tor::init(
            data_dir.clone(),
            bind_port,
            config.server.bind,
            max_tor,
            Arc::clone(&state),
            shutdown_rx.clone(),
        ))
    } else {
        None
    };

    // 9. Start console UI.
    let key_rx = start_console(&config, &state, &metrics, shutdown_rx.clone()).await?;

    // 10. Open browser (if configured).
    maybe_open_browser(&config, &state).await;

    // 11. Event dispatch loop.
    event_loop(key_rx, &config, &state, &metrics, data_dir, root_tx).await?;

    // 12. Graceful shutdown.
    graceful_shutdown(shutdown_tx, server_handle, tor_handle).await;
    Ok(())
}

// Shutdown drain budget constants (M-7).
//
// Previously the two drains (HTTP + Tor) shared a single 8-second wall-clock
// budget.  If the HTTP drain ran long, Tor circuits received whatever
// milliseconds were left — far too little for active streams to flush.
// The fix gives each drain its own independently-bounded timeout.

/// Shutdown budget (seconds) when Tor is **disabled**.
const DRAIN_HTTP_ONLY_SECS: u64 = 8;

/// Shutdown budget (seconds) for the HTTP drain when Tor is **enabled**.
///
/// Tor circuits need their own separate window after this.
const DRAIN_HTTP_WITH_TOR_SECS: u64 = 5;

/// Shutdown budget (seconds) for Tor circuit teardown.
///
/// Arti closes circuits asynchronously; waiting up to this long gives active
/// Tor streams a chance to flush their final bytes before the process exits.
const DRAIN_TOR_SECS: u64 = 10;

/// Signal shutdown, then drain the HTTP server and (if Tor is enabled) the Tor
/// circuits with separate, independently-bounded timeouts.
///
/// - **HTTP only** (Tor disabled): full [`DRAIN_HTTP_ONLY_SECS`] seconds.
/// - **HTTP + Tor**: [`DRAIN_HTTP_WITH_TOR_SECS`] seconds for HTTP, then a
///   fresh [`DRAIN_TOR_SECS`]-second budget for Tor circuit teardown.
///
/// The hard caps are intentional — the process must not hang forever.
/// Callers drop the Tokio runtime after this function returns, which cancels
/// any tasks that did not complete within their budget.
async fn graceful_shutdown(
    shutdown_tx: watch::Sender<bool>,
    server_handle: tokio::task::JoinHandle<()>,
    tor_handle: Option<tokio::task::JoinHandle<()>>,
) {
    log::info!("Shutting down…");
    let _ = shutdown_tx.send(true);

    // HTTP drain — budget depends on whether Tor needs its own window.
    let http_budget = if tor_handle.is_some() {
        Duration::from_secs(DRAIN_HTTP_WITH_TOR_SECS)
    } else {
        Duration::from_secs(DRAIN_HTTP_ONLY_SECS)
    };

    if tokio::time::timeout(http_budget, server_handle)
        .await
        .is_err()
    {
        let secs = http_budget.as_secs();
        log::warn!(
            "HTTP drain did not complete within {secs} s; \
             some connections may be abruptly closed",
        );
    }

    // Tor drain — only if Tor was started, with its own fresh budget so that
    // a slow HTTP drain does not steal time from Tor circuit teardown.
    if let Some(handle) = tor_handle {
        if tokio::time::timeout(Duration::from_secs(DRAIN_TOR_SECS), handle)
            .await
            .is_err()
        {
            log::warn!(
                "Tor circuit teardown did not complete within {DRAIN_TOR_SECS} s; \
                 active Tor streams will be forcibly closed",
            );
        }
    }

    log::info!("RustHost shut down cleanly.");
    logging::flush();
    console::cleanup();
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Spawn the HTTP server task and return its `JoinHandle` so the shutdown
/// sequence can await the connection drain.
///
/// Returns the `JoinHandle` and the `watch::Sender` used to push a new
/// `canonical_root` to the accept loop when the operator presses `[R]`.
fn spawn_server(
    config: &Arc<Config>,
    state: &SharedState,
    metrics: &SharedMetrics,
    shutdown: &watch::Receiver<bool>,
    port_tx: oneshot::Sender<u16>,
    data_dir: PathBuf,
    budget: SharedConnectionBudget,
) -> (
    tokio::task::JoinHandle<()>,
    watch::Sender<Arc<std::path::Path>>,
) {
    // Resolve initial canonical root for the watch channel seed value.
    let initial_root: Arc<std::path::Path> = {
        let site_path = data_dir.join(&config.site.directory);
        let resolved = site_path.canonicalize().unwrap_or(site_path);
        Arc::from(resolved.as_path())
    };
    let (root_tx, root_rx) = watch::channel(initial_root);

    let server_config = Arc::clone(config);
    let server_state = Arc::clone(state);
    let server_metrics = Arc::clone(metrics);
    let server_shutdown = shutdown.clone();
    let handle = tokio::spawn(async move {
        server::run(
            server_config,
            server_state,
            server_metrics,
            data_dir,
            server_shutdown,
            port_tx,
            root_rx,
            budget.semaphore,
            budget.per_ip_map,
        )
        .await;
    });
    (handle, root_tx)
}

async fn start_console(
    config: &Arc<Config>,
    state: &SharedState,
    metrics: &SharedMetrics,
    shutdown: watch::Receiver<bool>,
) -> Result<Option<mpsc::UnboundedReceiver<events::KeyEvent>>> {
    if config.console.interactive {
        let rx = console::start(
            Arc::clone(config),
            Arc::clone(state),
            Arc::clone(metrics),
            shutdown,
        )?;
        Ok(Some(rx))
    } else {
        let port = state.read().await.actual_port;
        // 4.2 — config.server.bind is IpAddr, Display impl formats correctly.
        println!("RustHost running on http://{}:{port}", config.server.bind);
        Ok(None)
    }
}

// ─── SIGTERM helper ───────────────────────────────────────────────────────────
//
// `tokio::select!` does not support `#[cfg(...)]` on individual arms; the macro
// expands its arms textually before cfg evaluation, so a guarded arm produces a
// parse error.  The solution is a cross-platform helper with identical call-site
// syntax on every target:
//
//   • Unix     — registers a SIGTERM handler and awaits the first delivery.
//   • non-Unix — awaits `std::future::pending()`, which never resolves.
//
// Both variants share the name `next_sigterm()` and return `()`, so a single
// unconditional `select!` arm covers all platforms.  The caller pins the
// returned future outside its loop so the Unix `Signal` handle (and its OS-level
// signal pipe) is created exactly once for the lifetime of the event loop.
//
// Failure to register the Unix handler (e.g. signal limit reached) is logged as
// a warning and the function falls back to `pending()` — the process remains
// functional, just without SIGTERM-triggered graceful shutdown.

/// On Unix, resolve once when `SIGTERM` is delivered; fall back to pending
/// forever if the signal stream cannot be registered.
///
/// See the module-level comment above for the cross-platform design rationale.
#[cfg(unix)]
async fn next_sigterm() {
    use tokio::signal::unix::{signal, SignalKind};
    match signal(SignalKind::terminate()) {
        Ok(mut stream) => {
            // recv() returns Option<()>; None means the stream was dropped,
            // which cannot happen here.  Either way we return so the select!
            // arm fires and the graceful shutdown path runs.
            stream.recv().await;
        }
        Err(e) => {
            log::warn!(
                "Could not register SIGTERM handler: {e}. \
                 Send Ctrl-C or use --signal-file to stop the process."
            );
            std::future::pending::<()>().await;
        }
    }
}

/// On non-Unix platforms, pend forever so the `select!` arm is always
/// present in the source but never fires.
///
/// See the module-level comment above for the cross-platform design rationale.
#[cfg(not(unix))]
async fn next_sigterm() {
    std::future::pending::<()>().await;
}

async fn event_loop(
    key_rx: Option<mpsc::UnboundedReceiver<events::KeyEvent>>,
    config: &Arc<Config>,
    state: &SharedState,
    metrics: &SharedMetrics,
    data_dir: PathBuf,
    root_tx: watch::Sender<Arc<std::path::Path>>,
) -> Result<()> {
    // 2.8 — mutable so we can set to None when the channel closes.
    let mut key_rx = key_rx;

    // 4.7 — tokio::signal::ctrl_c() replaces ctrlc crate's set_handler + mpsc.
    //        Pinned so it can be polled repeatedly inside select! without moving.
    let ctrl_c = tokio::signal::ctrl_c();
    tokio::pin!(ctrl_c);

    // SIGTERM handling — cross-platform design note
    // ─────────────────────────────────────────────
    // `tokio::select!` is a declarative macro that expands its arms textually;
    // it does not honour `#[cfg(...)]` attributes placed on individual arms.
    // Putting `#[cfg(unix)] _ = sigterm.recv() => { … }` inside the macro
    // causes a parse error ("no rules expected `}`") on every platform.
    //
    // Solution: a platform-unified helper function `next_sigterm()` with
    // identical call-site syntax on all targets:
    //   • Unix     — awaits the next SIGTERM delivery from the OS.
    //   • non-Unix — awaits `std::future::pending()` (never resolves).
    // Both branches return `()` so `select!` sees one unconditional arm.
    //
    // The future is pinned here, outside the loop, so the Unix `Signal` handle
    // (and its internal OS registration) is created exactly once and reused
    // across every `select!` iteration — same pattern as `ctrl_c` above.
    let sigterm = next_sigterm();
    tokio::pin!(sigterm);

    loop {
        // Build a future that yields the next key, or pends forever once the
        // channel closes (avoids repeated None-match after input task death).
        let key_fut = async {
            if let Some(rx) = key_rx.as_mut() {
                rx.recv().await
            } else {
                std::future::pending().await
            }
        };

        tokio::select! {
            maybe_key = key_fut => {
                if let Some(key) = maybe_key {
                    let quit = events::handle(
                        key,
                        config,
                        Arc::clone(state),
                        Arc::clone(metrics),
                        data_dir.clone(),
                        &root_tx,
                    ).await?;
                    if quit { break; }
                } else {
                    // 2.8 — input task exited; disable key arm and warn operator.
                    log::warn!(
                        "Console input task exited — keyboard input disabled. \
                         Use Ctrl-C to quit."
                    );
                    key_rx = None;
                }
            }
            // 4.7 — Ctrl-C handled directly through Tokio's signal machinery.
            result = &mut ctrl_c => {
                if let Err(e) = result {
                    log::warn!("Ctrl-C signal error: {e}");
                }
                break;
            }
            // Graceful shutdown on SIGTERM.
            // On Unix this arm fires when the OS delivers SIGTERM, covering
            // `systemctl stop`, `docker stop`, launchd unload, and any process
            // supervisor that sends SIGTERM before SIGKILL.
            // On non-Unix platforms `next_sigterm()` pends forever, so this
            // arm is syntactically present but never selected.
            () = &mut sigterm => {
                log::info!("SIGTERM received — shutting down gracefully.");
                break;
            }
        }
    }
    Ok(())
}

// ─── Placeholder HTML ────────────────────────────────────────────────────────

const PLACEHOLDER_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>RustHost</title>
  <style>
    body { font-family: system-ui, sans-serif; max-width: 600px;
           margin: 4rem auto; padding: 0 1rem; color: #1a1a1a; }
    h1   { font-size: 1.5rem; font-weight: 500; }
    p    { color: #555; line-height: 1.6; }
    code { background: #f1f1f1; padding: 2px 6px; border-radius: 4px; }
  </style>
</head>
<body>
  <h1>RustHost is running</h1>
  <p>
    Replace this file with your own content.<br>
    Drop files into <code>./rusthost-data/site/</code> and press
    <kbd>R</kbd> to reload.
  </p>
</body>
</html>
"#;
