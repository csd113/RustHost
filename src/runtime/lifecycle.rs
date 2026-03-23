//! # Lifecycle
//!
//! **Directory:** `src/runtime/`
//!
//! Two paths:
//! 1. **First run** — creates the directory tree, writes defaults, prints
//!    instructions, and exits cleanly.
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
        state::{AppState, Metrics, SharedMetrics, SharedState, TorStatus},
    },
    server, tor, AppError, Result,
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

    if settings_path.exists() {
        normal_run(data_dir, &settings_path).await?;
    } else {
        first_run_setup(&data_dir, &settings_path)?;
    }
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

    // Write a minimal in-memory settings.toml-equivalent path so `normal_run`
    // can be reused unchanged.  We create a temporary settings file in a tmpdir
    // rather than duplicating all of normal_run's startup steps.
    //
    // Simpler approach: build a Config directly and pass it to normal_run's inner
    // logic via a secondary entry point that accepts an Arc<Config>.
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
    });

    normal_run_with_config(data_dir, config).await
}

/// Compute the default data directory (`<exe-dir>/rusthost-data/`).
/// Compute the default data directory (`<exe-dir>/rusthost-data/`).
///
/// fix L-1 — if `current_exe()` fails (deleted binary, unusual OS, restricted
/// environment) we previously fell back silently to `./rusthost-data`, hiding
/// the misconfiguration.  Now we emit a visible warning so operators know the
/// key material and site files landed somewhere unexpected.
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
    println!("  RustHost — initialised");
    println!("  ─────────────────────────────────────────");
    println!("  Drop your site files into:  ./rusthost-data/site/");
    println!("  Then run RustHost again to go live.");
    println!();
    println!("  Tor onion service is built-in — no external install required.");
    println!("  On first run, Arti will download ~2 MB of directory data (~30 s).");
    println!("  Your .onion address will be shown in the dashboard once ready.");
    println!();

    Ok(())
}

// ─── Normal Run ──────────────────────────────────────────────────────────────

async fn normal_run(data_dir: PathBuf, settings_path: &Path) -> Result<()> {
    let config = Arc::new(config::loader::load(settings_path)?);
    normal_run_with_config(data_dir, config).await
}

/// Core server startup given an already-built `Config`.
///
/// Shared by the standard settings.toml path and the `--serve` one-shot mode.
async fn normal_run_with_config(data_dir: PathBuf, config: Arc<Config>) -> Result<()> {
    // 2. Initialise logging.
    logging::init(&config.logging, &data_dir)?;
    // M-16 — initialise the structured access log (Combined Log Format).
    // Best-effort: a failure here is logged but does not abort startup.
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
    // 2.2 — wrap in spawn_blocking; scan_site now returns Result.
    {
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

    // 6. Shutdown channels.
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // 7. Start HTTP server task.
    let (port_tx, port_rx) = oneshot::channel::<u16>();
    // 2.10 — keep the JoinHandle so we can await the server during shutdown drain.
    // H-2  — root_tx lets the [R] reload handler push a new canonical_root to the
    //         accept loop without restarting the server.
    let (server_handle, root_tx) = spawn_server(
        &config,
        &state,
        &metrics,
        &shutdown_rx,
        port_tx,
        data_dir.clone(),
    );

    // Wait for the server to signal its bound port via the oneshot channel.
    // A 10-second timeout ensures a bind failure doesn't block forever.
    let bind_port = match tokio::time::timeout(Duration::from_secs(10), port_rx).await {
        Ok(Ok(port)) => port,
        Ok(Err(_)) => {
            log::error!("Server port channel closed before sending — server failed to bind");
            return Err(AppError::ServerStartup(
                "Server task exited before signalling its bound port".into(),
            ));
        }
        Err(_) => {
            log::error!("Timed out waiting for server to bind");
            return Err(AppError::ServerStartup(
                "Timed out waiting for server to bind (10 s)".into(),
            ));
        }
    };

    // 8. Start Tor (if enabled).
    //    tor::init() spawns a Tokio task and returns its JoinHandle.
    //    fix 3.1  — we store the handle and await it during shutdown so active
    //               Tor circuits get a chance to close cleanly (max 5 s).
    //    fix 3.6  — pass config.server.bind so the local proxy connect uses the
    //               correct loopback address (e.g. ::1 on IPv6-only machines).
    //    2.10 — pass shutdown_rx so Tor's stream loop exits on clean shutdown.
    let tor_handle = if config.tor.enabled {
        // fix T-2 — pass max_connections so the Tor semaphore is sized
        // identically to the HTTP server connection limit.
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
    if config.server.open_browser_on_start {
        let port = state.read().await.actual_port;
        // fix S-1 — use the actual bind address instead of hardcoding "localhost".
        // If bind = "::1" and localhost resolves to 127.0.0.1, the browser
        // tries the wrong interface.  Format IPv6 with brackets.
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

    // 11. Event dispatch loop.
    // H-2 — root_tx is passed so the [R] reload handler can push a new
    // canonical_root to the accept loop without restarting the server.
    event_loop(key_rx, &config, &state, &metrics, data_dir, root_tx).await?;

    // 12. Graceful shutdown.
    graceful_shutdown(shutdown_tx, server_handle, tor_handle).await;
    Ok(())
}

/// Signal shutdown, then await the server and Tor tasks with a shared 8-second
/// deadline.  Extracted from [`normal_run_with_config`] to stay within the
/// 100-line function-length limit.
async fn graceful_shutdown(
    shutdown_tx: watch::Sender<bool>,
    server_handle: tokio::task::JoinHandle<()>,
    tor_handle: Option<tokio::task::JoinHandle<()>>,
) {
    log::info!("Shutting down…");
    let _ = shutdown_tx.send(true);

    // fix M-2 / clippy::integer_arithmetic — checked_add returns None only if
    // the instant would overflow (practically impossible); fall back to now so
    // the drain phase exits immediately rather than panicking or using bare `+`.
    let shutdown_deadline = tokio::time::Instant::now()
        .checked_add(Duration::from_secs(8))
        .unwrap_or_else(tokio::time::Instant::now);
    let _ = tokio::time::timeout_at(shutdown_deadline, server_handle).await;
    if let Some(handle) = tor_handle {
        let remaining = shutdown_deadline.saturating_duration_since(tokio::time::Instant::now());
        let _ = tokio::time::timeout(remaining, handle).await;
    }

    log::info!("RustHost shut down cleanly.");
    logging::flush();
    console::cleanup();
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Spawn the HTTP server task and return its `JoinHandle` so the shutdown
/// sequence can await the connection drain (fix 2.10).
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

    let cfg = Arc::clone(config);
    let st = Arc::clone(state);
    let met = Arc::clone(metrics);
    let shut = shutdown.clone();
    let handle = tokio::spawn(async move {
        server::run(cfg, st, met, data_dir, shut, port_tx, root_rx).await;
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
    std::future::pending::<()>().await
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
