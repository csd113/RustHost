//! # Lifecycle
//! Two paths:
//! 1. **First run** — creates the directory tree, writes defaults, prints a
//!    "fresh install" notice, then continues directly into the normal run.
//! 2. **Normal run** — loads config, starts every subsystem, enters the
//!    event dispatch loop, then shuts down gracefully.
//!
//! ## CLI override support
//!
//! [`CliArgs`] carries optional path overrides from `--config` and `--data-dir`.
//! When absent the original defaults (relative to `current_exe()`) are used,
//! preserving backward compatibility for zero-argument invocations.

mod support;

use std::{
    fmt::Write as _,
    io::Write as _,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use tokio::sync::{mpsc, oneshot, watch, RwLock};

use crate::{
    config::{self, Config},
    console, logging,
    path_display::display_path,
    runtime::{
        events, runtime_root,
        state::{AppState, Metrics, SharedMetrics, SharedState, TorStatus},
    },
    server, tor, Result,
};
use support::{
    graceful_shutdown, maybe_open_browser, setup_tls, wait_for_background_task, wait_for_bind_port,
    ListenerReady,
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
    /// One-shot `--serve <dir>` mode.
    pub serve_dir: Option<PathBuf>,
    /// Port to use in `--serve` mode.  Ignored when `serve_dir` is `None`.
    pub serve_port: u16,
    /// Disable Tor in `--serve` mode.
    pub no_tor: bool,
    /// Disable the interactive console (useful for headless / CI use).
    pub headless: bool,
}

/// Resolve the data directory and settings path using the same precedence as
/// production startup.
#[must_use]
pub fn resolve_config_paths(args: &CliArgs) -> (PathBuf, PathBuf) {
    let data_dir = args.data_dir.clone().unwrap_or_else(default_data_dir);
    let settings_path = args
        .config_path
        .clone()
        .unwrap_or_else(|| data_dir.join("settings.toml"));
    (data_dir, settings_path)
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
    // If --serve <dir> was passed, bypass settings.toml entirely and spin up a
    // minimal server pointed at the given directory.
    if let Some(dir) = args.serve_dir {
        return one_shot_serve(dir, args.serve_port, !args.no_tor, args.headless).await;
    }

    // data_dir is computed exactly once and threaded everywhere. A CLI
    // override takes precedence; the default is relative to current_exe().
    let (data_dir, settings_path) = resolve_config_paths(&args);

    if !settings_path.exists() {
        let install_kind = detect_install_kind(&data_dir);
        first_run_setup(&data_dir, &settings_path, install_kind, args.headless)?;
    }
    normal_run(data_dir, &settings_path, args.headless).await?;
    Ok(())
}

/// Serve `dir` directly with minimal configuration — no `settings.toml` needed.
///
/// Builds a `Config` in memory with sensible defaults, skips first-run setup,
/// and calls [`normal_run`].
async fn one_shot_serve(dir: PathBuf, port: u16, tor_enabled: bool, headless: bool) -> Result<()> {
    use std::num::NonZeroU16;

    let (data_dir, site_dir) = one_shot_paths(&dir)?;

    // Start from the standard defaults and change only what `--serve` needs, so
    // this path cannot silently drift from `Config::default()`.
    let mut config = Config::default();
    config.server.port = NonZeroU16::new(port).unwrap_or(NonZeroU16::MIN);
    config.server.bind = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
    config.site.directory = site_dir;
    config.site.enable_directory_listing = true;
    config.tor.enabled = tor_enabled;
    config.tor.shutdown_grace_secs = 30;
    config.logging.enabled = false;
    config.console.interactive = !headless;

    normal_run_with_config(data_dir, None, Arc::new(config)).await
}

/// Resolve before creating runtime files, and never substitute the parent for
/// a leaf that cannot be represented by the string-valued site configuration.
fn one_shot_paths(dir: &Path) -> Result<(PathBuf, String)> {
    let canonical_dir = dir.canonicalize().map_err(|e| {
        crate::AppError::ConfigLoad(format!(
            "Cannot resolve site directory {}: {e}",
            dir.display()
        ))
    })?;
    if !canonical_dir.is_dir() {
        return Err(crate::AppError::ConfigLoad(format!(
            "Site path {} is not a directory",
            dir.display()
        )));
    }
    let site_dir = match canonical_dir.file_name() {
        Some(name) => name
            .to_str()
            .ok_or_else(|| {
                crate::AppError::ConfigLoad(
                    "The resolved site directory name must be valid UTF-8".into(),
                )
            })?
            .to_owned(),
        None => ".".to_owned(),
    };
    let data_dir = canonical_dir
        .parent()
        .map_or_else(|| canonical_dir.clone(), Path::to_path_buf);
    Ok((data_dir, site_dir))
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
            let _ = writeln!(
                std::io::stderr(),
                "Warning: cannot determine executable path ({e});\n\
                 using ./rusthost-data as data directory."
            );
            PathBuf::from("rusthost-data")
        }
    }
}

// ─── First Run ───────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum InstallKind {
    Fresh,
    RegeneratedSettings,
}

fn detect_install_kind(data_dir: &Path) -> InstallKind {
    if data_dir.join("site").exists() || runtime_root(data_dir).exists() {
        InstallKind::RegeneratedSettings
    } else {
        InstallKind::Fresh
    }
}

fn first_run_setup(
    data_dir: &Path,
    settings_path: &Path,
    install_kind: InstallKind,
    headless: bool,
) -> Result<()> {
    crate::persistence::create_dir_all(&data_dir.join("site"))?;
    crate::persistence::create_dir_all(&runtime_root(data_dir))?;

    let placeholder = data_dir.join("site/index.html");
    crate::persistence::create_default(&placeholder, PLACEHOLDER_HTML.as_bytes())?;
    // Publish settings last: interrupted first-run setup is safe to retry.
    config::defaults::write_default_config(settings_path)?;

    if headless {
        let mut stdout = std::io::stdout();
        stdout.write_all(
            first_run_headless_message(data_dir, settings_path, install_kind).as_bytes(),
        )?;
        return Ok(());
    }

    let mut stdout = std::io::stdout();
    stdout.write_all(first_run_interactive_message(data_dir, install_kind).as_bytes())?;

    Ok(())
}

fn first_run_headless_message(
    data_dir: &Path,
    settings_path: &Path,
    install_kind: InstallKind,
) -> String {
    let mut out = String::new();
    match install_kind {
        InstallKind::Fresh => {
            out.push_str("RustHost initialized data directory\n");
            let _ = writeln!(
                out,
                "Created default config: {}",
                display_path(settings_path)
            );
        }
        InstallKind::RegeneratedSettings => {
            out.push_str("RustHost regenerated missing settings.toml\n");
            let _ = writeln!(out, "Regenerated config: {}", display_path(settings_path));
        }
    }
    let _ = writeln!(
        out,
        "Site directory: {}",
        display_path(&data_dir.join("site"))
    );
    let _ = writeln!(
        out,
        "Runtime directory: {}",
        display_path(&runtime_root(data_dir))
    );
    out.push_str("Starting server now...\n");
    out
}

fn first_run_interactive_message(data_dir: &Path, install_kind: InstallKind) -> String {
    let mut out = String::new();
    out.push('\n');
    match install_kind {
        InstallKind::Fresh => {
            out.push_str("  RustHost — fresh install detected\n");
            out.push_str("  ─────────────────────────────────────────\n");
            out.push_str("  Data directories and a default config have been created.\n");
        }
        InstallKind::RegeneratedSettings => {
            out.push_str("  settings.toml missing; regenerated from defaults\n");
            out.push_str("  ─────────────────────────────────────────\n");
            out.push_str(
                "  Existing site/runtime data was kept; review the new config before production use.\n",
            );
        }
    }
    let _ = writeln!(
        out,
        "  You can drop your site files into:  {}/",
        display_path(&data_dir.join("site"))
    );
    let _ = writeln!(
        out,
        "  Runtime-managed files live under:    {}/",
        display_path(&runtime_root(data_dir))
    );
    out.push('\n');
    out.push_str("  Tor onion service is built-in — no external install required.\n");
    out.push_str("  On first run, Arti will download ~2 MB of directory data (~30 s).\n");
    out.push_str("  Your .onion address will be shown in the dashboard once ready.\n");
    out.push('\n');
    out.push_str("  Starting server now…\n\n");
    out
}

// ─── Normal Run ──────────────────────────────────────────────────────────────

async fn normal_run(data_dir: PathBuf, settings_path: &Path, headless: bool) -> Result<()> {
    let mut config = config::loader::load(settings_path)?;
    let mode = managed_runner_mode(headless, &config);
    apply_managed_runtime_mode(&mut config, mode);
    let config = Arc::new(config);
    normal_run_with_config(data_dir, Some(settings_path.to_path_buf()), config).await
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ManagedRunnerMode {
    Interactive,
    Headless,
}

const fn managed_runner_mode(headless: bool, config: &Config) -> ManagedRunnerMode {
    if headless || !config.console.interactive {
        ManagedRunnerMode::Headless
    } else {
        ManagedRunnerMode::Interactive
    }
}

const fn apply_managed_runtime_mode(config: &mut Config, mode: ManagedRunnerMode) {
    config.console.interactive = matches!(mode, ManagedRunnerMode::Interactive);
}

// ─── Extracted helpers for normal_run_with_config ─────────────────────────────

// ─── Core startup ─────────────────────────────────────────────────────────────

/// Core server startup given an already-built `Config`.
///
/// Shared by the standard settings.toml path and the `--serve` one-shot mode.
#[expect(
    clippy::too_many_lines,
    reason = "Startup wiring intentionally centralizes subsystem initialization."
)]
async fn normal_run_with_config(
    data_dir: PathBuf,
    settings_path: Option<PathBuf>,
    config: Arc<Config>,
) -> Result<()> {
    ensure_data_directories(&data_dir)?;

    // 2. Initialise logging.
    logging::init(&config.logging, &data_dir)?;
    if let Err(e) = logging::init_access_log(&config.logging, &data_dir) {
        log::warn!("Could not initialise access log: {e}");
    }
    log::info!("RustHost starting — version {}", env!("CARGO_PKG_VERSION"));

    // config.server.bind is typed as IpAddr, so use is_unspecified() instead
    // of string comparison.
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

    // 5. Shutdown channels.
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let budget = SharedConnectionBudget {
        semaphore: std::sync::Arc::new(tokio::sync::Semaphore::new(
            config.server.max_connections as usize,
        )),
        per_ip_map: std::sync::Arc::new(dashmap::DashMap::new()),
    };
    let snapshot_config = Arc::clone(&config);
    let snapshot_dir = data_dir.clone();
    let (root_tx, root_rx) =
        tokio::task::spawn_blocking(move || make_root_watch(&snapshot_config, &snapshot_dir))
            .await
            .map_err(|e| {
                crate::AppError::ConfigLoad(format!("site preparation task failed: {e}"))
            })??;
    let redirect_public_http = uses_redirect_public_http(&config);
    let server_handle = if redirect_public_http {
        None
    } else {
        // 6. Start HTTP server task.
        let (port_tx, port_rx) = oneshot::channel::<ListenerReady>();
        let server_handle = spawn_server(
            &config,
            &state,
            &metrics,
            &shutdown_rx,
            port_tx,
            data_dir.clone(),
            root_rx,
            budget.clone(),
        );

        // Wait for the server to signal its bound port via the oneshot channel.
        match wait_for_bind_port(port_rx, "HTTP server").await {
            Ok(port) => port,
            Err(err) => {
                let _ = shutdown_tx.send(true);
                wait_for_background_task(
                    Some(server_handle),
                    Duration::from_secs(5),
                    "HTTP server startup task",
                )
                .await;
                return Err(err);
            }
        };
        Some(server_handle)
    };

    // 6b. TLS / HTTPS — optional. If TLS is disabled this is a no-op; if it is
    // enabled but initialisation or binding fails, the failure is fatal and the
    // already-started HTTP listener is torn down by the shutdown path below.
    let background_tasks = setup_tls(
        &config,
        &state,
        &metrics,
        &shutdown_rx,
        &data_dir,
        &budget,
        &root_tx,
    )
    .await;
    let mut background_tasks = match background_tasks {
        Ok(tasks) => tasks,
        Err(err) => {
            graceful_shutdown(
                &config,
                shutdown_tx,
                server_handle,
                None,
                support::BackgroundTasks::default(),
            )
            .await;
            return Err(err);
        }
    };

    // 7. Start Tor (if enabled).
    //    tor::init() spawns a Tokio task and returns its JoinHandle.
    //    Pass shutdown_rx so Tor's stream loop exits on clean shutdown.
    let tor_handle = if config.tor.enabled {
        let tor_bind_addr = server::tor_loopback_addr(config.server.bind);
        let (tor_ingress_port_tx, tor_ingress_port_rx) = oneshot::channel::<ListenerReady>();
        let tor_ingress_config = Arc::clone(&config);
        let tor_ingress_state = Arc::clone(&state);
        let tor_ingress_metrics = Arc::clone(&metrics);
        let tor_ingress_shutdown = shutdown_rx.clone();
        let tor_ingress_data_dir = data_dir.clone();
        let tor_ingress_sem = std::sync::Arc::clone(&budget.semaphore);
        let tor_ingress_root_rx = root_tx.subscribe();
        background_tasks.tor_ingress = Some(tokio::spawn(async move {
            server::run_tor_ingress(
                tor_ingress_config,
                tor_ingress_state,
                tor_ingress_metrics,
                tor_ingress_data_dir,
                tor_ingress_shutdown,
                tor_ingress_port_tx,
                tor_ingress_sem,
                tor_ingress_root_rx,
            )
            .await;
        }));
        let tor_ingress_port =
            match wait_for_bind_port(tor_ingress_port_rx, "Tor ingress server").await {
                Ok(port) => port,
                Err(err) => {
                    graceful_shutdown(&config, shutdown_tx, server_handle, None, background_tasks)
                        .await;
                    return Err(err);
                }
            };
        let max_tor = config.server.max_connections as usize;
        Some(tor::init(
            data_dir.clone(),
            tor_ingress_port,
            tor_bind_addr,
            max_tor,
            Arc::clone(&state),
            shutdown_rx.clone(),
        ))
    } else {
        None
    };

    {
        let mut state = state.write().await;
        state.site_file_count = root_tx.borrow().file_count;
        state.site_total_bytes = root_tx.borrow().total_bytes;
    }

    // 8. Start console UI.
    let console_session =
        match start_console(&config, &state, &metrics, shutdown_rx.clone(), &data_dir).await {
            Ok(session) => session,
            Err(err) => {
                graceful_shutdown(
                    &config,
                    shutdown_tx,
                    server_handle,
                    tor_handle,
                    background_tasks,
                )
                .await;
                return Err(err);
            }
        };

    // 9. Open browser (if configured).
    maybe_open_browser(&config, &state).await;

    state.write().await.runtime_ready = true;

    // 10. Event dispatch loop.  Always continue into the single shutdown path
    // so listener/background cleanup runs even if event handling fails.
    let event_result = event_loop(
        console_session,
        &config,
        &state,
        &metrics,
        data_dir,
        settings_path,
        root_tx,
    )
    .await;

    state.write().await.runtime_ready = false;

    // 11. Graceful shutdown.
    graceful_shutdown(
        &config,
        shutdown_tx,
        server_handle,
        tor_handle,
        background_tasks,
    )
    .await;
    event_result
}

fn ensure_data_directories(data_dir: &Path) -> Result<()> {
    crate::persistence::create_dir_all(&runtime_root(data_dir))?;
    Ok(())
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Spawn the HTTP server task and return its `JoinHandle` so the shutdown
/// sequence can await the connection drain.
///
/// Returns the `JoinHandle` and the `watch::Sender` used to push a new
/// `canonical_root` to the accept loop when the operator presses `[R]`.
#[expect(
    clippy::too_many_arguments,
    reason = "Background server task needs the shared startup context explicitly."
)]
fn spawn_server(
    config: &Arc<Config>,
    state: &SharedState,
    metrics: &SharedMetrics,
    shutdown: &watch::Receiver<bool>,
    port_tx: oneshot::Sender<ListenerReady>,
    data_dir: PathBuf,
    root_rx: watch::Receiver<Arc<server::SiteSnapshot>>,
    budget: SharedConnectionBudget,
) -> tokio::task::JoinHandle<()> {
    let server_config = Arc::clone(config);
    let server_state = Arc::clone(state);
    let server_metrics = Arc::clone(metrics);
    let server_shutdown = shutdown.clone();
    tokio::spawn(async move {
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
    })
}

type SiteWatch = (
    watch::Sender<Arc<server::SiteSnapshot>>,
    watch::Receiver<Arc<server::SiteSnapshot>>,
);

fn make_root_watch(config: &Config, data_dir: &Path) -> Result<SiteWatch> {
    Ok(watch::channel(server::SiteSnapshot::prepare(
        config, data_dir,
    )?))
}

const fn uses_redirect_public_http(config: &Config) -> bool {
    config.tls.enabled && config.tls.redirect_http
}

async fn start_console(
    config: &Arc<Config>,
    state: &SharedState,
    metrics: &SharedMetrics,
    shutdown: watch::Receiver<bool>,
    data_dir: &Path,
) -> Result<Option<(mpsc::Receiver<events::KeyEvent>, Arc<tokio::sync::Notify>)>> {
    if config.console.interactive {
        let session = console::start(
            Arc::clone(config),
            Arc::clone(state),
            Arc::clone(metrics),
            shutdown,
            data_dir.to_path_buf(),
        )?;
        Ok(Some(session))
    } else {
        let snapshot = state.read().await.clone();
        let mut stdout = std::io::stdout();
        let _ = writeln!(stdout, "RustHost running");
        let _ = writeln!(
            stdout,
            " HTTP : http://{}:{}",
            config.server.bind, snapshot.actual_port
        );
        if snapshot.tls_running {
            if let Some(tls_port) = snapshot.tls_port {
                let _ = writeln!(stdout, " HTTPS: https://{}:{tls_port}", config.server.bind);
            }
        }
        let _ = writeln!(
            stdout,
            " Site : {}",
            display_path(&data_dir.join(&config.site.directory))
        );
        let _ = writeln!(
            stdout,
            " Tor  : {}",
            if config.tor.enabled {
                "enabled"
            } else {
                "disabled"
            }
        );
        Ok(None)
    }
}

#[cfg(unix)]
fn make_sighup_signal() -> Option<tokio::signal::unix::Signal> {
    use tokio::signal::unix::{signal, SignalKind};

    match signal(SignalKind::hangup()) {
        Ok(stream) => Some(stream),
        Err(e) => {
            log::warn!("Could not register SIGHUP handler: {e}");
            None
        }
    }
}

#[cfg(not(unix))]
const fn make_sighup_signal() -> Option<()> {
    None
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
    session: Option<(mpsc::Receiver<events::KeyEvent>, Arc<tokio::sync::Notify>)>,
    config: &Arc<Config>,
    state: &SharedState,
    metrics: &SharedMetrics,
    data_dir: PathBuf,
    settings_path: Option<PathBuf>,
    root_tx: watch::Sender<Arc<server::SiteSnapshot>>,
) -> Result<()> {
    // 2.8 — mutable so we can set to None when the channel closes.
    let (mut key_rx, render_notify) = match session {
        Some((rx, notify)) => (Some(rx), Some(notify)),
        None => (None, None),
    };

    // Pin ctrl_c so it can be polled repeatedly inside select! without moving.
    let ctrl_c = tokio::signal::ctrl_c();
    tokio::pin!(ctrl_c);
    #[cfg(unix)]
    let mut sighup = make_sighup_signal();
    #[cfg(not(unix))]
    let sighup = make_sighup_signal();

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
                std::future::pending::<Option<events::KeyEvent>>().await
            }
        };
        let sighup_fut = async {
            #[cfg(unix)]
            {
                if let Some(stream) = sighup.as_mut() {
                    stream.recv().await
                } else {
                    std::future::pending::<Option<()>>().await
                }
            }
            #[cfg(not(unix))]
            {
                let _ = &sighup;
                std::future::pending::<Option<()>>().await
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
                        settings_path.clone(),
                        &root_tx,
                    ).await?;
                    // Repaint immediately so key-driven state changes are
                    // visible without waiting for the next refresh tick.
                    if let Some(notify) = &render_notify {
                        notify.notify_one();
                    }
                    if quit { break; }
                } else {
                    log::warn!(
                        "Console input task exited — keyboard input disabled. \
                         Use Ctrl-C to quit."
                    );
                    key_rx = None;
                }
            }
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
            maybe_hup = sighup_fut => {
                if maybe_hup.is_some() {
                    log::info!("SIGHUP received — reloading site state.");
                    events::reload_site(config, Arc::clone(state), data_dir.clone(), &root_tx).await?;
                }
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
  <link rel="icon" href="data:,">
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

#[cfg(test)]
mod tests {
    // Linux filesystems permit non-UTF-8 names; macOS APFS rejects this fixture.
    #[cfg(target_os = "linux")]
    #[test]
    fn one_shot_rejects_non_utf8_symlink_target_without_serving_parent() -> crate::Result<()> {
        use std::os::unix::ffi::OsStrExt as _;
        let tmp = tempfile::tempdir()?;
        let target = tmp.path().join(std::ffi::OsStr::from_bytes(b"site-\xff"));
        std::fs::create_dir(&target)?;
        let alias = tmp.path().join("public");
        std::os::unix::fs::symlink(&target, &alias)?;
        assert!(super::one_shot_paths(&alias).is_err());
        assert!(!tmp.path().join("runtime").exists());
        Ok(())
    }

    #[test]
    fn one_shot_requires_an_existing_directory() -> crate::Result<()> {
        let tmp = tempfile::tempdir()?;
        let file = tmp.path().join("file");
        std::fs::write(&file, b"file")?;
        assert!(super::one_shot_paths(&file).is_err());
        assert!(super::one_shot_paths(&tmp.path().join("missing")).is_err());
        let (data_dir, site_dir) = super::one_shot_paths(tmp.path())?;
        assert_eq!(data_dir.join(site_dir), tmp.path().canonicalize()?);
        Ok(())
    }

    use super::{
        apply_managed_runtime_mode, detect_install_kind, ensure_data_directories,
        first_run_headless_message, first_run_interactive_message, first_run_setup,
        managed_runner_mode, uses_redirect_public_http, InstallKind, ManagedRunnerMode,
    };
    use crate::config::Config;
    use std::path::Path;

    #[test]
    fn headless_cli_selects_headless_managed_runner() {
        let mut config = Config::default();
        config.console.interactive = true;

        assert_eq!(
            managed_runner_mode(true, &config),
            ManagedRunnerMode::Headless
        );
    }

    #[test]
    fn default_interactive_config_selects_interactive_managed_runner() {
        let mut config = Config::default();
        config.console.interactive = true;

        assert_eq!(
            managed_runner_mode(false, &config),
            ManagedRunnerMode::Interactive
        );
    }

    #[test]
    fn config_can_disable_interactive_managed_runner_without_cli_flag() {
        let mut config = Config::default();
        config.console.interactive = false;

        assert_eq!(
            managed_runner_mode(false, &config),
            ManagedRunnerMode::Headless
        );
    }

    #[test]
    fn applying_headless_managed_runner_disables_console_interactivity() {
        let mut config = Config::default();
        config.console.interactive = true;

        apply_managed_runtime_mode(&mut config, ManagedRunnerMode::Headless);

        assert!(!config.console.interactive);
    }

    #[test]
    fn redirect_http_replaces_public_plain_http_only_when_tls_is_enabled() {
        let mut config = Config::default();
        config.tls.redirect_http = true;
        assert!(!uses_redirect_public_http(&config));

        config.tls.enabled = true;
        assert!(uses_redirect_public_http(&config));
    }

    #[test]
    fn first_run_setup_creates_site_and_runtime_directories() -> crate::Result<()> {
        let tmp = tempfile::tempdir()?;
        let data_dir = tmp.path().join("rusthost-data");
        let settings = data_dir.join("settings.toml");

        first_run_setup(&data_dir, &settings, InstallKind::Fresh, false)?;

        assert!(data_dir.join("site").is_dir());
        assert!(data_dir.join("runtime").is_dir());
        assert!(settings.is_file());
        Ok(())
    }

    #[test]
    fn ensure_data_directories_creates_runtime_directory() -> crate::Result<()> {
        let tmp = tempfile::tempdir()?;
        let data_dir = tmp.path().join("rusthost-data");

        ensure_data_directories(&data_dir)?;

        assert!(data_dir.join("runtime").is_dir());
        Ok(())
    }

    #[test]
    fn missing_settings_with_existing_site_is_regeneration() -> crate::Result<()> {
        let tmp = tempfile::tempdir()?;
        let data_dir = tmp.path().join("rusthost-data");
        crate::persistence::create_dir_all(&data_dir.join("site"))?;

        assert_eq!(
            detect_install_kind(&data_dir),
            InstallKind::RegeneratedSettings
        );
        Ok(())
    }

    #[test]
    fn missing_settings_without_site_or_runtime_is_fresh_install() -> crate::Result<()> {
        let tmp = tempfile::tempdir()?;
        let data_dir = tmp.path().join("rusthost-data");

        assert_eq!(detect_install_kind(&data_dir), InstallKind::Fresh);
        Ok(())
    }

    #[test]
    fn first_run_headless_message_uses_active_data_dir() -> crate::Result<()> {
        let tmp = tempfile::tempdir()?;
        let data_dir = tmp.path().join("custom-data");
        let settings_path = data_dir.join("settings.toml");

        let output = first_run_headless_message(&data_dir, &settings_path, InstallKind::Fresh);

        assert!(output.contains(&format!(
            "Site directory: {}",
            data_dir.join("site").display()
        )));
        assert!(output.contains(&format!(
            "Runtime directory: {}",
            data_dir.join("runtime").display()
        )));
        Ok(())
    }

    #[test]
    fn first_run_interactive_message_uses_active_data_dir() -> crate::Result<()> {
        let tmp = tempfile::tempdir()?;
        let data_dir = tmp.path().join("custom-data");

        let output = first_run_interactive_message(&data_dir, InstallKind::Fresh);

        assert!(output.contains(&format!("{}/", data_dir.join("site").display())));
        assert!(output.contains(&format!("{}/", data_dir.join("runtime").display())));
        assert!(!output.contains("./rusthost-data/site/"));
        Ok(())
    }

    #[test]
    fn first_run_messages_trim_parents_before_rusthost_data() {
        let data_dir = Path::new("/Users/example/Desktop/rusthost-data");
        let settings_path = data_dir.join("settings.toml");

        let headless = first_run_headless_message(data_dir, &settings_path, InstallKind::Fresh);
        let interactive = first_run_interactive_message(data_dir, InstallKind::Fresh);

        let display_root = Path::new("rusthost-data");
        assert!(headless.contains(&format!(
            "Created default config: {}",
            display_root.join("settings.toml").display()
        )));
        assert!(headless.contains(&format!(
            "Site directory: {}",
            display_root.join("site").display()
        )));
        assert!(headless.contains(&format!(
            "Runtime directory: {}",
            display_root.join("runtime").display()
        )));
        assert!(interactive.contains(&format!("{}/", display_root.join("site").display())));
        assert!(interactive.contains(&format!("{}/", display_root.join("runtime").display())));
        assert!(!headless.contains("/Users/example/Desktop/rusthost-data"));
        assert!(!interactive.contains("/Users/example/Desktop/rusthost-data"));
    }
}
