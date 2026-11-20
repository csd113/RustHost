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

mod services;

use std::{
    fmt::Write as _,
    io::Write as _,
    path::{Path, PathBuf},
    sync::Arc,
};

use tokio::sync::{mpsc, watch, RwLock};

use crate::{
    config::{self, Config},
    console::{self, actions},
    logging,
    path_display::display_path,
    runtime::{
        runtime_root,
        service_status::{RuntimeState, TorPhase},
        shutdown::Shutdown,
        site_reload,
        state::{AppState, Metrics, SharedMetrics},
    },
    server::{
        self,
        listeners::{ConnectionBudget, ListenerContext},
    },
    Result,
};
use services::{maybe_open_browser, Services};

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
async fn normal_run_with_config(
    data_dir: PathBuf,
    settings_path: Option<PathBuf>,
    config: Arc<Config>,
) -> Result<()> {
    ensure_data_directories(&data_dir)?;
    logging::init(&config.logging, &data_dir)?;
    if let Err(error) = logging::init_access_log(&config.logging, &data_dir) {
        log::warn!("Could not initialise access log: {error}");
    }
    log::info!("RustHost starting — version {}", env!("CARGO_PKG_VERSION"));
    if config.server.bind.is_unspecified() {
        log::warn!(
            "[server] bind = \"{}\" — server is reachable on all interfaces.",
            config.server.bind
        );
    }

    let (trigger, signal) = watch::channel(false);
    let (context, root_tx) =
        prepare_runtime(config, data_dir, Shutdown::from_receiver(signal)).await?;
    let mut services = Services::default();
    let outcome = run_services(&context, settings_path, root_tx, &mut services).await;
    services.shutdown(&context, &trigger).await;
    outcome
}

async fn prepare_runtime(
    config: Arc<Config>,
    data_dir: PathBuf,
    shutdown: Shutdown,
) -> Result<(ListenerContext, watch::Sender<Arc<server::SiteSnapshot>>)> {
    let snapshot_config = Arc::clone(&config);
    let snapshot_dir = data_dir.clone();
    let site = tokio::task::spawn_blocking(move || {
        server::SiteSnapshot::prepare(&snapshot_config, &snapshot_dir)
    })
    .await
    .map_err(|error| {
        crate::AppError::ConfigLoad(format!("site preparation task failed: {error}"))
    })??;
    let mut state = AppState::new();
    state.site_file_count = site.file_count;
    state.site_total_bytes = site.total_bytes;
    let state = RuntimeState::new(Arc::new(RwLock::new(state)));
    if !config.tor.enabled {
        state.set_tor(TorPhase::Disabled, None).await;
    }
    let (root_tx, site_watch) = watch::channel(site);
    let budget = ConnectionBudget {
        semaphore: Arc::new(tokio::sync::Semaphore::new(
            config.server.max_connections as usize,
        )),
        per_ip_map: Arc::new(dashmap::DashMap::new()),
    };
    Ok((
        ListenerContext {
            config,
            state,
            metrics: Arc::new(Metrics::new()),
            data_dir,
            shutdown,
            site_watch,
            budget,
        },
        root_tx,
    ))
}

async fn run_services(
    context: &ListenerContext,
    settings_path: Option<PathBuf>,
    root_tx: watch::Sender<Arc<server::SiteSnapshot>>,
    services: &mut Services,
) -> Result<()> {
    services.start(context).await?;
    let session = start_console(
        &context.config,
        &context.state,
        &context.metrics,
        context.shutdown.receiver(),
        &context.data_dir,
    )
    .await?;
    context.state.refresh_readiness(&context.config).await;
    maybe_open_browser(&context.config, &context.state).await;
    tokio::select! {
        result = services.wait_for_failure(&context.state) => result,
        result = event_loop(session, context, settings_path, root_tx) => result,
        () = shutdown_requested() => Ok(()),
    }
}

fn ensure_data_directories(data_dir: &Path) -> Result<()> {
    crate::persistence::create_dir_all(&runtime_root(data_dir))?;
    Ok(())
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

async fn start_console(
    config: &Arc<Config>,
    state: &RuntimeState,
    metrics: &SharedMetrics,
    shutdown: watch::Receiver<bool>,
    data_dir: &Path,
) -> Result<Option<(mpsc::Receiver<actions::KeyEvent>, Arc<tokio::sync::Notify>)>> {
    if config.console.interactive {
        let session = console::start_managed(
            Arc::clone(config),
            state.clone(),
            Arc::clone(metrics),
            shutdown,
            data_dir.to_path_buf(),
        )?;
        Ok(Some(session))
    } else {
        let (role, http, https, tor_ingress) = {
            let snapshot = state.status().await;
            (
                snapshot.public_http_role,
                snapshot.public_http.bound_addr(),
                snapshot.https.bound_addr(),
                snapshot.tor_ingress.bound_addr(),
            )
        };
        let mut stdout = std::io::stdout();
        let _ = writeln!(stdout, "RustHost running");
        if let Some(address) = http {
            let _ = writeln!(stdout, " {} : http://{address}", role.label());
        }
        if let Some(address) = https {
            let _ = writeln!(stdout, " HTTPS: https://{address}");
        }
        if let Some(address) = tor_ingress {
            let _ = writeln!(stdout, " Tor ingress : http://{address}");
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

async fn shutdown_requested() {
    tokio::select! {
        result = tokio::signal::ctrl_c() => {
            if let Err(error) = result {
                log::warn!("Ctrl-C signal error: {error}");
                next_sigterm().await;
            }
        }
        () = next_sigterm() => log::info!("SIGTERM received — shutting down gracefully."),
    }
}

async fn event_loop(
    session: Option<(mpsc::Receiver<actions::KeyEvent>, Arc<tokio::sync::Notify>)>,
    context: &ListenerContext,
    settings_path: Option<PathBuf>,
    root_tx: watch::Sender<Arc<server::SiteSnapshot>>,
) -> Result<()> {
    // 2.8 — mutable so we can set to None when the channel closes.
    let (mut key_rx, render_notify) = match session {
        Some((rx, notify)) => (Some(rx), Some(notify)),
        None => (None, None),
    };

    #[cfg(unix)]
    let mut sighup = make_sighup_signal();
    #[cfg(not(unix))]
    let sighup = make_sighup_signal();

    loop {
        // Build a future that yields the next key, or pends forever once the
        // channel closes (avoids repeated None-match after input task death).
        let key_fut = async {
            if let Some(rx) = key_rx.as_mut() {
                rx.recv().await
            } else {
                std::future::pending::<Option<actions::KeyEvent>>().await
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
                    let quit = actions::handle_with_runtime(
                        key,
                        &context.config,
                        Arc::clone(&context.state.app),
                        Some(&context.state),
                        context.data_dir.clone(),
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
            maybe_hup = sighup_fut => {
                if maybe_hup.is_some() {
                    log::info!("SIGHUP received — reloading site state.");
                    site_reload::reload_site(&context.config, Arc::clone(&context.state.app), context.data_dir.clone(), &root_tx).await?;
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
