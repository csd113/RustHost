//! # Lifecycle
//!
//! **Directory:** `src/runtime/`
//!
//! Two paths:
//! 1. **First run** — creates the directory tree, writes defaults, prints
//!    instructions, and exits cleanly.
//! 2. **Normal run** — loads config, starts every subsystem, enters the
//!    event dispatch loop, then shuts down gracefully.

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

// ─── Entry point ─────────────────────────────────────────────────────────────
//
// 4.4 — `data_dir()` and `settings_path()` are no longer free functions.
// The data directory is computed exactly once at the top of `run()` and
// threaded through every call that needs it as an explicit parameter.
// This removes the hidden `current_exe()` dependency from all internal
// functions and makes the path injectable (e.g. a tmp dir in tests).

pub async fn run() -> Result<()> {
    // 4.4 — single source of truth; computed here, nowhere else.
    let exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("."));
    let data_dir = exe
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("rusthost-data");
    let settings_path = data_dir.join("settings.toml");

    if settings_path.exists() {
        normal_run(data_dir).await?;
    } else {
        first_run_setup(&data_dir, &settings_path)?;
    }
    Ok(())
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

async fn normal_run(data_dir: PathBuf) -> Result<()> {
    let settings_path = data_dir.join("settings.toml");

    // 1. Load and validate config.
    let config = Arc::new(config::loader::load(&settings_path)?);

    // 2. Initialise logging.
    logging::init(&config.logging, &data_dir)?;
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
    let server_handle = spawn_server(
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
    //    tor::init() spawns a Tokio task and returns immediately.
    //    2.10 — pass shutdown_rx so Tor's stream loop exits on clean shutdown.
    if config.tor.enabled {
        tor::init(
            data_dir.clone(),
            bind_port,
            Arc::clone(&state),
            shutdown_rx.clone(),
        );
    }

    // 9. Start console UI.
    let key_rx = start_console(&config, &state, &metrics, shutdown_rx.clone()).await?;

    // 10. Open browser (if configured).
    if config.server.open_browser_on_start {
        let port = state.read().await.actual_port;
        // 2.4 — use canonical open_browser from crate::runtime
        super::open_browser(&format!("http://localhost:{port}"));
    }

    // 11. Event dispatch loop.
    // 4.7 — tokio::signal::ctrl_c() replaces the ctrlc crate. The signal
    //        future is passed into event_loop and used directly in select!,
    //        eliminating the threading conflict between the ctrlc crate's
    //        OS-level handler and Tokio's internal signal infrastructure.
    event_loop(key_rx, &config, &state, &metrics, data_dir).await?;

    // 12. Graceful shutdown.
    log::info!("Shutting down…");
    let _ = shutdown_tx.send(true);

    // 2.10 — wait for the HTTP server to drain in-flight connections (max 5 s).
    // tor::kill() has been removed — Tor exits when its task detects shutdown_rx.
    let _ = tokio::time::timeout(Duration::from_secs(5), server_handle).await;

    // 2.11 — write the final log entry, flush to disk, then restore the terminal.
    log::info!("RustHost shut down cleanly.");
    logging::flush();
    console::cleanup();

    Ok(())
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Spawn the HTTP server task and return its `JoinHandle` so the shutdown
/// sequence can await the connection drain (fix 2.10).
fn spawn_server(
    config: &Arc<Config>,
    state: &SharedState,
    metrics: &SharedMetrics,
    shutdown: &watch::Receiver<bool>,
    port_tx: oneshot::Sender<u16>,
    data_dir: PathBuf, // 3.1/4.4 — caller owns data_dir; no current_exe() here
) -> tokio::task::JoinHandle<()> {
    let cfg = Arc::clone(config);
    let st = Arc::clone(state);
    let met = Arc::clone(metrics);
    let shut = shutdown.clone();
    tokio::spawn(async move {
        server::run(cfg, st, met, data_dir, shut, port_tx).await;
    })
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

async fn event_loop(
    key_rx: Option<mpsc::UnboundedReceiver<events::KeyEvent>>,
    config: &Arc<Config>,
    state: &SharedState,
    metrics: &SharedMetrics,
    data_dir: PathBuf, // 3.1/4.4 — pre-computed by normal_run; not recomputed per event
) -> Result<()> {
    // 2.8 — mutable so we can set to None when the channel closes.
    let mut key_rx = key_rx;

    // 4.7 — tokio::signal::ctrl_c() replaces ctrlc crate's set_handler + mpsc.
    //        Pinned so it can be polled repeatedly inside select! without moving.
    let ctrl_c = tokio::signal::ctrl_c();
    tokio::pin!(ctrl_c);

    loop {
        // Build a future that yields the next key, or pends forever once the
        // channel closes (avoids repeated None-match after input task death).
        // When the channel closes we log once and park this arm (2.8).
        let key_fut = async {
            if let Some(rx) = key_rx.as_mut() {
                rx.recv().await
            } else {
                // Channel already closed — pend forever so ctrl_c can still fire.
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
                        data_dir.clone(), // 3.1 — cheap PathBuf clone, no syscall
                    ).await?;
                    if quit { break; }
                } else {
                    // 2.8 — input task exited; disable key arm and warn operator.
                    log::warn!(
                        "Console input task exited — keyboard input disabled. \
                         Use Ctrl-C to quit."
                    );
                    key_rx = None; // suppress repeated warnings on next select! iteration
                }
            }
            // 4.7 — Ctrl-C handled directly through Tokio's signal machinery.
            result = &mut ctrl_c => {
                if let Err(e) = result {
                    log::warn!("Ctrl-C signal error: {e}");
                }
                break;
            }
        }
    }
    Ok(())
}

// open_browser removed from this file — canonical definition is in
// crate::runtime (src/runtime/mod.rs), called via super::open_browser (fix 2.4).

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
