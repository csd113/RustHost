//! # Lifecycle
//!
//! **Directory:** `src/runtime/`
//!
//! Two paths:
//! 1. **First run** — creates the directory tree, writes defaults, prints
//!    instructions, and exits cleanly.
//! 2. **Normal run** — loads config, starts every subsystem, enters the
//!    event dispatch loop, then shuts down gracefully.

use std::{path::PathBuf, sync::Arc, time::Duration};

use tokio::sync::{mpsc, watch, RwLock};

use crate::{
    config::{self, Config},
    console, logging,
    runtime::{
        events,
        state::{AppState, Metrics, SharedMetrics, SharedState, TorStatus},
    },
    server, tor, Result,
};

// ─── Paths ──────────────────────────────────────────────────────────────────

fn data_dir() -> PathBuf {
    let exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("."));
    exe.parent()
        .unwrap_or_else(|| std::path::Path::new("."))
        .join("rusthost-data")
}

fn settings_path() -> PathBuf {
    data_dir().join("settings.toml")
}

// ─── Entry point ────────────────────────────────────────────────────────────

pub async fn run() -> Result<()> {
    if is_first_run() {
        first_run_setup()?;
    } else {
        normal_run().await?;
    }
    Ok(())
}

// ─── First Run ──────────────────────────────────────────────────────────────

fn is_first_run() -> bool {
    !settings_path().exists()
}

fn first_run_setup() -> Result<()> {
    let base = data_dir();

    for sub in &["site", "logs"] {
        std::fs::create_dir_all(base.join(sub))?;
    }

    config::defaults::write_default_config(&settings_path())?;

    let placeholder = base.join("site/index.html");
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

// ─── Normal Run ─────────────────────────────────────────────────────────────

async fn normal_run() -> Result<()> {
    // 1. Load and validate config.
    let config = Arc::new(config::loader::load(&settings_path())?);

    // 2. Initialise logging.
    logging::init(&config.logging, &data_dir())?;
    log::info!("RustHost starting — version {}", env!("CARGO_PKG_VERSION"));

    if config.server.bind == "0.0.0.0" {
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
    {
        let site_root = data_dir().join(&config.site.directory);
        let (count, bytes) = server::scan_site(&site_root);
        let mut s = state.write().await;
        s.site_file_count = count;
        s.site_total_bytes = bytes;
    }

    // 6. Shutdown channels.
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // 7. Ctrl-C handler.
    let (ctrlc_tx, mut ctrlc_rx) = mpsc::channel::<()>(1);
    ctrlc::set_handler(move || {
        let _ = ctrlc_tx.try_send(());
    })?;

    // 8. Start HTTP server task.
    spawn_server(&config, &state, &metrics, &shutdown_rx);

    // Wait for the server to bind so actual_port is populated before we pass
    // it to Tor. 50 ms is enough for localhost; the auto-fallback logic inside
    // server::run handles the real timing.
    tokio::time::sleep(Duration::from_millis(50)).await;

    // 9. Start Tor (if enabled).
    //    tor::init() spawns a Tokio task and returns immediately — never blocks
    //    the async executor.
    if config.tor.enabled {
        let bind_port = state.read().await.actual_port;
        tor::init(data_dir(), bind_port, Arc::clone(&state));
    }

    // 10. Start console UI.
    let key_rx = start_console(&config, &state, &metrics, shutdown_rx.clone()).await?;

    // 11. Open browser (if configured).
    if config.server.open_browser_on_start {
        let port = state.read().await.actual_port;
        open_browser(&format!("http://localhost:{port}"));
    }

    // 12. Event dispatch loop.
    event_loop(key_rx, &config, &state, &metrics, &mut ctrlc_rx).await?;

    // 13. Graceful shutdown.
    log::info!("Shutting down…");
    let _ = shutdown_tx.send(true);
    // Drop the Arti TorClient — closes all Tor circuits cleanly.
    tor::kill();
    tokio::time::sleep(Duration::from_millis(300)).await;
    console::cleanup();
    log::info!("Goodbye.");

    Ok(())
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn spawn_server(
    config: &Arc<Config>,
    state: &SharedState,
    metrics: &SharedMetrics,
    shutdown: &watch::Receiver<bool>,
) {
    let cfg = Arc::clone(config);
    let st = Arc::clone(state);
    let met = Arc::clone(metrics);
    let data = data_dir();
    let shut = shutdown.clone();
    tokio::spawn(async move {
        server::run(cfg, st, met, data, shut).await;
    });
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
        println!("RustHost running on http://{}:{port}", config.server.bind);
        Ok(None)
    }
}

async fn event_loop(
    key_rx: Option<mpsc::UnboundedReceiver<events::KeyEvent>>,
    config: &Arc<Config>,
    state: &SharedState,
    metrics: &SharedMetrics,
    ctrlc_rx: &mut mpsc::Receiver<()>,
) -> Result<()> {
    let mut key_rx = key_rx;
    loop {
        tokio::select! {
            Some(key) = async {
                match key_rx.as_mut() {
                    Some(rx) => rx.recv().await,
                    None     => None,
                }
            } => {
                let quit = events::handle(
                    key,
                    config,
                    Arc::clone(state),
                    Arc::clone(metrics),
                    data_dir(),
                ).await?;
                if quit { break; }
            }
            Some(()) = ctrlc_rx.recv() => { break; }
        }
    }
    Ok(())
}

fn open_browser(url: &str) {
    #[cfg(target_os = "macos")]
    let _ = std::process::Command::new("open").arg(url).spawn();
    #[cfg(target_os = "windows")]
    let _ = std::process::Command::new("explorer").arg(url).spawn();
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    let _ = std::process::Command::new("xdg-open").arg(url).spawn();
}

// ─── Placeholder HTML ─────────────────────────────────────────────────────────

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
