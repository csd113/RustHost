//! # Tor Module
//!
//! **Directory:** `src/tor/`
//!
//! Manages the Tor subprocess. Tor binary detection follows the same approach
//! used in `detect.rs`.
//!
//! On startup, `init()` is called once from the lifecycle module. It:
//!   1. Searches for the `tor` binary in common install paths + PATH.
//!   2. Creates `tor_data/` and `tor_hidden_service/` under `data_dir/` with
//!      mode `0700` (required by Tor).
//!   3. Writes a `torrc` with `SocksPort 0` — this disables the SOCKS proxy
//!      port entirely, which prevents the port-9050 conflict that occurs when
//!      a system Tor daemon is already running.
//!   4. Spawns `tor` as a subprocess and stores the handle in a [`OnceLock`].
//!   5. Registers a panic hook so the child is killed if the process crashes.
//!   6. Spawns a background thread that polls for the `hostname` file and
//!      writes the onion address into shared state once Tor is ready.
//!
//! Shutdown: call `kill()` during graceful shutdown to reap the child process.

use std::{
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{Arc, Mutex, OnceLock},
};

use crate::runtime::state::{SharedState, TorStatus};

// ─── Static child handle ─────────────────────────────────────────────────────

static TOR_CHILD: OnceLock<Arc<Mutex<std::process::Child>>> = OnceLock::new();

/// Kill and reap the Tor subprocess. Safe to call at any time; no-op if Tor
/// was never started or has already exited.
pub fn kill() {
    if let Some(child) = TOR_CHILD.get() {
        if let Ok(mut c) = child.lock() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

// ─── Candidate binary paths ──────────────────────────────────────────────────

/// Common install paths tried in order before falling back to bare `tor`
/// (which relies on PATH).
const TOR_CANDIDATES: &[&str] = &[
    "/opt/homebrew/bin/tor", // macOS Apple Silicon (Homebrew)
    "/usr/local/bin/tor",    // macOS Intel (Homebrew) / custom Linux installs
    "/usr/bin/tor",          // Debian / Ubuntu package
    "tor",                   // Anything in PATH
];

// ─── Public entry point ──────────────────────────────────────────────────────

/// Initialise Tor. Called once from `runtime::lifecycle` during normal startup.
///
/// Returns immediately after spawning the background polling thread — does not
/// block the async executor.
pub fn init(data_dir: PathBuf, bind_port: u16, state: SharedState) {
    // Run everything on a blocking thread so we never block the executor.
    // All downstream work (dir creation, process spawn, hostname polling) is
    // also synchronous / std-thread-based.
    std::thread::spawn(move || {
        run_sync(&data_dir, bind_port, &state);
    });
}

// ─── Core synchronous logic ──────────────────────────────────────────────────

fn run_sync(data_dir: &Path, bind_port: u16, state: &SharedState) {
    // 1. Find the tor binary.
    let Some(tor_bin) = find_tor_binary() else {
        log::warn!(
            "Tor binary not found — tried: {}",
            TOR_CANDIDATES.join(", ")
        );
        log::info!(
            "Install Tor to enable onion service:\n  \
             macOS:  brew install tor\n  \
             Linux:  sudo apt-get install tor\n  \
             Other:  https://www.torproject.org/download/tor/"
        );
        set_status(state, TorStatus::NotFound);
        return;
    };

    log::info!("Tor binary found: {tor_bin}");

    // 2. Prepare directories (must exist with 0700 before Tor starts).
    let hs_dir = data_dir.join("tor_hidden_service");
    let data_sub = data_dir.join("tor_data");
    if !prepare_directories(&hs_dir, &data_sub) {
        set_status(state, TorStatus::Failed(None));
        return;
    }

    // 3. Write torrc.
    let abs = |p: &Path| p.canonicalize().unwrap_or_else(|_| p.to_path_buf());
    let hs_abs = abs(&hs_dir);
    let data_abs = abs(&data_sub);
    let torrc_path = abs(data_dir).join("torrc");
    if !write_torrc(&torrc_path, &data_abs, &hs_abs, bind_port) {
        set_status(state, TorStatus::Failed(None));
        return;
    }

    // 4 + 5. Spawn Tor process and collect stderr.
    let Some((child, stderr_lines)) = spawn_tor_process(tor_bin, &torrc_path) else {
        set_status(state, TorStatus::Failed(None));
        return;
    };

    // 6. Store child handle and register panic hook.
    let child = Arc::new(Mutex::new(child));
    let _ = TOR_CHILD.set(Arc::clone(&child));
    register_panic_hook();

    // 7. Log PID and transition to Starting.
    let pid = child
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .id();
    log::info!("Tor: process started (PID {pid}) — polling for .onion address");
    set_status(state, TorStatus::Starting);

    // 8. Poll for hostname in a background thread.
    let hostname_path = hs_abs.join("hostname");
    let torrc_display = torrc_path.display().to_string();
    let tor_bin_owned = tor_bin.to_string();
    let child_bg = child; // move — no redundant Arc::clone needed
    let stderr_bg = stderr_lines;
    let state_bg = state.clone();

    std::thread::spawn(move || {
        // Brief initial pause — Tor takes a moment to write its first logs.
        std::thread::sleep(std::time::Duration::from_secs(4));

        // Early-exit check: if Tor died in the first 4 seconds, surface the
        // stderr output immediately rather than waiting through the poll loop.
        let try_wait = child_bg
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .try_wait();

        if let Ok(Some(status)) = try_wait {
            let lines = stderr_bg
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            log::error!("Tor: process exited early ({status})");
            for line in lines.iter().take(20) {
                log::error!("[tor stderr] {line}");
            }
            drop(lines);
            log::info!(
                "Tor troubleshooting:\n  \
                 Run manually:  {tor_bin_owned} -f {torrc_display}\n  \
                 Common causes: DataDirectory/HiddenServiceDir permissions (chmod 700),\n  \
                 \x20               macOS Homebrew conflict (brew services stop tor),\n  \
                 \x20               firewall blocking outbound TCP 9001/443."
            );
            set_status(&state_bg, TorStatus::Failed(status.code()));
            return;
        }

        poll_for_hostname(
            &hostname_path,
            &child_bg,
            &stderr_bg,
            &state_bg,
            &torrc_display,
            &tor_bin_owned,
            bind_port,
        );
    });
}

// ─── Extracted helpers ────────────────────────────────────────────────────────

/// Create `hs_dir` and `data_sub` with mode `0700`. Returns `false` on error.
fn prepare_directories(hs_dir: &Path, data_sub: &Path) -> bool {
    for dir in [hs_dir, data_sub] {
        if let Err(e) = std::fs::create_dir_all(dir) {
            log::error!("Tor: cannot create directory {}: {e}", dir.display());
            return false;
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Err(e) = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)) {
                // Non-fatal: log the warning and let Tor decide if it can proceed.
                log::warn!(
                    "Tor: could not set 0700 on {} (Tor may reject it): {e}",
                    dir.display()
                );
            }
        }
    }
    true
}

/// Write the auto-generated `torrc` file. Returns `false` on error.
fn write_torrc(torrc_path: &Path, data_abs: &Path, hs_abs: &Path, bind_port: u16) -> bool {
    //    SocksPort 0  — disable the SOCKS proxy entirely.  This is the key
    //    setting that prevents the port-9050 conflict when a system Tor daemon
    //    is already running on the same machine.
    let torrc_content = format!(
        "# RustHost — auto-generated torrc (do not edit while Tor is running)\n\
         \n\
         SocksPort 0\n\
         DataDirectory \"{data}\"\n\
         \n\
         HiddenServiceDir \"{hs}\"\n\
         HiddenServicePort 80 127.0.0.1:{bind_port}\n",
        data = data_abs.display(),
        hs = hs_abs.display(),
    );

    if let Err(e) = std::fs::write(torrc_path, &torrc_content) {
        log::error!("Tor: cannot write torrc to {}: {e}", torrc_path.display());
        return false;
    }
    log::info!("Tor: torrc written to {}", torrc_path.display());
    true
}

/// Spawn the Tor process and collect its stderr in a background thread.
///
/// Returns the child handle and the shared stderr buffer, or `None` on failure.
fn spawn_tor_process(
    tor_bin: &str,
    torrc_path: &Path,
) -> Option<(std::process::Child, Arc<Mutex<Vec<String>>>)> {
    //    stdout  → null   (Tor logs go to stderr; we don't need bootstrap output)
    //    stderr  → piped  (collected for diagnostics on early exit)
    let child = Command::new(tor_bin)
        .arg("-f")
        .arg(torrc_path)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn();

    let mut child = match child {
        Err(e) => {
            log::error!("Tor: failed to spawn process: {e}");
            return None;
        }
        Ok(c) => c,
    };

    let stderr_lines: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    if let Some(pipe) = child.stderr.take() {
        let buf = Arc::clone(&stderr_lines);
        std::thread::spawn(move || {
            use std::io::{BufRead, BufReader};
            for line in BufReader::new(pipe).lines().map_while(Result::ok).take(500) {
                if let Ok(mut g) = buf.lock() {
                    g.push(line);
                }
            }
        });
    }

    Some((child, stderr_lines))
}

/// Install a panic hook that kills the Tor child process on an unexpected crash.
fn register_panic_hook() {
    let prev_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        if let Some(child) = TOR_CHILD.get() {
            if let Ok(mut c) = child.try_lock() {
                let _ = c.kill();
                let _ = c.wait();
            }
        }
        prev_hook(info);
    }));
}

// ─── Hostname polling ─────────────────────────────────────────────────────────

fn poll_for_hostname(
    hostname_path: &Path,
    child: &Arc<Mutex<std::process::Child>>,
    stderr_lines: &Arc<Mutex<Vec<String>>>,
    state: &SharedState,
    torrc_display: &str,
    tor_bin: &str,
    bind_port: u16,
) {
    const TIMEOUT_SECS: u64 = 120;
    const POLL_MS: u64 = 500;
    let start = std::time::Instant::now();
    let timeout = std::time::Duration::from_secs(TIMEOUT_SECS);

    loop {
        // Check if the process has crashed.
        if let Ok(mut c) = child.try_lock() {
            if let Ok(Some(status)) = c.try_wait() {
                let lines = stderr_lines
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                log::error!("Tor: process crashed during startup ({status})");
                for line in lines.iter().take(20) {
                    log::error!("[tor stderr] {line}");
                }
                drop(lines);
                set_status(state, TorStatus::Failed(status.code()));
                return;
            }
        }

        // Check for the hostname file.
        if hostname_path.exists() {
            match std::fs::read_to_string(hostname_path) {
                Ok(raw) => {
                    let onion = raw.trim().to_owned();
                    if !onion.is_empty() {
                        log::info!("Tor: onion service active — http://{onion}");
                        log::info!(
                            "\n  ╔═══════════════════════════════════════════════════╗\n  \
                               ║   TOR ONION SERVICE ACTIVE                        ║\n  \
                               ╠═══════════════════════════════════════════════════╣\n  \
                               ║   http://{onion:<43}║\n  \
                               ║   Share this address with Tor Browser users.      ║\n  \
                               ╚═══════════════════════════════════════════════════╝",
                        );
                        set_onion(state, onion);
                        return;
                    }
                }
                Err(e) => {
                    log::warn!("Tor: hostname file unreadable: {e}");
                }
            }
        }

        if start.elapsed() >= timeout {
            let path_display = hostname_path.display();
            log::warn!(
                "Tor: timed out after {TIMEOUT_SECS}s waiting for hostname file at {path_display}",
            );
            log::info!(
                "Tor troubleshooting:\n  \
                 Run manually:  {tor_bin} -f {torrc_display}\n  \
                 Common causes: DataDirectory/HiddenServiceDir permissions (chmod 700),\n  \
                 \x20               firewall blocking outbound TCP 9001/443 (needed for bootstrap),\n  \
                 \x20               macOS Homebrew conflict: brew services stop tor\n  \
                 \x20               Linux SELinux/AppArmor: sudo journalctl -u tor --since '5 min ago'\n  \
                 Manual torrc:  HiddenServicePort 80 127.0.0.1:{bind_port}"
            );
            set_status(state, TorStatus::Failed(None));
            return;
        }

        std::thread::sleep(std::time::Duration::from_millis(POLL_MS));
    }
}

// ─── State helpers ────────────────────────────────────────────────────────────

fn set_status(state: &SharedState, status: TorStatus) {
    // We are on a std::thread (not the async executor), so use blocking_write()
    // which spins the current thread until the lock is available.
    state.blocking_write().tor_status = status;
}

fn set_onion(state: &SharedState, addr: String) {
    let mut s = state.blocking_write();
    s.tor_status = TorStatus::Ready;
    s.onion_address = Some(addr);
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn find_tor_binary() -> Option<&'static str> {
    TOR_CANDIDATES.iter().copied().find(|bin| {
        Command::new(bin)
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok()
    })
}
