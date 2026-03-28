//! # terminal – cross-platform auto-terminal launcher
//!
//! Detects whether the process is attached to a TTY. If it is not (e.g. the
//! binary was double-clicked in a file manager), the process relaunches itself
//! inside an appropriate terminal emulator and exits, so the user always sees
//! interactive output.
//!
//! ## Loop-prevention
//!
//! The env-var `RUSTHOST_SPAWNED=1` is injected into the child environment
//! before the relaunch. On entry, [`maybe_relaunch`] checks for that var and
//! skips respawning if it is set, preventing an infinite spawn loop.
//!
//! ## Platform behaviour
//!
//! | Platform | Strategy |
//! |----------|----------|
//! | Windows  | `cmd /C "set RUSTHOST_SPAWNED=1 && <exe> [args] \|\| pause"` |
//! | macOS    | `open -a Terminal <exe>` (Terminal.app sets the env var via the child env) |
//! | Linux    | Tries a priority-ordered list of terminal emulators and stops on the first success. |
//!
//! ### Linux terminal candidates (tried in order)
//! `x-terminal-emulator`, `gnome-terminal`, `konsole`, `alacritty`, `xterm`
//!
//! If none are found on Linux the user is asked to launch the binary from a
//! terminal manually.
//!
//! ## Usage
//!
//! Call [`maybe_relaunch`] at the very top of `main`, before any other
//! initialisation:
//!
//! ```rust,ignore
//! fn main() {
//!     rusthost::terminal::maybe_relaunch();
//!     // … rest of main …
//! }
//! ```

use std::env;
use std::path::PathBuf;
use std::process;

use anyhow::{Context, Result};

/// Sentinel environment variable used to prevent re-spawn loops.
const SPAWNED_VAR: &str = "RUSTHOST_SPAWNED";

// ─── Public entry point ───────────────────────────────────────────────────────

/// Check whether a relaunch is necessary and, if so, perform it then exit.
///
/// The function is a no-op when:
/// - the process is already attached to a TTY, **or**
/// - `RUSTHOST_SPAWNED=1` is already set in the environment.
///
/// If a relaunch is needed but fails, a short message is printed to stderr and
/// the process continues (it may produce garbled output but does not crash).
pub fn maybe_relaunch() {
    // Already inside a terminal spawned by us – do nothing.
    if env::var(SPAWNED_VAR).is_ok() {
        return;
    }

    // Already attached to a TTY – no relaunch required.
    if atty::is(atty::Stream::Stdin) && atty::is(atty::Stream::Stdout) {
        return;
    }

    // Not a TTY and env-var not set → try to relaunch inside a terminal.
    match spawn_in_terminal() {
        Ok(()) => {
            // The child terminal was successfully launched; exit this headless
            // instance so only the terminal window remains.
            process::exit(0);
        }
        Err(e) => {
            eprintln!("[rusthost] terminal relaunch failed: {e}");
            // Fall through and run headlessly – better than a silent crash.
        }
    }
}

// ─── Internal implementation ──────────────────────────────────────────────────

/// Spawn a platform-appropriate terminal emulator that re-executes this binary.
///
/// # Errors
///
/// Returns an error if the current executable path cannot be determined or if
/// no suitable terminal emulator can be found / launched.
fn spawn_in_terminal() -> Result<()> {
    let exe = current_exe()?;
    // Forward every CLI argument the parent received so the child inherits the
    // exact same invocation (e.g. `--serve ./public --port 3000`).
    let cli_args: Vec<String> = env::args().skip(1).collect();

    #[cfg(target_os = "windows")]
    return spawn_windows(&exe, &cli_args);

    #[cfg(target_os = "macos")]
    return spawn_macos(&exe, &cli_args);

    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    return spawn_linux(&exe, &cli_args);
}

/// Resolve the path to the currently-running executable.
fn current_exe() -> Result<PathBuf> {
    env::current_exe().context("could not determine the path to the current executable")
}

// ─── Windows ──────────────────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
fn spawn_windows(exe: &std::path::Path, cli_args: &[String]) -> Result<()> {
    use std::os::windows::process::CommandExt as _;
    use std::process::Command;

    // Build an argument list such as: `rusthost-cli.exe --serve .`
    let exe_str = exe.to_string_lossy();
    let arg_part = if cli_args.is_empty() {
        String::new()
    } else {
        format!(" {}", shell_escape_args(cli_args))
    };

    // The `|| pause` ensures the window stays open if the binary exits with a
    // non-zero code, giving the user a chance to read the error.
    let cmd_line = format!("set {SPAWNED_VAR}=1 && \"{exe_str}\"{arg_part} || pause");

    Command::new("cmd")
        .args(["/C", &cmd_line])
        // Spawn detached so this parent can exit immediately.
        .creation_flags(0x0000_0008) // DETACHED_PROCESS
        .spawn()
        .context("failed to spawn cmd.exe")?;

    Ok(())
}

// ─── macOS ───────────────────────────────────────────────────────────────────

#[cfg(target_os = "macos")]
fn spawn_macos(exe: &std::path::Path, cli_args: &[String]) -> Result<()> {
    use std::process::Command;

    // `open -a Terminal` opens a new Terminal.app window that runs the given
    // binary.  Arguments beyond the binary path are passed through correctly.
    // The env var is injected via `env`.
    let exe_str = exe.to_string_lossy().into_owned();

    // Build the argv for the child: [exe_path, cli_args…]
    let mut child_argv = vec![exe_str];
    child_argv.extend_from_slice(cli_args);

    // We cannot pass `env` through `open -a Terminal` directly; instead we
    // wrap the call in a small env(1) prefix so the env var is set inside the
    // new Terminal window.
    //
    // open -a Terminal -- /usr/bin/env RUSTHOST_SPAWNED=1 <exe> [args...]
    let mut open_args = vec![
        "-a".to_owned(),
        "Terminal".to_owned(),
        "--".to_owned(),
        "/usr/bin/env".to_owned(),
        format!("{SPAWNED_VAR}=1"),
    ];
    open_args.extend(child_argv);

    Command::new("open")
        .args(&open_args)
        .spawn()
        .context("failed to run `open -a Terminal`")?;

    Ok(())
}

// ─── Linux / other Unix ───────────────────────────────────────────────────────

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
fn spawn_linux(exe: &std::path::Path, cli_args: &[String]) -> Result<()> {
    /// Terminal emulators tried in priority order.
    ///
    /// `x-terminal-emulator` is the Debian/Ubuntu alternatives system
    /// symlink and resolves to whatever the user has configured as default.
    const CANDIDATES: &[&str] = &[
        "x-terminal-emulator",
        "gnome-terminal",
        "konsole",
        "alacritty",
        "xterm",
    ];

    let exe_str = exe.to_string_lossy().into_owned();

    // Build `[exe, cli_args…]` as the command the terminal should execute.
    let mut exec_argv: Vec<String> = vec![exe_str];
    exec_argv.extend_from_slice(cli_args);

    for &term in CANDIDATES {
        // Check whether this terminal emulator is on PATH before trying to
        // spawn it, so that "not found" is a quiet skip rather than an error.
        if which_on_path(term).is_none() {
            continue;
        }

        // Most terminal emulators accept `-e <cmd> [args]` to run a command.
        // gnome-terminal uses `--` to separate its own args from the command.
        let mut cmd = build_terminal_command(term, &exec_argv);

        // Inject the sentinel env var so the child does not re-spawn.
        cmd.env(SPAWNED_VAR, "1");

        match cmd.spawn() {
            Ok(_child) => return Ok(()),
            Err(e) => {
                // Log and try the next candidate.
                eprintln!("[rusthost] could not launch `{term}`: {e}");
            }
        }
    }

    // No terminal found.
    eprintln!("Please run this application from a terminal.");
    anyhow::bail!("no suitable terminal emulator found on PATH")
}

/// Construct the [`std::process::Command`] for the given terminal and argv.
///
/// Different terminal emulators use different conventions for specifying a
/// command to execute:
///
/// | Emulator              | Convention                          |
/// |-----------------------|-------------------------------------|
/// | `gnome-terminal`      | `gnome-terminal -- <cmd> [args]`    |
/// | everything else       | `<terminal> -e <cmd> [args]`        |
#[cfg(not(any(target_os = "windows", target_os = "macos")))]
fn build_terminal_command(term: &str, exec_argv: &[String]) -> std::process::Command {
    let mut cmd = std::process::Command::new(term);

    if term == "gnome-terminal" {
        // gnome-terminal uses `--` as the separator.
        cmd.arg("--");
    } else {
        // x-terminal-emulator, konsole, alacritty, xterm all accept `-e`.
        cmd.arg("-e");
    }

    if let Some((head, tail)) = exec_argv.split_first() {
        cmd.arg(head);
        cmd.args(tail);
    }

    cmd
}

/// Returns `Some(())` if `name` is found anywhere on `PATH`, otherwise `None`.
#[cfg(not(any(target_os = "windows", target_os = "macos")))]
fn which_on_path(name: &str) -> Option<()> {
    let path_var = env::var("PATH").unwrap_or_default();
    env::split_paths(&path_var)
        .map(|dir| dir.join(name))
        .find(|p| p.is_file())
        .map(|_| ())
}

// ─── Windows helpers ──────────────────────────────────────────────────────────

/// Produce a space-separated, double-quoted, cmd.exe–safe argument string.
///
/// Quotes each argument individually and escapes any embedded double-quotes by
/// doubling them — the conventional quoting rule for `cmd /C "…"` strings.
/// This is intentionally minimal: it is sufficient for paths and common flags
/// but is not a full shell-quoting library.
#[cfg(target_os = "windows")]
fn shell_escape_args(args: &[String]) -> String {
    args.iter()
        .map(|a| {
            // Double any embedded quotes, then wrap in outer quotes.
            let escaped = a.replace('"', "\"\"");
            format!("\"{escaped}\"")
        })
        .collect::<Vec<_>>()
        .join(" ")
}
