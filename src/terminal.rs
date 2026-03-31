//! # terminal – cross-platform auto-terminal launcher
//!
//! **File:** `terminal.rs`
//! **Location:** `src/terminal.rs`
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
//! | Windows  | Spawns this executable directly with `CREATE_NEW_CONSOLE`, forwarding all CLI args and injecting the sentinel env-var. No `cmd.exe` shell is involved, avoiding metacharacter escaping hazards. |
//! | macOS    | Uses `osascript` to open a new Terminal.app window executing the binary. |
//! | Linux    | Tries a priority-ordered list of terminal emulators and stops on the first success. |
//!
//! ### Linux terminal candidates (tried in order)
//! `x-terminal-emulator`, `gnome-terminal`, `konsole`, `alacritty`, `xterm`
//!
//! If none are found on Linux the user is asked to launch the binary from a
//! terminal manually.
//!
//! ## MSRV note
//!
//! TTY detection uses [`std::io::IsTerminal`], stable since Rust 1.70 (June
//! 2023). This project's MSRV is 1.90, so no additional crate is required.
//! The `atty` crate previously used here carries a known memory-safety
//! vulnerability on Windows (RUSTSEC-2021-0145) and has been removed.
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
use std::io::IsTerminal as _;
use std::path::PathBuf;
use std::process;

/// Sentinel environment variable used to prevent re-spawn loops.
const SPAWNED_VAR: &str = "RUSTHOST_SPAWNED";

/// Module-local boxed error type used by internal helper functions.
///
/// All errors ultimately surface as an `eprintln!` in [`maybe_relaunch`]; a
/// structured error type is not needed here.
type BoxError = Box<dyn std::error::Error + Send + Sync>;

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
    //
    // `std::io::IsTerminal` (stable since Rust 1.70) supersedes the
    // unmaintained `atty` crate, which carried a known memory-safety
    // vulnerability on Windows (RUSTSEC-2021-0145).
    if std::io::stdin().is_terminal() && std::io::stdout().is_terminal() {
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
fn spawn_in_terminal() -> Result<(), BoxError> {
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
fn current_exe() -> Result<PathBuf, BoxError> {
    env::current_exe()
        .map_err(|e| format!("could not determine the path to the current executable: {e}").into())
}

// ─── Windows ──────────────────────────────────────────────────────────────────

/// Spawn the current binary directly in a new console window.
///
/// We avoid using `cmd.exe /C "…"` to prevent the need to escape cmd.exe
/// metacharacters (`%`, `^`, `&`, `|`, `<`, `>`, `!`) in paths and arguments.
/// Rust's [`std::process::Command`] constructs the Windows command line
/// correctly via `CreateProcess`, so the sentinel env-var is injected through
/// the environment directly rather than as a shell `set` command.
#[cfg(target_os = "windows")]
fn spawn_windows(exe: &std::path::Path, cli_args: &[String]) -> Result<(), BoxError> {
    use std::os::windows::process::CommandExt as _;
    use std::process::Command;

    /// Open a new, visible console window for the child process.
    ///
    /// `CREATE_NEW_CONSOLE` (0x10) allocates a fresh console window.
    /// The previously used `DETACHED_PROCESS` (0x08) disconnects the child
    /// from *any* console including one `cmd.exe` might allocate itself,
    /// which is wrong for our intent: we want a visible interactive window.
    const CREATE_NEW_CONSOLE: u32 = 0x0000_0010;

    // The child is intentionally dropped without `wait()`. A brief zombie
    // entry exists until `process::exit(0)` (called immediately after this
    // function returns `Ok`) causes the OS to reap all children.
    Command::new(exe)
        .args(cli_args)
        .env(SPAWNED_VAR, "1")
        .creation_flags(CREATE_NEW_CONSOLE)
        .spawn()
        .map_err(|e| format!("failed to spawn new console window: {e}").into())?;

    Ok(())
}

// ─── macOS ───────────────────────────────────────────────────────────────────

/// Open a new Terminal.app window that re-executes this binary.
///
/// Uses `osascript` with an `AppleScript` `do script` command, which has been
/// stable since macOS 10.0 and is not subject to the behavioural changes in
/// `open -a Terminal --` across OS versions (the `open` approach broke
/// silently between macOS 12 and 13 for argument passing).
///
/// Each argument is POSIX single-quoted to prevent the shell inside Terminal
/// from interpreting metacharacters. Double-quotes within the resulting shell
/// command are escaped for `AppleScript` string embedding.
#[cfg(target_os = "macos")]
fn spawn_macos(exe: &std::path::Path, cli_args: &[String]) -> Result<(), BoxError> {
    use std::process::Command;

    // Build a shell command where every component is POSIX single-quoted.
    let shell_cmd: String = std::iter::once(exe.to_string_lossy().into_owned())
        .chain(cli_args.iter().cloned())
        .map(|s| posix_quote(&s))
        .collect::<Vec<_>>()
        .join(" ");

    // Escape for embedding inside an AppleScript double-quoted string:
    // backslashes first, then double-quotes, preserving correct nesting.
    let as_safe_cmd = shell_cmd.replace('\\', "\\\\").replace('"', "\\\"");

    // The `; exit` closes the Terminal window/tab after the program finishes.
    // Remove it if you prefer the window to remain open on exit.
    let script = format!(
        r#"tell application "Terminal" to do script "export {SPAWNED_VAR}=1; {as_safe_cmd}; exit""#
    );

    // The child (osascript process) is intentionally dropped without `wait()`.
    // A brief zombie exists until the parent calls `process::exit(0)`
    // immediately after this function returns `Ok(())`.
    Command::new("osascript")
        .args(["-e", &script])
        .spawn()
        .map_err(|e| -> BoxError { format!("failed to run `osascript`: {e}").into() })?;

    Ok(())
}

/// Wrap `s` in POSIX single-quotes, escaping any embedded single-quotes.
///
/// A single-quote inside a single-quoted string cannot be escaped by a
/// backslash; instead the quoting is terminated, a literal `\'` is inserted,
/// and quoting resumes: `'it'\''s'` → `it's`.
#[cfg(target_os = "macos")]
fn posix_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

// ─── Linux / other Unix ───────────────────────────────────────────────────────

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
fn spawn_linux(exe: &std::path::Path, cli_args: &[String]) -> Result<(), BoxError> {
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
        // Verify the emulator is on PATH *and* has the executable bit set
        // before attempting to spawn, so a non-executable file does not
        // produce a confusing permission error instead of a clean skip.
        if !is_on_path(term) {
            continue;
        }

        let mut cmd = build_terminal_command(term, &exec_argv);
        cmd.env(SPAWNED_VAR, "1");

        match cmd.spawn() {
            // The child (terminal process) is intentionally dropped without
            // calling `wait()`. A brief zombie entry exists until the parent
            // calls `process::exit(0)` immediately after this function returns
            // `Ok(())`, at which point the OS reaps all children.
            Ok(_child) => return Ok(()),
            Err(e) => {
                eprintln!("[rusthost] could not launch `{term}`: {e}");
            }
        }
    }

    eprintln!("Please run this application from a terminal.");
    Err("no suitable terminal emulator found on PATH".into())
}

/// Construct the [`std::process::Command`] for the given terminal and argv.
///
/// | Emulator         | Convention                       |
/// |------------------|----------------------------------|
/// | `gnome-terminal` | `gnome-terminal -- <cmd> [args]` |
/// | everything else  | `<terminal> -e <cmd> [args]`     |
#[cfg(not(any(target_os = "windows", target_os = "macos")))]
fn build_terminal_command(term: &str, exec_argv: &[String]) -> process::Command {
    let mut cmd = process::Command::new(term);

    if term == "gnome-terminal" {
        cmd.arg("--");
    } else {
        cmd.arg("-e");
    }

    if let Some((head, tail)) = exec_argv.split_first() {
        cmd.arg(head);
        cmd.args(tail);
    }

    cmd
}

/// Returns `true` if `name` is found on `PATH` and has the executable bit set.
///
/// Checking the executable permission prevents a silent spawn failure when a
/// non-executable file with the right name exists on PATH (e.g. a broken
/// `x-terminal-emulator` symlink or a script missing `chmod +x`).
#[cfg(not(any(target_os = "windows", target_os = "macos")))]
fn is_on_path(name: &str) -> bool {
    use std::os::unix::fs::PermissionsExt as _;

    let path_var = env::var_os("PATH").unwrap_or_default();
    env::split_paths(&path_var)
        .map(|dir| dir.join(name))
        .any(|p| {
            p.metadata()
                .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
                .unwrap_or(false)
        })
}
