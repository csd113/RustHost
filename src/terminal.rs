//! # terminal – cross-platform auto-terminal launcher
//! Detects whether the process was launched for an interactive, detached
//! session (for example by double-clicking the binary in a file manager). In
//! that narrow case, the process relaunches itself inside an appropriate
//! terminal emulator and exits, so the user sees interactive output.
//!
//! ## Loop-prevention
//!
//! The env-var `RUSTHOST_SPAWNED=1` is injected into the child environment
//! before the relaunch. On entry, [`maybe_relaunch`] checks for that var and
//! skips respawning if it is set, preventing an infinite spawn loop.
//!
//! ## Relaunch policy
//!
//! Relaunch is intentionally suppressed for:
//! - `--headless`
//! - `--help`
//! - `--version`
//! - invalid CLI arguments
//! - service / supervisor style runs where stdio is redirected to a pipe, file,
//!   or socket rather than detached to `/dev/null`
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
use std::io::Write as _;
use std::path::PathBuf;
#[cfg(unix)]
use std::sync::OnceLock;

/// Sentinel environment variable used to prevent re-spawn loops.
const SPAWNED_VAR: &str = "RUSTHOST_SPAWNED";

/// Module-local boxed error type used by internal helper functions.
///
/// All errors ultimately surface as an `eprintln!` in [`maybe_relaunch`]; a
/// structured error type is not needed here.
type BoxError = Box<dyn std::error::Error + Send + Sync>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelaunchIntent {
    Interactive,
    Headless,
    Help,
    Version,
    InvalidArguments,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StdioKind {
    Terminal,
    NullDevice,
    Redirected,
    Other,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct StdioSummary {
    stdin: StdioKind,
    stdout: StdioKind,
    stderr: StdioKind,
}

impl StdioSummary {
    const fn all_null_devices(self) -> bool {
        matches!(
            self,
            Self {
                stdin: StdioKind::NullDevice,
                stdout: StdioKind::NullDevice,
                stderr: StdioKind::NullDevice,
            }
        )
    }

    const fn has_terminal(self) -> bool {
        matches!(self.stdin, StdioKind::Terminal)
            || matches!(self.stdout, StdioKind::Terminal)
            || matches!(self.stderr, StdioKind::Terminal)
    }

    const fn has_redirected_stream(self) -> bool {
        matches!(self.stdin, StdioKind::Redirected)
            || matches!(self.stdout, StdioKind::Redirected)
            || matches!(self.stderr, StdioKind::Redirected)
    }
}

// ─── Public entry point ───────────────────────────────────────────────────────

/// Check whether a relaunch is necessary and, if so, perform it.
///
/// The function is a no-op when:
/// - the invocation intent is not interactive,
/// - the process is already attached to a TTY,
/// - stdio is redirected like a service / supervisor run, **or**
/// - `RUSTHOST_SPAWNED=1` is already set in the environment.
///
/// If a relaunch is needed but fails, a short message is printed to stderr and
/// the process continues (it may produce garbled output but does not crash).
///
/// Returns `true` when the current process should stop immediately because a
/// child terminal process was spawned successfully.
#[must_use]
pub fn maybe_relaunch(intent: RelaunchIntent) -> bool {
    if !should_relaunch(
        intent,
        env::var(SPAWNED_VAR).is_ok(),
        detect_stdio_summary(),
    ) {
        return false;
    }

    match spawn_in_terminal() {
        Ok(()) => true,
        Err(e) => {
            let _ = writeln!(
                std::io::stderr(),
                "[rusthost] terminal relaunch failed: {e}"
            );
            // Fall through and run headlessly – better than a silent crash.
            false
        }
    }
}

const fn should_relaunch(intent: RelaunchIntent, spawned: bool, stdio: StdioSummary) -> bool {
    if spawned || !matches!(intent, RelaunchIntent::Interactive) {
        return false;
    }
    if stdio.has_terminal() || stdio.has_redirected_stream() {
        return false;
    }
    stdio.all_null_devices()
}

fn detect_stdio_summary() -> StdioSummary {
    StdioSummary {
        stdin: classify_stdio(0, std::io::stdin().is_terminal()),
        stdout: classify_stdio(1, std::io::stdout().is_terminal()),
        stderr: classify_stdio(2, std::io::stderr().is_terminal()),
    }
}

#[cfg(unix)]
fn classify_stdio(fd: std::os::fd::RawFd, is_terminal: bool) -> StdioKind {
    use std::os::unix::fs::FileTypeExt as _;

    if is_terminal {
        return StdioKind::Terminal;
    }

    let Ok(metadata) = std::fs::metadata(format!("/dev/fd/{fd}")) else {
        return StdioKind::Other;
    };

    if is_dev_null(&metadata) {
        return StdioKind::NullDevice;
    }

    let file_type = metadata.file_type();
    if file_type.is_file() || file_type.is_fifo() || file_type.is_socket() {
        StdioKind::Redirected
    } else {
        StdioKind::Other
    }
}

#[cfg(unix)]
fn is_dev_null(metadata: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;

    static DEV_NULL: OnceLock<Option<(u64, u64)>> = OnceLock::new();

    DEV_NULL
        .get_or_init(|| {
            std::fs::metadata("/dev/null")
                .ok()
                .map(|meta| (meta.dev(), meta.ino()))
        })
        .is_some_and(|(dev, ino)| metadata.dev() == dev && metadata.ino() == ino)
}

#[cfg(not(unix))]
fn classify_stdio(_fd: i32, is_terminal: bool) -> StdioKind {
    if is_terminal {
        StdioKind::Terminal
    } else {
        StdioKind::Other
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
        .map_err(|e| -> BoxError { format!("failed to spawn new console window: {e}").into() })?;

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
                let _ = writeln!(
                    std::io::stderr(),
                    "[rusthost] could not launch `{term}`: {e}"
                );
            }
        }
    }

    let _ = writeln!(
        std::io::stderr(),
        "Please run this application from a terminal."
    );
    Err("no suitable terminal emulator found on PATH".into())
}

/// Construct the [`std::process::Command`] for the given terminal and argv.
///
/// | Emulator         | Convention                       |
/// |------------------|----------------------------------|
/// | `gnome-terminal` | `gnome-terminal -- <cmd> [args]` |
/// | everything else  | `<terminal> -e <cmd> [args]`     |
#[cfg(not(any(target_os = "windows", target_os = "macos")))]
fn build_terminal_command(term: &str, exec_argv: &[String]) -> std::process::Command {
    let mut cmd = std::process::Command::new(term);

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
                .is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        })
}

#[cfg(test)]
mod tests {
    use super::{should_relaunch, RelaunchIntent, StdioKind, StdioSummary};

    const NULL_STDIO: StdioSummary = StdioSummary {
        stdin: StdioKind::NullDevice,
        stdout: StdioKind::NullDevice,
        stderr: StdioKind::NullDevice,
    };

    const REDIRECTED_STDIO: StdioSummary = StdioSummary {
        stdin: StdioKind::Redirected,
        stdout: StdioKind::Redirected,
        stderr: StdioKind::Redirected,
    };

    #[test]
    fn headless_invocation_never_relaunches() {
        assert!(!should_relaunch(
            RelaunchIntent::Headless,
            false,
            NULL_STDIO
        ));
    }

    #[test]
    fn help_invocation_never_relaunches() {
        assert!(!should_relaunch(RelaunchIntent::Help, false, NULL_STDIO));
    }

    #[test]
    fn version_invocation_never_relaunches() {
        assert!(!should_relaunch(RelaunchIntent::Version, false, NULL_STDIO));
    }

    #[test]
    fn invalid_arguments_never_relaunch() {
        assert!(!should_relaunch(
            RelaunchIntent::InvalidArguments,
            false,
            NULL_STDIO
        ));
    }

    #[test]
    fn spawned_process_never_relaunches() {
        assert!(!should_relaunch(
            RelaunchIntent::Interactive,
            true,
            NULL_STDIO
        ));
    }

    #[test]
    fn redirected_stdio_is_treated_as_service_style() {
        assert!(!should_relaunch(
            RelaunchIntent::Interactive,
            false,
            REDIRECTED_STDIO
        ));
    }

    #[test]
    fn detached_interactive_stdio_requests_relaunch() {
        assert!(should_relaunch(
            RelaunchIntent::Interactive,
            false,
            NULL_STDIO
        ));
    }
}
