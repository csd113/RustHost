//! # rusthost-cli
//!
//! Binary entry point.  Parses CLI arguments then delegates all startup logic
//! to [`rusthost::runtime::lifecycle::run`].
//!
//! ## Flags
//!
//! ```text
//! --config   <path>   Override the path to settings.toml
//! --data-dir <path>   Override the data-directory root
//! --serve    <dir>    Serve a directory directly, no first-run setup needed
//! --port     <n>      Port to use with --serve (default: 8080)
//! --no-tor            Disable Tor when using --serve
//! --headless          Disable the interactive console (CI / scripted use)
//! -V, --version       Print the crate version and exit
//! -h, --help          Print usage and exit
//! ```

use std::panic::AssertUnwindSafe;
use std::path::PathBuf;
use std::sync::Once;

use rusthost::runtime::lifecycle::CliArgs;

/// Crate version, sourced once from `Cargo.toml` at compile time.
const VERSION: &str = env!("CARGO_PKG_VERSION");

// ─── Safe cleanup wrapper ─────────────────────────────────────────────────────

/// Ensure `console::cleanup()` runs at most once, regardless of which thread
/// calls it.
///
/// Guards against double-cleanup (panic hook + error branch), calls from
/// arbitrary Tokio worker threads, and calls before the console was ever
/// initialized.  `std::sync::Once` is thread-safe and guarantees
/// exactly-one execution.
///
/// Any panic inside `cleanup()` is caught so that a failing cleanup never
/// triggers a double-panic abort when called from the panic hook.
fn safe_cleanup() {
    static CLEANUP: Once = Once::new();
    CLEANUP.call_once(|| {
        let _ = std::panic::catch_unwind(AssertUnwindSafe(|| {
            rusthost::console::cleanup();
        }));
    });
}

// ─── CLI helpers ──────────────────────────────────────────────────────────────

/// Consume the next value from the iterator or exit with a missing-argument
/// error for the given `flag`.
fn next_value(args: &mut impl Iterator<Item = String>, flag: &str) -> String {
    args.next().unwrap_or_else(|| {
        eprintln!("error: {flag} requires an argument");
        std::process::exit(2);
    })
}

/// Resolve a flag's value: use the inline `--flag=value` form if present,
/// otherwise consume the next positional argument.
fn resolve_value(
    inline: Option<String>,
    args: &mut impl Iterator<Item = String>,
    flag: &str,
) -> String {
    inline.unwrap_or_else(|| next_value(args, flag))
}

/// Exit with an error if the flag has already been seen.
fn check_duplicate(seen: bool, flag: &str) {
    if seen {
        eprintln!("error: {flag} specified more than once");
        std::process::exit(2);
    }
}

/// Reject an inline value (`--flag=value`) for flags that take no argument.
fn reject_inline_value(inline: Option<&str>, flag: &str) {
    if inline.is_some() {
        eprintln!("error: {flag} does not accept a value");
        std::process::exit(2);
    }
}

/// Parse and validate a port number string.  Exits on non-numeric input or
/// a value outside the 1–65 535 range.
fn parse_port(raw: &str) -> u16 {
    let port = raw.parse::<u16>().unwrap_or_else(|_| {
        eprintln!("error: --port value must be a valid port number (1–65535)");
        std::process::exit(2);
    });
    if port == 0 {
        eprintln!("error: --port value must be a valid port number (1–65535)");
        std::process::exit(2);
    }
    port
}

/// Reject `--port` and `--no-tor` when `--serve` was not provided.
fn validate_serve_flags(has_serve: bool, explicit_port: bool, no_tor: bool) {
    if has_serve {
        return;
    }
    if explicit_port {
        eprintln!(
            "error: --port has no effect without --serve\n\
             \x20      Example: rusthost-cli --serve ./docs --port 3000"
        );
        std::process::exit(2);
    }
    if no_tor {
        eprintln!(
            "error: --no-tor has no effect without --serve\n\
             \x20      Example: rusthost-cli --serve ./docs --no-tor"
        );
        std::process::exit(2);
    }
}

// ─── CLI argument parsing ─────────────────────────────────────────────────────

/// Parse `std::env::args()` into a [`CliArgs`] value.
///
/// Exits the process immediately for `--version`, `--help`, unrecognised flags,
/// and invalid flag combinations so that the async runtime is never started
/// unnecessarily.
///
/// Both `--flag value` and `--flag=value` forms are accepted.  Use `--` to
/// signal the end of options.
fn parse_args() -> CliArgs {
    let mut config_path: Option<PathBuf> = None;
    let mut data_dir: Option<PathBuf> = None;
    let mut serve_dir: Option<PathBuf> = None;
    let mut serve_port: u16 = 8080;
    let mut no_tor = false;
    let mut headless = false;
    let mut explicit_port = false;

    let mut args = std::env::args().skip(1);

    while let Some(raw_flag) = args.next() {
        // `--` ends option parsing; remaining tokens are positional
        // (currently unused but reserved for forward compatibility).
        if raw_flag == "--" {
            break;
        }

        // Support both `--flag value` and `--flag=value` forms.
        let (flag, inline_value) = match raw_flag.split_once('=') {
            Some((f, v)) => (f.to_string(), Some(v.to_string())),
            None => (raw_flag, None),
        };

        match flag.as_str() {
            "--version" | "-V" => {
                reject_inline_value(inline_value.as_deref(), &flag);
                println!("rusthost {VERSION}");
                std::process::exit(0);
            }
            "--help" | "-h" => {
                reject_inline_value(inline_value.as_deref(), &flag);
                print_help();
                std::process::exit(0);
            }
            "--config" => {
                check_duplicate(config_path.is_some(), "--config");
                config_path = Some(PathBuf::from(resolve_value(
                    inline_value,
                    &mut args,
                    "--config",
                )));
            }
            "--data-dir" => {
                check_duplicate(data_dir.is_some(), "--data-dir");
                data_dir = Some(PathBuf::from(resolve_value(
                    inline_value,
                    &mut args,
                    "--data-dir",
                )));
            }
            "--serve" => {
                check_duplicate(serve_dir.is_some(), "--serve");
                let dir = PathBuf::from(resolve_value(inline_value, &mut args, "--serve"));
                if !dir.is_dir() {
                    eprintln!(
                        "error: --serve path '{}' is not an existing directory",
                        dir.display()
                    );
                    std::process::exit(2);
                }
                serve_dir = Some(dir);
            }
            "--port" => {
                check_duplicate(explicit_port, "--port");
                explicit_port = true;
                serve_port = parse_port(&resolve_value(inline_value, &mut args, "--port"));
            }
            "--no-tor" => {
                reject_inline_value(inline_value.as_deref(), "--no-tor");
                check_duplicate(no_tor, "--no-tor");
                no_tor = true;
            }
            "--headless" => {
                reject_inline_value(inline_value.as_deref(), "--headless");
                check_duplicate(headless, "--headless");
                headless = true;
            }
            other => {
                eprintln!(
                    "error: unrecognised argument '{other}'\n\
                     \x20      Run with --help for usage information."
                );
                std::process::exit(2);
            }
        }
    }

    validate_serve_flags(serve_dir.is_some(), explicit_port, no_tor);

    CliArgs {
        config_path,
        data_dir,
        serve_dir,
        serve_port,
        no_tor,
        headless,
    }
}

fn print_help() {
    println!(
        "rusthost {ver}
{desc}

USAGE:
    rusthost-cli [OPTIONS]

OPTIONS:
    --config   <path>   Override the path to settings.toml
                        (default: <exe-dir>/rusthost-data/settings.toml)
    --data-dir <path>   Override the data-directory root
                        (default: <exe-dir>/rusthost-data/)
    --serve    <dir>    Serve a directory directly — no first-run setup needed
                        Example: rusthost-cli --serve ./docs --port 3000 --no-tor
    --port     <n>      Port for --serve mode (default: 8080)
    --no-tor            Disable Tor in --serve mode
    --headless          Disable the interactive console (applies to all modes;
                        useful for CI / scripted use)
    -V, --version       Print version and exit
    -h, --help          Print this message and exit

Both --flag value and --flag=value forms are accepted.
Use -- to signal the end of options.",
        ver = VERSION,
        desc = env!("CARGO_PKG_DESCRIPTION"),
    );
}

// ─── Entry point ─────────────────────────────────────────────────────────────

fn main() {
    // Parse arguments before starting the async runtime so that --help and
    // --version never pay the runtime-construction cost.
    let args = parse_args();

    // Register a panic hook so the terminal is always restored, even when a
    // panic fires on an async executor thread.  `safe_cleanup()` uses
    // `std::sync::Once` so it is thread-safe and idempotent.
    std::panic::set_hook(Box::new(|info| {
        safe_cleanup();
        eprintln!("\nPanic: {info}");

        // Preserve backtrace support — the default hook respects
        // RUST_BACKTRACE=1.  Without this, panic diagnostics lose all
        // location information.
        let bt = std::backtrace::Backtrace::capture();
        if bt.status() == std::backtrace::BacktraceStatus::Captured {
            eprintln!("\nstack backtrace:\n{bt}");
        }
    }));

    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(err) => {
            eprintln!("Fatal error: failed to create Tokio runtime: {err}");
            std::process::exit(1);
        }
    };

    rt.block_on(async {
        if let Err(err) = rusthost::runtime::lifecycle::run(args).await {
            // Best-effort terminal restore.  `safe_cleanup()` is a no-op if
            // the panic hook already ran it, or if the console was never started.
            safe_cleanup();
            eprintln!("\nFatal error: {err}");
            std::process::exit(1);
        }
    });
}
