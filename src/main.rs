//! # rusthost-cli
//!
//! Binary entry point. Parses CLI arguments then delegates all startup logic
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

#![deny(clippy::all, clippy::pedantic)]
#![warn(clippy::nursery)]

use std::io::Write as _;
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
/// initialized. [`std::sync::Once`] is thread-safe and guarantees
/// exactly-one execution.
///
/// Any panic inside `cleanup()` is caught and written to stderr so that a
/// failing cleanup never triggers a double-panic abort when called from the
/// panic hook.
///
/// # Note on `AssertUnwindSafe`
///
/// `rusthost::console::cleanup()` is assumed to be unwind-safe: it must not
/// leave shared state inconsistent if it panics. If that assumption ever
/// changes, this wrapper must be revisited.
fn safe_cleanup() {
    static CLEANUP: Once = Once::new();
    CLEANUP.call_once(|| {
        if let Err(payload) = std::panic::catch_unwind(AssertUnwindSafe(|| {
            rusthost::console::cleanup();
        })) {
            let msg = payload
                .downcast_ref::<&str>()
                .copied()
                .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
                .unwrap_or("<non-string panic payload>");
            // Use `writeln!` on a raw stderr handle to reduce the risk of a
            // secondary panic from the formatting machinery in `eprintln!`.
            let _ = writeln!(std::io::stderr(), "\nconsole cleanup panicked: {msg}");
        }
    });
}

// ─── Argument-parsing errors ──────────────────────────────────────────────────

/// Structured errors produced during CLI argument parsing.
///
/// All variants carry a human-readable message displayed to the user prefixed
/// with `"error: "`. The exit code for all argument errors is `2` (POSIX
/// convention for command-line syntax errors). Callers that need to distinguish
/// specific failure modes should inspect the message text rather than the exit
/// code, as the single unified code is intentional.
#[derive(Debug)]
enum ArgError {
    /// A required argument value for a flag was missing.
    MissingValue(String),
    /// A flag that accepts no value received one via `--flag=value`.
    UnexpectedValue(String),
    /// A flag was specified more than once.
    Duplicate(String),
    /// A flag's value could not be parsed or is out of the valid range.
    InvalidValue(String),
    /// An unrecognised flag was encountered.
    Unrecognised(String),
    /// A flag was used in a context where it has no meaning.
    Inapplicable(String),
    /// A path argument does not exist or is not the expected kind.
    BadPath(String),
}

impl std::fmt::Display for ArgError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg = match self {
            Self::MissingValue(m)
            | Self::UnexpectedValue(m)
            | Self::Duplicate(m)
            | Self::InvalidValue(m)
            | Self::Unrecognised(m)
            | Self::Inapplicable(m)
            | Self::BadPath(m) => m,
        };
        write!(f, "error: {msg}")
    }
}

impl std::error::Error for ArgError {}

// ─── CLI helpers ──────────────────────────────────────────────────────────────

/// Consume the next value from the iterator.
///
/// # Errors
///
/// Returns [`ArgError::MissingValue`] if the iterator is exhausted.
#[must_use = "a missing argument is a fatal error; the Result must be checked"]
fn next_value(args: &mut impl Iterator<Item = String>, flag: &str) -> Result<String, ArgError> {
    args.next()
        .ok_or_else(|| ArgError::MissingValue(format!("{flag} requires an argument")))
}

/// Resolve a flag's value from the inline `--flag=value` form, or by
/// consuming the next positional argument.
///
/// # Errors
///
/// Propagates any error from [`next_value`] when the inline form is absent.
#[must_use = "the resolved value must be used"]
fn resolve_value(
    inline: Option<String>,
    args: &mut impl Iterator<Item = String>,
    flag: &str,
) -> Result<String, ArgError> {
    inline.map_or_else(|| next_value(args, flag), Ok)
}

/// Return an error if the flag has already been seen.
///
/// `seen` should reflect the current recorded state — typically
/// `some_option.is_some()` or a `bool` tracking whether the flag appeared.
///
/// # Errors
///
/// Returns [`ArgError::Duplicate`] when `seen` is `true`.
fn check_duplicate(seen: bool, flag: &str) -> Result<(), ArgError> {
    if seen {
        return Err(ArgError::Duplicate(format!(
            "{flag} specified more than once"
        )));
    }
    Ok(())
}

/// Return an error if an inline value was supplied for a no-argument flag.
///
/// # Errors
///
/// Returns [`ArgError::UnexpectedValue`] when `inline` is `Some`.
fn reject_inline_value(inline: Option<&str>, flag: &str) -> Result<(), ArgError> {
    if inline.is_some() {
        return Err(ArgError::UnexpectedValue(format!(
            "{flag} does not accept a value"
        )));
    }
    Ok(())
}

/// Parse and validate a raw port-number string.
///
/// # Errors
///
/// Returns [`ArgError::InvalidValue`] for non-numeric input or a value outside
/// the valid port range (1–65 535). Port `0` is explicitly rejected because it
/// requests an OS-assigned ephemeral port, which is not a useful target here.
fn parse_port(raw: &str) -> Result<u16, ArgError> {
    // `u16` already rejects values > 65 535; the explicit zero-check below
    // handles port 0, which would otherwise parse successfully.
    let port = raw.parse::<u16>().map_err(|_| {
        ArgError::InvalidValue("--port value must be a valid port number (1–65535)".to_owned())
    })?;
    if port == 0 {
        return Err(ArgError::InvalidValue(
            "--port value must be a valid port number (1–65535)".to_owned(),
        ));
    }
    Ok(port)
}

/// Return an error if `--port` or `--no-tor` were given without `--serve`.
///
/// # Errors
///
/// Returns [`ArgError::Inapplicable`] when either flag is set but
/// `has_serve` is `false`.
fn validate_serve_flags(
    has_serve: bool,
    explicit_port: bool,
    no_tor: bool,
) -> Result<(), ArgError> {
    if has_serve {
        return Ok(());
    }
    if explicit_port {
        return Err(ArgError::Inapplicable(
            "--port has no effect without --serve\n       \
             Example: rusthost-cli --serve ./docs --port 3000"
                .to_owned(),
        ));
    }
    if no_tor {
        return Err(ArgError::Inapplicable(
            "--no-tor has no effect without --serve\n       \
             Example: rusthost-cli --serve ./docs --no-tor"
                .to_owned(),
        ));
    }
    Ok(())
}

// ─── CLI argument parsing ─────────────────────────────────────────────────────

/// Parse an iterator of raw argument strings into a [`CliArgs`] value.
///
/// Both `--flag value` and `--flag=value` forms are accepted. Use `--` to
/// signal the end of options; any tokens after `--` are currently unused and
/// trigger a warning rather than being silently discarded.
///
/// # Errors
///
/// Returns an [`ArgError`] for unrecognised flags, missing values, duplicate
/// flags, invalid values, or unsupported flag combinations.
#[allow(clippy::too_many_lines)]
fn parse_args_from(mut args: impl Iterator<Item = String>) -> Result<CliArgs, ArgError> {
    let mut config_path: Option<PathBuf> = None;
    let mut data_dir: Option<PathBuf> = None;
    let mut serve_dir: Option<PathBuf> = None;
    let mut serve_port: u16 = 8080;
    let mut no_tor = false;
    let mut headless = false;
    let mut explicit_port = false;

    while let Some(raw_flag) = args.next() {
        if raw_flag == "--" {
            // Warn rather than silently discard tokens after `--`: dropping
            // them without feedback is a confusing footgun for users who
            // expect positional arguments to be honoured.
            let extras: Vec<String> = args.collect();
            if !extras.is_empty() {
                eprintln!(
                    "warning: positional arguments after '--' are not yet \
                     supported and will be ignored: {}",
                    extras.join(", ")
                );
            }
            break;
        }

        let (flag, inline_value) = match raw_flag.split_once('=') {
            Some((f, v)) => (f.to_owned(), Some(v.to_owned())),
            None => (raw_flag, None),
        };

        match flag.as_str() {
            "--version" | "-V" => {
                reject_inline_value(inline_value.as_deref(), &flag)?;
                println!("rusthost {VERSION}");
                std::process::exit(0);
            }
            "--help" | "-h" => {
                reject_inline_value(inline_value.as_deref(), &flag)?;
                print_help();
                std::process::exit(0);
            }
            "--config" => {
                check_duplicate(config_path.is_some(), "--config")?;
                config_path = Some(PathBuf::from(resolve_value(
                    inline_value,
                    &mut args,
                    "--config",
                )?));
            }
            "--data-dir" => {
                check_duplicate(data_dir.is_some(), "--data-dir")?;
                data_dir = Some(PathBuf::from(resolve_value(
                    inline_value,
                    &mut args,
                    "--data-dir",
                )?));
            }
            "--serve" => {
                check_duplicate(serve_dir.is_some(), "--serve")?;
                let dir = PathBuf::from(resolve_value(inline_value, &mut args, "--serve")?);
                // NOTE: This is a best-effort early check only. A TOCTOU race
                // exists between this validation and when `lifecycle::run`
                // actually opens the directory. The authoritative check must
                // occur at the point of use.
                if !dir.is_dir() {
                    return Err(ArgError::BadPath(format!(
                        "--serve path '{}' is not an existing directory",
                        dir.display()
                    )));
                }
                serve_dir = Some(dir);
            }
            "--port" => {
                check_duplicate(explicit_port, "--port")?;
                explicit_port = true;
                serve_port = parse_port(&resolve_value(inline_value, &mut args, "--port")?)?;
            }
            "--no-tor" => {
                reject_inline_value(inline_value.as_deref(), "--no-tor")?;
                check_duplicate(no_tor, "--no-tor")?;
                no_tor = true;
            }
            "--headless" => {
                reject_inline_value(inline_value.as_deref(), "--headless")?;
                check_duplicate(headless, "--headless")?;
                headless = true;
            }
            other => {
                return Err(ArgError::Unrecognised(format!(
                    "unrecognised argument '{other}'\n       \
                     Run with --help for usage information."
                )));
            }
        }
    }

    validate_serve_flags(serve_dir.is_some(), explicit_port, no_tor)?;

    Ok(CliArgs {
        config_path,
        data_dir,
        serve_dir,
        serve_port,
        no_tor,
        headless,
    })
}

/// Parse `std::env::args()` into a [`CliArgs`] value, exiting the process on
/// any error.
///
/// Thin wrapper around [`parse_args_from`] that sources from the real process
/// argument list. Argument errors produce a message on stderr followed by
/// `exit(2)`.
#[must_use]
fn parse_args() -> CliArgs {
    parse_args_from(std::env::args().skip(1)).unwrap_or_else(|err| {
        eprintln!("{err}");
        std::process::exit(2);
    })
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

    // Register a panic hook so the terminal is always restored even when a
    // panic fires on an executor thread. `safe_cleanup` uses `Once` and is
    // therefore thread-safe and idempotent.
    std::panic::set_hook(Box::new(|info| {
        safe_cleanup();

        // Use `writeln!` on a raw stderr handle rather than `eprintln!` to
        // reduce the risk of a secondary panic from the formatting machinery
        // when stderr is in a broken state (e.g. a closed pipe).
        //
        // The version is embedded so that panic reports are unambiguously
        // tied to a specific release without needing additional context.
        let _ = writeln!(std::io::stderr(), "\nPanic (rusthost {VERSION}): {info}");

        let bt = std::backtrace::Backtrace::capture();
        if bt.status() == std::backtrace::BacktraceStatus::Captured {
            let _ = writeln!(std::io::stderr(), "\nstack backtrace:\n{bt}");
        } else {
            // Mirror the hint from the default panic hook so users know how
            // to obtain a backtrace; without this it is silently absent.
            let _ = writeln!(
                std::io::stderr(),
                "\nnote: run with RUST_BACKTRACE=1 environment variable to \
                 display a backtrace"
            );
        }
    }));

    // Name the worker threads so they appear meaningfully in profilers,
    // debuggers, and crash reports rather than as generic "tokio-runtime-worker".
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("rusthost-worker")
        .build()
    {
        Ok(rt) => rt,
        Err(err) => {
            eprintln!("Fatal error: failed to create Tokio runtime: {err}");
            std::process::exit(1);
        }
    };

    rt.block_on(async {
        if let Err(err) = rusthost::runtime::lifecycle::run(args).await {
            // `safe_cleanup` is idempotent — it is a no-op if the panic hook
            // already ran it. When `run` returns `Err` without panicking, this
            // call is the only cleanup path.
            //
            // NOTE: A teardown race is inherent here: if the process receives
            // a signal between `block_on` returning and `safe_cleanup`
            // finishing, the terminal may not be fully restored. Eliminating
            // this race would require signal-handler integration beyond the
            // scope of this binary.
            safe_cleanup();
            eprintln!("\nFatal error: {err}");
            std::process::exit(1);
        }
    });
}
