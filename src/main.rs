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
//! --version           Print the crate version and exit
//! --help              Print usage and exit
//! ```

use std::path::PathBuf;

use rusthost::runtime::lifecycle::CliArgs;

// ─── CLI argument parsing ─────────────────────────────────────────────────────

/// Parse `std::env::args()` into a [`CliArgs`] value.
///
/// Exits the process immediately for `--version`, `--help`, and unrecognised
/// flags so that the async runtime is never started unnecessarily.
fn parse_args() -> CliArgs {
    let mut config_path: Option<PathBuf> = None;
    let mut data_dir: Option<PathBuf> = None;
    let mut serve_dir: Option<PathBuf> = None;
    let mut serve_port: u16 = 8080;
    let mut no_tor = false;
    let mut headless = false;
    let mut args = std::env::args().skip(1);

    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--version" | "-V" => {
                println!("rusthost {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            "--help" | "-h" => {
                print_help();
                std::process::exit(0);
            }
            "--config" => {
                config_path = Some(PathBuf::from(args.next().unwrap_or_else(|| {
                    eprintln!("error: --config requires a <path> argument");
                    std::process::exit(1);
                })));
            }
            "--data-dir" => {
                data_dir = Some(PathBuf::from(args.next().unwrap_or_else(|| {
                    eprintln!("error: --data-dir requires a <path> argument");
                    std::process::exit(1);
                })));
            }
            "--serve" => {
                serve_dir = Some(PathBuf::from(args.next().unwrap_or_else(|| {
                    eprintln!("error: --serve requires a <dir> argument");
                    std::process::exit(1);
                })));
            }
            "--port" => {
                let raw = args.next().unwrap_or_else(|| {
                    eprintln!("error: --port requires a <n> argument");
                    std::process::exit(1);
                });
                serve_port = raw.parse::<u16>().unwrap_or_else(|_| {
                    eprintln!("error: --port value must be a valid port number (1–65535)");
                    std::process::exit(1);
                });
            }
            "--no-tor" => {
                no_tor = true;
            }
            "--headless" => {
                headless = true;
            }
            unknown => {
                eprintln!("error: unrecognised argument '{unknown}'");
                eprintln!("       Run with --help for usage information.");
                std::process::exit(1);
            }
        }
    }

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
    --headless          Disable the interactive console (useful for CI / scripted use)
    --version           Print version and exit
    --help              Print this message and exit",
        ver = env!("CARGO_PKG_VERSION"),
        desc = env!("CARGO_PKG_DESCRIPTION"),
    );
}

// ─── Entry point ─────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    // Register a panic hook so the terminal is always restored, even when a
    // panic fires on an async executor thread.
    std::panic::set_hook(Box::new(|info| {
        rusthost::console::cleanup();
        eprintln!("\nPanic: {info}");
    }));

    let args = parse_args();

    if let Err(err) = rusthost::runtime::lifecycle::run(args).await {
        // Best-effort terminal restore in case we crashed inside the console.
        rusthost::console::cleanup();
        eprintln!("\nFatal error: {err}");
        std::process::exit(1);
    }
}
