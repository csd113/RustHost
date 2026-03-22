//! # Logging Module
//!
//! **Directory:** `src/logging/`
//!
//! Implements the [`log::Log`] trait so that standard `log::info!()`,
//! `log::warn!()` etc. macros work everywhere without importing a concrete
//! logger.
//!
//! Each log record is:
//! 1. Written to the log file (if `logging.enabled = true`).
//! 2. Pushed into the global in-memory ring buffer so the console
//!    log view can display recent entries without reading the file.
//!
//! The logger is registered exactly once via [`init`], using `Box::leak`
//! to produce the `'static` reference required by `log::set_logger`.

use std::{
    collections::VecDeque,
    fs::{File, OpenOptions},
    io::Write,
    path::Path,
    sync::{Mutex, OnceLock},
};

use chrono::Local;
use log::{Level, LevelFilter, Log, Metadata, Record};

use crate::{config::LoggingConfig, AppError, Result};

// ─── Global ring buffer ──────────────────────────────────────────────────────

/// Global in-memory ring buffer shared between the logger and the console
/// log view. Holds at most 1 000 formatted lines.
static LOG_BUFFER: OnceLock<Mutex<VecDeque<String>>> = OnceLock::new();

/// Read a snapshot of the most recent `limit` log lines.
///
/// Called by the console log view on each render tick.
pub fn recent_lines(limit: usize) -> Vec<String> {
    if let Some(buf) = LOG_BUFFER.get() {
        if let Ok(guard) = buf.lock() {
            let start = guard.len().saturating_sub(limit);
            return guard.range(start..).cloned().collect();
        }
    }
    Vec::new()
}

// ─── Logger ──────────────────────────────────────────────────────────────────

/// Maximum log file size before rotation (100 MB).
///
/// fix G-2 — without a size cap the log file grows unboundedly.  At INFO level
/// with modest traffic this reaches ~2.5 GB/year; DEBUG with Arti noise is
/// orders of magnitude larger.  A full disk silently corrupts Arti's circuit
/// database and prevents Tor consensus downloads on restart.
const MAX_LOG_BYTES: u64 = 100 * 1024 * 1024; // 100 MB

/// Wraps the log file handle together with its path so the write path can
/// rotate the file (rename current → .log.1, open fresh) when it grows large.
struct LogFile {
    file: File,
    path: std::path::PathBuf,
}

impl LogFile {
    /// Write `line` to the file, rotating first if the file exceeds [`MAX_LOG_BYTES`].
    fn write_line(&mut self, line: &str) {
        // fix G-2 — check size before every write.  On error (e.g. the file
        // was deleted by logrotate externally) we just write to the current
        // handle and let the OS sort it out.
        if let Ok(meta) = self.file.metadata() {
            if meta.len() >= MAX_LOG_BYTES {
                let rotated = self.path.with_extension("log.1");
                // best-effort rename; ignore errors (read-only fs, etc.)
                let _ = std::fs::rename(&self.path, &rotated);
                // Re-open with the same restrictive permissions.
                #[cfg(unix)]
                let new_file = {
                    use std::os::unix::fs::OpenOptionsExt;
                    OpenOptions::new()
                        .create(true)
                        .append(true)
                        .mode(0o600)
                        .open(&self.path)
                };
                #[cfg(not(unix))]
                let new_file = OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&self.path);
                if let Ok(f) = new_file {
                    self.file = f;
                }
            }
        }
        let _ = writeln!(self.file, "{line}");
    }
}

struct RustHostLogger {
    max_level: LevelFilter,
    filter_dependencies: bool,
    /// Optional file handle. `None` when `logging.enabled = false`.
    file: Option<Mutex<LogFile>>,
}

impl Log for RustHostLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        if metadata.level() > self.max_level {
            return false;
        }
        // 4.3 — Target-based dependency filtering.
        //
        // When `filter_dependencies` is true, only pass through records that:
        //   a) come from the `rusthost` crate (target starts with "rusthost"), OR
        //   b) are at Warn level or above (always surfaced regardless of origin).
        //
        // This suppresses Info/Debug/Trace noise from Arti, Tokio, TLS internals
        // and keeps the log file focused on application events.
        if self.filter_dependencies {
            let target = metadata.target();
            let is_app = target.starts_with("rusthost");
            let is_important = metadata.level() <= Level::Warn;
            return is_app || is_important;
        }
        true
    }

    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }

        let timestamp = Local::now().format("%H:%M:%S").to_string();
        let level = level_label(record.level());
        let line = format!("[{level}] [{timestamp}] {}", record.args());

        // Push to ring buffer.
        // 3.5 — Clone before acquiring the lock so the String heap allocation
        // does not contend with concurrent Arti logging threads. The lock is
        // then held only for the O(1) push_back pointer swap.
        if let Some(buf) = LOG_BUFFER.get() {
            let ring_line = line.clone();
            if let Ok(mut guard) = buf.lock() {
                if guard.len() >= 1_000 {
                    guard.pop_front();
                }
                guard.push_back(ring_line);
            }
        }

        // Write to file.
        if let Some(file_mutex) = &self.file {
            if let Ok(mut lf) = file_mutex.lock() {
                lf.write_line(&line);
            }
        }
    }

    fn flush(&self) {
        if let Some(file_mutex) = &self.file {
            if let Ok(mut lf) = file_mutex.lock() {
                let _ = lf.file.flush();
            }
        }
    }
}

/// Flush all buffered log entries to the log file.
///
/// Invokes `RustHostLogger::flush()`, which acquires the file mutex and calls
/// `File::flush()`. Call this once during shutdown, after the final log entry
/// has been written, to guarantee no lines are lost in the OS page cache.
pub fn flush() {
    log::logger().flush();
}

// ─── Init ────────────────────────────────────────────────────────────────────

/// Initialise the global logger. Must be called once before any `log!` macro.
///
/// - `data_dir` — the absolute `./data/` path used to resolve the log file.
///
/// Opens the log file in append mode (creating parent dirs as needed),
/// registers the logger, and initialises the ring buffer.
///
/// # Errors
///
/// Returns [`AppError::Io`] if the log file's parent directory cannot be
/// created, or [`AppError::LogInit`] if the logger is already initialised or
/// cannot be registered with the `log` facade.
pub fn init(config: &LoggingConfig, data_dir: &Path) -> Result<()> {
    LOG_BUFFER.get_or_init(|| Mutex::new(VecDeque::with_capacity(1_000)));

    // 4.2 — LogLevel is now a typed enum; convert directly to LevelFilter.
    let max_level: LevelFilter = config.level.into();

    let file = if config.enabled {
        let log_path = data_dir.join(&config.file);

        // fix G-1 — restrict the log directory to owner-only (0o700) before
        // creating the file.  Default umask typically yields 0o755, meaning
        // any local user on a shared host can read the log and discover the
        // .onion address that is logged at INFO level on every startup.
        if let Some(parent) = log_path.parent() {
            std::fs::create_dir_all(parent)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
            }
        }

        // fix G-1 — open with explicit 0o600 mode (owner read/write only).
        // Without this, OpenOptions inherits the process umask, typically
        // producing a world-readable 0o644 file.
        #[cfg(unix)]
        let f = {
            use std::os::unix::fs::OpenOptionsExt;
            OpenOptions::new()
                .create(true)
                .append(true)
                .mode(0o600)
                .open(&log_path)
                .map_err(|e| {
                    AppError::LogInit(format!("Cannot open log file {}: {e}", log_path.display()))
                })?
        };
        #[cfg(not(unix))]
        let f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
            .map_err(|e| {
                AppError::LogInit(format!("Cannot open log file {}: {e}", log_path.display()))
            })?;

        // fix G-2 — store the path alongside the file handle so the write
        // path can rotate the file when it exceeds MAX_LOG_BYTES.
        Some(Mutex::new(LogFile {
            file: f,
            path: log_path,
        }))
    } else {
        None
    };

    let logger = Box::new(RustHostLogger {
        max_level,
        filter_dependencies: config.filter_dependencies,
        file,
    });

    log::set_logger(Box::leak(logger))
        .map_err(|e| AppError::LogInit(format!("Failed to set global logger: {e}")))?;
    log::set_max_level(max_level);

    Ok(())
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

const fn level_label(level: Level) -> &'static str {
    match level {
        Level::Trace => "TRACE",
        Level::Debug => "DEBUG",
        Level::Info => "INFO ",
        Level::Warn => "WARN ",
        Level::Error => "ERROR",
    }
}
