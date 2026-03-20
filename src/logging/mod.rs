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

use crate::{config::LoggingConfig, Result};

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

struct RustHostLogger {
    max_level: LevelFilter,
    /// Optional file handle. `None` when `logging.enabled = false`.
    file: Option<Mutex<File>>,
}

impl Log for RustHostLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= self.max_level
    }

    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }

        let timestamp = Local::now().format("%H:%M:%S").to_string();
        let level = level_label(record.level());
        let line = format!("[{level}] [{timestamp}] {}", record.args());

        // Push to ring buffer.
        if let Some(buf) = LOG_BUFFER.get() {
            if let Ok(mut guard) = buf.lock() {
                if guard.len() >= 1_000 {
                    guard.pop_front();
                }
                guard.push_back(line.clone());
            }
        }

        // Write to file.
        if let Some(file_mutex) = &self.file {
            if let Ok(mut f) = file_mutex.lock() {
                let _ = writeln!(f, "{line}");
            }
        }
    }

    fn flush(&self) {
        if let Some(file_mutex) = &self.file {
            if let Ok(mut f) = file_mutex.lock() {
                let _ = f.flush();
            }
        }
    }
}

// ─── Init ────────────────────────────────────────────────────────────────────

/// Initialise the global logger. Must be called once before any `log!` macro.
///
/// - `data_dir` — the absolute `./data/` path used to resolve the log file.
///
/// Opens the log file in append mode (creating parent dirs as needed),
/// registers the logger, and initialises the ring buffer.
pub fn init(config: &LoggingConfig, data_dir: &Path) -> Result<()> {
    LOG_BUFFER.get_or_init(|| Mutex::new(VecDeque::with_capacity(1_000)));

    let max_level = parse_level(&config.level);

    let file = if config.enabled {
        let log_path = data_dir.join(&config.file);
        if let Some(parent) = log_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
            .map_err(|e| format!("Cannot open log file {}: {e}", log_path.display()))?;
        Some(Mutex::new(f))
    } else {
        None
    };

    let logger = Box::new(RustHostLogger { max_level, file });

    log::set_logger(Box::leak(logger)).map_err(|e| format!("Failed to set global logger: {e}"))?;
    log::set_max_level(max_level);

    Ok(())
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn parse_level(s: &str) -> LevelFilter {
    match s.to_ascii_lowercase().as_str() {
        "trace" => LevelFilter::Trace,
        "debug" => LevelFilter::Debug,
        "warn" => LevelFilter::Warn,
        "error" => LevelFilter::Error,
        _ => LevelFilter::Info, // "info" and any unknown value
    }
}

const fn level_label(level: Level) -> &'static str {
    match level {
        Level::Trace => "TRACE",
        Level::Debug => "DEBUG",
        Level::Info => "INFO ",
        Level::Warn => "WARN ",
        Level::Error => "ERROR",
    }
}
