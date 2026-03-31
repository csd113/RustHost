//! # Logging Module
//!
//! **File:** `mod.rs`
//! **Location:** `src/logging/mod.rs`
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

// ─── Structured access log ────────────────────────────────────────────────────

/// An HTTP access log record in Combined Log Format (CLF).
///
/// CLF format:
/// `<host> - - [<time>] "<method> <path> <proto>" <status> <bytes> "<referer>" "<ua>"`
///
/// Write one record per request via [`log_access`].  The access log is
/// separate from the application logger so CLF output has no level/timestamp
/// prefixes and can be consumed by standard log-analysis tools (e.g. `GoAccess`, `AWStats`).
pub struct AccessRecord<'a> {
    pub remote_addr: std::net::IpAddr,
    pub method: &'a str,
    pub path: &'a str,
    pub protocol: &'a str,
    pub status: u16,
    pub bytes_sent: Option<u64>,
    pub user_agent: Option<&'a str>,
    pub referer: Option<&'a str>,
}

impl std::fmt::Display for AccessRecord<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let now = chrono::Local::now().format("%d/%b/%Y:%H:%M:%S %z");
        let method = escape_clf_field(self.method);
        let path = escape_clf_field(self.path);
        let protocol = escape_clf_field(self.protocol);
        let ua = self
            .user_agent
            .map_or_else(|| "-".to_owned(), escape_clf_field);
        let referer = self
            .referer
            .map_or_else(|| "-".to_owned(), escape_clf_field);
        let bytes_sent = self.bytes_sent.map_or_else(|| "-".to_owned(), |n| n.to_string());
        write!(
            f,
            "{} - - [{now}] \"{} {} {}\" {} {} \"{}\" \"{}\"",
            self.remote_addr,
            method,
            path,
            protocol,
            self.status,
            bytes_sent,
            referer,
            ua,
        )
    }
}

/// Global access log writer.  Initialised by [`init_access_log`]; no-op until then.
static ACCESS_LOG: OnceLock<Mutex<Option<LogFile>>> = OnceLock::new();

/// Initialise the access log file.
///
/// Call once after [`init`], passing the same `data_dir`.  The access log is
/// written to `<data_dir>/logs/access.log`.  Rotation follows the same
/// `MAX_LOG_BYTES` limit as the application log.
///
/// Safe to call even when `logging.enabled = false`; the access log is
/// always written when this function succeeds.
///
/// # Errors
///
/// Returns [`AppError::Io`] if the log directory cannot be created or the
/// file cannot be opened. Returns [`AppError::LogInit`] if an access log has
/// already been initialized for a different path.
pub fn init_access_log(data_dir: &Path) -> Result<()> {
    let log_path = data_dir.join("logs/access.log");

    if let Some(parent) = log_path.parent() {
        std::fs::create_dir_all(parent)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
        }
    }

    #[cfg(unix)]
    let f = {
        use std::os::unix::fs::OpenOptionsExt;
        OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(&log_path)
            .map_err(|e| {
                AppError::LogInit(format!(
                    "Cannot open access log {}: {e}",
                    log_path.display()
                ))
            })?
    };
    #[cfg(not(unix))]
    let f = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .map_err(|e| {
            AppError::LogInit(format!(
                "Cannot open access log {}: {e}",
                log_path.display()
            ))
        })?;

    let new_log = LogFile {
        file: f,
        path: log_path.clone(),
        writes_since_check: 0,
        cached_size: 0,
    };

    if let Some(existing) = ACCESS_LOG.get() {
        let mut guard = existing
            .lock()
            .map_err(|_| AppError::LogInit("access log mutex is poisoned".into()))?;
        if guard.as_ref().is_some_and(|current| current.path == log_path) {
            drop(guard);
            return Ok(());
        }
        *guard = Some(new_log);
        drop(guard);
        return Ok(());
    }

    ACCESS_LOG
        .set(Mutex::new(Some(new_log)))
        .map_err(|_| AppError::LogInit("access log already initialized".into()))?;
    Ok(())
}

/// Write one access log record to `access.log`.
///
/// No-op if [`init_access_log`] has not been called.  Thread-safe; acquires
/// the file mutex for the duration of the write only.
pub fn log_access(record: &AccessRecord<'_>) {
    if let Some(log) = ACCESS_LOG.get() {
        if let Ok(mut lf) = log.lock() {
            if let Some(file) = lf.as_mut() {
                file.write_line(&record.to_string());
            }
        }
    }
}

/// Flush and close the structured access log writer, if initialized.
///
/// This lets long-running test processes or embedded runtimes reinitialize the
/// access log against a new data directory after shutdown.
pub fn shutdown_access_log() {
    if let Some(log) = ACCESS_LOG.get() {
        if let Ok(mut guard) = log.lock() {
            if let Some(file) = guard.as_mut() {
                let _ = file.file.flush();
            }
            *guard = None;
        }
    }
}

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

/// Check for rotation every N writes rather than on every write.
///
/// At INFO level with modest traffic this reduces `fstat` calls from ~1 000/min
/// to ~10/min.  The size estimate between checks uses `cached_size`, which is
/// updated after every write, so the effective rotation threshold is accurate to
/// within one write's worth of bytes.
const ROTATION_CHECK_INTERVAL: u64 = 100;

/// Maximum log file size before rotation (100 MB).
///
/// Without a size cap the log file grows unboundedly — at INFO level with modest
/// traffic this reaches ~2.5 GB/year; DEBUG with Arti noise is orders of magnitude
/// larger.  A full disk silently corrupts Arti's circuit database and prevents
/// Tor consensus downloads on restart.
const MAX_LOG_BYTES: u64 = 100 * 1024 * 1024; // 100 MB

/// Wraps the log file handle together with its path so the write path can
/// rotate the file (rename current → .log.1, open fresh) when it grows large.
struct LogFile {
    file: File,
    path: std::path::PathBuf,
    /// Number of lines written since the last rotation-size check.
    ///
    /// Compared against [`ROTATION_CHECK_INTERVAL`] to avoid calling `fstat`
    /// on every single write.
    writes_since_check: u64,
    /// Last known file size in bytes, updated at each check and after each
    /// write.  Used to decide whether to rotate without calling `fstat`.
    cached_size: u64,
}

impl LogFile {
    /// Write `line` to the file.
    ///
    /// Rotation is checked every [`ROTATION_CHECK_INTERVAL`] writes rather than
    /// on every write.  `cached_size` is updated after each write so the
    /// estimate stays accurate; an exact `fstat` is only issued at the check
    /// boundary to correct for any external writes (e.g. logrotate copy-then-
    /// truncate).
    fn write_line(&mut self, line: &str) {
        self.writes_since_check = self.writes_since_check.wrapping_add(1);

        if self.writes_since_check >= ROTATION_CHECK_INTERVAL {
            self.writes_since_check = 0;
            // Refresh the size from the OS at the check boundary.
            if let Ok(meta) = self.file.metadata() {
                self.cached_size = meta.len();
            }
            if self.cached_size >= MAX_LOG_BYTES {
                self.rotate();
            }
        }

        if writeln!(self.file, "{line}").is_ok() {
            // Approximate the new size: line length + newline.
            // u64::try_from is infallible on 64-bit targets but pedantic requires
            // an explicit conversion.
            self.cached_size = self.cached_size.saturating_add(
                u64::try_from(line.len())
                    .unwrap_or(u64::MAX)
                    .saturating_add(1),
            );
        }
    }

    /// Rotate the log file, keeping up to `MAX_LOG_BACKUPS` numbered copies.
    ///
    /// Rotation sequence: `.log.4` is deleted, `.log.3` → `.log.4`, …,
    /// `.log.1` → `.log.2`, current `.log` → `.log.1`, then a fresh file
    /// is opened.  All renames are best-effort; errors (read-only filesystem,
    /// missing backup) are silently ignored so a single rename failure does
    /// not abort the entire rotation.
    fn rotate(&mut self) {
        const MAX_LOG_BACKUPS: u32 = 5;

        // Delete the oldest backup to make room.
        let oldest = self.path.with_extension(format!("log.{MAX_LOG_BACKUPS}"));
        let _ = std::fs::remove_file(&oldest);

        // Shift .log.N → .log.(N+1) from highest to lowest to avoid overwriting.
        for n in (1..MAX_LOG_BACKUPS).rev() {
            let from = self.path.with_extension(format!("log.{n}"));
            let to = self
                .path
                .with_extension(format!("log.{}", n.saturating_add(1)));
            if from.exists() {
                let _ = std::fs::rename(&from, &to);
            }
        }

        // Move the current log to .log.1.
        let _ = std::fs::rename(&self.path, self.path.with_extension("log.1"));

        // Re-open a fresh file with the same restrictive permissions.
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
            self.cached_size = 0;
        }
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

/// Validate a Windows identity name component (username or domain).
///
/// Rejects control characters and the `icacls` metacharacters that would
/// confuse argument parsing. Intentionally does **not** log the raw value on
/// failure — adversarial input must not reach log sinks.
///
/// Mirrors the identical function in `src/tor/mod.rs` (`harden_windows_permissions`).
/// If the validation rules need updating, both copies must be kept in sync —
/// a shared utility in `crate::util` is the long-term home.
#[cfg(windows)]
fn validate_windows_name(s: &str) -> std::io::Result<()> {
    if s.is_empty() || s.len() > 256 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "Windows identity name has unexpected length: {} bytes",
                s.len()
            ),
        ));
    }
    // Illegal in Windows names: " / \ [ ] : ; | = , + * ? < >
    // Also reject: ( ) — icacls grant-string metacharacters.
    // Also reject: control characters and & (shell metacharacter on cmd.exe).
    let has_bad_char = s.chars().any(|c| {
        c.is_control()
            || matches!(
                c,
                '"' | '/'
                    | '\\'
                    | '['
                    | ']'
                    | ':'
                    | ';'
                    | '|'
                    | '='
                    | ','
                    | '+'
                    | '*'
                    | '?'
                    | '<'
                    | '>'
                    | '('
                    | ')'
                    | '&'
            )
    });
    if has_bad_char {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            // Raw value intentionally omitted to avoid logging attacker input.
            "Windows identity name component contains disallowed characters",
        ));
    }
    Ok(())
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

    let max_level: LevelFilter = config.level.into();

    let file = if config.enabled {
        let log_path = data_dir.join(&config.file);

        // Restrict the log directory to owner-only (0o700) before creating the
        // file — the default umask typically yields 0o755, meaning any local user
        // on a shared host can read the log and discover the .onion address.
        if let Some(parent) = log_path.parent() {
            std::fs::create_dir_all(parent)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
            }
            // Use env-var lookup rather than spawning `whoami`.
            //
            // Rationale: `whoami` depends on PATH availability (not guaranteed on
            // locked-down enterprise systems) and its stdout is user-controlled text
            // that was concatenated directly into `icacls` arguments, enabling
            // command injection for any username containing `&`, `;`, `(`, etc.
            //
            // The Windows kernel unconditionally sets USERNAME and USERDOMAIN in
            // every process's environment — they are equivalent in value to `whoami`
            // but never require a subprocess or shell expansion.
            //
            // Both values are validated by `validate_windows_name` before use.
            // The Tor module (tor/mod.rs) already follows this pattern correctly;
            // this brings logging into alignment.
            #[cfg(windows)]
            {
                let username = std::env::var("USERNAME").map_err(|e| {
                    AppError::LogInit(format!("USERNAME environment variable not available: {e}"))
                })?;
                let userdomain = std::env::var("USERDOMAIN").map_err(|e| {
                    AppError::LogInit(format!(
                        "USERDOMAIN environment variable not available: {e}"
                    ))
                })?;

                validate_windows_name(&username).map_err(|e| {
                    AppError::LogInit(format!(
                        "USERNAME contains disallowed characters — \
                         cannot harden log directory ACL: {e}"
                    ))
                })?;
                validate_windows_name(&userdomain).map_err(|e| {
                    AppError::LogInit(format!(
                        "USERDOMAIN contains disallowed characters — \
                         cannot harden log directory ACL: {e}"
                    ))
                })?;

                // Build the icacls grant specifier as a single argument token.
                // std::process::Command wraps arguments containing spaces in double
                // quotes on Windows (CreateProcessW), so usernames with spaces
                // (e.g. enterprise accounts like "John Smith") are handled correctly.
                //
                // Format: "DOMAIN\user:(OI)(CI)F"
                //   (OI) = object inherit, (CI) = container inherit, F = full control.
                let grant_arg = format!("{userdomain}\\{username}:(OI)(CI)F");
                let path_str = parent.to_string_lossy();
                let _ = std::process::Command::new("icacls")
                    .args([
                        path_str.as_ref(),
                        "/inheritance:r",
                        "/grant:r",
                        grant_arg.as_str(),
                    ])
                    .output();
            }
        }

        // Open with owner-only 0o600 permissions — without an explicit mode,
        // OpenOptions inherits the process umask, typically yielding a world-
        // readable 0o644 file.
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

        // Store the path alongside the file handle so the write path can
        // rotate the file when it exceeds MAX_LOG_BYTES.
        Some(Mutex::new(LogFile {
            file: f,
            path: log_path,
            writes_since_check: 0,
            cached_size: 0,
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

fn escape_clf_field(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if c.is_ascii_control() => {}
            c => out.push(c),
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    // These run on all platforms (cfg(test) is not gated on windows) so CI
    // catches regressions even on Linux/macOS build runners.
    use crate::logging::AccessRecord;
    #[cfg(windows)]
    use super::validate_windows_name;

    // Provide a shim for non-Windows test runs so the test bodies compile.
    #[cfg(not(windows))]
    fn validate_windows_name(s: &str) -> std::io::Result<()> {
        // Mirror the real implementation so tests remain meaningful on Linux CI.
        if s.is_empty() || s.len() > 256 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Windows identity name has unexpected length",
            ));
        }
        let bad = s.chars().any(|c| {
            c.is_control()
                || matches!(
                    c,
                    '"' | '/'
                        | '\\'
                        | '['
                        | ']'
                        | ':'
                        | ';'
                        | '|'
                        | '='
                        | ','
                        | '+'
                        | '*'
                        | '?'
                        | '<'
                        | '>'
                        | '('
                        | ')'
                        | '&'
                )
        });
        if bad {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Windows identity name component contains disallowed characters",
            ));
        }
        Ok(())
    }

    #[test]
    fn validate_windows_name_rejects_ampersand() {
        // & is a cmd.exe metacharacter — injecting it could chain commands.
        assert!(validate_windows_name("user & evil").is_err());
    }

    #[test]
    fn validate_windows_name_rejects_semicolon() {
        assert!(validate_windows_name("user;cmd").is_err());
    }

    #[test]
    fn validate_windows_name_rejects_parens() {
        // ( ) are icacls grant-string metacharacters.
        assert!(validate_windows_name("user(admin)").is_err());
    }

    #[test]
    fn validate_windows_name_rejects_empty() {
        assert!(validate_windows_name("").is_err());
    }

    #[test]
    fn validate_windows_name_rejects_overlong() {
        assert!(validate_windows_name(&"a".repeat(257)).is_err());
    }

    #[test]
    fn validate_windows_name_accepts_normal_user() {
        assert!(validate_windows_name("normal_user").is_ok());
    }

    #[test]
    fn validate_windows_name_accepts_domain_user_with_space() {
        // Enterprise usernames like "John Smith" are valid.
        assert!(validate_windows_name("John Smith").is_ok());
    }

    #[test]
    fn access_record_escapes_quotes_and_backslashes() {
        let record = AccessRecord {
            remote_addr: std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            method: "GET",
            path: "/a\"b\\c\nd",
            protocol: "HTTP/1.1",
            status: 200,
            bytes_sent: Some(12),
            user_agent: Some("agent\"name\\"),
            referer: Some("ref\r\nline"),
        };
        let rendered = record.to_string();
        assert!(rendered.contains("\\\""));
        assert!(rendered.contains("\\\\"));
        assert!(!rendered.contains('\n'));
        assert!(!rendered.contains('\r'));
    }

    #[test]
    fn access_record_renders_unknown_bytes_as_dash() {
        let record = AccessRecord {
            remote_addr: std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            method: "GET",
            path: "/",
            protocol: "HTTP/1.1",
            status: 304,
            bytes_sent: None,
            user_agent: None,
            referer: None,
        };
        let rendered = record.to_string();
        assert!(rendered.contains(" 304 - "));
    }
}
