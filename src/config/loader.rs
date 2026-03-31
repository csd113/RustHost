//! # Config Loader
//!
//! **File:** `loader.rs`
//! **Location:** `src/config/loader.rs`

use super::Config;
use crate::{AppError, Result};
use std::path::Path;

/// Load and validate the configuration from `path`.
///
/// # Errors
///
/// Returns [`AppError::ConfigLoad`] if the file cannot be read or is
/// malformed TOML, or [`AppError::ConfigValidation`] if any field fails
/// semantic validation.
#[must_use = "the loaded Config must be used to start the server"]
pub fn load(path: &Path) -> Result<Config> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| AppError::ConfigLoad(format!("Cannot read {}: {e}", path.display())))?;

    let config: Config = toml::from_str(&raw)
        .map_err(|e| AppError::ConfigLoad(format!("{} is malformed: {e}", path.display())))?;

    validate(&config)?;
    Ok(config)
}

fn reject_parent_dir(value: &str, label: &str, errors: &mut Vec<String>) {
    let path = std::path::Path::new(value);
    if path.has_root() {
        errors.push(format!("[site] {label} must not be an absolute path"));
        return;
    }
    if path
        .components()
        .any(|c| c == std::path::Component::ParentDir)
    {
        errors.push(format!("[site] {label} must not contain '..' components"));
    }
}

fn validate_redirects(cfg: &Config, errors: &mut Vec<String>) {
    for (idx, rule) in cfg.redirects.iter().enumerate() {
        let prefix = format!("[[redirects]] entry {}", idx.saturating_add(1));
        if rule.from.is_empty() {
            errors.push(format!("{prefix}: from must not be empty"));
        } else {
            if !rule.from.starts_with('/') {
                errors.push(format!("{prefix}: from must start with '/'"));
            }
            if rule.from.chars().any(char::is_control) {
                errors.push(format!(
                    "{prefix}: from must not contain control characters"
                ));
            }
        }

        if rule.to.is_empty() {
            errors.push(format!("{prefix}: to must not be empty"));
        } else if rule.to.chars().any(char::is_control) {
            errors.push(format!("{prefix}: to must not contain control characters"));
        } else if !rule.to.is_ascii() {
            errors.push(format!(
                "{prefix}: to must be ASCII so it can be emitted safely as an HTTP Location header"
            ));
        }

        if !matches!(rule.status, 301 | 302) {
            errors.push(format!(
                "{prefix}: status must be either 301 or 302, got {}",
                rule.status
            ));
        }
    }
}

#[allow(clippy::too_many_lines)] // Centralizes config validation in one place.
fn validate(cfg: &Config) -> Result<()> {
    let mut errors: Vec<String> = Vec::new();

    // [server]
    // max_connections = 0 deadlocks the semaphore (never grants permits).
    // Values > 65_535 are impractical for most OS-level connection limits.
    if cfg.server.max_connections == 0 {
        errors.push("[server] max_connections must be at least 1".into());
    }
    if cfg.server.max_connections > 65_535 {
        errors.push(format!(
            "[server] max_connections = {} exceeds the practical limit of 65535",
            cfg.server.max_connections
        ));
    }

    // max_connections_per_ip = 0 makes every connection fail immediately.
    // max_connections_per_ip > max_connections makes the per-IP guard useless.
    if cfg.server.max_connections_per_ip == 0 {
        errors.push("[server] max_connections_per_ip must be at least 1".into());
    }
    if cfg.server.max_connections_per_ip > cfg.server.max_connections {
        errors.push(format!(
            "[server] max_connections_per_ip ({}) must be ≤ max_connections ({})",
            cfg.server.max_connections_per_ip, cfg.server.max_connections
        ));
    }
    if cfg.server.shutdown_grace_secs == 0 {
        errors.push("[server] shutdown_grace_secs must be at least 1".into());
    }

    // [site]
    if cfg.site.directory.is_empty() {
        errors.push("[site] directory must not be empty".into());
    }
    if cfg.site.index_file.is_empty() {
        errors.push("[site] index_file must not be empty".into());
    }

    // index_file must be a bare filename (no path separators or directories).
    if std::path::Path::new(&cfg.site.index_file)
        .components()
        .count()
        > 1
    {
        errors.push("[site] index_file must be a filename only, not a path".into());
    }

    {
        let dir_path = std::path::Path::new(&cfg.site.directory);
        if dir_path.has_root() {
            errors.push("[site] directory must not be an absolute path".into());
        }
        if dir_path
            .components()
            .any(|c| c == std::path::Component::ParentDir)
        {
            errors.push("[site] directory must not contain '..' components".into());
        }
        // Allow at most one Normal component (simple directory name only).
        if dir_path
            .components()
            .filter(|c| matches!(c, std::path::Component::Normal(_)))
            .count()
            > 1
        {
            errors.push("[site] directory must be a directory name only, not a path".into());
        }
    }

    if let Some(error_404) = &cfg.site.error_404 {
        reject_parent_dir(error_404, "error_404", &mut errors);
    }
    if let Some(error_503) = &cfg.site.error_503 {
        reject_parent_dir(error_503, "error_503", &mut errors);
    }

    // [logging]
    if cfg.logging.file.is_empty() {
        errors.push("[logging] file must not be empty".into());
    }

    {
        let log_path = std::path::Path::new(&cfg.logging.file);
        if log_path.has_root() {
            errors.push("[logging] file must not be an absolute path".into());
        }
        if log_path
            .components()
            .any(|c| c == std::path::Component::ParentDir)
        {
            errors.push("[logging] file must not contain '..' components".into());
        }
    }

    // [console]
    if cfg.console.refresh_rate_ms < 100 {
        errors.push(format!(
            "[console] refresh_rate_ms = {} is below the minimum of 100 ms",
            cfg.console.refresh_rate_ms
        ));
    }

    // [identity]
    if cfg.identity.instance_name.is_empty() {
        errors.push("[identity] instance_name must not be empty".into());
    }
    if cfg.identity.instance_name.chars().count() > 32 {
        errors.push(format!(
            "[identity] instance_name is {} characters; maximum is 32",
            cfg.identity.instance_name.chars().count()
        ));
    }
    // Prevent ANSI/VT escape-sequence injection into the terminal dashboard.
    if cfg.identity.instance_name.chars().any(char::is_control) {
        errors.push("[identity] instance_name must not contain control characters".into());
    }

    validate_redirects(cfg, &mut errors);

    if cfg.tor.shutdown_grace_secs == 0 {
        errors.push("[tor] shutdown_grace_secs must be at least 1".into());
    }

    if cfg.tls.redirect_http {
        if !cfg.tls.enabled {
            errors.push("[tls] redirect_http requires [tls] enabled = true".into());
        }
        if cfg.tls.http_port == cfg.server.port {
            errors.push(
                "[tls] http_port must differ from [server] port when redirect_http = true".into(),
            );
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(AppError::ConfigValidation(errors))
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::{validate, Config};
    use crate::AppError;

    // Helper: a valid config derived from the Default impl.
    fn valid() -> Config {
        Config::default()
    }

    // ── validate — happy path ────────────────────────────────────────────────
    #[test]
    fn validate_valid_config_returns_ok() {
        assert!(validate(&valid()).is_ok());
    }

    // ── validate — [server] max_connections_per_ip ───────────────────────────
    #[test]
    fn validate_max_connections_per_ip_zero_is_rejected() {
        let mut cfg = valid();
        cfg.server.max_connections_per_ip = 0;
        let result = validate(&cfg);
        assert!(
            matches!(&result, Err(AppError::ConfigValidation(e))
                if e.iter().any(|s| s.contains("max_connections_per_ip"))),
            "expected ConfigValidation error mentioning max_connections_per_ip, got: {result:?}"
        );
    }

    #[test]
    fn validate_max_connections_per_ip_exceeds_max_connections() {
        let mut cfg = valid();
        cfg.server.max_connections = 32;
        cfg.server.max_connections_per_ip = 64;
        let result = validate(&cfg);
        assert!(
            matches!(&result, Err(AppError::ConfigValidation(e))
                if e.iter().any(|s| s.contains("max_connections_per_ip"))),
            "expected ConfigValidation error mentioning max_connections_per_ip, got: {result:?}"
        );
    }

    #[test]
    fn validate_max_connections_per_ip_equal_to_max_connections_is_ok() {
        let mut cfg = valid();
        cfg.server.max_connections = 32;
        cfg.server.max_connections_per_ip = 32;
        assert!(validate(&cfg).is_ok());
    }

    #[test]
    fn validate_shutdown_grace_zero_is_rejected() {
        let mut cfg = valid();
        cfg.server.shutdown_grace_secs = 0;
        let result = validate(&cfg);
        assert!(
            matches!(&result, Err(AppError::ConfigValidation(e))
                if e.iter().any(|s| s.contains("shutdown_grace_secs"))),
            "expected ConfigValidation error mentioning shutdown_grace_secs, got: {result:?}"
        );
    }

    #[test]
    fn validate_redirect_http_requires_tls_enabled() {
        let mut cfg = valid();
        cfg.tls.redirect_http = true;
        cfg.tls.enabled = false;
        cfg.tls.http_port = std::num::NonZeroU16::new(8081).unwrap_or(std::num::NonZeroU16::MIN);
        let result = validate(&cfg);
        assert!(
            matches!(&result, Err(AppError::ConfigValidation(e))
                if e.iter().any(|s| s.contains("redirect_http requires"))),
            "expected ConfigValidation error mentioning redirect_http requires tls, got: {result:?}"
        );
    }

    #[test]
    fn validate_redirect_http_rejects_port_conflict() {
        let mut cfg = valid();
        cfg.tls.enabled = true;
        cfg.tls.redirect_http = true;
        cfg.tls.http_port = cfg.server.port;
        let result = validate(&cfg);
        assert!(
            matches!(&result, Err(AppError::ConfigValidation(e))
                if e.iter().any(|s| s.contains("http_port must differ"))),
            "expected ConfigValidation error mentioning http_port conflict, got: {result:?}"
        );
    }

    // ── validate — [site] directory ─────────────────────────────────────────
    #[test]
    fn validate_site_directory_empty_is_rejected() {
        let mut cfg = valid();
        cfg.site.directory = String::new();
        let result = validate(&cfg);
        assert!(
            matches!(&result, Err(AppError::ConfigValidation(e))
                if e.iter().any(|s| s.contains("[site] directory"))),
            "expected ConfigValidation error mentioning [site] directory, got: {result:?}"
        );
    }

    #[test]
    fn validate_site_directory_relative_traversal() {
        let mut cfg = valid();
        cfg.site.directory = "../../etc".into();
        let result = validate(&cfg);
        assert!(
            matches!(&result, Err(AppError::ConfigValidation(e))
                if e.iter().any(|s| s.contains("[site] directory"))),
            "expected ConfigValidation error with '[site] directory', got: {result:?}"
        );
    }

    #[test]
    fn validate_site_directory_absolute_path() {
        let mut cfg = valid();
        cfg.site.directory = "/etc".into();
        let result = validate(&cfg);
        assert!(
            matches!(&result, Err(AppError::ConfigValidation(e))
                if e.iter().any(|s| s.contains("[site] directory"))),
            "expected ConfigValidation error with '[site] directory', got: {result:?}"
        );
    }

    #[test]
    fn validate_site_index_file_empty_is_rejected() {
        let mut cfg = valid();
        cfg.site.index_file = String::new();
        let result = validate(&cfg);
        assert!(
            matches!(&result, Err(AppError::ConfigValidation(e))
                if e.iter().any(|s| s.contains("[site] index_file"))),
            "expected ConfigValidation error mentioning [site] index_file, got: {result:?}"
        );
    }

    // ── validate — [logging] file ────────────────────────────────────────────
    #[test]
    fn validate_logging_file_empty_is_rejected() {
        let mut cfg = valid();
        cfg.logging.file = String::new();
        let result = validate(&cfg);
        assert!(
            matches!(&result, Err(AppError::ConfigValidation(e))
                if e.iter().any(|s| s.contains("[logging] file"))),
            "expected ConfigValidation error mentioning [logging] file, got: {result:?}"
        );
    }

    #[test]
    fn validate_logging_file_traversal() {
        let mut cfg = valid();
        cfg.logging.file = "../../.bashrc".into();
        let result = validate(&cfg);
        assert!(
            matches!(&result, Err(AppError::ConfigValidation(e))
                if e.iter().any(|s| s.contains("[logging] file"))),
            "expected ConfigValidation error with '[logging] file', got: {result:?}"
        );
    }

    #[test]
    fn validate_error_404_traversal() {
        let mut cfg = valid();
        cfg.site.error_404 = Some("../outside.html".into());
        let result = validate(&cfg);
        assert!(
            matches!(&result, Err(AppError::ConfigValidation(e))
                if e.iter().any(|s| s.contains("error_404"))),
            "expected ConfigValidation error mentioning error_404, got: {result:?}"
        );
    }

    #[test]
    fn validate_error_503_absolute_path() {
        let mut cfg = valid();
        cfg.site.error_503 = Some("/tmp/error.html".into());
        let result = validate(&cfg);
        assert!(
            matches!(&result, Err(AppError::ConfigValidation(e))
                if e.iter().any(|s| s.contains("error_503"))),
            "expected ConfigValidation error mentioning error_503, got: {result:?}"
        );
    }

    // ── validate — [identity] instance_name ──────────────────────────────────
    #[test]
    fn validate_instance_name_empty_is_rejected() {
        let mut cfg = valid();
        cfg.identity.instance_name = String::new();
        let result = validate(&cfg);
        assert!(
            matches!(&result, Err(AppError::ConfigValidation(e))
                if e.iter().any(|s| s.contains("instance_name"))),
            "expected ConfigValidation error mentioning instance_name, got: {result:?}"
        );
    }

    #[test]
    fn validate_instance_name_too_long_is_rejected() {
        let mut cfg = valid();
        cfg.identity.instance_name = "x".repeat(33);
        let result = validate(&cfg);
        assert!(
            matches!(&result, Err(AppError::ConfigValidation(e))
                if e.iter().any(|s| s.contains("instance_name"))),
            "expected ConfigValidation error mentioning instance_name, got: {result:?}"
        );
    }

    #[test]
    fn validate_instance_name_control_char_is_rejected() {
        let mut cfg = valid();
        cfg.identity.instance_name = "Test\x1b".into(); // ESC
        let result = validate(&cfg);
        assert!(
            matches!(&result, Err(AppError::ConfigValidation(e))
                if e.iter().any(|s| s.contains("instance_name"))),
            "expected ConfigValidation error mentioning instance_name, got: {result:?}"
        );
    }

    // ── validate — port ──────────────────────────────────────────────────────
    //
    // Port 0 is already rejected by `NonZeroU16` at the serde layer.
    #[test]
    fn config_rejects_port_zero_at_parse_time() {
        let toml_str = make_full_toml("port = 0");
        let result = toml::from_str::<Config>(&toml_str);
        assert!(result.is_err(), "expected serde error for port = 0");
    }

    // ── validate — bind address ──────────────────────────────────────────────
    #[test]
    fn config_rejects_invalid_bind_address_at_parse_time() {
        let toml_str = make_full_toml("bind = \"not.an.ip\"");
        let result = toml::from_str::<Config>(&toml_str);
        assert!(
            result.is_err(),
            "expected serde error for invalid bind address"
        );
    }

    // ── validate — deny_unknown_fields ───────────────────────────────────────
    #[test]
    fn config_rejects_unknown_fields_at_parse_time() {
        let toml_str = make_full_toml("completely_unknown_key = true");
        let result = toml::from_str::<Config>(&toml_str);
        assert!(result.is_err(), "expected serde error for unknown field");
    }

    // ── Helpers ──────────────────────────────────────────────────────────────
    /// Build a complete, valid TOML document with `extra` injected into
    /// the `[server]` section.
    fn make_full_toml(extra: &str) -> String {
        format!(
            r#"
[server]
port = 8080
bind = "127.0.0.1"
auto_port_fallback = true
open_browser_on_start = false
max_connections = 256
max_connections_per_ip = 16
csp_level = "off"
{extra}

[site]
directory = "site"
index_file = "index.html"
enable_directory_listing = false

[tor]
enabled = false

[logging]
enabled = true
level = "info"
file = "logs/rusthost.log"
filter_dependencies = true

[console]
interactive = false
refresh_rate_ms = 500
show_timestamps = false

[identity]
instance_name = "Test"
"#
        )
    }
}
