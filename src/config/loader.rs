//! # Config Loader
//!
//! **Directory:** `src/config/`

use std::path::Path;

use super::Config;
use crate::{AppError, Result};

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
        .map_err(|e| AppError::ConfigLoad(format!("settings.toml is malformed: {e}")))?;

    validate(&config)?;
    Ok(config)
}

fn validate(cfg: &Config) -> Result<()> {
    let mut errors: Vec<String> = Vec::new();

    // [server]
    // port: NonZeroU16 — port 0 is already rejected by serde at parse time (4.2).
    // bind: IpAddr     — invalid IPs are already rejected by serde at parse time (4.2).
    // level: LogLevel  — invalid levels are already rejected by serde at parse time (4.2).

    // [site]
    if cfg.site.index_file.contains(std::path::MAIN_SEPARATOR) {
        errors.push("[site] index_file must be a filename only, not a path".into());
    }
    {
        let dir_path = std::path::Path::new(&cfg.site.directory);
        if dir_path.is_absolute() {
            errors.push("[site] directory must not be an absolute path".into());
        }
        if dir_path
            .components()
            .any(|c| c == std::path::Component::ParentDir)
        {
            errors.push("[site] directory must not contain '..' components".into());
        }
        if cfg.site.directory.contains(std::path::MAIN_SEPARATOR) {
            errors.push("[site] directory must be a directory name only, not a path".into());
        }
    }

    // [logging]
    {
        let log_path = std::path::Path::new(&cfg.logging.file);
        if log_path.is_absolute() {
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
    if cfg.identity.instance_name.len() > 32 {
        errors.push(format!(
            "[identity] instance_name is {} chars; maximum is 32",
            cfg.identity.instance_name.len()
        ));
    }
    // `char::is_control` covers U+001B (ESC), BEL (\x07), backspace (\x08),
    // null (\x00), and all other C0/C1 control characters. This check prevents
    // ANSI/VT escape-sequence injection through `instance_name` into the
    // terminal dashboard, which renders the value directly in raw mode.
    if cfg.identity.instance_name.chars().any(char::is_control) {
        errors.push("[identity] instance_name must not contain control characters".into());
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

    // ── validate — [site] directory ─────────────────────────────────────────

    #[test]
    fn validate_site_directory_relative_traversal() {
        let mut cfg = valid();
        cfg.site.directory = "../../etc".into();
        let result = validate(&cfg);
        assert!(
            matches!(&result, Err(AppError::ConfigValidation(e)) if e.iter().any(|s| s.contains("[site] directory"))),
            "expected ConfigValidation error with '[site] directory', got: {result:?}"
        );
    }

    #[test]
    fn validate_site_directory_absolute_path() {
        let mut cfg = valid();
        cfg.site.directory = "/etc".into();
        let result = validate(&cfg);
        assert!(
            matches!(&result, Err(AppError::ConfigValidation(e)) if e.iter().any(|s| s.contains("[site] directory"))),
            "expected ConfigValidation error with '[site] directory', got: {result:?}"
        );
    }

    // ── validate — [logging] file ────────────────────────────────────────────

    #[test]
    fn validate_logging_file_traversal() {
        let mut cfg = valid();
        cfg.logging.file = "../../.bashrc".into();
        let result = validate(&cfg);
        assert!(
            matches!(&result, Err(AppError::ConfigValidation(e)) if e.iter().any(|s| s.contains("[logging] file"))),
            "expected ConfigValidation error with '[logging] file', got: {result:?}"
        );
    }

    // ── validate — port ──────────────────────────────────────────────────────
    //
    // Port 0 is already rejected by `NonZeroU16` at the serde layer (fix 4.2),
    // so we verify that serde rejects a zero value rather than testing via
    // `validate()` (which only receives already-parsed configs).

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

    // ── validate — deny_unknown_fields (fix 2.5) ─────────────────────────────

    #[test]
    fn config_rejects_unknown_fields_at_parse_time() {
        // Insert an unrecognised key into [server] — must be rejected by serde
        // because all Config structs carry `#[serde(deny_unknown_fields)]`.
        let toml_str = make_full_toml("completely_unknown_key = true");
        let result = toml::from_str::<Config>(&toml_str);
        assert!(result.is_err(), "expected serde error for unknown field");
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    /// Build a complete, valid TOML document with `extra` injected into
    /// the `[server]` section, so individual field-level tests can be
    /// expressed as minimal one-liner overrides.
    fn make_full_toml(extra: &str) -> String {
        format!(
            r#"
[server]
port = 8080
bind = "127.0.0.1"
auto_port_fallback = true
open_browser_on_start = false
max_connections = 256
content_security_policy = "default-src 'self'"
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
