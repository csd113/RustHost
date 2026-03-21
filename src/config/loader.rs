//! # Config Loader
//!
//! **Directory:** `src/config/`

use std::path::Path;

use super::Config;
use crate::{AppError, Result};

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
