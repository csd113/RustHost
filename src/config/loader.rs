//! # Config Loader

use super::Config;
use crate::{AppError, Result};
use std::path::Path;

fn is_rooted_path(path: &Path) -> bool {
    path.components().any(|component| {
        matches!(
            component,
            std::path::Component::Prefix(_) | std::path::Component::RootDir
        )
    })
}

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
    if is_rooted_path(path) {
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

#[expect(
    clippy::too_many_lines,
    reason = "Centralizes config validation in one place."
)]
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
        if is_rooted_path(dir_path) {
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
    if cfg.site.favicon.is_empty() {
        errors.push("[site] favicon must not be empty".into());
    } else {
        reject_parent_dir(&cfg.site.favicon, "favicon", &mut errors);
        let ext = std::path::Path::new(&cfg.site.favicon)
            .extension()
            .and_then(|ext| ext.to_str())
            .map(str::to_ascii_lowercase);
        if !matches!(ext.as_deref(), Some("ico" | "png" | "svg")) {
            errors.push("[site] favicon must end in .ico, .png, or .svg".into());
        }
        if matches!(ext.as_deref(), Some("png")) && !cfg.site.enable_png_favicon {
            errors.push("[site] enable_png_favicon must be true when favicon ends in .png".into());
        }
    }

    // [logging]
    if cfg.logging.file.is_empty() {
        errors.push("[logging] file must not be empty".into());
    }

    {
        let log_path = std::path::Path::new(&cfg.logging.file);
        if is_rooted_path(log_path) {
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

    if cfg.tls.redirect_http && !cfg.tls.enabled {
        errors.push("[tls] redirect_http requires [tls] enabled = true".into());
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(AppError::config_validation(errors))
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────
