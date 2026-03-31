//! # Tor Filesystem Helpers
//!
//! **File:** `fs.rs`
//! **Location:** `src/tor/fs.rs`

/// Create a directory intended to be private to the current user and harden
/// its permissions.
///
/// ## Security limitations
///
/// - Symlinks at the target path are rejected and the path is re-verified
///   after creation.
/// - A local attacker who can race filesystem operations may still exploit
///   TOCTOU windows. On hostile multi-user systems this is a real risk for
///   Tor private key material.
///
/// ## Platform notes
///
/// - **Unix**: the final directory is created with mode `0700` atomically.
/// - **Windows**: ACLs are set via `icacls`. The identity is read from the
///   `USERNAME` / `USERDOMAIN` process-environment variables (set
///   unconditionally by the Windows kernel) rather than spawning `whoami`,
///   avoiding PATH-dependency and subprocess stdout encoding issues.
///   Both values are validated before use to prevent injection into the
///   `icacls` argument string.
///
/// **Future work (Windows)**: replace the `icacls` subprocess with a direct
/// call to `SetNamedSecurityInfoW` via the `windows-sys` crate. That
/// eliminates the subprocess entirely and removes all injection surface.
pub(super) fn ensure_private_dir(path: &std::path::Path) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    if let Ok(meta) = std::fs::symlink_metadata(path) {
        let ft = meta.file_type();
        if ft.is_symlink() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "refusing to use symlink as private directory: {}",
                    path.display()
                ),
            ));
        }
        if !ft.is_dir() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!("path exists but is not a directory: {}", path.display()),
            ));
        }
    }

    #[cfg(unix)]
    create_private_dir_unix(path)?;
    #[cfg(not(unix))]
    std::fs::create_dir_all(path)?;

    #[cfg(unix)]
    harden_unix_permissions(path)?;

    #[cfg(windows)]
    harden_windows_permissions(path)?;

    Ok(())
}

#[cfg(unix)]
fn create_private_dir_unix(path: &std::path::Path) -> std::io::Result<()> {
    use std::fs::DirBuilder;
    use std::os::unix::fs::DirBuilderExt;

    match DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(e) => Err(e),
    }
}

#[cfg(unix)]
fn harden_unix_permissions(path: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let meta = std::fs::symlink_metadata(path)?;
    let ft = meta.file_type();
    if ft.is_symlink() || !ft.is_dir() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "private dir path is not a real directory after creation: {}",
                path.display()
            ),
        ));
    }

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
}

#[cfg(windows)]
fn harden_windows_permissions(path: &std::path::Path) -> std::io::Result<()> {
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
                )
        });
        if has_bad_char {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Windows identity name component contains disallowed characters",
            ));
        }
        Ok(())
    }

    let username = std::env::var("USERNAME").map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("USERNAME environment variable not available: {e}"),
        )
    })?;
    let userdomain = std::env::var("USERDOMAIN").map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("USERDOMAIN environment variable not available: {e}"),
        )
    })?;

    validate_windows_name(&username)?;
    validate_windows_name(&userdomain)?;

    let grant_arg = format!("{userdomain}\\{username}:(OI)(CI)F");

    let path_str = path.to_string_lossy();
    let icacls_out = std::process::Command::new("icacls")
        .args([
            path_str.as_ref(),
            "/inheritance:r",
            "/grant:r",
            grant_arg.as_str(),
        ])
        .output()?;

    if !icacls_out.status.success() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!(
                "icacls failed (exit {:?}): {}",
                icacls_out.status.code(),
                String::from_utf8_lossy(&icacls_out.stderr).trim(),
            ),
        ));
    }

    Ok(())
}
