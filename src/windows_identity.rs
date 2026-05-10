#[cfg(any(windows, test))]
use std::io;

#[cfg(any(windows, test))]
pub fn validate_windows_identity_name_component(
    s: &str,
    extra_disallowed: &[char],
) -> io::Result<()> {
    if s.is_empty() || s.len() > 256 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
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
            || extra_disallowed.contains(&c)
    });
    if has_bad_char {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Windows identity name component contains disallowed characters",
        ));
    }

    Ok(())
}

#[cfg(windows)]
pub fn current_windows_identity(extra_disallowed: &[char]) -> io::Result<(String, String)> {
    let username = std::env::var("USERNAME").map_err(|e| {
        io::Error::other(format!("USERNAME environment variable not available: {e}"))
    })?;
    let userdomain = std::env::var("USERDOMAIN").map_err(|e| {
        io::Error::other(format!(
            "USERDOMAIN environment variable not available: {e}"
        ))
    })?;

    validate_windows_identity_name_component(&username, extra_disallowed)?;
    validate_windows_identity_name_component(&userdomain, extra_disallowed)?;

    Ok((username, userdomain))
}

#[cfg(test)]
mod tests {
    use super::validate_windows_identity_name_component;

    #[test]
    fn rejects_empty_names() {
        assert!(validate_windows_identity_name_component("", &[]).is_err());
    }

    #[test]
    fn rejects_overlong_names() {
        assert!(validate_windows_identity_name_component(&"a".repeat(257), &[]).is_err());
    }

    #[test]
    fn rejects_common_icacls_metacharacters() {
        assert!(validate_windows_identity_name_component("user(admin)", &[]).is_err());
        assert!(validate_windows_identity_name_component("user;cmd", &[]).is_err());
    }

    #[test]
    fn rejects_optional_extra_characters() {
        assert!(validate_windows_identity_name_component("user & evil", &['&']).is_err());
    }

    #[test]
    fn accepts_normal_names() {
        assert!(validate_windows_identity_name_component("John Smith", &[]).is_ok());
        assert!(validate_windows_identity_name_component("normal_user", &['&']).is_ok());
    }
}
