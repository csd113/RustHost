//! Shared version/build helpers.

const FALLBACK_VERSION: &str = "1.0.0";

#[must_use]
pub const fn package_version() -> &'static str {
    match option_env!("CARGO_PKG_VERSION") {
        Some(version) => version,
        None => FALLBACK_VERSION,
    }
}

#[must_use]
pub fn product_version_line() -> String {
    format!("RustHost {}", package_version())
}
