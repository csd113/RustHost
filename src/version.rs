//! Shared version/build helpers.

const FALLBACK_VERSION: &str = "1.2.0";
const UNKNOWN_BUILD_METADATA: &str = "unknown";

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

#[must_use]
pub const fn build_profile() -> &'static str {
    match option_env!("RUSTHOST_BUILD_PROFILE") {
        Some(profile) => profile,
        None => UNKNOWN_BUILD_METADATA,
    }
}

#[must_use]
pub const fn commit_sha() -> &'static str {
    match option_env!("RUSTHOST_GIT_COMMIT") {
        Some(commit) => commit,
        None => UNKNOWN_BUILD_METADATA,
    }
}

#[must_use]
pub const fn target_triple() -> &'static str {
    match option_env!("RUSTHOST_BUILD_TARGET") {
        Some(target) => target,
        None => UNKNOWN_BUILD_METADATA,
    }
}

#[must_use]
pub fn cli_version_output() -> String {
    format!(
        "{}\nBuild: {}\nCommit: {}\nTarget: {}",
        product_version_line(),
        build_profile(),
        commit_sha(),
        target_triple()
    )
}
