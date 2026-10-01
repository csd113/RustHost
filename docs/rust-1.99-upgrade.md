# Rust 1.99 compiler upgrade — 2026-10-01

Development, CI platform builds, releases and container builds now use Rust 1.99.0,
replacing the Rust 1.91 compiler pin. Cargo's Rust 1.91 MSRV is retained because
it is the compatibility floor required by Arti 0.46, not the release compiler.
Edition 2021, dependencies, lockfile and application version 1.1.0 are unchanged.

CI explicitly selects the latest stable compiler for strict Clippy and full tests,
and Rust 1.91.0 for compatibility checks. Future stable releases must pass the
same validation before advancing reproducible toolchain and release pins.
There is no background updater or floating compiler in release builds.

The official Rust 1.99 Docker Bookworm tags were unavailable on release day.
The Dockerfile bootstraps from official rust:1.98.1-bookworm, then installs and
selects exact Rust 1.99.0 using official rustup. The resulting build compiler is
1.99.0; the Linux Debian 12 runtime and unprivileged UID 10001 remain unchanged.

The new duration-unit Clippy finding was fixed with Duration::from_hours(24),
which is available at the declared MSRV. No lint allowance or test removal was added.

## Validation

All checks passed locally on macOS Apple Silicon:

- cargo +1.99.0 fmt --all --check
- cargo +1.99.0 check --locked --workspace --all-features
- cargo +1.99.0 clippy --locked --workspace --all-targets --all-features -- -D warnings -D clippy::all -D clippy::pedantic -D clippy::nursery -D clippy::cargo
- cargo +1.99.0 test --locked --workspace --all-features: 352 tests passed; one existing documentation example ignored.
- cargo +1.99.0 build --locked --release --workspace --all-features
- cargo +1.91.0 check --locked --workspace --all-features
- Updated Docker multi-stage build on Linux ARM64 with two compiler jobs.
- Container version/target probe, HTTP /ready response and unprivileged user/data-layout smoke check.
- Workflow YAML parsing and git diff --check.

The other existing Linux x86-64, Windows and macOS CI/release target definitions
are retained; no new remote run or physical hardware validation is claimed.
The change is local only: no push, tag, production deployment or release.
