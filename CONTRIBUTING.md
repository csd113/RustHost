# Contributing

[Home](README.md) · [Setup](SETUP.md) · [Operations](docs/operations.md)

## Build from source

Binary users do not need these tools. For development, install Rust through rustup and native build tools: Visual Studio's C++ workload on Windows, Xcode Command Line Tools on macOS, or a C compiler and build tools on Linux.

```sh
git clone https://github.com/csd113/RustHost.git
cd RustHost
cargo build --locked --release
```

The binary is `target/release/rusthost-cli` (`rusthost-cli.exe` on Windows). The checkout's `rust-toolchain.toml` selects Rust **1.99.1**, also the minimum compiler in `Cargo.toml`. CI checks both that pin and current stable. No global rustup default change is needed.

For a local development run with the retained sample site:

```sh
cargo run -- --serve ./docs/fixtures/html_stress --no-tor
```

## Validate changes

Install the dependency-checking tools once:

```sh
cargo install --locked cargo-deny cargo-audit
```

Run the gates used by the project:

```sh
cargo fmt --all --check
cargo check --locked --workspace --all-targets --all-features
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings -D clippy::all -D clippy::pedantic -D clippy::nursery -D clippy::cargo
cargo build --locked --release --workspace --all-features
cargo deny check advisories bans licenses sources
cargo audit --deny unsound --file Cargo.lock
```

Audit the lockfile, not `.cargo/audit.toml`: the latter is policy configuration. Confirm the audit reports a nonzero dependency count.

Project-owned unit and integration harnesses were retired in 1.2.0. Validate behavior changes against an isolated data directory using the built binary. Cover the affected paths and, for releases, version/help, Doctor, GET/HEAD, health/readiness, TLS, ranges, caching, compression, path rejection, persisted certificate reuse, and graceful shutdown. Do not use an operator's live data for smoke checks.

CI runs Linux/Windows formatting and lint jobs and Linux ARM64, macOS Apple Silicon, and Windows build jobs. The required status named `Tests` is a legacy name for a production Cargo check; it does not run the retired tests. `Quality` aggregates the lint matrix. Docker CI separately builds both architectures and checks container readiness and persistent-volume setup. A build or local smoke check does not establish live Tor, ACME renewal, power-loss recovery, or production-load behavior.

## Code and dependency policy

- Keep changes focused. Explain the problem, resulting behavior, and validation in the PR.
- Unsafe code is forbidden. Propagate errors or handle them explicitly; the lint policy rejects unwrap/expect, panic, todo, and unimplemented calls.
- Explain non-obvious decisions in comments. Keep lint exceptions narrow and give a reason; use the existing `#[expect(..., reason = ...)]` style where appropriate.
- Update config types, validation, generated defaults, and user documentation together when settings change.
- Add user-facing changes to the changelog. Preserve historical entries as records of their releases.

The manifest denies Clippy's `all`, `pedantic`, `nursery`, and `cargo` groups plus selected restrictions. It also denies `raw_borrows_via_references`; the selected 1.99 restrictions include `rest_pattern_accessible_field` and `unnecessary_rest_pattern`. The entire restriction group is not enabled: rules can conflict or impose unrelated style choices. `definition_in_module_root` was evaluated and left disabled because it prescribes a different module layout without adding a runtime safeguard.

[clippy.toml](clippy.toml) lists known duplicate crate names required by incompatible Arti/Tor, TLS/ACME, crypto, and derive-macro dependency lines. Unexpected duplicate names still fail the lint. [deny.toml](deny.toml) records the dependency-policy subset. Remove exceptions as upstream versions converge; do not force incompatible libraries onto one version merely to silence a warning.

The existing advisory exceptions cover RSA used by Arti for signature verification (not RSA decryption) and the upstream unmaintained `paste` dependency. Their exact IDs and reasons are in `deny.toml` and [.cargo/audit.toml](.cargo/audit.toml). Re-evaluate these when upgrading dependencies. Bundled rusqlite stays on 0.40.2 because Arti 0.48 requires `<0.41`.

## Find the code

| Location | Responsibility |
| --- | --- |
| `src/main.rs` | CLI parsing and process entry |
| `src/runtime/` | Startup, shutdown, events, shared status |
| `src/config/` | Typed settings, validation, generated defaults |
| `src/server/` | HTTP handling, admission, site snapshots, files and redirects |
| `src/tls/` | Manual and development certificates, ACME and its cache |
| `src/tor/` | In-process Arti lifecycle and onion stream relay |
| `src/console/` | Dashboard, input, menus, Doctor and diagnostics |
| `src/logging/` | File logging and console log buffer |
| `src/persistence.rs` | Atomic publication and cooperating-writer locks |
| `src/io_timeout.rs` | Connection progress and I/O deadlines |
| `.github/workflows/` | Quality, audit, container and release automation |

The 10 files in `docs/fixtures/html_stress/` are a small sample site. `docs/generate-static-stress-site.sh` is an optional Bash generator for a larger manual fixture; its default output is `test-sites/static-stress/`. **It deletes and recreates its output directory.** Use only a disposable output path. Optional Python/ffmpeg support adds media assets.

## Submit and release

Open a focused pull request and let the required checks pass before merging. Do not bypass protected-branch requirements. Include reproduction steps for bugs; avoid putting secrets or private site data in issues or logs.

For a compiler upgrade, update the toolchain, manifest minimum, CI, release, audit, and container pins together, then run the gates above. Keep the release compiler pinned even though CI also checks stable.

The release workflow requires the `v` tag to match the package version and a matching `[vX.Y.Z]` changelog entry. It packages binaries, README, and LICENSE for four targets and publishes a verified `SHA256SUMS.txt`. Container automation publishes release version/minor tags and main-branch `edge` builds. These workflows are the source of truth for packaging; tagging and publishing are separate release actions.
