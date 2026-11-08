# RustHost 1.2.0 upgrade — 2026-11-08

## Release versions

The release compiler and minimum supported Rust version are both **1.99.1**.
The official [Rust announcement](https://blog.rust-lang.org/2026/10/15/Rust-1.99.1/)
and the installed Razer compiler confirm availability:
`rustc 1.99.1 (58cf8f9c3 2026-10-13)` and Clippy 0.1.99.
The toolchain file, CI, release workflow, audit workflow, container bootstrap,
README and contributor requirements use the patched compiler consistently.
CI also checks floating stable to surface future compiler changes. Releases
remain pinned; edition 2021 is retained.

The container retains its published Debian 12 bootstrap image
`rust:1.98.1-bookworm`, then installs and selects exactly Rust 1.99.1 via rustup.
Its non-root runtime, health check and data-volume behavior are retained.

## Dependencies

Stable versions were verified against the live
[crates.io API](https://crates.io/api/v1/crates/arti-client) on 2026-11-08,
then resolved with Cargo 1.99.1. Direct requirement minimums and Cargo.lock
were refreshed. All Arti/Tor crates advance together to **0.48.0**.

SQLite is the compatibility exception: rusqlite 0.41.1 is published, but
[tor-dirmgr 0.48.0](https://crates.io/api/v1/crates/tor-dirmgr/0.48.0/dependencies)
requires `>=0.36.0, <0.41.0`. The selected 0.40.2 is the newest compatible
stable line; bundled SQLite remains enabled to unify the native-library graph.
No prerelease or yanked versions were selected.

The unmaintained direct rustls-pemfile dependency was removed. Certificate
chains and supported private-key formats now use rustls-pki-types' `PemObject`
parser through rustls, preserving bounded reads, validation and certificate
expiry checks. Its obsolete advisory exception was removed from deny.toml.

| Direct dependency | Selected stable version |
|---|---|
| x509-cert | 0.3.0 |
| time | 0.3.55 |
| tokio-rustls | 0.26.6 |
| tokio-util | 0.7.20 |
| rustls | 0.23.46 |
| rustls-acme | 0.15.4 |
| webpki-roots | 1.0.11 |
| rcgen | 0.14.10 |
| tokio | 1.54.1 |
| arti-client | 0.48.0 |
| tor-hsservice | 0.48.0 |
| tor-cell | 0.48.0 |
| tor-rtcompat | 0.48.0 |
| futures | 0.3.34 |
| anyhow | 1.0.104 |
| sha3 | 0.12.0 |
| data-encoding | 2.11.1 |
| thiserror | 2.0.21 |
| serde | 1.0.229 |
| toml | 1.2.1+spec-1.1.0 |
| log | 0.4.35 |
| crossterm | 0.29.0 |
| chrono | 0.4.45 |
| libc | 0.2.191 |
| rusqlite | 0.40.2 |
| dashmap | 6.2.1 |
| percent-encoding | 2.3.2 |
| hyper | 1.12.0 |
| hyper-util | 0.1.21 |
| http-body-util | 0.1.5 |
| bytes | 1.12.1 |
| httpdate | 1.0.3 |
| async-compression | 0.4.52 |

## Lint policy

The manifest denies all, pedantic, nursery and cargo groups. Existing prohibitions
on unsafe code, unwrap/expect, panic, todo and unimplemented remain. Debug macros,
mem::forget, and the new Rust 1.99 `rest_pattern_accessible_field` and
`unnecessary_rest_pattern` restriction lints are denied explicitly. The new
compiler `raw_borrows_via_references` lint is also denied.

The versioned [Clippy 1.99 catalog](https://rust-lang.github.io/rust-clippy/rust-1.99.0/index.html)
was checked for additions, rather than inferring them from release numbering.
The groups cover the Rust 1.98 additions assert_is_empty, block_scrutinee,
by_ref_peekable_peek, for_unbounded_range, manual_bit_width,
manual_isolate_lowest_one, mismatched_bit_width_type,
nonnull_unchecked_on_box_ptr, unnecessary_unwrap_unchecked,
unused_async_trait_impl and with_capacity_zero. Unsafe-related cases remain
inapplicable under unsafe_code=forbid. The Rust 1.99
`definition_in_module_root` layout restriction was evaluated and left disabled:
it prescribes a different file organization without adding a runtime safeguard.
The restriction group as a whole is deliberately not enabled.

The log-worker shutdown destructuring now names the ignored path field explicitly.
Directory synchronization is compiled and called only on Unix, removing the
Windows no-op wrapper while retaining file flushes and Unix directory flushes.
Neither fix adds a lint allowance.

The former crate-wide multiple_crate_versions suppression and
renamed_and_removed_lints suppressions were removed. `clippy.toml` instead lists
only the known duplicate crate names required by the Arti/Tor, ACME/TLS, crypto
and derive-macro dependency graphs. New duplicate names fail the cargo lint
again. The active dependency-policy subset is recorded in deny.toml. Remove these
entries as upstream semver lines converge; forcing a single version now would
break upstream API or native-library constraints. Existing narrowly scoped
`#[expect(..., reason = ...)]` annotations retain their documented rationale.

Existing RSA signature-verification and upstream paste advisory exceptions remain
in force; this upgrade does not add RSA decryption or broaden those exceptions.

## Retired infrastructure and preserved data

Removed the project-owned unit-test modules, integration test harnesses and
helper module, and development-only tempfile/test-util declarations. Removed
local Playwright ignore entries; no Playwright harness or browser installation
exists in either inspected checkout, so no global browser tooling was touched.
The 10 static-site fixture files were moved byte-for-byte to
`docs/fixtures/html_stress/`; the reusable fixture generator remains.
Production path containment, request validation, readiness, bounds, persistence,
TLS validation and container smoke checks remain. Historical audit/changelog
records still describe the tests that existed when those records were written.

## Validation and platform limits

- Windows strict Clippy passes with all targets and features, warnings denied,
  and all/pedantic/nursery/cargo denied.
- Formatting and dependency advisories/bans/licenses/sources checks pass.
- Native `cargo +1.99.1 build --locked --release --workspace --all-features`
  passes on x86_64-pc-windows-msvc (optimized, LTO).
- All 23 isolated release probes pass: version/target/help and invalid CLI
  rejection; HTTP GET/HEAD; health/readiness; HTTPS with generated and manual PEM
  bundles; ETags, ranges and gzip; method, dotfile, traversal and null-byte guards;
  certificate reuse after restart; doctor preflight; manual certificate path
  containment; and three graceful Ctrl-C shutdowns with exit status 0.
- The fixture move preserves all 10 original working-copy byte sequences and
  Git blob hashes. Workflow YAML and all TOML configurations parse successfully.
- The old Rust tests are intentionally retired; these results are fresh release
  smoke probes against production code, not a claim that removed tests ran.
- This Razer has no installed WSL distribution or Docker command. Linux/macOS
  execution and container builds are unavailable locally. Existing native Linux,
  macOS and Windows build/release matrices remain; the quality matrix now checks
  both Linux and Windows. Their remote results are not claimed as local passes.
- No live public Tor onion-service or ACME issuance validation is claimed.
