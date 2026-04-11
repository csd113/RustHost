# Contributing to RustHost

Thank you for considering a contribution. This document explains the development
workflow, code standards, and review expectations so your time is spent well.

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Getting Started](#getting-started)
3. [Code Standards](#code-standards)
4. [Testing](#testing)
5. [Submitting a Pull Request](#submitting-a-pull-request)
6. [Architecture Overview](#architecture-overview)
7. [Issue Labels](#issue-labels)

---

## Prerequisites

| Tool | Minimum version | Notes |
|------|-----------------|-------|
| Rust (stable) | 1.90+ | matches the crate's `rust-version` in `Cargo.toml` |
| `cargo-deny` | latest | `cargo install cargo-deny` |

---

## Getting Started

```sh
git clone https://github.com/your-org/rusthost
cd rusthost

# Build and run tests
cargo test --all-targets --all-features

# Run clippy (same flags as CI)
cargo clippy --all-targets --all-features -- -D warnings

# Run the binary against a local directory
cargo run -- --serve ./my-site
```

---

## Code Standards

### Lint gates

Every file must pass the workspace-level gates declared in `Cargo.toml`:

```toml
[lints.rust]
unsafe_code = "forbid"

[lints.clippy]
all      = { level = "deny",  priority = -1 }
pedantic = { level = "deny",  priority = -1 }
nursery  = { level = "warn",  priority = -1 }
```

Use `#[allow(...)]` sparingly and always include a comment explaining why the
lint is suppressed.  Suppressions must be as narrow as possible — prefer a
targeted `#[allow]` on a single expression over a module-level gate.

### Comment style

- Explain **why**, not **what** — the code already says what it does.
- Never use opaque internal tags like `fix H-1` or `fix 3.2` in comments.
  Replace them with a sentence that makes sense to a new contributor.
- Doc comments (`///` and `//!`) must be written in full sentences and end with
  a period.

### No `unsafe`

`unsafe_code = "forbid"` is set at the workspace level. PRs that add `unsafe`
will not be merged.

### Error handling

All subsystems return `crate::Result<T>` (alias for `Result<T, AppError>`).
Avoid `.unwrap()` and `.expect()` in non-test code; use `?` propagation and
match on `AppError` variants at call sites that need to handle specific cases.

---

## Testing

```sh
# Unit tests only
cargo test --lib

# All tests (unit + integration)
cargo test --all-targets --all-features

# A specific test by name
cargo test percent_decode

# Dependency policy check
cargo deny check advisories bans licenses sources
```

Integration tests live in `tests/`. They import items re-exported from
`src/lib.rs` under `#[cfg(test)]` guards so they do not pollute the public API.

---

## Submitting a Pull Request

1. **Branch naming**: `fix/<short-description>` or `feat/<short-description>`.
2. **Commit messages**: use the imperative mood (`Add`, `Fix`, `Remove`), ≤72
   characters on the subject line.  Add a body paragraph for anything that
   needs explaining.
3. **One concern per PR**: a PR that mixes a bug fix with a refactor is harder
   to review and revert.
4. **Changelog**: add a line under `[Unreleased]` in `CHANGELOG.md` before
   opening the PR.
5. **CI must be green**: all three CI jobs (`test`, `lint`, `deny`) must pass.
   The `test` job runs on Ubuntu, macOS, and Windows.

---

## Architecture Overview

```
rusthost-cli (src/main.rs)
  └── runtime::lifecycle::run()
        ├── logging    — file logger + in-memory ring buffer for the console
        ├── server     — hyper HTTP/1.1 accept loop + per-connection handler
        ├── tor        — Arti in-process Tor client + onion service proxy
        ├── console    — crossterm TUI (render task + input task)
        └── config     — TOML loader + typed structs
```

Key data flows:

- **Request path**: `TcpListener::accept` → `server::handler::handle` →
  `resolve_path` → file I/O → hyper response.
- **Tor path**: `tor::init` → Arti bootstrap → `StreamRequest` loop →
  `proxy_stream` → local `TcpStream` → bidirectional copy.
- **Shared state**: `SharedState` (an `Arc<RwLock<AppState>>`) is the single
  source of truth for the dashboard.  Write only from the lifecycle/event tasks;
  read from the render task.

---

## Issue Labels

| Label | Meaning |
|-------|---------|
| `bug` | Confirmed defect |
| `security` | Security-relevant issue — see `SECURITY.md` for disclosure policy |
| `enhancement` | New feature or improvement |
| `good first issue` | Well-scoped, low-risk; suitable for new contributors |
| `help wanted` | We'd appreciate community input |
| `needs-repro` | Cannot reproduce; awaiting steps |
