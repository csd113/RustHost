# RustHost engineering audit — 2026-09-05

Reviewed startup and shutdown, HTTP/HTTPS/Tor admission and task ownership, request routing, filesystem containment, redirects, conditional requests, ranges, compression, logging, configuration, certificate persistence, Tor bootstrap/retry/relay behavior, metrics, site reload/scans, console/Doctor diagnostics, CLI/terminal launch, and build/CI/release workflows. This was a source and local regression audit, not a proof of correctness or a public-network penetration test. RustHost has no application-owned database schema or restore workflow; persistent Tor databases are managed by Arti.

**Verified problems fixed**

| Area | Finding and change |
|---|---|
| Connection admission | An accepting thread cloned an IP counter and released the map lock before incrementing it. The final departing connection could remove that counter, allowing concurrent listeners to create a second one and undercount active connections. Acquisition now holds the shard lock through the increment and explicitly releases it before returning. |
| TLS resource limits | Static and ACME handshakes could wait forever while holding the shared global/per-IP admission guard. A single 10-second deadline now covers ACME negotiation and the subsequent handshake. |
| Redirect request memory | `read_line` could allocate an arbitrarily large unterminated request/header line before checking its size. The underlying reader now caps consumption at 16 KiB plus one overflow-detection byte; incomplete headers are rejected. |
| Logging deadlock | Rotation called `log::warn!` while the application logger held its own file mutex. A rotation error recursively locked that mutex. Rotation diagnostics now go directly to stderr. A bounded subprocess regression forces the error with a temporary sparse log and an obstructed backup path. |
| Lifecycle | Closed shutdown channels could cause busy loops; the blocking console input thread could survive cancellation. Listeners/rendering now exit on channel closure, and input exits when its sender or receiver disappears. TLS/Tor-ingress/console startup errors take the cleanup path. Background task ownership cancels services on drop; timed-out HTTP/Tor/background tasks are aborted and joined instead of detached. |
| Path handling | Directory listing and SPA fallback could bypass the hidden-target check through a non-hidden symlink. Both now enforce the resolved-path policy. Directory redirects and listing links encode decoded filename delimiters, use a single leading slash, and redirects retain the query string. This also prevents decoded double slashes from producing an external, scheme-relative redirect. |
| File representation correctness | Brotli selection could fall back to a gzip sidecar even with `gzip;q=0`. Sidecars now follow the selected encoding. Identity and 304 responses include `Vary: Accept-Encoding`. Metadata ETags retain subsecond timestamps and sidecar tags are correctly weak. Satisfiable ranges clamp their end to EOF; HEAD ignores ranges. Conditional range requests receive the full representation because metadata-derived validators cannot establish byte identity. |
| One-shot root selection | A UTF-8 symlink pointing to a non-UTF-8 directory name could make `--serve` substitute `.` and serve the parent directory. Resolution now fails explicitly before runtime-directory creation, and requires an existing directory. |
| Dependency audit | CI used `--file audit.toml`; locally this exited successfully after scanning **zero dependencies**. Moved the existing configuration to `.cargo/audit.toml` and made CI explicitly scan `Cargo.lock`. The corrected command scanned **567 dependencies**. |

The HTTP changes follow the conservative range and representation rules in [RFC 9110](https://www.rfc-editor.org/rfc/rfc9110.html#name-range). The audit configuration location is documented in [cargo-audit's configuration implementation](https://github.com/rustsec/rustsec/blob/main/cargo-audit/src/config.rs).

**Observable changes and efficiency**

Idle TLS peers are disconnected after 10 seconds. Encoded directory URLs now redirect to the correct same-origin URL. Hidden symlink targets that previously slipped through listing/SPA paths return 403. Invalid one-shot roots fail at startup. Existing validators may cause one full refresh after the ETag format change. `If-Range` requests conservatively receive 200/full content, including validators that might otherwise match; supporting efficient conditional resumes needs a strong-validator strategy.

No throughput improvement is claimed. The useful efficiency changes are bounded redirect buffering, release of idle TLS slots, and elimination of closed-channel CPU spinning. The 80,000-attempt concurrent admission regression checks correctness, not throughput. Existing streaming file bodies, bounded directory-listing output, connection semaphores, and the bounded access-log queue were retained. Selecting Brotli without a Brotli sidecar may use streaming compression even if a gzip sidecar exists; this preserves the negotiated encoding at a possible CPU cost.

**Important issues left unchanged**

- **Tor and HTTP transfer timeouts:** `src/tor/mod.rs::relay_with_idle_timeout` times reads independently in each direction, but does not bound writes or shutdown. A download with no further upstream bytes can hit the 60-second upstream read timeout while downstream remains active. `src/server/handler.rs::IdleTimeoutStream` also only times reads. A follow-up should define connection-wide progress semantics and test sustained one-way transfers, half-close, and a stalled receiver; the handshake fix does not solve these cases.
- **Filesystem and persistent-state consistency:** static serving checks canonical paths before opening them, leaving a race if a local writer replaces the checked path. Special files such as FIFOs are not consistently excluded before opening. Self-signed key/certificate files are truncated separately, and reuse checks certificate expiry without first establishing a usable pair; a missing or mismatched key fails startup. First-run defaults use check-then-write. These need secure handle-based access and a tested publication/recovery design, rather than silently replacing persistent identities or changing symlink support. No user certificate, Tor state, or settings file was rewritten by this audit.
- **Reload is not one coherent snapshot:** accept loops update the canonical root only between accepts; existing connections retain their old root, while favicon containment and cached custom-error pages retain startup state. Switching a site symlink during reload can expose mixed generations or reject the favicon. An immutable per-request site snapshot should be considered with explicit compatibility tests. No broad reload redesign was included.
- **Lifetime visitor retention:** `Metrics::visitor_keys` retains one hash per distinct clearnet identity without a cap or expiry. IPv6 address churn can increase memory for the process lifetime. Capping, expiring, or approximating this count changes the displayed metric's meaning, so that policy was not chosen implicitly.
- **Blocking work and observability:** manual TLS reads, some favicon/sidecar lookups, application logging, and console diagnostics still perform synchronous I/O in async paths. Application log writes can fail silently; access-log shutdown joins a blocking writer. Site scans can report success with skipped/unreadable directories, and `/ready` probes log-directory writability even when file logging is disabled. These deserve slow-filesystem and fault-injection testing before changing operational policy or restructuring workers.
- **Dependency maintenance:** the corrected audit reports unmaintained `bincode` (RUSTSEC-2025-0141), `paste` (RUSTSEC-2024-0436), and `rustls-pemfile` (RUSTSEC-2025-0134). Existing RSA advisory policy was preserved. No new suppressions or dependency upgrades were introduced. Migrating the direct PEM dependency is a separate compatibility change; transitive replacements depend on the Tor dependency graph.

Cosmetic module reshuffling, speculative allocation tuning, generalized HTTP abstractions, and duplicate-version churn were intentionally avoided.

**Validation**

- `cargo fmt --all --check` — passed after formatting only touched Rust files.
- `cargo clippy --workspace --all-targets --all-features -- -D warnings -D clippy::all -D clippy::pedantic -D clippy::nursery -D clippy::cargo` — passed.
- `cargo test --workspace --all-features` — **328 passed**, one existing doctest ignored: 274 library tests, 6 CLI tests, 1 HTML stress test, 46 HTTP integration tests, and 1 doctest passed.
- `cargo test --workspace --all-features --lib` was also used during development. An existing range assertion was updated to preserve out-of-bounds coverage while separately testing EOF clamping.
- `cargo audit --deny unsound --file Cargo.lock` — passed with three unmaintained-dependency warnings after fetching 1,239 advisories; scanned 567 dependencies.
- `cargo audit --deny unsound --file audit.toml --no-fetch` — reproduced the original CI defect before relocating the configuration: successful exit, zero dependencies scanned.
- `git diff --check` — passed.

Tests ran on macOS Apple Silicon using isolated temporary files and loopback listeners. APFS rejects non-UTF-8 names, so the symlink/root-selection filesystem regression is Linux-only and was not executed here. Linux/Windows runtime behavior, live Tor bootstrap/reconnection, external ACME issuance/renewal, crash recovery, and production load/slow-I/O behavior still need platform-specific testing. The CI workflow command was exercised locally; no GitHub workflow or release was triggered.

**Files changed**

- `.github/workflows/audit.yml`
- `audit.toml` moved to `.cargo/audit.toml` (existing advisory policy retained)
- `src/console/input.rs`, `src/console/mod.rs`
- `src/logging/mod.rs`
- `src/runtime/lifecycle.rs`, `src/runtime/lifecycle/support.rs`
- `src/server/admission.rs`, `src/server/mod.rs`, `src/server/redirect.rs`
- `src/server/handler.rs`, `src/server/handler/pathing.rs`
- `tests/http_integration.rs`
- `docs/engineering-audit-2026-09-05.md`

`Cargo.lock` was already modified before the audit; its existing dependency selection was preserved. No new dependencies or commits were created.
