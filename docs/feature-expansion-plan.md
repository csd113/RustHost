# RustHost Feature Expansion Plan

This document sketches how to add the requested features to RustHost without fighting the current architecture.

It is grounded in the current codebase as of March 31, 2026:

- request handling lives in [src/server/handler.rs](/Users/connordawkins/Documents/GitHub/RustHost/src/server/handler.rs)
- bind/config parsing lives in [src/config/mod.rs](/Users/connordawkins/Documents/GitHub/RustHost/src/config/mod.rs) and [src/config/loader.rs](/Users/connordawkins/Documents/GitHub/RustHost/src/config/loader.rs)
- Tor lifecycle lives in [src/tor/mod.rs](/Users/connordawkins/Documents/GitHub/RustHost/src/tor/mod.rs)
- runtime state/metrics live in [src/runtime/state.rs](/Users/connordawkins/Documents/GitHub/RustHost/src/runtime/state.rs)
- integration coverage currently lives in [tests/http_integration.rs](/Users/connordawkins/Documents/GitHub/RustHost/tests/http_integration.rs)

## Current Status Snapshot

Two requested items are already partially present:

- IPv6 already works for a single explicit bind address because `server.bind` is typed as `IpAddr` and there is an integration test for `::1`.
- Pre-compressed asset serving is already implemented for sidecar variants in `serve_file()`, with existing coverage for `.br`.

The plan below therefore focuses on what still needs to be added or polished.

## 1. Optional Prometheus `/metrics` Endpoint

### Goal

Expose machine-readable metrics for headless/systemd deployments, but keep the feature disabled by default and avoid adding handler overhead when unused.

### Proposed config shape

Add a new block to [src/config/mod.rs](/Users/connordawkins/Documents/GitHub/RustHost/src/config/mod.rs):

```toml
[metrics]
enabled = false
path = "/metrics"
bind = "127.0.0.1"
port = 9090
include_process = true
```

Recommended rules:

- default `enabled = false`
- default to a separate listener instead of multiplexing on the main site port
- default bind to loopback for safer local scraping
- reject non-rooted paths and port conflicts in [src/config/loader.rs](/Users/connordawkins/Documents/GitHub/RustHost/src/config/loader.rs)

### Why a separate listener fits this codebase best

RustHost currently serves the site through Hyper in [src/server/handler.rs](/Users/connordawkins/Documents/GitHub/RustHost/src/server/handler.rs), but startup/shutdown orchestration is already split across multiple listeners in [src/runtime/lifecycle/support.rs](/Users/connordawkins/Documents/GitHub/RustHost/src/runtime/lifecycle/support.rs) and [src/server/redirect.rs](/Users/connordawkins/Documents/GitHub/RustHost/src/server/redirect.rs). A dedicated metrics listener fits that pattern and avoids:

- special-casing `/metrics` inside static file routing
- accidental public exposure on the main web port
- CSP/security-header interactions that do not matter for Prometheus

### Metrics to expose

Build this in layers:

1. Existing counters
   - total requests
   - total errors

2. Derived gauges/rates
   - active connections
   - requests/sec over a rolling window

3. Tor health
   - `rusthost_tor_up`
   - `rusthost_tor_bootstrap_state`
   - `rusthost_onion_service_up`

4. Tor traffic
   - bytes proxied from onion client to local server
   - bytes proxied from local server back to onion client

5. Process/system
   - resident memory
   - open FDs if available
   - CPU time / utilization if available

### Implementation notes

- Extend `Metrics` in [src/runtime/state.rs](/Users/connordawkins/Documents/GitHub/RustHost/src/runtime/state.rs) with more atomics:
  - `bytes_out_http`
  - `bytes_out_tor`
  - `tor_streams_active`
  - rolling-window state for request rate
- Add a tiny `src/metrics/mod.rs` module that:
  - owns Prometheus text rendering
  - starts a dedicated listener task
  - snapshots runtime state plus hot-path counters
- Keep the hot path cheap:
  - increment atomics in handlers
  - compute Prometheus text only when scraped
- Tor bandwidth should be counted inside the proxying copy loops in [src/tor/mod.rs](/Users/connordawkins/Documents/GitHub/RustHost/src/tor/mod.rs), not estimated from request sizes
- CPU/process stats may need an extra crate such as `sysinfo` or `heim`; if you want to keep deps small, gate those behind `include_process`

### Suggested exported metric names

- `rusthost_http_requests_total`
- `rusthost_http_errors_total`
- `rusthost_http_active_connections`
- `rusthost_http_requests_per_second`
- `rusthost_tor_streams_active`
- `rusthost_tor_bytes_in_total`
- `rusthost_tor_bytes_out_total`
- `rusthost_tor_bootstrap_state`
- `rusthost_tls_enabled`

## 2. IPv6 Support and Dual-Stack

### Current status

This is partly present already:

- `server.bind` is `IpAddr` in [src/config/mod.rs](/Users/connordawkins/Documents/GitHub/RustHost/src/config/mod.rs)
- the server binds via `SocketAddr::new(bind_addr, port)` in [src/server/mod.rs](/Users/connordawkins/Documents/GitHub/RustHost/src/server/mod.rs)
- there is an IPv6 integration test in [tests/http_integration.rs](/Users/connordawkins/Documents/GitHub/RustHost/tests/http_integration.rs)

### What is still missing

What the repo has today is "single address family bind," not a polished dual-stack feature.

### Proposed config evolution

Option A, minimal:

```toml
[server]
bind = "::"
dual_stack = true
```

Option B, more explicit and future-proof:

```toml
[server]
bind = ["0.0.0.0", "::"]
```

For RustHost, Option A is the least disruptive because current config parsing already assumes one bind value.

### Implementation approach

Add `dual_stack: bool` under `[server]` and switch bind logic in [src/server/mod.rs](/Users/connordawkins/Documents/GitHub/RustHost/src/server/mod.rs) from plain `StdTcpListener::bind()` to explicit socket setup for IPv6 listeners:

- if `bind` is IPv4: current behavior
- if `bind` is IPv6 and `dual_stack = false`: set `only_v6 = true`
- if `bind` is IPv6 and `dual_stack = true`: set `only_v6 = false`

That likely means introducing `socket2` so the listener can set `IPV6_V6ONLY` before bind.

### Scope notes

- Apply the same behavior to:
  - main HTTP listener
  - HTTPS listener
  - redirect listener
  - metrics listener if added
- Update console URL rendering in [src/console/dashboard.rs](/Users/connordawkins/Documents/GitHub/RustHost/src/console/dashboard.rs) so unspecified IPv6 binds do not produce awkward URLs for humans
- Add validation text and defaults in [src/config/defaults.rs](/Users/connordawkins/Documents/GitHub/RustHost/src/config/defaults.rs)

## 3. Test Expansion

### Current status

The existing integration suite is stronger than your request implies:

- IPv6 bind coverage already exists
- `.br` precompressed sidecar coverage already exists
- redirect server coverage already exists
- rate-limit/connection-limit coverage already exists

Still, the suite should be split and expanded.

### Recommended test layout

Break [tests/http_integration.rs](/Users/connordawkins/Documents/GitHub/RustHost/tests/http_integration.rs) into:

- `tests/http_core.rs`
- `tests/https_redirect.rs`
- `tests/spa_fallback.rs`
- `tests/rate_limiting.rs`
- `tests/precompressed.rs`
- `tests/tor_integration.rs`
- `tests/property_mime_and_paths.rs`

This keeps compile times and failure output saner.

### New integration tests

Add explicit tests for:

- Tor bootstrap smoke test
  - only when outbound network is available or behind an ignored-by-default feature flag
  - assert state transitions `Starting -> Ready` rather than depending on a full public-network scrape in normal CI
- HTTPS redirect end-to-end
  - start HTTPS + redirect listener together, not just the redirect module in isolation
- Rate limiting
  - distinguish global connection cap from per-IP cap
  - verify behavior under short bursts, not just one extra socket
- SPA fallback
  - unknown nested route returns `index.html` with `200` when `spa_routing = true`
  - same request returns `404` when disabled

### Property-based testing

Add `proptest` to `[dev-dependencies]` in [Cargo.toml](/Users/connordawkins/Documents/GitHub/RustHost/Cargo.toml).

For MIME in [src/server/mime.rs](/Users/connordawkins/Documents/GitHub/RustHost/src/server/mime.rs):

- extension lookup should never panic
- uppercase/lowercase variants should resolve identically
- overlong extensions should always fall back to `application/octet-stream`

For path traversal in [src/server/handler/pathing.rs](/Users/connordawkins/Documents/GitHub/RustHost/src/server/handler/pathing.rs):

- percent-decoding should never panic on arbitrary byte-like inputs encoded as strings
- any resolved path must either remain under `canonical_root` or be rejected
- dotfile blocking should hold across mixed separators and encoded segments

### Tor testing strategy

I would keep Tor tests in two layers:

- deterministic unit tests for helpers/state transitions
- opt-in integration tests for real Arti bootstrap

That avoids making normal CI flaky or internet-dependent.

## 4. Pre-Compressed Asset Serving

### Current status

This is already mostly implemented in [src/server/handler.rs](/Users/connordawkins/Documents/GitHub/RustHost/src/server/handler.rs):

- `Accept-Encoding` negotiation exists
- sidecar lookup exists via `open_precompressed_variant()`
- `.br` and `.gz` selection logic exists
- `Vary: Accept-Encoding` is set

### Remaining work

This item is better framed as "finish and harden" than "add from scratch."

Recommended follow-ups:

- add explicit `.gz` integration coverage, not just `.br`
- add `HEAD` coverage for precompressed sidecars
- ensure range requests never serve precompressed sidecars unless byte ranges for that encoded representation are intentionally supported
- document precedence clearly:
  - `.br` first
  - `.gz` fallback
  - dynamic compression only when no sidecar exists
- verify ETag semantics across original vs sidecar assets

### Possible enhancement

If the operator has disabled Brotli/Gzip generation logic in the future, tie sidecar serving to the same feature gates so behavior stays unsurprising.

## 5. `Onion-Location` Header

### Goal

When a request arrives over clearnet HTTPS and RustHost knows its `.onion` hostname, add:

```http
Onion-Location: https://<onion-host><request-path>
```

That lets supporting browsers advertise the onion endpoint.

### Where it fits

This belongs in response decoration in [src/server/handler.rs](/Users/connordawkins/Documents/GitHub/RustHost/src/server/handler.rs), alongside HSTS and the existing security-header logic.

### State plumbing needed

Today the handler gets `SharedMetrics`, but not shared app state. The onion hostname lives in [src/runtime/state.rs](/Users/connordawkins/Documents/GitHub/RustHost/src/runtime/state.rs).

The cleanest change is:

- pass a read-only shared runtime snapshot or shared state handle into handlers
- copy out `onion_address` when building the per-listener context in [src/server/mod.rs](/Users/connordawkins/Documents/GitHub/RustHost/src/server/mod.rs)

Avoid reading the full `RwLock` on every request if you can help it. A practical pattern is:

- keep `AppState` as-is for general state
- add a dedicated shared `ArcSwapOption<String>` or `watch::Receiver<Option<String>>` for the onion address

### Header injection rules

Only emit `Onion-Location` when all of these are true:

- the request is being served over HTTPS
- Tor is enabled and the onion address is known
- the current request is not already for an onion host
- the request path/query can be reconstructed safely

Suggested format:

- preserve path and query
- do not include a non-default port on the onion URL

### Test cases

Add integration tests that cover:

- HTTPS response includes `Onion-Location` when onion address is known
- HTTP response does not include it
- HTTPS response omits it when Tor is disabled or still bootstrapping
- query string is preserved

## Suggested Delivery Order

If we want the cleanest incremental rollout:

1. Finish test reorganization and add missing coverage
2. Add `Onion-Location`
3. Polish precompressed sidecar support
4. Add dual-stack IPv6
5. Add optional Prometheus listener last

That order keeps the early changes small and gives the metrics work better counters/state to build on.

## Suggested Dependency Additions

- `proptest` for property-based tests
- `socket2` for dual-stack listener control
- optionally `sysinfo` for process CPU/memory metrics

## Notes on Existing Overlap

If the goal is to market these as "new features," I would describe them this way:

- Prometheus endpoint: new
- IPv6 dual-stack: enhancement to existing IPv6-capable bind support
- test expansion: enhancement to an already solid integration suite
- precompressed sidecars: already present, needs broader coverage and docs
- `Onion-Location`: new
