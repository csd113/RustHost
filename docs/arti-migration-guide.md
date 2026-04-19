# Migrating from C Tor Subprocess to Arti (In-Process Tor)

This document describes exactly how a Rust project was migrated from
spawning the system C Tor binary as a subprocess to running Arti, the
official Tor Project Rust implementation, fully in-process. Use this as a
step-by-step reference for applying the same migration to other projects.

> **Tested against:** `arti-client 0.41.0`, `tor-hsservice 0.41.0`, `tor-cell 0.41.0`
> on Rust 1.90 (macOS arm64 + x86, Linux x86_64).

---

## Background: What the Old System Did

The original approach (common in many Rust projects) worked like this:

1. **Binary search** — scan a hardcoded list of filesystem paths plus `PATH`
   for the `tor` executable at runtime.
2. **Directory setup** — create `tor_data/` and `tor_hidden_service/` with
   `chmod 0700` (C Tor refuses to start if it doesn't own those dirs).
3. **torrc generation** — write a `torrc` file to disk with `SocksPort 0`
   (disables the SOCKS proxy to avoid conflict with any system Tor daemon),
   `DataDirectory`, `HiddenServiceDir`, and `HiddenServicePort`.
4. **Process spawn** — `Command::new(tor_bin).arg("-f").arg(&torrc_path).spawn()`
5. **stderr collection** — pipe stderr into a background thread for diagnostics.
6. **Panic hook** — register a panic hook to kill the child if the process crashes.
7. **Hostname polling** — spin a background thread checking for
   `tor_hidden_service/hostname` every 500 ms for up to 120 seconds.
8. **Shutdown** — `child.kill()` + `child.wait()` in a `kill()` function called
   during graceful shutdown.

This required the user to have Tor installed (`brew install tor`,
`apt-get install tor`, etc.) and produced two runtime artifacts on disk:
`torrc` and `tor_hidden_service/hostname`.

---

## Why Arti Replaces This Cleanly

Arti is the Tor Project's own Rust rewrite of the C Tor client. As of the
2.x release series (February 2026), it supports onion service *hosting*
(not just connecting). Because it is a Rust crate, it compiles directly into
your binary — no external binary, no torrc, no hostname file polling.

The `arti-client` crate provides a high-level async API. The `tor-hsservice`
crate provides the onion service types. Both are first-party from the Tor
Project and versioned together.

---

## Step 1 — Cargo.toml Changes

### MSRV

Arti 0.41+ requires Rust **1.90** in this codebase. If your project targets
1.89 or lower, bump it:

```toml
# Before
rust-version = "1.89"

# After
rust-version = "1.90"
```

### Add dependencies

Add these six entries to `[dependencies]`:

```toml
# arti-client: high-level Tor client. Features needed for onion service hosting:
#   tokio                 — Tokio async runtime backend (required)
#   rustls                — TLS for connecting to Tor relays (required)
#   onion-service-service — enables *hosting* onion services
arti-client = { version = "0.41", features = [
    "tokio",
    "rustls",
    "onion-service-service",
] }

# tor-hsservice: lower-level onion service types used directly:
#   OnionServiceConfigBuilder, handle_rend_requests, HsId, StreamRequest
tor-hsservice = { version = "0.41" }

# tor-cell: needed to construct the Connected message passed to
#   StreamRequest::accept(Connected) — see the stream proxying section
tor-cell = { version = "0.41" }

# futures: StreamExt::next() for iterating the stream of incoming connections
futures = "0.3"

# sha3 + data-encoding: used to encode HsId → "${base32}.onion" manually.
# HsId does not implement std::fmt::Display in arti-client 0.41 — see the
# "Getting the onion address" section for the full explanation.
sha3 = "0.10"
data-encoding = "2"
```

### Remove nothing from existing deps

`tokio`, `log`, `serde`, etc. are unchanged. No existing dep needs to be
removed.

---

## Step 2 — Delete `src/tor/torrc.rs`

If your project has a separate module for generating `torrc` files, delete it.
There is no torrc concept with Arti — configuration is built in Rust code.

If it was declared as `mod torrc;` anywhere, remove that declaration too.

---

## Step 3 — Rewrite `src/tor/mod.rs`

This is the entire migration. Everything else in the project stays the same.

### Imports

```rust
// Old imports — remove all of these
use std::{
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{Arc, Mutex, OnceLock},
};

// New imports
use std::path::PathBuf;

use arti_client::config::TorClientConfigBuilder;
use arti_client::TorClient;
use futures::StreamExt;
use tokio::net::TcpStream;
use tor_cell::relaycell::msg::Connected;
use tor_hsservice::{config::OnionServiceConfigBuilder, handle_rend_requests, HsId, StreamRequest};
```

Notes on the import changes:
- `TorClientConfig` is **not** imported — it is not used directly. The builder is accessed via `TorClientConfigBuilder` instead (see the config section below).
- `HsId` is imported from `tor_hsservice`, **not** from `arti_client`. In arti 0.41, the re-export in `arti_client` is gated behind `feature = "onion-service-client"` and `feature = "experimental-api"` — neither of which is enabled in this setup. `tor_hsservice::HsId` is the ungated path.

---

### `init()` — public signature unchanged

The public API surface stays identical so nothing that calls `tor::init()`
needs to change. The only internal difference is switching from
`std::thread::spawn` to `tokio::spawn`, since the work is now async:

```rust
// Old
pub fn init(data_dir: PathBuf, bind_port: u16, state: SharedState) {
    std::thread::spawn(move || {
        run_sync(data_dir, bind_port, state);
    });
}

// New
pub fn init(data_dir: PathBuf, bind_port: u16, state: SharedState) {
    tokio::spawn(async move {
        if let Err(e) = run(data_dir, bind_port, state.clone()).await {
            log::error!("Tor: fatal error: {e}");
            set_status(&state, TorStatus::Failed(None)).await;
        }
    });
}
```

---

### `kill()` — becomes a no-op

```rust
// Old — had to kill and reap the subprocess
pub fn kill() {
    if let Some(child) = TOR_CHILD.get() {
        if let Ok(mut c) = child.lock() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

// New — nothing to do; TorClient drops with the task
pub fn kill() {}
```

The call site in your shutdown sequence does not need to change. The
`TorClient` is owned by the `tokio::spawn` task. When the Tokio runtime
shuts down, the task is dropped, which drops `TorClient`, which closes all
circuits cleanly.

---

### The `OnceLock<Arc<Mutex<Child>>>` static — remove entirely

```rust
// Old — remove this
static TOR_CHILD: OnceLock<Arc<Mutex<std::process::Child>>> = OnceLock::new();
```

There is no process handle to track. Delete it along with the panic hook
that referenced it.

---

### Building `TorClientConfig` — the CfgPath pitfall

> ⚠️ **This is the most common compile error when migrating.**

The `StorageConfigBuilder` methods `.cache_dir()` and `.state_dir()` take
`Into<CfgPath>`, and `CfgPath` does **not** implement `From<PathBuf>`. If you
try to pass a `PathBuf` directly you get:

```
error[E0277]: the trait bound `CfgPath: From<PathBuf>` is not satisfied
```

**Do not use** `.storage().cache_dir().state_dir()`. Instead use
`TorClientConfigBuilder::from_directories`, which takes `AsRef<Path>` and
handles the conversion internally.

> ⚠️ **A second pitfall:** `from_directories` is an *associated function*, not
> a method — it cannot be chained off `.builder()`. Doing so produces:
> ```
> error[E0599]: no method named `from_directories` found for struct `TorClientConfigBuilder`
> note: found the following associated functions; to be used as methods,
>       functions must have a `self` parameter
> ```

```rust
// Wrong — does not compile (CfgPath conversion fails)
let config = {
    let mut b = TorClientConfig::builder();
    b.storage()
        .cache_dir(data_dir.join("arti_cache"))   // ← E0277
        .state_dir(data_dir.join("arti_state"));  // ← E0277
    b.build()?
};

// Wrong — also does not compile (from_directories has no `self`, cannot chain)
let config = TorClientConfig::builder()
    .from_directories(                            // ← E0599
        data_dir.join("arti_state"),
        data_dir.join("arti_cache"),
    )
    .build()?;

// Correct — call from_directories directly on TorClientConfigBuilder
let config = TorClientConfigBuilder::from_directories(
    data_dir.join("arti_state"),
    data_dir.join("arti_cache"),
)
.build()?;
```

Note the argument order is `(state_dir, cache_dir)` — state first, cache second.

Two directories are created automatically on first run:
- `arti_state/` — service keypair. **Determines your `.onion` address.**
  Keep it to preserve the address across restarts. Delete it to rotate.
- `arti_cache/` — consensus cache. Safe to delete; re-downloaded on next run.

Without setting these paths explicitly, Arti defaults to platform-specific
user directories. Always set them explicitly so everything lives inside your
project's data directory.

---

### Bootstrap

```rust
// Old
let child = Command::new(tor_bin)
    .arg("-f").arg(&torrc_path)
    .stdout(Stdio::null())
    .stderr(Stdio::piped())
    .spawn();

// New
let tor_client = TorClient::create_bootstrapped(config).await?;
```

`create_bootstrapped` async-blocks until Tor has downloaded enough directory
information to open circuits. First run takes ~30 seconds (~2 MB download).
Subsequent runs complete in a few seconds using the cached consensus.

The old stderr collection thread and panic hook are deleted entirely — there
is no subprocess stderr to collect and no child process to kill on panic.

---

### Getting the onion address — Display is not implemented on HsId

> ⚠️ **Three separate pitfalls here, not two.**

**Pitfall 1:** `onion_name()` is deprecated. Use `onion_address()` instead.

**Pitfall 2:** `HsId` does **not** implement `std::fmt::Display` in
`arti-client 0.41`. Neither `format!("{}", hsid)` nor `.to_string()` compile,
regardless of whether you got the `HsId` from `onion_name()` or
`onion_address()`:

```
error[E0599]: `HsId` doesn't implement `std::fmt::Display`
```

`HsId` implements `DisplayRedacted` from the `safelog` crate instead, which
intentionally opts out of `std::fmt::Display` to prevent accidental logging of
sensitive identifiers. `format!("{}", ...)` and `.to_string()` both require
`Display` — neither works.

**Pitfall 3:** `HsId` in `arti_client` is gated behind two features
(`onion-service-client` and `experimental-api`). If you try
`arti_client::HsId` without enabling those features:

```
error[E0425]: cannot find type `HsId` in crate `arti_client`
note: found an item that was configured out
note: the item is gated behind the `onion-service-client` feature
```

Import `HsId` from `tor_hsservice` instead — it is ungated there.

**The correct pattern** — encode the address manually from the raw key bytes:

```rust
// Wrong — deprecated
let onion_name = onion_service.onion_name()?.to_string();  // ← deprecated + E0599

// Wrong — onion_address() returns HsId, which still has no Display in 0.41
let onion_name = format!(
    "{}",
    onion_service.onion_address().ok_or("...")?              // ← E0599
);

// Wrong — same problem, HsId::to_string() doesn't exist
let onion_name = onion_service.onion_address().ok_or("?")?.to_string();  // ← E0599

// Correct — encode the address ourselves using the v3 onion address spec
let hsid = onion_service
    .onion_address()
    .ok_or("Tor: onion address not yet available")?;
let onion_name = hsid_to_onion_address(hsid);
```

Where `hsid_to_onion_address` is:

```rust
fn hsid_to_onion_address(hsid: HsId) -> String {
    use sha3::{Digest, Sha3_256};

    let pubkey: &[u8; 32] = hsid.as_ref();  // HsId: AsRef<[u8; 32]> is stable
    let version: u8 = 3;

    // CHECKSUM = SHA3-256(".onion checksum" || PUBKEY || VERSION) truncated to 2 bytes
    let mut hasher = Sha3_256::new();
    hasher.update(b".onion checksum");
    hasher.update(pubkey);
    hasher.update([version]);
    let hash = hasher.finalize();

    // ADDRESS_BYTES = PUBKEY (32) || CHECKSUM (2) || VERSION (1) = 35 bytes
    let mut address_bytes = [0u8; 35];
    address_bytes[..32].copy_from_slice(pubkey);
    address_bytes[32..34].copy_from_slice(&hash[..2]);
    address_bytes[34] = version;

    // RFC 4648 base32, no padding, lowercase → 56 characters
    let encoded = data_encoding::BASE32_NOPAD
        .encode(&address_bytes)
        .to_ascii_lowercase();

    format!("{}.onion", encoded)
}
```

This implements the [v3 onion address spec](https://spec.torproject.org/rend-spec/overview.html)
directly. `HsId: AsRef<[u8; 32]>` is stable across arti 0.41+, so it will
keep working regardless of whether `Display` is ever added to `HsId`.

The address is available immediately when `launch_onion_service` returns —
no polling required.

---

### Incoming connections — replacing `HiddenServicePort` and accepting streams

> ⚠️ **`StreamRequest::accept()` requires a `Connected` argument.**

In the old torrc, `HiddenServicePort 80 127.0.0.1:{port}` told C Tor to
forward incoming connections to your local server automatically. With Arti
you handle this yourself.

**`handle_rend_requests`** takes the `Stream<Item = RendRequest>` from
`launch_onion_service`, auto-accepts each Tor rendezvous handshake, and
yields a `StreamRequest` for every fully-established inbound connection.

**`stream_req.accept(Connected)`** sends a `RELAY_CONNECTED` cell back to
the Tor client (confirming the connection succeeded) and returns the
`DataStream` you can read and write. It requires a `Connected` argument —
calling it with no arguments fails to compile:

```
error[E0061]: this method takes 1 argument but 0 arguments were supplied
    --> src/tor/mod.rs:194:37
     |
     | let mut tor_stream = stream_req.accept().await?;
     |                                  ^^^^^^-- argument #1 of type
     |                       `tor_cell::relaycell::msg::Connected` is missing
```

For hidden services, use `Connected::new_empty()`. This is correct because
you are the service — there is no exit IP to report to the client:

```rust
// Wrong — missing argument
let mut tor_stream = stream_req.accept().await?;

// Correct
let mut tor_stream = stream_req.accept(Connected::new_empty()).await?;
```

The full stream loop:

```rust
let mut stream_requests = handle_rend_requests(rend_requests);

while let Some(stream_req) = stream_requests.next().await {
    let local_addr = format!("127.0.0.1:{bind_port}");
    tokio::spawn(async move {
        if let Err(e) = proxy_stream(stream_req, &local_addr).await {
            log::debug!("Tor: stream closed: {e}");
        }
    });
}
```

```rust
async fn proxy_stream(
    stream_req: StreamRequest,
    local_addr: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut tor_stream = stream_req.accept(Connected::new_empty()).await?;
    let mut local = TcpStream::connect(local_addr).await?;
    tokio::io::copy_bidirectional(&mut tor_stream, &mut local).await?;
    Ok(())
}
```

`DataStream` implements `tokio::io::AsyncRead + AsyncWrite` when compiled
with the `tokio` feature on `arti-client`, so `copy_bidirectional` works
with no adapter.

---

### State helpers — switch from `blocking_write()` to `.await`

The old code ran on `std::thread` so it had to use `blocking_write()` on the
`tokio::sync::RwLock`. The new code runs inside `tokio::spawn`, so use the
normal async form:

```rust
// Old (on std::thread — must use blocking variant)
fn set_status(state: &SharedState, status: TorStatus) {
    state.blocking_write().tor_status = status;
}

// New (inside tokio::spawn — use normal async)
async fn set_status(state: &SharedState, status: TorStatus) {
    state.write().await.tor_status = status;
}
```

---

## Step 4 — Fix any unused import warnings in other files

When removing the subprocess approach you may expose a pre-existing unused
import warning elsewhere. In this project, `src/runtime/events.rs` had:

```rust
// Before — Arc was imported but not used in events.rs
use std::{path::PathBuf, sync::Arc};

// After
use std::path::PathBuf;
```

This was always there but was silenced by the previous build error. Once
the errors are fixed, `#[warn(unused_imports)]` surfaces it.

---

## Step 5 — Update comments, docs, and user-facing strings

Search for and update any references to:

| Old text | Replace with |
|---|---|
| `brew install tor` | Remove — Tor is built-in, no install required |
| `apt-get install tor` | Same |
| `tor_hidden_service/hostname` | `arti_state/keys/` |
| `torrc` | Remove — config is built in Rust code |
| `SocksPort 0` | Not applicable |
| `spawns std threads` | `spawns a Tokio task` |
| `Kill the Tor subprocess` | `Drop the Arti TorClient` |

In any first-run setup output, replace the `brew`/`apt-get` install
instructions with a note that Tor is built-in and the first run takes ~30 s.

---

## Complete `src/tor/mod.rs` After Migration

```rust
use std::path::PathBuf;

use arti_client::config::TorClientConfigBuilder;
use arti_client::TorClient;
use futures::StreamExt;
use tokio::net::TcpStream;
use tor_cell::relaycell::msg::Connected;
use tor_hsservice::{config::OnionServiceConfigBuilder, handle_rend_requests, HsId, StreamRequest};

use crate::runtime::state::{SharedState, TorStatus};

pub fn init(data_dir: PathBuf, bind_port: u16, state: SharedState) {
    tokio::spawn(async move {
        if let Err(e) = run(data_dir, bind_port, state.clone()).await {
            log::error!("Tor: fatal error: {e}");
            set_status(&state, TorStatus::Failed(None)).await;
        }
    });
}

pub fn kill() {}

async fn run(
    data_dir: PathBuf,
    bind_port: u16,
    state: SharedState,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    set_status(&state, TorStatus::Starting).await;

    let config = TorClientConfigBuilder::from_directories(
        data_dir.join("arti_state"),
        data_dir.join("arti_cache"),
    )
    .build()?;

    log::info!("Tor: bootstrapping — first run downloads ~2 MB (~30 s)");

    let tor_client = TorClient::create_bootstrapped(config)
        .await
        .map_err(|e| format!("Tor bootstrap failed: {e}"))?;

    log::info!("Tor: connected to the Tor network");

    let svc_config = OnionServiceConfigBuilder::default()
        .nickname("your-app-name".parse()?)
        .build()?;

    let (onion_service, rend_requests) = tor_client
        .launch_onion_service(svc_config)?
        .ok_or("Tor: onion service returned None")?;

    let hsid = onion_service
        .onion_address()
        .ok_or("Tor: onion address not yet available")?;
    let onion_name = hsid_to_onion_address(hsid);

    log::info!("Tor: onion service active — http://{onion_name}");
    set_onion(&state, onion_name).await;

    let mut stream_requests = handle_rend_requests(rend_requests);

    while let Some(stream_req) = stream_requests.next().await {
        let local_addr = format!("127.0.0.1:{bind_port}");
        tokio::spawn(async move {
            if let Err(e) = proxy_stream(stream_req, &local_addr).await {
                log::debug!("Tor: stream closed: {e}");
            }
        });
    }

    log::warn!("Tor: stream_requests stream ended");
    Ok(())
}

async fn proxy_stream(
    stream_req: StreamRequest,
    local_addr: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut tor_stream = stream_req.accept(Connected::new_empty()).await?;
    let mut local = TcpStream::connect(local_addr).await?;
    tokio::io::copy_bidirectional(&mut tor_stream, &mut local).await?;
    Ok(())
}

fn hsid_to_onion_address(hsid: HsId) -> String {
    use sha3::{Digest, Sha3_256};

    let pubkey: &[u8; 32] = hsid.as_ref();
    let version: u8 = 3;

    let mut hasher = Sha3_256::new();
    hasher.update(b".onion checksum");
    hasher.update(pubkey);
    hasher.update([version]);
    let hash = hasher.finalize();

    let mut address_bytes = [0u8; 35];
    address_bytes[..32].copy_from_slice(pubkey);
    address_bytes[32..34].copy_from_slice(&hash[..2]);
    address_bytes[34] = version;

    let encoded = data_encoding::BASE32_NOPAD
        .encode(&address_bytes)
        .to_ascii_lowercase();

    format!("{}.onion", encoded)
}

async fn set_status(state: &SharedState, status: TorStatus) {
    state.write().await.tor_status = status;
}

async fn set_onion(state: &SharedState, addr: String) {
    let mut s = state.write().await;
    s.tor_status = TorStatus::Ready;
    s.onion_address = Some(addr);
}
```

---

## Summary of Every Changed File

| File | Change |
|---|---|
| `Cargo.toml` | `rust-version` 1.89 → 1.90; add `arti-client`, `tor-hsservice`, `tor-cell`, `futures`, `sha3`, `data-encoding` |
| `src/tor/mod.rs` | Complete rewrite (see above) |
| `src/tor/torrc.rs` | Delete |
| `src/config/defaults.rs` | Update `[tor]` comment block |
| `src/runtime/lifecycle.rs` | Update first-run message + shutdown comment |
| `src/runtime/events.rs` | Remove unused `sync::Arc` import |

Every other file — server, console, state, config loader, logging, main —
is completely unchanged. The public API of the `tor` module (`init`, `kill`)
stays identical.

---

## Compile Errors Reference

A summary of every real error encountered during this migration, with the
exact fix for each one.

| Error | Cause | Fix |
|---|---|---|
| `E0277: CfgPath: From<PathBuf>` | Used `.storage().cache_dir(PathBuf)` | Use `TorClientConfigBuilder::from_directories(state, cache)` |
| `E0599: no method named 'from_directories'` | Called `TorClientConfig::builder().from_directories(…)` as a method chain | `from_directories` is an associated function — call it as `TorClientConfigBuilder::from_directories(…).build()?` directly |
| `deprecated: onion_name` | Called `.onion_name()` | Use `.onion_address()` instead |
| `E0599: HsId doesn't implement Display` | Called `format!("{}", hsid)` or `.to_string()` on `HsId` | `HsId` has no `Display` in arti 0.41. Add `sha3 = "0.10"` and `data-encoding = "2"` deps and encode the address manually with `hsid_to_onion_address(hsid)` using `HsId: AsRef<[u8; 32]>` |
| `E0425: cannot find type 'HsId' in crate 'arti_client'` | Wrote `arti_client::HsId` in function signature | `HsId` is feature-gated in `arti_client`. Import it from `tor_hsservice::HsId` instead — it is ungated there |
| `E0061: accept() takes 1 argument` | Called `stream_req.accept()` with no args | Use `stream_req.accept(Connected::new_empty())` |
| `warn(unused_imports): sync::Arc` | Pre-existing unused import unmasked | Remove `Arc` from the import line |

---

## Data Directory Layout: Before and After

**Before** (C Tor subprocess):
```
your-data-dir/
  tor_data/            ← C Tor's DataDirectory (0700)
  tor_hidden_service/  ← C Tor's HiddenServiceDir (0700)
    hostname           ← polled to get .onion address
  torrc                ← written on every startup
```

**After** (Arti in-process):
```
your-data-dir/
  arti_cache/          ← consensus cache (safe to delete; re-downloaded on next run)
  arti_state/          ← keypair + other persistent state
    keys/              ← service keypair (DELETE to rotate .onion address)
```

The old `tor_data/`, `tor_hidden_service/`, and `torrc` can be deleted after
migration. They are never created or read by Arti.

---

## Behaviour Differences to Be Aware Of

**Address rotation on first post-migration run:** The keypair that determines
the `.onion` address moves from `tor_hidden_service/` to `arti_state/keys/`.
The old keypair is not read by Arti, so the address will be different on the
first run after migration. Users will need the new address.

**First-run latency:** Both approaches bootstrap to the Tor network on first
run (~30 s). The user-visible timing is similar, but Arti's bootstrap happens
inside `create_bootstrapped` rather than being hidden behind a background
polling loop.

**`TorStatus::NotFound`:** This status was set when the `tor` binary search
failed. With Arti it can never occur. Keep the variant for API compatibility
or remove it and update any match arms.

**Logging:** C Tor's logs came through stderr (captured and forwarded). Arti
logs through the `tracing` crate. If your project uses the `log` crate, Arti's
output will appear automatically as long as you have a `log`-compatible
subscriber. No explicit bridging is needed in most setups.

**`SocksPort 0`:** This torrc setting prevented port-9050 conflicts with a
system Tor daemon. It is not needed with Arti since Arti never opens a SOCKS
port unless you explicitly configure one.
