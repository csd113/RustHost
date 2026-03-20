//! # Tor Module — Arti (in-process)
//!
//! **Directory:** `src/tor/`
//!
//! Replaces the old subprocess + torrc approach with Arti, the official
//! Tor implementation in Rust, running entirely in-process.
//!
//! ## What changed vs. the old implementation
//!
//! | Old (C Tor subprocess)               | New (Arti in-process)                  |
//! |--------------------------------------|----------------------------------------|
//! | Searches for `tor` binary in PATH    | No external binary needed              |
//! | Writes a `torrc` file to disk        | Config is built in Rust code           |
//! | Polls `hostname` file to get address | Address available on launch            |
//! | Subprocess killed on shutdown        | Dropped automatically with task exit   |
//!
//! ## Flow
//!
//! 1. `init()` spawns a Tokio task (non-blocking, same public API as before).
//! 2. `TorClient::create_bootstrapped()` connects to the Tor network.
//!    First run downloads ~2 MB of directory consensus (~30 s).  Subsequent
//!    runs reuse the cache in `rusthost-data/arti_cache/` and are fast.
//! 3. `tor_client.launch_onion_service()` registers the hidden service.
//!    The address is derived from the keypair and is available immediately.
//!    The keypair is persisted in `rusthost-data/arti_state/keys/` so the
//!    same `.onion` address is used on every restart.
//! 4. `handle_rend_requests()` converts incoming `RendRequest`s into
//!    `StreamRequest`s (the Arti equivalent of each new TCP connection
//!    arriving on `HiddenServicePort 80 127.0.0.1:{port}`).
//! 5. Each `StreamRequest` is accepted and bridged to the local HTTP server
//!    with `tokio::io::copy_bidirectional` in its own Tokio task.
//! 6. `kill()` is a no-op — the `TorClient` is dropped when the task exits
//!    during normal Tokio runtime shutdown, which closes all circuits cleanly.

use std::path::PathBuf;

use arti_client::config::TorClientConfigBuilder;
use arti_client::TorClient;
use futures::StreamExt;
use tokio::net::TcpStream;
use tor_cell::relaycell::msg::Connected;
use tor_hsservice::{config::OnionServiceConfigBuilder, handle_rend_requests, HsId, StreamRequest};

use crate::runtime::state::{SharedState, TorStatus};

// ─── Public entry point ──────────────────────────────────────────────────────

/// Initialise Tor using the embedded Arti client.
///
/// Spawns a Tokio task and returns immediately.  Tor status and the onion
/// address are written into `state` as things progress, exactly as before.
///
/// The signature is intentionally identical to the old subprocess version
/// so `lifecycle.rs` requires zero changes.
pub fn init(data_dir: PathBuf, bind_port: u16, state: SharedState) {
    tokio::spawn(async move {
        if let Err(e) = run(data_dir, bind_port, state.clone()).await {
            log::error!("Tor: fatal error: {e}");
            set_status(&state, TorStatus::Failed(None)).await;
        }
    });
}

/// No-op on shutdown.
///
/// The `TorClient` is owned by the Tokio task spawned in `init()` and is
/// dropped — closing all Tor circuits — when that task exits as part of the
/// normal Tokio runtime shutdown.  Nothing needs to be done explicitly here.
pub const fn kill() {}

// ─── Core async logic ─────────────────────────────────────────────────────────

async fn run(
    data_dir: PathBuf,
    bind_port: u16,
    state: SharedState,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    set_status(&state, TorStatus::Starting).await;

    // ── 1. Build TorClientConfig ──────────────────────────────────────────
    //
    // `from_directories(state_dir, cache_dir)` is the idiomatic Arti helper
    // that sets both storage paths in one call.  It takes `AsRef<Path>` so
    // we pass PathBuf directly — no CfgPath conversion needed.
    //
    // The state directory persists the service keypair across restarts, giving
    // you a stable .onion address.  Delete it to rotate to a new address.
    let config = TorClientConfigBuilder::from_directories(
        data_dir.join("arti_state"),
        data_dir.join("arti_cache"),
    )
    .build()?;

    log::info!("Tor: bootstrapping — first run downloads ~2 MB of directory data (~30 s)");

    // ── 2. Bootstrap ──────────────────────────────────────────────────────
    //
    // Async-blocks until Tor has fetched enough directory info to open
    // circuits safely.  Subsequent runs reuse the cached consensus and
    // finish in a few seconds.
    let tor_client = TorClient::create_bootstrapped(config)
        .await
        .map_err(|e| format!("Tor bootstrap failed: {e}"))?;

    log::info!("Tor: connected to the Tor network");

    // ── 3. Launch the onion service ───────────────────────────────────────
    //
    // The nickname is a local label only — it never appears in the .onion
    // address and does not need to match anything external.
    let svc_config = OnionServiceConfigBuilder::default()
        .nickname("rusthost".parse()?)
        .build()?;

    let (onion_service, rend_requests) = tor_client
        .launch_onion_service(svc_config)?
        .ok_or("Tor: onion service returned None (should not happen with in-code config)")?;

    // ── 4. Read the onion address ─────────────────────────────────────────
    //
    // In arti-client 0.40, HsId implements DisplayRedacted (from the safelog
    // crate) rather than std::fmt::Display, so direct format!("{}", hsid)
    // does not compile.  Instead we encode the address manually from the raw
    // 32-byte public key using the v3 onion-address spec:
    //
    //   onion_address = base32(PUBKEY | CHECKSUM | VERSION) + ".onion"
    //   CHECKSUM = SHA3-256(".onion checksum" | PUBKEY | VERSION)[:2]
    //   VERSION  = 0x03
    //
    // HsId: AsRef<[u8; 32]> is stable across arti 0.40+, so this approach
    // will keep working even if the Display story changes in a future release.
    let hsid = onion_service
        .onion_address()
        .ok_or("Tor: onion address not yet available (key generation incomplete)")?;
    let onion_name = hsid_to_onion_address(hsid);

    log::info!(
        "\n  ╔═══════════════════════════════════════════════════╗\n  \
           ║   TOR ONION SERVICE ACTIVE                        ║\n  \
           ╠═══════════════════════════════════════════════════╣\n  \
           ║   http://{onion_name:<43}║\n  \
           ║   Share this address with Tor Browser users.      ║\n  \
           ╚═══════════════════════════════════════════════════╝"
    );

    set_onion(&state, onion_name).await;

    // ── 5. Bridge incoming streams to the local HTTP server ───────────────
    //
    // `handle_rend_requests` takes the raw `Stream<Item = RendRequest>` from
    // `launch_onion_service`, auto-accepts each rendezvous handshake, and
    // yields a `StreamRequest` for every new inbound connection — the Arti
    // equivalent of the old torrc line:
    //
    //   HiddenServicePort 80 127.0.0.1:{bind_port}
    //
    // Each connection is proxied in its own Tokio task so they do not block
    // each other.  Dropping the task naturally closes the Tor circuit.
    let mut stream_requests = handle_rend_requests(rend_requests);

    while let Some(stream_req) = stream_requests.next().await {
        let local_addr = format!("127.0.0.1:{bind_port}");
        tokio::spawn(async move {
            if let Err(e) = proxy_stream(stream_req, &local_addr).await {
                // Downgraded to debug — normal on abrupt disconnects.
                log::debug!("Tor: stream closed: {e}");
            }
        });
    }

    log::warn!("Tor: stream_requests stream ended — onion service is no longer active");
    Ok(())
}

// ─── Stream proxying ─────────────────────────────────────────────────────────

/// Accept one `StreamRequest` and proxy it bidirectionally to the local HTTP
/// server.
///
/// `stream_req.accept(Connected::new_empty())` sends back the `RELAY_CONNECTED`
/// cell to the client (indicating the connection succeeded) and returns the
/// `DataStream` we then bridge to our local HTTP server.
///
/// `Connected::new_empty()` is the correct form for hidden services: we don't
/// report an exit IP to the client (there isn't one — we're the service).
///
/// `DataStream` implements `tokio::io::AsyncRead + AsyncWrite` when the
/// `tokio` feature is enabled on `arti-client`, so `copy_bidirectional`
/// works with no adapter needed.
async fn proxy_stream(
    stream_req: StreamRequest,
    local_addr: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut tor_stream = stream_req.accept(Connected::new_empty()).await?;
    let mut local = TcpStream::connect(local_addr).await?;
    tokio::io::copy_bidirectional(&mut tor_stream, &mut local).await?;
    Ok(())
}

// ─── Onion address encoding ───────────────────────────────────────────────────

/// Encode an `HsId` (ed25519 public key) as a v3 `.onion` domain name.
///
/// `arti-client 0.40` exposes `HsId` via `DisplayRedacted` (from the `safelog`
/// crate) rather than `std::fmt::Display`, so we cannot use `format!("{}", …)`
/// directly.  We implement the encoding ourselves using the spec:
///
/// ```text
/// onion_address = base32(PUBKEY | CHECKSUM | VERSION) + ".onion"
/// CHECKSUM      = SHA3-256(".onion checksum" | PUBKEY | VERSION)[:2]
/// VERSION       = 0x03
/// ```
///
/// `HsId: AsRef<[u8; 32]>` is stable across arti 0.40+.
fn hsid_to_onion_address(hsid: HsId) -> String {
    use sha3::{Digest, Sha3_256};

    let pubkey: &[u8; 32] = hsid.as_ref();
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
    // Consume the first two checksum bytes via an iterator — clippy cannot
    // prove at compile time that a GenericArray has >= 2 elements, so direct
    // indexing (hash[0], hash[1]) triggers `indexing_slicing`.  SHA3-256
    // always produces 32 bytes, so next() will never return None here.
    let mut hash_iter = hash.iter().copied();
    address_bytes[32] = hash_iter.next().unwrap_or(0);
    address_bytes[33] = hash_iter.next().unwrap_or(0);
    address_bytes[34] = version;

    // RFC 4648 base32, no padding, lowercase  →  56 characters
    let encoded = data_encoding::BASE32_NOPAD
        .encode(&address_bytes)
        .to_ascii_lowercase();

    format!("{encoded}.onion")
}

// ─── State helpers ────────────────────────────────────────────────────────────

async fn set_status(state: &SharedState, status: TorStatus) {
    state.write().await.tor_status = status;
}

async fn set_onion(state: &SharedState, addr: String) {
    let mut s = state.write().await;
    s.tor_status = TorStatus::Ready;
    s.onion_address = Some(addr);
}
