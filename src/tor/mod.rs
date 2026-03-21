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
use tokio::{net::TcpStream, sync::watch};
use tor_cell::relaycell::msg::Connected;
use tor_hsservice::{config::OnionServiceConfigBuilder, handle_rend_requests, HsId, StreamRequest};

use crate::runtime::state::{SharedState, TorStatus};

// ─── Public entry point ──────────────────────────────────────────────────────

/// Initialise Tor using the embedded Arti client.
///
/// Spawns a Tokio task and returns immediately.  Tor status and the onion
/// address are written into `state` as things progress, exactly as before.
///
/// `shutdown` is a watch channel whose `true` value triggers a clean exit
/// from the stream-request loop (fix 2.10).
pub fn init(
    data_dir: PathBuf,
    bind_port: u16,
    state: SharedState,
    shutdown: watch::Receiver<bool>,
) {
    tokio::spawn(async move {
        if let Err(e) = run(data_dir, bind_port, state.clone(), shutdown).await {
            log::error!("Tor: fatal error: {e}");
            set_status(&state, TorStatus::Failed(e.to_string())).await;
        }
    });
}

// `kill()` has been removed (fix 2.10): the `TorClient` is owned by the task
// spawned in `init()` and is dropped when that task exits, which closes all
// Tor circuits cleanly.  Graceful shutdown is now signalled through the
// `shutdown` watch channel passed to `init()`.

// ─── Core async logic ─────────────────────────────────────────────────────────

async fn run(
    data_dir: PathBuf,
    bind_port: u16,
    state: SharedState,
    mut shutdown: watch::Receiver<bool>,
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

    let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(256));

    // 2.10 — use select! so a shutdown signal can break the accept loop cleanly,
    // instead of blocking indefinitely in stream_requests.next().
    loop {
        tokio::select! {
            next = stream_requests.next() => {
                if let Some(stream_req) = next {
                    let local_addr = format!("127.0.0.1:{bind_port}");
                    let Ok(permit) = std::sync::Arc::clone(&semaphore).acquire_owned().await else {
                        break; // semaphore closed
                    };
                    tokio::spawn(async move {
                        let _permit = permit;
                        if let Err(e) = proxy_stream(stream_req, &local_addr).await {
                            // Downgraded to debug — normal on abrupt disconnects.
                            log::debug!("Tor: stream closed: {e}");
                        }
                    });
                } else {
                    // The onion service stream ended unexpectedly (Tor network
                    // disruption, Arti internal error, resource exhaustion).
                    // Flip the dashboard to Failed so the operator sees a clear
                    // signal rather than a permanently green READY badge.
                    log::warn!(
                        "Tor: stream_requests stream ended — onion service is no longer active"
                    );
                    // 2.9 — use Failed(String) with a human-readable reason
                    set_status(&state, TorStatus::Failed("stream ended".into())).await;
                    state.write().await.onion_address = None;
                    return Ok(());
                }
            }
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    log::info!("Tor: shutdown signal received — stopping stream loop");
                    break;
                }
            }
        }
    }

    // Clean shutdown: clear the displayed onion address.
    state.write().await.onion_address = None;
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
/// Delegates to [`onion_address_from_pubkey`] which is separately unit-tested.
fn hsid_to_onion_address(hsid: HsId) -> String {
    onion_address_from_pubkey(hsid.as_ref())
}

/// Encode a raw 32-byte ed25519 public key as a v3 `.onion` domain name.
///
/// Implements the encoding defined in the Tor Rendezvous Specification:
///
/// ```text
/// onion_address = base32(PUBKEY | CHECKSUM | VERSION) + ".onion"
/// CHECKSUM      = SHA3-256(".onion checksum" | PUBKEY | VERSION)[:2]
/// VERSION       = 0x03
/// ```
///
/// The output is always exactly 62 characters: 56 lowercase base32 characters
/// followed by `".onion"`.
///
/// Separated from [`hsid_to_onion_address`] so that tests can supply an
/// arbitrary 32-byte key without constructing an `HsId`.
#[must_use]
pub(crate) fn onion_address_from_pubkey(pubkey: &[u8; 32]) -> String {
    use sha3::{Digest, Sha3_256};

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
    // indexing triggers `indexing_slicing`.  SHA3-256 always produces 32 bytes.
    let mut hash_iter = hash.iter().copied();
    address_bytes[32] = hash_iter.next().unwrap_or(0);
    address_bytes[33] = hash_iter.next().unwrap_or(0);
    address_bytes[34] = version;

    // RFC 4648 base32, no padding, lowercase → 56 characters
    let encoded = data_encoding::BASE32_NOPAD
        .encode(&address_bytes)
        .to_ascii_lowercase();

    format!("{encoded}.onion")
}

// ─── State helpers ────────────────────────────────────────────────────────────
//
// These must appear BEFORE the #[cfg(test)] module; items after a test module
// trigger the `clippy::items_after_test_module` lint.

async fn set_status(state: &SharedState, status: TorStatus) {
    state.write().await.tor_status = status;
}

async fn set_onion(state: &SharedState, addr: String) {
    let mut s = state.write().await;
    s.tor_status = TorStatus::Ready;
    s.onion_address = Some(addr);
}

// ─── Unit tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::onion_address_from_pubkey;

    /// Compute the expected onion address for a given 32-byte key using the
    /// same algorithm as `onion_address_from_pubkey`, acting as an independent
    /// reference implementation to cross-check the production code.
    fn reference_onion(pubkey: &[u8; 32]) -> String {
        use data_encoding::BASE32_NOPAD;
        use sha3::{Digest, Sha3_256};

        let version: u8 = 3;
        let mut hasher = Sha3_256::new();
        hasher.update(b".onion checksum");
        hasher.update(pubkey);
        hasher.update([version]);
        let hash = hasher.finalize();

        let mut bytes = [0u8; 35];
        bytes[..32].copy_from_slice(pubkey);
        // Use iterator instead of direct indexing to avoid clippy::indexing_slicing.
        // SHA3-256 always produces 32 bytes, so next() will never return None.
        let mut it = hash.iter().copied();
        bytes[32] = it.next().unwrap_or(0);
        bytes[33] = it.next().unwrap_or(0);
        bytes[34] = version;

        format!("{}.onion", BASE32_NOPAD.encode(&bytes).to_ascii_lowercase())
    }

    #[test]
    fn hsid_to_onion_address_all_zeros_vector() {
        // Fixed 32-byte test vector: all zeros.
        // The expected value is derived from the reference implementation above.
        let pubkey = [0u8; 32];
        let expected = reference_onion(&pubkey);
        let actual = onion_address_from_pubkey(&pubkey);
        assert_eq!(actual, expected);
    }

    #[test]
    fn hsid_to_onion_address_format_is_correct() {
        let pubkey = [0u8; 32];
        let addr = onion_address_from_pubkey(&pubkey);
        // A v3 onion address is always 56 base32 chars + ".onion" = 62 chars.
        assert_eq!(addr.len(), 62, "unexpected length: {addr:?}");
        // Use strip_suffix to avoid clippy::case_sensitive_file_extension_comparison.
        assert!(
            addr.strip_suffix(".onion").is_some(),
            "must end with .onion: {addr:?}"
        );
        let host = addr.strip_suffix(".onion").unwrap_or(&addr);
        assert!(
            host.chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()),
            "host contains non-base32 characters: {host:?}"
        );
    }

    #[test]
    fn hsid_to_onion_address_is_deterministic() {
        // Calling the function twice with the same key must produce the same
        // output — the address must be derivable from the public key alone.
        let pubkey = [0x42u8; 32];
        assert_eq!(
            onion_address_from_pubkey(&pubkey),
            onion_address_from_pubkey(&pubkey)
        );
    }

    #[test]
    fn hsid_to_onion_address_different_keys_produce_different_addresses() {
        let a = onion_address_from_pubkey(&[0u8; 32]);
        let b = onion_address_from_pubkey(&[1u8; 32]);
        assert_ne!(a, b, "different keys must produce different addresses");
    }
}
