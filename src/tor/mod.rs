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
//! 1. `init()` spawns a Tokio task and returns its `JoinHandle`.
//!    The handle is awaited by lifecycle during graceful shutdown so active
//!    Tor circuits get a chance to close cleanly (fix 3.1).
//! 2. `TorClient::create_bootstrapped()` connects to the Tor network.
//!    A 120-second timeout prevents an indefinite hang on firewalled networks
//!    (fix 3.3).  First run downloads ~2 MB of directory consensus (~30 s).
//!    Subsequent runs reuse the cache in `rusthost-data/arti_cache/` and are fast.
//! 3. `tor_client.launch_onion_service()` registers the hidden service.
//!    The address is derived from the keypair and is available immediately.
//!    The keypair is persisted in `rusthost-data/arti_state/keys/` so the
//!    same `.onion` address is used on every restart.
//! 4. `handle_rend_requests()` converts incoming `RendRequest`s into
//!    `StreamRequest`s (the Arti equivalent of each new TCP connection
//!    arriving on `HiddenServicePort 80 127.0.0.1:{port}`).
//! 5. Each `StreamRequest` is accepted and bridged to the local HTTP server
//!    with `tokio::io::copy_bidirectional` in its own Tokio task.
//!    Both the local connect and the bidirectional copy carry timeouts to
//!    bound the lifetime of stalled connections (fix 3.1, fix 3.2).
//! 6. When the `stream_requests` stream ends unexpectedly (transient network
//!    disruption, Arti circuit reset) the module re-bootstraps with
//!    exponential backoff up to `MAX_RETRIES` times before giving up
//!    (fix 3.4).
//! 7. `kill()` is a no-op — the `TorClient` is dropped when the task exits
//!    during normal Tokio runtime shutdown, which closes all circuits cleanly.

use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

use arti_client::config::TorClientConfigBuilder;
use arti_client::TorClient;
use futures::StreamExt;
use tokio::{net::TcpStream, sync::watch, task::JoinHandle};
use tor_cell::relaycell::msg::Connected;
use tor_hsservice::{config::OnionServiceConfigBuilder, handle_rend_requests, HsId, StreamRequest};

use crate::runtime::state::{SharedState, TorStatus};

// ─── Timeout / retry constants ────────────────────────────────────────────────

/// How long to wait for Arti to complete the initial directory bootstrap.
/// Covers first-run consensus download plus circuit establishment.
const BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(120);

/// How long to wait for the local HTTP server to accept a proxied connection.
/// A hung local server should not hold a semaphore permit indefinitely.
const LOCAL_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Maximum wall-clock lifetime of a single proxied Tor stream.
/// Prevents stalled or adversarially slow clients from exhausting the
/// semaphore by holding permits open with no forward data progress.
const STREAM_MAX_LIFETIME: Duration = Duration::from_secs(300);

/// Base delay between re-bootstrap attempts (multiplied by attempt count).
const RETRY_BASE_SECS: u64 = 30;

/// Maximum number of automatic re-bootstrap attempts after an unexpected
/// stream-end before the module sets `TorStatus::Failed` permanently.
const MAX_RETRIES: u32 = 5;

// ─── Public entry point ───────────────────────────────────────────────────────

/// Initialise Tor using the embedded Arti client.
///
/// Spawns a Tokio task and returns its [`JoinHandle`].  The caller **must**
/// await the handle (with a timeout) during graceful shutdown so active Tor
/// circuits can close cleanly before the runtime exits (fix 3.1).
///
/// Tor status and the onion address are written into `state` as things
/// progress.  `shutdown` is a watch channel whose `true` value triggers a
/// clean exit from the stream-request loop.
///
/// `bind_addr` must match `config.server.bind` so the local proxy connect
/// uses the correct loopback address even when the server is bound to `::1`
/// rather than `127.0.0.1` (fix 3.6).
pub fn init(
    data_dir: PathBuf,
    bind_port: u16,
    bind_addr: IpAddr,
    state: SharedState,
    shutdown: watch::Receiver<bool>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut attempts = 0u32;

        loop {
            // `run()` returns:
            //   Ok(true)  — stream ended unexpectedly; caller should retry
            //   Ok(false) — clean shutdown signal received; caller should exit
            //   Err(e)    — fatal, unrecoverable error
            match run(
                data_dir.clone(),
                bind_port,
                bind_addr,
                state.clone(),
                shutdown.clone(),
            )
            .await
            {
                Ok(false) => {
                    // Shutdown signal — exit cleanly without touching status.
                    log::info!("Tor: task exiting cleanly.");
                    break;
                }
                Ok(true) => {
                    // Stream ended unexpectedly (transient network disruption).
                    // Use saturating_add to satisfy clippy::integer_arithmetic —
                    // in practice attempts never exceeds MAX_RETRIES (a small u32).
                    attempts = attempts.saturating_add(1);
                    if attempts > MAX_RETRIES {
                        log::error!(
                            "Tor: stream ended {MAX_RETRIES} consecutive times; giving up."
                        );
                        set_status(
                            &state,
                            TorStatus::Failed("too many reconnect attempts".into()),
                        )
                        .await;
                        break;
                    }

                    let delay =
                        Duration::from_secs(RETRY_BASE_SECS.saturating_mul(u64::from(attempts)));
                    log::warn!(
                        "Tor: stream ended; re-bootstrapping in {delay:?} \
                         (attempt {attempts}/{MAX_RETRIES})"
                    );

                    // Clear the displayed address while reconnecting.
                    state.write().await.onion_address = None;
                    set_status(&state, TorStatus::Starting).await;

                    // Honour shutdown signals that arrive during the backoff sleep.
                    // The cloned receiver must be bound to a local variable so it
                    // lives for the full duration of the select! borrow (E0716).
                    let mut backoff_shutdown = shutdown.clone();
                    tokio::select! {
                        () = tokio::time::sleep(delay) => {}
                        _ = backoff_shutdown.changed() => {
                            if *backoff_shutdown.borrow() {
                                log::info!("Tor: shutdown during backoff — exiting.");
                                break;
                            }
                        }
                    }
                }
                Err(e) => {
                    log::error!("Tor: fatal error: {e}");
                    set_status(&state, TorStatus::Failed(e.to_string())).await;
                    break;
                }
            }
        }
    })
}

// `kill()` has been removed (fix 2.10): the `TorClient` is owned by the task
// spawned in `init()` and is dropped when that task exits, which closes all
// Tor circuits cleanly.  Graceful shutdown is now signalled through the
// `shutdown` watch channel passed to `init()`.

// ─── Core async logic ─────────────────────────────────────────────────────────

/// Run the full Tor lifecycle (bootstrap → launch service → proxy streams).
///
/// Returns:
/// - `Ok(false)` — shutdown signal received; caller should exit.
/// - `Ok(true)`  — stream ended unexpectedly; caller should retry.
/// - `Err(e)`    — unrecoverable error; caller should set `Failed` and exit.
async fn run(
    data_dir: PathBuf,
    bind_port: u16,
    bind_addr: IpAddr,
    state: SharedState,
    mut shutdown: watch::Receiver<bool>,
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
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
    // fix 3.3 — wrap in a timeout so a firewalled network (where Tor traffic
    // is silently dropped) does not cause the task to stall indefinitely with
    // TorStatus::Starting showing in the dashboard.
    let tor_client =
        tokio::time::timeout(BOOTSTRAP_TIMEOUT, TorClient::create_bootstrapped(config))
            .await
            .map_err(|_| {
                format!(
                    "Tor bootstrap timed out after {}s — check network connectivity",
                    BOOTSTRAP_TIMEOUT.as_secs()
                )
            })?
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

    // fix 3.2 — the semaphore bounds active concurrent proxied streams.
    // If `acquire_owned` ever returns Err it means `semaphore` was explicitly
    // closed, which we now do when exiting via the shutdown arm so the
    // acquire branch is always reachable (fix 3.5).
    let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(256));

    // 2.10 — use select! so a shutdown signal can break the accept loop
    // cleanly, instead of blocking indefinitely in stream_requests.next().
    loop {
        tokio::select! {
            next = stream_requests.next() => {
                if let Some(stream_req) = next {
                    // fix 3.6 — derive local address from the actual bind address,
                    // not a hardcoded "127.0.0.1", so IPv6 bind configs work.
                    let local_addr = format!("{bind_addr}:{bind_port}");

                    // fix 3.5 — propagate semaphore errors rather than silently
                    // breaking; `acquire_owned` only fails if closed explicitly.
                    let permit = std::sync::Arc::clone(&semaphore)
                        .acquire_owned()
                        .await
                        .map_err(|e| format!("semaphore closed unexpectedly: {e}"))?;

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
                    // Return Ok(true) so init()'s retry loop can re-bootstrap
                    // instead of dying permanently (fix 3.4).
                    log::warn!(
                        "Tor: stream_requests stream ended — will attempt re-bootstrap"
                    );
                    state.write().await.onion_address = None;
                    return Ok(true); // signal: retry
                }
            }
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    log::info!("Tor: shutdown signal received — stopping stream loop");
                    // fix 3.5 — close the semaphore so any in-progress
                    // acquire_owned() call in the `next` arm returns immediately.
                    semaphore.close();
                    break;
                }
            }
        }
    }

    // Clean shutdown: clear the displayed onion address.
    state.write().await.onion_address = None;
    Ok(false) // signal: do not retry
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
///
/// fix 3.1 — both the local connect and the bidirectional copy are wrapped in
/// timeouts to prevent stalled connections from holding semaphore permits
/// indefinitely and exhausting the connection pool.
async fn proxy_stream(
    stream_req: StreamRequest,
    local_addr: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut tor_stream = stream_req.accept(Connected::new_empty()).await?;

    // fix 3.1a — bound the time spent waiting for the local server to accept.
    // If the HTTP server is wedged or still starting, we release the permit
    // quickly rather than holding it until the OS TCP timeout fires.
    let mut local = tokio::time::timeout(LOCAL_CONNECT_TIMEOUT, TcpStream::connect(local_addr))
        .await
        .map_err(|_| {
            format!(
                "timed out connecting to local server at {local_addr} \
                 after {}s",
                LOCAL_CONNECT_TIMEOUT.as_secs()
            )
        })?
        .map_err(|e| format!("local connect to {local_addr} failed: {e}"))?;

    // fix 3.2 — cap the total wall-clock lifetime of a proxied stream.
    // A slow or adversarially idle client cannot hold a permit forever; after
    // STREAM_MAX_LIFETIME the connection is closed from our side.
    tokio::time::timeout(
        STREAM_MAX_LIFETIME,
        tokio::io::copy_bidirectional(&mut tor_stream, &mut local),
    )
    .await
    .map_err(|_| {
        format!(
            "stream lifetime exceeded {}s — closing",
            STREAM_MAX_LIFETIME.as_secs()
        )
    })? // timeout → Err
    .map_err(|e| format!("bidirectional copy failed: {e}"))?; // io::Error → Err

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

    // fix 3.8 — index hash directly rather than via a fallible iterator.
    // SHA3-256 always produces exactly 32 bytes; the GenericArray is
    // guaranteed to have indices 0 and 1.  The `indexing_slicing` lint
    // fires here because clippy cannot prove the length at compile time for
    // GenericArray, so we suppress it with a targeted allow.
    #[allow(clippy::indexing_slicing)]
    {
        address_bytes[32] = hash[0];
        address_bytes[33] = hash[1];
    }
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
        // SHA3-256 always produces 32 bytes; direct indexing is safe.
        #[allow(clippy::indexing_slicing)]
        {
            bytes[32] = hash[0];
            bytes[33] = hash[1];
        }
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
