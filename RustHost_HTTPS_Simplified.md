# RustHost HTTPS — Implementation Plan (Simplified)

## Decision

Use **`tokio-rustls`** + **`rustls-acme`**. Pure Rust, no FFI, compatible with `unsafe_code = "forbid"`. Preserves single-binary. No external processes.

```toml
# Cargo.toml
tokio-rustls = "0.26"
rustls-pemfile = "2"
rustls       = { version = "0.23", features = ["ring"] }
rustls-acme  = { version = "0.12", features = ["tokio"] }
rcgen        = { version = "0.13", optional = true }   # self-signed dev certs
```

---

## What Changes

### 1. Config — add `[tls]` section

New struct in `src/config/mod.rs`. **Do not touch `ServerConfig`** — its `deny_unknown_fields` stays intact. Add `TlsConfig` as a separate top-level field with `#[serde(default)]`.

```rust
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TlsConfig {
    #[serde(default)] pub enabled: bool,
    #[serde(default = "default_https_port")] pub port: NonZeroU16, // 8443
    #[serde(default)] pub redirect_http: bool,
    #[serde(default = "default_http_port")] pub http_port: NonZeroU16, // 8080
    #[serde(default)] pub acme: AcmeConfig,
    pub manual_cert: Option<ManualCertConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AcmeConfig {
    #[serde(default)] pub enabled: bool,
    #[serde(default)] pub domains: Vec<String>,
    pub email: Option<String>,
    #[serde(default = "default_true")] pub staging: bool, // staging=true protects against LE rate limits
    #[serde(default = "default_acme_dir")] pub cache_dir: String, // "tls/acme"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManualCertConfig {
    pub cert_path: String,
    pub key_path: String,
}
```

Add to `Config`:
```rust
#[serde(default)]
pub tls: TlsConfig,
```

### 2. Handler — make generic

Change `handler::handle(stream: TcpStream, …)` to accept any async stream. Call sites don't change — the generic is inferred.

```rust
pub async fn handle<S>(stream: S, …) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let io = TokioIo::new(stream);
    hyper::server::conn::http1::Builder::new()
        .keep_alive(true)
        .serve_connection(io, service_fn(move |req| …))
        .await
        .map_err(|e| AppError::Io(std::io::Error::other(e.to_string())))
}
```

### 3. New module: `src/tls/`

```
src/tls/
  mod.rs          — build_acceptor() dispatcher
  acme.rs         — rustls-acme config + event loop
  self_signed.rs  — rcgen dev cert generation
```

**`tls/mod.rs`** — one public function, three branches:

```rust
pub async fn build_acceptor(cfg: &TlsConfig, data_dir: &Path)
    -> Result<Option<Arc<TlsAcceptor>>>
{
    if !cfg.enabled { return Ok(None); }
    if let Some(m) = &cfg.manual_cert {
        return Ok(Some(load_manual_cert(m, data_dir)?));
    }
    if cfg.acme.enabled {
        return Ok(Some(acme::build_acme_acceptor(&cfg.acme, data_dir).await?));
    }
    Ok(Some(self_signed::generate_or_load(data_dir)?))
}
```

**`tls/self_signed.rs`** — dev cert:

```rust
pub fn generate_or_load(data_dir: &Path) -> Result<Arc<TlsAcceptor>> {
    let dir = data_dir.join("tls/dev");
    std::fs::create_dir_all(&dir)?;
    let cert_path = dir.join("self-signed.crt");
    let key_path  = dir.join("self-signed.key");
    if needs_regeneration(&cert_path) {
        let cert = rcgen::generate_simple_self_signed(
            vec!["localhost".into(), "127.0.0.1".into(), "::1".into()]
        )?;
        std::fs::write(&cert_path, cert.cert.pem())?;
        std::fs::write(&key_path,  cert.key_pair.serialize_pem())?;
    }
    load_pem_as_acceptor(&cert_path, &key_path)
}
```

**`tls/acme.rs`** — Let's Encrypt:

```rust
pub async fn build_acme_acceptor(cfg: &AcmeConfig, data_dir: &Path)
    -> Result<Arc<TlsAcceptor>>
{
    let cache  = rustls_acme::caches::DirCache::new(data_dir.join(&cfg.cache_dir));
    let domains: Vec<&str> = cfg.domains.iter().map(String::as_str).collect();
    let acme = rustls_acme::AcmeConfig::new(domains)
        .contact_push(format!("mailto:{}", cfg.email.as_deref().unwrap_or("")))
        .cache(cache)
        .directory_lets_encrypt(cfg.staging);
    let mut state = acme.state();
    let acceptor = Arc::new(state.acceptor().into());
    // Spawn the ACME event loop — handles renewals and challenge responses
    tokio::spawn(async move {
        loop {
            match state.next().await {
                Some(Ok(ev))  => log::info!("ACME: {ev:?}"),
                Some(Err(e))  => log::warn!("ACME error: {e}"),
                None          => break,
            }
        }
    });
    Ok(acceptor)
}
```

### 4. Server — add `run_https()` (additive, `run()` untouched)

```rust
pub async fn run_https(
    config: Arc<Config>,
    tls_acceptor: Arc<TlsAcceptor>,
    /* same params as run() */
) {
    // Identical accept loop to run(), except:
    let tls_stream = match tls_acceptor.accept(tcp_stream).await {
        Ok(s)  => s,
        Err(e) => {
            log::debug!("TLS handshake failed from {peer}: {e}"); // debug, not warn — port scanners
            continue;
        }
    };
    handler::handle(tls_stream, …).await;
}
```

Share the existing `per_ip_map` and `semaphore` from `ServerContext` across both listeners — construct once, `Arc::clone` into both.

### 5. Lifecycle wiring (`src/runtime/lifecycle.rs`)

```rust
let tls_acceptor = match tls::build_acceptor(&config.tls, &data_dir).await {
    Ok(v)  => v,
    Err(e) => { log::error!("TLS init failed: {e}. Running HTTP only."); None }
};

tokio::spawn(server::run(Arc::clone(&config), …));            // existing — unchanged

if let Some(acceptor) = tls_acceptor {
    tokio::spawn(server::run_https(Arc::clone(&config), acceptor, …));
}

if config.tls.enabled && config.tls.redirect_http {
    tokio::spawn(redirect::run_redirect_server(
        config.tls.http_port.get(),
        config.tls.port.get(),
        shutdown_rx.clone(),
    ));
}
```

---

## Security (no work required — rustls defaults cover it)

rustls enforces TLS 1.2+ and a safe cipher list out of the box. Don't override defaults.

The only additions needed in `handler.rs`:

```rust
fn inject_security_headers(resp: &mut Response<BoxBody>, is_https: bool) {
    if is_https {
        resp.headers_mut().insert(
            header::STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static("max-age=63072000; includeSubDomains"),
        );
    }
    resp.headers_mut().insert(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    resp.headers_mut().insert(
        HeaderName::from_static("x-frame-options"),
        HeaderValue::from_static("SAMEORIGIN"),
    );
}
```

Pass `is_https: bool` through `RouteConfig`. For TLS handshake failures: log at `debug`, never `warn` — scanners hit port 443 constantly.

---

## Config Examples

**Self-signed (local dev):**
```toml
[tls]
enabled = true
port = 8443
```

**Let's Encrypt staging (verify ACME works first):**
```toml
[tls]
enabled = true
port = 8443

[tls.acme]
enabled = true
domains = ["example.com"]
email = "you@example.com"
staging = true
```

**Production:**
```toml
[tls]
enabled = true
port = 443
redirect_http = true
http_port = 80

[tls.acme]
enabled = true
domains = ["example.com", "www.example.com"]
email = "you@example.com"
staging = false
```

**BYO cert:**
```toml
[tls]
enabled = true
port = 443

[tls.manual_cert]
cert_path = "tls/manual/fullchain.pem"
key_path  = "tls/manual/privkey.pem"
```

**HTTP only (existing configs — zero change needed):**
```toml
# No [tls] section — works exactly as before
```

---

## Cert Storage Layout

`rustls-acme` manages the `acme/` subtree itself via `DirCache`. RustHost only needs to create `tls/` at startup with correct permissions.

```
rusthost-data/tls/
  acme/                  ← managed by rustls-acme (DirCache)
    accounts/<hash>/
    certs/<domain>/
  dev/
    self-signed.crt      ← auto-generated by rcgen
    self-signed.key      (mode 0600)
```

---

## Backwards Compatibility

| Existing config | Behaviour after upgrade |
|---|---|
| No `[tls]` section | HTTP only — no change |
| `[tls] enabled = false` | HTTP only — no change |
| `[tls] enabled = true` | HTTP + HTTPS on configured port |
| `[tls] enabled = true` + `redirect_http = true` | HTTPS only; HTTP redirects |

Tor (.onion) connections are end-to-end encrypted — plain HTTP is correct for them. HTTP is never removed.

**Port 443 on Linux without root:**
```bash
sudo setcap cap_net_bind_service=+ep $(which rusthost-cli)
# or redirect at the firewall:
sudo iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-port 8443
```

---

## Build Order (each step independently revertable)

| Step | Action | Risk |
|---|---|---|
| 1 | Add `TlsConfig` to `Config` with `#[serde(default)]` | Zero — additive |
| 2 | Make `handler::handle()` generic over `S: AsyncRead+AsyncWrite+Unpin` | Minimal — HTTP path unchanged |
| 3 | Add `src/tls/self_signed.rs` + `src/tls/mod.rs` | Zero — new code only |
| 4 | Add `run_https()` + `spawn_https_connection()` | Minimal — additive |
| 5 | Wire into lifecycle; test with self-signed cert | Ship as v0 |
| 6 | Add `redirect::run_redirect_server()` | Low |
| 7 | Add `src/tls/acme.rs`; test against LE staging | Medium — network dep |
| 8 | Add `CertStatus` to `AppState` + dashboard display | Low |

Steps 1–5 can ship as "HTTPS with self-signed cert" before ACME is ready.

---

## Files to Edit

| File | What changes |
|---|---|
| `Cargo.toml` | Add `tokio-rustls`, `rustls`, `rustls-acme`, `rcgen` dependencies |
| `src/config/mod.rs` | Add `TlsConfig`, `AcmeConfig`, `ManualCertConfig` structs; add `pub tls: TlsConfig` field to `Config` |
| `src/server/handler.rs` | Make `handle()` generic over `S: AsyncRead + AsyncWrite + Unpin + Send + 'static`; add `inject_security_headers()`; thread `is_https: bool` through `RouteConfig` |
| `src/server/mod.rs` | Add `run_https()` and `spawn_https_connection()`; `Arc::clone` existing `per_ip_map` and `semaphore` into both listeners |
| `src/runtime/lifecycle.rs` | Call `tls::build_acceptor()` at startup; conditionally spawn `run_https()` and `redirect::run_redirect_server()` |
| `src/dashboard/app_state.rs` | Add `tls_running: bool`, `tls_port: Option<u16>`, `tls_cert_status: CertStatus` to `AppState` |

---

## New Files to Create

| File | Purpose |
|---|---|
| `src/tls/mod.rs` | `build_acceptor()` dispatcher — routes to ACME, manual cert, or self-signed based on config |
| `src/tls/acme.rs` | `build_acme_acceptor()` — configures `rustls-acme`, spawns the ACME renewal event loop |
| `src/tls/self_signed.rs` | `generate_or_load()` — generates a `localhost` self-signed cert via `rcgen` if missing or expiring |
| `src/server/redirect.rs` | `run_redirect_server()` — lightweight HTTP listener that issues 301 redirects to HTTPS |
