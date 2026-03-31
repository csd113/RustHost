# RustHost Setup Guide

This guide covers local development, production-style setup, HTTPS options, and cross-platform notes for macOS, Linux, and Windows.

## 1. Requirements

### Rust

RustHost requires **Rust 1.90 or newer**.

Check your toolchain:

```bash
rustc --version
cargo --version
```

If you need Rust:

- macOS / Linux: install via [rustup](https://rustup.rs/)
- Windows: install via [rustup](https://rustup.rs/) or the official Rust installer flow

Update an existing installation:

```bash
rustup update stable
```

### Build tools

Rust itself handles most of the heavy lifting, but you still need a working native toolchain.

- macOS: install Xcode Command Line Tools with `xcode-select --install`
- Debian / Ubuntu: install `build-essential`
- Fedora: install `gcc` and `make`
- Windows: install Visual Studio Build Tools or the Visual Studio C++ workload

### Optional runtime requirements

- outbound internet access if Tor / Arti bootstrap is enabled
- publicly reachable ports if using ACME with a real domain

## 2. Build the Project

From the repository root:

```bash
cargo build --release
```

The release binary is:

```bash
./target/release/rusthost-cli
```

For development:

```bash
cargo run -- --help
```

## 3. Choose a Startup Mode

### Option A: one-shot directory serve

Best for quick local testing.

```bash
./target/release/rusthost-cli --serve ./public
```

Useful variants:

```bash
./target/release/rusthost-cli --serve ./public --port 3000
./target/release/rusthost-cli --serve ./public --no-tor
./target/release/rusthost-cli --serve ./public --headless
```

### Option B: managed data directory

Best when you want persistent config, logs, certificates, and Tor state.

```bash
./target/release/rusthost-cli --data-dir ./rusthost-data
```

On first run RustHost creates:

- `rusthost-data/settings.toml`
- `rusthost-data/site/`
- `rusthost-data/logs/`

Place your static files in `rusthost-data/site/` and restart.

## 4. Basic Configuration

The generated `settings.toml` starts with safe local defaults:

```toml
[server]
port = 8080
bind = "127.0.0.1"

[site]
directory = "site"
index_file = "index.html"

[tor]
enabled = true
```

Recommended early decisions:

- keep `bind = "127.0.0.1"` for local development
- set `bind = "::1"` if you specifically want IPv6 localhost
- use `bind = "0.0.0.0"` or a real interface address only when you intentionally want network exposure
- disable Tor if you do not need onion access

## 5. HTTPS Setup

### Self-signed local HTTPS

```toml
[tls]
enabled = true
port = 8443
```

RustHost will create a self-signed certificate under the data directory and reuse it until near expiry.

This is appropriate for local development and testing, not for public browser-facing production.

### Manual certificate files

```toml
[tls]
enabled = true
port = 443

[tls.manual_cert]
cert_path = "tls/manual/fullchain.pem"
key_path = "tls/manual/privkey.pem"
```

Notes:

- the paths are relative to the data directory
- they must remain inside the data directory
- path traversal and absolute-path escapes are rejected

### ACME / Let's Encrypt

```toml
[tls]
enabled = true
port = 443
redirect_http = true
http_port = 80

[tls.acme]
enabled = true
domains = ["example.com", "www.example.com"]
email = "ops@example.com"
staging = true
cache_dir = "tls/acme"
```

Deployment checklist for ACME:

1. Point DNS at the machine that will run RustHost
2. Make the chosen HTTPS port reachable from the public internet
3. If using `redirect_http = true`, make `http_port` reachable too
4. Start with `staging = true`
5. Confirm HTTPS startup and certificate flow
6. Switch to `staging = false`

Important:

- `localhost` and raw IP addresses are not valid ACME domains
- ACME state is persisted under the configured cache directory
- only one ACME lifecycle may be active at a time in-process

## 6. Tor / Onion Service

If `[tor] enabled = true`, RustHost starts Arti and attempts to publish an onion service for the same HTTP site.

What to expect:

- first bootstrap is slower because Tor directory material must be downloaded
- later runs are faster because state is cached
- onion identity persistence depends on preserving the Tor state directory

Operational recommendations:

- back up Tor state if the onion address matters
- run under a dedicated OS account for public deployments
- do not share the data directory between unrelated instances

## 7. Headless and Service Operation

For services, containers, CI, or remote shells, disable the interactive dashboard:

```toml
[console]
interactive = false
```

Or from the CLI in one-shot mode:

```bash
./target/release/rusthost-cli --serve ./public --headless
```

Headless mode is the preferred production posture.

## 8. Reverse Proxy Guidance

RustHost can sit directly on the network edge, but a reverse proxy is often useful if you need:

- centralized TLS and certificate policy
- auth in front of private or operator-only surfaces
- advanced request filtering
- richer observability
- shared ingress across multiple services

If you configure trusted proxies, only include addresses you control.

## 9. Validation and Verification

Basic HTTP check:

```bash
curl -I http://127.0.0.1:8080
```

Self-signed HTTPS check:

```bash
curl -k -I https://127.0.0.1:8443
```

If bound to IPv6 loopback:

```bash
curl -I http://[::1]:8080
curl -k -I https://[::1]:8443
```

Project quality gates:

```bash
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets
```

## 10. Common Issues

### Port already in use

- change `[server].port` or `[tls].port`
- disable `redirect_http` if it conflicts with another listener
- review whether `auto_port_fallback` should be enabled

### HTTPS starts but browser warns

- self-signed certificates are expected to warn in browsers
- use ACME or a trusted manual cert for public production use

### ACME does not issue a certificate

- verify DNS points at the correct machine
- confirm the configured domain names are real FQDNs
- confirm the relevant ports are publicly reachable
- keep `staging = true` until the flow works

### Tor is slow on first run

- this is normal while Arti bootstraps
- later startups reuse cached state

### Browser does not auto-open

- browser launching is best-effort
- this is environment-dependent on all desktop OSes
- use the printed URL manually if needed

## 11. Cross-Platform Notes

### macOS

- `open` and Terminal automation are used when desktop convenience features are enabled
- firewall prompts may appear the first time you bind publicly

### Linux

- `xdg-open` is used for browser launching
- terminal auto-spawn depends on the available terminal emulator
- headless mode is recommended for system services

### Windows

- browser launching uses the shell association path
- console and ACL behavior depends on the user context and local policy
- keep the data directory in a user-writable location unless you intentionally run as a service account

## 12. Upgrade Workflow

Typical upgrade:

```bash
git pull
cargo build --release
```

Before restarting a public instance:

- back up the data directory
- especially preserve TLS and Tor state if continuity matters
- review the changelog for config changes

## 13. File Layout Reference

Typical managed layout:

```text
rusthost-data/
├── logs/
├── site/
├── settings.toml
├── tls/
└── arti_state/   (or other Tor state paths created by runtime components)
```

The exact TLS and Tor subdirectories depend on the features you enable.
