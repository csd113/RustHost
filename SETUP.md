# RustHost Setup Guide

RustHost is a static file server with an optional dashboard, HTTPS, and a built-in Tor onion service. This guide starts with the simplest local run and then points out the knobs you are most likely to need.

## Requirements

Install a current Rust toolchain, then check it:

```bash
rustc --version
cargo --version
```

You also need normal native build tools:

- macOS: Xcode Command Line Tools, installed with `xcode-select --install`
- Debian / Ubuntu: `build-essential`
- Fedora: `gcc` and `make`
- Windows: Visual Studio Build Tools or the Visual Studio C++ workload

Build RustHost from the repository root:

```bash
cargo build --release
```

The release binary is `./target/release/rusthost-cli`.

## Fresh Install

For a managed install with persistent config, site files, logs, TLS state, and Tor state:

```bash
./target/release/rusthost-cli --data-dir ./rusthost-data
```

On first run RustHost creates:

```text
rusthost-data/
├── settings.toml
├── site/
│   └── index.html
└── runtime/
    ├── logs/
    ├── tls/
    └── tor/
```

Put your static site files in `rusthost-data/site/`. The generated `settings.toml` also lives in `rusthost-data/`.

If `settings.toml` is deleted later, RustHost regenerates it from defaults and keeps existing `site/` and `runtime/` data.

## Quick One-Shot Serve

If you only want to serve a directory without creating `settings.toml`:

```bash
./target/release/rusthost-cli --serve ./public
```

Useful variants:

```bash
./target/release/rusthost-cli --serve ./public --port 3000
./target/release/rusthost-cli --serve ./public --no-tor
./target/release/rusthost-cli --serve ./public --headless
```

## Basic Settings

The most important generated defaults are:

```toml
[server]
port = 8080
bind = "127.0.0.1"
csp_level = "off"

[site]
directory = "site"
index_file = "index.html"
favicon = "favicon.ico"
enable_png_favicon = false

[tor]
enabled = true
```

Keep `bind = "127.0.0.1"` for local work. Use `0.0.0.0` or a specific LAN/public interface only when you intentionally want other machines to connect.

## Favicon Basics

By default, browsers can request:

```text
http://127.0.0.1:8080/favicon.ico
```

RustHost serves that from:

```text
rusthost-data/site/favicon.ico
```

To use a different `.ico` file under the site directory:

```toml
[site]
favicon = "assets/site-icon.ico"
```

To use PNG instead:

```toml
[site]
favicon = "assets/site-icon.png"
enable_png_favicon = true
```

Favicon paths are resolved under the site directory and cannot escape it.

## TUI Basics

When `[console] interactive = true`, RustHost opens a simple terminal dashboard.

Keys:

- `H`: help
- `R`: rescan the site directory and refresh serving state
- `O`: open the local URL in your default browser
- `L`: show recent logs
- `Q`: ask for shutdown confirmation
- `Y`: confirm shutdown
- `N`: cancel shutdown

Reloads show a short status message, such as `Reload complete`. During shutdown, the TUI reports that the web server and background services are stopping. If Tor is enabled, cleanup can take a few seconds while active streams close.

For services, containers, CI, or SSH sessions where an alternate-screen dashboard is not wanted:

```toml
[console]
interactive = false
```

## Serveo Quick Public Testing

Serveo can expose your local RustHost port through an SSH tunnel without router port forwarding. This is useful for short public tests, demos, or phone/browser checks.

Start RustHost locally:

```bash
./target/release/rusthost-cli --data-dir ./rusthost-data
```

In another terminal, create a tunnel to the local HTTP port:

```bash
ssh -R 80:127.0.0.1:8080 serveo.net
```

Serveo prints a public URL. Keep both terminals running while testing.

Use this only for temporary testing. For production, use your own domain, firewall rules, TLS setup, monitoring, and service manager.

## HTTPS and ACME

For local HTTPS with a self-signed certificate:

```toml
[tls]
enabled = true
port = 8443
```

Browsers will warn for self-signed certificates. That is expected.

For Let's Encrypt / ACME, configure `[tls.acme]` in `settings.toml`:

```toml
[tls]
enabled = true
port = 443
redirect_http = true
http_port = 80

[tls.acme]
enabled = true
domains = ["example.com", "www.example.com"]
email = "admin@example.com"
staging = true
cache_dir = "runtime/tls/acme"
```

ACME basics:

- DNS must point at the machine running RustHost.
- The public HTTP/HTTPS ports must be reachable from the internet.
- `localhost` and raw IP addresses do not work for Let's Encrypt certificates.
- Start with `staging = true` to avoid production rate limits.
- Switch to `staging = false` only after the staging flow works.

Manual certificates are also supported:

```toml
[tls.manual_cert]
cert_path = "runtime/tls/manual/fullchain.pem"
key_path = "runtime/tls/manual/privkey.pem"
```

## Tor Onion Service

When `[tor] enabled = true`, RustHost starts Arti in-process and publishes an onion service for the same static site.

Expect the first startup to take longer because Arti downloads Tor directory data. Later runs reuse cached state under `rusthost-data/runtime/tor/`.

If the onion address matters, back up the runtime Tor state and do not share one data directory between unrelated RustHost instances.

## Troubleshooting

### Port Already In Use

Change `[server].port`, `[tls].port`, or `[tls].http_port`. If this is a development machine and you are comfortable with fallback ports, you can set:

```toml
[server]
auto_port_fallback = true
```

For production, fixed ports are usually better because reverse proxies, firewall rules, and monitors expect stable addresses.

### Tor Startup Is Slow Or Fails

First startup can be slow while Arti bootstraps. Confirm outbound internet access is allowed. If you do not need onion access:

```toml
[tor]
enabled = false
```

Check `rusthost-data/runtime/logs/rusthost.log` for the detailed Tor status.

### Reload Did Not Pick Up Changes

Press `R` in the TUI and watch for the reload status line. In headless mode, send SIGHUP on Unix systems or restart the process.

If reload reports a failure, check that `[site].directory` exists under `rusthost-data/` and that RustHost can read the files.

### Browser Warns On HTTPS

Self-signed local certificates trigger browser warnings. Use ACME or your own trusted certificate for public browser-facing deployments.

### Favicon Does Not Appear

Check that `rusthost-data/site/favicon.ico` exists, or update `[site].favicon` to the correct file under the site directory. For PNG files, set `enable_png_favicon = true` and request `/favicon.png`.

## Upgrade Workflow

From the repository root:

```bash
git pull
cargo build --release
```

Before restarting a public instance, back up `rusthost-data/`, especially TLS and Tor runtime state.
