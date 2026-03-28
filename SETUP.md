# Setting Up RustHost

This guide walks you through everything you need to get RustHost running — from installing Rust to verifying your `.onion` address is live.

---

## Prerequisites

### Rust

RustHost requires **Rust 1.86 or newer**. This is set as the minimum because the Tor library it uses (`arti-client`) needs features from that release.

To check what version you have:

```bash
rustc --version
```

If you don't have Rust installed, the easiest way is [rustup](https://rustup.rs/):

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Follow the prompts, then restart your terminal (or run `source ~/.cargo/env`). Verify with:

```bash
rustc --version
cargo --version
```

To update an existing Rust install:

```bash
rustup update stable
```

### Git

You need Git to clone the repo. Most systems already have it.

```bash
git --version
```

If not:
- **macOS**: `xcode-select --install` (installs Git as part of the Xcode CLI tools)
- **Linux**: `sudo apt install git` (Debian/Ubuntu) or `sudo dnf install git` (Fedora)
- **Windows**: Download from [git-scm.com](https://git-scm.com/)

### Build tools

Rust needs a C linker. On most systems this is already present.

- **macOS**: You'll need the Xcode Command Line Tools — run `xcode-select --install` if you haven't already.
- **Linux**: Install `gcc` and `build-essential` (Debian/Ubuntu) or `gcc` and `make` (Fedora/RHEL).
- **Windows**: Install the Microsoft C++ Build Tools.

---

## Installing RustHost

### Step 1 — Clone the repository

```bash
git clone https://github.com/yourname/rusthost
cd rusthost
```

### Step 2 — Build in release mode

```bash
cargo build --release
```

### Step 3 — First run (data directory setup)

```bash
./target/release/rusthost
```

### Step 4 — Add your site files

```bash
cp -r /path/to/your/site/* rusthost-data/site/
```

### Step 5 — Start the server

```bash
./target/release/rusthost
```

---

## Setting Up HTTPS

### Option 1 — Self-signed certificate

```toml
[tls]
enabled = true
port = 8443
```

### Option 2 — Let's Encrypt

```toml
[tls]
enabled = true
port = 443

[tls.acme]
enabled = true
domains = ["example.com"]
email = "you@example.com"
staging = true
```

### Option 3 — Bring your own certificate

```toml
[tls]
enabled = true
port = 443

[tls.manual_cert]
cert_path = "tls/manual/fullchain.pem"
key_path  = "tls/manual/privkey.pem"
```

---

## Running as a systemd service

```bash
sudo systemctl enable rusthost
sudo systemctl start rusthost
```

---

## Verifying Everything Works

```bash
curl -I http://localhost:8080
```

---

## Common Errors

- Port already in use → change port
- TLS init failed → check cert paths
- ACME failed → check domain + ports

---

## Updating

```bash
git pull
cargo build --release
```

---

## Uninstalling

```bash
rm target/release/rusthost
rm -rf rusthost-data/
```
```