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
- **Windows**: Install the [Microsoft C++ Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/). When the installer asks, select "Desktop development with C++".

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

This downloads and compiles all dependencies (including Arti, which is the Rust Tor library — this takes a few minutes on first build). The final binary ends up at:

```
target/release/rusthost          (Linux / macOS)
target\release\rusthost.exe      (Windows)
```

> **Slow build?** The first build is always slow because Cargo is compiling everything from scratch. Subsequent builds are much faster thanks to the cache.

### Step 3 — First run (data directory setup)

Run the binary once from the project directory:

```bash
./target/release/rusthost
```

On first run, RustHost detects that `rusthost-data/settings.toml` doesn't exist and does the following:

- Creates the `rusthost-data/` directory next to the binary
- Writes a default `settings.toml` with all options commented
- Creates `rusthost-data/site/` with a placeholder `index.html`
- Creates `rusthost-data/logs/`
- Prints a getting-started message and exits

Nothing is started yet — this is just setup.

### Step 4 — Add your site files

Replace (or edit) the placeholder file:

```bash
# Put your HTML files in rusthost-data/site/
cp -r /path/to/your/site/* rusthost-data/site/
```

### Step 5 — Start the server

```bash
./target/release/rusthost
```

The terminal dashboard appears. Your site is live at `http://localhost:8080`.

Tor bootstraps in the background — your `.onion` address will appear in the **Endpoints** section of the dashboard after roughly 30 seconds on first run (subsequent starts reuse the cache and are much faster).

---

## OS-Specific Notes

### macOS

Everything works out of the box. If you see a firewall prompt asking whether to allow RustHost to accept incoming connections, click Allow.

If you want to expose your server on your local network (not just `localhost`), change the bind address in `settings.toml`:

```toml
[server]
bind = "0.0.0.0"
```

RustHost will log a warning when you do this — that's expected and intentional.

### Linux

Works the same as macOS. If you're running under systemd, see the [Running as a systemd service](#running-as-a-systemd-service) section below.

On some minimal Linux installs you may need to install the OpenSSL development headers:

```bash
# Debian/Ubuntu
sudo apt install pkg-config libssl-dev

# Fedora
sudo dnf install pkg-config openssl-devel
```

### Windows

Build and run commands are the same, but use backslashes and the `.exe` extension:

```powershell
cargo build --release
.\target\release\rusthost.exe
```

Note that file permissions (e.g., restricting the log file to owner-only) behave differently on Windows. The security restrictions around key directories and log files are enforced where the Windows API supports it.

---

## Running as a systemd service

If you want RustHost to start automatically on boot, here's a simple service unit.

First, move your binary and data directory somewhere stable:

```bash
sudo cp target/release/rusthost /usr/local/bin/rusthost
sudo mkdir -p /var/rusthost
sudo cp -r rusthost-data/* /var/rusthost/
```

Set `interactive = false` in `/var/rusthost/settings.toml` so RustHost doesn't try to draw a TUI:

```toml
[console]
interactive = false
```

Create the service file:

```bash
sudo nano /etc/systemd/system/rusthost.service
```

```ini
[Unit]
Description=RustHost static file server
After=network.target

[Service]
Type=simple
User=www-data
ExecStart=/usr/local/bin/rusthost --config /var/rusthost/settings.toml --data-dir /var/rusthost
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
```

Enable and start it:

```bash
sudo systemctl daemon-reload
sudo systemctl enable rusthost
sudo systemctl start rusthost
sudo systemctl status rusthost
```

View logs:

```bash
journalctl -u rusthost -f
```

---

## Verifying Everything Works

### 1. Check the HTTP server

Open a browser and go to `http://localhost:8080`. You should see your site (or the placeholder page on a fresh install).

From the terminal:

```bash
curl -I http://localhost:8080
```

You should see a `200 OK` response with security headers like `X-Content-Type-Options` and `X-Frame-Options`.

### 2. Check the Tor onion address

Wait for the dashboard to show `TOR ● READY`. The `.onion` address will appear in the **Endpoints** section.

Open the Tor Browser and navigate to that address. Your site should load.

> **First run only:** Tor needs to download ~2 MB of directory data on first run. This usually takes 20–40 seconds. Subsequent starts reuse the cache and are ready in a few seconds.

### 3. Check the logs

Press `[L]` in the dashboard to switch to the log view. You should see startup messages and, once Tor is ready, a prominent banner with your `.onion` address.

The log file is at `rusthost-data/logs/rusthost.log`.

---

## Common Errors and Fixes

### `error: package 'arti-client v0.40.x' cannot be built because it requires rustc 1.86.0`

Your Rust version is too old. Run `rustup update stable` and try again.

### `Address already in use (os error 98)`

Port 8080 is taken by something else. Either:
- Stop the other service, or
- Change the port in `settings.toml`:

```toml
[server]
port = 9090
```

Or enable auto port fallback (it's on by default):

```toml
[server]
auto_port_fallback = true
```

### `error[E0463]: can't find crate for 'std'` (Windows)

The Microsoft C++ Build Tools aren't installed or aren't on the path. Install them from [visualstudio.microsoft.com/visual-cpp-build-tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/) and restart your terminal.

### Tor gets stuck on "STARTING" forever

This is usually a network issue. Check that:
- You have an internet connection
- Your firewall isn't blocking outbound connections on port 443 or 9001 (Tor's relay ports)
- You're not behind a strict corporate or school network that blocks Tor

If you're on a network that blocks Tor, you may need [bridges](https://bridges.torproject.org/). Arti bridge support is still maturing — this is one area where using the classic `tor` binary is currently more reliable.

### The terminal is messed up after RustHost crashes

RustHost installs a panic hook that attempts to restore the terminal on crash. If it fails anyway, run:

```bash
reset
```

Or close and reopen your terminal.

### `Unknown field "bund"` (or similar) at startup

You have a typo in `settings.toml`. RustHost rejects unknown config keys at startup. Check the spelling of the field name in the config — the error message will tell you exactly which field it doesn't recognise.

### My `.onion` address changed

If `rusthost-data/arti_state/` was deleted or moved, RustHost generates a new keypair and a new address. The state directory is what makes the address stable across restarts — back it up.

---

## Backing Up Your `.onion` Keypair

Your stable `.onion` address is tied to a keypair stored in:

```
rusthost-data/arti_state/
```

**Back this directory up somewhere safe.** If you lose it, you lose your `.onion` address permanently and will get a new one on the next start. There is no recovery.

To restore a backed-up keypair, copy the `arti_state/` directory back before starting RustHost.

---

## Updating RustHost

```bash
git pull
cargo build --release
```

Your `rusthost-data/` directory is not touched by the build — your config, site files, and keypair are safe.

---

## Uninstalling

Delete the binary and the `rusthost-data/` directory:

```bash
rm target/release/rusthost
rm -rf rusthost-data/
```

If you ran it as a systemd service:

```bash
sudo systemctl stop rusthost
sudo systemctl disable rusthost
sudo rm /etc/systemd/system/rusthost.service
sudo rm /usr/local/bin/rusthost
sudo rm -rf /var/rusthost
sudo systemctl daemon-reload
```
