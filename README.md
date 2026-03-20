# RustHost

A single-binary, zero-setup static-site hosting appliance written in Rust.

Serve a local website on `localhost` **and** expose it as a `.onion` address
over the Tor network — no configuration, no external services, no fuss.

---

## Quick start

```sh
# 1. Download or build the binary
cargo build --release
cp target/release/rusthost .

# 2. First run — creates ./data/ and writes default config
./rusthost

# 3. Drop your site into the data directory
cp -r my-site/* data/site/

# 4. Run again — local + onion live immediately
./rusthost
```

---

## Requirements

| Requirement | Notes |
|---|---|
| **Rust 1.75+** | For building from source |
| **Tor** | Only needed when `[tor] enabled = true` (the default). Install via your package manager: `apt install tor`, `brew install tor`, etc. RustHost detects if Tor is missing and warns you at launch. |

RustHost itself has **no other runtime dependencies**.  The binary is
self-contained; it generates all config files and directories automatically.

---

## Directory layout

After first run, RustHost creates the following structure next to the binary:

```
rusthost              ← the binary
data/
  settings.toml       ← full commented config (edit freely)
  site/               ← drop your HTML / CSS / JS here
    index.html        ← placeholder, replace with your content
  tor/
    torrc             ← auto-generated on every run (do not edit)
    data/             ← Tor's internal state (keys, routing cache)
    hidden_service/   ← written by Tor: hostname + private_key
  logs/
    rusthost.log      ← append-only log file
```

> **Important:** `data/tor/hidden_service/` is created and owned by the `tor`
> process. Deleting it generates a new `.onion` address permanently.

---

## Configuration

`data/settings.toml` is generated on first run with every field present and
documented.  Edit it freely; press **R** in the dashboard to reload.

### Key settings

```toml
[tor]
# Master on/off switch — disable if you only need local serving
enabled = true

[server]
# Increment automatically if the port is busy
auto_port_fallback = true

[console]
# Set to false for headless / systemd use
interactive = true
```

---

## Dashboard

```
────────────────────────────────
  RustHost
────────────────────────────────

Status
  Local Server : RUNNING (127.0.0.1:8080)
  Tor          : READY

Endpoints
  Local : http://localhost:8080
  Onion : http://abc123xyz456.onion

Site
  Directory : ./data/site
  Files     : 12
  Size      : 1.4 MB

Activity
  Requests  : 42
  Errors    : 0

────────────────────────────────
[H] Help   [R] Reload   [T] Restart Tor   [O] Open   [L] Logs   [Q] Quit
────────────────────────────────
```

### Key bindings

| Key | Action |
|---|---|
| `H` | Show key-binding help overlay |
| `R` | Rescan `./data/site/` and update file stats |
| `T` | Restart the Tor subprocess |
| `O` | Open local URL in system browser |
| `L` | Toggle log view |
| `Q` | Graceful shutdown |

---

## Building

```sh
# Debug build
cargo build

# Optimised release build (with LTO + strip)
cargo build --release
```

---

## Headless / systemd

Set `[console] interactive = false` in `settings.toml` to disable the
interactive dashboard.  RustHost will print a single startup line and run
silently, suitable for use as a `systemd` service or in a container.

Example `systemd` unit:

```ini
[Unit]
Description=RustHost static site server
After=network.target

[Service]
ExecStart=/opt/rusthost/rusthost
WorkingDirectory=/opt/rusthost
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

---

## Tor not found?

If you see this at launch:

```
  ⚠  Tor not detected.
     `tor` was not found in your PATH.
     Install Tor and restart, or set [tor] enabled = false.
```

Either install Tor for your platform:

```sh
# Debian / Ubuntu
sudo apt install tor

# macOS
brew install tor

# Arch
sudo pacman -S tor
```

…or disable Tor entirely in `settings.toml`:

```toml
[tor]
enabled = false
```

---

## License

MIT
