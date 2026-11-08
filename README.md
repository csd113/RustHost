# RustHost

[![CI](https://github.com/csd113/RustHost/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/csd113/RustHost/actions/workflows/ci.yml)
[![Dependency Audit](https://github.com/csd113/RustHost/actions/workflows/audit.yml/badge.svg)](https://github.com/csd113/RustHost/actions/workflows/audit.yml)
[![License: MIT](https://img.shields.io/github/license/csd113/RustHost)](LICENSE)

Serve a folder of HTML, CSS, JavaScript, and other files from one executable. RustHost includes a terminal dashboard, optional HTTPS, and a built-in Tor onion service.

## Download and run

**You do not need Rust or a separate Tor installation.**

1. Download a ZIP from [Releases](https://github.com/csd113/RustHost/releases/latest) for your computer:

   | Archive suffix | Computer |
   | --- | --- |
   | `windows-x86_64` | Windows, Intel/AMD 64-bit |
   | `apple-silicon` | macOS, Apple Silicon |
   | `linux-x86_64` | Linux, Intel/AMD 64-bit |
   | `linux-arm64` | Linux, ARM64 |

2. Extract the ZIP and open a terminal in the extracted folder.
3. Start RustHost:

   **Windows (PowerShell)**

   ```powershell
   .\rusthost-cli.exe --data-dir .\rusthost-data
   ```

   **macOS / Linux**

   ```sh
   chmod +x ./rusthost-cli
   ./rusthost-cli --data-dir ./rusthost-data
   ```

4. Open **http://127.0.0.1:8080**. Replace `rusthost-data/site/index.html` with your own page and put the rest of your site in that folder.

The dashboard shows addresses and status. Press `H` for help, `R` to rescan the site, or `Q` then `Y` to stop.

**Tor is on by default**, so your site can also become available at a public `.onion` address even though HTTP is bound to localhost. For local-only use, stop RustHost, set `enabled = false` under `[tor]` in `rusthost-data/settings.toml`, and restart.

## Already have a site folder?

Serve it directly without creating a settings file:

```sh
./rusthost-cli --serve ./public --no-tor
```

On Windows, use `.\rusthost-cli.exe` instead. Add `--port 3000` to change the port or `--headless` to run without the dashboard. This mode enables directory listings and disables file logging. Omit `--no-tor` to enable onion access. Runtime data can still be created beside the served folder.

## What it supports

- Static files, directory listings, single-page app routing, custom error pages, and redirects.
- HTTP caching, range requests, compression, and precompressed `.br` / `.gz` files.
- HTTPS with a local self-signed certificate, your own certificate, or Let's Encrypt.
- Built-in Tor through Arti, health checks, logs, and a `doctor` command for troubleshooting.

RustHost does not execute server-side code or provide accounts, uploads, or authentication. Review the files you publish; use an authentication service in front of it if your site needs access control.

## More help

- [Setup guide](https://github.com/csd113/RustHost/blob/main/SETUP.md): settings, HTTPS, Tor, Docker, and upgrades.
- [Operations reference](https://github.com/csd113/RustHost/blob/main/docs/operations.md): CLI options, deployment limits, persistence, and known limitations.
- [Contributing](https://github.com/csd113/RustHost/blob/main/CONTRIBUTING.md): build from source and validate changes.
- [Changelog](https://github.com/csd113/RustHost/blob/main/CHANGELOG.md): release history.

The online guides also work when this README is opened from a release ZIP. RustHost is available under the [MIT License](LICENSE).
