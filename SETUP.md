# Setup guide

[Home](README.md) · [Operations reference](docs/operations.md) · [Development](CONTRIBUTING.md)

Start with the [download instructions](README.md#download-and-run). The commands below assume you are in the extracted binary folder. On Windows, replace `./rusthost-cli` with `.\rusthost-cli.exe`.

## Keep your site and settings together

```sh
./rusthost-cli --data-dir ./rusthost-data
```

The first run creates a settings file and a starter page. Runtime subdirectories appear as their services need them:

```text
rusthost-data/
  settings.toml
  site/
    index.html
  runtime/
    logs/
    tls/
    tor/
```

Put your files in `site/`. Edit `settings.toml` to change how RustHost runs, then restart. Pressing `R` only rescans the site; it does not reload settings. Without `--data-dir`, the data folder defaults to `rusthost-data` next to the executable.

## Change the common settings

Edit the existing sections in the generated file. The snippets in this guide are **edits to that file**, not complete replacement configurations. Do not create a second copy of a section.

| Setting | Default | Use |
| --- | --- | --- |
| `[server] bind` | `"127.0.0.1"` | Local HTTP only; use a LAN address or `"0.0.0.0"` to accept connections from other machines |
| `[server] port` | `8080` | HTTP port |
| `[site] directory` | `"site"` | Site folder, relative to the data directory |
| `[site] index_file` | `"index.html"` | Default page |
| `[tor] enabled` | `true` | Publish the site as an onion service |
| `[tls] enabled` | `false` | Start HTTPS |
| `[logging] enabled` | `true` | Write runtime logs |
| `[console] interactive` | `true` | Show the dashboard |

For local-only hosting, disable Tor as well as keeping the loopback bind:

```toml
[tor]
enabled = false
```

For a single-page app, add `spa_routing = true` under `[site]`. Unknown routes then serve the index page. Optional `error_404` and `error_503` values name custom HTML files relative to the site folder.

Directory listings and dotfile access are off in managed mode. Their settings are `enable_directory_listing` and `expose_dotfiles` under `[site]`. Keep private files outside the site folder.

For a PNG favicon, edit `[site]`:

```toml
[site]
favicon = "assets/site-icon.png"
enable_png_favicon = true
```

The path must stay inside the site folder. PNG support adds `/favicon.png`; `/favicon.ico` uses the configured favicon.

## Run without the dashboard

```sh
./rusthost-cli --data-dir ./rusthost-data --headless
```

Use this with a service manager, container, or remote shell. Stop with Ctrl+C or your service manager's normal stop signal. Use a writable data directory and keep one instance per directory.

## Enable HTTPS

### Local HTTPS

Edit `[tls]`:

```toml
[tls]
enabled = true
port = 8443
```

Open `https://localhost:8443`. RustHost creates a self-signed certificate; browsers will warn because they do not trust it. Plain HTTP remains available unless you enable redirects.

### Your own certificate

Place the PEM certificate chain and private key inside the data directory, enable TLS, and add:

```toml
[tls.manual_cert]
cert_path = "runtime/tls/manual/fullchain.pem"
key_path = "runtime/tls/manual/privkey.pem"
```

Both paths must stay within the data directory, and each file must be at most 1 MiB. Restart after replacing them. Manual certificates take priority over ACME when both are configured.

### Let's Encrypt

Point your domain's DNS at this machine and allow inbound TCP port 443. RustHost uses **TLS-ALPN-01** validation, so the ACME connection must reach RustHost's TLS listener. A proxy that terminates TLS may prevent validation. Wildcards are not supported by this challenge method.

Edit the generated sections:

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

Replace the example domain and email. Remove any `[tls.manual_cert]` section when choosing ACME. Test with `staging = true`, then change it to `false` and restart for trusted certificates. Staging certificates produce browser warnings. Binding ports 80/443 may require OS privileges or port forwarding.

Port 80 is needed for the HTTP redirect in this example, not for certificate validation. In redirect mode, `[tls].http_port` replaces the normal HTTP file-serving listener; it may equal `[server].port`. Redirects require TLS to be enabled. See the [ACME limitations](docs/operations.md#known-limitations) before relying on unattended renewal.

## Use Tor

Tor runs inside RustHost through Arti. No external daemon or `torrc` is needed. The dashboard shows bootstrap progress and the onion address; use Tor Browser to visit that address. First startup may take longer while directory data downloads.

Tor serves the same site through its own internal HTTP ingress. Keep `runtime/tor/arti_state/` to preserve the onion identity, and back up the whole data directory while stopped. Do not copy an active identity between simultaneously running instances. Tor state and cache live under `runtime/tor/`.

## Use Docker

Release images are published to `ghcr.io/csd113/rusthost` for Linux AMD64 and ARM64. Choose an available release tag; main-branch builds use `edge`.

```sh
docker run -d --name rusthost --restart unless-stopped \
  -p 127.0.0.1:8080:8080 \
  -v rusthost-data:/data \
  ghcr.io/csd113/rusthost:1.2.0
```

Open `http://127.0.0.1:8080`. The named volume keeps settings, site files, TLS state, and the Tor identity across container replacements. Container defaults are headless, bind internally to `0.0.0.0:8080`, and enable Tor. The host port above accepts local HTTP connections only; onion access is still enabled.

Edit `/data/settings.toml`, populate `/data/site`, then restart. The process uses UID/GID `10001`. Bind-mounted directories must be writable by that identity and contain settings with `server.bind = "0.0.0.0"`; an empty bind mount hides the image's settings. Map an additional port if you enable HTTPS. The built-in health check requests HTTP `/ready` on port 8080; override it if you change ports or enable redirects.

To build the image yourself, run `docker build -t rusthost:local .` from the source checkout.

## Troubleshoot

```sh
./rusthost-cli doctor --data-dir ./rusthost-data
```

Doctor checks the configuration, paths, listeners, TLS, Tor setup, and logging without starting the server. Results use `PASS`, `WARN`, `FAIL`, and `NOT RUN`. The dashboard's Doctor and Diagnostics pages provide more detail. Check `runtime/logs/rusthost.log` for runtime errors.

| Problem | Next step |
| --- | --- |
| Port is in use | Stop the other process or change the configured port; restart RustHost |
| Changed settings have no effect | Restart; `R` only rescans site files |
| Site rescan fails | Check permissions, file paths, configured error pages, and the scan limits in the operations reference |
| Tor is slow or fails | Check outbound internet access and logs; disable Tor if it is not needed |
| HTTPS browser warning | Self-signed and staging certificates are untrusted; use a trusted manual certificate or production ACME |
| Favicon missing | Check the path under the site folder and enable PNG support if needed |

## Upgrade

Stop RustHost, back up the data directory, and replace the executable with the new release binary. Start it with the same `--data-dir`. Keep your existing settings and runtime state, especially TLS keys and Tor identity. Read the [changelog](CHANGELOG.md) before upgrading.

If the settings file is missing, RustHost generates defaults without replacing an existing site or runtime data. Losing settings can re-enable default behavior, including Tor, so restore your saved configuration before restarting.
