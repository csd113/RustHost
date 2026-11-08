# Operations reference

[Home](../README.md) · [Setup](../SETUP.md) · [Development](../CONTRIBUTING.md)

Use the setup guide for common tasks. This reference covers deployment behavior and limits that matter when running a persistent service.

## Command line

| Argument | Purpose |
| --- | --- |
| `--data-dir <path>` | Use a specific data root; otherwise `rusthost-data` beside the executable |
| `--config <path>` | Read an alternative settings file; does not change the data root |
| `--serve <dir>` | Serve an existing folder with in-memory settings |
| `--port <n>` | Change the one-shot port; only valid with `--serve` |
| `--no-tor` | Disable Tor in one-shot mode; only valid with `--serve` |
| `--headless` | Disable the interactive dashboard |
| `doctor` | Check configuration and startup assumptions without serving |
| `-h`, `--help` | Print usage |
| `-V`, `--version` | Print version, profile, commit, and target |

One-shot mode ignores managed settings, binds to `127.0.0.1`, enables directory listings and Tor, and disables file logging. It uses the resolved site's parent as its data root, so `runtime/` may be created there even though no settings file is written. Use `--no-tor` for a local-only run.

## Configuration reference

Start with the generated `settings.toml`. The required top-level sections are `[server]`, `[site]`, `[tor]`, `[logging]`, `[console]`, and `[identity]`; individual fields have defaults. `[tls]` and `[[redirects]]` are optional. A file containing only server and site sections is incomplete.

| Section | Settings |
| --- | --- |
| `server` | `bind`, `port`, `auto_port_fallback`, `open_browser_on_start`, `max_connections`, `max_connections_per_ip`, `shutdown_grace_secs`, `csp_level`, `trusted_proxies` |
| `site` | `directory`, `index_file`, `favicon`, `enable_png_favicon`, `enable_directory_listing`, `expose_dotfiles`, `spa_routing`, `error_404`, `error_503` |
| `tor` | `enabled`, `shutdown_grace_secs` |
| `logging` | `enabled`, `level`, `file`, `filter_dependencies` |
| `console` | `interactive`, `refresh_rate_ms`, `show_timestamps` |
| `identity` | `instance_name` |
| `tls` | `enabled`, `port`, `redirect_http`, `http_port`, `acme`, `manual_cert` |
| `tls.acme` | `enabled`, `domains`, `email`, `staging`, `cache_dir` |
| `tls.manual_cert` | `cert_path`, `key_path` |

The [types and defaults](../src/config/mod.rs), [validation](../src/config/loader.rs), and [generated settings](../src/config/defaults.rs) define exact accepted values. Unknown fields in the main configuration sections are rejected. Restart for all settings changes.

Add exact-path redirects with array entries:

```toml
[[redirects]]
from = "/old-page"
to = "/new-page"
status = 301
```

Redirects run before filesystem lookup. Use `302` for a temporary redirect. Redirect destinations are validated. `server.bind` takes one IPv4 or IPv6 address; there is no separate dual-stack setting. There is no built-in Prometheus metrics endpoint.

## Monitoring and reloads

```sh
curl -i http://127.0.0.1:8080/health
curl -i http://127.0.0.1:8080/ready
```

`/health` returns `OK`; `/ready` returns `READY` after startup and active-directory checks succeed. Use the HTTPS endpoint when HTTP redirects are enabled. Readiness is not proof of external onion reachability or successful ACME renewal.

The dashboard's Home, Logs, Doctor, Diagnostics, Tor, Network, Site, Settings, and Help pages show runtime status. `M` opens the menu, `L` shows logs, `H` shows help, `O` opens the local URL, and `Esc` goes back. `Q` asks for shutdown confirmation. In headless mode use Ctrl+C or the service manager; Unix also supports SIGHUP for a site rescan.

`R` and SIGHUP prepare a new site snapshot, including favicon and custom error pages. Each request selects one complete generation, even on existing keep-alive connections. A failed scan keeps the previous generation. It cannot undo external file changes: retain old deployment directories until in-flight requests finish, and switch a stable symlink or equivalent when publishing a new tree. Editing files in place is not a filesystem snapshot.

## Exposure and HTTP behavior

The default HTTP bind is loopback, but **Tor is enabled by default**. Disable Tor explicitly if the site should remain local. Use firewall rules for public HTTP/HTTPS and put an authentication service in front if needed. RustHost has no accounts or access-control layer.

Keep sensitive content outside the site root. Dotfiles are blocked by default, including hidden symlink targets; path and favicon containment checks do not make a directory writable by hostile local users safe. Only regular files are served. Ancestor replacement by a local writer remains a filesystem race boundary.

`trusted_proxies` is empty by default, so forwarded client addresses are ignored. Configure only proxies you control. CSP defaults to `off`; `relaxed` permits external resources and eval, while `strict` uses same-origin resources but still permits inline scripts/styles. `Referrer-Policy: no-referrer` is always sent.

HTTP supports GET, HEAD, and OPTIONS. Compression respects encoding negotiation; `.br` and `.gz` sidecars must match the selected encoding. Metadata ETags are not proof of byte identity: `If-Range` conservatively returns full content, and HEAD ignores ranges. Keep sidecars synchronized with their source files.

## Resource limits

| Resource | Limit / behavior |
| --- | --- |
| Connections | Default 256 total, 16 per IP; HTTP, HTTPS and Tor ingress share admission capacity |
| Shutdown | Managed HTTP/HTTPS grace 30 seconds; managed Tor grace 5 seconds (one-shot Tor uses 30 seconds) |
| Request headers | Five-second deadline and 16 KiB request buffer |
| TLS handshake | Ten seconds, including ACME ALPN negotiation |
| Transfer inactivity | Five seconds for clearnet; 60 seconds for Tor relay/ingress; progress in either direction counts |
| Blocked write/flush/shutdown | 60 seconds; shorter inactivity limits can expire first |
| Total connection lifetime | 24 hours for HTTP drivers and Tor relays, even with continuing trickle traffic |
| HTTP redirect write | Ten seconds |
| Tor bootstrap / local connect / stream accept | 120 seconds / five seconds / ten seconds; bootstrap retry/backoff is bounded |
| Site scan | 64 directory levels, one million entries, 4,096 pending directories; unreadable entries reject the scan |
| Directory listing | At most 512 entries |
| Unique visitors | At most 65,536 in-memory hashes; `65536+` is a lifetime lower bound; identifiers are not persisted |
| Logs | File writes stop at 100 MiB if rotation fails; periodic rotation attempts continue |
| Access logs / display / key input | Bounded queues of 4,096 records / 1,000 messages / 64 keys |
| Manual TLS files and ACME cache objects | At most 1 MiB each |

## Persistence and backup

Stop the instance and back up the whole data directory. Treat TLS bundles, ACME account keys, and Tor state as secrets. Avoid sharing a data directory or log files between active instances.

Development TLS stores the certificate and key together in `runtime/tls/dev/self-signed.pem`. Renewal retains `self-signed.previous.pem`. Valid legacy `.crt`/`.key` pairs can be imported without changing identity. Missing or malformed identity state without a valid recovery pair requires operator repair; it is not silently replaced.

Settings, development TLS bundles, ACME cache entries, and Doctor reports use atomic publication. Defaults do not overwrite existing files. ACME cache writes retain a validated previous generation, and cache failures stop issuance while an already deployed certificate can remain active. Manual certificates are validated and read, not rewritten.

The persistence helper reserves `.rusthost-persist.lock` and `.rusthost-persist.tmp`. Never remove the lock file while RustHost uses that directory. A later cooperating writer cleans abandoned staging files after acquiring the lock. A failed sync after rename means durability is unconfirmed; it does not guarantee the old file is still visible.

Unix writes sync file contents and directory metadata. These guarantees depend on filesystem support; default creation needs hard links. Windows file flushing is retained, but power-loss durability of rename/directory metadata is not established. Logs are best-effort diagnostics: crashes may lose buffered records, and rotation is not a multi-file transaction.

## Known limitations

- **ACME network bounds:** the selected upstream client lacks exposed per-operation deadlines and a response-body size limit. A stalled or excessive authenticated response can stall renewal or consume memory. Readiness may remain successful with an existing certificate even if issuance stops. Monitor certificate expiry separately. Timing out `state.next()` alone would not reliably cancel the retained order future.
- **Tor internals and identity durability:** RustHost bounds its bootstrap and relay work; Arti owns internal circuit queues, databases, and key persistence. Power-loss durability of onion-key updates is not established. Live Tor load, reconnect, and failure behavior require separate validation.
- **Filesystem and OS stalls:** cancellation cannot force a blocked synchronous syscall or filesystem worker to finish. Power-cut, disk-full, ACL, symlink-race, and platform-specific recovery behavior require deployment-specific testing.
- **Validation scope:** compiler/build checks and isolated release probes do not establish live ACME issuance/renewal, public Tor reachability, or production throughput. See [Contributing](../CONTRIBUTING.md) for current checks and dependency exceptions.

Superseded migration plans and audit narratives were removed from the working tree. Their historical evidence remains in Git history; [CHANGELOG.md](../CHANGELOG.md) retains release history. This page describes current operational constraints without treating old test runs as current coverage.
