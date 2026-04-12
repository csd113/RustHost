# RustHost — File Tree Reference

Complete annotated layout of every file in the project.
Use this as your map when organizing or navigating the codebase.

```
rusthost/                          ← project root (clone / unzip here)
│
├── Cargo.toml                     ← package manifest + all dependencies
├── README.md                      ← setup, usage, headless guide
├── FILE_TREE.md                   ← this file
│
└── src/
    │
    ├── main.rs                    ← binary entry point; boots Tokio runtime
    │                                declares all top-level modules
    │
    ├── config/                    ← everything related to settings.toml
    │   ├── mod.rs                 ← Config struct + all sub-structs + Default impl
    │   ├── loader.rs              ← load() + validate() — reads settings.toml
    │   └── defaults.rs            ← write_default_config() — first-run file writer
    │
    ├── runtime/                   ← orchestration layer; owns shared state
    │   ├── mod.rs                 ← re-exports sub-modules
    │   ├── state.rs               ← AppState, SharedState, Metrics, TorStatus,
    │   │                            ConsoleMode, format_bytes()
    │   ├── lifecycle.rs           ← run() — first-run detection, normal startup
    │   │                            sequence, shutdown, browser open
    │   └── events.rs              ← KeyEvent enum + handle() dispatcher
    │                                (H / R / T / O / L / Q)
    │
    ├── server/                    ← static HTTP/1.1 file server
    │   ├── mod.rs                 ← run() — port binding with fallback,
    │   │                            accept loop, scan_site()
    │   ├── handler.rs             ← per-connection handler: path resolution,
    │   │                            path-traversal guard, file serving
    │   ├── mime.rs                ← for_extension() — 30+ MIME type mappings
    │   └── fallback.rs            ← NO_SITE_HTML — built-in "no site" page
    │
    ├── tor/                       ← Tor subprocess manager
    │   ├── mod.rs                 ← run() — spawn, monitor stdout,
    │   │                            bootstrap detection, watchdog / restart
    │   └── torrc.rs               ← write() — generates torrc from config
    │
    ├── console/                   ← interactive terminal dashboard
    │   ├── mod.rs                 ← start() — raw mode, render loop task,
    │   │                            cleanup() — terminal restore
    │   ├── dashboard.rs           ← render_dashboard(), render_log_view(),
    │   │                            render_help() — pure string formatters
    │   └── input.rs               ← spawn() — blocking key reader on
    │                                dedicated thread → KeyEvent channel
    │
    └── logging/
        └── mod.rs                 ← init() — registers global log::Log impl;
                                     writes to file + in-memory ring buffer;
                                     recent_lines() for console log view
```

---

## Module dependency graph

```
main
 └── runtime::lifecycle          ← top-level orchestrator
      ├── config::loader         ← reads + validates settings.toml
      ├── config::defaults       ← writes settings.toml on first run
      ├── logging                ← global logger (init once)
      ├── runtime::state         ← SharedState + SharedMetrics
      ├── runtime::events        ← key dispatch (H/R/T/O/L/Q)
      ├── server                 ← HTTP server task
      │    ├── server::handler   ← per-connection handler
      │    ├── server::mime      ← MIME table
      │    └── server::fallback  ← built-in 404 page
      ├── tor                    ← Tor process manager task
      │    └── tor::torrc        ← torrc generator
      └── console                ← terminal UI tasks
           ├── console::dashboard ← screen formatters
           └── console::input    ← raw key reader thread
```

---

## Generated runtime layout (next to binary)

Created automatically — never commit these to version control.

```
./rusthost                         ← the binary

./data/
    settings.toml                  ← generated on first run; edit freely
    site/
        index.html                 ← placeholder; replace with your content
        ...                        ← your HTML / CSS / JS / assets
    runtime/
        logs/
            rusthost.log           ← append-only; survives restarts
        tls/
            dev/
                self-signed.crt    ← local dev cert (if TLS enabled)
                self-signed.key    ← local dev key (if TLS enabled)
            acme/                  ← ACME cache/state (if ACME enabled)
        tor/
            arti_state/            ← Tor identity + persistent state
            arti_cache/            ← Tor consensus cache
```

---

## Key facts per file

| File | Lines | Purpose |
|---|---|---|
| `main.rs` | ~25 | Entry point only; no logic |
| `config/mod.rs` | ~130 | All config structs + Default |
| `config/loader.rs` | ~100 | Parse + validate settings.toml |
| `config/defaults.rs` | ~110 | Commented default config string |
| `runtime/state.rs` | ~130 | All shared mutable state |
| `runtime/lifecycle.rs` | ~220 | Full startup + shutdown sequence |
| `runtime/events.rs` | ~90 | Key → action dispatch |
| `server/mod.rs` | ~130 | TCP bind + accept loop |
| `server/handler.rs` | ~200 | HTTP parsing + file serving |
| `server/mime.rs` | ~55 | Extension → MIME mapping |
| `server/fallback.rs` | ~50 | Built-in "no site" HTML |
| `tor/mod.rs` | ~180 | Process spawn + monitor + restart |
| `tor/torrc.rs` | ~70 | torrc file generation |
| `console/mod.rs` | ~130 | Raw mode + render loop |
| `console/dashboard.rs` | ~180 | Dashboard / log / help formatters |
| `console/input.rs` | ~80 | Blocking key reader |
| `logging/mod.rs` | ~140 | File + ring-buffer logger |

---

## Build commands

```sh
# Development build
cargo build

# Optimised release (LTO + strip — smallest binary)
cargo build --release

# Run directly
cargo run

# Run release binary
./target/release/rusthost
```

## Adding a feature

1. Identify which module owns the concern (see graph above).
2. Add the logic to the appropriate sub-module file.
3. If the feature needs new shared state, add fields to `runtime/state.rs`.
4. If the feature needs a new key binding, add a variant to `runtime/events.rs`
   and a mapping in `console/input.rs`.
5. If the feature needs a new config field, add it to `config/mod.rs`,
   `config/loader.rs` (validation), and `config/defaults.rs` (documented default).
