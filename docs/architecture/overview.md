# Architecture overview

A 30-second tour of how proxxx is put together, then deeper rabbit
holes per topic.

## Shape

```
                        ┌────────────────────────────┐
                        │           main.rs          │
                        │  install panic_hook()      │
                        │  init tracing (file rot.)  │
                        │  wait_for_shutdown_signal  │
                        └─────────────┬──────────────┘
                                      │
            ┌─────────────────────────┼──────────────────────────┐
            │                         │                          │
            ▼                         ▼                          ▼
        cli::execute              tui::run                 mcp::run_server
   (argv → side effect)    (Elm: state + reducer)    (stdio JSON-RPC dispatch)
            │                         │                          │
            └─────────────┬───────────┴──────────────────────────┘
                          ▼
              ┌───────────────────────────┐
              │  enforce_preflight        │  ← risk gate (Vector V27.x)
              │  check_hitl               │  ← Telegram round-trip
              └────────────┬──────────────┘
                           ▼
              ┌───────────────────────────┐
              │   ProxmoxGateway trait    │
              │   (api/mod.rs)            │
              └────────────┬──────────────┘
                           ▼
              ┌───────────────────────────┐
              │   PxClient (api/client)   │  ← reqwest + governor +
              │   PbsClient (pbs/client)  │    rate limit + 32 MiB cap
              └────────────┬──────────────┘
                           ▼
                ┌──────────────────────┐
                │  Proxmox VE / PBS    │
                └──────────────────────┘
```

## Key constraints

The architecture is shaped by four hard rules:

1. **Single binary, no installer.** Cross-platform (macOS, Linux,
   musl static), zero system deps beyond TLS (rustls, no openssl).
2. **No skip flags in the gate.** Eight-stage pre-commit gate
   (secret-shape scan, fmt, clippy, audit, cargo-deny, all-tests,
   live read, live mutation) — anything that bypasses it is owned
   by the bypasser.
3. **Three callers, one core.** CLI, TUI, MCP — same risk gate, same
   HITL gate, same API client. Whatever protections apply to one,
   apply to all.
4. **Honest transparency.** "Implemented" and "verified end-to-end"
   are tracked separately in `pre-commit/*.md`. Today, 23 of 157
   invariants are E2E-verified (15%) — the gap is declared, not hidden.

## Module map

```
src/
├── main.rs              ; entry: panic hook, tracing init, shutdown signal
├── lib.rs               ; pub re-exports
├── api/                 ; PVE REST client + typed errors + types
│   ├── client.rs        ;   PxClient (reqwest + governor + 32 MiB cap)
│   ├── error.rs         ;   ApiError closed enum 
│   ├── auth.rs          ;   Token / ticket / Zeroizing<String> 
│   ├── mod.rs           ;   ProxmoxGateway trait
│   └── types/           ;   ~3100 LOC of serde-typed PVE responses,
│                        ;   split across 16 submodules (cluster, ha,
│                        ;   guest, guest_agent, storage, firewall,
│                        ;   pool, node, node_hw, task, replication,
│                        ;   access, acme, backup, console, notifications)
├── pbs/                 ; PBS REST client + restore subprocess
├── ssh/                 ; russh client + TOFU known_hosts + per-node pool
├── wsterm/              ; WebSocket termproxy client (serial console)
├── handoff/             ; SPICE .vv writer + noVNC URL builder + launchers
├── hitl/                ; Telegram bot + policy engine
├── alerts/              ; Predicates + dedup + notifier
├── mcp/                 ; Stdio JSON-RPC server + tool registry
├── access/              ; pveum shell-out for full grant-tree expansion
                          ; (`access permissions` API path is in api/client.rs)
├── state/               ; GitOps loop — export, diff, apply across 8
                          ; state families (pools, ACL, storage,
                          ; backup-jobs, firewall-cluster,
                          ; notifications, HA rules, HA resources)
├── audit/               ; Append-only SQLite mutation log + HMAC chain
├── incident/            ; Cluster-wide write kill-switch (freeze/thaw)
├── metrics/             ; Cluster heatmap + accounting + anomaly
├── config/              ; TOML loader + secret resolution
├── util/                ; panic_hook, shutdown, format
├── app.rs               ; Elm reducer (~2000 LOC)
├── app/                 ; Sub-state for views
│   ├── cache.rs         ;   SQLite time-travel cache
│   ├── queue.rs         ;   Operation queue + replay-as-script
│   ├── preflight.rs     ;   Pre-flight risk assessment (V27.x)
│   ├── snaptree.rs      ;   Snapshot tree builder
│   ├── ha.rs            ;   HA failover preview
│   ├── hw.rs            ;   PCI conflict detector
│   ├── search.rs        ;   nucleo fuzzy index
│   ├── iso_library.rs   ;   Curated cloud-image catalog
│   └── patch.rs         ;   Rolling upgrade orchestrator
├── tui/                 ; ratatui rendering
│   ├── mod.rs           ;   Run loop, dispatch, terminal guard
│   ├── event.rs         ;   Crossterm key → Action mapping
│   ├── terminal_guard.rs;   RAII enter/leave raw mode 
│   ├── views/           ;   18 view modules (one per screen)
│   └── widgets/         ;   modal, input_bar, pty
└── cli/                 ; argv parser + execute()
```

## The Elm pattern

The TUI is pure-functional Elm Architecture: `update(state, action)`
returns `(state, Option<SideEffect>)` with no I/O. Side effects are
dispatched as tokio tasks that send back `DataMsg`s over an mpsc.
This makes the reducer trivially testable without async.

See [Elm pattern](/architecture/elm-pattern).

## Error model

A typed `ApiError` enum in the domain layer, `anyhow::Error` at the
application boundary. Callers that want differentiated handling
`.downcast_ref::<ApiError>()`; callers that don't keep working
unchanged via `?`.

See [Error handling](/architecture/error-handling).

## Security model

Defense in depth across:

- TLS verification (per-profile, mirrors into WS client)
- Secret zeroization (`Zeroizing<String>` everywhere)
- Closed MCP tool registry (compile-time fixed)
- Pre-flight risk gate (V27.x)
- HITL approval round-trip (Telegram, deny-on-timeout)
- TOCTOU-safe SPICE `.vv` (mode 0600, O_EXCL, random suffix)
- Shell-injection-safe pveum invocation (`shell_quote` + 7 unit tests)
- Body cap (32 MiB) — no OOM via hostile API response
- Capped log rotation — no disk fill from long-running daemons

See [Security model](/architecture/security).

## What's not here

- **No web UI.** proxxx is terminal-only. The Proxmox web UI exists
  for graphical workflows.
- **No state machine for orchestration.** Long-running ops (patching,
  evacuation) are imperative + checkpointed; we are not Kubernetes.
- **No DSL for alerts / policies.** Closed enums of predicates,
  decided at compile time. Adding one is a code change.
- **No re-implementation of `pve-access-control`.** When ground truth
  lives in PVE's Perl, proxxx shells out and parses (`proxxx perms`
  uses `pveum` over SSH). The API-side `proxxx access permissions`
  is also available — same typed tree from `/access/permissions`,
  no SSH dependency — for the common case where the evaluator's full
  expansion isn't needed.

## See also

- [Elm pattern](/architecture/elm-pattern)
- [Error handling](/architecture/error-handling)
- [Security model](/architecture/security)
