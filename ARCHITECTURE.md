# Architecture

> **Audience**: contributors, security reviewers, AI agents driving
> a `cargo build` and wondering what they're staring at.
>
> **Length budget**: one page. For depth on any single subsystem,
> follow the file links — every module has a top-of-file `//!`
> block that explains itself.

## What proxxx is

A single Rust binary that exposes **three callers** over **one
state machine**: a CLI (scriptable, JSON-friendly), a TUI
(interactive, ratatui), and an MCP server (LLM agents). Talks to
Proxmox VE and Proxmox Backup Server over REST + SSH + WebSocket.
No agent on the cluster.

## The three callers, one core

```
                    ┌─────────────────────────────┐
                    │     pure state machine      │
                    │       (src/app/*.rs)        │
                    │   Action → State + SideEff  │
                    └──────────────┬──────────────┘
                                   │
                       Action / SideEffect bus
                                   │
              ┌───────────────────┼────────────────────┐
              │                   │                    │
        ┌───────┐         ┌───────────┐          ┌───────────┐
        │  CLI  │         │   TUI     │          │   MCP     │
        │ (clap)│         │ (ratatui) │          │ (stdio +  │
        │       │         │           │          │  HTTP)    │
        └───────┘         └───────────┘          └───────────┘
```

All three callers go through the same:
* `app::reducer` (pure: Action × AppState → AppState + SideEffect)
* `api::ProxmoxGateway` trait (network I/O)
* `app::preflight::assess()` (11-variant risk gate)
* `hitl::policy` (Telegram approval gate)
* `audit::AuditLogger` (HMAC-chain mutation log)

Same gates apply to every mutation, regardless of which caller
initiated it. There is no "skip the risk gate for MCP" path.

## Module map (`src/`)

| Module | Responsibility | Sync / Async |
| :--- | :--- | :--- |
| [`api/`](src/api/) | PVE REST client. rustls, cookie store, retry, typed `ApiError`, per-profile TOFU pin | async |
| [`pbs/`](src/pbs/) | PBS REST client + restore handoff to `proxmox-backup-client` | async |
| [`wsterm/`](src/wsterm/) | Termproxy WebSocket (serial console). Frame size capped, custom rustls verifier when `verify_tls=false` | async |
| [`ssh/`](src/ssh/) | russh-based PTY pool. Hardened algorithm whitelist (Terrapin-safe) | async |
| [`access/`](src/access/) | `pveum` shell-out + parser for effective permissions. `shell_quote` defends injection | sync (parser), async (shellout) |
| [`config/`](src/config/) | TOML profile loader + secret resolution (env → file → inline → keychain). Watcher for SIGHUP reload | sync (load), async (watch) |
| [`audit/`](src/audit/) | Append-only SQLite audit log with HMAC-SHA256 chain | sync |
| [`app/`](src/app/) | **Pure state**. Reducer, preflight (11 risk variants), snaptree builder, cache, HA preview, batch policy. Zero I/O — testable end-to-end without a cluster | sync |
| [`alerts/`](src/alerts/) | Alert daemon: engine (predicates over cluster snapshots) + dedup + notifier (slack/discord/telegram/webhook) | async |
| [`hitl/`](src/hitl/) | Telegram daemon: long-poll, callback HMAC, replay-rejection, deny-on-timeout | async |
| [`mcp/`](src/mcp/) | MCP server: stdio JSON-RPC + Streamable HTTP. Compile-time tool registry, SHA-256 pinned | async |
| [`metrics/`](src/metrics/) | Prometheus exporter (cardinality-bounded labels) | async |
| [`tui/`](src/tui/) | ratatui render loop + views + widgets + event loop | sync (renderer), async (events) |
| [`cli/`](src/cli/) | clap dispatch. Per-domain handlers (vm, ct, access, audit, doctor, events, …) | async |
| [`handoff/`](src/handoff/) | SPICE `.vv` file + noVNC URL launcher + remote-viewer spawn | sync |
| [`util/`](src/util/) | sanitize (ANSI), format (output dispatch), shutdown (signal), spawn_traced, panic_hook (flight recorder), sparkline | sync |

## Data flow — three representative paths

### CLI mutation: `proxxx delete 100 --yes`

```
argv ─► clap ─► cli::execute_delete
              │
              ├─► find_guest(client, vmid=100) ── REST /cluster/resources
              │
              ├─► assess_deep(client, pbs, Op::Delete, &guest)
              │      └─ 11 risk variants checked; if SEVERE without
              │         --allow-risk → PreflightRefusal (exit 6)
              │
              ├─► hitl::policy::match_or_request_approval()
              │      └─ if destructive + secure_mode: Telegram round-trip,
              │         deny-on-timeout 120s
              │
              ├─► client.delete_guest(node, vmid)  ── REST DELETE
              │
              ├─► audit::AuditLogger::log("delete", user, Some(100), ...)
              │
              └─► JSON to stdout, exit 0 / typed exit code on Err
```

### TUI keystroke: 'd' on a guest row

```
crossterm event ─► tui::event::Event::Key ─► tui::reducer
                                                 │
                                                 ├─► Action::PromptDelete(vmid)
                                                 │       │
                                                 │       └─ AppState gains
                                                 │          PendingDelete { vmid }
                                                 │       
                                                 └─► tui::view::overlay
                                                         renders modal
                                                         "Confirm delete?"
on 'y':
                              ─► Action::ConfirmDelete(vmid)
                                       │
                                       └─► SideEffect::EnqueueDelete
                                                │
                                                └─ async worker takes the
                                                   SideEffect off the queue,
                                                   then runs the SAME chain
                                                   as the CLI path above:
                                                   preflight → HITL → API → audit
```

### MCP tool call: `tools/call` `delete_guest({"guest_id":100})`

```
stdio JSON line ─► RpcRequest deserialize (16 MiB cap)
                     │
                     ├─ method == "tools/call"
                     │      params.name == "delete_guest"
                     │      params.arguments == {"guest_id": 100}
                     │
                     └─► dispatch::handle_tool_call(client, config, ...)
                                │
                                ├─► tools/* registry lookup
                                │      ├─ ParamType check (Int / Bool / Str)
                                │      └─ destructive flag = true
                                │
                                ├─► hitl gate (same as CLI path)
                                │
                                ├─► tokio::time::timeout(timeout_secs,
                                │      delete_guest_impl(...))
                                │      └─ DoS guard: -32001 on timeout
                                │
                                ├─► audit log (same writer)
                                │
                                └─► JSON-RPC result envelope
```

## Process model

| Daemon | Entry point | Lifecycle | State |
| :--- | :--- | :--- | :--- |
| One-shot CLI | `proxxx <verb>` | exec → tokio runtime → block_on → exit | in-memory only; audit log persisted |
| TUI loop | `proxxx` (no args) | exec → tokio runtime → ratatui loop → quit | in-memory `AppState`; SQLite cache persisted |
| Alerts daemon | `proxxx alerts watch` | long-running; SIGHUP reload, SIGINT graceful shutdown | dedup state in cache schema v2 |
| HITL daemon | `proxxx hitl serve` | long-running Telegram long-poll | session-local approval map; HMAC key on disk |
| MCP stdio | `proxxx mcp serve` | spawned by LLM client; one process per session | stateless beyond the underlying PVE client |
| MCP HTTP | `proxxx mcp serve-http --port 8080` | long-running axum server | stateless |
| Prometheus exporter | `proxxx metrics serve` | long-running axum server; scrapes PVE on every pull | stateless |

All processes share the **same binary** — the dispatch in
[src/main.rs](src/main.rs) routes by `cli.command` to the relevant
entry point; the TUI run-loop is the default.

## Reducer + side effect bus

The TUI uses an **Elm-style reducer**: state evolution is
`AppState × Action → AppState × Vec<SideEffect>`. Pure functions only;
the runtime drains side effects asynchronously and feeds results back
in as new Actions.

```
                ┌─────────────────┐
                │   AppState      │
                │   (pure data)   │
                └────────┬────────┘
                         │
   Event ─► Action ──► reducer ──► (AppState', [SideEffect])
                                          │
                                          ▼
                                  async worker pool
                                          │
                                  REST / SSH / WS / SQLite
                                          │
                                          ▼
                                  ResultEvent ─► Action ─► (loop)
```

This is what makes proxxx **testable without a cluster**: the
reducer is pure; the only thing that touches the network is the
`ProxmoxGateway` trait, which can be mock-implemented (see
`tests/api_test.rs` for the wiremock harness).

## Build profiles

| Profile | Flags | Use |
| :--- | :--- | :--- |
| `dev` | default | local iteration |
| `release` | `lto = true`, `codegen-units = 1`, `strip = true`, `opt-level = "z"` | size-optimised distribution (~6 MiB stripped) — single static musl binary for Linux x86_64 / aarch64; dynamic glibc for macOS aarch64 |
| `bench` | inherits `release` | criterion (`cargo bench`) |
| `test` | dev + `proptest` | full unit + integration + proptest runs |

The strict CI gate (`scripts/gate.sh`) builds in `release` so the
test surface matches the shipped binary's optimisation level.

## Cross-references

* [README.md](README.md) — user-facing surface
* [THREAT_MODEL.md](THREAT_MODEL.md) — attack surfaces + mitigations
* [SECURITY.md](SECURITY.md) — vulnerability reporting
* [CONTRIBUTING.md](CONTRIBUTING.md) — how to land a PR
* [`pre-commit/01-feature-coverage.md`](pre-commit/01-feature-coverage.md) — per-feature live-verification matrix
* [`pre-commit/03-security-invariants.md`](pre-commit/03-security-invariants.md) — security invariant ledger

## Non-goals

proxxx does **not**:

* render graphical SPICE / VNC frames (hands off to `remote-viewer`
  / system browser)
* re-implement `pveum` in Rust (when ground truth lives in pveum, we
  shell out, parse, and stay out of the way)
* manage cluster bring-up (corosync / qdevice mutations are read-only
  or operator-in-the-loop)
* replace the Proxmox web UI (built for the workflows where the web
  UI is slow, repetitive, or unreachable from a terminal context)
