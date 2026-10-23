# Architecture

> **Audience**: contributors, security reviewers, AI agents driving
> a `cargo build` and wondering what they're staring at.
>
> **Length budget**: one page. For depth on any single subsystem,
> follow the file links — every module has a top-of-file `//!`
> block that explains itself.
>
> **Every structural claim here is checked** by
> `tests/architecture_claims.rs` (names, paths, gate order, I/O rules)
> and by the `main.rs` tests (the commands in the process table parse).
> A claim that cannot be checked does not belong on this page.

## What proxxx is

A single Rust binary with **three callers**: a CLI (scriptable,
JSON-friendly), a TUI (interactive, ratatui), and an MCP server (LLM
agents). It talks to Proxmox VE and Proxmox Backup Server over REST, SSH
and WebSocket. No agent runs on the cluster.

## The gates, and which caller runs which

Two layers. The **gateway layer** is shared by construction; the
**caller layer** is not, and differs per caller.

**Gateway layer: every mutation, every caller.** Every mutating HTTP
request `PxClient` sends is built in one of four places in
`src/api/client.rs`: the private helpers `post`, `put` and `delete`, and
the streaming storage upload. Each runs, in this order and before the
request leaves the process:

1. `PxClient::guard_read_only`: refuses when the profile is `read_only`.
2. `incident::check_not_frozen_for`: refuses during an incident freeze
   (global, or of this profile).
3. `audit::MutationAuditCtx::write_ahead_at`: the write-ahead entry in
   the HMAC-chained audit log; refuses (exit 8) when it cannot be
   written. The outcome is recorded after the response.

A new gateway method that mutates through the helpers cannot skip them,
and the test fails on a mutating request built anywhere else in
`src/api` without them.

**Caller layer: risk preflight and human approval.**

| | CLI | TUI | MCP |
| :--- | :--- | :--- | :--- |
| Risk preflight (`app::preflight`) | `assess_deep` on stop, restart, delete, migrate, disk move and disk resize; a Severe risk refuses (exit 6) unless `--allow-risk` | `assess` (no deep checks) on operations run from the operation queue; actions from the command palette run none | none |
| Human approval (`hitl`) | none: with `--secure`, destructive commands are refused (exit 8) | `hitl::policy::check_policies` plus `--secure`: Telegram approval before the side effect runs | every destructive tool needs a matching policy and is queued for Telegram approval; `proxxx hitl serve` executes it after approval |

The differences in the caller layer are the current state, not a
design goal; closing them is tracked in #507.

## Module map (`src/`)

| Module | Responsibility | Sync / Async |
| :--- | :--- | :--- |
| [`api/`](src/api/) | PVE REST client: `ProxmoxGateway` trait, `PxClient`, typed `ApiError`, retry, per-profile TLS pin | async |
| [`pbs/`](src/pbs/) | PBS REST client + restore handoff to `proxmox-backup-client` | async |
| [`wsterm/`](src/wsterm/) | Termproxy WebSocket (serial console), with frame and message size caps | async |
| [`ssh/`](src/ssh/) | russh-based sessions and PTY | async |
| [`access/`](src/access/) | parser for effective permissions (`pveum` output) | sync |
| [`config/`](src/config/) | TOML profiles, secret resolution, live reload (`config::watcher`) | sync (load), async (watch) |
| [`audit/`](src/audit/) | append-only SQLite audit log with an HMAC-SHA256 chain | sync |
| [`incident/`](src/incident/) | freeze lock (`incident freeze` / `thaw`) | sync |
| [`app.rs`](src/app.rs) | the TUI reducer: `Action × AppState → AppState + SideEffect`; no `.await` and no file, network or process I/O | sync |
| [`app/`](src/app/) | helpers: preflight, snaptree, cache, HA preview, queue, search. `preflight`, `patch` and `cache` do I/O | mixed |
| [`alerts/`](src/alerts/) | alert engine, dedup and notifiers | async |
| [`hitl/`](src/hitl/) | Telegram approvals: signed callbacks, pending store, execution after approval | async |
| [`mcp/`](src/mcp/) | MCP server: stdio JSON-RPC and Streamable HTTP, tool registry in `mcp::tools` | async |
| [`metrics/`](src/metrics/) | Prometheus exporter | async |
| [`tui/`](src/tui/) | ratatui render loop, views, widgets, event loop | sync (render), async (events) |
| [`cli/`](src/cli/) | clap dispatch and per-domain handlers | async |
| [`handoff/`](src/handoff/) | SPICE `.vv` file, noVNC URL, `remote-viewer` launch | sync |
| [`util/`](src/util/) | sanitize, output format, shutdown, panic hook, durable writes | sync |

`AppState` is used only by the TUI: `src/tui/`, `src/app.rs` and the
reducer helpers `src/app/queue.rs` and `src/app/search.rs`. The CLI and
MCP paths are imperative and reach the gates directly.

## Data flow: deleting guest 100

### CLI: `proxxx delete 100 --yes`

```
main ─► cli::execute
          ├─ enforce_cli_secure_mode        (--secure: refuse, exit 8)
          ├─ cli::common::find_guest_full    (GET /cluster/resources)
          ├─ cli::common::enforce_preflight_with_notes
          │     └─ app::preflight::assess_deep   (Severe: exit 6)
          └─ execute_delete ─► PxClient::delete_guest
                                 ├─ GET status/current (must be stopped)
                                 └─ PxClient::delete   (gateway layer)
```

### TUI: `d` on a guest row

```
tui::event::map_key ─► Action::EnqueueBatchOperation([DeleteGuest])
app::update          ─► app::queue::QueuedOp in AppState.op_queue
'C' in the queue     ─► Action::ExecuteQueue ─► SideEffect::ExecuteQueue
tui dispatch_side_effect
          ├─ queue snapshot saved first (refuses to run if it cannot be)
          ├─ HITL check per operation (policy / --secure)
          ├─ app::preflight::assess          (Severe: operation fails)
          └─ PxClient::delete_guest ─► PxClient::delete (gateway layer)
```

### MCP: `tools/call delete_guest {"guest_id": 100}`

```
stdin line (16 MiB cap, mcp::server::MAX_RPC_LINE_BYTES)
  ─► mcp::server::RpcRequest ─► mcp::dispatch::dispatch_rpc
       └─ tokio::time::timeout(tool budget) ─► mcp::dispatch::handle_tool_call
            ├─ registry lookup + parameter type checks
            └─ destructive: hitl::policy::check_policies
                 ├─ no policy: refused
                 └─ policy: pending request stored, Telegram approval sent,
                            result "intercepted", nothing deleted yet
proxxx hitl serve, on approval:
  hitl::daemon::handle_callback_update ─► guest re-checked against the request
  ─► mcp::dispatch::exec_delete_guest ─► PxClient::delete_guest (gateway layer)
```

## Process model

| Process | Entry point | Lifecycle |
| :--- | :--- | :--- |
| One-shot CLI | `proxxx <command>` | runs one command and exits |
| TUI | `proxxx` (no command) | interactive until quit |
| Background daemon | `proxxx daemon serve` | long-running: alerts, HITL listener and schedule tick in one process |
| Alerts watcher | `proxxx alerts watch` | long-running |
| HITL listener | `proxxx hitl serve` | long-running Telegram long-poll |
| MCP stdio | `proxxx mcp serve` | one process per client session |
| MCP HTTP | `proxxx mcp serve-http --port 8080` | long-running HTTP server |
| Prometheus exporter | `proxxx metrics serve` | long-running HTTP server |

All of them are the same binary; `src/main.rs` routes by command, and
no command means the TUI.

## Build profiles

`[profile.release]` in `Cargo.toml`: `lto = true`, `codegen-units = 1`,
`strip = true`, `opt-level = "z"`. `scripts/gate.sh` runs clippy and the
test suite with `--release`, so the gate tests the optimisation level
that ships.

## Cross-references

* [README.md](README.md) — user-facing surface
* [THREAT_MODEL.md](THREAT_MODEL.md) — attack surfaces + mitigations
* [SECURITY.md](SECURITY.md) — vulnerability reporting
* [CONTRIBUTING.md](CONTRIBUTING.md) — how to land a PR
* [`pre-commit/01-feature-coverage.md`](pre-commit/01-feature-coverage.md) — per-feature live-verification matrix
* [`pre-commit/03-security-invariants.md`](pre-commit/03-security-invariants.md) — security invariant ledger

## Non-goals

These are stated intent, not checked behaviour. proxxx does **not**:

* render graphical SPICE / VNC frames (hands off to `remote-viewer`
  / system browser)
* re-implement `pveum` in Rust (when ground truth lives in pveum, we
  shell out, parse, and stay out of the way)
* manage cluster bring-up (corosync / qdevice mutations are read-only
  or operator-in-the-loop)
* replace the Proxmox web UI (built for the workflows where the web
  UI is slow, repetitive, or unreachable from a terminal context)
