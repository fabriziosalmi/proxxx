# MCP server

proxxx ships a Model Context Protocol server so LLM agents (Claude
Desktop, Cursor, custom Anthropic SDK clients) can drive Proxmox
clusters through the same hardened code path as the CLI and TUI.

## Why MCP

Letting a language model run shell commands against a Proxmox cluster
is a recipe for outages. MCP solves it by exposing a **typed,
deterministic, registry-pinned tool surface** — the agent picks from
a closed enum of operations, parameters are validated by the host
before execution, and destructive operations route through the same
HITL gate as human callers.

## The tool surface

Closed enum, compile-time fixed — 25 tools as of v0.2.0. Regenerate this
table from your binary with `proxxx mcp tools --json`:

| Tool | Destructive | Budget | Description |
| :--- | :---: | :---: | :--- |
| `list_nodes` | no | 30 s | Cluster nodes with status, CPU, RAM, uptime |
| `list_guests` | no | 30 s | All VMs and LXCs across the cluster |
| `get_guest_status` | no | 30 s | Detailed status for one guest |
| `start_guest` | no | 60 s | Start a stopped guest |
| `stop_guest` | **yes** | 60 s | Graceful or hard stop |
| `restart_guest` | **yes** | 60 s | Restart |
| `delete_guest` | **yes** | 180 s | Permanent delete (cannot be undone) |
| `suspend_guest` | **yes** | 60 s | Pause a running guest |
| `resume_guest` | no | 60 s | Resume a suspended guest |
| `clone_guest` | **yes** | 180 s | Clone a VM/LXC to a new VMID |
| `clone_with_cloudinit` | **yes** | 300 s | Clone QEMU template + apply cloud-init (user, sshkey, ipconfig0) in one call |
| `migrate_guest` | **yes** | 300 s | Live-migrate to another node |
| `create_guest` | **yes** | 120 s | Create new QEMU VM or LXC (node, type, name, memory, cores, disk, …) |
| `create_snapshot` | **yes** | 120 s | Create snapshot |
| `list_snapshots` | no | 30 s | List snapshots for a guest |
| `delete_snapshot` | **yes** | 120 s | Delete snapshot |
| `get_storage_pools` | no | 30 s | Per-node storage list with usage |
| `get_node_resources` | no | 30 s | Node CPU / memory / status detail |
| `get_node_status` | no | 30 s | Node uptime, kernel, version |
| `get_cluster_status` | no | 30 s | Cluster-wide quorum, nodes, services |
| `list_tasks` | no | 30 s | Recent cluster tasks (running + completed) |
| `get_task_log` | no | 30 s | Task log output by UPID |
| `list_cluster_events` | no | 15 s | Recent task events with elapsed time |
| `list_backup_jobs` | no | 30 s | Configured vzdump jobs |
| `get_replication_status` | no | 30 s | Replication job status for a node |

The full schema is exposed by `proxxx mcp tools --json`. Example
entry:

```json
{
    "name": "stop_guest",
    "description": "Stop a VM or LXC container",
    "destructive": true,
    "timeout_secs": 60,
    "parameters": [
        { "name": "guest_id", "type": "int",  "required": true,  "description": "Guest VMID (100-999999)" },
        { "name": "force",    "type": "bool", "required": false, "description": "Force stop without graceful shutdown" }
    ]
}
```

## Why a closed registry

LLM-driven prompt injection is real. If the registry were dynamic
(loaded from a TOML at startup, mutated by config), an attacker
controlling the config file could add arbitrary tools.

The registry is a Rust `static` — defined at compile time. Adding a
tool requires a code change, a PR, and the gate to pass. The MCP
server cannot be configured to expose more than what the binary
ships.

## Running the server

```sh
proxxx mcp serve
```

Stdio transport. Speaks JSON-RPC 2.0 framed by Content-Length
headers — the standard MCP envelope. Pipe-it under whatever client
your agent uses.

### HTTP transport, `mcp_token`, and DNS rebinding defence

For clients that speak MCP over HTTP:

```sh
proxxx mcp serve-http
```

Because an HTTP listener is reachable off the box (or from a local browser tab
via DNS rebinding on `127.0.0.1`), `serve-http` enforces two fail-closed
router layers:

1. **`Host` and `Origin` validation (DNS rebinding defence, `#342`)** — runs
   on **every** route (`POST /mcp`, `GET /mcp` SSE, and `GET /health`)
   **before** Bearer authentication:
   - **`Host` header**: must be present (a missing or empty `Host` header
     returns `400 Bad Request`) and must match one of the allowed authorities:
     - **Loopback bind** (`127.0.0.1`, `localhost`, `::1`, or any `127.0.0.0/8`
       address): `127.0.0.1:<port>`, `localhost:<port>`, and `[::1]:<port>`
       (plus `<bind>:<port>` and any explicit `--allowed-host` values).
     - **Exposed bind** (e.g. `0.0.0.0`, `::`, or a LAN IP): `<bind>:<port>`
       plus each value passed via the repeatable
       `--allowed-host <host[:port]>` flag (for example
       `proxxx mcp serve-http --bind 0.0.0.0 --port 3000 --token ... --allowed-host mcp.lan:3000`).
     - Any other `Host` returns `403 Forbidden` with a plain-text message naming
       the rejected host (`Forbidden: rejected Host '<host>'`), blocking DNS
       rebinding attacks where a rebound browser page sends
       `Host: attacker.example`.
   - **`Origin` header**: if present, must be `http://<allowed-authority>` or
     `https://<allowed-authority>`; otherwise `403 Forbidden` is returned.
     Requests without an `Origin` header (`curl`, CLI tools, and MCP SDK
     clients) are allowed.
   - **No CORS headers**: `serve-http` never emits `Access-Control-Allow-*`
     headers, as cross-origin browser access is not intended.
2. **Bearer token authentication and `SIGHUP` reload persistence (`#343`)**:
   - `serve-http` **refuses to start** on a non-loopback bind (e.g. `0.0.0.0`)
     unless a non-empty token is configured via `mcp_token` in the profile or
     `--token` on the CLI — pass `--insecure-bind` to override that consciously.
   - A token passed via the `--token` CLI flag is kept out of the reloadable
     `ProfileConfig` (`ConfigHandle`) and stored in `McpState` at startup. When
     `--token` is set, the auth gate always checks `cli_token`; when `--token`
     is omitted, it reads `mcp_token` from the live config so a `SIGHUP` reload
     can rotate the config token without ever dropping a CLI-supplied token.
   - An empty or whitespace-only token counts as **absent**. When the server is
     network-exposed without `--insecure-bind` and the effective token is
     absent, every request is denied (`401 Unauthorized`).

## Claude Desktop config

Drop into `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "proxxx": {
      "command": "/usr/local/bin/proxxx",
      "args": ["mcp", "serve", "--profile", "homelab"]
    }
  }
}
```

Restart Claude Desktop. The agent now sees the 25-tool surface.

## Audit the registry

Every MCP-capable build has a deterministic registry hash:

```sh
$ proxxx mcp tools --checksum
{
  "checksum": "8467de772787baa0"
}
```

Pin this in your CI / supply-chain tracker. If the hash changes
between builds, the tool surface changed — review the diff.

## Per-tool execution budget

JSON-RPC over stdio serializes requests — one slow tool blocks every
subsequent call. A misbehaving cluster (storage hung on a lock,
upstream PVE wedged, network stall) or a hostile prompt-injection
that nudges the agent into a long-running call would otherwise stall
the MCP loop indefinitely.

Each `ToolDef` carries a `timeout_secs` budget (see the table above).
The dispatch wraps `handle_tool_call` in `tokio::time::timeout`. On
expiry the request returns JSON-RPC error code **`-32001`** with the
budget in the message; the request loop continues and the next call
is unaffected.

```json
{
  "jsonrpc": "2.0",
  "id": 7,
  "error": {
    "code": -32001,
    "message": "tool 'create_snapshot' exceeded 120s execution budget"
  }
}
```

`-32001` is in the JSON-RPC server-defined range (`-32000` ..=
`-32099`). Clients should treat it as "ephemeral, retry-safe at the
caller's discretion" — the tool may have partially executed, so for
destructive ops the caller MUST verify state before retrying.

`delete_guest` carries an extended 180 s budget because the HITL
gate alone consumes up to 120 s waiting for Telegram approval, and
the actual delete + task-log poll runs after that. A test
(`test_hitl_gated_delete_guest_has_post_hitl_budget`) pins this
invariant so the budget cannot drift below 120 s by accident.

## HITL on MCP destructive calls

The destructive tool set is **fail-closed** over MCP:

- `stop_guest`, `restart_guest`, `delete_guest`, `create_snapshot`,
  `delete_snapshot`, `suspend_guest`, `clone_guest`, `migrate_guest`,
  `create_guest`, and `clone_with_cloudinit`.

A destructive tool call with **no matching `[[policies]]` entry is
REFUSED**. proxxx returns a typed `isError` envelope and the PVE
gateway is never reached — nothing is queued, nothing executes. There
is no ungated inline path for a destructive tool.

The **only** way to run a destructive tool over MCP is a matching
`[[policies]]` entry:

1. **Request persistence (`mcp::dispatch`)**: when a policy matches, MCP
   resolves the target guest's current `(node, guest_type)` (or records the
   requested `node` / `type` / `vmid` for `create_guest`), persists a pending
   row in `<config_dir>/hitl_pending.db` with the full tool arguments in
   `params`, sends the signed `approve:<id>` / `deny:<id>` inline keyboard to
   Telegram, and returns the interception message containing the transaction
   ID.
2. **Typed decoding & guest binding (`proxxx hitl serve`)**: once `require`
   authorised approvers approve the request within its 120 s TTL, the HITL
   daemon deserializes `(action, params)` into the closed `ApprovedOp` enum
   (`#[serde(deny_unknown_fields)]`, `Shape::Name` validation on path-bearing
   strings). Any row that fails to decode is marked `failed` with
   `cannot decode approved operation: ...` without calling PVE. Before
   executing, the daemon re-resolves the guest on the cluster:
   - For operations on an existing guest (`stop_guest`, `restart_guest`,
     `delete_guest`, `create_snapshot`, `delete_snapshot`, `suspend_guest`,
     `clone_guest`, `migrate_guest`, `clone_with_cloudinit`), if the guest is
     missing or its live `node` or `guest_type` differs from the stored row,
     the daemon marks the row `failed` with
     `guest changed since the request (expected <node>/<type>, found ...)` and
     does not execute.
   - For `create_guest`, `clone_guest`, and `clone_with_cloudinit`, if an
     explicit target VMID (`vmid` / `newid`) is now occupied on the cluster,
     the daemon marks the row `failed` with
     `guest changed since the request (expected target VMID <id> to be free, found <node>/<type>)`
     and does not execute.
3. **Shared execution & outcome recording**: the daemon executes all 10
   destructive MCP tools above (plus the 5 CLI batch actions `start`, `stop`,
   `restart`, `suspend`, `resume`) through the exact same `mcp::dispatch::exec_*`
   and `cli::common::exec_cli_batch_op` functions used inline. On success the
   store row is marked `executed` with the PVE `upid`; on PVE error it is
   marked `failed` with the error message, and the Telegram message footer is
   updated accordingly.

Non-destructive tools (`start_guest`, `resume_guest`, and the
`get_*` / `list_*` reads) still run inline without a policy.

## Why no `move_disk` in the MCP surface

`migrate_guest` **is** in the registry — it is exposed as a
destructive, policy-gated tool (see the table and the fail-closed
rules above), so an agent can only trigger it through a matching
`[[policies]]` entry and a human approval.

`move_disk` is a different story: it is deliberately **not** exposed
via MCP. A misplanned disk move can leave a guest straddling two
storages, and the operation has no clean partial-failure recovery. An
agent that needs to move a disk proxes through a human-driven CLI
invocation.

## Vector framework

The MCP server is gated by:

- **(typed errors).** MCP responses carry `ApiError` variants
  in the JSON-RPC error.code, so the agent can distinguish "guest
  not found" (caller bug) from "cluster busy" (retry).
- ** (body cap).** A misbehaving cluster cannot OOM proxxx by
  returning a giant response — even via the MCP path.
- ** (graceful shutdown).** SIGTERM cleans up the JSON-RPC
  loop, flushes the audit log, and exits within the systemd
  90-second window.

## See also

- [HITL via Telegram](/integrations/hitl) — gating destructive MCP calls
- [Error categories](/reference/errors) — surfaced as JSON-RPC errors
- `proxxx mcp tools --json` — live tool registry inspection
