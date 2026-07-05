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

### HTTP transport and `mcp_token`

For clients that speak MCP over HTTP:

```sh
proxxx mcp serve-http
```

Because an HTTP listener is reachable off the box, it is
**fail-closed on authentication**. `serve-http` **refuses to start**
on a non-loopback bind (e.g. `0.0.0.0`) unless an `mcp_token` is set —
pass `--insecure-bind` to override that consciously.

Set the token as the `mcp_token` profile config field or with the
`--token` CLI flag. An empty or whitespace-only token counts as
**absent**. When the server is network-exposed and the token is
absent, every request is denied — and this fail-closed state survives
a `SIGHUP` that clears the token, so a reload cannot silently drop
authentication.

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

- `stop_guest`, `restart_guest`, `delete_guest`, `delete_snapshot`,
  `migrate_guest`, `clone_guest`, `clone_with_cloudinit`, `create_guest`,
  and — new in v0.13.0 — `suspend_guest` and `create_snapshot`.

A destructive tool call with **no matching `[[policies]]` entry is
REFUSED**. proxxx returns a typed `isError` envelope and the PVE
gateway is never reached — nothing is queued, nothing executes. There
is no ungated inline path for a destructive tool.

The **only** way to run a destructive tool over MCP is a matching
`[[policies]]` entry, which routes the call through `enforce_preflight`
and `check_hitl` exactly like CLI calls and requires a human approval
before execution. When a policy matches, the agent sees a
`pending_hitl` response and can poll for completion via
`get_guest_status` or wait — proxxx returns a transient error code
clients are expected to retry on.

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
