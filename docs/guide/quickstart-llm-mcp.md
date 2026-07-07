# Quickstart: LLM agent / MCP server

You're wiring Claude, Cursor, or any MCP-compatible agent into a
Proxmox cluster. You want a deterministic tool surface, audit-
pinned via SHA-256, with a HITL gate on destructive ops. You do
NOT want to write a custom integration.

This page gets you to a working `proxxx mcp serve` in ~5 min.

::: tip
The MCP surface is **compile-time fixed** — the agent sees
exactly 25 tools, no more, no less. Adding a tool requires a
proxxx PR and a release. This is intentional: prompt-injection
attacks can't extend the tool registry at runtime. The registry
is **append-only** across SemVer releases.
:::

<p align="center">
  <img src="/demo-mcp.svg" alt="proxxx MCP server — 25 typed tools, 10 flagged destructive; an MCP tools/call list_guests returns live guest data to the agent" width="760">
</p>

## 1. Configure proxxx itself

You need a working `config.toml` first. Quickest path: run
[`proxxx init --interactive`](/guide/quick-start#easy-path-the-wizard)
against your cluster and validate with `proxxx ls nodes`. If
that returns a table, you're ready.

## 2. Inspect the tool registry

```bash
proxxx mcp tools
```

Returns the full registry as JSON: 25 tools across five clusters —
inventory / reads (`list_nodes`, `list_guests`, `get_guest_status`,
`get_storage_pools`, `get_node_resources`, `list_snapshots`,
`get_task_log`, `get_cluster_status`, `get_node_status`,
`get_replication_status`, `list_tasks`, `list_backup_jobs`,
`list_cluster_events`), lifecycle (`start_guest`, `stop_guest`,
`restart_guest`, `suspend_guest`, `resume_guest`, `delete_guest`),
snapshots (`create_snapshot`, `delete_snapshot`), provisioning
(`clone_guest`, `clone_with_cloudinit`, `create_guest`), and
migration (`migrate_guest`). Each with parameters, descriptions,
destructive flag, and per-tool execution timeout.

For supply-chain pinning:

```bash
proxxx mcp tools --checksum
# → { "checksum": "8467de772787baa0" }
```

Pin this hash in your CI / agent config. If the deployed binary's
registry hash drifts, the tool surface changed — review the
diff before unpinning.

## 3. Configure HITL on destructive tools (required)

Destructive tools are **fail-closed**: a destructive call with no
matching `[[policies]]` entry is **refused** before it ever reaches
the PVE gateway — the agent gets a typed `isError` envelope, not an
autonomous `delete_guest`. There is no ungated inline path. The
*only* way to run a destructive tool over MCP is a matching
`[[policies]]` entry that routes it through HITL approval:

```toml
# config.toml
[telegram]
bot_token = "<bot-api-token>"
chat_id = "<your-chat-id>"

[[policies]]
when = { action = "delete" }
require = "telegram"
channel = "telegram"

[[policies]]
when = { action = "stop", tag = "prod" }
require = "telegram"
channel = "telegram"
```

The 120 s deny-on-timeout is hardcoded — if you don't approve,
the op is rejected (NOT auto-approved). Replay protection is
session-local: a stale callback from yesterday's chat history
won't re-fire.

The tools flagged destructive — and therefore refused without a
matching policy — are `stop_guest`, `restart_guest`, `suspend_guest`,
`delete_guest`, `create_snapshot`, `delete_snapshot`, `clone_guest`,
`clone_with_cloudinit`, `create_guest`, and `migrate_guest`.
Everything else — `start_guest`, `resume_guest`, and every
`get_*` / `list_*` read — runs inline, no approval required.

Test the round-trip:

```bash
proxxx mcp serve &        # background-launch
echo '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete_guest","arguments":{"guest_id":999}}}' \
  | nc -q1 - <(proxxx mcp serve)
# → Telegram message arrives → tap Approve → daemon runs → response
```

## 4. Wire up Claude Desktop

```json
// ~/Library/Application Support/Claude/claude_desktop_config.json (macOS)
// ~/.config/Claude/claude_desktop_config.json (Linux)
{
  "mcpServers": {
    "proxxx": {
      "command": "/usr/local/bin/proxxx",
      "args": ["mcp", "serve", "--profile", "homelab"]
    }
  }
}
```

Restart Claude Desktop. The agent now sees the 25-tool surface
in any conversation. Prompt: *"List the running VMs on my
cluster and stop the one tagged 'staging'."* — Claude calls
`list_guests`, filters, calls `stop_guest`, the HITL gate fires
on Telegram, you approve, op executes. Long-running operations
(migration, restore) stream `notifications/cluster-event` so the
agent sees `started` and `completed` without polling.

## 5. Wire up Cursor or another IDE

Same JSON shape, different config path. See your client's MCP
docs for the exact location.

## 6. Operational notes

- **Per-tool timeouts** (`timeout_secs` in `mcp tools` output)
  bound a single tool call. Default 30 s for read-ops, 60 s for
  start/stop/restart, 120 s for snapshots, 180 s for
  `delete_guest` (which has to wait through the 120 s HITL
  window). On expiry the call returns JSON-RPC error code
  `-32001`; the JSON-RPC loop continues — one slow tool can't
  brick subsequent calls.

- **Two transports at parity** — `proxxx mcp serve` (stdio
  JSON-RPC, agent runs as subprocess, no port) or
  `proxxx mcp serve-http` (Streamable HTTP/SSE per MCP 2025-03-26;
  defaults to `--bind 127.0.0.1 --port 3000`). Same tool registry,
  same HITL, same audit. HTTP is for hosted agents that can't spawn
  subprocesses; stdio for local agents (Claude Desktop, Cursor).
  Pick one per deployment.

- **serve-http is fail-closed on the network** — on a non-loopback
  bind (e.g. `--bind 0.0.0.0`) the server **refuses to start** unless
  `mcp_token` is set. Configure it in the profile (`mcp_token = "…"`)
  or pass `--token`; every `POST /mcp` and `GET /mcp` then demands a
  matching `Authorization: Bearer` header. An empty / whitespace token
  counts as absent — so a SIGHUP that clears `mcp_token` leaves the
  exposed server denying every request instead of silently opening
  up. To expose a public interface *without* a token (trusted network
  or an auth-enforcing reverse proxy only) you must consciously pass
  `--insecure-bind`. Loopback binds need no token.

- **Server-sent notifications** — both transports stream
  `notifications/cluster-event` for `task_state_change`
  (started / completed / failed) and `incident` (frozen / thawed).
  Over stdio, these are JSON-RPC 2.0 notification lines interleaved
  with the request/response stream; over HTTP they arrive as SSE
  events on `GET /mcp`. Subscribe via `notifications/subscribe`
  (informational ack only — delivery flows automatically on the
  same channel).

- **Audit trail** — every tool invocation logs to the proxxx
  audit log (same path as CLI / TUI). HITL callbacks log
  separately under `crate::hitl::daemon`.

- **Read-only mode**? Comment out the `delete_guest`,
  `stop_guest`, `restart_guest`, `create_snapshot`,
  `delete_snapshot` entries from your agent's allowed-tools
  list. The proxxx server still exposes them; the agent just
  won't call them.

## Common stumbles

| Symptom | Fix |
| :--- | :--- |
| Agent: `tool 'X' exceeded N s execution budget` | Cluster is hung on a lock. Check `proxxx ls nodes` directly; resolve upstream. |
| Agent: `Method not found` | Tool name typo or registry-checksum mismatch. Run `proxxx mcp tools --checksum` to verify your pin. |
| HITL: `replay rejected: <txn>` | The callback was already consumed in this session. Ask the agent to re-issue the operation. |
| Claude Desktop doesn't show proxxx tools | Path in `command` is wrong, or `proxxx mcp serve` exits immediately (config invalid → check `proxxx ls nodes` first). |

Full troubleshooting at [/guide/troubleshooting](/guide/troubleshooting).

## See also

- [MCP server reference](/integrations/mcp) — full tool registry,
  HITL routing, audit log details.
- [Pre-flight risk gate](/architecture/security#pre-flight-risk-gate)
  — what destructive ops the agent can / can't do unilaterally.
- [HITL via Telegram](/integrations/hitl) — full approval flow.
