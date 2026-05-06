# Troubleshooting

Errors you might hit on first use, sorted by category. Every entry
shows the **exact message** so you can grep. proxxx renders the
full anyhow chain with `Fatal Error: <outer>: <cause>: <root>` —
look at the rightmost segment first; that's usually the real cause.

::: tip
Most "I can't even start" issues come from config drift. Run
[`proxxx init --interactive`](/reference/cli#configuration-bootstrap)
to regenerate a known-good `config.toml` validated against the
live cluster.
:::

## Connection & TLS

### `Fatal Error: HTTP request failed (cluster unreachable, wrong URL, or TLS rejection)`

Hit during the wizard's Step 1 probe or first `ls nodes`.

**Causes, in order of likelihood:**

1. URL is wrong (wrong port, missing scheme, typo).
2. Cluster is on a private network that this host can't reach.
3. TLS certificate is self-signed and `verify_tls = true` in your config.

**Fix:**

```bash
# 1. Try a raw curl first — eliminates proxxx from the equation.
curl -k -sSf https://<host>:8006/api2/json/version
#   → JSON  : URL good, certificate maybe self-signed (the -k flag
#             ignored that). If you got JSON, set verify_tls=false
#             in config or re-run wizard and pick "n" at Step 2.
#   → 401   : URL good, cluster up; the wizard will treat 401 as
#             "alive — auth needed" (this is normal on PVE 8+).
#   → empty : URL wrong, port wrong, or cluster down.
```

### Wizard says: `⚠ anonymous probe failed (response was not JSON); proceeding anyway`

Not actually an error. PVE 8+ requires auth for `/api2/json/version`
and returns 401 with an empty body. As of v0.1.3 the wizard treats
401/403 as "alive (auth required)" and shows that explicitly. If
you still see the false-negative wording, you're on an older
proxxx — `proxxx --version` should report `0.1.3` or newer.

## Auth / secrets

### `Fatal Error: Token secret not found. Check CLI args, PROXXX_TOKEN_SECRET, inline `token_secret =` in config.toml, token_secret_file, or keychain.`

The literal resolution order is:

1. `--token-secret <X>` on the command line (overrides everything).
2. `PROXXX_TOKEN_SECRET` env var.
3. `token_secret_file = "/path"` in config.toml (the file must be
   mode 0600 on Unix or proxxx refuses).
4. `token_secret = "..."` inline in config.toml.
5. OS keychain entry under service `"proxxx"`, account `"token_secret"`.

**Fix the cleanest way for your context:**

```bash
# Quickest one-shot for testing:
PROXXX_TOKEN_SECRET="<uuid>" proxxx ls nodes

# Persistent + secure on Linux/macOS via 0600 file:
mkdir -p ~/.config/proxxx
printf '%s' '<uuid>' > ~/.config/proxxx/token.secret
chmod 600 ~/.config/proxxx/token.secret
# then in config.toml:
#   token_secret_file = "/home/<you>/.config/proxxx/token.secret"
```

### `Fatal Error: Security Error: token_secret_file '<path>' has unsafe permissions <mode>`

proxxx refuses to read a token from a world-readable file. PVE
tokens are bearer credentials.

```bash
chmod 600 <path>
ls -l <path>   # should show -rw-------
```

### `HTTP 401 No ticket` after first call

Token has expired or you typed the wrong secret. PVE tokens don't
expire by default but a `pveum user token remove` flips them off
immediately. Re-issue:

```bash
ssh root@<node>
pveum user token list root@pam
pveum user token remove root@pam <token-id>
pveum user token add    root@pam <token-id> --privsep=0
# Take the printed value — it's shown ONCE.
```

### `HTTP 403 Permission denied`

The token's ACL doesn't grant the operation.

- Read errors → token needs `Sys.Audit` on the relevant path.
- Write errors → `VM.Allocate`, `VM.Config.Disk`, etc.
- Token list of effective perms: `proxxx perms <user>`.

If you hit 403 on a lifecycle op (`start`/`stop`/`restart`) but
the user is admin in the web UI, you probably created the token
with `--privsep=1` and didn't grant the role to the **token**.
PVE has user-side ACLs and token-side ACLs.

## SSH layer

### `Fatal Error: no [ssh] block in config.toml`

`proxxx perms`, `proxxx patch apply`, and `proxxx ssh <vmid>`
shell out via SSH. Add the block:

```toml
[ssh]
user = "root"
key_path = "~/.ssh/id_ed25519"
```

Or run `proxxx init --interactive` and answer `y` at the SSH step
— it auto-discovers keys in `~/.ssh/` and tests the connection.

### `Fatal Error: no [ssh.guests."<vmid>"] entry in config.toml AND auto-discovery failed: ...`

`proxxx ssh <vmid>` resolves a guest's connection details first
from explicit `[ssh.guests."<vmid>"]` config, then falls back to
auto-discovery. The error chain tells you why both failed:

- **`QEMU guest-agent query failed`** → guest doesn't have the
  agent installed, or the agent isn't running, or `agent: 1` was
  added in `qm config` without a full power cycle (warm reboot
  doesn't pick it up).
- **`QGA returned no routable IPv4`** → guest has only loopback
  / link-local addresses. Pin a host explicitly:
  ```toml
  [ssh.guests."100"]
  host = "10.0.0.42"
  ```
- **`LXC interface query failed`** → PVE shells out to `lxc-info`
  on the node; if that fails, the LXC has no namespaces yet
  (newly-created and not started).

### SSH probe in the wizard says `Identity file not accessible`

Default path is `~/.ssh/id_ed25519`; older operators may have
`id_rsa` or named keys (`id_ed25519_root`, `proxxx_e2e_ed25519`).
As of v0.1.3 the wizard auto-discovers keys in `~/.ssh/`. If you
still see the hardcoded default, upgrade.

## Config / wizard

### `Fatal Error: Config not found at <path>`

You haven't run `proxxx init` yet, or you're on a host with no
existing config dir. Easiest:

```bash
proxxx init --interactive   # validates each input live
# OR for a hand-edited template:
proxxx init                 # writes a commented config.toml
```

### Wizard step 4 SSH test: `exit status: 255`

SSH connection itself failed. The wizard ran:

```bash
ssh -o BatchMode=yes \
    -o ConnectTimeout=5 \
    -o StrictHostKeyChecking=accept-new \
    -i <key> root@<host> uname -a
```

`BatchMode=yes` disables password prompts — if the key isn't
authorised on the remote, `ssh` exits 255 immediately. Verify
with the same command without BatchMode (you'll see "Permission
denied (publickey)" or whatever the real cause is).

To deploy the key:

```bash
ssh-copy-id -i ~/.ssh/<key>.pub root@<host>
```

## Backup / replication

### `Fatal Error: Failed to parse response from /cluster/backup`

The cluster returned `{"data":[]}` (no backup jobs configured).
This was a real bug pre-v0.1.4 — the deserializer rejected the
empty array on certain code paths. Fixed in commit e0d203c
(error-chain display + regression test). Upgrade to v0.1.4+.

### Live test fail: `pbs datastores` exits non-zero

The live test gate now treats PBS probes as opt-in (PBS isn't
required for proxxx). Set `PROXXX_E2E_PBS_ENABLE=1` in
`tests/live/env.local` only if your test cluster has a PBS
configured under `[pbs]`.

## HITL / Telegram

### Wizard step 5 says: `⚠ Telegram probe failed: HTTP 401`

The bot token is wrong. Get a fresh one from `@BotFather` →
`/mybots` → select bot → `API Token`.

### `Fatal Error: HITL replay rejected: <txn>`

You replayed a callback that was already approved+executed
(network hiccup, browser back button, log grep + paste). The
replay protection is doing its job — reissue the operation as
a fresh one with a new transaction id.

## MCP / LLM agents

### Agent reports: `tool 'X' exceeded N s execution budget`

JSON-RPC error code `-32001`. Each MCP tool has a per-tool
timeout; the dispatch wraps `handle_tool_call` in
`tokio::time::timeout`. The cluster is hung on a lock or the
upstream API is wedged. Check:

```bash
proxxx ls nodes               # is PVE responsive at all?
proxxx get-task-log <upid>    # what's the in-flight task doing?
```

Budgets per tool: see [`proxxx mcp tools --json`](/integrations/mcp).

### MCP server checksum changed unexpectedly

`proxxx mcp tools --checksum` returns a deterministic SHA-256
of the tool registry. If your CI pin doesn't match the deployed
binary, the registry shape changed — review the new tool /
parameter / description before unpinning.

## Pre-commit gate

### Stage 5/6 fail with `proxxx ls nodes failed`

The live cluster harness uses `tests/live/env.local` (gitignored).
If your config.toml drifts away from that env, the harness
points at the wrong cluster. Fix:

```bash
source tests/live/env.local
export PROXXX_TOKEN_SECRET="${PROXXX_E2E_PVE_TOKEN#*=}"
proxxx ls nodes   # should respond before the gate stage runs
```

### Stage 6 `LXC didn't reach stopped within 60s`

LXC create succeeded (UPID returned) but the guest never
materialised. Storage full, template missing, or PVE task
queue stuck. Debug on the node:

```bash
ssh root@<node>
pct list
pveam list local                        # is the alpine template there?
pveam download local alpine-3.22-...    # if not
df -h                                    # disk space?
```

## Filing an issue

If none of the above match, please include in the issue:

```bash
proxxx version --json     # build + capability metadata
proxxx --format json ls nodes 2>&1 | head -3   # 1-line repro
RUST_LOG=debug proxxx <failing-command> 2>&1 | tail -30
```

The first command is critical — it shows the exact build,
target, audit policy, and risk-variant count. The maintainer
team uses it to bisect against released versions.
