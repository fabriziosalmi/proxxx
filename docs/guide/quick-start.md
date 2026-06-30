# Quick start

Five minutes from `cargo build` to driving a real cluster.

## 1. Authenticate

Create an API token in the Proxmox web UI under
**Datacenter → Permissions → API Tokens**. Untick "Privilege Separation"
unless you know which roles you need. Copy the secret — Proxmox shows
it only once.

### Easy path: the wizard

```sh
proxxx init --interactive
```

5-step prompted flow that walks you through URL, TLS, auth (token
or password), optional SSH layer + per-guest overrides, optional
Telegram for HITL. Each input is validated against the live
cluster before write — a wrong token is caught at the prompt, never
lands in the TOML. Existing config triggers a backup-or-cancel
prompt; new file written with mode 0600.

### Manual path

If you'd rather edit the file by hand:

```toml
# ~/.config/proxxx/config.toml  (Linux)
url = "https://pve1.lan:8006/"
user = "root@pam"
auth = "token"
token_id = "proxxx"
token_secret = "00000000-0000-0000-0000-000000000000"
verify_tls = false   # set to true if your cluster has a real cert
```

::: tip
The token secret can also come from the `PROXXX_TOKEN_SECRET`
environment variable, a 0600-mode file referenced as
`token_secret_file`, or your OS keychain. Resolution order is
documented under [Configuration → Secrets](/guide/configuration#secrets).
:::

## 2. Read the cluster

```sh
proxxx ls nodes
proxxx ls guests
proxxx ls storage
```

Pipe-friendly JSON for scripting:

```sh
proxxx ls guests --format json | jq '.[] | select(.status == "running") | .vmid'
```

## 3. Try the TUI

Run with no arguments:

```sh
proxxx
```

Vim-style keybindings throughout. Press `?` for the keymap reference.

| Key | Action |
| :-- | :----- |
| `j` `k` | move selection |
| `Enter` `l` | drill in |
| `h` `Esc` | back |
| `1`–`9` | switch view |
| `/` | fuzzy search across the cluster |
| `:` | command palette |
| `R` | force refresh |
| `q` | quit |

## 4. Run an operation safely

Every destructive op routes through a pre-flight risk check. Try:

```sh
proxxx stop 100 --force
```

If guest 100 is tagged `prod`, has been up for over 30 days, or has
active network traffic, proxxx prints the risk summary and asks for
explicit `--allow-risk`. The risk levels are `NOTICE` (advisory),
`WARN` (advisory), and `SEVERE` (refuses without override).

See [Pre-flight risk gate](/architecture/security#pre-flight-risk-gate).

## 5. Hand off a graphical console

```sh
proxxx ssh    100                       # interactive ssh (system ssh + QGA auto-discovery)
proxxx serial 100 --node pve1           # raw termproxy WebSocket
proxxx spice  100 --node pve1           # writes a 0600 .vv, launches remote-viewer
proxxx novnc  100 --node pve1           # opens browser to the web UI's noVNC
```

`spice` and `novnc` need a graphical client on the local machine —
proxxx never renders frames itself. See [Console handoff](/integrations/console).

## 6. Wire HITL (optional)

If you want destructive ops gated by Telegram approval:

```toml
[telegram]
bot_token = "123456:ABC..."
chat_id   = -1001234567890

[[policies]]
action  = "delete"
target  = "tag:prod"
require_approval = true
```

Now `proxxx delete <vmid> --yes` on a guest tagged `prod` will:

1. Send an inline-keyboard approval request to your Telegram chat.
2. Wait up to 120 s for a callback.
3. Execute on **Approve**, refuse on **Deny** or timeout.

See [HITL via Telegram](/integrations/hitl).

## 7. Wire CI

Every CLI command is `--format json` capable. Exit codes are stable —
see [Exit codes](/reference/exit-codes) for the full table.

`proxxx reconcile run --source <git>` is the GitOps drift gate: exit **2**
when the live cluster has drifted from the desired state declared in git,
**0** when in sync — drop it in a pipeline step. `reconcile converge`
applies the fix, safe by default (deletes need an explicit `--prune`).

<p align="center">
  <img src="/demo-gitops.svg" alt="proxxx reconcile loop — detect drift against the desired state in git, converge (safe by default), then back in sync, against a live Proxmox VE 9.1 cluster" width="760">
</p>

## Next steps

- [Configuration](/guide/configuration) — profiles, secrets, TLS, HITL
- [Pre-commit gate](/guide/pre-commit-gate) — for contributors
- [MCP server](/integrations/mcp) — drive proxxx from an LLM agent
