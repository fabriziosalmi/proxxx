# Production deployment checklist

A single page to walk through before pointing proxxx at a real
cluster you care about. Each item is a one-line check + a
verifiable command. Treat this as the minimum bar — your shop's
own runbook may be stricter.

::: tip
This page is for the **operator deploying proxxx**, not for the
PVE cluster itself. Cluster hardening (corosync over a private
ring, firewall rules, certificate rotation) is upstream Proxmox
material; we link to it but don't restate it.
:::

<p align="center">
  <img src="/demo-incident.svg" alt="proxxx incident lockdown — freeze halts every write fleet-wide; a stop is refused 'the fleet is FROZEN' before reaching PVE; thaw lifts it" width="760">
</p>

> On-call essential: `incident freeze` is a fleet-wide write kill-switch —
> during a maintenance window or a suspected compromise, every mutation is
> refused before it reaches Proxmox until you `thaw`.

## 1. Verify the binary

### `[ ]` Download from a tagged release, not `main`

```bash
TARGET=x86_64-unknown-linux-musl   # or aarch64-apple-darwin
VERSION=$(gh release view --repo fabriziosalmi/proxxx --json tagName -q .tagName | sed 's/^v//')  # latest tag
gh release download v${VERSION} \
  --repo fabriziosalmi/proxxx \
  --pattern "*-${TARGET}.tar.gz" \
  --pattern "*-${TARGET}.tar.gz.sha256"
```

### `[ ]` Check the SHA-256 sidecar

```bash
shasum -a 256 -c proxxx-${VERSION}-${TARGET}.tar.gz.sha256
# → proxxx-...tar.gz: OK
```

### `[ ]` Verify the sigstore keyless cosign signature (release ≥ next-tag-after-v0.1.6)

```bash
gh release download v${VERSION} \
  --repo fabriziosalmi/proxxx \
  --pattern "*-${TARGET}.tar.gz.cosign.bundle"

cosign verify-blob \
  --bundle proxxx-${VERSION}-${TARGET}.tar.gz.cosign.bundle \
  --certificate-identity-regexp 'https://github.com/fabriziosalmi/proxxx/.github/workflows/release.yml@.*' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  proxxx-${VERSION}-${TARGET}.tar.gz
# → Verified OK
```

The cert-identity-regexp pins the OIDC subject to **this exact
workflow path** in **this exact repo** — a leaked sigstore cert
from any other workflow or any other repo can't validate against
these bundles. The transparency-log inclusion proof is embedded
in the bundle, so verification is offline.

### `[ ]` Audit the CycloneDX SBOM (optional but recommended)

```bash
gh release download v${VERSION} --repo fabriziosalmi/proxxx \
  --pattern "*.cdx.json" --pattern "*.cdx.json.sha256"
shasum -a 256 -c proxxx-${VERSION}.cdx.json.sha256
grype sbom:proxxx-${VERSION}.cdx.json   # or trivy / cyclonedx-cli
```

## 2. Configure access

### `[ ]` Use API tokens, not passwords

Tokens are revocable, scopable, and don't carry full account
privilege when `--privsep=1`. Create with:

```bash
ssh root@<node>
pveum user token add operator@pve proxxx --privsep=1
# Grants the TOKEN the same role you grant on the user side:
pveum acl modify /vms/100 -tokens 'operator@pve!proxxx' -roles PVEVMAdmin
```

### `[ ]` Pin `verify_tls = true` unless you know why not

Self-signed labs flip this to `false` for convenience. In
production:

```toml
verify_tls = true
```

If you're running PVE behind a real cert (Let's Encrypt, internal
CA, ACME via PVE itself), this is the only correct setting.
Disabling TLS verification exposes the **entire API + WebSocket
traffic** (including serial-console tickets) to any MITM on the
path.

### `[ ]` Store the token secret in the OS keychain or a 0600 file, not inline

```bash
# Option A: macOS keychain
security add-generic-password \
  -a "$USER" -s proxxx -w "<token-uuid>"

# Option B: Linux secret-service (gnome-keyring / kwallet)
secret-tool store --label proxxx service proxxx account token_secret
# (proxxx reads via the `keyring` crate, falling back to
# secret-service on Linux, libsecret on macOS keychain)

# Option C: 0600 file referenced from config.toml
mkdir -p ~/.config/proxxx
printf '%s' '<uuid>' > ~/.config/proxxx/token.secret
chmod 600 ~/.config/proxxx/token.secret
# token_secret_file = "~/.config/proxxx/token.secret" in config.toml
```

::: warning
proxxx refuses to read `token_secret_file` if the file is not
mode 0600 (Unix). It will print
`Security Error: token_secret_file '&lt;path&gt;' has unsafe permissions &lt;mode&gt;`
and exit. This is intentional — don't `chmod 644` to "fix" it.
:::

### `[ ]` Validate the connection works as the deploying user

```bash
proxxx ls nodes
proxxx ls guests --format json | jq '.[] | {vmid, name, status}'
proxxx perms <user>
```

## 3. Configure HITL (if any operator runs destructive ops)

### `[ ]` Provision a dedicated Telegram bot

Don't reuse a bot that's also wired to other systems — the
HITL daemon polls and acknowledges every callback, and a
shared bot's other listeners may double-fire.

```bash
# In Telegram: chat with @BotFather
/newbot → name + username → copy the API token
/setprivacy → DISABLE  (so the bot sees group messages)
```

### `[ ]` Pin `[telegram]` in config.toml

```toml
[telegram]
bot_token = "<bot-api-token>"
chat_id = "<your-numeric-chat-id>"
```

The bot token resolves with the same hierarchy as the PVE
token: `PROXXX_TELEGRAM_BOT_TOKEN` env, `bot_token_file`,
keychain, inline.

### `[ ]` Configure `[[policies]]` rules

```toml
[[policies]]
when = { action = "delete", tag = "prod" }
require = "telegram-2of3"   # or "telegram"
channel = "telegram"

[[policies]]
when = { action = "stop", vmid = "100" }
require = "telegram"
channel = "telegram"
```

Policies match by `action`, `tag`, `vmid`, or wildcard. The
**deny-on-timeout** is hardcoded to 120 s — if the human
doesn't approve in that window, the op is rejected (NOT
auto-approved).

### `[ ]` Run the HITL daemon under a process supervisor

```bash
# systemd unit at /etc/systemd/system/proxxx-hitl.service:
[Unit]
Description=proxxx HITL approval daemon
After=network-online.target

[Service]
Type=simple
User=proxxx-ops
ExecStart=/usr/local/bin/proxxx hitl serve
Restart=on-failure
RestartSec=5
# Replay protection survives single-process restart via
# session-local consumed-txn-id set; no persistence layer
# needed.

[Install]
WantedBy=multi-user.target
```

### `[ ]` Test the round-trip end-to-end

```bash
proxxx hitl test --action delete --vmid 999
# → Telegram → tap Approve in &lt;120s → daemon runs the op
# → daemon answers callback "✅ Done" → message lifecycle done
```

## 4. Configure alerting (optional)

### `[ ]` Define `[[alerts]]` rules in config.toml

```toml
[[alerts]]
name = "node_offline"
when = "node_offline"
for_secs = 120
severity = "critical"
route = ["telegram", "ntfy:proxxx-prod"]
dedup_secs = 600
```

Predicates available: `node_offline`, `storage_above`,
`replication_failing`. The `dedup_secs` window prevents
re-fire spam.

### `[ ]` Run the alert daemon under a supervisor

```ini
ExecStart=/usr/local/bin/proxxx alerts watch --interval 30
```

The daemon **persists its dedup window to SQLite** (cache
schema 1 → 2 since v0.1.2), so a routine restart doesn't
re-fire every active alert. Persistence is local to the
daemon's host — no shared state across replicas.

### `[ ]` Test each route once

```bash
proxxx alerts test --route 'telegram'
proxxx alerts test --route 'ntfy:proxxx-prod'
proxxx alerts test --route 'webhook:https://hooks.example/notify'
```

## 5. Configure SSH layer (if running `proxxx perms` or `proxxx patch apply`)

### `[ ]` Provision a dedicated SSH key for proxxx

Don't reuse your personal `~/.ssh/id_ed25519`. proxxx maintains
its own `known_hosts` at `$XDG_CONFIG_HOME/proxxx/known_hosts`
— giving it a dedicated key keeps the audit trail separate.

```bash
ssh-keygen -t ed25519 -f ~/.ssh/proxxx_ops -N "" \
  -C "proxxx-ops@$(hostname)"
ssh-copy-id -i ~/.ssh/proxxx_ops.pub root@<each-node>
```

### `[ ]` Configure `[ssh]` block

```toml
[ssh]
user = "root"
key_path = "~/.ssh/proxxx_ops"
strict_host_key_checking = "tofu"   # default; pinning happens on first connect
```

### `[ ]` Verify the round-trip

```bash
proxxx perms <user>            # exercises the same path
# → table of effective ACLs; if you see the table, SSH works.
```

## 6. Lock down the operator host itself

### `[ ]` Treat `~/.config/proxxx/config.toml` as a credential file

```bash
chmod 600 ~/.config/proxxx/config.toml
ls -l ~/.config/proxxx/
```

### `[ ]` Confirm shells aren't leaking secrets via history

```bash
# Bash:
echo $HISTFILE
grep -E 'PROXXX_TOKEN_SECRET|PROXXX_PBS_TOKEN_SECRET' ~/.bash_history
# Zsh: ~/.zsh_history. Fish: ~/.local/share/fish/fish_history.
```

If you find tokens in history, rotate them on the cluster side
**before** deleting from history.

### `[ ]` Pin a Rust version + build from source for reproducibility (optional)

```bash
git clone https://github.com/fabriziosalmi/proxxx.git
cd proxxx
git checkout v${VERSION}
cargo build --release --target x86_64-unknown-linux-musl
# Compare your binary's sha256 against the release sha256.
```

## 7. Operational runbook

### `[ ]` Pin the build into your fleet inventory

```bash
proxxx version --json
# → { "version": "0.1.6", "git_sha_short": "...", "audit_ignores_count": 1, ... }
```

Snapshot this output into your inventory (Ansible facts /
Salt grain / Puppet fact) so a security advisory triage can
answer "which hosts have `<vulnerable version>`" instantly.

### `[ ]` Subscribe to release notifications

GitHub repo → **Watch** → **Custom** → **Releases**. Or pin
the release feed: `https://github.com/fabriziosalmi/proxxx/releases.atom`.

### `[ ]` Document your local risk-override policy

`--allow-risk` bypasses the pre-flight gate. If your shop
permits this for any class of op (e.g. patch-apply during
a planned window), document **who can use it** and **for what**
in your runbook. The flag is ungated by design — proxxx trusts
the operator who typed `--yes` AND `--allow-risk`.

### `[ ]` Test recovery: token revocation

```bash
ssh root@<node>
pveum user token remove operator@pve proxxx
# → next proxxx call from the operator host should 401
proxxx ls nodes   # expect: HTTP 401 No ticket
```

If it doesn't 401, the token wasn't actually scoped — re-issue
with `--privsep=1` and grant the role to the **token** path.

## 8. Harden the MCP server (if you expose proxxx over MCP)

### `[ ]` Keep the transport on loopback, or set `mcp_token` before exposing it

`proxxx mcp serve-http` **refuses to start** on a non-loopback bind
(e.g. `0.0.0.0`) unless `mcp_token` is set:

```bash
# Local-only (default, safe): binds 127.0.0.1
proxxx mcp serve-http

# Network-exposed without a token → refused
proxxx mcp serve-http --bind 0.0.0.0:8080
# → error: refusing to bind a non-loopback address without a token.
#    Set `mcp_token` (or pass --token), bind to 127.0.0.1, or pass
#    --insecure-bind to override.
```

`mcp_token` is a profile config field (or the `--token` flag). An
**empty or whitespace token counts as absent** — don't set it to `""`
and think you're covered. When the server is network-exposed and the
token is absent, every request is denied (fail-closed), and that denial
**survives a `SIGHUP`** that clears the token from a live config.

`--insecure-bind` overrides the refusal. **Never pass it on an untrusted
network** — it exists for consciously-chosen trusted-segment cases only
(see AR-3 in [ACCEPTED-RISKS.md](https://github.com/fabriziosalmi/proxxx/blob/main/pre-commit/ACCEPTED-RISKS.md)).

### `[ ]` Gate every destructive MCP tool with a `[[policies]]` entry

Over MCP, proxxx is **fail-closed**: a destructive tool with **no
matching `[[policies]]` entry is refused** (a typed `isError` envelope —
the PVE gateway is never reached). There is no ungated inline path. The
only way to run a destructive tool over MCP is a matching policy that
routes it to HITL approval.

Destructive (policy-gated) tools: `stop_guest`, `restart_guest`,
`suspend_guest`, `delete_guest`, `create_guest`, `clone_guest`,
`clone_with_cloudinit`, `migrate_guest`, `create_snapshot`,
`delete_snapshot`. Non-destructive tools stay inline: `start_guest`,
`resume_guest`, and every `get_*` / `list_*` read.

```toml
# Without a matching policy, a destructive tool is simply unavailable
# to the MCP client. Confirm your rules cover every destructive action
# you intend a client to perform.
[[policies]]
when = { action = "delete" }
require = "telegram"
channel = "telegram"
```

## 9. Guard unmanned auto-converge (if you run `reconcile watch --auto-converge`)

### `[ ]` Set a small `max_unmanned_changes` before enabling `converge_prune`

`converge_prune = true` lets unmanned converge **delete** drifted
resources — but it **holds all deletes** unless `max_unmanned_changes`
(a per-tick change cap) is **also** set. With prune on and no cap, deletes
are held and only create/update operations converge.

```toml
[reconcile]
auto_converge = true
converge_prune = true
max_unmanned_changes = 3       # keep this single-digit
allowed_families = ["lxc"]     # whitelist which families converge unmanned
```

Size the cap **small — single digits**. A large cap (e.g. `49`)
re-opens the 10–49 unmanned-delete band, which is exactly the blast
radius the cap exists to close (see AR-4). Use `allowed_families` to
whitelist which resource families are allowed to converge without a human.

## 10. Protect the audit chain

### `[ ]` Keep `audit.key` at 0600, and consider a separate volume

The audit log is HMAC-signed. proxxx creates the audit dir `0700` and
**refuses to load a group- or world-readable `audit.key`** (Unix), so
keep it owner-only:

```bash
chmod 600 <audit-dir>/audit.key
ls -l <audit-dir>/audit.key    # → -rw------- (0600)
```

To keep the signing key off the same volume as the database it signs,
point `PROXXX_AUDIT_KEY` at a separate volume — a same-user/root attacker
who can rewrite the DB then can't silently re-sign it (AR-5).
`PROXXX_AUDIT_DIR` relocates the DB **and** key together if you'd rather
move the whole directory.

### `[ ]` Run `audit verify` from a separate trust context

```bash
proxxx audit verify        # exits non-zero if the chain has been tampered with
```

Run this from a host or account that **can't write** the audit DB — a
verifier that shares the operator's write access can't prove much. Wire
the non-zero exit into your monitoring.

## See also

- [Configuration schema](/reference/configuration) — every TOML
  block by section.
- [Security model](/architecture/security) — threat model +
  invariants.
- [Pre-commit gate](/guide/pre-commit-gate) — what every release
  passes before tagging.
- [`ACCEPTED-RISKS.md`](https://github.com/fabriziosalmi/proxxx/blob/main/pre-commit/ACCEPTED-RISKS.md)
  — residual risks (AR-1…AR-6) knowingly accepted for this release,
  with the guardrails above cross-referenced.
- [Troubleshooting](/guide/troubleshooting) — error message → fix
  index.
- [`SECURITY.md`](https://github.com/fabriziosalmi/proxxx/blob/main/SECURITY.md)
  — coordinated disclosure contact.
