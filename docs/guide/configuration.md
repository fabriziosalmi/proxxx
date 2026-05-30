# Configuration

proxxx reads a single TOML file. Profiles, secrets, TLS, SSH, HITL,
PBS, and alerts all live there.

## File location

| Platform | Path |
| :--- | :--- |
| Linux   | `~/.config/proxxx/config.toml` |
| macOS   | `~/Library/Application Support/dev.proxxx.proxxx/config.toml` |
| Windows | `%APPDATA%\dev\proxxx\proxxx\config.toml` |

The path follows the [`directories`](https://crates.io/crates/directories) crate's
project-dirs convention (`dev.proxxx.proxxx`).

## Minimum viable

```toml
url = "https://pve1.lan:8006/"
user = "root@pam"
auth = "token"
token_id = "proxxx"
token_secret = "00000000-0000-0000-0000-000000000000"
verify_tls = false
```

That's enough for read-only and most write operations against a single
cluster.

## Auth modes

```toml
auth = "token"      # API token (recommended — scoped, revocable)
auth = "password"   # username/password ticket flow (legacy)
```

For `auth = "token"`, set `token_id` and one of: `token_secret`,
`token_secret_file`, `PROXXX_TOKEN_SECRET` env, or store it in the
keychain.

For `auth = "password"`, set `password`, `password_file`,
`PROXXX_PASSWORD` env, or keychain.

## Secrets

The resolution order for token / password / PBS secret is:

1. **CLI flag** (`--token-secret VALUE`) — highest priority, takes
   precedence over everything else.
2. **Environment variable** — `PROXXX_TOKEN_SECRET`,
   `PROXXX_PASSWORD`, or `PROXXX_PBS_TOKEN_SECRET`.
3. **File reference** — `token_secret_file = "/etc/proxxx/token"`.
   The file must be readable; mode 0600 is recommended (proxxx does
   not enforce, but flags non-0600 files in the audit log).
4. **OS keychain** — last resort. Service `proxxx`, key
   `token_secret` / `password` / `pbs_token_secret`. Disabled if you
   build with `--no-default-features`.

Once loaded, secrets live in `Zeroizing<String>` — they are wiped from
the heap on `Drop` . They are never written to logs.

## TLS

```toml
verify_tls = true   # default in production
verify_tls = false  # accept self-signed (homelab)
```

Setting `verify_tls = false` enables `danger_accept_invalid_certs` on
the reqwest client AND mirrors the bypass into the WebSocket client
used for serial console (`wsterm::tls::dangerous_no_verify_config`).

It does NOT disable SSH host key verification. SSH uses its own
TOFU `known_hosts` at `$XDG_CONFIG_HOME/proxxx/known_hosts` (separate
from `~/.ssh/known_hosts`).

## Profiles

Multiple clusters, one config:

```toml
default = "homelab"

[profiles.homelab]
url = "https://pve1.lan:8006/"
user = "root@pam"
auth = "token"
token_id = "proxxx"
token_secret = "00000000-0000-0000-0000-000000000000"
verify_tls = false

[profiles.prod]
url = "https://pve.example.org:8006/"
user = "ops@pve"
auth = "token"
token_id = "ci"
token_secret_file = "/etc/proxxx/prod-token"
verify_tls = true
```

Switch with `proxxx --profile prod ls nodes`. The flat top-level
profile (no `[profiles.X]`) is treated as the default if no `default`
key is set.

### Read-only profiles (`read_only`)

Set `read_only = true` on a profile to make proxxx refuse **every**
mutation (POST/PUT/DELETE) on it — enforced client-side, at the single
API write chokepoint, before the request leaves the process. Reads (GET)
are unaffected. The refusal is a typed error with exit code `8` (the same
"mutation refused by a local lock" family as `incident freeze`).

It's declarative (lives in config, version-controllable, always on) —
unlike `[[policies]]` (which only *request* approval) or `incident freeze`
(a runtime lock you have to remember to set). Pair it with a read-only
PVE API token (`PVEAuditor` role on `/`) for defence in depth:

- **`read_only = true`** → client-enforced: proxxx never sends the write.
- **`PVEAuditor` token** → server-enforced: PVE returns `403` on any write.

Either alone blocks writes; together they're belt-and-suspenders for the
production clusters you only ever observe.

### Multi-Proxmox pattern (prod read-only + writable test)

The intended fleet layout: production hosts get a `PVEAuditor` token
**and** `read_only = true`; the one writable test cluster gets a
privileged token and no flag.

```toml
# Production — observe only (client lock + server lock)
[profiles.prod-a]
url = "https://10.0.0.10:8006"
user = "proxxx@pve"            # token bound to PVEAuditor on /
token_id = "auto"
token_secret_file = "/etc/proxxx/prod-a.token"
verify_tls = true
read_only = true

# Test cluster — full read+write
[profiles.lab]
url = "https://10.0.0.120:8006"
user = "proxxx@pve"
token_id = "auto"
token_secret_file = "/etc/proxxx/lab.token"
verify_tls = false
```

Mint the read-only token on each production node:

```bash
pveum user add proxxx@pve
pveum acl modify / --user proxxx@pve --role PVEAuditor
pveum user token add proxxx@pve auto --privsep 0   # prints the secret once
```

View the whole fleet (read-only) in one screen with `proxxx fleet` —
see the [TUI reference](../reference/tui.md). `proxxx fleet` ignores
`--profile`: it always aggregates every configured profile.

## SSH

For `proxxx ssh <vmid>`, `proxxx perms`, and the patching orchestrator:

```toml
[ssh]
key  = "/home/fab/.ssh/proxxx_homelab"      # ed25519 private key, no passphrase
host = "10.0.0.1"                       # default node for `proxxx perms`
port = 22                                    # optional, defaults to 22
user = "root"                                # optional, defaults to "root"

[ssh.guests."100"]
host = "10.10.10.100"
user = "fab"

[ssh.guests."200"]
host = "10.10.10.200"
key  = "/home/fab/.ssh/k8s_master"
```

SSH uses publickey only — no passphrase prompt, no agent. If your key
is encrypted, set `PROXXX_SSH_KEY_PASSPHRASE`. The known_hosts file is
TOFU on first connect with a warning log.

## PBS

For `proxxx pbs ...`:

```toml
[pbs]
url          = "https://pbs.lan:8007/"
user         = "proxxx@pbs"
token_id     = "reader"
token_secret = "00000000-0000-0000-0000-000000000000"
verify_tls   = false
rate_limit   = 10        # max requests/second
```

::: warning
PBS uses `PBSAPIToken=user!tokenid:secret` — note the **colon**
between token id and secret. PVE uses `=`. If you copy a PVE-style
header to PBS you'll get a 401 with no useful diagnostic.
:::

## Telegram (HITL + alerts)

```toml
[telegram]
bot_token = "123456:ABC..."
chat_id   = -1001234567890
```

Get `bot_token` from [@BotFather](https://t.me/BotFather), `chat_id`
from any message metadata to your bot (e.g. via
`https://api.telegram.org/bot<token>/getUpdates`).

## HITL policies

```toml
[[policies]]
action           = "delete"          # delete | stop | restart | migrate | exec | move_disk | resize_disk
target           = "tag:prod"        # tag:<X> | <vmid> | *
require_approval = true
timeout_secs     = 120               # default 120
```

Multiple policies are evaluated in order; the first matching one wins.
See [HITL via Telegram](/integrations/hitl).

## Alerts

```toml
[[alerts]]
name        = "node_down"
trigger     = "node_offline"
threshold   = 60                     # seconds offline before firing
route       = ["telegram", "ntfy:proxxx-prod"]
dedup_secs  = 600                    # don't re-fire within 10 min
```

See [Alerts](/integrations/alerts) for the full predicate set.

## Schema reference

Full type-by-type schema with defaults: [Configuration schema](/reference/configuration).
