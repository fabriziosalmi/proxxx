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

For `auth = "password"`, set `password`,
`PROXXX_PASSWORD` env, or keychain.

## Secrets

The resolution order for token / password / PBS secret is:

1. **CLI flag** (`--token-secret VALUE`) — highest priority, takes
   precedence over everything else.
2. **Environment variable** — `PROXXX_TOKEN_SECRET`,
   `PROXXX_PASSWORD`, or `PROXXX_PBS_TOKEN_SECRET`.
3. **File reference** — `token_secret_file = "~/.config/proxxx/secrets/pve.token"`
   (or `/etc/proxxx/token`). Leading `~` and `~/...` are expanded against
   `$HOME` (`pbs.token_secret_file` and `telegram.bot_token_file` use the
   same expansion). On Unix the file must have mode `0600` or stricter;
   proxxx refuses to read files with group or world permissions.
4. **OS keychain** — last resort. Service `proxxx`, key
   `token_secret` / `password` / `pbs_token_secret`. Disabled if you
   build with `--no-default-features`.

Once loaded, secrets live in `Zeroizing<String>` — they are wiped from
the heap on `Drop` . They are never written to logs.

## TLS

```toml
verify_tls = true         # default in production (WebPKI + standard CA roots)
tls_pin_mode = "tofu"     # Trust-On-First-Use leaf-certificate SHA-256 pinning (recommended for homelabs)
verify_tls = false        # disable TLS verification (not recommended)
```

### Leaf-certificate pinning (`tls_pin_mode = "tofu"`)

With `verify_tls = true` and `tls_pin_mode = "tofu"`, proxxx pins the exact
end-entity (leaf) certificate by its SHA-256 DER digest:

- **First connect**: if `<config_dir>/known_certs/<host>_<port>.der` does not
  exist, proxxx fetches the server's leaf certificate, logs a warning with its
  colon-separated SHA-256 fingerprint, writes `<host>_<port>.der` atomically
  (`0600` inside `0700` `known_certs/`), and pins that leaf for the session.
- **Subsequent connects**: every PVE HTTPS request and serial-console WebSocket
  connection (`wsterm`) uses a custom `rustls` `PinnedLeafVerifier` that accepts
  the handshake if and only if `SHA-256(end_entity DER)` matches the pinned
  32-byte digest in constant time and the server proves possession of the
  leaf's private key (`CertificateVerify`). This works with Proxmox VE's
  default `pve-root-ca.pem` → `pve-ssl.pem` hierarchy as well as self-signed
  certificates or IP literal URLs without weakening `verify_tls` to `false`.
- **Re-trusting after a certificate renewal**: if the server's leaf certificate
  changes, proxxx aborts immediately (no retry) and prints both the pinned and
  presented SHA-256 fingerprints along with the `<host>_<port>.der` path. Verify
  the new fingerprint on the Proxmox node (`pvenode cert info` or
  `openssl x509 -noout -fingerprint -sha256 -in /etc/pve/local/pve-ssl.pem`),
  then delete `<config_dir>/known_certs/<host>_<port>.der` and reconnect.
- **Directory override (`PROXXX_KNOWN_CERTS_DIR`)**: set `PROXXX_KNOWN_CERTS_DIR=/path/to/dir`
  to override the directory where TOFU `<host>_<port>.der` files are read and
  written (defaults to `<config_dir>/known_certs`).

### Disabling verification (`verify_tls = false`)

Setting `verify_tls = false` (with `tls_pin_mode` unset or `"disabled"`)
enables `danger_accept_invalid_certs` on the reqwest client AND mirrors the
bypass into the WebSocket client used for serial console
(`wsterm::tls::dangerous_no_verify_config`).

It does NOT disable SSH host key verification. SSH uses its own
TOFU `known_hosts` at `<config_dir>/known_hosts` (separate
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

Every subsystem uses the **resolved** profile label (`ProfileConfig::profile_label()`):
the explicit `--profile <name>`, the `default = "<name>"` key, or the
sole `[profiles.<name>]` section — falling back to `"default"` only when
the configuration is a flat top-level file with no `[profiles]` table.
That resolved label names the SQLite state/queue/dedup/drift cache file
(`<cache_dir>/proxxx/<profile>_state.db`), the `[meta] profile` header
written by `proxxx state export`, the `"profile"` field in `audit.db`
`params_json`, the `profile` label on Prometheus reconcile metrics, and
MCP reconciliation notifications.

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

For `proxxx ssh <vmid>`, `proxxx perms`, `proxxx doctor`, and the patching orchestrator:

```toml
[ssh]
key_path = "~/.ssh/proxxx_homelab"           # ed25519/RSA private key (~ expanded against $HOME)
user     = "root"                            # optional, defaults to "root"

[ssh.hosts]
pve1 = "10.0.0.1:22"

[ssh.guests."100"]
host = "10.10.10.100"
user = "fab"

[ssh.guests."200"]
host     = "10.10.10.200"
key_path = "~/.ssh/k8s_master"               # optional, falls back to [ssh].key_path (~ expanded)
```

Both `key_path` (at `[ssh]` and `[ssh.guests."<vmid>"]`) and `known_hosts`
accept a leading `~` or `~/...` (expanded via `util::path::expand_tilde`,
shared with `token_secret_file` and `proxxx doctor`). SSH uses publickey
only — no agent. If your key is encrypted, set `PROXXX_SSH_KEY_PASSPHRASE`
(or unlock it in the TUI prompt). The `known_hosts` file is TOFU on first
connect with a warning log.

## PBS

For `proxxx pbs ...`:

```toml
[pbs]
url               = "https://pbs.lan:8007/"
user              = "proxxx@pbs"
token_id          = "reader"
token_secret_file = "~/.config/proxxx/secrets/pbs.token"   # ~ expanded; 0600 on Unix (or inline token_secret)
verify_tls        = true
fingerprint       = "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99"
rate_limit        = 10        # max requests/second
```

When `fingerprint` is set (taken from `proxmox-backup-manager cert info`, either
32 colon-separated hex octets `AA:BB:...` or 64 hex chars), `PbsClient` and
`proxxx doctor` pin the PBS leaf certificate's SHA-256 DER digest via the same
`PinnedLeafVerifier` used by PVE TOFU pinning — even when `verify_tls = true`
against a self-signed PBS certificate. Malformed fingerprints are rejected at
config load with exit code `3`.

::: warning
PBS uses `PBSAPIToken=user!tokenid:secret` — note the **colon**
between token id and secret. PVE uses `=`. If you copy a PVE-style
header to PBS you'll get a 401 with no useful diagnostic.
:::

## Telegram (HITL + alerts)

```toml
[telegram]
bot_token = "123456:ABC..."
chat_id   = "-1001234567890"
```

Get `bot_token` from [@BotFather](https://t.me/BotFather), `chat_id`
from any message metadata to your bot (e.g. via
`https://api.telegram.org/bot<token>/getUpdates`).

## HITL policies

```toml
[[policies]]
action  = "delete"     # delete | stop | restart | migrate | exec | move_disk | resize_disk | *
target  = "tag:prod"   # tag:<X> | <vmid> | *
channel = "telegram"   # approval channel
require = 1            # approvals needed (2 or more = quorum)
```

Multiple policies are evaluated in order; the first matching one wins.
See [HITL via Telegram](/integrations/hitl).

## Alerts

```toml
[[alerts]]
name        = "node_down"
trigger     = "node_offline"
for_secs    = 60                     # seconds offline before firing
route       = ["telegram", "ntfy:proxxx-prod"]
dedup_secs  = 600                    # don't re-fire within 10 min
```

See [Alerts](/integrations/alerts) for the full predicate set.

## Schema reference

Full type-by-type schema with defaults: [Configuration schema](/reference/configuration).
