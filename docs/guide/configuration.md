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

### Bootstrap a token (`proxxx token bootstrap`)

Minting a token manually with `pveum user token add` prints the secret to the
terminal (scrollback, shell history, clipboard, or agent context), and
`proxxx token create` requires an already-working API token. To onboard a node
over SSH without the secret ever reaching the terminal (`#330`):

```bash
proxxx --profile pve1 token bootstrap \
  [--userid root@pam] \
  [--tokenid proxxx] \
  [--role PVEAuditor] \
  [--acl-path /] \
  [--ssh-host 10.0.0.10:22] \
  [--secret-file ~/.config/proxxx/secrets/pve1.token] \
  [--rotate] \
  --yes
```

How `token bootstrap` works:

1. **Profile & guardrails**: loads `[profiles.<X>]` (with `[defaults]` merged)
   before constructing an API client. `user` and `token_id` come from the
   profile unless overridden by `--userid` / `--tokenid`. Refuses `read_only = true`
   profiles (exit code `8`) and requires `--yes` before opening an SSH session.
2. **SSH target**: connects to `--ssh-host <host[:port]>` if given, otherwise to
   the host parsed from the profile's `url` on port `22`. Because no working API
   token exists yet, `token bootstrap` does **not** call `/cluster/status` and
   does **not** run the remote `hostname` node-name check. Host key verification
   always goes through the profile's `known_hosts` policy (`tofu` or `strict`;
   `strict_host_key_checking = "off"` is refused).
3. **Pre-check & rotation**: runs `pveum user token list <user> --output-format json`.
   If `<tokenid>` already exists, refuses unless `--rotate` is passed (which
   removes the old token via `pveum user token remove <user> <tokenid>` and
   recreates it, invalidating the previous secret immediately).
4. **Create & ACL**: runs `pveum user token add <user> <tokenid> --privsep 1 --output-format json`,
   parses `value` directly into a `SecretString`, immediately zeroizes the raw
   `stdout` buffer, and grants `--role` (default `PVEAuditor`) on `--acl-path`
   (default `/`) via `pveum acl modify <acl-path> --tokens '<user>!<tokenid>' --roles <role>`.
5. **Store & rollback**: stores the secret before reporting success, choosing the
   target in order: explicit `--secret-file <path>` -> `token_secret_file` on the
   profile -> macOS Keychain (`proxxx` / `<profile>/token_secret`, when compiled
   in) -> `<config_dir>/secrets/<profile>.token`. Secret files are opened with
   mode `0600` from the first byte inside a `0700` parent directory and renamed
   atomically; existing files or keychain entries are refused unless `--rotate` is
   set. If ACL assignment or local secret storage fails after token creation,
   `proxxx` removes the newly created token over SSH (rollback) and never prints
   the secret as a fallback.
6. **Verify & TOML snippet**: builds a `PxClient` with the stored secret, runs
   `GET /version` and `GET /nodes` (a verification failure keeps the stored
   secret and exits `1`), records write-ahead `"sent"` and outcome entries in the
   HMAC-chained audit log (with `user`, `tokenid`, `role`, `path`, and `node` —
   never the secret), and prints the `token_id` (plus `token_secret_file` when a
   file was used) TOML lines without editing `config.toml`.

## Secrets

The resolution order for PVE (`token_secret`, `password`), PBS (`pbs.token_secret`), and Telegram (`telegram.bot_token`) is:

1. **CLI flag** (`--token-secret VALUE` or `--token-secret-file PATH`) — highest priority, takes
   precedence over everything else. It holds ONE secret for the selected profile: it is
   used for that profile's PVE credentials, and for PBS only by `proxxx pbs ...` commands
   (there is no separate PBS flag; elsewhere PBS resolves its own secret). Commands that
   contact every profile (`ls --all-profiles`, `find`, `fleet`) refuse it with exit 3, and
   after a profile switch in the TUI the next profile resolves its own secret.
2. **Environment variable** (`PROXXX_TOKEN_SECRET`, `PROXXX_PASSWORD`,
   `PROXXX_PBS_TOKEN_SECRET`, or `PROXXX_TELEGRAM_BOT_TOKEN`; capped at 64 KiB).
3. **Inline TOML key** (`token_secret`, `password`, `pbs.token_secret`; note that for Telegram, `telegram.bot_token_file` is checked before inline `telegram.bot_token`).
4. **File reference** — `token_secret_file = "~/.config/proxxx/secrets/pve.token"`
   (or `pbs.token_secret_file`, `telegram.bot_token_file`). Leading `~` and `~/...`
   are expanded against `$HOME`. On Unix the file must have mode `0600` or stricter;
   proxxx refuses to read files with group or world permissions.
5. **macOS Keychain (macOS only)** — last resort. Service is always `proxxx`.
   For a named profile `<profile>`, proxxx queries the profile-scoped account first
   and falls back to the flat account name:
   - PVE API token secret: `<profile>/token_secret`, then `token_secret`
   - PVE password: `<profile>/password`, then `password`
   - PBS API token secret: `<profile>/pbs_token_secret`, then `pbs_token_secret`
   - Telegram bot token: `<profile>/telegram_bot_token`, then `telegram_bot_token`

   The keychain backend (`keyring` with `apple-native` / Security.framework) is
   compiled on macOS only (`--no-default-features` disables it on macOS; on Linux
   and other targets the `keychain` Cargo feature is a no-op and no keychain store
   is compiled in — use `token_secret_file` or environment variables there).
   Verify whether a keychain store is compiled into your binary with
   `proxxx version --json` (`keychain.compiled` / `keychain.store`) or `proxxx doctor`.

When no secret can be resolved, the error lists every source consulted in order
and why each did not yield a secret (without ever printing a secret value).

Once loaded, secrets are held as `SecretString`: its `Debug` prints
`[REDACTED]`, it has no `Display`, and its heap allocation is wiped on
`Drop`. The temporaries a secret passes through while the config loads
are not wiped.

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

### Shared profile defaults (`[defaults]`)

When several standalone Proxmox nodes or clusters share the same `user`,
`token_id`, `verify_tls`, `[ssh]`, `[pbs]`, `[telegram]`, `[reconcile]`,
`[[policies]]`, or `[[alerts]]` settings, declare them once in a top-level
`[defaults]` table (`#331`). Every `[profiles.<name>]` entry inherits
from `[defaults]` before deserialization:

```toml
default = "pve1"

[defaults]
user = "root@pam"
token_id = "proxxx"
verify_tls = false

[defaults.ssh]
user = "root"
key_path = "~/.ssh/proxxx_ed25519"

[profiles.pve1]
url = "https://pve1.lan:8006"
token_secret_file = "~/.config/proxxx/secrets/pve1.token"

[profiles.pve2]
url = "https://pve2.lan:8006"
token_secret_file = "~/.config/proxxx/secrets/pve2.token"
```

Merge rules:

- **Profile always wins**: any key set in `[profiles.<name>]` overrides `[defaults]`.
- **One-level sub-table merge**: `[defaults.ssh]`, `[defaults.pbs]`,
  `[defaults.telegram]`, and `[defaults.reconcile]` fill missing keys in the
  corresponding `[profiles.<name>.<sub>]` table. Nested maps inside a sub-table
  (such as `[ssh.hosts]` or `[ssh.guests]`) are **not** merged recursively — if
  the profile sets `hosts` or `guests`, the profile's map replaces the default map
  whole; otherwise the default map is inherited whole.
- **Arrays replace**: `[[defaults.policies]]` and `[[defaults.alerts]]` are
  replaced wholesale when a profile defines its own `[[profiles.<name>.policies]]`
  or `[[profiles.<name>.alerts]]`.
- **Refusals (exit code `3`)**:
  - `url` is forbidden in `[defaults]` (each profile must declare its own endpoint).
  - Secrets (`token_secret`, `token_secret_file`, `password`, `mcp_token`,
    `pbs.token_secret`, `pbs.token_secret_file`, `telegram.bot_token`,
    `telegram.bot_token_file`) are forbidden in `[defaults]` so a single credential
    is never silently shared across every node; store secrets per profile, via
    environment variables, or in the OS keychain.
  - Unknown keys in `[defaults]` or its sub-tables fail immediately with a
    `ConfigError` (exit code `3`) naming `[defaults]`.
- **Flat top-level configs (no `[profiles]`)**: `[defaults]` is still schema-validated,
  then stripped with a warning because no named profile is active.

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

### Reloading a running daemon (`SIGHUP`)

`daemon serve`, `mcp serve`, `mcp serve-http` and `alerts watch` reload `config.toml` on
`SIGHUP` (a reload that fails to parse keeps the previous config). Applied without a
restart: `read_only` (checked before every write, so setting `read_only = true` and sending
`SIGHUP` stops writes immediately), `[reconcile]` (re-read on every reconcile tick, including
`auto_converge`), `[[alerts]]`, `[[policies]]`, the `[telegram]` structure and `mcp_token`.
Restart required: `url`, `user`, `token_id`, the token secret, `rate_limit`,
`reconcile.interval_secs` and Telegram bot credentials. The reload log line lists both.
`daemon serve` starts its alerts, HITL and reconcile components only when `[[alerts]]` rules,
`[telegram]` and `[reconcile]` are present at startup; adding one of them later needs a restart.

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

::: tip Flat config or profiles
The SSH, PBS, Telegram, policy and alert sections below are written at the
top level, as in a flat config. With `[profiles.<name>]` tables, put them
under the profile (`[profiles.homelab.telegram]`, `[[profiles.homelab.alerts]]`)
or under `[defaults]` to share them; a top-level one is refused (exit 3)
there, since no profile would read it.
:::

## SSH

For `proxxx ssh <vmid>`, `proxxx perms`, `proxxx gpu inspect`, `proxxx logs tail`, `proxxx doctor`, and the patching orchestrator (`proxxx patch apply`):

```toml
[ssh]
key_path = "~/.ssh/proxxx_homelab"           # Ed25519, ECDSA or RSA >= 2048 bits (~ expanded against $HOME)
user     = "root"                            # optional, defaults to "root"

[ssh.hosts]
pve1 = "10.0.0.1:22"
pve2 = "10.0.0.2:22"

[ssh.guests."100"]
host = "10.10.10.100"
user = "fab"

[ssh.guests."200"]
host     = "10.10.10.200"
key_path = "~/.ssh/k8s_master"               # optional, falls back to [ssh].key_path (~ expanded)
```

For node-level SSH (`proxxx perms`, `proxxx gpu inspect`, `proxxx logs tail`, `proxxx patch apply`), `SshPool` resolves a target `<node>` in strict order:

1. **`[ssh.hosts]` override (`hosts.<node>`)** — always wins when present (no `/cluster/status` call is needed). Accepts `<host>` (defaults to port `22`) or `<host>:<port>` (including bracketed IPv6 `[::1]:2222`).
2. **Profile `url` host fallback (port `22`)** — used **only** when `<node>` is the node answering the PVE API (`/cluster/status` entry with `local = true`, or the single node of a standalone install). On a session opened through this fallback, `SshPool` runs `hostname` before the first command and refuses the connection if the remote short hostname does not match `<node>` (protecting against a profile `url` that points at a VIP or load balancer).
3. **Node-name DNS / `/etc/hosts` fallback (`<node>:22`)** — for every other member of a cluster (or if `/cluster/status` is unavailable), `SshPool` falls back to `<node>:22` without an identity check. If that connection fails with a name-lookup error, the error adds `hosts = { <node> = "<ip>:22" }` so operators whose non-API cluster node names do not resolve in DNS know the exact `[ssh.hosts]` entry to add.

Both `key_path` (at `[ssh]` and `[ssh.guests."<vmid>"]`) and `known_hosts`
accept a leading `~` or `~/...` (expanded via `util::path::expand_tilde`,
shared with `token_secret_file` and `proxxx doctor`). SSH uses publickey
only — no agent. An RSA key must have at least 2048 bits and a DSA key is
refused (the NIST minimum through 2030); proxxx says so before it connects.
Ed25519 is recommended. If your key is encrypted, set `PROXXX_SSH_KEY_PASSPHRASE`
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
