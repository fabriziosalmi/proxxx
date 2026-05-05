# Configuration schema

The full TOML schema, section by section. Defaults shown when
applicable.

## Top level

```toml
default = "homelab"        # optional: name of profile to use when --profile omitted
url = "..."                # if no [profiles.X] tables, top-level fields ARE the default profile
user = "..."
auth = "token" | "password"
token_id = "..."
token_secret = "..."
verify_tls = true
```

If both `default` and `[profiles.X]` are present, `default` selects
which profile to load. If only top-level fields are present, those
fields are the implicit profile.

## `[profiles.<name>]`

```toml
[profiles.homelab]
url           = "https://pve1.lan:8006/"
user          = "root@pam"
auth          = "token"               # token | password
token_id      = "proxxx"
token_secret  = "..."                 # plain string OR
token_secret_file = "/etc/proxxx/token"
password      = "..."                 # only if auth = "password"
password_file = "..."
verify_tls    = false
rate_limit    = 10                    # max API requests/second (default 10)
```

## `[ssh]` (top-level default)

```toml
[ssh]
key  = "/home/fab/.ssh/proxxx_homelab"   # ed25519 / rsa private key path
host = "10.0.0.1"                    # default node for `proxxx perms` and patching
port = 22                                  # optional, default 22
user = "root"                              # optional, default "root"
known_hosts = "~/.config/proxxx/known_hosts"  # optional, default to XDG path
```

## `[ssh.guests.<vmid>]`

Per-guest SSH targets for `proxxx ssh <vmid>`:

```toml
[ssh.guests."100"]
host = "10.10.10.100"
port = 22
user = "fab"
key  = "/home/fab/.ssh/k8s_master"        # optional, falls back to top-level [ssh].key
```

VMIDs must be quoted (TOML key restriction).

## `[telegram]`

Used by HITL and alert routing.

```toml
[telegram]
bot_token = "123456:ABC..."           # from @BotFather
chat_id   = -1001234567890            # from getUpdates response
```

## `[[policies]]` (HITL)

```toml
[[policies]]
action           = "delete"           # delete | stop | restart | migrate | exec | move_disk | resize_disk
target           = "tag:prod"         # tag:<X> | <vmid> | * (numeric or wildcard)
require_approval = true
timeout_secs     = 120                # default 120
```

Multiple `[[policies]]` arrays are evaluated in order. The first
matching one wins.

## `[pbs]`

For Proxmox Backup Server browse and restore.

```toml
[pbs]
url                = "https://pbs.lan:8007/"
user               = "proxxx@pbs"
token_id           = "reader"
token_secret       = "..."
token_secret_file  = "/etc/proxxx/pbs-token"
verify_tls         = false
rate_limit         = 10
```

::: warning
PBS uses `:` between `token_id` and `secret` in the auth header, not
`=` like PVE. proxxx handles this internally — you don't need to
pre-format the secret.
:::

## `[[alerts]]`

```toml
[[alerts]]
name              = "node_down"
trigger           = "node_offline"           # closed enum: see Alerts integration
threshold         = 60                        # seconds
storage           = "ceph-rbd"                # filter for storage_above (optional)
threshold_percent = 85                        # for storage_above
severity          = "critical"                # info | warning | critical
route             = ["telegram", "ntfy:topic"]
dedup_secs        = 600                       # don't re-fire within N seconds
```

The `trigger` is a closed enum (`node_offline`, `storage_above`,
`replication_failing`). New triggers require code changes — that is
intentional, see [Alerts](/integrations/alerts).

## Resolution order for secrets

For each of `token_secret`, `password`, `pbs.token_secret`:

1. CLI flag (`--token-secret VALUE`)
2. Env var (`PROXXX_TOKEN_SECRET`, `PROXXX_PASSWORD`,
   `PROXXX_PBS_TOKEN_SECRET`)
3. File reference (`<...>_secret_file = "..."`)
4. Inline TOML value (`<...>_secret = "..."`)
5. OS keychain (service `proxxx`, key matches the field name)

The first one that resolves wins. Loaded values live in
`Zeroizing<String>` and are wiped from the heap on Drop.

## Defaults summary

| Field | Default |
| :--- | :--- |
| `verify_tls` | `true` |
| `rate_limit` | `10` |
| `port` (SSH) | `22` |
| `user` (SSH) | `"root"` |
| `timeout_secs` (HITL policy) | `120` |
| `dedup_secs` (alert) | `600` |
| `severity` (alert) | `"warning"` |
| `auth` | `"token"` |

## File location

| Platform | Path |
| :--- | :--- |
| Linux   | `~/.config/proxxx/config.toml` |
| macOS   | `~/Library/Application Support/dev.proxxx.proxxx/config.toml` |
| Windows | `%APPDATA%\dev\proxxx\proxxx\config.toml` |

Set `PROXXX_CONFIG=/path/to/file.toml` to override.

## Validation

proxxx validates the schema on load. A failed validation prints the
section and key, then exits with code 3 (`Configuration error`).
Common errors:

- **`url` missing trailing colon** — proxxx adds `/api2/json` itself,
  so the URL stops at `:8006/`
- **`token_secret` has trailing whitespace** — copy-paste from the
  web UI sometimes appends a newline; trim it
- **`auth = "token"` without `token_id`** — both fields are required
- **`[ssh]` referenced but `key` is missing** — `proxxx ssh <vmid>`,
  `proxxx perms`, and `proxxx patch apply` all require it
