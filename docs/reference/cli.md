# CLI reference

Every command supports `--format json|table|plain`. Default is `table`.
JSON output is part of the public contract — additive-only changes
within a major version.

## Global flags

```
--profile <NAME>           Connection profile name (default: top-level)
--format <FORMAT>          Output format: json | table | plain (default: table)
--token-secret <VALUE>     Override token from config / env / keychain
--secure                   Require Telegram approval for every destructive op
```

## Read commands

| Command | What it does |
| :--- | :--- |
| `proxxx ls nodes`              | Cluster nodes with CPU / RAM / uptime / status |
| `proxxx ls guests`             | All VMs and LXCs across the cluster |
| `proxxx ls storage`            | Storage pools, type, used / available |
| `proxxx cluster-resources [--kind ...]` | Single-shot cluster-wide flat list (web-UI dashboard query) |
| `proxxx pve-version`           | PVE API version + git rev (compat-gating) |
| `proxxx tasks [--node N]`      | Recent tasks, newest first; `--node` filters per-node |
| `proxxx cluster-log [--max N]` | Cluster event log (login/quorum/task lifecycle) |
| `proxxx config <vmid>`         | Current Proxmox config for a guest |
| `proxxx search <query>`        | Fuzzy search across nodes, guests, storage |
| `proxxx feature <vmid> --feature X` | Pre-flight cap check (`snapshot`/`clone`/`migrate`/...) |
| `proxxx ha groups`             | HA groups (PVE-version-tolerant) |
| `proxxx ha groups-legacy`      | Legacy `/cluster/ha/groups` path (PVE 8 only) |
| `proxxx ha resources`          | Resources managed by HA |
| `proxxx ha status`             | Raw HA manager runtime state |
| `proxxx ha status-current`     | User-facing live HA status (per-node + per-service rows) |
| `proxxx ha preview --node N`   | Failover preview if a node went down |
| `proxxx replication jobs`      | Storage replication jobs |
| `proxxx replication status`    | Per-node replication runtime |
| `proxxx hw pci --node N`       | PCI device inventory |
| `proxxx hw usb --node N`       | USB device inventory |
| `proxxx hw conflicts --node N` | PCI passthrough conflict detector |
| `proxxx perms <user>`          | Effective permissions (SSH-shellout to `pveum`) |
| `proxxx access permissions [--userid X] [--path Y]` | API-side permissions tree, no SSH dep |
| `proxxx access acl`            | ACL entries |
| `proxxx access users`          | User list |
| `proxxx access groups`         | Group list |
| `proxxx access roles`          | Role definitions |
| `proxxx access realms`         | Authentication realms |
| `proxxx access tfa`            | TFA enrollments |
| `proxxx token list`            | API tokens |
| `proxxx network --node N`      | Node network interfaces |
| `proxxx firewall`              | Firewall rules (cluster / node / guest scopes — read-only) |
| `proxxx pool list / show`      | Multi-tenancy pool listing + member inspection |
| `proxxx version --json`        | Build + capability metadata |

## Write commands (require `--yes` or pre-flight clearance)

| Command | What it does |
| :--- | :--- |
| `proxxx start <vmid>...`                 | Start one or more guests in parallel |
| `proxxx stop <vmid> [--force]`           | Graceful shutdown (or hard stop) |
| `proxxx restart <vmid>`                  | Restart a guest |
| `proxxx delete <vmid> --yes`             | Delete a guest |
| `proxxx migrate <vmid> --target N --yes` | Migrate to another node (auto online/offline) |
| `proxxx exec <vmid> -- <cmd>`            | Run a command via QEMU Guest Agent |
| `proxxx snapshot create <vmid> --name X` | Create a snapshot |
| `proxxx snapshot delete <vmid> --name X` | Delete a snapshot |
| `proxxx backup <vmid>... --storage S`    | vzdump one-shot backup |
| `proxxx backup-jobs {list,show,create,update,delete,info,extract-config}` | Recurring vzdump scheduler (cluster `/backup`) |
| `proxxx template <vmid> --yes`           | Convert guest to template (irreversible) |
| `proxxx clone <vmid> <new-vmid> [--full]`| Clone guest or template |
| `proxxx disk move <vmid> --disk D --storage S --yes` | Move disk between storages |
| `proxxx disk resize <vmid> --disk D --size +10G --yes` | Grow disk |
| `proxxx task-stop --node N --upid U --yes` | Cancel a running task (vzdump / migration / etc.) |
| `proxxx token create <user> <id>`        | Create API token (secret shown once) |
| `proxxx token revoke <user> <id> --yes`  | Revoke token |
| `proxxx access password <userid> --password X` | Change a user's password |
| `proxxx pool {create,add-members,remove-members,set-comment,delete}` | Multi-tenancy pool CRUD |

## Configuration writes

| Command | What it does |
| :--- | :--- |
| `proxxx vm set <vmid> --cores N --memory MB`  | Typed VM hardware config |
| `proxxx vm cloudinit <vmid> --user U --sshkey FILE` | Cloud-init parameters |
| `proxxx vm cloudinit-dump <vmid> [--kind user\|network\|meta]` | Dump generated cloud-init data (debug template inheritance) |
| `proxxx vm raw-set <vmid> --key K --value V`  | Escape hatch for untyped keys |
| `proxxx vm sendkey <vmid> --key K`            | Send NMI/sysrq via QMP (kernel debug) |
| `proxxx vm unlink <vmid> --idlist scsi1 [--force --yes]` | Detach disk; `--force` also deletes volume |
| `proxxx ct set <vmid> --cores N --memory MB`  | LXC config |
| `proxxx ct interfaces <vmid>`                 | Container network interfaces (LXC equivalent of QGA net-get-interfaces) |

## Firewall CRUD

| Command | What it does |
| :--- | :--- |
| `proxxx firewall-cluster alias {list,create,update,delete}`     | Cluster alias CRUD (named CIDRs) |
| `proxxx firewall-cluster group {list,create,delete,rules}`      | Security group CRUD + rule listing |
| `proxxx firewall-cluster ipset {list,create,delete,cidrs,add-cidr,remove-cidr}` | IP set CRUD + per-CIDR mgmt |
| `proxxx firewall-cluster options {get,set}`                     | Global cluster firewall options |
| `proxxx firewall-guest <vmid> alias {list,create,update,delete}`| Per-guest alias CRUD |
| `proxxx firewall-guest <vmid> options {get,set}`                | Per-guest firewall options (NIC-level knobs) |

## Cluster lifecycle

| Command | What it does |
| :--- | :--- |
| `proxxx cluster-config {get,set}`                    | Global cluster options (mac_prefix, migration network, console, ...) |
| `proxxx cluster-bootstrap nodes {list,add,remove}`   | Corosync node membership |
| `proxxx cluster-bootstrap join {info,join}`          | Get join data / actually join an existing cluster |
| `proxxx cluster-bootstrap qdevice {get,setup,update,delete}` | Quorum device tiebreaker |
| `proxxx cluster-bootstrap totem`                     | Inspect corosync totem transport (read-only) |
| `proxxx ha group-create --group X --nodes ...`       | Create HA group (PVE 8) |
| `proxxx ha group-update <group> [...]`               | Update HA group |
| `proxxx ha group-delete <group> --yes`               | Delete HA group |

## Storage + ACME + mapping

| Command | What it does |
| :--- | :--- |
| `proxxx storage-defs {list,show,create,update,delete}` | Cluster-wide storage CRUD (NFS, PBS, ZFS pool, dir, RBD, ...) |
| `proxxx cluster-mapping pci {list,create,update,delete}` | PCI passthrough mapping (logical names for GPU passthrough across nodes) |
| `proxxx cluster-mapping usb {list,create,update,delete}` | USB passthrough mapping |
| `proxxx acme account {list,show,create,update,delete}`   | ACME CA account registration |
| `proxxx acme plugin {list,show,create,update,delete}`    | DNS-01 / HTTP-01 challenge plugins |
| `proxxx acme {tos,directories,challenge-schema}`         | Read-only ACME support endpoints |
| `proxxx aplinfo {list,download} --node N`                | LXC template catalog (`pveam available` / `pveam download`) |
| `proxxx url-info --node N --url ...`                     | Pre-flight a URL for `download_to_storage` (size + filename + mime) |

## Notifications + metrics

| Command | What it does |
| :--- | :--- |
| `proxxx notifications endpoint {list,create,update,delete}` | PVE 8+ delivery: sendmail / smtp / gotify / webhook |
| `proxxx notifications matcher {list,create,update,delete}`  | Routing rules (which events go where) |
| `proxxx notifications targets`                              | Read-only flat list of valid delivery names |
| `proxxx metric-servers {list,show,create,update,delete}`    | InfluxDB / Graphite exporter CRUD (cluster-wide) |
| `proxxx metrics rrd-png <vmid> --ds X`                      | Pre-rendered PNG graph reference (UI / export pipelines) |

## Node system layer

`proxxx node-system <node> ...` covers the node-scoped admin surface:

| Subcommand | What it does |
| :--- | :--- |
| `dns {get,set}`        | Resolver config (search domain + up to 3 nameservers) |
| `hosts {get,set}`      | `/etc/hosts` content (digest-guarded atomic replace) |
| `journal [...]`        | Tail systemd journal with PVE filters |
| `syslog [...]`         | Tail `/var/log/syslog` (line-numbered for paging) |
| `time {get,set}`       | NTP / timezone (clock itself is NTP-driven) |
| `wol`                  | Wake-on-LAN magic packet via cluster network |
| `subscription {get,set,refresh,delete}` | Subscription key management |
| `cert {info,upload,delete,acme-order}`  | pveproxy TLS certs — list / upload custom / order ACME |
| `report`               | `pvereport` support bundle (plain text) |

## QEMU Guest Agent (QGA file ops)

| Command | What it does |
| :--- | :--- |
| `proxxx qga <vmid> read --file /path`         | Read a file inside a running QEMU guest |
| `proxxx qga <vmid> write --file /path --content ...` | Write a file inside the guest |
| `proxxx qga <vmid> net`                       | Guest-kernel-reported network interfaces (more authoritative than cloud-init) |

## Console handoff

| Command | What it does |
| :--- | :--- |
| `proxxx ssh <vmid> [--cmd "<remote-cmd>"]` | Spawn the system `ssh` against the guest. Resolves via `[ssh.guests."<vmid>"]` first, then auto-discovers via QGA (QEMU) or `/lxc/N/interfaces` (LXC). Picks first routable IPv4 (skips loopback / link-local). `--cmd` runs a one-shot non-interactively |
| `proxxx serial <vmid> --node N`  | Raw termproxy WebSocket. Ctrl+] then `q` to exit |
| `proxxx spice <vmid> --node N`   | Write 0600 `.vv`, launch `remote-viewer` / `virt-viewer` |
| `proxxx novnc <vmid> --node N`   | Open the system browser at the web UI's noVNC console |
| `proxxx vnc <vmid> [--ws-url]`   | Mint a one-shot VNC ticket; `--ws-url` also emits the wss:// URL for hand-off to noVNC / `tokio-tungstenite` |

## Long-running daemons

| Command | What it does |
| :--- | :--- |
| `proxxx mcp serve`                  | Stdio JSON-RPC MCP server for LLM agents |
| `proxxx mcp tools [--checksum]`     | Introspect the tool registry; `--checksum` prints SHA-256 |
| `proxxx hitl serve`                 | Long-poll Telegram for HITL approval callbacks |
| `proxxx alerts watch [--interval N]`| Rule-driven alerting daemon |
| `proxxx alerts eval`                | One-shot rule evaluation |
| `proxxx alerts test --route R`      | Send a synthetic event end-to-end |
| `proxxx watch --since 1h`           | Diff cluster state vs N ago |
| `proxxx watch <target> --until X`   | Wait for a condition; optionally `--notify telegram` |
| `proxxx replay <timestamp>`         | Show cached cluster state at a point in time |

## Operations orchestrators

| Command | What it does |
| :--- | :--- |
| `proxxx patch plan`                                  | apt refresh + classify pending upgrades |
| `proxxx patch apply [--reboot=auto] [--dry-run]`     | Rolling cluster patch + reboot |

## PBS

| Command | What it does |
| :--- | :--- |
| `proxxx pbs datastores`                                  | List PBS datastores |
| `proxxx pbs snapshots --store S [--backup-type T] [--backup-id I]` | Browse snapshots |
| `proxxx pbs files --store S --type T --backup-id I --time U` | List archive files in a snapshot |
| `proxxx pbs restore --store S --snapshot R --archive A --target T --yes` | Full archive restore |

## ISO library

| Command | What it does |
| :--- | :--- |
| `proxxx iso list`                                              | Curated cloud-image catalog with pinned SHA-256 |
| `proxxx iso download --id ID --node N --storage S`             | Download from curated library (refuses unpinned entries) |
| `proxxx iso download --url URL --filename F --content C [--sha256 H]` | Download an arbitrary URL to a node's storage |

## Diagnostics

| Command | What it does |
| :--- | :--- |
| `proxxx doctor`                  | Self-diagnostic: config, cluster connectivity, auth, Telegram HITL, PBS, SSH key, audit log. Exits 0 if all critical checks pass |
| `proxxx dev-panic [--message X]` | Flight-recorder smoke — trigger a controlled panic to test the flight-recorder hook |
| `proxxx version --json`          | Test count, vector framework hash, audit ignores, build metadata |
| `proxxx completions {bash\|zsh\|fish\|powershell}` | Print shell completion script to stdout — pipe to your shell's completions dir |

## Audit log

| Command | What it does |
| :--- | :--- |
| `proxxx audit log [--limit N] [--since T]`        | Show recent audit entries (SQLite, append-only) |
| `proxxx audit export --format {json\|csv}`        | Dump entries for SIEM ingestion |
| `proxxx audit verify`                             | Walk the full HMAC-SHA256 chain — NIS2/ISO 27001 evidence |

## Guest lifecycle (additional)

| Command | What it does |
| :--- | :--- |
| `proxxx vm create --node <n> [--vmid <id>] [--name <s>] [--memory <M>] [--cores <N>] [--disk <storage:sizeG>] [--iso <volid>] [--ostype <t>] [--bridge <br>] [--wait]` | Create new QEMU VM from scratch. VMID auto-assigned if omitted |
| `proxxx ct create --node <n> --template <volid> [--vmid <id>] [--hostname <h>] [--memory <M>] [--cores <N>] [--rootfs <storage:sizeG>] [--bridge <br>] [--password <p>] [--wait]` | Create new LXC from template |
| `proxxx clone <src_vmid> [--newid <id>] [--name <s>] [--cloud-init-user <file.toml>]` | Clone guest; with `--cloud-init-user`, parse TOML profile (ciuser, sshkey, ipconfig0, …) and apply after clone task lands + regen drive |

## Events

| Command | What it does |
| :--- | :--- |
| `proxxx events stream [--interval <s>] [--node <n>] [--type <t>] [--vmid <id>] [--no-existing] [--format {text\|json}]` | Tail real-time cluster task events (START/DONE/FAIL). NDJSON output with `--format json` |

## Configuration bootstrap

| Command | What it does |
| :--- | :--- |
| `proxxx init`                | Write a commented starter `config.toml` to the OS-default config dir; refuses to overwrite without `--force` |
| `proxxx init --interactive`  | 5-step prompted wizard: URL + reachability probe, TLS choice, auth (token or password) live-validated, optional SSH layer with `~/.ssh/` key auto-discovery + per-guest overrides, optional Telegram for HITL. A wrong field is caught at the prompt, never lands in TOML |
| `proxxx init --force`        | Overwrite an existing config without backup (template-only path) |

## See also

- [TUI reference](/reference/tui) — keymap and views
- [Configuration schema](/reference/configuration) — TOML by section
- [Exit codes](/reference/exit-codes) — stable contract
- [Error categories](/reference/errors) — typed error model
