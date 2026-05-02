# proxxx

The Proxmox CLI / TUI you'd hire someone to write. Rust, async, single
binary, no installer. Works as a fast read-only inspector and as the
operational tool for the messy parts of running a homelab or small-prod
Proxmox cluster.

> **Status.** Pre-release. Tier 1 + 2 + 3 + the full Tavola Alta
> backlog are shipped (see [`features.md`](features.md) for the
> verified per-component status). 262 tests passing, 9/9 known bugs
> fixed, 3/3 architectural blockers closed. Niente push fino a
> validazione live contro un cluster reale (vedi
> [`docs/cluster_smoke.md`](docs/cluster_smoke.md)).

## What it does

### Daily-driver TUI

Run with no arguments to enter the TUI:

```bash
proxxx
```

- Cluster dashboard with sparklines, fuzzy search (`/`), command
  palette (`:`).
- Node list, guest list (unified VM/LXC), storage pools, live task
  log streaming.
- Multi-select + bulk ops (start/stop/restart/migrate/delete).
- Operation queue with dry-run, diff preview, and HITL approval gate
  (Telegram / policy-driven).
- Hotspot heatmap, backup health board, config drift detector,
  storage trend forecast, audit timeline scrub.

### Pipeline-friendly CLI

Every command supports `--format json` for piping into `jq` / scripts.

```bash
# Read
proxxx ls nodes                                 # alias: `proxxx get nodes`
proxxx ls guests --format json | jq '.[] | select(.status=="running")'
proxxx ha preview --node pve1                   # failover what-if
proxxx hw conflicts --node pve1                 # PCI passthrough audit
proxxx alerts eval                              # one-shot rule check
proxxx perms root@pam --node pve1               # effective permissions

# Write (every destructive op requires explicit consent)
proxxx start 100 101 102
proxxx stop 100 --force
proxxx delete 100 --yes
proxxx snapshot create 100 --name pre-upgrade
proxxx token create root@pam ci --comment "CI key"
proxxx disk move 100 --disk scsi0 --storage ceph-rbd --yes
proxxx patch apply --reboot=auto --dry-run

# Console handoff
proxxx ssh 100                                  # via TUI palette: ":ssh 100"
proxxx serial 100 --node pve1                   # raw termproxy WebSocket
proxxx spice 100 --node pve1                    # writes .vv, launches remote-viewer
proxxx novnc 100 --node pve1                    # opens browser to web UI's noVNC

# Operations
proxxx patch plan                               # apt update + classify
proxxx pbs snapshots --store main               # browse PBS backups
proxxx pbs restore --store main --snapshot ... --target /tmp/...
proxxx alerts watch --interval 30               # alert daemon

# AI agent surface
proxxx mcp serve                                # MCP stdio server
proxxx mcp tools --checksum                     # registry hash for audit
```

Full subcommand list: `proxxx --help`.

## Build

```bash
cargo build --release
# binary: target/release/proxxx (~12-15 MB stripped)
```

Quality gates:

```bash
cargo test                # 262 tests, ~3s wall time
cargo clippy --all-targets  # 0 errors, ~540 pedantic-only warnings
cargo fmt --check
```

## Configuration

Drop a profile config at `~/.config/proxxx/config.toml`. Start from
[`docs/config.example.toml`](docs/config.example.toml) — every section
is annotated with what it unlocks.

Minimum viable config (read-only Proxmox VE access):

```toml
url = "https://pve1.lan:8006"
user = "root@pam"
auth = "token"
token_id = "proxxx"
verify_tls = false
```

The token secret can come from a CLI flag, the `PROXXX_TOKEN_SECRET`
env var, a 0600 file, or the OS keychain — in that order.

Optional sections enable extra surface area:

| Section          | Unlocks                                                                |
| :--------------- | :--------------------------------------------------------------------- |
| `[telegram]`     | HITL approvals for destructive ops + alert routing                     |
| `[ssh]`          | Patching orchestrator (#9), permission debugger (#10), guest SSH (#1a) |
| `[ssh.guests.X]` | Per-guest SSH session targets for `:ssh <vmid>`                        |
| `[pbs]`          | Backup browse + restore                                                |
| `[[alerts]]`     | Alerting daemon                                                        |
| `[[policies]]`   | HITL gating rules                                                      |

## Architecture

The codebase follows the Elm Architecture for the TUI:

```
        crossterm key            tokio::mpsc
  user ─────────────────► event::map_key ─► Action
                                              │
                                              ▼
                                   app::update(state, action)
                                              │
                                ┌─────────────┴────────────┐
                                ▼                          ▼
                          AppState mutation      Option<SideEffect>
                                                          │
                                                          ▼
                                              dispatch_side_effect
                                              (HITL gate, then API)
```

- **Pure reducer** in [`src/app.rs`](src/app.rs). No I/O, no async.
- **Side effects** are async tokio tasks that send `DataMsg` back over
  an mpsc channel.
- **API gateway** in [`src/api/`](src/api) — single `ProxmoxGateway`
  trait, all writes type-aware (qemu vs lxc) since bug #1.
- **SSH layer** ([`src/ssh/`](src/ssh)) is `russh`-based, publickey
  only, dedicated TOFU known_hosts.
- **Cache** is SQLite-backed for time-travel (`proxxx replay <ts>`).

The full module map and "honest cuts" per feature are in
[`features.md`](features.md).

## Documentation

- [`features.md`](features.md) — per-feature status + tagli onesti
  (release-time TODOs, deferred scope, declared limits).
- [`CHANGELOG.md`](CHANGELOG.md) — what's in the box.
- [`docs/config.example.toml`](docs/config.example.toml) — every config
  knob with comments.
- [`docs/cluster_smoke.md`](docs/cluster_smoke.md) — end-to-end runbook
  for live validation against a real PVE cluster.
- [`docs/cli-contract.md`](docs/cli-contract.md) — CLI exit code +
  JSON output stability promises.
- [`bootstrap.md`](bootstrap.md) — original architecture spec, kept
  for historical context.

## Honest non-goals

- No GUI. Proxmox already has a web UI; we're for terminal users.
- No multi-cluster aggregation in the TUI yet (planned).
- No frame rendering (graphical SPICE/noVNC) — we hand off to
  `remote-viewer` / browser.
- No re-implementation of Perl algorithms in Rust where the Perl is
  the ground truth (e.g. effective permissions — we shell out to
  `pveum`).
- No new dependencies for trivial things — `Command::new` per platform
  beats pulling `opener` for a 3-line problem.

## License

MIT.
