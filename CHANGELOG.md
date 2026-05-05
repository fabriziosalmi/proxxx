# Changelog

All notable changes are documented here. The project follows this
SemVer contract:

- TUI layout changes are NOT covered (minor).
- CLI commands + exit codes are strictly SemVer.
- `--format json` output is additive-only (removing/renaming fields →
  major bump).
- Config schema is backwards compatible.
- MCP tool registry is append-only.

## [Unreleased]

### Added — 2026-05-04 — PVE API surface expansion (51% → 85%)

A focused multi-region session adding 67 PVE endpoints across 11
self-contained surfaces. Map coverage went 96/188 → 163/190 (51% →
85%). Sixteen feature commits, four documentation refresh commits,
each one through the full pre-commit gate (fmt, clippy, audit, tests,
live read probes, live LXC mutation lifecycle) and three remote CI
jobs.

CLI surfaces shipped (one or more new top-level commands per region,
documented in `docs/reference/cli.md`):

- **Backup scheduler** (`backup-jobs`) — recurring vzdump CRUD with
  schedule + retention + email; distinct from existing one-shot
  `backup`. PVE quirk noted: `/cluster/backup-info` is restricted to
  literal `root@pam` user, token auth gets 403.
- **Cluster firewall CRUD** (`firewall-cluster`, `firewall-guest`) —
  aliases, security groups, ipsets (with per-CIDR add/remove), global
  options. Both cluster scope (`/cluster/firewall/*`) and per-guest
  scope (`/nodes/{n}/{kind}/{vmid}/firewall/*`).
- **Hardware passthrough mapping** (`cluster-mapping`) — cluster-wide
  PCI / USB device pools (stable logical names that survive guest
  migrations across nodes with different PCI addresses).
- **QGA file ops** (`qga`) — `read`/`write`/`net` for QEMU guests via
  the guest-agent. `truncated` flag on read surfaces partial reads
  (PVE caps at ~16 KiB QGA buffer).
- **Node system layer** (`node-system <node>`) — DNS, /etc/hosts
  (digest-guarded atomic replace), NTP/timezone, journal/syslog with
  filters, subscription CRUD, certificate info + custom + ACME order,
  pvereport, wake-on-LAN.
- **Foundationals** (`pool`, `cluster-resources`, `pve-version`) —
  multi-tenancy pools (the multi-tenant primitive ACL paths target),
  the `/cluster/resources` single-shot dashboard query the web UI
  depends on, and `/version` for compat-gating.
- **Cluster options + log** (`cluster-config`, `cluster-log`) — global
  cluster config (mac_prefix, default migration network, console
  viewer, etc.) + cluster event log.
- **HA legacy + status/current** (`ha group-create/update/delete`,
  `ha status-current`) — PVE 8 `/cluster/ha/groups` CRUD (PVE 9 uses
  rules; both paths exposed) + the user-facing live HA status (vs the
  raw CRM `manager_status`).
- **PVE 8+ Notifications** (`notifications`) — endpoints (delivery
  mechanisms: sendmail/smtp/gotify/webhook), matchers (routing
  rules), targets (read-only flat list).
- **Storage definitions CRUD** (`storage-defs`) — add/update/delete
  cluster storages (NFS, PBS, ZFS pool, dir, RBD, LVM-thin, etc.).
- **ACME accounts + plugins** (`acme`) — account registration with
  the CA + DNS-01/HTTP-01 challenge plugins. Pairs with the per-node
  `node-system <node> cert acme-order`.
- **Cluster bootstrap** (`cluster-bootstrap`) — corosync node
  membership, join wizard (info + actual join), quorum-device
  tiebreaker CRUD, totem transport inspection.
- **Top-tier 80/20 grab-bag** — tasks per-node + cancel
  (`tasks --node N`, `task-stop`), guest feature pre-flight check
  (`feature`), QEMU sendkey/unlink (`vm sendkey`, `vm unlink`), LXC
  template catalog (`aplinfo`), URL pre-flight (`url-info`), VNC
  WebSocket URL builder (`vnc --ws-url`), API-side perms
  (`access permissions` — alternative to the SSH-shellout
  `proxxx perms`), password change (`access password`), LXC
  interfaces (`ct interfaces`), cloud-init dump (`vm cloudinit-dump`),
  RRD PNG graph references (`metrics rrd-png`), cluster metric
  exporters (`metric-servers`).

### Test count refresh

- **608 tests across 16 binaries** (was: 262 across 8). Includes
  246 lib unit + 212 wiremock + 22 TUI snapshot + the rest split
  across hitl, mcp, pbs, panic_hook, app, e2e wiremock harnesses.
  All passing, 0 failing.
- **38/38 live cluster read probes** — verified each commit.
- **LXC 9999 mutation lifecycle** — full create → start → snapshot →
  stop → delete cycle on every commit, never failed.

### ISO supply-chain — BLOCKER 1 fully closed (pin shipped)

The refuse-on-`None` gate was added at v0.0 (BLOCKER 1 first fix); the
release-time TODO was to pin actual hex against dated upstream
manifests. **Now shipped:** all 6 curated entries carry real lowercase
hex pins fetched from dated upstream `SHA*SUMS` (Ubuntu 22.04 / 24.04,
Debian 12, Fedora 41, Alpine 3.21.7, Rocky 9.7). Debian uses SHA-512
because the project does not publish SHA-256.

Test `all_entries_are_pinned` (in `src/app/iso_library.rs`) enforces
that no future entry can ship with `checksum: None`, even with the
gate in place. Prior CHANGELOG language describing the entries as
unpinned has been corrected to reflect the actual code state.

### Documentation aligned to shipped surface

- `README.md` — refreshed `## Honest non-goals` to distinguish design
  boundaries (Ceph writes, SDN config writes, browser-only auth) from
  the 11 surfaces shipped this cycle. Added
  `### Was a non-goal, now shipped` subsection.
- `docs/integrations/pve.md` — expanded endpoint coverage table from
  10 narrow rows to 19 categories spanning the full 163-endpoint
  surface. Replaced "What's missing" with the same boundaries +
  shipped-now split as the README.
- `docs/reference/cli.md` — added ~30 missing commands across new
  sections (Firewall CRUD, Cluster lifecycle, Storage+ACME+mapping,
  Notifications+metrics, Node system layer, QGA).
- `docs/index.md` — refreshed numeric counts (380+ → 600+ tests,
  19 → 18 TUI views, 39 → 65 CLI subcommands, 440 → 608 across 16
  binaries). All measured directly from the codebase.

### Added — Tier 1 / Core

- Cluster-wide instant fuzzy search (`/`)
- Operation queue with dry-run, diff preview, and `--secure` HITL gate
- Tag-based bulk ops (semicolon split, `t` keybind)
- Local SQLite cache with time-travel (`proxxx replay <ts>`)
- Node evacuation wizard (max-free-RAM target picking)
- Replay-as-script export: proxxx, pvesh, curl, Ansible

### Added — Tier 2 / Differenziatori

- Live hotspot heatmap (`H` view)
- Backup health board (per-guest age + duration)
- Config drift detector (`D` side-by-side compare)
- Storage trend & ETA-to-saturation (24h cache history)
- Parallel guest-agent broadcast (`X` from selection)
- CLI `watch` mode with Telegram notifications

### Added — Tier 3

- Audit timeline scrubbable (`T` view)
- Quick-open palette (`Ctrl-K`)
- Cluster-wide config grep (`G`)

### Added — Pillar 0: SSH layer

- `russh` 0.46 client, publickey-only auth
- TOFU known_hosts dedicated to proxxx (NOT `~/.ssh/known_hosts`)
- `HostKeyVerifier` trait (TOFU/Strict/Off)
- Per-(profile, node) connection pool with semaphore concurrency cap
- `exec` (capture) + `exec_stream` (line-by-line callback)

### Added — Tavola Alta features

- **1a.** SSH guest session — `:ssh <vmid>` PTY embedded in ratatui via
  vt100-ctt parser; russh PTY channel; resize forwarding; auto-close
  on remote shell exit; per-guest config block.
- **1b.** Serial console via termproxy WebSocket — `proxxx serial <vmid>`
  with raw-mode terminal, exit chord `Ctrl+] q`, custom rustls verifier
  for `verify_tls=false` profiles.
- **1c.** SPICE / noVNC handoff — `proxxx spice <vmid>` writes a `.vv`
  file (mode 0600 on Unix) and launches `remote-viewer`;
  `proxxx novnc <vmid>` deep-links into the web UI's noVNC console.
- **2.** ISO / cloud-image lifecycle — curated library (Ubuntu 22/24,
  Debian 12, Fedora 39, Alpine 3.19, Rocky 9), server-side download
  via Proxmox `/storage/{s}/download-url` with SHA-256 verification.
  *Refuse-on-None gate*: curated library entries with unpinned sha256
  are blocked from downloading (release-time TODO).
- **3.** PBS browse + restore — read-only REST browse of datastores,
  snapshots, and archive files; full-archive restore via shell-out to
  `proxmox-backup-client` with Ctrl+C signal handling and `kill_on_drop`
  safety net (BLOCKER 2).
- **4.** Hardware passthrough inventory + conflict detector —
  `proxxx hw pci/usb/conflicts`; detects DirectShared and IommuGroupSplit
  conflicts; uses Proxmox API's native `iommugroup` field (no SSH).
- **5.** HA + replication console — `proxxx ha groups/resources/status`,
  `proxxx ha preview --node N` (deterministic failover preview, no
  `pve-ha-manager` reimplementation), `proxxx replication jobs/status`.
- **6.** Live disk move/resize — `proxxx disk move/resize`. Force-enqueue
  invariant in TUI: `Action::MoveDisk`/`ResizeDisk` never emit
  `SideEffect` directly — must go via the Operation Queue.
- **7.** Snapshot tree branching visualizer — `:tree <vmid>` with diff
  view; cycle detection (self/2/3-node) and 1000-deep iterative build
  (no stack overflow on long chains).
- **8.** Alerting & notification routing — `proxxx alerts watch/eval/test`;
  3 closed-enum predicates (`node_offline`, `storage_above`,
  `replication_failing`); 3 channels (Telegram, ntfy.sh, webhook); per
  (rule, target) dedup window.
- **9.** Patching & rolling-reboot orchestrator — `proxxx patch plan/apply`;
  state machine Pending→Refresh→Inventory→Upgrade→Reboot→WaitReboot;
  abort-safe ("never two nodes mid-upgrade"); `RebootPolicy` Auto/Always/Never.
- **10.** ACL/Token/MFA console — `proxxx access acl/users/groups/roles/realms/tfa`,
  `proxxx token create/revoke`, `proxxx perms <user> --node N` (shells
  out to `pveum user permissions` per the architectural review's
  Option A — the Perl code on the node is the authority).

### Architectural blockers v1.0.0 (3/3 closed)

- **BLOCKER 1** — ISO supply-chain hardening: `sha256` is `Option`,
  refuse-on-None gate, all-zero-placeholder invariant test.
- **BLOCKER 2** — PBS restore signal handling: `kill_on_drop(true)` +
  `tokio::signal::ctrl_c()` propagation; verified via smoke test
  (`/bin/sleep 60` + drop handle → `kill -0` returns ESRCH).
- **BLOCKER 3** — Flight-recorder panic hook: idempotent install in
  `main()` covers both TUI and CLI; restores raw mode + alt screen +
  cursor; logs to tracing; `proxxx dev-panic` integration smoke test.

### Bugs fixed

| #  | Bug                                                         | Severity   |
| --:| :---------------------------------------------------------- | :--------- |
| 1  | All LXC ops routed to `/qemu/...`                            | high       |
| 2  | `stop_guest(force=false)` hit `/status/stop` (hard kill)     | high       |
| 3  | `proxxx snapshot` returned `"not yet implemented"`           | medium     |
| 4  | `proxxx search <query>` was missing                          | low (doc)  |
| 5  | `proxxx get` not aliased to `ls`                             | low (doc)  |
| 6  | `proxxx delete <vmid>` was missing                           | low (doc)  |
| 7  | `--secure` flag parsed but not wired to `state.secure_mode` | medium     |
| 8  | "Multi-pane SSH/qm broadcast" mislabeled (uses agent/exec)  | low (doc)  |
| 9  | `Action::MigrateGuest` reducer no-op for direct dispatch     | medium     |

### Architectural code-review verifications

- **ACPI polling event-driven**: per-poll `DataMsg::GuestStatusPolled`
  fires every 3s while the shutdown poller waits up to 60s. Render
  thread is never blocked. Tested via wiremock with real progress
  callback inspection.
- **Snapshot tree cycle/depth**: classifies self-cycles, 2-node,
  3-node, and combined "valid root + disjoint cycle" graphs as
  orphans without panicking. Build is iterative (DFS + bottom-up
  materialization) — verified safe up to 1000-deep chains.
- **Operation queue persistence**: `PersistedQueueEntry` round-trips
  through SQLite (lossless for the 7 supported `PersistedOp` variants);
  dirty-flag flushes once per render tick so the on-disk state is
  always at-least-as-fresh-as the displayed state.

### Code quality (consolidation)

- `cargo clippy --all-targets`: **0 errors**, 0 unused/dead_code warnings.
  Remaining ~540 warnings are pedantic/nursery style suggestions
  (`unreadable_literal`, `module_name_repetitions`, etc.) that don't
  affect correctness.
- `cargo test`: **262 unique tests passing** across 8 binaries:
  142 lib unit + 56 app reducer + 41 api wiremock + 8 hitl + 9 mcp +
  5 pbs wiremock + 1 panic_hook integration smoke.
- Production paths obey the strict deny lints (`unwrap_used`,
  `expect_used`, `panic`, `indexing_slicing`); `#[cfg(test)]` blocks
  are relaxed via `cfg_attr` so test ergonomics stay clean.
- Bin entry refactored: `main.rs` consumes the lib via `proxxx::*`
  rather than re-declaring `mod` for every source file — eliminated
  ~50 spurious "dead code" warnings from duplicate compilation.

### Known limits (declared honestly, NOT regressions)

Highlights:

- ISO library checksums: shipped pinned (5× SHA-256 + 1× SHA-512 for
  Debian) against dated upstream manifests. The refuse-on-`None` gate
  remains as a safety net; the `all_entries_are_pinned` invariant test
  enforces at compile-CI that no future entry can ship without a pin.
- PBS restore Linux-only (no `proxmox-backup-client` for macOS/Windows).
- HA console no full failover simulator (deterministic priority-list
  preview suffices for 95% of cases).
- HW passthrough no VFIO writes (modprobe + initramfs + reboot). Read-only.
- ACL effective-permission debugger via `pveum` shell-out (Option A).
- WebAuthn enrollment from TUI is impossible (browser cert ceremony).
- Disk format conversion + encryption rinviati post-v1.0.
- Alerting: 3 predicates closed enum, no oncall scheduler.
- Serial console TUI integration deferred — CLI-only.
