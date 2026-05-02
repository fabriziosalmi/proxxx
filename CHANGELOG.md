# Changelog

All notable changes are documented here. The project follows the SemVer
contract declared in [bootstrap.md](bootstrap.md) §12.3:

- TUI layout changes are NOT covered (minor).
- CLI commands + exit codes are strictly SemVer.
- `--format json` output is additive-only (removing/renaming fields →
  major bump).
- Config schema is backwards compatible.
- MCP tool registry is append-only.

## [Unreleased]

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

See `features.md` "Tagli onesti" sections per feature for the full list.
Highlights:

- ISO library checksums are `None` until release-time pinning against
  upstream `SHA256SUMS`. Curated downloads refuse until then.
- PBS restore Linux-only (no `proxmox-backup-client` for macOS/Windows).
- HA console no full failover simulator (deterministic priority-list
  preview suffices for 95% of cases).
- HW passthrough no VFIO writes (modprobe + initramfs + reboot). Read-only.
- ACL effective-permission debugger via `pveum` shell-out (Option A).
- WebAuthn enrollment from TUI is impossible (browser cert ceremony).
- Disk format conversion + encryption rinviati post-v1.0.
- Alerting: 3 predicates closed enum, no oncall scheduler.
- Serial console TUI integration deferred — CLI-only.
