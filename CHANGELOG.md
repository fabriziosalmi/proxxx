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

### Added

- **Wizard step 4 now optionally pins per-guest SSH overrides.**
  After the standard `[ssh]` block, the wizard asks "Pin per-guest
  SSH targets now?" and (on yes) loops VMID → host until empty
  VMID. Each pair lands as `[ssh.guests."<vmid>"]` in config.toml.
  Default is no — auto-discovery via QGA covers most cases now;
  the explicit-pin path stays surfaced for the legitimate
  exceptions: agent-less guests, QGA reporting only loopback /
  link-local, or operator preference for a stable DNS name over a
  rotating DHCP IP. Duplicate VMIDs in one session overwrite (with
  a warning) so a typo doesn't get re-typed; non-numeric VMIDs are
  rejected loudly. Round-trip-via-serde test pins that wizard
  output parses back as `ssh.guests` table with the right VMIDs.

### Changed

- **`proxxx ssh <vmid>` now auto-discovers guest IPs via QGA / LXC
  interfaces.** Previously required an explicit
  `[ssh.guests."<vmid>"]` block in config.toml; now falls back to
  asking PVE for the live IPs (QGA `network-get-interfaces` for
  QEMU, `/lxc/{vmid}/interfaces` for LXC) and picks the first
  routable IPv4 (skipping loopback 127.0.0.0/8 and link-local
  169.254.0.0/16). Uses `[ssh].user` / `[ssh].key_path` as
  defaults. Explicit config still wins; the source ("config.toml"
  or "QGA / lxc-interfaces auto-discovery") is echoed before the
  ssh exec so the operator knows which path resolved. Diagnostic-
  rich error chain when both fail (agent off vs. only-loopback
  vs. no [ssh].key_path) so the message tells you what to fix
  rather than just "guest not found". 6 unit tests pin the IP
  selection invariants (loopback skipped, link-local skipped,
  IPv6-only returns None, malformed input rejected).
- **Wizard SSH step now auto-discovers `~/.ssh/` private keys.**
  Previously hardcoded `~/.ssh/id_ed25519` as the default path —
  operators with named keys (`id_ed25519_root`,
  `proxxx_e2e_ed25519`, `id_rsa`) accepted the default, the SSH
  probe failed, the config got written pointing at a path that
  didn't exist. Now the wizard scans `~/.ssh/`, content-checks each
  candidate against `-----BEGIN ... PRIVATE KEY-----` (so `.pub`
  siblings, `known_hosts`, `config`, `authorized_keys`, and random
  files don't pollute the list), and presents a numbered choice
  (OpenSSH-format keys first, then RSA PEM, alphabetical within).
  Falls back to free-form prompt only when no keys are found OR
  HOME is unset. 3 unit tests pin the filter rules + sort order.

### Added

- **`proxxx ssh <vmid>` CLI subcommand.** Opens an interactive SSH
  session into a guest by spawning the system `ssh` (so the
  operator's existing keys, agent, known_hosts, and `~/.ssh/config`
  apply transparently — re-implementing those in russh would be
  incomplete and invisible to muscle memory). Per-guest connection
  details come from `[ssh.guests."<vmid>"]` in config.toml. When
  the block is missing, proxxx prints the exact TOML to paste in
  plus a `proxxx --format json ls guests | jq` recipe to discover
  the guest's IP. `--cmd "<remote-command>"` runs a one-shot
  instead of an interactive shell. Closes a long-standing gap
  where `proxxx ssh 100` was advertised in the docs but unreachable
  at the CLI (existed only inside the TUI's `c` keypress flow).
- **TUI always-visible status footer with contextual keybindings.**
  Bottom row of every view now surfaces 3-9 view-specific bindings
  (`j/k:nav  ↵:detail  s:start  S:stop  r:restart  c:console
  /:search  ?:help  q:back` for the guest list) plus universal
  `?:help  q:back` so a new user always sees how to leave the
  current view. Follows the htop / lazygit / k9s convention; the
  `?` modal stays for the full keymap reference. Input bar
  (Command / InputTag / InputBroadcast) and modal overlays cover
  the footer naturally when active. 7 unit tests pin invariants:
  every top-level view has `?:help`, every view has a quit/back
  binding, GuestList surfaces all four lifecycle keys (s/S/r/c),
  Help mode collapses to "any key dismisses".
- **`proxxx init --interactive` config wizard.** Five-step prompted
  flow that walks a first-time user from "fresh machine" to
  "validated, working `config.toml`". Each input is probed live
  against the cluster before write — anonymous PVE version probe,
  token / password authentication test against
  `/access/permissions`, optional SSH `uname -a` round-trip via
  `ssh -o BatchMode=yes`, optional Telegram `getMe`. A failed probe
  never lands in TOML; the user fixes the wrong field in place.
  Existing config triggers a backup-or-cancel prompt
  (`config.toml.bak.<epoch>`); the new file is written atomically
  with mode 0600 (token / password lives in it). No new dependency
  — uses reqwest + crossterm (already in tree). Pinned by 12 unit
  tests covering token-string parsing, URL normalisation, TOML
  rendering, and round-trip-via-serde so wizard output is
  guaranteed to parse as TOML.

## [0.1.2] — 2026-05-05

### Added

- **SSH layer live tests (`tests/ssh_live.rs`).** Two `#[ignore]`-
  gated tests exercise the SSH layer end-to-end against a real PVE
  node: `ssh_pool_exec_uname_round_trip` (boring smoke — `uname -a`
  pins the russh handshake + channel exec) and
  `ssh_pool_exec_pveum_user_permissions_round_trip` (mirrors the
  `proxxx perms` shell-out path; pins the parse contract by
  asserting `root@pam` is in stdout). The harness builds an
  `SshConfig` from env vars (NOT from the user's `config.toml`) and
  uses a per-process tmp `known_hosts` so the operator's real host
  key store is never touched. Opt in with `PROXXX_E2E_SSH_ENABLE=1`.
- **`setup_demo.sh --with-ssh`.** New flag that adds an SSH
  preflight phase (key file mode 600/400, round-trip `uname -a`
  over `ssh -o BatchMode=yes`, `pveum` reachable on remote PATH)
  before declaring the cluster ready. Read-only by design — never
  deploys keys, never edits the operator's `~/.ssh`.
- **HITL callback replay-attack live test
  (`hitl_callback_replay_rejected_under_live_pve`).** Drives
  `handle_callback_update` twice with an identical `Update` against
  a real `PxClient` (operator persona) + a wiremock Telegram
  stand-in; pins `CallbackOutcome::Replay` on the second call and
  `pending.consumed_count() == 1`. Pure-logic dedup is already
  unit-tested; this test pins the contract under realistic
  live-PVE wiring. Side-effect-free — uses the sentinel
  `BLIND_VMID` so the first call lands at `NodeNotFound` rather
  than restarting a real VM. `#[ignore]`-gated; opt in with
  `PROXXX_E2E_RBAC_ENABLE=1` and persona tokens.
- **Alert daemon dedup persistence (cache schema 1 → 2).** `alerts
  watch` now persists the `(rule, target) → last_fired` window to
  the SQLite cache after each tick (and at graceful shutdown), and
  reloads it on startup. Without this, a routine daemon restart
  (config reload, kernel update, accidental SIGHUP) re-fired every
  active alert immediately — a single restart could flood Telegram
  with 50 duplicate notices for problems the operator had already
  seen and acknowledged. Best-effort: a missing/corrupt cache
  yields an empty state rather than failing the daemon. Schema
  bump pinned by a 1 → 2 migration regression test plus an
  end-to-end round-trip test.
- **MCP per-tool execution timeout (DoS guard).** Each `ToolDef`
  carries a `timeout_secs` budget; the JSON-RPC `tools/call`
  dispatch wraps `handle_tool_call` in `tokio::time::timeout`. On
  expiry the request returns server-defined error code `-32001` with
  the budget in the message; the request loop continues. Without
  this, a single hung call (storage lock, network stall, upstream
  PVE wedged) would block every subsequent JSON-RPC line — stdio is
  serialized. Read-only tools get 30 s; lifecycle ops 60 s; snapshot
  ops 120 s; `delete_guest` 180 s to accommodate the 120 s HITL
  Telegram round-trip plus the actual delete. Budget is also
  serialized into `proxxx mcp tools --json` for external audit.

## [0.1.1]

Documentation patch release. No functional changes; no API surface
shift; no `--format json` schema change. Two doc-only edits prompted
by an external review pass:

- **Default `verify_tls = true`** in the starter config written by
  `proxxx init`. Operators with self-signed homelab clusters now opt
  out explicitly with `verify_tls = false`. Inline comment in the
  generated `config.toml` warns that disabling TLS verification
  exposes the full API + WebSocket traffic (incl. serial-console
  tickets) to MITM. Existing config files are unaffected — this only
  changes what `proxxx init` writes for new installs.
- **PBS restore caveat clarified** in `docs/integrations/pbs.md`. The
  prior wording said `kill_on_drop` "cleans up the stale download" —
  inaccurate. SIGKILL stops the `proxmox-backup-client` child
  immediately (good — bandwidth + I/O bounded) but bypasses
  upstream's own cleanup. Partial archive files (`*.pxar`,
  `*.img.fidx`, chunk-store working files) **may remain in the
  target directory** after a kill. Doc now states that explicitly +
  recommends treating the target dir as untrusted after an
  interrupted restore.

## [0.1.0]

First public release. proxxx 0.1.0 ships as a single static binary
with a CLI, a TUI, an MCP server, an alert daemon, and a HITL daemon
in the same executable. PVE API map coverage: 163 of 190 endpoints
(85%); the remaining 27 are documented design boundaries (Ceph
cluster writes, SDN config writes, browser-only auth flows).

### Talking to the cluster

- **PVE REST client** with typed `ApiError` (8 categorical variants),
  reqwest + rustls, 32 MiB body cap, per-profile rate limiter
  (`governor`).
- **PBS REST client** for read-only browse (datastores, snapshots,
  archive metadata) plus shell-out to `proxmox-backup-client restore`
  with `kill_on_drop` supervision and `tokio::signal::ctrl_c`
  propagation.
- **SSH layer** (`russh`, publickey only) for the paths PVE doesn't
  expose over REST: patch apply, `proxxx perms` shell-out to
  `pveum user permissions`, per-guest interactive sessions. TOFU
  `known_hosts` is dedicated (separate from `~/.ssh/known_hosts`).
- **WebSocket termproxy** for serial console, custom rustls verifier
  for `verify_tls = false` profiles, raw-mode terminal with `Ctrl+] q`
  exit chord.
- **Local console handoff** — SPICE (`.vv` mode 0600 with `O_EXCL`
  + 128-bit random suffix; launches `remote-viewer`), noVNC (system
  browser; never embeds the auth ticket in the URL).

### Operational surface

- **65 top-level CLI subcommands**. Stable exit codes (`0` ok, `1`
  runtime, `2` argparse, `3` HITL denied, `4` precondition refused).
  `--format json | table | plain`.
- **18 TUI views** under one Elm-pattern reducer (sync, total, async-
  free). Vim keys, fuzzy search across the cluster (`/`), command
  palette (`:`), quick-open (`Ctrl+K`), bulk ops with multi-select.
- **Operation queue** with dry-run, diff preview, and replay-as-
  script export (proxxx CLI / pvesh / curl / Ansible).
- **SQLite-backed time-travel cache** — `proxxx replay <timestamp>`
  reconstructs the cluster as it looked at any past moment.
- **MCP server** — stdio JSON-RPC for LLM agents. 10-tool registry
  is compile-time fixed and SHA-256 pinned via
  `proxxx mcp tools --checksum`.

### Pre-flight risk gate

Every destructive op routes through 11 risk variants — `Locked`,
`Running`, `LongUptime`, `TaggedProd`, `ActiveNetTraffic`, `HaManaged`,
`HasManySnapshots`, `BackupAgeWarning`, `NoBackupFound`,
`ListeningOnService`, `DeepCheckSkipped` — with per-op weighting.
`Severe` refuses without `--allow-risk`; `Notice` and `Warning`
print and proceed. Operator owns the override.

### HITL approval gate

Real Telegram round-trip via `HitlCoordinator` and a single shared
`getUpdates` poller. Deny on 120 s timeout, deny when Telegram is
unconfigured but a policy matched. Policy-driven by tag / vmid /
wildcard with multi-approver support (`require = N`).

### Security hardening

- All secrets (token, ticket, CSRF, password, PBS token) live in
  `Zeroizing<String>` — `Drop` overwrites the heap allocation.
- 32 MiB body cap on every API response (no OOM via hostile JSON).
- `cargo clippy --deny unwrap_used --deny expect_used --deny panic
  --deny indexing_slicing --deny await_holding_lock` in production
  code. Tests are relaxed via `cfg_attr(test, allow(...))`.
- TOFU `known_hosts` for SSH; `HostKeyVerifier` trait
  (`TOFU` / `Strict` / `Off`).
- TOCTOU-safe SPICE handoff (`tempfile` + `O_EXCL` + 128-bit random
  suffix + mode 0600).
- Shell-injection-safe `pveum` invocation: 3 layers of defence
  (metachar refusal + `shell_quote` + `--` separator), tested with
  `'; touch /tmp/pwned`, `$(rm -rf /)`, backticks, pipes, semicolons,
  newlines.
- `cargo audit --deny warnings` runs as gate stage 3 + nightly cron
  in CI. Documented advisory ignores live in `.cargo/audit.toml`
  with crate, dependency path, threat model, and remediation.
- Compile-time-fixed MCP tool registry — no runtime registration
  path; an attacker controlling the config file cannot inject tools.
- Pre-flight risk gate refuses destructive ops on running guests
  without `--allow-risk`.

### Quality gate

Six stages, run as both a pre-commit hook and the CI contract:

1. `cargo fmt --check`
2. `cargo clippy --release --all-targets` (deny tier)
3. `cargo audit --deny warnings`
4. `cargo test --release --all-targets` (lib unit + wiremock + TUI
   snapshot + integration)
5. 88 read-only probes against a live PVE cluster
6. Full mutation lifecycle (LXC create → start → snapshot → stop →
   delete, plus cluster-level CRUD across pool, firewall-cluster
   alias / group / ipset, backup-jobs, notifications endpoint +
   matcher, storage-defs; QEMU 9998 from an alpine ISO; opt-in QGA
   agent-required round-trips via `PROXXX_E2E_QGA_VMID=<vmid>`)

The matrix at `pre-commit/01-feature-coverage.md` distinguishes
*implemented* from *verified end-to-end live* row by row.

### Known limits

See `## Honest non-goals` in [`README.md`](README.md) for the full
list of design boundaries. Highlights:

- ISO library checksums are pinned (5× SHA-256, 1× SHA-512 for
  Debian) against dated upstream manifests; the `all_entries_are_
  pinned` invariant test enforces at every `cargo test` that no
  future entry can ship with `checksum: None`.
- PBS restore is Linux-only (no `proxmox-backup-client` for macOS /
  Windows upstream).
- HA console has no full failover simulator; the deterministic
  priority-list preview suffices for the common case.
- Hardware-passthrough mapping is read-only (no VFIO writes —
  modprobe + initramfs + reboot territory, out of scope).
- Effective-permissions resolution shells out to `pveum user
  permissions` (`proxxx perms`) since the Perl evaluator on the
  node is canonical. The API-side `proxxx access permissions` is
  also available — same typed tree from `/access/permissions`,
  no SSH dependency — for the common case where the evaluator's
  full grant-tree expansion isn't needed.
- WebAuthn enrolment from the TUI is impossible (browser cert
  ceremony). proxxx exposes the API-driven primitives (token CRUD,
  password change, ACL editing) but stays out of `/access/openid/*`
  and `/access/tfa/u2f`.
- Snapshot rollback is intentionally not exposed — the TUI shows a
  read-only rollback impact preview; the destructive trigger runs
  through `qm rollback` / `pct rollback` or the PVE web UI by
  design.
