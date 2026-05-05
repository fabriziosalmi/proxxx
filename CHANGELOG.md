# Changelog

All notable changes are documented here. The project follows this
SemVer contract:

- TUI layout changes are NOT covered (minor).
- CLI commands + exit codes are strictly SemVer.
- `--format json` output is additive-only (removing/renaming fields →
  major bump).
- Config schema is backwards compatible.
- MCP tool registry is append-only.

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
