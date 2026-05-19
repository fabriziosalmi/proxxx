# Changelog

All notable changes are documented here. The project follows this
SemVer contract:

- TUI layout changes are NOT covered (minor).
- CLI commands + exit codes are strictly SemVer.
- `--format json` output is additive-only (removing/renaming fields →
  major bump).
- Config schema is backwards compatible.
- MCP tool registry is append-only.

## [Unreleased] — v0.1.28

### Added
- **Shell completions** — `proxxx completions {bash|zsh|fish|powershell}` prints the shell
  completion script to stdout; pipe to your shell's completions dir.
- **`proxxx doctor`** — self-diagnostic: validates config, cluster connectivity, auth,
  Telegram HITL, PBS, SSH key, and audit log in one pass. Exits 0 if all critical
  checks pass, 1 otherwise. Pipeline-friendly JSON output.
- **Audit log v2** — SQLite append-only log with per-entry HMAC-SHA256 chain.
  New subcommand `proxxx audit {log,export,verify}`:
  - `log` — show recent entries (filterable by time, default 50)
  - `export` — dump to JSON or CSV for SIEM ingestion
  - `verify` — walk the full chain and check every HMAC (NIS2/ISO27001 alignment)
- **`proxxx vm create`** — create a new QEMU VM from scratch (node, vmid, name,
  memory, cores, disk, iso, ostype, bridge). VMID auto-assigned if omitted.
- **`proxxx ct create`** — create a new LXC container (node, vmid, hostname,
  template, memory, cores, rootfs, bridge, password). VMID auto-assigned if omitted.
- **MCP tool `create_guest`** (tool #23) — LLM-callable guest creation for both
  QEMU and LXC; node, type, name, memory, cores, storage, disk_size, template/iso,
  bridge. Registry SHA-256 updated; counter 22→23.
- **Real-time event stream** — `proxxx events stream` polls cluster task
  queues and prints new task starts/completions as they appear (STARTED /
  DONE / FAIL). Supports `--node`, `--type`, `--vmid` filters, `--interval`
  (default 2 s), and `--format json` for NDJSON piping. Shows currently-running
  tasks at startup; `--no-existing` skips the snapshot.
- **MCP tool `list_cluster_events`** (tool #24) — returns recent cluster-wide
  task events with elapsed time; `limit` (default 50) and `running_only` params.
- **Config hot-reload** — `SIGHUP` atomically swaps the live config in the
  `alerts watch`, `mcp serve`, and `mcp serve-http` daemons. After `kill -HUP
  $(pgrep proxxx)`, the next tick/request picks up new `[[alerts]]` rules,
  `[[policies]]`, `[telegram]` structure, and `mcp_token` without restarting.
  Fields baked into `PxClient` at startup (`url`, `user`, `token_id`,
  `token_secret`) and Telegram bot credentials require a full restart. The
  `ConfigHandle` (`Arc<RwLock<ProfileConfig>>`) is re-exported from
  `crate::config` for downstream use.
- **MCP schema type validation** — `dispatch_rpc` now validates every param
  against its declared `ParamType` (Int/Bool/Str) and returns a clear error
  (`"Parameter 'guest_id': expected integer, got \"abc\""`) rather than
  silently misrouting the value.
- **EU & compliance section** in README — NIS2/ISO 27001/GDPR alignment table.
- **Cloud-init clone** — `proxxx clone <src> --cloud-init-user <file.toml>`
  parses a TOML profile (ciuser, cipassword, sshkey/sshkey_file, ipconfig0,
  searchdomain, nameserver), waits for the clone task to land, then applies
  the cloud-init fields and regenerates the drive. Canonical IaC pattern in
  one command — no more clone → set → regen dance.
- **MCP tool `clone_with_cloudinit`** (tool #25) — same flow callable by LLMs
  with inline params (no file). QEMU-only; LXC is rejected explicitly.
  Registry SHA-256 updated; counter 24→25.

## [0.1.27] — 2026-05-14

Headline: **draconian TUI polish** — the rendered surface is now native
ASCII / sentence-case throughout, no emoji, fewer borders, smaller
palette. No behaviour, CLI, MCP, or config-schema changes.

### Changed — TUI only

- **Glyph purge** (`refactor(tui): glyph purge`). Removed every emoji
  from rendered surfaces: status icons (🟢🔴🟡⏳⏰), title decoration
  (⚡📝🕒🛡️💾🖥🚀), banner glyphs (⚠️🚨), modal "⚠️ WARNING" header.
  Status carries via row color + the status word column. Telegram
  callback strings retain emoji (different audience, not TUI surface).

- **Separators unified**. Footer drops `│` after the mode pill and uses
  `·` only. View titles drop inline `│` between header spans (use
  whitespace). Arrows `↵ ← → ↑ ↓` replaced with keyboard letters
  (`Enter`, `h/l`) or ASCII (`->`). snaptree's `│  ` tree-drawing
  lines kept (semantic).

- **Progress bars consolidated**. Sub-block precision glyphs
  (`▏▎▍▌▋▊▉`) duplicated in guests + storage collapsed to full-block
  + light-shade `█░` (matches nodes.rs). Input-bar fake cursor `█`
  now a `Modifier::REVERSED` space — the terminal's native cursor look.

- **Color palette: 18 → 13** (`refactor(tui): palette diet`). Removed
  `ACCENT_DIM` (unused). Collapsed `ONLINE / OFFLINE / STALE / PAUSED`
  onto `SUCCESS / DANGER / WARNING / INFO` (purple paused → blue, since
  paused is an intentional state, not a warning). Removed
  `GAUGE_LOW / MED / HIGH` (triple-aliased SUCCESS / WARNING / DANGER).
  `status_badge()` and `gauge_color()` reference semantic colors
  directly. 9 callsites in guests / approval / tasks migrated.

- **Density pass** (`refactor(tui): density pass`). ha_console's 4
  stacked sections each wrapped in `Borders::ALL` (box-of-boxes feel)
  now use `Borders::TOP` only — single underlined title line per
  section. Reclaims ~6 vertical rows + ~80 char columns of border
  chrome on a 100-col terminal. Input bar: `Length(3) + Borders::ALL`
  → `Length(2) + Borders::TOP` (the prompt prefix `/` `:` already
  carries the mode signal).

- **Text discipline** (`refactor(tui): text discipline`). Lowercased
  all user-visible labels — table column headers (VMID → vmid),
  status badges (HEALTHY / STALE / FAILING / QUORATE / NO QUORUM /
  STUCK / DEGRADED / UNPROTECTED / DIRECT / CREATED / DELETED →
  lowercase), mode pill labels (NORMAL / SEARCH / CONFIG GREP →
  lowercase). Color still carries severity. External Proxmox output
  ("TASK OK", "ERROR", "FAILED") and log/warn! lines untouched.

### Test surface

- 13 TUI snapshot tests regenerated to match the polished rendering.
  4 `dump.contains(...)` assertions updated for the new sentence-case
  strings. All 22 snapshot tests + 355 lib tests + 224 integration
  tests pass.

### SemVer note

Per `CHANGELOG.md` SemVer contract, TUI layout changes are explicitly
NOT covered. This release is therefore a patch bump despite the broad
visual change — no CLI command, exit code, `--format json` field, MCP
tool, or config schema was touched.

## [0.1.26] — 2026-05-14

Headline release: **MCP registry expands 10 → 23 tools**, Streamable HTTP
transport, multi-profile TUI switching, Prometheus exporter, batch
execution policies, full audit campaign sweep (HIGH + MEDIUM + LOW), and
the README hero asset rebuilt from scratch.

### Added — MCP surface expansion

- **MCP tool registry: 10 → 23 tools** (`feat(mcp): expand tool registry
  10 → 22 tools`). New tools: `suspend_guest`, `resume_guest`,
  `clone_guest`, `migrate_guest`, `get_cluster_status`, `list_tasks`,
  `get_node_status`, `list_backup_jobs`, `get_replication_status`, plus
  registry-completeness fixes for `list_snapshots`, `get_task_log`,
  `get_node_resources` (which had `ToolAction` variants but no
  `ToolDef`). Registry remains compile-time-fixed and SHA-256 pinned;
  fetch the new checksum via `proxxx mcp tools --checksum`. **The
  append-only SemVer promise is honoured** — no tool was renamed or
  removed.

- **Streamable HTTP transport for MCP** (`feat(mcp): add Streamable HTTP
  transport — POST /mcp + GET /mcp SSE`). Opt-in via
  `proxxx mcp serve --transport http --bind 127.0.0.1:8080`. Stdio
  remains the default (no behaviour change for existing Claude Code /
  Cursor integrations). Unlocks remote LLM agents and multi-tenant
  deployments without the per-call fork/exec cost of stdio.

### Added — operational surface

- **Multi-profile TUI switching** (`feat(tui): multi-profile support`).
  `Tab` cycles between configured clusters without restarting the
  binary. Cached state is now segregated per profile — see RBAC row 108
  test below.

- **Prometheus exporter** (`feat(metrics): proxxx metrics serve`).
  Exposes guest CPU / memory / disk + node + storage metrics in the
  Prometheus text format on a configurable port. Cardinality-bounded
  labels (`vmid`, `name`, `node`, `storage`); designed for Grafana
  scraping at sub-30 s intervals.

- **Batch execution policies — canary + rolling** (`feat(batch): canary
  + rolling execution policies for multi-guest ops`).
  `--policy canary=N%` runs the first percentile, waits an observation
  window, then continues only if no errors. `--policy rolling=N` caps
  concurrency. Replaces the previous all-at-once behaviour for
  `batch stop` / `batch restart`. Pilot count uses ceiling division
  (`min(n, max(1, ceil(n·p)))`) — see `canary_pilot_count` for the
  exact contract.

- **PBS typed auth errors + `pbs ping` command** (`feat(pbs): typed auth
  errors + pbs ping command`). Auth failures now surface as
  `AuthFailed` rather than generic `RequestFailed`, so callers can
  match on error category instead of grepping prose.

- **TUI blind-persona hardening** (`feat(tui): blind-persona hardening
  — surface guest fetch errors in VM list`). When a guest fetch fails
  (typically RBAC blocking `/nodes/X/qemu`), the VM list now surfaces
  the per-node error inline instead of silently dropping the row.
  Operators with restricted permissions can now SEE what they cannot
  see — closes a long-standing footgun.

### Fixed — draconian audit campaign

- **HIGH findings** (`fix(audit): HIGH findings`). Seven correctness
  fixes: batch policy parser rejected `canary=10%`, `find_guest`
  accepted ambiguous cross-node matches, JoinError in the retry path
  was silently swallowed, the HITL approval gate could double-fire
  under a tight race, `clone_guest` was incorrectly classified
  non-destructive (allowed an LLM agent to clone without HITL),
  sensitive config fields (`token_secret`, `password`, PBS
  `token_secret`) are now wrapped in `Zeroizing<String>` and
  zero-on-drop, and the Prometheus exporter called `get_nodes()` once
  per metric kind instead of once per scrape.

- **MEDIUM findings** (`fix(audit): MEDIUM findings`). Six fixes: the
  `watch` subcommand had no timeout cap (now `--timeout 300s` default
  with `<` / `>` comparator parsing); cache directory was not created
  on first run for non-state callers; SSH `--cmd` arg now rejects NUL
  / CR / LF (command-injection prevention); `poll_task_until_done`
  honoured `timeout_secs=0` as "poll forever" (now capped at
  `DEFAULT_TASK_TIMEOUT_SECS=3600`); `escape_label` did not escape
  `\r` (Prometheus label-injection vector closed); `idle_client()`
  test helper now returns the `MockServer` so it cannot be
  drop-killed mid-test (RBAC E2E flake source).

- **LOW findings**. Clock-before-UNIX-epoch now surfaces a typed error
  instead of silently saturating with `unwrap_or_default()`; alert-dedup
  persistence assertions use `assert_eq!(count, 1, …)` instead of the
  weaker `>= 1`.

- **MCP correctness** (`fix(mcp): 3 correctness issues from draconian
  audit`). `action_str` dropped the suffix on multi-word tool names
  (so audit logs showed `stop` instead of `stop_guest`); `clone_guest`
  was incorrectly classified non-destructive; registry checksum test
  was pinned to a stale SHA.

- **Cache directory creation moved into `open_db`** (`fix(cache):
  ensure_cache_dir in open_db — covers all callers, not just
  save_state`). The original audit fix had `ensure_cache_dir()` only
  in `load_state` / `save_state`. CI revealed
  `alert_dedup_persistence_round_trip` failed on clean runners because
  `save_alert_dedup` (and four other callers) did not call it.
  `create_dir_all` now lives in `open_db` itself, so the invariant
  holds for every SQLite opener — no future caller can forget.

- **Shutdown daemon-saturation, follow-up** — see also v0.1.25.

### Security

- **OpenSSF Scorecard `TokenPermissions` alerts**
  (`ci: add explicit permissions`). Both `.github/workflows/ci.yml`
  and `.github/workflows/release.yml` now declare minimal top-level
  `permissions: contents: read`, with `release.yml` explicitly
  elevating only the `release` job to `contents: write, id-token:
  write`. Scorecard `TokenPermissions` score moves from 0 → 10.

### Tests

- **RBAC cache segregation per-profile** (`test(rbac): cache
  segregation per-profile — closes row 108`). The multi-profile TUI
  switching above (the feature) is paired with the test that pins the
  contract: a switch between two profiles does not leak cached cluster
  state between them. Row 108 of the RBAC test matrix now passes.

### Documentation

- **README hero asset rebuilt from scratch.** The AI-generated
  `assets/proxxx-overview.jpg` is gone; in its place is
  `assets/demo.svg` — a 13 KB animated SVG storyboard generated by
  [firstframe](https://github.com/fabriziosalmi/firstframe) (a small
  companion tool that produces beat-based animated terminal demos
  from TOML manifests). The demo types a destructive command,
  the pre-flight risk gate refuses it, HITL approval arrives via
  Telegram, the action executes. Same SVG is the VitePress home hero.
  Respects `prefers-reduced-motion`.

- README + `docs/index.md` numbers refreshed: source 28 → 44 KLOC,
  tests 5 → 14 KLOC, MCP tool registry 10 → 23 tools.

## [0.1.25] — 2026-05-13

### Fixed — shutdown daemon-saturation

- **`shutdown_guest` did not pass a timeout to PVE**, so any guest
  that did not respond to ACPI (or had a stuck init) would leave the
  `qmshutdown` task appended indefinitely on the node — saturating
  `pvedaemon` worker threads. Observed in production as a node-level
  hardware freeze requiring a manual reset.

  `shutdown_guest` now takes `timeout_secs` (default 60 at every call
  site) and forwards both `timeout=N` and `forceStop=1` to PVE for
  QEMU (PVE rejects `forceStop` for LXC, so only `timeout=N` is sent
  there). CLI gains `--stop-timeout <secs>`; ignored with `--force`.
  Three wiremock tests assert per-guest-type body params.

## [0.1.24] — 2026-05-13

### Added — `snapshot rollback`

- **`proxxx snapshot rollback --vmid N --name S --yes`** rolls a
  guest back to a named snapshot via
  `POST .../snapshot/{name}/rollback`. Trait method, `PxClient` impl,
  mock stubs (`patch.rs` + `hitl_e2e.rs`), and two wiremock routing
  tests (QEMU + LXC, with a negative guard on wrong guest type)
  included. Map-coverage snapshot updated.

### Fixed — live RBAC test failures

- Six live RBAC E2E tests were flaking intermittently; root cause was
  test-side HITL callback signing using the wrong HMAC key when the
  runner had `PROXXX_HITL_SECRET` set globally. Tests now sign with
  the per-test ephemeral key — no production code change.

## [0.1.23] — 2026-05-12

### Fixed — password-auth credential rotation + auth-failure UX

- **`resolve_password()` had the resolution order BACKWARDS.** The
  helper checked the inline `password =` value in config.toml
  FIRST, then `PROXXX_PASSWORD` env, then keychain. So any profile
  with a hand-edited inline password silently ignored the env-var
  rotation path — `PROXXX_PASSWORD=new` would NEVER take effect
  unless the operator first edited config.toml to remove the
  inline value. This was inconsistent with `resolve_token_secret`,
  which has always put env > inline.

  Flipped to **env > inline > keychain**. Same hierarchy as
  token-secret; matches the long-standing "env always wins"
  promise in `docs/guide/secrets.md`.

  Operator-visible behaviour change: a profile with BOTH inline
  `password =` AND `$PROXXX_PASSWORD` set will now use the env
  value. If you were intentionally relying on the inline value
  while having a stale env var set, unset the env var.

- **Password-auth 401 surfaced as "Failed to parse auth response"
  instead of "401 Unauthorized".** `AuthMethod::login` called
  `.json()` directly on PVE's response without checking the
  status code first. When the credentials were wrong, PVE
  returned 401 with a JSON body that didn't match
  `TicketResponse`, so the visible error was a parse failure —
  burying the actual cause and silently breaking any caller
  grepping for "401" / "Unauthorized".

  `login` now reads `resp.status()` first and bails with a
  proper "Authentication failed: 401 Unauthorized from <url>
  — <body snippet>" error, capped to 1 KiB of body so a hostile
  server can't OOM the auth path.

### Fixed — E2E test flakiness on clean cluster runs

- **`e2e_alpha` (CRUD lifecycle) timed out 60s every clean run.**
  PVE returns `500 "Configuration file 'nodes/X/lxc/N.conf' does
  not exist"` (NOT 404) on `/status/current` for a deleted LXC.
  Two poll loops in the test+harness classified that as transient
  and retried until timeout: the in-test step-6 "guest 404s after
  CLI delete" poll and the RAII teardown's "guest reaches stopped"
  poll.

  Both now recognise the PVE quirk via a new helper
  `pve_error_is_gone(&err)` that matches the literal substring
  pattern PVE actually emits (case-insensitive `"does not exist"`
  alongside the existing `"404"` / `"not found"` checks). Added
  a `guest_is_gone()` fast-path to `TestResourceGuard` so the
  whole stop+poll+delete dance is skipped when the test has
  already removed the guest.

- **`e2e_beta::beta_bad_token_surfaces_401_cleanly`** assumed the
  local config.toml uses token-auth and only overrode
  `PROXXX_TOKEN_SECRET`. On password-auth configs the env-override
  was a no-op (compounded by the resolve_password bug above) so
  proxxx silently authenticated with the REAL password and the
  test failed the "must exit non-zero" assertion. Now overrides
  both `PROXXX_TOKEN_SECRET` AND `PROXXX_PASSWORD` so either
  auth path lands a 401.

### Internal

- `pve_error_is_gone` + `guest_is_gone` helpers added to
  [`tests/common/mod.rs`](tests/common/mod.rs) — reusable by any
  future E2E test that needs to detect deleted-guest state.
- 2 E2E tests now green that were pre-existingly broken on the
  local cluster fixture; no other test changes.
- Live gate (87 read + 47 mutation probes) green on every commit.

## [0.1.22] — 2026-05-12

### Breaking — HITL callbacks must now be HMAC-signed

- **The v0.1.21 backward-compat shim is gone.** Unsigned callbacks
  (anything without a trailing `:<16-hex-char-tag>`) are refused
  outright by both the standalone daemon (`proxxx hitl serve`) and
  the in-process TUI poller. This was the explicit promise in
  v0.1.21's CHANGELOG and in the test name
  `legacy_unsigned_callback_still_accepted_in_v0_1_21`.

- Refusal surface:
  - Daemon: returns `CallbackOutcome::InvalidFormat`, answers the
    user with `"❌ Unsigned callback refused — daemon upgrade needed"`,
    no PVE-side mutation attempted.
  - TUI poller: drops the callback, answers
    `"❌ Unsigned callback refused — TUI upgrade needed"`,
    `coord.resolve` is not called so any pending approval stays
    in flight (the operator can re-issue after restart).
  - Inverted test `legacy_unsigned_callback_is_refused_in_v0_1_22`
    pins the contract; also asserts the refused txn does NOT
    consume the replay-protection slot (a re-signed retry of the
    same txn must not falsely 401 as replay).

### Upgrade path

- v0.1.21 → v0.1.22: restart the HITL daemon (or the TUI) so the
  next `request_approval` mints a freshly-signed inline keyboard.
  Approvals issued under v0.1.21-or-earlier daemons that haven't
  been clicked yet will be refused — the operator must re-trigger
  the destructive op so a new signed prompt is generated.
- Skipping v0.1.21 entirely (v0.1.20 → v0.1.22 direct): same as
  above. The HMAC key auto-bootstraps at
  `<config_dir>/telegram_hmac.key` on first start.

### Internal

- 4 pre-existing tests (`replay_callback_does_not_re_execute`,
  `pve_403_during_execute_surfaces_as_failure`,
  `deny_callback_does_not_invoke_gateway`,
  `fast_op_skips_intermediate_executing_edit`) constructed callbacks
  by hand without a tag and silently passed under the v0.1.21 shim.
  All now build their callback via the new `signed(key, payload)`
  helper that mirrors what `request_approval` emits at runtime.
- The `Replay.txn_id` assertion in
  `replay_callback_does_not_re_execute` now matches the full signed
  string (tag included) since that's what the dedup engine keys off.
- 12 hitl_e2e tests pass; no production change beyond the two
  parser sites (daemon + TUI poller).

## [0.1.21] — 2026-05-12

### Added — HMAC-signed HITL callback_data (defence-in-depth against bot-token leak)

- **Before this release, HITL callback authentication was a single layer:
  the TLS channel to `api.telegram.org` plus the secrecy of the bot
  token.** If the bot token leaked (env-var dump, log scrape,
  supply-chain compromise of a deploy step), an attacker could:
  1. Send arbitrary messages from the bot, including a freshly-forged
     inline keyboard whose `callback_data` is `approve:delete:9001`.
  2. Coerce or social-engineer any chat member into clicking it.
  3. The proxxx HITL poller — TUI in-process or `proxxx hitl serve`
     standalone — happily dispatches the PVE-side delete because the
     callback parsed cleanly.

  Real-CA TLS doesn't help: the attacker is sending messages **through**
  the legitimate Telegram bot, not impersonating the server.

- New module `hitl::hmac_key`:
  - `load_or_generate_hmac_key()` auto-bootstraps a 32-byte random
    key at `<config_dir>/telegram_hmac.key` (mode 0600 on Unix,
    atomic temp+rename write). Same `directories::ProjectDirs`
    layout as the TLS-pin file from v0.1.17.
  - `sign(key, payload)` → 16-hex-char truncated HMAC-SHA256 tag
    (8 raw bytes = 64-bit forgery resistance, fits comfortably in
    Telegram's 64-byte `callback_data` cap).
  - `verify(key, payload, tag)` → constant-time check via
    `Hmac::verify_truncated_left`, fails-closed on bad hex / wrong
    length / signing key mismatch.

- Send side: `TelegramGateway::request_approval` now appends `:<tag>`
  to both the Approve and Deny `callback_data`. The receive side in
  BOTH `daemon::handle_callback_update` (used by `proxxx hitl serve`)
  AND `tui::run_hitl_poller` (used in-process by the TUI) peels the
  tag off and verifies before dispatching.

### Backward compatibility

- Callbacks issued by v0.1.20-or-earlier daemons have no tag. v0.1.21
  accepts them with a structured `warn!(target: "hitl.legacy_unsigned", ...)`
  log — so an operator running the rollout can grep for sustained
  unsigned traffic before flipping the toggle. **v0.1.22 will refuse
  unsigned callbacks** — the contract change is staged so in-flight
  approvals at upgrade time still resolve cleanly.

### Internal

- New direct deps: `hmac = "0.12"` and `getrandom = "0.2"` (both were
  already transitive via `rustls`/`tokio-rustls`; promoted to direct
  so the call sites are grep-able).
- 10 new unit tests in [`src/hitl/hmac_key.rs::tests`](src/hitl/hmac_key.rs):
  - `sign_is_deterministic_for_same_payload`
  - `sign_changes_with_payload`
  - `sign_changes_with_key`
  - `verify_accepts_own_signature`
  - `verify_rejects_tampered_payload`
  - `verify_rejects_tampered_tag`
  - `verify_rejects_wrong_length_tag`
  - `verify_rejects_non_hex_tag`
  - `verify_rejects_with_wrong_key` — the bot-token-leak defence
  - `telegram_callback_data_budget_holds` — locks the 64-byte cap
- 4 new integration tests in [`tests/hitl_e2e.rs`](tests/hitl_e2e.rs):
  - `signed_callback_with_valid_tag_executes`
  - `callback_with_tampered_tag_is_refused`
  - `callback_signed_with_wrong_key_is_refused`
  - `legacy_unsigned_callback_still_accepted_in_v0_1_21`
    (test name itself documents the v0.1.22 inversion point)

## [0.1.20] — 2026-05-12

### Fixed — snapshot tests now enforce content, not just layout

- **TUI snapshot tests in `tests/tui_snapshot.rs` were layout-only.**
  `insta::assert_snapshot!(dump)` catches "anything visible changed"
  but the de-facto regression workflow is `cargo insta review` →
  accept all → commit. A test named
  `dashboard_with_two_nodes_aggregates_correctly` could silently
  lock in a snapshot where one node had silently dropped out, as
  long as the layout still rendered.

- Added per-test `assert!(dump.contains(...))` semantic anchors on
  top of every snapshot call. The two layers complement each other:
  the snapshot still catches layout shifts; the explicit asserts
  catch data-flow regressions that `cargo insta accept` would
  otherwise hide.

  Per-test contract:

  - `help_overlay_renders_keymap` — title `"Help"`, `"Navigation"`
    section header, `"quit"` binding documented.
  - `dashboard_empty_cluster_does_not_panic_and_shows_idle_state`
    — must show `"Loading"` hint (the "idle state" the test name
    promises) and the `"0 nodes"` header.
  - `dashboard_with_two_nodes_aggregates_correctly` — both node
    names + the `"1/2 guests"` aggregate header.
  - `guests_table_with_mixed_status` — both `"running"` +
    `"stopped"` statuses, all four vmids (100/101/200/999), and
    crucially **no raw `\u{1b}` ESC byte** (the Phase 5.13
    ANSI-injection invariant — a snapshot can't safely enforce
    "no ESC in dump" because a reviewer scanning a unicode diff
    won't spot a U+001B).
  - `compare_view_with_two_selected_guests` — both guest names +
    `"(2 guests)"` panel header.
  - `nodes_view_with_quorum_and_stale_stats_badges` — both node
    names + `"(2 total)"` header.
  - `ssh_session_with_pty_content` — pty content (`"alpine"`,
    `"uname"`) renders through the parser.
  - Empty-state hints pinned: `"No pending approvals"`,
    `"No guests to monitor"` (backup + heatmap), `"Queue is empty"`,
    `"No snapshot data"`, `"Loading storage"`, `"Waiting for logs"`,
    `"No data for this snapshot"`.
  - `tasks_view_empty_state` also pins the `"UPID:test"` prefix —
    the UPID is the only forensic anchor between a log view and the
    task that triggered it; a refactor that "cleans up" the header
    by truncating it must break this test.

### Internal

- All 22 snapshot tests pass with the added asserts against the
  existing accepted snapshots — no snapshot regeneration needed.
- No production code changes.

## [0.1.19] — 2026-05-11

### Fixed — typed `ConfigError` wired to exit code 3

- **Config-load failures now exit `3` ("Configuration error") as
  `docs/reference/exit-codes.md` has promised since v0.1.10.** Before
  this release every config-load failure (file missing, IO error,
  malformed TOML, missing required field) became an opaque
  `anyhow::Error` that landed in main.rs's catch-all and exited `1`.
  Scripts written against the documented contract (`case $? in 3) ...`)
  silently never matched.

- New `config::ConfigError` enum with three variants:
  - `NotFound { path }` — `config.toml` doesn't exist at the
    resolved path (first-run case; message points to `proxxx init`).
  - `Io { path, source }` — file exists but couldn't be read
    (permission denied, EIO, disk gone — fix is chmod / unmount
    diagnostics, not `proxxx init`).
  - `Toml { path, source }` — read succeeded but TOML parsing
    failed: syntax error, type mismatch, or missing required field
    (the `toml::de::Error` `Display` carries line/col).

- All three map to `ConfigError::EXIT_CODE = 3`. Single constant
  because the contract slot is one code; splitting variants to
  distinct codes later is an additive (minor) bump per the doc.

### Internal

- New unit tests in `src/config/mod.rs::config_error_tests`:
  - `config_error_variants_carry_through_anyhow_chain` — every
    variant is downcast-recoverable from `anyhow::Error::chain()`,
    pinning the contract main.rs's typed-exit walker relies on.
  - `config_error_exit_code_is_three` — locks the documented value.
  - `config_error_not_found_renders_actionable_message` — the
    operator-facing message must keep pointing at `proxxx init`.

- main.rs's typed-exit chain walker grew a third arm next to the
  existing `ApiError` (v0.1.15) and `PreflightRefusal` (v0.1.13)
  branches — same downcast pattern.

## [0.1.18] — 2026-05-11

### Fixed — panic visibility for fire-and-forget TUI dispatch spawns

- **17 `tokio::spawn(async move { ... })` call sites in
  `src/tui/mod.rs::dispatch_side_effect` + 1 in the SSH-session open
  branch were dropping their `JoinHandle` on the floor.** Any panic
  inside (e.g. `unreachable!` reached on malformed cluster data, an
  `as` truncation hitting `panic = abort` in release, a serde
  deserialise on garbage from a misbehaving PVE) was silently eaten
  by the runtime: the task vanished, the user saw "operation did
  nothing" and the log was blank.

  New helper `util::spawn_traced::spawn_traced(name, future)`:
  - Spawns `future` exactly like `tokio::spawn`.
  - Spawns a tiny observer task that awaits the inner `JoinHandle`
    and, on `JoinError::is_panic()`, recovers the payload and emits
    `tracing::error!(task = name, "background task panicked: ...")`.
  - Cancellation stays quiet (expected on runtime teardown).
  - The observer self-completes when the inner task finishes — no
    leak, no extra resource cost beyond ~200 ns per call.

  Per-task labels: `start_guest`, `stop_guest`, `restart_guest`,
  `create_snapshot`, `delete_guest`, `migrate_guest`,
  `execute_guest_command`, `fetch_task_log`, `execute_queue`,
  `download_iso`, `move_disk`, `resize_disk`, `fetch_hardware`,
  `fetch_ha_console`, `fetch_snapshot_tree`, `config_grep`,
  `hitl_approval`, `ssh_session_open`. `grep "task panicked"
  proxxx.log` is now a usable triage command.

  Long-lived tasks at [`src/tui/mod.rs:262`](src/tui/mod.rs#L262)
  (HITL poller) and [`src/tui/mod.rs:347`](src/tui/mod.rs#L347)
  (API worker) are unchanged — they already keep their
  `JoinHandle` and are aborted + awaited at teardown
  ([:679-692](src/tui/mod.rs#L679-L692)), so panic visibility was
  already covered for those.

### Internal

- New module [`src/util/spawn_traced.rs`](src/util/spawn_traced.rs)
  with 3 unit tests:
  - `spawn_traced_runs_to_completion_for_normal_task`
  - `spawn_traced_observer_completes_after_panic`
  - `spawn_traced_observer_handles_string_panic`

## [0.1.17] — 2026-05-11

### Added — TLS certificate pinning (Trust On First Use)

- **New `tls_pin_mode = "tofu"` profile option** for homelab clusters
  with self-signed certificates. The v0.1.10 audit flagged that
  `verify_tls = false` accepts ANY certificate, which is silent MITM
  bait: a rogue cert on the same network can intercept the entire
  REST/WebSocket session including serial-console tickets. TOFU sits
  between "strict CA validation" and "accept anything":

  - **First connect:** proxxx opens a TLS handshake with an
    accept-any verifier, snapshots the leaf cert in DER form to
    `<config_dir>/known_certs/<host>_<port>.der`, and logs the
    SHA-256 fingerprint.
  - **Subsequent connects:** reqwest is built with the pinned cert
    as the ONLY trusted root (built-in roots disabled). If the
    cluster rotates the cert — legit renewal or MITM swap — the
    standard rustls verifier rejects the new cert with a clear
    error and the operator can inspect the cert out-of-band and
    delete the file to re-trust.

  Pin storage is keyed by `host_port`, not by profile name — two
  profiles targeting the same cluster (e.g. `--profile readonly` +
  `--profile admin`) share the pinned cert because it's the same
  cluster identity. Writes use temp-file + rename so a crash mid-
  write can't leave a half-written cert.

  New module: [`src/api/tls_pin.rs`](src/api/tls_pin.rs) with
  `probe_leaf_cert`, `fingerprint_sha256`, `pinned_cert_path`,
  `load_pinned_cert`, `save_pinned_cert`. Wired into
  `PxClient::new` via the new `resolve_tofu_cert` helper in
  [`src/api/client.rs`](src/api/client.rs).

### Config

- New optional field `tls_pin_mode: Option<String>` on
  `ProfileConfig`. Defaults to `None` (current behaviour: trust
  decided by `verify_tls` alone). Set to `"tofu"` (case-insensitive)
  to opt in. Documented inline in the `proxxx init` template.

### Internal

- New direct dep: `tokio-rustls = "0.26"` (rustls 0.23 ABI) for the
  bootstrap handshake. The `rustls` crate was already a direct dep
  for the WebSocket custom verifier.
- 6 new lib tests in `src/api/tls_pin.rs::tests`:
  - `fingerprint_sha256_empty_input`
  - `fingerprint_sha256_deterministic`
  - `pinned_cert_save_load_round_trip`
  - `load_pinned_cert_missing_file_returns_none`
  - `pinned_cert_path_sanitises_special_chars`
  - `pinned_cert_path_collapses_url_variants_to_same_path`

## [0.1.16] — 2026-05-11

### Fixed — async SQLite writers (TUI render-loop latency)

- **The three steady-state SQLite writers now run on `spawn_blocking`
  instead of pinning the tokio runtime worker.** The v0.1.10 audit
  flagged that `cache::save_queue` was called synchronously from the
  TUI render loop; under WAL-checkpoint contention the writer can
  block for up to `busy_timeout` (5000 ms), stalling every keypress
  and every API tick in the same window. Same pattern as
  `config::keyring_get` which already uses `spawn_blocking` for the
  identical reason on the keychain side.

  New async wrappers in `src/app/cache.rs`:
  - `save_queue_async(Option<String>, Vec<PersistedQueueEntry>)`
  - `save_state_async(Option<String>, Vec<Node>, Vec<Guest>, Vec<StoragePool>)`
  - `save_alert_dedup_async(Option<String>, Vec<(String,String,u64)>)`

  Each wrapper takes owned arguments (`spawn_blocking` requires
  `'static`) and routes the synchronous `save_*` impl through
  `tokio::task::spawn_blocking`. The sync versions stay intact for
  any non-async callers.

  Call-site updates:
  - `src/tui/mod.rs:400` — queue persistence flush every render tick
  - `src/tui/mod.rs:543` — full cluster-state snapshot after each
    storage sync (every ~5 s)
  - `src/cli/monitoring.rs:579,630` — alerts daemon tick + graceful
    shutdown flush

  Reads at TUI startup (`load_state`, `load_queue`, `load_state_at`)
  and at daemon startup (`load_alert_dedup`) remain synchronous —
  they're one-shot cold-path calls before any concurrent writer
  exists, so spawn_blocking would add overhead without buying
  anything.

### Internal

- 3 new lib tests in `src/app/cache.rs::concurrency_tests`:
  - `save_queue_async_round_trips_through_load_queue`
  - `save_state_async_round_trips_through_load_state`
  - `save_alert_dedup_async_round_trips_through_load_alert_dedup`

  Each writes via the async wrapper and reads back via the sync
  loader, pinning that the wrapping doesn't break the data path.
  The structural claim ("doesn't block the runtime") is left to
  `spawn_blocking`'s own docs — we don't try to measure latency
  here.

- Total lib tests: 314 → 317. clippy --all-targets clean.
- No public-API or CLI surface change.

## [0.1.15] — 2026-05-11

### Fixed — typed exit codes (closes documentation drift)

- **`main.rs` now exits with the typed exit code documented in
  [docs/reference/exit-codes.md].** The contract had been published
  for several releases (`4` = auth/authz, `5` = not found, `7` =
  cluster transient, `6` = pre-flight refused) but `main.rs` always
  exited `1` for any `Err(_)` from the CLI dispatch. Shell scripts
  branching on `$?` to distinguish "auth expired" from "guest gone"
  silently got the wrong code.

  Implementation:
  - **`ApiError::exit_code() -> i32`** — closed match over every
    variant. `Unauthorized` and `Forbidden` collapse to `4` (one
    `case` arm in shell); `NotFound` → `5`; `RateLimited` and
    `StorageHang` collapse to `7` (transient — same retry strategy).
    `Parse` / `Transport` / `PayloadTooLarge` / `Other` → `1`
    (no shell-actionable distinction; the hint and stderr carry
    the detail).
  - **`app::preflight::PreflightRefusal`** — new typed error with
    `pub const EXIT_CODE: i32 = 6`. `enforce_preflight` previously
    bailed with an untyped `anyhow::bail!("refusing destructive
    op …")`; the message is unchanged but the chain now carries the
    typed marker so `main.rs` can map it to `6` instead of `1`.
  - **`main.rs` Err path** walks the anyhow chain via
    `Error::chain().find_map(downcast_ref)` looking for `ApiError`
    or `PreflightRefusal` and exits with the typed code. Non-typed
    errors fall through to `1` as before.

### Internal

- 5 new lib tests in `src/api/error.rs` pinning the exit-code
  contract per variant + a full-table assertion catching future
  variants that forget to extend the `exit_code` match. The
  existing `enforce_preflight_bails_on_severe_without_force` test
  now also asserts the chain carries `PreflightRefusal` so a future
  refactor reverting to `anyhow::bail!` breaks the test loudly.
- `docs/reference/exit-codes.md`: fixed stale `ApiError::Schema` →
  `ApiError::Parse`, added `Other`, marked configuration-load
  errors as still exiting `1` pending a follow-up `ConfigError`
  variant. Total lib tests: 309 → 314.

## [0.1.14] — 2026-05-11

### Added — actionable error hints

- **`ApiError` now carries a per-variant `actionable_hint()` returning a
  one-line "what should I do next?" string.** The v0.1.10 audit flagged
  that proxxx's typed-error architecture existed but every error
  collapsed to the same generic anyhow chain at the application
  boundary — operators saw "Proxmox rejected our credentials" with no
  follow-up. Each variant now points at a concrete next step:
  - `Unauthorized` → "credentials rejected — re-run `proxxx init
    --interactive` to rotate the token, or verify `$PROXXX_TOKEN_SECRET`
    matches the live secret in PVE (`pveum user token list <user>`)"
  - `Forbidden` → "token is valid but lacks the privilege for this op —
    inspect the ACL with `proxxx access acl` and grant the needed role
    on the affected path; `proxxx perms <user>` shows effective rights"
  - `NotFound` → "the resource doesn't exist on the cluster — it may
    have been deleted, renamed, or the vmid/storage/node name is wrong
    (try `proxxx ls guests` / `proxxx ls nodes` to enumerate)"
  - `RateLimited`, `StorageHang`, `Transport`, `Parse`, `PayloadTooLarge`,
    `Other` — each gets its own targeted hint pointing at the right
    diagnostic command or config knob.
- **`api::error::extract_hint(&anyhow::Error) -> Option<&'static str>`**
  walks an anyhow chain and surfaces the inner `ApiError`'s hint. Used
  by `main.rs` for CLI error rendering:
  - Text mode: appends `  hint: …` line under `Fatal Error: …`
  - JSON mode: adds a `"hint"` field to the error object alongside
    `"error"` and `"status"`. Non-API errors omit the field — proxxx
    doesn't invent hints for config-parse or IO failures.

### Internal

- 7 new lib tests in `src/api/error.rs` covering: every variant has a
  non-empty hint (≥20 chars), specific text checks for the four
  highest-traffic variants, `extract_hint` finds typed errors through
  `.context()` wrapping, and returns `None` for non-API errors.
- Total lib tests: 302 → 309. No production-API change beyond the new
  `actionable_hint()` / `extract_hint()` surface area.

## [0.1.13] — 2026-05-11

### Added — pre-flight risk gate coverage

- **9 new unit tests** closing the pre-flight risk gate coverage gap
  the v0.1.10 audit flagged. The cheap `assess()` path already had
  6 tests pinning `Locked`/`HaManaged`/`Running`/`LongUptime`/
  `TaggedProd`/`ActiveNetTraffic`, but the 5 deep-only variants and
  the entire `--allow-risk` bypass semantic were unprotected:

  - **`assess_deep` (5 tests in `src/app/preflight.rs`)** — each
    exercises the corresponding code path via wiremock against PVE:
    - `HasManySnapshots` (Op::Delete + 6 snapshots → Warning)
    - `BackupAgeWarning` (Op::Delete + backup ctime 30h ago → Warning,
      with a ±1h slop for clock drift)
    - `NoBackupFound` (Op::Delete + empty backup storage, no PBS → Notice)
    - `ListeningOnService` (running QEMU + QGA returns `LISTEN ... :80`
      → Warning, `name: "http"`) — exercises the two-step
      `agent/exec` POST + `agent/exec-status` GET wiring end-to-end
    - `DeepCheckSkipped` for running LXC (no QGA path → Notice). The
      test asserts **zero** HTTP calls hit the mock server, pinning
      that the LXC short-circuit returns before any I/O.

  - **`enforce_preflight` (4 tests in `src/cli/common.rs`)** — pins
    the `--allow-risk` bypass contract that the audit found had zero
    tests:
    - `bails_on_severe_without_force` — Locked guest, force=false
      surfaces an error that names both `SEVERE` and `--allow-risk`
      so the operator sees the escape hatch.
    - `proceeds_on_severe_with_force` — same Locked guest, force=true
      returns Ok (operator owns the consequence).
    - `proceeds_on_warning_without_force` — tagged-prod guest yields
      `TaggedProd` (Warning); the gate only refuses on Severe.
    - `returns_ok_on_clean_guest` — no risks: Ok regardless of force.

  Total lib tests now: 302 (was 293). Cargo clippy --all-targets
  clean (8 missing-backtick lints fixed inline).

### Internal

- No production code change; tests-only patch release.

## [0.1.12] — 2026-05-11

### Fixed — TUI concurrency hardening

- **Main `tokio::select!` is now `biased;` with a shutdown branch.**
  The TUI run loop in `src/tui/mod.rs` previously had a 2-arm select
  between UI events (`events.recv()`) and API worker messages
  (`data_rx.recv()`). With tokio's default fair (random) selection,
  a busy data channel could starve a `q` keypress for up to one API
  tick (~5 s). The select is now `biased;` with three arms in priority
  order: external shutdown signal → UI events → data messages. The
  `q` keypath is unchanged but the shutdown signal is now first-class:
  SIGINT/SIGTERM cleanly breaks the loop and runs the teardown
  (queue cache flush, terminal restore, background task abort)
  instead of dying on runtime drop. Pattern mirrors the HITL daemon
  (`src/hitl/daemon.rs`) and the alerts daemon
  (`src/cli/monitoring.rs`), which already used `biased;` for the
  same reason.
- **`JoinHandle` stored for the HITL poller and the API worker.**
  Both long-lived spawns previously discarded their handle —
  `tokio::spawn(async move { … })`. On quit the tokio runtime dropped
  them silently. Symptoms: if the HITL poller died hours earlier
  (Telegram token revoked, panic in the resolve path) the TUI
  reported "TUI exited cleanly" with no indication. Now both handles
  are captured. On quit we `abort()` + `await` each; the expected
  outcome is `JoinError::is_cancelled() == true`, anything else is
  logged via `tracing::warn!`. An operator restarting the TUI now
  sees in the audit log whether a background task had been quietly
  dead.

### Internal

- No public-API or CLI surface change. `proxxx --help` is identical;
  exit codes and JSON output unchanged.

## [0.1.11] — 2026-05-11

### Added — RBAC test coverage

- **12 new wiremock-based RBAC tests** covering the read-path /
  visibility-filter gaps the v0.1.10 audit flagged. The Phase 7 fixture
  pinned the three matrix-level invariants (typed `ApiError::Forbidden`
  on destructive 403; filtered-empty deserialization; `privsep` wire
  format) but said nothing about what each non-root persona is allowed
  to *see*. The new section pins per-persona contracts:
  - **operator@pve** (PVEVMAdmin on `/vms`, no `/nodes`, no `/access`):
    `/nodes` returns filtered-empty (not 403 — PVE prefers filtering
    for collection endpoints); `get_guests` returns only owned VMIDs;
    per-VM `status/current` on an unowned VMID returns typed Forbidden
    on both QEMU and LXC fallback paths; `cluster/resources` returns
    a partial union containing owned VMs but no `node`-type entries.
  - **auditor@pve** (PVEAuditor global, read-only): `get_guests` sees
    the full list (no filtering for `Sys.Audit` globally); `list_users`
    succeeds (read path != User.Modify write path); `stop_guest` and
    `create_snapshot` both surface typed Forbidden on the destructive
    POSTs against `/qemu/{vmid}/status/stop` and `/qemu/{vmid}/snapshot`.
  - **blind@pve** (PVEVMUser scoped to VMID 999): `get_guests` returns
    a single-entry filtered list (not empty — the operator-test bonus
    above only covered all-empty); `get_guest_status` on the scoped
    VMID succeeds; `get_guest_status` on any other VMID returns typed
    Forbidden on both QEMU+LXC paths; `cluster/resources` returns
    only the scoped entry.

  `tests/rbac_e2e.rs` is now 27 wiremock tests (15 Phase 7 + 12
  Phase 8). The live-cluster suite (`tests/rbac_live.rs`, 10 tests,
  `#[ignore]`) still depends on a re-provisioned PVE test cluster
  for end-to-end `pveum` validation — unchanged.

### Internal

- No production-code changes; tests-only patch release.

## [0.1.10] — 2026-05-11

### Internal — refactor

- **`src/cli/mod.rs` split into 12 domain submodules.** The CLI module
  had grown to 9141 lines (208 `Command` enum variants + 27 nested
  sub-enums + 45 async handlers + 7 shared helpers, all inline), making
  compile times, merge conflicts, and onboarding all measurably worse.
  Pulled out per-domain modules — `cli::{vm, ct, node, cluster, access,
  storage, firewall, monitoring, console, patch, init}` plus
  `cli::common` for shared helpers (`find_guest`, `enforce_preflight`,
  `wait_and_classify`, `classify_pending`, `parse_kv_pairs`, `BatchOp`,
  `NoSsh`, `execute_batch_op`). Sub-enums move with their handler (e.g.
  `VmCommand` lives in `cli/vm.rs`, referenced from the top-level
  `Command` as `vm::VmCommand`). `mod.rs` is now ~1670 lines — the
  irreducible `Command` enum + dispatch + small daemons (`hitl_serve`,
  `execute_search`, `execute_delete`, `build_version_payload`).
  `ssh_discovery_tests` migrates to `console.rs` alongside the
  predicates it pins; `parse_kv_pairs_tests` to `common.rs`;
  `shell_quote_tests` to `access.rs`. **No user-facing surface change**
  — clap parser tree, `--help`, `--format json` shapes, exit codes, and
  the MCP tool registry are all bit-identical to 0.1.9.

## [0.1.9] — 2026-05-07

### Fixed — security hardening

- **SSH argv injection (CWE-88).** The CLI's `proxxx ssh <vmid>` and the
  init-wizard's connectivity probe both shell out to system `ssh(1)`
  with `format!("{user}@{host}")` as the destination positional. Without
  a `--` separator before the destination, a `host` value beginning with
  `-` (e.g. via a tampered TOML or a hostile QGA reply) would be parsed
  as a flag — `-oProxyCommand=…` is the canonical exploit. Both call
  sites now (1) refuse the operation up-front via the new
  `config::validate_ssh_destination(user, host)` helper and (2) emit a
  POSIX `--` before the destination as defense-in-depth. The validator
  rejects empty strings, leading `-`, embedded `@` in `user`,
  whitespace, and NUL bytes; covered by six unit tests.

### Fixed — test reliability

- **Process-global `env::set_var` race in test fixtures.** Five mock
  client builders (`src/app/preflight.rs`, `tests/api_test.rs`,
  `tests/common/mod.rs`, `tests/rbac_e2e.rs`, `tests/rbac_live.rs`)
  injected the auth secret via `std::env::set_var("PROXXX_TOKEN_SECRET",
  …)`. Cargo runs unit and integration tests in parallel and env state
  is process-global, so any concurrent test reading the variable could
  observe the wrong value or race a sibling's `remove_var`. Replaced
  with the `cli_secret` resolver-priority-#1 parameter — same effect,
  zero shared mutable state, no `serial_test` annotation needed for the
  wiremock-only suites.

### Internal — code clarity

- `Orchestrator::wait_for_reboot` reads as if it swallows API errors
  in its node-liveness poll loop. The `unwrap_or_default()` is in fact
  load-bearing — the loop is designed to outlast a reboot, so transient
  TCP/TLS failures during cluster reconvergence MUST keep polling
  rather than abort the upgrade orchestration. Comment added; behaviour
  unchanged.

## [0.1.8] — 2026-05-07

### Added — supply chain

- **Every GitHub Actions `uses:` is now pinned to a 40-char commit
  SHA**, with a trailing `# vX.Y.Z` comment recording what version
  the SHA mapped to at pin time. Closes the floating-tag attack
  surface (the tj-actions/changed-files class of supply-chain
  compromise where a re-tagged `@v4` silently picks up malicious
  code with the runner's `GITHUB_TOKEN`). Dependabot is configured
  to update both the SHA and the trailing comment together so pins
  do not drift past published releases.
- **OpenSSF Scorecard workflow** (`.github/workflows/scorecard.yml`)
  running weekly + on push-to-main + on branch-protection-rule
  changes. Results land in GitHub Code-Scanning (per-finding
  remediation, visible under Security → Code scanning) and the
  public Scorecard API at api.securityscorecards.dev — feeds the
  badge added to README.md.

### Changed — operator-facing

- `proxxx init` SSH-key discovery now compares the `.pub` extension
  case-insensitively. On a case-preserving filesystem (HFS+ default,
  exFAT, NTFS via fuse) a public key named `id_rsa.PUB` previously
  slipped past the filter and was offered as a private-key candidate
  in the wizard menu.
- iso library detail panel: the "NOT PINNED — download refused"
  status string no longer carries a parenthetical maintainer note.
  The refusal behaviour is unchanged.

### Fixed — contributor experience

- `scripts/gate.sh` now resolves its working tree from the hook's
  cwd when invoked under `GIT_DIR` (i.e. as a pre-commit hook).
  Previously, in nested-worktree layouts (e.g. Claude Code's
  `.claude/worktrees/<name>` under the main checkout) the gate
  resolved `ROOT` to `scripts/` itself and stage 3 (`cargo audit`)
  died with "Couldn't load Cargo.lock". Single-worktree commits are
  unaffected.
- The OpenSSF Scorecard workflow's pins for `ossf/scorecard-action`
  and `github/codeql-action/upload-sarif` now point at the underlying
  commit SHAs, not the annotated-tag object SHAs the GitHub git-refs
  API initially returned. The Scorecard webapp's workflow-verification
  step rejects annotated-tag SHAs as "imposter commits", so the very
  first weekly run failed at the publish step with a 400. Other pinned
  actions in `ci.yml` / `release.yml` / `docs.yml` use lightweight
  tags (no dereferencing required) and were unaffected.

### Added — community / repo surface

- `CODE_OF_CONDUCT.md` (Contributor Covenant 2.1) — closes the
  broken link `CONTRIBUTING.md` already pointed at.
- `.github/ISSUE_TEMPLATE/{bug_report,feature_request,config}.yml`
  with required-field validations and a security redirect to the
  private advisory flow.
- `.github/PULL_REQUEST_TEMPLATE.md` matching the gate.sh + live-
  cluster + CHANGELOG verification policy.
- `.github/CODEOWNERS` routing for build-system, CI, and the
  security-impacting source paths.
- README badge sweep: latest release, MSRV (linked to
  `rust-toolchain.toml`), and OpenSSF Scorecard alongside the
  existing CI + license badges.

### Internal — code health

- `cargo clippy --all-targets` now emits zero warnings on Rust
  1.95.0 — including the pedantic / nursery groups already wired
  as `warn`. Five pedantic-level production fixes (case-insensitive
  `.pub`, `Option<&T>` over `&Option<T>`, `format!` collapse,
  struct-bools allow on the genuinely-flat `GuestFirewallOptions`,
  blank-line-after-outer-attr) plus a sweep of the test stubs
  (justified file-level `default_trait_access` allow on the
  fake-gateway fixtures, `float_cmp` allow on the exact-min/max
  sparkline asserts, digit-grouping + missing-backtick fixes).

## [0.1.7] — 2026-05-06

### Added — supply chain

- **Sigstore keyless cosign signatures on every release tarball.**
  Each per-target tarball now ships with a `.cosign.bundle`
  (signature + signing certificate + transparency-log inclusion
  proof — all in one self-verifiable file). Verification:
  ```bash
  cosign verify-blob \
    --bundle proxxx-0.1.7-<target>.tar.gz.cosign.bundle \
    --certificate-identity-regexp 'https://github.com/fabriziosalmi/proxxx/.github/workflows/release.yml@.*' \
    --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
    proxxx-0.1.7-<target>.tar.gz
  ```
  The cert-identity regexp pins to the exact workflow path —
  a leaked sigstore cert from any other repo or workflow can
  not validate against these bundles. Offline verification (the
  transparency-log inclusion proof is embedded in the bundle).
- **CycloneDX SBOM (`proxxx-0.1.7.cdx.json`).** Generated in
  the release job from `Cargo.lock` via `cargo-cyclonedx
  --frozen` — authoritative source-side dep graph (more precise
  than scanning the binary). Ships with its own `.sha256`
  sidecar. Audit with `grype sbom:proxxx-0.1.7.cdx.json` or
  any CycloneDX-aware scanner.

### Added — docs

- **README "Who is this for?" personas table** above "What you
  get". Six rows mapping persona → concerns → deep link, so a
  first-time visitor evaluating in 30 seconds gets a
  jump-to-the-right-page table instead of a feature list.
- **`/guide/troubleshooting`** — 16 common errors covering
  connection, TLS, auth, secrets, SSH, config, backup, HITL,
  MCP, and pre-commit-gate failure modes. Every entry quotes
  the exact `Fatal Error: ...` string proxxx emits, then the
  cause + a copy-pasteable fix.
- **`/guide/production-checklist`** — 7-section, 26-item
  walkthrough for operators deploying to prod: verify the
  binary (sha + cosign + SBOM), configure access (token /
  TLS / secret storage), HITL setup with systemd, alerting,
  SSH layer, host hardening, operational runbook (inventory
  pin, release notifications, recovery test).
- **Persona quickstarts**: `/guide/quickstart-homelab`
  (5-min single-node walkthrough) and `/guide/quickstart-llm-mcp`
  (5-min Claude Desktop / Cursor wiring with HITL on destructive
  tools). Sidebar new "Quickstarts by persona" section.

## [0.1.6] — 2026-05-06

### Added

- **Click-to-zoom on the docs landing page hero image.** The
  6-panel overview infographic embedded in the home hero slot
  is now zoomable via `medium-zoom` (~3 KB JS, the canonical
  vitepress recipe). Click anywhere on the image → smooth
  zoom-to-viewport with the page-bg as backdrop; click again
  or Esc → zoom back. Wired generically to `.VPHero img` and
  `.vp-doc img`, so any future screenshot in `/guide/` or
  `/reference/` benefits automatically. The navbar logo
  (`.VPNavBar img`) is intentionally excluded — clicking the
  brand mark in the corner shouldn't zoom it. SSR-safe (init
  gated in `onMounted`); re-binds across SPA navigation.

### Removed

- **Dead `repl_jobs` pipeline pruned from the TUI path.** Pre-cleanup
  the TUI fetched `client.list_replication_jobs()` on every HA-console
  open, routed it through `DataMsg::HaData → Action::HaDataLoaded →
  state.repl_jobs`, and… nothing read it. Six call sites surgically
  removed: `AppState.repl_jobs` field + initializer, `Action::
  HaDataLoaded.repl_jobs` variant field, `DataMsg::HaData.repl_jobs`,
  the `client.list_replication_jobs()` future in the HA fetch
  fan-out + its `tokio::join!` arm, the `repl_status.clear()`-
  alongside `repl_jobs.clear()` line in the view-pop GC, and a
  test fixture. The trait method `ProxmoxGateway::list_replication_
  jobs()` and the CLI `proxxx replication jobs` command stay —
  the CLI reads the gateway directly, bypassing AppState. Net:
  one less network round-trip per HA console open, ~30 lines
  removed, no behaviour change visible to operators. Surfaced by
  the from-zero project audit; verified with `grep -rn repl_jobs
  src/ tests/` returning nothing in the live tree.

### Docs

- **CHANGELOG `[Unreleased]` section restored.** Post-v0.1.5
  release the section was missing — future commits had nowhere
  to land until the next bump. Added at the top so the next
  feature/fix lands in the right slot without a manual restore.

## [0.1.5] — 2026-05-06

### Fixed

- **Operation Queue: navigation + remove key wired, instruction
  text honest.** Pre-fix the queue's instruction strip advertised
  `[Q] Back · [D] Remove Selected · [C] Commit · [R] Refresh` and
  three of those four were lies:
  - `[Q]` switches TO the queue (no-op when already there); `q`
    actually quits the app.
  - `[D]` only deletes guests in GuestList; on the queue, it did
    nothing.
  - `j/k` navigation was broken because `item_count()` didn't
    include `OperationQueue` — the selected-index was frozen at
    0 even with multiple entries.
  - Only `[C]` and `[R]` worked.
  Result: the queue was a viewer with one usable button. Now `j/k`
  walks the entries, lowercase `d` removes the highlighted one
  (`Action::DequeueOperation` was reachable from the reducer side
  but never wired to a key — fixed), and the legend reflects the
  truth: `[j/k] Nav · [d] Remove · [C] Commit & Execute · [R]
  Refresh · [Esc] Back`. The global status footer's
  `OperationQueue` bindings updated to match.

## [0.1.4] — 2026-05-06

### Fixed

- **TUI single source of truth for the bottom status row.** Two
  related fixes after operator feedback on v0.1.3:
  - Footer truth-in-binds: the global status footer claimed
    `q back` on every internal view (NodeList / GuestList / etc.)
    — a lie. `event::map_key` wires `q` unconditionally to
    `Action::Quit`; `Action::Back` is bound to `Esc / h / ←`.
    An operator on GuestList who hit `q` expecting to return to
    Dashboard got dumped to the shell instead. Now internal views
    surface BOTH chords with their real labels (`Esc back · q
    quit`); Dashboard shows only `q quit` (it's the nav root,
    where `Action::Back` would also exit). 2 new tests pin the
    contract.
  - Two-stacked-bars across views: `dashboard.rs::draw_status_bar`
    rendered its own mode pill + binds row, BELOW which the new
    global footer rendered another row — two visually identical
    lines. `nodes.rs::draw` was even worse: it called
    `super::dashboard::draw` (a forgotten copy-paste from when
    nodes.rs was forked) which fired the WHOLE dashboard pipeline
    into a 1-row chunk with everything but the trailing line
    clipped. `guests.rs` and `storage.rs` had their own
    `draw_action_bar` hint rows on top of the table, also
    duplicated by the new footer. All four per-view status / hint
    bars removed; the mode pill is promoted into the global
    footer. Each view reclaims its bottom row for content. Single
    source of truth: `widgets::status_footer` is THE bottom row
    for every view.

## [0.1.3] — 2026-05-06

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
