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
