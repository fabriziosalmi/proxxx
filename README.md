<p align="center">
  <img src="assets/icon/brand-square-512.png" alt="proxxx" width="120" height="120">
</p>

<h1 align="center">proxxx</h1>

<p align="center">
  <strong>Terminal cockpit for Proxmox VE & Proxmox Backup Server.</strong>
</p>

<p align="center">
  Rust · async · single static binary · no installer · no agent.<br>
  Talks to the things that already exist on your cluster — REST against PVE and PBS, SSH for the rest — instead of asking you to deploy a new daemon.
</p>

<p align="center">
  <a href="https://github.com/fabriziosalmi/proxxx/actions/workflows/ci.yml"><img src="https://github.com/fabriziosalmi/proxxx/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/fabriziosalmi/proxxx/actions/workflows/scorecard.yml"><img src="https://api.securityscorecards.dev/projects/github.com/fabriziosalmi/proxxx/badge" alt="OpenSSF Scorecard"></a>
  <a href="https://github.com/fabriziosalmi/proxxx/releases/latest"><img src="https://img.shields.io/github/v/release/fabriziosalmi/proxxx?sort=semver&display_name=tag" alt="Latest release"></a>
  <a href="https://github.com/fabriziosalmi/proxxx/blob/main/rust-toolchain.toml"><img src="https://img.shields.io/badge/MSRV-1.95-orange?logo=rust" alt="MSRV 1.95"></a>
  <a href="#license"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="MIT"></a>
</p>

<p align="center">
  <img src="assets/demo.svg" alt="proxxx animated demo — a destructive command is typed, refused by the pre-flight risk gate, then approved via Telegram HITL and executed" width="900">
</p>

---

## Who is this for?

Pick the row that matches you and jump straight to the right page.

| If you are… | …you'll care about | Start here |
| :--- | :--- | :--- |
| **Homelab solo** running 1-3 nodes | wizard, fast TUI, single binary, no daemons | [5-min homelab quickstart](https://fabriziosalmi.github.io/proxxx/guide/quickstart-homelab) |
| **Platform / SRE** on 10-50 nodes with on-call | HITL Telegram gate, alert daemon, `--format json` for CI, `--profile` for multi-cluster | [Production checklist](https://fabriziosalmi.github.io/proxxx/guide/production-checklist) · [HITL](https://fabriziosalmi.github.io/proxxx/integrations/hitl) |
| **DevOps** scripting Proxmox in pipelines | typed exit codes, deterministic JSON, pre-flight risk gate, batch ops with `--yes` | [CLI reference](https://fabriziosalmi.github.io/proxxx/reference/cli) · [Exit codes](https://fabriziosalmi.github.io/proxxx/reference/exit-codes) |
| **LLM / agent integrator** wiring Claude/Cursor to a cluster | MCP server (stdio + Streamable HTTP), compile-time-fixed 25-tool registry, SHA-256 pinned for supply-chain audit | [LLM/MCP quickstart](https://fabriziosalmi.github.io/proxxx/guide/quickstart-llm-mcp) |
| **Security / compliance** evaluating before deploy | typed errors, HITL replay protection, sigstore-signed releases, CycloneDX SBOM, gate on every commit | [`THREAT_MODEL.md`](THREAT_MODEL.md) · [`SECURITY.md`](SECURITY.md) · [Production checklist](https://fabriziosalmi.github.io/proxxx/guide/production-checklist) |
| **EU-regulated ops** (NIS2 / ISO 27001 / GDPR) | append-only SQLite audit log with HMAC-SHA256 chain, `proxxx audit verify`, zero telemetry, fully self-hosted | [EU & compliance](#eu--compliance) |
| **Contributor** sending a PR | 8-stage commit gate (fmt + clippy + audit + cargo-deny + test+proptest + live cluster + mutation lifecycle), no-skip-flags policy | [`ARCHITECTURE.md`](ARCHITECTURE.md) · [`CONTRIBUTING.md`](CONTRIBUTING.md) · [Pre-commit gate](https://fabriziosalmi.github.io/proxxx/guide/pre-commit-gate) |

---

## What you get

- **One binary** — `proxxx`. CLI, TUI, MCP server, unified daemon (alerts + HITL + schedule) all in the same executable.
- **Cluster-wide read in a second** — `proxxx ls nodes`, `proxxx ls guests`, fuzzy search across the whole cluster from `/`. `--all-profiles` fans the read across every configured cluster in parallel.
- **GitOps for Proxmox** — `proxxx state {export,diff,apply}` produces a byte-stable TOML across **eight state families** (pools, ACL grants, storage definitions, backup jobs, cluster firewall, notification matchers, HA rules, HA resources), diffs against live, converges via dispatched API calls. Pre-flight risk gates refuse Severe changes (non-empty pool delete, root-role ACL delete, shared-storage delete, HA-rule strict-flip) unless `--allow-risk`; `--interactive` adds per-Severe `[y/N]` stdin prompts.
- **Pipeline writes** — start, stop, migrate, snapshot, clone, backup, patch, disk-move, with `--format json` for jq. `migrate --stream` shows live per-disk progress.
- **Pre-flight risk gate** — both per-guest (Locked/Running/LongUptime/TaggedProd/ActiveNetTraffic/HaManaged + 5 more) and state-change (PoolDeleteNonEmpty/AclDeleteRootRole/StorageDeleteShared/BackupJobDelete/NotificationMatcherDelete/HaRuleDelete/HaRuleStrictChange/HaResourceDelete/HaResourceStateChange/BulkChangeCount) — refuses destructive ops without explicit override.
- **HITL** — Telegram-mediated human approval gate, deny-on-timeout (120 s), policy-driven by tag / vmid / wildcard.
- **Incident lockdown** — `proxxx incident freeze --reason X --ttl 4h` halts every mutation cluster-wide (`POST`/`PUT`/`DELETE` refuse with exit 8); `thaw` lifts it. Reads keep working for investigators.
- **Console handoff + recording** — SSH/serial/SPICE/noVNC, all from `proxxx <verb> <vmid>`. `proxxx serial --record` writes asciinema cast v2; `proxxx play-cast` replays.
- **Cross-cluster** — `proxxx find <vmid>` answers "which cluster owns this guest?" without manual profile-switching.
- **Fleet view** — `proxxx fleet` aggregates **every** configured profile (clusters + standalone hosts, mixed) into one read-only TUI: per-cluster health summary + an aggregated guest table. `↑↓` select a cluster, `Tab` toggle the guest pane (selected vs whole fleet), `Enter` drill into a cluster's full TUI, `q` quit.
- **Read-only profiles** — `read_only = true` on a profile makes proxxx refuse *every* mutation on it client-side (reads still work); pair with a `PVEAuditor` PVE token for a server-enforced lock too. Observe production safely, write only on your test cluster.
- **PBS browse + restore** — REST browse plus `proxmox-backup-client` restore with `kill_on_drop` supervision. `proxxx backup-verify` does metadata-level integrity probing.
- **Observability** — `proxxx logs tail` (cross-node journalctl fanout via SSH), `proxxx heatmap` (per-node API RTT), `proxxx anomaly` (z-score outliers), `proxxx accounting --timeframe month` (CPU-hours/GiB·h/net-GiB from per-guest RRD).
- **Upgrade pre-flight** — `proxxx upgrade-check --target 9.x` scans cluster + config against bundled rules; exit code 1 on any block-severity finding (CI-gateable).
- **Bundled error knowledge base** — `proxxx explain <error-id>` for every typed error proxxx can emit (15 entries; ships with the binary, no network needed).
- **Cluster digest for LLMs** — `proxxx describe --output llm-context` emits a token-compact prose+key:value paste-pronto for AI chats.
- **MCP server** — stdio JSON-RPC + HTTP/SSE for LLM agents, compile-time-fixed tool registry, surface SHA-256 pinned. Server-sent `notifications/cluster-event` on both transports (task lifecycle + freeze/thaw events).
- **Verifiable releases** — every tarball ships with three layers: SHA-256 sidecar, sigstore keyless cosign signature pinned to this exact workflow path (offline-verifiable; transparency-log inclusion proof embedded), and a CycloneDX SBOM generated from `Cargo.lock`. Audit with `cosign verify-blob` + `grype` / `trivy`.

## EU & compliance

proxxx is designed for operators who need auditability, data sovereignty, and supply-chain transparency — requirements increasingly mandated under NIS2, ISO 27001, and GDPR in the EU.

| Requirement | How proxxx addresses it |
| :--- | :--- |
| **No telemetry** | Zero outbound connections except to your configured PVE/PBS endpoints and, if you opt in, your own Telegram bot. No analytics, no crash-reporting, no version-check pings. |
| **Data sovereignty** | All state — config, cache, audit log, HITL keys — lives on-prem, under paths you control (`~/.config/proxxx/` / `~/.local/share/proxxx/` on Linux). Nothing leaves your environment unless you push it there. |
| **Append-only audit log** | `proxxx audit log` — every mutation (start, stop, delete, snapshot, patch, create) is written to a local SQLite database with a per-entry HMAC-SHA256 chain. Tampering any record breaks the chain. |
| **Cryptographic chain verification** | `proxxx audit verify` walks every entry, recomputes the HMAC chain from the keyed root, and reports the first broken link. CI-friendly: exits 0 on pass, 1 on violation — wire it into your compliance pipeline. |
| **Export for SIEM** | `proxxx audit export --format json` or `--format csv` — pipe into Splunk, Elastic, Wazuh, or any log aggregator without an agent. |
| **Supply-chain** | Every release ships: SHA-256 sidecar, sigstore keyless cosign signature (pinned to the exact workflow path, offline-verifiable, transparency-log proof embedded), and a CycloneDX SBOM from `Cargo.lock`. Audit with `cosign verify-blob` + `grype` / `trivy`. |
| **Self-diagnostic** | `proxxx doctor` validates config, cluster connectivity, auth, Telegram HITL, PBS, SSH key, and audit log integrity in one pass. Exits 0 if all critical checks pass. |
| **Secrets hygiene** | All secret values live in `Zeroizing<String>` (heap-wiped on Drop). HMAC and audit keys are stored at 0600 paths; proxxx refuses to start if a key file has world-readable permissions. |

> **Note:** proxxx is a management tool, not a compliance product. `proxxx audit verify` provides integrity assurance for the local mutation log; it does not replace a SIEM or a formal audit trail required by a certification body. Use it as one control layer in a broader NIS2 / ISO 27001 implementation.

---

## Install

Pre-built binaries for **macOS Apple Silicon**, **Linux x86_64-musl**, and **Linux aarch64-musl** (Pi 4/5, Ampere, Graviton, Oracle Free Tier) are attached to each [tagged release](https://github.com/fabriziosalmi/proxxx/releases). All Linux artefacts are statically linked — no glibc, drops onto Alpine through RHEL.

Download + verify the full supply-chain trio:

```bash
TARGET=x86_64-unknown-linux-musl     # or aarch64-apple-darwin
VERSION=0.2.0                        # latest at time of writing

gh release download v${VERSION} --repo fabriziosalmi/proxxx \
  --pattern "*-${TARGET}.tar.gz" \
  --pattern "*-${TARGET}.tar.gz.sha256" \
  --pattern "*-${TARGET}.tar.gz.cosign.bundle"

# 1. Checksum
shasum -a 256 -c proxxx-${VERSION}-${TARGET}.tar.gz.sha256

# 2. Sigstore keyless signature (offline; cert pinned to release.yml)
cosign verify-blob \
  --bundle proxxx-${VERSION}-${TARGET}.tar.gz.cosign.bundle \
  --certificate-identity-regexp 'https://github.com/fabriziosalmi/proxxx/.github/workflows/release.yml@.*' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  proxxx-${VERSION}-${TARGET}.tar.gz

# 3. (optional) Audit the CycloneDX SBOM
gh release download v${VERSION} --repo fabriziosalmi/proxxx \
  --pattern "*.cdx.json" --pattern "*.cdx.json.sha256"
shasum -a 256 -c proxxx-${VERSION}.cdx.json.sha256
grype sbom:proxxx-${VERSION}.cdx.json   # or trivy / cyclonedx-cli

tar xzf proxxx-${VERSION}-${TARGET}.tar.gz
./proxxx-${VERSION}-${TARGET}/proxxx --version
```

If you only want the binary fast (no verification), skip steps 2–3 and run just `shasum -a 256 -c …` from the snippet above. Production deployments should run all three — see the [Production checklist](https://fabriziosalmi.github.io/proxxx/guide/production-checklist).

Or build from source (needs Rust 1.95+):

```bash
git clone https://github.com/fabriziosalmi/proxxx.git
cd proxxx && cargo build --release
./target/release/proxxx --version
```

The Linux musl artifact is statically linked — runs on every distro from RHEL 6 to Alpine 3.x without GLIBC drama.

### Debian / Ubuntu / Proxmox VE — `.deb`

Each release also ships a `.deb` for **amd64** and **arm64**, signed with the same sigstore bundle. The binary is static-musl, so the package declares **no runtime dependencies** — drop it straight onto a Proxmox VE node (which is Debian):

```bash
VERSION=0.8.5
gh release download v${VERSION} --repo fabriziosalmi/proxxx \
  --pattern "proxxx_${VERSION}-1_amd64.deb"      # or _arm64.deb
sudo apt install ./proxxx_${VERSION}-1_amd64.deb # or: sudo dpkg -i proxxx_*.deb
proxxx --version
```

Verify its signature exactly like the tarball — `cosign verify-blob --bundle proxxx_${VERSION}-1_amd64.deb.cosign.bundle …` with the same `--certificate-identity-regexp` / `--certificate-oidc-issuer` as above.

## Quick start

```bash
proxxx init --interactive               # 5-step wizard: prompts for URL, auth, TLS, optional
                                        # SSH + Telegram, validates each input against the
                                        # live cluster before write. Recommended for first
                                        # run — wrong field caught here, never lands in TOML.
proxxx init                             # non-interactive variant: writes a commented
                                        # starter config.toml; refuses to overwrite — pass
                                        # --force if you mean it. Edit url / user /
                                        # token_id / token_secret manually after.
proxxx ls nodes                         # validates the connection.
proxxx                                  # TUI (no args). Press ? for the keymap; the
                                        # bottom-row footer shows contextual binds always.
proxxx --help                           # full subcommand list.
proxxx version --json                   # build + capability metadata.
```

The starter `config.toml` carries inline comments for every secret-resolution path (CLI flag → env var → 0600 file → OS keychain). Optional sections — HITL via Telegram, SSH layer, PBS, alerts, policies — are commented out so the API-only operator doesn't have to delete anything.

## Daily-driver TUI

Run with no arguments. Vim keys, fuzzy search across the cluster (`/`), command palette (`:`), quick-open palette (`Ctrl+K`). 18 views over the same Elm-pattern reducer:

| `1` Dashboard | `2` Nodes | `3` Guests | `4` Storage |
| :---: | :---: | :---: | :---: |
| `H` Heatmap | `B` Backup board | `G` Config grep | `Q` Operation queue |
| `T` Audit timeline | `Z` Snapshot tree | `D` Drift compare | `W` Hardware passthrough |

Plus a read-only **fleet view** (`proxxx fleet`) that aggregates every configured profile into one screen — `↑↓` select cluster, `Tab` toggle guest pane, `Enter` drill into a cluster, `q` quit.

Multi-select + bulk ops with pre-flight risk preview. Operation queue with dry-run, diff preview, replay-as-script export (proxxx CLI / pvesh / curl / Ansible), and HITL approval gate (Telegram, policy-driven).

The terminal is restored on every exit path — happy, `?` early-return, panic. RAII `TerminalGuard` plus a flight-recorder panic hook installed in `main()` before the runtime starts.

## Pipeline-friendly CLI

```bash
# Read
proxxx ls guests --format json | jq '.[] | select(.status == "running") | .vmid'
proxxx ha preview --node pve1                   # failover what-if
proxxx hw conflicts --node pve1                 # PCI passthrough audit
proxxx perms root@pam --node pve1               # effective permissions
```

```bash
# Write — every destructive op routes through the pre-flight risk gate
proxxx start 100 101 102
proxxx delete 100 --yes
proxxx migrate 100 pve2 --yes
proxxx snapshot create 100 --name pre-upgrade
proxxx disk move 100 --disk scsi0 --storage ceph-rbd --yes
proxxx patch apply --reboot=auto --dry-run
```

```bash
# Console handoff
proxxx ssh    100                               # interactive ssh into guest (system ssh +
                                                # QGA / lxc-interfaces auto-discovery; falls
                                                # back to [ssh.guests."100"] when explicit)
proxxx serial 100 --node pve1                   # raw termproxy WebSocket
proxxx spice  100 --node pve1                   # writes 0600 .vv, launches remote-viewer
proxxx novnc  100 --node pve1                   # opens browser to web UI's noVNC
```

```bash
# GitOps loop — export, diff, apply with safety on top
proxxx state export > state.toml                  # snapshot cluster state
git add state.toml && git commit -m snapshot      # version it
$EDITOR state.toml                                # declare intent
proxxx state diff state.toml                      # preview drift, exit 2 if any
proxxx state apply state.toml --dry-run           # rehearse, never mutates
proxxx state apply state.toml --prune             # pre-flight refuses Severe (exit 6)
proxxx state apply state.toml --prune --interactive  # per-Severe [y/N] prompt
```

```bash
# Cross-cluster fanout + cluster digest
proxxx find 100                                   # which profile owns VMID 100?
proxxx ls guests --all-profiles                   # every guest across every cluster
proxxx fleet                                      # read-only TUI: ALL profiles in one screen
proxxx describe --output llm-context              # paste at top of an LLM chat
proxxx accounting --group-by pool --timeframe month  # CPU-hours / GiB·h / net-GiB
proxxx heatmap                                    # per-node API RTT, color-bucketed
proxxx anomaly --threshold 3                      # z-score outliers on CPU + mem%
proxxx logs tail --service pveproxy --since "1 hour ago"  # cross-node journalctl
```

```bash
# Incident lockdown + upgrade pre-flight
proxxx incident freeze --reason "rotating token" --ttl 4h   # halt every mutation cluster-wide
proxxx incident status --output json
proxxx incident thaw --reason "rotation complete"
proxxx upgrade-check --target 9.x                 # exits 1 on any block-severity finding
proxxx explain freeze-refusal                     # bundled error knowledge base
```

```bash
# Console handoff + session recording
proxxx ssh    100                                 # interactive ssh into guest (auto-discovery)
proxxx serial 100 --node pve1 --record            # raw termproxy WebSocket + asciinema cast
proxxx play-cast ~/.../sessions/<ts>-100-serial.cast --speed 2
proxxx spice  100 --node pve1                     # writes 0600 .vv, launches remote-viewer
proxxx novnc  100 --node pve1                     # opens browser to web UI's noVNC
```

```bash
# Long-running daemon — alerts + HITL + schedule under ONE process
proxxx daemon serve                               # all three with one SIGTERM
proxxx daemon serve --no-hitl                     # alerts + schedule only
proxxx schedule add --name nightly-snap --every 1d --cmd "vm snapshot 100 --yes"

# MCP for AI agents (stdio JSON-RPC, HTTP/SSE for streaming)
proxxx mcp serve                                  # stdio + interleaved server-sent notifications
proxxx mcp serve-http --bind 0.0.0.0:8080         # HTTP/SSE transport
proxxx mcp tools --checksum                       # registry SHA-256 for audit pinning
```

Exit codes are stable contract — see [`docs/reference/exit-codes.md`](docs/reference/exit-codes.md) for the full table.

## Configuration

Default location follows the `directories` project-dirs convention:

| Platform | Path |
| :--- | :--- |
| Linux | `~/.config/proxxx/config.toml` |
| macOS | `~/Library/Application Support/dev.proxxx.proxxx/config.toml` |

Secrets resolve in order: CLI flag → `PROXXX_TOKEN_SECRET` env → `token_secret_file` (0600 enforced) → inline TOML → OS keychain. Loaded values live in `Zeroizing<String>` and are wiped from the heap on `Drop`.

| Optional section | Unlocks |
| :--- | :--- |
| `[telegram]`     | HITL approvals + alert routing |
| `[ssh]`          | Patching orchestrator, `proxxx perms`, guest SSH |
| `[ssh.guests.X]` | Per-guest SSH overrides (optional — `proxxx ssh <vmid>` auto-discovers via QGA / lxc-interfaces by default; pin only when the agent's off, only loopback/link-local IPs are returned, or you want a stable DNS name) |
| `[pbs]`          | PBS browse + restore |
| `[[alerts]]`     | Alerting daemon — `node_offline`, `storage_above`, `replication_failing` |
| `[[policies]]`   | HITL gating rules — match by tag / vmid / wildcard |

Per-profile, set `read_only = true` to refuse all mutations on that profile client-side (reads unaffected, exit 8) — pair with a `PVEAuditor` PVE token for a server-side lock. See the [configuration guide](docs/guide/configuration.md#read-only-profiles-read_only).

## Quality gate

Eight stages, run as both a pre-commit hook and the CI contract in [`.github/workflows/ci.yml`](.github/workflows/ci.yml).

| Stage | What | Time |
| :---: | :--- | :---: |
| 0 | secret regression scan | <1 s |
| 1 | `cargo fmt --all -- --check` | ~3 s |
| 2 | `cargo clippy --release --all-targets` | 10–60 s |
| 3 | `cargo audit --deny warnings` | 3–5 s |
| 4 | `cargo deny check` (license / banned crates / sources / wildcards) | 2–4 s |
| 5 | `cargo test --release --all-targets` (646 lib tests + 447 integration tests including ~25 proptest properties × 256 cases each) | 10–90 s |
| 6 | `tests/live/test_run.sh` (67 read-only probes against the live cluster) | ~30 s |
| 7 | `tests/live/test_mutation.sh` (34 mutation probes: LXC + cluster-level CRUD across all 8 state families + QEMU; opt-in QGA via `PROXXX_E2E_QGA_VMID=<vmid>`) | ~60 s |

End-to-end wall time against a reachable cluster: **~340–480 s**.

```bash
git config core.hooksPath .githooks
chmod +x scripts/gate.sh .githooks/pre-commit .githooks/pre-push
cargo install cargo-audit --locked
cargo install cargo-deny --locked
```

The clippy `[lints.clippy]` block in [`Cargo.toml`](Cargo.toml) denies `unwrap_used`, `expect_used`, `panic`, `todo`, `await_holding_lock` in production code.

## Architecture

Pure Elm-pattern TUI over a typed REST client. The reducer is sync, total, and tested without a runtime.

```
        crossterm key            tokio::mpsc<DataMsg>
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
                                       enforce_preflight  →  check_hitl
                                       (risk gate)           (Telegram round-trip)
                                                          │
                                                          ▼
                                       ProxmoxGateway / PbsGateway / SshPool
```

| Module | Responsibility |
| :--- | :--- |
| [`src/app.rs`](src/app.rs) | Pure reducer. No I/O, no async. ~70 `Action` variants, ~20 `SideEffect`. |
| [`src/api/`](src/api) | `ProxmoxGateway` trait, typed `ApiError` enum (9 categorical variants), reqwest client with 32 MiB body cap and rate limiter. The `types/` directory holds ~3100 LOC of serde-typed PVE responses split across 16 submodules. |
| [`src/api/error.rs`](src/api/error.rs) | `Unauthorized`, `Forbidden`, `NotFound`, `RateLimited`, `PayloadTooLarge`, `StorageHang`, `Transport`, `Parse`, `Other`. Callers `.downcast_ref()` for differentiated handling. |
| [`src/state/`](src/state) | GitOps loop — model + export + diff + apply + preflight, eight state families (pools, ACL, storage, backup-jobs, firewall-cluster, notifications, HA rules, HA resources), byte-stable TOML. |
| [`src/pbs/`](src/pbs) | PBS REST browse + `kill_on_drop(true)` supervision over `proxmox-backup-client restore`. |
| [`src/ssh/`](src/ssh) | `russh`, publickey only, dedicated TOFU `known_hosts` (separate from `~/.ssh/`), per-node connection pool. |
| [`src/app/cache.rs`](src/app/cache.rs) | SQLite-backed time-travel cache, drives `proxxx replay <timestamp>`. |
| [`src/app/preflight.rs`](src/app/preflight.rs) | 11 risk variants with per-op weighting and `--allow-risk` override. |
| [`src/hitl/`](src/hitl) | Real Telegram round-trip via `HitlCoordinator` + a single shared `getUpdates` poller. Deny on 120 s timeout, deny when Telegram unconfigured but a policy matched. |
| [`src/mcp/`](src/mcp) | JSON-RPC server with stdio + Streamable HTTP transports. Compile-time-fixed tool registry (25 tools). Surface SHA-256 pinned via `proxxx mcp tools --checksum`. |
| [`src/util/`](src/util) | `panic_hook` (flight recorder), `terminal_guard` (RAII raw-mode), `shutdown` (SIGTERM / SIGINT for daemons). |

## Documentation

- **VitePress site** — [`docs/`](docs/) and [the live build](https://fabriziosalmi.github.io/proxxx/). Local preview: `cd docs && npm install && npx vitepress dev`.
- [`CHANGELOG.md`](CHANGELOG.md) — what shipped, with the SemVer contract for CLI / JSON / config / MCP registry surfaces.
- [`pre-commit/`](pre-commit/) — four matrices distinguishing *implemented* from *verified end-to-end*:
    [`01-feature-coverage.md`](pre-commit/01-feature-coverage.md) ·
    [`02-error-handling.md`](pre-commit/02-error-handling.md) ·
    [`03-security-invariants.md`](pre-commit/03-security-invariants.md) ·
    [`04-resiliency-and-chaos.md`](pre-commit/04-resiliency-and-chaos.md)
- [`ARCHITECTURE.md`](ARCHITECTURE.md) — one-page module map + data flow + reducer/side-effect bus + process model.
- [`THREAT_MODEL.md`](THREAT_MODEL.md) — attack surfaces, mitigations, accepted risks, verification ladder.
- [`SECURITY.md`](SECURITY.md) — vulnerability reporting policy + scope + hardening snapshot.
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — onboarding, the gate, live-cluster verification format.
- [`.cargo/audit.toml`](.cargo/audit.toml) — supply-chain advisory ignore policy.
- [`deny.toml`](deny.toml) — cargo-deny policy: license whitelist + banned crates + source lock.

## Live cluster harness

[`tests/live/`](tests/live/) drives the release binary against a real PVE cluster — separate from the cargo integration tests in [`tests/`](tests/) which use `wiremock`.

| File | Tracked | Purpose |
| :--- | :---: | :--- |
| [`test_run.sh`](tests/live/test_run.sh) | ✓ | 67 read-only probes covering the full CLI surface; logs to `test_run.log` |
| [`test_mutation.sh`](tests/live/test_mutation.sh) | ✓ | 34 mutation probes with `trap EXIT` cleanup: LXC 9999 (create → start → snapshot → stop → delete), cluster-level CRUD across all 8 state families (pool / ACL / storage-defs / backup-job / firewall-cluster alias+group+ipset / notifications matcher / HA rules / HA resources), QEMU 9998 from alpine ISO, opt-in QGA round-trips via `PROXXX_E2E_QGA_VMID=<vmid>` |
| `test_*.log` | — | Generated by the harness |

## Honest non-goals

Design boundaries — proxxx will not ship these.

- **No GUI.** Proxmox already has a web UI; proxxx is for terminal users who want CLI / TUI / scripting parity.
- **No frame rendering** for graphical SPICE or VNC. proxxx hands off to `remote-viewer` / `virt-viewer` (SPICE) or the system browser (noVNC). It never holds pixel buffers.
- **No re-implementation of Perl algorithms in Rust** where the Perl on the node is the ground truth. `proxxx perms` shells out to `pveum user permissions` over SSH and parses, since the `pve-access-control` evaluator is canonical. The API-side `proxxx access permissions` is also available — same typed tree from `/access/permissions`, no SSH dependency — for the common case where the evaluator's full expansion isn't needed.
- **No new dependencies for trivial things.** Three-line per-platform `Command::new` beats pulling `opener` for a launcher.
- **No multi-cluster _writes_ from one TUI.** The interactive per-cluster TUI is single-profile-per-process by architectural decision (switch with `--profile`); every mutation targets exactly one cluster. The read-only `proxxx fleet` view *does* aggregate every configured profile into one pane — but it stays strictly read-only and drills into a single-profile TUI (`Enter`) to act. The boundary is writable aggregation, not aggregation itself.
- **No Ceph cluster writes.** Operators reach for the `ceph` CLI directly on the node where the kernel module is loaded; proxxx wraps Ceph reads (status, metadata, flags) but not destructive ops (osd add/down, mon create, pool prune).
- **No SDN config writes.** PVE SDN is opt-in cluster config that few clusters enable, and the wire shape changes between PVE versions. Skipped rather than ship a fragile surface.
- **No browser-only auth flows.** U2F/WebAuthn registration and OIDC's redirect-callback dance both need a browser to drive them. proxxx exposes the API-driven primitives (token CRUD, password change, ACL editing) but stays out of `/access/openid/*` and `/access/tfa/u2f` — there's no terminal UX for those that beats the web UI.
- **No snapshot rollback as a destructive trigger.** The snapshot-tree TUI shows a read-only rollback impact preview (what would be discarded + time delta); the actual rollback runs through `qm rollback` / `pct rollback` or the PVE web UI. Read-only inspector views never expose destructive entry points by design.

## License

MIT. Copyright © 2026 Fabrizio Salmi. See [`LICENSE`](LICENSE).
