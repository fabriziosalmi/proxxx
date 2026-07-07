# Threat model

> **Status**: living document, last consolidated 2026-07-07. Anything
> below that is no longer true is a bug — open an issue.

## In scope

proxxx is a terminal cockpit that talks to a Proxmox VE / PBS
cluster on the operator's behalf. It is **client software**: every
attack surface is reachable only after a hostile party has either
(a) network access to the cluster (where they could attack PVE
directly without going through us), (b) local access to the
operator's machine (where they have a lower-friction shell already),
or (c) the ability to influence one of the data streams below.

The threats this document enumerates are the ones we have actively
hardened against — what a hostile party would find if they audited
the binary tomorrow.

## Trust boundaries

```
                       ┌───────────────────────────────────┐
                       │            operator               │
                       │  (terminal + config + ssh keys)   │
                       └───┬───────────────────────────────┘
                           │ (1) argv + stdin + env
                           ▼
              ┌─────────────────────────────┐
              │            proxxx           │
              │   ┌──────────────────┐      │
              │   │ pure state machine│     │
              │   └──────────────────┘      │
              └──┬───┬──┬───┬──┬──┬──┬──────┘
                 │   │  │   │  │  │  │
                 │   │  │   │  │  │  └─(8) SQLite (local audit + cache)
                 │   │  │   │  │  └────(7) Filesystem (SPICE handoff)
                 │   │  │   │  └───────(6) Subprocess (ssh, remote-viewer,
                 │   │  │   │            proxmox-backup-client, pveum)
                 │   │  │   └──────────(5) MCP JSON-RPC (LLM agent)
                 │   │  └──────────────(4) Telegram bot (HITL daemon)
                 │   └─────────────────(3) Network: PBS REST + handoff
                 └─────────────────────(2) Network: PVE REST + WebSocket
```

## Attack surfaces (numbered to match the diagram above)

### 1. Operator-supplied input: argv + stdin + env vars + config

| Surface | Mitigation | Pinned at |
| :--- | :--- | :--- |
| TOML config — arbitrary text via `<config_dir>/config.toml` | Standard `toml` crate parser; rejected at startup, no shell-out | [src/config/mod.rs](src/config/mod.rs) |
| Env vars — secrets via `PROXXX_TOKEN_SECRET`, `PROXXX_TELEGRAM_BOT_TOKEN`, etc. | Capped at 64 KiB to prevent OOM ([config/mod.rs:151](src/config/mod.rs#L151)) | `ENV_SECRET_MAX_BYTES` |
| CLI argv — clap surface | Total parse: 5 proptests in `batch_policy_proptests` prove `BatchPolicy::parse` is a total function (no panic on any input), respects documented bounds, case-insensitive, trim-neutral | [src/cli/common.rs](src/cli/common.rs) `mod batch_policy_proptests` |

### 2. PVE REST + WebSocket (network)

PVE is **partially trusted** — we authenticate to it, but a hostile
node-level attacker who can ARP-spoof the cluster IP can serve us
malicious responses. Hardening:

| Surface | Mitigation | Pinned at |
| :--- | :--- | :--- |
| TLS | rustls only (no native-tls / openssl in the tree — banned in `deny.toml`); `proxxx init` writes `verify_tls = true`; **caveat**: a hand-written profile that *omits* the key falls back to `false` via serde default ([src/config/mod.rs:18](src/config/mod.rs#L18)) — flip to secure-by-default is planned for v0.14. PBS defaults to `true`. Per-profile TOFU pinning available (`tls_pin_mode = "tofu"`) | [src/api/client.rs](src/api/client.rs), [src/api/tls_pin.rs](src/api/tls_pin.rs) |
| Auth | Token bearer via OS keychain (`keyring` crate) OR `Zeroizing<String>` env var. Keychain lookups are per-profile scoped first (`keyring_get_scoped` tries `<profile>/<item>` before the shared flat entry — opt-in isolation, AR-9). Cookies + CSRF token round-trip for password auth (legacy) | [src/api/auth.rs](src/api/auth.rs), [src/config/mod.rs](src/config/mod.rs) |
| Response parsing | Typed `ApiError` per HTTP status (Unauthorized / NotFound / RateLimited / PayloadTooLarge / Transport / Parse); JSON parse failures don't panic — they bubble up as typed `ApiError::Parse` | [src/api/error.rs](src/api/error.rs) |
| ANSI injection via VM names / tags / PBS notes | `util::sanitize::sanitize_display()` strips C0 + DEL at render time. 6 proptests cover the universe of UTF-8 inputs | [src/util/sanitize.rs](src/util/sanitize.rs) `mod proptests` |
| WebSocket (`/vncwebsocket?vncticket=...`) | 1 MiB max frame / 4 MiB max message ceilings (explicit, not relying on tungstenite defaults). Custom rustls verifier when `verify_tls = false`. Backpressure: synchronous stdout write between frames. The `vncticket` can never reach a log: `WsTarget` carries a hand-written redacting `Debug` (both `url` and `auth` fields), and the panic hook scrubs tickets from crash output (AR-7 covers the deliberate plain-text emission on explicit CLI export paths) | [src/wsterm/mod.rs](src/wsterm/mod.rs), [src/wsterm/url.rs](src/wsterm/url.rs) |
| Cluster-state RAM | TUI memory eviction on view-pop; SQLite cache is segregated per profile (`get_db_path(profile_name)`) so a hostile token in profile A can't read profile B's cached state | [src/app/cache.rs](src/app/cache.rs) |

### 3. PBS REST + restore handoff

| Surface | Mitigation | Pinned at |
| :--- | :--- | :--- |
| Auth | Token-only (PVE-style PAM-based tickets not used) | [src/pbs/client.rs](src/pbs/client.rs) |
| Restore | Shell-out to `proxmox-backup-client restore` with `kill_on_drop`: if proxxx panics or the user Ctrl+C's, the child is SIGKILL-ed (no orphan process holding a backup lock) | [src/pbs/restore.rs](src/pbs/restore.rs) |
| Args to subprocess | Standard `Command::arg()` — no shell interpretation | n/a |

### 4. Telegram HITL daemon

Telegram is **untrusted** — the bot token can be observed (by every
GitHub Actions workflow that uses it, by the operator's shell
history, by the Telegram server itself), and the API can in
principle be man-in-the-middled.

| Surface | Mitigation | Pinned at |
| :--- | :--- | :--- |
| `callback_data` forgery | Every callback carries an HMAC-SHA256 over the operation + nonce. Key is a separate 0600 file at `<config_dir>/telegram_hmac.key`, auto-bootstrapped via `getrandom`. An attacker who steals the bot token cannot forge valid `callback_data` | [src/hitl/hmac_key.rs](src/hitl/hmac_key.rs) |
| Replay attack | `PendingApprovals` atomically check-and-marks every consumed `txn_id` in a session-local `Mutex<HashSet>` — a second delivery of the same callback returns `Replay` | [src/hitl/pending.rs](src/hitl/pending.rs) |
| Privilege escalation via approval | HITL approval does NOT re-issue the PVE call with elevated credentials — proxxx uses the calling token, so an operator-token's approval is still bound by the operator's ACL. Pinned by `hitl_does_not_escalate_auditor_to_admin` in `tests/rbac_live.rs` | [src/hitl/daemon.rs](src/hitl/daemon.rs) |
| `secure_mode` bypass | `--secure` forces request_approval for every destructive op even if policy says otherwise; pinned by `secure_mode_forces_request_approval_for_destructive` in `tests/hitl_e2e.rs` | n/a |
| Deny-on-timeout | 120 s default; an unanswered callback collapses to deny, NOT approve | [src/hitl/daemon.rs](src/hitl/daemon.rs) |

### 5. MCP JSON-RPC (stdio + Streamable HTTP)

**The MCP surface is the most exposed** — an LLM agent driving
proxxx can send any sequence of `tools/call` requests. The
defensive posture:

| Surface | Mitigation | Pinned at |
| :--- | :--- | :--- |
| Tool registry | Compile-time fixed, 25 tools, SHA-256 pinned via `mcp tools --checksum`; no dynamic tool registration | [src/mcp/tools.rs](src/mcp/tools.rs) |
| Per-tool timeout | Every tool has a `timeout_secs` budget; `tools/call` wraps the dispatch in `tokio::time::timeout` — DoS via slow tool returns `-32001`, doesn't hang the request loop | [src/mcp/server.rs](src/mcp/server.rs) |
| Destructive tools **fail closed** | 10 of the 25 tools are flagged `destructive: true` (`stop_guest`, `restart_guest`, `suspend_guest`, `delete_guest`, `create_snapshot`, `delete_snapshot`, `clone_guest`, `clone_with_cloudinit`, `create_guest`, `migrate_guest`). A destructive call with **no matching `[[policies]]` entry is REFUSED pre-dispatch** — typed `isError` result, the PVE gateway is never reached. The only sanctioned route is policy match → HITL approval (Telegram) → daemon execution; approval itself never executes inline. Pinned by `mcp_destructive_without_policy_is_refused` and `mcp_destructive_with_matching_policy_routes_to_approval_not_execution` in [tests/mcp_security_e2e.rs](tests/mcp_security_e2e.rs) (security-invariants row 11) | [src/mcp/dispatch.rs](src/mcp/dispatch.rs) |
| Oversize-line DoS (stdio) | 16 MiB hard cap on a single JSON-RPC line; drain-and-continue rather than allocate-and-crash | [src/mcp/server.rs:36](src/mcp/server.rs#L36) `MAX_RPC_LINE_BYTES` |
| HTTP transport auth | Constant-time XOR-fold token comparison prevents timing side-channels leaking token prefix; live `mcp_token` read from config so SIGHUP rotation works mid-flight | [src/mcp/http_server.rs](src/mcp/http_server.rs) |
| Param schema enforcement | Every tool declares typed `ParamType` (Int/Bool/Str/Required); pre-dispatch validation refuses mismatched/missing required params with a JSON-RPC error, not a panic | [src/mcp/dispatch.rs](src/mcp/dispatch.rs) |

### 6. Subprocess execution

proxxx shells out for paths PVE never exposed over REST. Every
shell-out is hardened.

| Surface | Mitigation | Pinned at |
| :--- | :--- | :--- |
| `pveum user permissions <userid>` | `shell_quote(userid)` wraps in single quotes with `'\''` escape; an empty-string input gets the explicit `''` form so bash word-splitting doesn't drop the argument. 4 proptests prove round-trip safety + bare-path correctness + determinism + no-metachars-bare | [src/cli/access.rs](src/cli/access.rs) `mod shell_quote_proptests` |
| SSH | system `ssh` via `Command` (separate argv tokens, no shell). For russh-based remote-viewer / serial console: `hardened_algorithms()` whitelists curve25519-sha256 + ChaCha20-Poly1305 + AES-256-GCM + HMAC-SHA-512/256-ETM + Ed25519. RSA / DH-G14 / AES-CTR / HMAC-SHA1 all dropped (Terrapin / CVE-2023-48795 strict-kex markers preserved) | [src/ssh/session.rs](src/ssh/session.rs) |
| `remote-viewer` (SPICE) | Spawned with arg `<temp.vv path>`, no shell. `.vv` file written via `O_EXCL` + 128-bit random suffix + mode 0600 verified post-write; symlink-attack rejection | [src/handoff/spice.rs](src/handoff/spice.rs) |

### 7. Filesystem

| Surface | Mitigation | Pinned at |
| :--- | :--- | :--- |
| SPICE `.vv` TOCTOU | Tempfile + `O_EXCL` + random suffix + 0600 verified post-write + symlink rejection (V2). 8 unit tests pin the invariants | [src/handoff/spice.rs](src/handoff/spice.rs) |
| Audit / HMAC / Telegram-HMAC key files | All written at 0600 on unix via `OpenOptions::create_new + mode(0o600)`; proxxx refuses to start if a key file has world-readable permissions | [src/audit/mod.rs](src/audit/mod.rs), [src/hitl/hmac_key.rs](src/hitl/hmac_key.rs) |
| Config / cache / audit-DB paths | Resolved via `directories::ProjectDirs` (XDG-respecting on Linux, `~/Library/Application Support/` on macOS). No `/tmp` writes for state. | [src/config/mod.rs](src/config/mod.rs) |
| Permissions hygiene at startup | `verify_secret_file_permissions()` enforces 0600 on `bot_token_file` etc. Lax modes refused | [src/config/mod.rs](src/config/mod.rs) |

### 8. SQLite (local audit + cache)

The audit DB and cache DB are local files under
`<data_dir>/<profile>_state.db` and `<data_dir>/audit.db`. A local
attacker who can write to these can corrupt them. The HMAC chain
provides forensic detection but not write protection.

| Surface | Mitigation | Pinned at |
| :--- | :--- | :--- |
| Cache at rest | The data dir is created `0700` and every cache DB — including the SQLite `-wal` / `-shm` sidecars — is forced to `0600` (tighten-on-open; AR-8 documents the owner-protection-not-encryption posture) | [src/app/cache.rs](src/app/cache.rs) |
| Audit log tampering | HMAC-SHA256 chain per entry. The current format (**v2**) binds WHO and WHAT into the MAC: `chain_hmac = HMAC(key, "v2" \|\| prev \|\| ts \|\| action \|\| user \|\| vmid \|\| node \|\| params_json \|\| result)` — so an attacker who can write the DB can no longer rewrite the actor or parameters of a record without breaking the chain. `proxxx audit verify` recomputes each row under its own `chain_version` and reports the first broken link; legacy **v1** rows (pre-migration: `HMAC(key, prev \|\| ts \|\| action \|\| vmid \|\| result)`) keep verifying under the v1 formula. Proptests pin: round-trip; any single covered-column mutation (now incl. `user`/`node`/`params_json`) breaks ≥ 1 link; blast radius exactly 1–2 rows (pinpoint over cascade — deliberate); and v1↔v2 migration compatibility | [src/audit/mod.rs](src/audit/mod.rs) `mod proptests` |
| Cache cross-profile read | `get_db_path(profile_name)` produces distinct paths per profile; pinned by `cache_is_segregated_per_profile` unit test | [src/app/cache.rs](src/app/cache.rs) |
| Secrets in cache | Never written: `save_state` only persists `nodes/guests/storage`; `GuestExecResult` (which could contain command output with secrets) never reaches the cache schema | [src/app/cache.rs](src/app/cache.rs) |

## Accepted risks (not mitigated)

The **signed operational accepted-risk register** (AR-1 … AR-10, each
with rationale, blast radius and revisit trigger) lives at
[pre-commit/ACCEPTED-RISKS.md](pre-commit/ACCEPTED-RISKS.md); the
executable side of every closed invariant is indexed in
[pre-commit/03-security-invariants.md](pre-commit/03-security-invariants.md).
The table below keeps the threat-model-level acceptances:

| Risk | Why we accept it | Documented at |
| :--- | :--- | :--- |
| RSA Marvin Attack (RUSTSEC-2023-0071) | Transitive via russh → internal-russh-forked-ssh-key → rsa 0.10.0-rc.16. The attack requires a network attacker issuing many adaptive RSA decryption queries with timing observation — not our threat model (one-shot SSH console handoff, not a network crypto service). Blocked on upstream `rsa` constant-time path | [.cargo/audit.toml](.cargo/audit.toml), [deny.toml](deny.toml) |
| `verify_tls = false` profiles | Operator opt-in for homelab self-signed certs; the TUI tag-shows `INSECURE` on any view of that profile. Pin via `tls_pin_mode = "tofu"` is the preferred path. Note: a hand-written profile that *omits* the key currently gets `false` too (serde default) — the flip to secure-by-default is planned for v0.14 | [src/config/mod.rs](src/config/mod.rs) |
| Local-trust assumption for `<config_dir>` | A local attacker who can edit `config.toml` or `audit.key` can subvert proxxx. We don't sandbox against the operator's own user account | n/a — out of scope |
| Telegram server compromise | If Telegram itself is hostile, callback_data HMAC still holds (separate key), but a hostile Telegram could refuse to deliver approvals (deny-of-service). Acceptable — operator notices missing approvals immediately | n/a |
| `keyring v3` over `keyring-core` | Upstream `keyring v4` is "sample only"; migration to `keyring-core` is tracked but not urgent | [#28](https://github.com/fabriziosalmi/proxxx/pull/28) closed, [.github/dependabot.yml](.github/dependabot.yml) ignore rule |

## Verification ladder

| Layer | Tool | Surface |
| :--- | :--- | :--- |
| Lint/style | `cargo clippy` deny-tier (`unwrap_used` / `expect_used` / `panic` / `todo` / `await_holding_lock`) | declared bad patterns |
| Supply-chain CVE | `cargo audit` (`.cargo/audit.toml`) | RustSec advisories |
| Supply-chain policy | `cargo deny` (`deny.toml`) | license whitelist + banned crates (openssl/native-tls) + crates.io-only sources + wildcard ban |
| Posture | OpenSSF Scorecard | branch protection, pinned actions, signed releases |
| SAST | CodeQL Rust (security-and-quality) | taint flow, CWE patterns |
| Invariant | `proptest` (25 properties, ~6 400 random cases per run) | sanitize / snaptree / audit chain / shell_quote / BatchPolicy parser — each ~256 cases × 25 = ~6 400 |
| Test | `cargo test --all-targets` | full suite: lib tests + 24 integration files + gated live suites (exact counts tracked in [README](README.md)) |
| Gate | `scripts/gate.sh` 8 stages | secret-scan + fmt + clippy + audit + deny + test + live cluster + mutation lifecycle — runs locally pre-commit + pre-push, mirrored in CI |
| Live | `tests/rbac_live.rs`, `tests/ssh_live.rs`, `tests/live/test_*.sh` | 4-persona RBAC + SSH round-trip + 87 read-only probes + 47 mutation probes against real PVE 9.1.1 |

## Reporting a vulnerability

See [`SECURITY.md`](SECURITY.md) — preferred channel is **GitHub
private vulnerability report** (Security → Report a vulnerability).
Email fallback: `fabrizio.salmi@gmail.com` with subject
`[proxxx security]`. Triage in 7 days, fix in 30 for High/Critical,
coordinated disclosure 14 days after fix ships.
