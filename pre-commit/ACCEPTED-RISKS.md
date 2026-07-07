# Accepted Risks

Residual risks that proxxx does **not** mitigate at the code layer, recorded
here as conscious decisions rather than left implicit in code comments. Each
entry states the risk, why it's out of scope, and what the operator must do
instead. An entry here means: *we looked at it, we decided not to close it in
code, and here is the reasoning* — not *we didn't think of it*.

Format: every entry is signed (owner + date) so an auditor can see the decision
was made by a named person at a point in time.

---

## AR-1 · MCP bearer token is the credential, not an identity

**Context:** [invariant 03 — "Destructive MCP tool without a governing policy is REFUSED"](03-security-invariants.md)

When the MCP HTTP server is exposed with `mcp_token` set, authentication is a
single shared bearer token (constant-time compared, [http_server.rs:66](../src/mcp/http_server.rs#L66)).
Anyone who obtains that token — or the Telegram `bot_token`, for the HITL
approval channel — can act as an authorized MCP client.

**Why not closed in code:** a shared-secret bearer is the MCP spec's transport
auth model; per-caller identity / mTLS / OIDC is a deployment concern, not a
client-library one. proxxx cannot mint or verify per-user identities without
becoming an auth server.

**Operator's responsibility:**
- Store `mcp_token` and Telegram `bot_token` via the OS keychain or a `0600`
  file (both resolver paths are enforced — see `resolve_bot_token`,
  [config/mod.rs](../src/config/mod.rs)).
- Rotate on suspected compromise (SIGHUP hot-reloads `mcp_token` without a
  restart — this mitigation is now proven by `reload_swaps_mcp_token_policies_and_rate_limit`
  and `failed_reload_keeps_last_known_good` in [config/watcher.rs](../src/config/watcher.rs),
  plus the real-signal `tests/config_reload_e2e.rs`; a reload that fails to
  parse keeps the last-known-good config rather than clearing auth).
- Terminate real user identity at a reverse proxy (mTLS / OIDC) in front of the
  MCP endpoint if per-user attribution is required.

*Accepted by Fabrizio Salmi — 2026-07-05.*

---

## AR-2 · Tag-based HITL policies are operational, not a security boundary

**Context:** [policy.rs:4-11](../src/hitl/policy.rs#L4) (SPOF 5.1, Category 5 audit)

Policies whose target is `tag:<name>` match on guest tags. PVE — not proxxx —
owns tags. Any other client (`qm set --tags`, the web UI, raw curl) can mutate
a guest's tags out of band; proxxx sees the new set only on its next refresh,
after which a `tag:`-scoped HITL match may no longer fire.

**Why not closed in code:** there is no fix at the client layer — the tag is not
a trusted attribute from proxxx's vantage point. The only correct enforcement is
PVE-side ACLs restricting who may mutate tags AND who may call destructive ops.

**Operator's responsibility:**
- For prod-grade gating, prefer **action/target policies** (`action="delete"`,
  `target="*"`) which don't depend on mutable tags, and PVE-side RBAC.
- Tag-change observability: `app::audit_tag_changes` logs at WARN when a guest's
  tag set changes between snapshots, leaving a forensic trail even when an
  out-of-band mutation bypasses a `tag:` policy.

*Accepted by Fabrizio Salmi — 2026-07-05.*

---

## AR-3 · `--insecure-bind` is a conscious footgun, not a default

**Context:** [invariant 03](03-security-invariants.md), [http_server.rs](../src/mcp/http_server.rs)

By default the MCP HTTP server refuses to bind a non-loopback interface without
`mcp_token`. The `--insecure-bind` flag overrides this — binding to the network
with no auth.

**Why not closed in code:** legitimate deployments exist where auth is enforced
one layer up (a reverse proxy, a service mesh, a WireGuard-only network). We
refuse by default and require an explicit, named flag to opt out, rather than
removing the capability entirely.

**Operator's responsibility:** only pass `--insecure-bind` when a trusted network
boundary or an auth-enforcing proxy sits in front of the endpoint. It is never
appropriate on an interface reachable from an untrusted network.

*Accepted by Fabrizio Salmi — 2026-07-05.*

---

## AR-4 · Uncapped non-prune auto-converge can apply 10–49 create/update changes unmanned

**Context:** [invariant 03 — "Unmanned auto-converge blast radius is bounded"](03-security-invariants.md), [daemon.rs](../src/cli/daemon.rs)

The unmanned mass-**delete** footgun is now closed: `converge_prune = true`
without a `max_unmanned_changes` cap holds all deletes (`effective_unmanned_prune`).
What remains: a **non-prune** auto-converge (or the create/update half of any
converge) with no cap can still auto-apply a batch of 10–49 create/update changes
in one tick without human review — the Severe bulk gate only trips at ≥50, and
`allowed_families` narrows *which* families but not the change *count*.

**Why not closed in code:** creates/updates converge the cluster TOWARD the
declared state — the desired, version-controlled intent — rather than destroying
it. A flood of them is a re-materialisation, not a wipe; refusing it by default
would defeat the purpose of continuous convergence. The blast radius is bounded
by design (no deletes without a cap) and observable (every dispatched tick writes
one HMAC-chained audit entry + a Telegram summary).

**Operator's responsibility:**
- Set `max_unmanned_changes` to bound every unmanned tick (creates/updates
  included), not only to unlock prune. Recommended for any production profile.
- **Size it small.** The cap should be the smallest count a legitimate tick
  would ever apply (single digits for most profiles). A generously-large cap
  (e.g. `49`) satisfies the gate but re-opens the exact 10–49 unmanned-delete
  band the guard exists to bound — the cap *unlocks* prune, it does not by
  itself make a flood safe.
- Use `allowed_families` for graduated trust — let the daemon converge low-risk
  families unmanned, keep high-blast-radius ones (`acl`, `storage`) human-only.
- Protect the desired-state repo (branch protection, atomic pushes) so a
  half-pushed tree can't present a spurious flood in the first place.

*Accepted by Fabrizio Salmi — 2026-07-05.*

---

## AR-5 · Audit HMAC key co-located with the DB — a same-user / root attacker can forge

**Context:** [invariant 03 — "Chain is admin-verifiable … HMAC key is custody-hardened"](03-security-invariants.md), [audit/mod.rs](../src/audit/mod.rs)

The audit chain is tamper-**evident**, not tamper-**proof**. Its guarantee holds
against an attacker who can write `audit.db` but cannot read the HMAC key — for
example a *different* unprivileged user on the host (now enforced: a
group/world-readable `audit.key` is refused on load). By default the key lives in
the same data dir as the DB, so an attacker running **as the proxxx user or as
root** — who can rewrite `audit.db` — can also read `audit.key`, recompute every
MAC, and produce a chain that `audit verify` accepts.

**Why not closed in code:** no client-side key store defeats a root attacker on
the same host — root can read process memory, the keychain, any file. Genuine
non-repudiation requires the key and/or the log to leave the host's trust domain.
Refusing to run without that would break the common single-host homelab install.
The load-path custody check *is* hardened: it fails **closed** (a `stat` error
refuses the key rather than skipping the check) and fstat's the open fd (no
TOCTOU / symlink-swap window). It is **unix-only** — non-unix has no POSIX mode
to enforce; the only supported release targets are darwin + linux-musl.

**Operator's responsibility (defense in depth, pick per threat model):**
- **Relocate the key — with a caveat.** `PROXXX_AUDIT_KEY` moves the key off the
  DB's volume, but proxxx must still *read* it on every `AuditLogger::open()`,
  and the `0o077` check enforces owner-only *access mode* (not *ownership* — a
  `0600` key owned by another uid still passes the mode check; the audit dir is
  created `0700` so a different user cannot swap the key in, but a same-uid/root
  attacker with dir-write can). So a "root-owned key the proxxx
  user can't read" only helps if proxxx itself runs as that principal;
  co-location on a single-user host buys little on its own. Prefer log
  externalisation for real cross-domain separation.
- **Externalise the log:** ship audit entries to an append-only sink outside the
  host (remote syslog / SIEM / WORM store). A local forge then diverges from the
  external copy — the divergence is the evidence.
- **Run `proxxx audit verify` from a separate trust context** (a monitoring box,
  a cron on a different account) rather than trusting the host to check itself.

*Accepted by Fabrizio Salmi — 2026-07-05.*

---

## AR-6 · Operation-queue recovery reconciles against PVE, not a distributed log

**Context:** [invariant 03 — "Operation-queue crash recovery is idempotent"](03-security-invariants.md), [tui/mod.rs](../src/tui/mod.rs)

The op_queue is a **TUI-local** convenience. Crash-recovery idempotency is
enforced by: (a) restart re-renders the queue, never auto-runs it; (b) only
`Pending` ops dispatch, so a restored `Running` op is never re-executed; (c) a
write-ahead persist records `Running` durably before any PVE call. What is NOT
guaranteed: a globally-consistent view of whether a `Running` op actually
completed on PVE.

**Why not closed in code:** proxxx is a client; PVE owns task truth. An op saved
as `Running` may, after a crash, have (i) never reached PVE, (ii) be still
running as a PVE task, or (iii) have completed. proxxx does not persist the PVE
UPID transactionally with the status, so it cannot always distinguish these on
its own — and inventing a two-phase commit against PVE is out of scope for a TUI
queue. Fail-safe direction: the code errs toward NOT re-dispatching (a stuck
`Running` needing manual attention) rather than double-executing.

**Operator's responsibility:**
- After a crash, treat any restored `Running` op as *unknown* — check the guest's
  actual state / the PVE task log before dismissing or retrying it.
- The queue never re-runs a `Running` op automatically; a retry is always an
  explicit user action, so verify first for non-idempotent ops (migrate, delete,
  move-disk with delete-source).
- This surface is TUI-only: unattended automation uses the daemon/CLI paths,
  which do not carry the op_queue.
- **The command palette is a present-operator fast path.** Guest-list
  keypresses (stop/delete/restart/start) *enqueue* — they flow through the queue
  and its write-ahead persist. The one path that runs a destructive op *outside*
  the queue is the fuzzy search / command palette (`/`, then e.g. `Delete VM
  100` → Enter): it dispatches the action immediately with only the HA/lock
  guard — no queue entry, no write-ahead, and no confirm modal. A crash mid-op
  there leaves nothing to reconcile. For the durable crash-recovery guarantee,
  drive destructive intent through the guest list (which enqueues) rather than
  the palette.

*Accepted by Fabrizio Salmi — 2026-07-05.*

---

## AR-7 · Console session tickets are emitted by design on the explicit CLI paths

**Context:** [wsterm/url.rs](../src/wsterm/url.rs), [cli/console.rs](../src/cli/console.rs), [cli/node.rs](../src/cli/node.rs)

The Proxmox `vncticket` is a short-lived console credential. Two kinds of exposure existed:

- **Unintentional (FIXED):** the WS connect URL — which carries `?vncticket=…` — was logged at INFO and in connect-error messages on every console attach. That leak is closed: `wsterm::url::redact_ticket` replaces the ticket value with `[REDACTED]` at every log/error site (`wsterm/mod.rs`), keeping host/path/port for diagnostics.
- **Intentional (accepted):** `proxxx vnc <vmid> --ws-url` and the ticket JSON output deliberately print the full ticket / WS URL to stdout — that IS the feature (hand the URL to a browser noVNC client or an external tool). Redacting it would defeat the purpose.

**Why not closed in code:** the emitting commands exist to *export* the ticket for immediate use; a redacted ticket is useless to the caller.

**Operator's responsibility:** treat `--ws-url` / ticket output like a password on the command line — don't pipe it into a log, a shared terminal recording, or shell history you keep. The ticket's short TTL (seconds–minutes) is the backstop: connect immediately, and a captured ticket is dead soon after.

*Accepted by Fabrizio Salmi — 2026-07-06.*

---

## AR-8 · Cache-at-rest is owner-protected, not encrypted

**Context:** [app/cache.rs](../src/app/cache.rs)

The per-profile SQLite cache holds a cluster-topology snapshot (nodes / guests / storage) plus the operation queue (vmids, nodes, disk/storage targets) — not credentials (secrets never reach the cache schema; see the "exec output not cached" invariant). On unix it is now created owner-only: the parent dir `0700`, and the `{profile}_state.db` **plus its `-wal` / `-shm` sidecars** `0600` (fresh sidecars inherit the db's mode; the explicit tighten also retightens a legacy `0644` `-wal` left by a pre-hardening unclean shutdown). The file tighten is **best-effort / fail-open** — a `stat`/`chmod` error is ignored so the cache still opens (unlike the audit key, which fails *closed*: topology is not a forgery key).

**Why not closed further in code:** `create_dir_all` no-ops on a pre-existing directory and does not tighten its mode, so a dir the operator created lax stays lax; and proxxx does not encrypt the cache at rest — topology is low-sensitivity and encryption would need a key-management story the tool doesn't own. The `0700` **directory** is the real guard: a different user can't enter it to read the db or its sidecars regardless of file modes, which also bounds the brief create-then-chmod TOCTOU window on the main db.

**Operator's responsibility:** on a multi-tenant host, ensure the data dir isn't group/world-writable (proxxx creates it `0700`, but a pre-existing one is yours); if the topology snapshot is sensitive in your environment, place the data dir on an encrypted volume.

*Accepted by Fabrizio Salmi — 2026-07-06.*

---

## AR-9 · Keychain per-profile isolation is opt-in (and stored manually); a flat entry stays shared

**Context:** [config/mod.rs](../src/config/mod.rs) — `keyring_candidates` / `keyring_get_scoped`

The OS-keychain lookup for the primary cluster credentials (`token_secret`, `password`) now tries the profile-scoped item `<profile>/<item>` **first**, then the flat `<item>`. So per-profile isolation is *available* — but honestly scoped:

- **It is opt-in.** You get isolation only by *storing* the secret under the profile-scoped item name. proxxx has **no keychain-write command** — the entry is created by hand (see below).
- **A flat entry stays shared.** A named profile with no per-profile entry falls back to the flat `<item>`, so an un-migrated flat key has the same cross-cluster sharing as before. This fallback is deliberate back-compat.
- **Telegram bot-token + PBS token stay flat** (resolved on `TelegramConfig` / `PbsConfig`, which don't carry the profile name; typically one shared bot / one PBS).

**Why not closed further in code:** removing the flat fallback (fail-closed per profile) would break every existing keychain deployment overnight — their named profiles would suddenly stop resolving. The scoped-first-then-flat order is the standard non-breaking migration.

**Operator's responsibility:**
- To isolate a profile's cluster credential in the keychain, store it under the scoped item. macOS: `security add-generic-password -s proxxx -a "prod/token_secret" -w "<secret>"`. Linux (Secret Service): store an entry with service `proxxx`, account `prod/token_secret`. That profile then resolves its own entry; the flat fallback fires only if the scoped one is absent.
- If you won't manage per-profile keychain entries (or need per-profile Telegram/PBS secrets), prefer per-profile `token_secret_file` / `bot_token_file` (0600) or the `PROXXX_*` env vars — those already resolve unambiguously per profile.

*Accepted by Fabrizio Salmi — 2026-07-06.*

---

## AR-10 · State export carries no *modelled* secret — but free-text fields pass through verbatim

**Context:** [state/model.rs](../src/state/model.rs), [state/export.rs](../src/state/export.rs), GitHub issue #178

`proxxx state export` emits pools / ACLs / storage / backup-jobs / firewall / mappings / HA. **No `Decl` struct has a secret field** — each exporter copies a fixed *whitelist* of named fields (there is no `#[serde(flatten)]` of a raw API response), and the real secrets (`ApiToken.value`; storage credentials PVE masks on `GET`) are never on the export path. The field-whitelist is the safety mechanism (not, as an earlier wording implied, PVE's masking — that's incidental). Notification *targets* (gotify tokens / SMTP passwords) are **deliberately not modelled** — PVE never returns them on `GET`, so they can't round-trip.

**Residual — free-text passthrough:** ~10 free-text fields (`comment`, `description`, `notes_template`) are exported *verbatim*, unredacted. An operator who embeds a secret in a comment (e.g. a gotify/webhook URL with an inline bearer token in a storage `comment` or a notification `notes_template`) will export it in cleartext. proxxx does not scan free text for secrets. So export is secret-free by *structure*, not by *guarantee* against operator-embedded secrets.

**Why this is an accepted risk and not a fix:** there is nothing to elide today — the risk is *future*. The moment a secret-bearing state family is added (issue #180 users/tokens, #181 metric-servers with API keys), naive export would write secrets to disk / git.

**Gate (the operator/maintainer contract):** issue #178 (secret-ref / elide-on-export convention) is the **mandatory prerequisite** before merging ANY secret-bearing state family. #178 stays frozen until that demand appears — but it must land *first*, not alongside. This entry is the tripwire.

*Accepted by Fabrizio Salmi — 2026-07-06.*
