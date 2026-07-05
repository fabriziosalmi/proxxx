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
  restart).
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

**Operator's responsibility (defense in depth, pick per threat model):**
- **Separate the key's trust domain:** set `PROXXX_AUDIT_KEY` to a path on a
  volume owned by a *different* principal than the proxxx user (e.g. a root-owned
  `0600` key on a mount the proxxx user can't read), so DB-write ≠ key-read.
- **Externalise the log:** ship audit entries to an append-only sink outside the
  host (remote syslog / SIEM / WORM store). A local forge then diverges from the
  external copy — the divergence is the evidence.
- **Run `proxxx audit verify` from a separate trust context** (a monitoring box,
  a cron on a different account) rather than trusting the host to check itself.

*Accepted by Fabrizio Salmi — 2026-07-05.*
