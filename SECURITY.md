# Security policy

proxxx is a terminal cockpit for Proxmox VE & PBS that handles cluster
API tokens, SSH credentials, and (optionally) Telegram bot tokens. We
take vulnerability reports seriously and prefer responsible disclosure.

## Reporting a vulnerability

**Do not open a public GitHub issue for security problems.** Instead,
report privately via one of:

- **GitHub private vulnerability report** (preferred): use the
  *Security → Report a vulnerability* button on the repository page.
  This opens a private advisory thread visible only to maintainers.
- **Email**: `fabrizio.salmi@gmail.com` with subject prefix
  `[proxxx security]`. PGP not required; if you prefer encrypted
  email, ask in your first message and we will exchange a key.

Please include:

1. A description of the issue and its impact.
2. The proxxx version (`proxxx version --json`) and host OS / arch.
3. Steps to reproduce, ideally a minimal config + command sequence.
4. Whether a public CVE has been requested elsewhere, so we can
   coordinate.

## Response timeline

- **Acknowledgement**: within 72 hours.
- **Triage** (severity classification, scope): within 7 days.
- **Fix or mitigation plan**: within 30 days for High/Critical.
  Lower severities are scheduled with the next release.
- **Coordinated disclosure**: by default, public disclosure 14 days
  after a fix ships in a tagged release; sooner if the issue is
  already public, longer if you need additional time to update
  downstream.

## Scope

In scope:

- Privilege escalation via crafted PVE / PBS API responses.
- Secret leakage (token, password, ticket, CSRF) into logs, audit
  files, swap, core dumps, or process output.
- Shell-injection in any path that shells out (`pveum`,
  `proxmox-backup-client`).
- TLS verification bypass beyond the documented per-profile
  `verify_tls = false`.
- TOCTOU on temp files (e.g. SPICE `.vv` handoff).
- HITL-bypass paths in the approval gate (Telegram round-trip).
- Memory-safety issues unique to proxxx (vs upstream crates).
- MCP tool registry tampering or schema-mismatched payloads.

Out of scope (please do not report):

- Vulnerabilities in upstream crates that are already documented in
  `.cargo/audit.toml` and ignored with a stated reason. `cargo audit`
  runs on every commit + nightly; ignored advisories are listed in
  `proxxx version --json` under `audit_ignores`.
- Misconfiguration of the operator's PVE/PBS cluster itself.
- DoS via clearly hostile inputs (ridiculous CIDR ranges, recursive
  config) unless they break a documented invariant.
- Findings against `tests/`, `development/`, or `docs/` content
  (these are not part of the shipped binary's attack surface).
- Theoretical issues without a reproducer.

## Hardening already in place

If you're auditing the codebase, these mechanisms are intentional and
documented in `docs/architecture/security.md`:

- `Zeroizing<String>` for every secret (token, ticket, CSRF, password,
  PBS token) — `Drop` overwrites the heap allocation.
- `cargo clippy --deny unwrap_used --deny expect_used --deny panic
  --deny indexing_slicing` on every commit + CI.
- 32 MiB body cap on every API response (no OOM via hostile JSON).
- Rate-limited API client (`governor`) per profile.
- TOFU `known_hosts` for SSH (no blind trust).
- TOCTOU-safe SPICE `.vv` handoff: `tempfile` + `O_EXCL` + 128-bit
  random suffix + mode 0600.
- Shell-quoted `pveum` invocation with metachar refusal + `--`
  separator (3 layers of defence; tested with `'; touch /tmp/pwned`,
  `$(rm -rf /)`, backticks, pipes, semicolons, newlines).
- `cargo audit --deny warnings` runs locally as gate stage 3,
  in CI on every push, and nightly via cron.
- Compile-time-fixed MCP tool registry (no runtime registration);
  registry hash exposed via `proxxx mcp tools --checksum` for
  supply-chain pinning.
- Pre-flight risk gate refuses destructive ops on running guests
  without `--allow-risk`.

## Recognition

We don't run a paid bug bounty (single-maintainer project), but we
will credit reporters in `CHANGELOG.md` and the GitHub advisory
unless you ask to remain anonymous.
