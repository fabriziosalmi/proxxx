# Contributing to proxxx

Thanks for considering a contribution. proxxx is a security-sensitive
infrastructure tool — a small bug can lock an admin out of their
cluster — so the bar is "demonstrate it works against a real PVE
node, not just in unit tests". This document explains how.

## TL;DR

1. Open an issue first for non-trivial work to align on scope.
2. Run the full local gate before opening a PR (`scripts/gate.sh`).
3. Live-cluster verification is required for changes that touch the
   API client, the mutation lifecycle, or any TUI that issues writes.
4. Security-impacting changes go through `SECURITY.md`, not a PR.
5. Be kind (see `CODE_OF_CONDUCT.md`).

## Before you start

- **Issue first**: open a GitHub issue describing what you want to
  change. For feature requests, mention which existing surface it
  would touch and whether it overlaps with any documented design
  boundary (`README.md` → "Honest non-goals"). For bug reports,
  include `proxxx version --json`, OS / arch, and a minimal repro.
- **No surprise mega-PRs**: a 2000-line PR with no preceding issue
  is unlikely to land. Break it down or open the design conversation
  first.
- **Existing roadmap**: the `pre-commit/01-feature-coverage.md`
  matrix tracks every feature with its verification status (✅ live /
  🟡 partial / ⚠️ wiremock-only / ❌ not verified). Pick something
  that's already on the matrix or propose a new row.

## Development environment

```bash
# Toolchain pinned in rust-toolchain.toml (1.95.0 + rustfmt + clippy
# + x86_64-unknown-linux-musl). rustup picks it up automatically
# on first cargo invocation.
git clone https://github.com/fabriziosalmi/proxxx.git
cd proxxx
cargo build --release   # ~1 minute cold; cached after that
./target/release/proxxx init
# Edit ~/.config/proxxx/config.toml (Linux) or
# ~/Library/Application Support/dev.proxxx.proxxx/config.toml (macOS)
./target/release/proxxx ls nodes
```

For VitePress docs:

```bash
cd docs && npm install && npx vitepress dev
# http://localhost:5173 — edit Markdown under docs/, hot reloads
```

## The gate (commit acceptance criteria)

Every commit on `main` passes an 8-stage local gate AND CI. Bypassing
either with `--no-verify` is owned by the bypasser. Stages:

| # | Stage | What | Roughly |
| - | --- | --- | --- |
| 0 | secret regression scan | Looks for tokens / passwords accidentally committed | <1 s |
| 1 | `cargo fmt --check` | Code style | ~3 s |
| 2 | `cargo clippy --release --all-targets` | Lints, deny tier (`unwrap_used`, `expect_used`, `panic`, `todo`, `await_holding_lock`) | 10–60 s |
| 3 | `cargo audit --deny warnings` | Supply-chain CVEs from `Cargo.lock` | 3–5 s |
| 4 | `cargo deny check` | License whitelist + banned crates + crates.io-only sources + wildcard ban | 2–4 s |
| 5 | `cargo test --release --all-targets` | All unit + integration + wiremock + proptest cases (~25 properties × 256 random cases) | 10–90 s |
| 6 | `tests/live/test_run.sh` | 87 read-only probes against a real PVE cluster | ~30 s |
| 7 | `tests/live/test_mutation.sh` | LXC 9999 lifecycle + cluster-level CRUD + QEMU 9998; opt-in QGA via `PROXXX_E2E_QGA_VMID=<vmid>` | ~60 s |

End-to-end wall time against a reachable cluster: **~340–480 s** (a
release build dominates; stages 6+7 themselves are ~100 s combined).

Hook setup:

```bash
git config core.hooksPath .githooks
chmod +x scripts/gate.sh .githooks/pre-commit .githooks/pre-push
cp tests/live/env.local.example tests/live/env.local
# fill in PROXXX_E2E_PVE_URL / TOKEN / NODE
```

Stages 6 + 7 require a reachable PVE cluster. If you don't have one,
**explicitly skip stages 6 + 7** in your PR description — a maintainer
will run them. Don't silently bypass.

## Live-cluster verification

The single most useful thing a contributor can do is run a change
against a real cluster and report results. The harness expects:

- A 1-3 node PVE cluster (lab is fine — `pve1`, `pve2`,
  `pve3`).
- VMID 9999 free for the LXC mutation lifecycle.
- VMID 9998 free for the QEMU mutation lifecycle (boots from an
  alpine ISO; auto-cleaned via `trap EXIT`).
- Optionally a QGA-enabled QEMU VM for the agent-required round-trip
  probes — set `PROXXX_E2E_QGA_VMID=<vmid>`. The env-file template
  carries the alpine apk one-liner to install qemu-guest-agent.

Findings format (paste in PR description):

```
Cluster: PVE 9.x.y, 3 nodes, ~16 GB RAM
Local gate: PASS=88 / FAIL=0 (read), PASS=53 / FAIL=0 (mutation+QGA)
Notes: <anything you saw that the harness didn't catch>
```

## Writing tests

- **Wiremock first**: every API client method gets at least one
  wiremock test covering the URL path + form encoding + at least
  one PVE-quirky shape (numerics-as-strings, hyphen-renamed fields,
  `null` where the schema implies a value, bool-from-int).
- **Live regression after**: when a live test surfaces a wire-shape
  bug, add a wiremock that pins the OBSERVED shape — not just the
  PVE-docs shape. Real PVE drifts from its docs.
- **Pre-flight risk variants**: any new destructive op MUST add at
  least one variant to `src/app/preflight.rs` if it raises a new
  class of risk; otherwise document why an existing variant covers it.
- **No `unwrap` in production paths**. `cargo clippy` enforces.
  Tests are relaxed via `cfg_attr(test, allow(...))`.

## Pull requests

- Branch from `main`, name like `feat/<short>` / `fix/<short>` /
  `docs/<short>`.
- Commits in **conventional style** (`feat:`, `fix:`, `docs:`,
  `test:`, `chore:`, `refactor:`); the gate enforces nothing about
  the message format but reviewers will ask you to rewrite if it
  reads as a noise.
- One concept per PR. Mixed concerns get split.
- Update `CHANGELOG.md` under `[Unreleased]` describing what changes
  for users.
- If the change touches a row in `pre-commit/01-feature-coverage.md`,
  update the row's status emoji + cite the test or live evidence.

## What gets refused (saving you time)

- PRs that bypass the gate (`--no-verify`, deleted hooks, soften
  clippy lints, skip stages without a stated reason).
- PRs that introduce a new dep larger than ~200 KB without a clear
  load-bearing justification — proxxx is "single static binary" by
  design.
- PRs that re-implement something PVE already does (e.g. a Perl-side
  algorithm); we shell out instead, per the architectural review.
- "Improvements" to error messages that swallow detail. Errors
  should remain typed and forensically useful.

## Scope reminder

Out-of-scope features (already declared design boundaries — won't
land):

- A web UI for proxxx itself (proxxx is terminal-only by design).
- Re-implementation of `pve-access-control` (we shell out via
  `pveum`).
- WebAuthn enrolment from the TUI (browser cert ceremony required).
- Single-file extraction from PBS archives (full archive only).

The full list lives in `README.md` → "Honest non-goals".

## Questions?

Open a discussion on GitHub or an issue. For security findings,
do not open a public issue — see `SECURITY.md`.
