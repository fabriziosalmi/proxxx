# Pre-commit gate

proxxx ships with a six-stage gate that runs against the local source
tree AND a real Proxmox cluster. It is the single source of truth for
"ready to commit". There are **no skip flags**.

## Installing the gate

```sh
git config core.hooksPath .githooks
chmod +x scripts/gate.sh .githooks/pre-commit .githooks/pre-push
cargo install cargo-audit --locked
```

Both hooks call `scripts/gate.sh`. Defense in depth — even if you
`git commit --no-verify`, the push hook re-runs the gate before
anything reaches the remote.

## The six stages

```
─── stage 1/6: cargo fmt --check ───
─── stage 2/6: cargo clippy --release --all-targets ───
─── stage 3/6: cargo audit --deny warnings ───
─── stage 4/6: cargo test --release --all-targets ───
─── stage 5/6: tests/live/test_run.sh ───
─── stage 6/6: tests/live/test_mutation.sh ───
✓ GATE PASSED in 84s
```

| # | Stage | Time | Catches |
|---|---|---|---|
| 1 | `cargo fmt --all -- --check` | ~3 s | formatting drift |
| 2 | `cargo clippy --all-targets` | 10–60 s | lint policy: `unwrap_used`, `expect_used`, `panic`, `todo`, `await_holding_lock` are `deny` |
| 3 | `cargo audit --deny warnings` | 3–5 s | new CVEs in `Cargo.lock`, against a documented advisory ignore policy in `.cargo/audit.toml` |
| 4 | `cargo test --release --all-targets` | 10–90 s | 380+ unit and integration tests across 11 binaries |
| 5 | `tests/live/test_run.sh` | ~10 s | 38 read-only probes against a live cluster |
| 6 | `tests/live/test_mutation.sh` | ~30 s | full lifecycle of LXC 9999 (create → start → snapshot → stop → delete) |

Stages 1–4 mirror CI exactly. Stages 5–6 require `pve-test-1`,
`pve-test-2`, `pve-test-3` to be reachable — they are skipped on
machines without that environment, but they are **not** skipped on
the developer's primary workstation where the cluster lives.

## Why integration tests in the gate

A previous gate ran `cargo test --release --lib` only. That covered
171 lib tests but missed 200+ tests in `tests/*.rs` that CI catches.
A developer could land a stale-mock regression locally, push, and CI
would fail in remote — wasting a round trip.

The gate now runs `--all-targets` so the local checkpoint is *exactly*
what CI sees. Stage 4 is intentionally identical to the
`.github/workflows/ci.yml#test` step.

## The audit policy

`.cargo/audit.toml` documents every advisory we accept, with:

1. The crate + version
2. The dependency path that pulls it in
3. The reason we accept it (with threat model justification)
4. The planned remediation

Entries without remediation are **debt, not policy** — that is the
declared rule. Today the file ignores three advisories, all in the
`russh` / `ratatui` transitive surface, all with planned
upstream-bumps tracked.

## What "live" means

Stage 5 (read-only) runs every read CLI against the cluster:

```
[probe] ls nodes      [OK] exit=0
[probe] ls guests     [OK] exit=0
[probe] ls storage    [OK] exit=0
[probe] ha preview    [OK] exit=0
[probe] hw conflicts  [OK] exit=0
... 38 probes total, 0 fail ...
```

Stage 6 (mutation) creates LXC 9999 on `pve-test-1`, exercises the
full lifecycle, and tears down via `trap EXIT` — a panic mid-test
still cleans up the guest.

## Bypassing

The only way out is `git commit --no-verify` (or
`git push --no-verify`). The committer **owns the consequence** —
that is the explicit policy in `scripts/gate.sh`. CI will re-run
all six stages and reject the push if anything is broken.

See [Bypass policy](/guide/bypass-policy) for when bypass is
acceptable.

## Trade-offs

- **Latency.** A commit-grade run is ~60–120 s end-to-end. This is
  the price of "no surprises in CI".
- **Cluster requirement.** Stages 5–6 assume the test cluster is up.
  If it is not, the hook fails — by design. proxxx does not pretend
  the cluster is fine when it cannot reach it.
- **Strict mode.** There is no `--lite` mode. If you need to commit
  in a hurry, use `--no-verify` and accept the responsibility — the
  gate refuses to be partially-applied.
