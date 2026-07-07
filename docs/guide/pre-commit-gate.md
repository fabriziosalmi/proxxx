# Pre-commit gate

proxxx ships with an eight-stage gate that runs against the local source
tree AND a real Proxmox cluster. It is the single source of truth for
"ready to commit". There are **no skip flags**.

## Installing the gate

```sh
git config core.hooksPath .githooks
chmod +x scripts/gate.sh .githooks/pre-commit .githooks/pre-push
cargo install cargo-audit --locked
cargo install cargo-deny --locked
```

Both hooks call `scripts/gate.sh`. Defense in depth — even if you
`git commit --no-verify`, the push hook re-runs the gate before
anything reaches the remote.

## The eight stages

```
─── stage 0/8: secret regression scan ───
─── stage 1/8: cargo fmt --check ───
─── stage 2/8: cargo clippy --release --all-targets ───
─── stage 3/8: cargo audit --deny warnings ───
─── stage 4/8: cargo deny check ───
─── stage 5/8: cargo test --release --all-targets ───
─── stage 6/8: tests/live/test_run.sh ───
─── stage 7/8: tests/live/test_mutation.sh ───
✓ GATE PASSED in ~340–480s
```

| # | Stage | Time | Catches |
|---|---|---|---|
| 0 | secret regression scan | <1 s | inline secrets / tokens / private keys in staged files |
| 1 | `cargo fmt --all -- --check` | ~3 s | formatting drift |
| 2 | `cargo clippy --release --all-targets` | 10–60 s | lint policy: `unwrap_used`, `expect_used`, `panic`, `todo`, `await_holding_lock` are `deny` |
| 3 | `cargo audit --deny warnings` | 3–5 s | new CVEs in `Cargo.lock`, against a documented advisory ignore policy in `.cargo/audit.toml` |
| 4 | `cargo deny check` | 2–4 s | license whitelist, banned crates (`openssl`, `native-tls`, etc.), crates.io-only sources, wildcard ban — policy in `deny.toml` |
| 5 | `cargo test --release --all-targets` | 10–90 s | full unit + integration + wiremock + TUI snapshot suites (745 lib tests + 478 integration tests + ~25 proptest properties × 256 cases each) |
| 6 | `tests/live/test_run.sh` | ~30 s | 67 read-only probes against a live cluster |
| 7 | `tests/live/test_mutation.sh` | ~60 s | 34 mutation probes covering full lifecycle: LXC 9999 (create → start → snapshot → stop → delete), cluster-level CRUD across 8 of the 10 state families (pools / ACL / storage-defs / backup-jobs / firewall-cluster / notifications / HA rules / HA resources), QEMU 9998 from alpine ISO, opt-in QGA round-trips via `PROXXX_E2E_QGA_VMID=<vmid>` |

Stages 0–5 mirror CI exactly. Stages 6–7 require `pve1`,
`pve2`, `pve3` to be reachable — they are skipped on
machines without that environment, but they are **not** skipped on
the developer's primary workstation where the cluster lives.

## Why integration tests in the gate

A previous gate ran `cargo test --release --lib` only. That covered
the lib tests but missed the 478 tests in `tests/*.rs` that CI catches.
A developer could land a stale-mock regression locally, push, and CI
would fail in remote — wasting a round trip.

The gate now runs `--all-targets` so the local checkpoint is *exactly*
what CI sees. Stage 5 is intentionally identical to the
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

Stage 6 (read-only) runs every read CLI against the cluster:

```
[probe] ls nodes      [OK] exit=0
[probe] ls guests     [OK] exit=0
[probe] ls storage    [OK] exit=0
[probe] ha preview    [OK] exit=0
[probe] hw conflicts  [OK] exit=0
... 67 probes total, 0 fail ...
```

Stage 7 (mutation) runs the full lifecycle on the live cluster:
LXC 9999 (create → start → snapshot → stop → delete), cluster-level
CRUD across 8 of the 10 state families (pool / ACL grant / storage-defs /
backup-job / firewall-cluster alias+group+ipset / notifications
matcher / HA rules node-affinity+resource-affinity / HA resources —
the two PCI/USB passthrough-mapping families are not yet exercised
by the live harness),
QEMU 9998 booted from an alpine ISO, and — when
`PROXXX_E2E_QGA_VMID=<vmid>` is set — QGA agent-required round-trips
(file read / write / network probe / QMP sendkey). Every artifact
uses a `proxxx-mut-` prefix and a `trap EXIT` cleanup sweeps even
after a panic mid-test.

## Bypassing

The only way out is `git commit --no-verify` (or
`git push --no-verify`). The committer **owns the consequence** —
that is the explicit policy in `scripts/gate.sh`. CI will re-run
all eight stages and reject the push if anything is broken.

See [Bypass policy](/guide/bypass-policy) for when bypass is
acceptable.

## Trade-offs

- **Latency.** A commit-grade run is ~340–480 s end-to-end on the
  primary workstation (with the cluster reachable). Stages 0–5 alone
  are ~30–160 s. This is the price of "no surprises in CI".
- **Cluster requirement.** Stages 6–7 assume the test cluster is up.
  If it is not, the hook fails — by design. proxxx does not pretend
  the cluster is fine when it cannot reach it.
- **Strict mode.** There is no `--lite` mode. If you need to commit
  in a hurry, use `--no-verify` and accept the responsibility — the
  gate refuses to be partially-applied.
