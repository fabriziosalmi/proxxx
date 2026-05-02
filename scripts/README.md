# proxxx pre-commit gate

A single, strict verification pipeline that runs on every `git commit`
AND `git push`. There are no skip flags. The only escape is
`git commit --no-verify` (or `git push --no-verify`) — and the
committer owns the consequence.

## What the gate enforces

| Stage | What | ~Time | Source of truth |
|---|---|---|---|
| 1 | `cargo fmt --check` | 1s | rustfmt defaults |
| 2 | `cargo clippy --release --all-targets` | 10–60s | `[lints.clippy]` in Cargo.toml |
| 3 | `cargo test --release --lib` | 5–30s | `cargo test` (171 unit tests) |
| 4 | `tests/live/test_run.sh` | 10s | 38 read-only probes against the live cluster |
| 5 | `tests/live/test_mutation.sh` | 30s | LXC 9999 lifecycle: create → start → snap → stop → delete |

Total cold: ~3 min. Total warm (cargo cache hot): ~60s.

The four `pre-commit/0N-*.md` matrices document **what** is verified;
this gate is **how** it's verified. The matrices are human-readable
trackers — the gate is the executable contract.

## Bootstrap

```sh
git config core.hooksPath .githooks
chmod +x scripts/gate.sh .githooks/pre-commit .githooks/pre-push
```

Then verify the gate is reachable:

```sh
scripts/gate.sh
```

## Cluster prerequisites

Stages 4 & 5 require a live Proxmox cluster reachable at the URL in
`~/Library/Application Support/dev.proxxx.proxxx/config.toml` (macOS
path; on Linux: `~/.config/proxxx/config.toml`).

The token must be `Administrator` at `/`:

```sh
ssh root@<any-pve-node> \
  'pveum acl modify / --tokens "root@pam!proxxx" --roles Administrator'
```

### PBS prerequisite (stage 4 currently includes `pbs datastores`)

Proxmox Backup Server keeps a separate user database from PVE. The
PVE token does NOT exist on the PBS host — the PBS probe fails with
`401 Unauthorized` until you create a PBS-side token:

```sh
ssh root@<pbs-host> 'proxmox-backup-manager user create proxxx@pbs --password <choose>'
ssh root@<pbs-host> 'proxmox-backup-manager user generate-token proxxx@pbs proxxx'
# → copy the returned secret into [profiles.<name>.pbs] token_secret in config.toml
ssh root@<pbs-host> 'proxmox-backup-manager acl update / DatastoreAudit --auth-id proxxx@pbs!proxxx'
```

## Bypassing (and when it's legitimate)

```sh
git commit --no-verify   # bypasses pre-commit; pre-push still runs
git push --no-verify     # bypasses pre-push too — last line of defence
```

Legitimate use cases:

- The cluster is intentionally offline (e.g. teardown during dev).
- Emergency hotfix that must land before the gate can be brought green.
- A WIP commit on a private branch that you'll squash before push.

NOT legitimate:

- "It takes too long" → use the cargo cache; warm runs are ~60s.
- "Clippy is annoying" → fix the lint or change the policy in Cargo.toml.
- "The cluster is flaky" → fix the flake; flakiness is a real signal.

## Disabling

Permanent (rare; e.g. CI runs the gate instead):

```sh
git config --unset core.hooksPath
```

Single commit (use sparingly):

```sh
git commit --no-verify
```
