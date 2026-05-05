# Bypass policy

The pre-commit gate has no skip flags. The only way past it is
`git commit --no-verify` (or `git push --no-verify`). This page
documents when that is acceptable.

## TL;DR

Bypass is acceptable in three cases:

1. **The gate itself is broken** (e.g. the cluster is offline) and the
   commit you are making does not touch the gated surface.
2. **You are committing the gate fix** that will resume green builds.
3. **You are committing a `WIP` to a private branch** that you will
   force-push and rebase before opening a PR.

In every other case, fix the failure. The gate is the contract — a
green gate means a green CI means a deployable build.

## Why so strict

The gate exists because we tried lighter policies and they leaked
regressions:

- **`--lib` only** missed 200+ integration tests. Closed in audit #3.
- **No `cargo audit` locally** meant CVEs were caught only daily by
  the cron job. Closed by adding stage 3.
- **No live cluster probes** meant schema drift between PVE versions
  shipped silently. Closed by adding stage 5.
- **No mutation lifecycle** meant the destructive happy-path was only
  exercised by manual smoke. Closed by adding stage 6.

Every stage was added because something slipped through. Removing one
re-opens the corresponding hole.

## Acceptable bypass scenarios

### 1. Cluster is offline, commit does not touch live-surface

You are working on a doc change, the test cluster's UPS just kicked
on, and stage 5 fails because the API is unreachable. Acceptable:

```sh
git commit --no-verify -m "docs(quick-start): clarify token rotation"
git push --no-verify
```

CI will re-run all six stages. CI's stage 5/6 *do not* require a
live cluster (they check the binary builds and unit tests pass),
so CI will be green. The bypass was inert.

### 2. Committing the fix that makes the gate green again

The gate is broken because `cargo audit` flagged a new CVE you are
mitigating in this very commit. Bypass to land the mitigation:

```sh
git commit --no-verify -m "audit: mitigate RUSTSEC-2026-0042 by bumping foo to 1.4"
```

The next commit will pass without bypass.

### 3. Private WIP, will be rebased

You are pushing a feature branch to your fork for backup or to share
mid-work with a collaborator. The branch will be force-pushed and
rebased onto a clean commit before the PR opens.

```sh
git commit --no-verify -m "WIP: serial console buffer reflow"
git push --no-verify origin feature/serial-buffer
```

You **must** rebase to a green-gate state before opening the PR.

## Unacceptable bypass scenarios

- **"It's just a tiny fix"** — the gate runs in 60 s. Tiny fixes are
  exactly the cases where a stale cache lets a regression through
  unnoticed. Pay the 60 s.
- **"clippy is being pedantic"** — clippy's `deny` tier is `unwrap_used`,
  `expect_used`, `panic`, `todo`, `await_holding_lock`. None of these are
  pedantic — every one of them was added after a real incident. Either
  fix the code or add `#[allow(clippy::X)]` with a justifying comment.
- **"I'll fix it in the next commit"** — no, you won't. Leaving the gate
  red breaks the contract for everyone else who runs `git pull` after you.

## Audit trail

Every bypass leaves a trail in `git reflog`. The author is on record
in the commit, and the merge commit on `main` is reviewable. If a
regression lands via bypass, `git log --no-verify` is searchable:

```sh
git log --all --pretty=format:"%h %ae %s" | grep -i 'wip\|--no-verify'
```

(In practice, look for non-conventional commit messages — they are the
breadcrumbs that someone bypassed.)

## When the gate evolves

Adding a stage is straightforward (extend `scripts/gate.sh`). Removing
one requires explicit justification in CHANGELOG and a documented
threat-model argument for why the corresponding hole is now closed
elsewhere.

The gate is the contract. Treat it that way.
