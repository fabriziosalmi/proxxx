#!/usr/bin/env bash
# proxxx pre-commit / pre-push gate — STRICT MODE.
#
# Runs the full verification pipeline against the local source tree AND
# the live test cluster. Designed to be the single source of truth for
# what "ready to commit" means. There are NO skip flags. The only way
# out is `git commit --no-verify` (or `git push --no-verify`) — and the
# committer owns the consequence.
#
# Stages (run in order, fail-fast):
#   0. secret regression scan      (~0.1s — grep tracked files for known
#                                   secret shapes; was ZERO until a PVE
#                                   token leaked inline in test_mutation.sh)
#   1. cargo fmt --check           (~3s)
#   2. cargo clippy --all-targets  (~10–60s, cache-dependent)
#   3. cargo audit                 (~3–5s — supply-chain CVE scan against
#                                   Cargo.lock; same tool CI runs)
#   4. cargo deny check            (~2–4s — supply-chain policy: license
#                                   whitelist, banned crates, source lock;
#                                   config in deny.toml, same tool CI runs)
#   5. cargo test --all-targets    (~10–90s — lib + tests/*.rs integration;
#                                   --lib alone misses 200+ tests that CI
#                                   would catch, leaving a false-pass.)
#   6. tests/live/test_run.sh      (~10s — read-only cluster probes)
#   7. tests/live/test_mutation.sh (~30s — LXC 9999 lifecycle)
#
# Coverage matrix:
#   pre-commit/01-feature-coverage.md   ← live-probe coverage (stages 6–7)
#   pre-commit/02-error-handling.md     ← unit-test invariants (stage 5)
#   pre-commit/03-security-invariants.md ← static + unit + RBAC E2E
#   pre-commit/04-resiliency-and-chaos.md ← signal/chaos handling

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Resolve the working tree the gate should test against:
#   - When invoked as a pre-commit hook (git sets GIT_DIR), the hook's
#     cwd already IS the working tree git is committing FROM. Use it
#     directly. This handles nested worktree layouts where SCRIPT_DIR
#     lives in the main checkout but the commit is happening in a
#     sibling worktree — naively asking `git -C "$SCRIPT_DIR" rev-parse
#     --show-toplevel` under hook env returns SCRIPT_DIR itself, and
#     `cd $ROOT` lands in scripts/ where there is no Cargo.lock; stage 3
#     `cargo audit` then fails with "Couldn't load Cargo.lock".
#   - Otherwise (manual `bash scripts/gate.sh`), derive from script
#     location.
# Either way, drop GIT_DIR / GIT_WORK_TREE so the cargo subcommands
# below see a clean env (each one re-derives its own context).
if [ -n "${GIT_DIR:-}" ]; then
    ROOT="$(pwd)"
else
    ROOT="$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel)"
fi
unset GIT_DIR GIT_WORK_TREE
cd "$ROOT"

T0=$(date +%s)

# Colours only when stdout is a TTY (so logs stay clean).
if [ -t 1 ]; then
    G='\033[0;32m'; R='\033[0;31m'; Y='\033[0;33m'; B='\033[1m'; N='\033[0m'
else
    G=''; R=''; Y=''; B=''; N=''
fi

stage() {
    local n="$1"; shift
    printf "\n${B}─── stage %s/7: %s ───${N}\n" "$n" "$*"
}

fail() {
    local stage_name="$1"; local rc="$2"
    local elapsed=$(( $(date +%s) - T0 ))
    printf "\n${R}✗ GATE FAILED at stage %s after %ss (exit=%s)${N}\n" \
        "$stage_name" "$elapsed" "$rc"
    printf "  bypass: ${Y}git commit --no-verify${N} (you own the consequence)\n"
    exit "$rc"
}

run() {
    local stage_name="$1"; shift
    "$@"
    local rc=$?
    if [ $rc -ne 0 ]; then
        fail "$stage_name" "$rc"
    fi
}

# ── Stage 0: secret regression scan ──
# A PVE root token leaked inline in tests/live/test_mutation.sh
# (see the env.local refactor + this gate stage). Cheap regex over
# the tracked file set is enough for the obvious shapes: PVE/PBS
# tokens (UUIDv4 after `=`), Telegram bot tokens (`bot_id:secret`
# colon form), and `password = "…"` TOML lines.
#
# Bypass with `git commit --no-verify` if you're committing a
# DELIBERATELY public sample value (e.g. doc snippets); add the
# false-positive shape to `_fp_grep` below if it recurs.
stage 0 "secret regression scan"
_secret_findings=$(
    git ls-files -z | xargs -0 grep -nIE '(PVEAPIToken=[^ "]*=[0-9a-f]{8}-[0-9a-f]{4}|bot[0-9]{8,}:[A-Za-z0-9_-]{30,}|^[a-z_]+_secret\s*=\s*"[0-9a-f-]{20,}")' 2>/dev/null \
    | grep -vE '(env\.local\.example|env\.example|README\.md:|\.example|test_(pbs|api)\.rs|MOCK|fake|0000|XXXX)' || true
)
if [ -n "$_secret_findings" ]; then
    printf "${R}secret-shape strings in tracked files:${N}\n%s\n" "$_secret_findings"
    fail secret-scan 1
fi

# ── Stage 1: format ──
stage 1 "cargo fmt --check"
run fmt cargo fmt --all -- --check

# ── Stage 2: lint ──
# Lint policy lives in Cargo.toml `[lints.clippy]` — `unwrap_used`,
# `expect_used`, `panic`, `todo` are deny-level (block); `pedantic` and
# `nursery` are warn-level (advisory). Don't override with `-D warnings`
# here — that would be stricter than the project's stated policy.
stage 2 "cargo clippy --release"
run clippy cargo clippy --release --all-targets

# ── Stage 3: supply-chain audit ──
# Mirrors CI exactly: `cargo audit --deny warnings` against Cargo.lock,
# with documented ignores in `.cargo/audit.toml`. Catching a vulnerable
# transitive dep at commit-time beats catching it post-push. If
# `cargo-audit` isn't installed, fail with a clear hint — don't silently
# skip (that defeats the rigor).
stage 3 "cargo audit --deny warnings"
if ! command -v cargo-audit >/dev/null 2>&1; then
    printf "${R}cargo-audit not installed.${N} install once with:\n"
    printf "  cargo install cargo-audit --locked\n"
    fail audit 127
fi
run audit cargo audit --deny warnings

# ── Stage 4: supply-chain policy (cargo-deny) ──
# Companion to stage 3 (cargo-audit). audit checks RustSec advisories
# against Cargo.lock; deny additionally enforces license whitelist
# (MIT/Apache-2.0/BSD/ISC/MPL-2.0 + curated exceptions), banned crates
# (openssl/native-tls — rustls-only posture), source locking (crates.io
# only, no git deps), and wildcard-version rejection. Config in
# `deny.toml`; every ignore/exception documented with dep path +
# why-accepted + remediation. Fail-fast like cargo-audit.
stage 4 "cargo deny check"
if ! command -v cargo-deny >/dev/null 2>&1; then
    printf "${R}cargo-deny not installed.${N} install once with:\n"
    printf "  cargo install cargo-deny --locked\n"
    fail deny 127
fi
run deny cargo deny check

# ── Stage 5: unit + integration tests ──
# `--all-targets` covers src/**/*.rs unit tests AND tests/*.rs integration
# tests. Running just `--lib` here would let regressions in tests/api_test.rs,
# tests/e2e_*.rs, etc. slip past the gate (CI would catch them, but only
# AFTER push — that's a false-pass on local commit).
stage 5 "cargo test --release --all-targets"
run tests cargo test --release --all-targets

# ── Stage 6: read-only live probes ──
stage 6 "tests/live/test_run.sh"
run test_run tests/live/test_run.sh

# ── Stage 7: live mutation lifecycle ──
stage 7 "tests/live/test_mutation.sh"
run test_mutation tests/live/test_mutation.sh

T1=$(date +%s)
printf "\n${G}✓ GATE PASSED in %ss${N}\n" "$((T1 - T0))"
