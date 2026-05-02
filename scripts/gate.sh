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
#   1. cargo fmt --check           (~3s)
#   2. cargo clippy -D warnings    (~10–60s, cache-dependent)
#   3. cargo test --release --lib  (~5–30s, cache-dependent)
#   4. tests/live/test_run.sh      (~10s — read-only cluster probes)
#   5. tests/live/test_mutation.sh (~30s — LXC 9999 lifecycle)
#
# Coverage matrix:
#   pre-commit/01-feature-coverage.md   ← live-probe coverage (stages 4–5)
#   pre-commit/02-error-handling.md     ← unit-test invariants (stage 3)
#   pre-commit/03-security-invariants.md ← static + unit + RBAC E2E
#   pre-commit/04-resiliency-and-chaos.md ← signal/chaos handling

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel)"
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
    printf "\n${B}─── stage %s/5: %s ───${N}\n" "$n" "$*"
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

# ── Stage 3: unit tests ──
stage 3 "cargo test --release --lib"
run tests cargo test --release --lib

# ── Stage 4: read-only live probes ──
stage 4 "tests/live/test_run.sh"
run test_run tests/live/test_run.sh

# ── Stage 5: live mutation lifecycle ──
stage 5 "tests/live/test_mutation.sh"
run test_mutation tests/live/test_mutation.sh

T1=$(date +%s)
printf "\n${G}✓ GATE PASSED in %ss${N}\n" "$((T1 - T0))"
