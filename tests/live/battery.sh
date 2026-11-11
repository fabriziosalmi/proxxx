#!/usr/bin/env bash
# Pre-tag live battery (#543): every live suite in order, one summary line
# each, and a read-only inventory of the cluster taken before and after.
#
# Usage:
#   tests/live/battery.sh                 # all suites + inventory comparison
#   tests/live/battery.sh --no-inventory  # suites only
#
# MUTATING: test_mutation.sh, the state and reconcile suites and the cargo
# e2e suites create, change and delete real guests and settings. Run it
# against a lab cluster only, never a production one.
#
# Logs and the summary go to LOG_DIR (default: tests/live/battery-out/,
# gitignored). Without BIN, the release build is made first and used; the
# cargo suites build their own. Exit code: the number of suites that exited
# non-zero, plus one when the inventory differs.

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel)"
build_bin=0
[[ -z "${BIN:-}" ]] && build_bin=1
export BIN="${BIN:-$ROOT/target/release/proxxx}"
LOG_DIR="${LOG_DIR:-$SCRIPT_DIR/battery-out}"
SUMMARY="$LOG_DIR/summary.txt"

inventory=1
for arg in "$@"; do
    case "$arg" in
        --no-inventory) inventory=0 ;;
        -h|--help) sed -n '2,15p' "$0"; exit 0 ;;
        *) echo "battery.sh: unknown argument $arg" >&2; exit 64 ;;
    esac
done

# shellcheck source=tests/live/lib.sh
. "$SCRIPT_DIR/lib.sh"
# Export everything the env file sets: the cargo suites read it from the
# environment.
set -a
live_load_env
set +a

mkdir -p "$LOG_DIR"
: > "$SUMMARY"
failures=0

say() { echo "$*" | tee -a "$SUMMARY"; }

# counts LOG: "pass=N fail=M" from the last PASS=/FAIL= line of a shell suite
# or the last `test result:` line of a cargo suite, plus "skipped=K": the
# cargo suites' env-gated early returns (`[e2e] PROXXX_E2E_ENABLE != 1 —
# skipping`), which cargo reports as passed.
counts() {
    local log="$1" line pass fail skipped
    line="$(grep -aE 'PASS=[0-9]+ +FAIL=[0-9]+' "$log" | tail -1)"
    if [[ -n "$line" ]]; then
        pass="$(sed -E 's/.*PASS=([0-9]+).*/\1/' <<<"$line")"
        fail="$(sed -E 's/.*FAIL=([0-9]+).*/\1/' <<<"$line")"
        echo "pass=$pass fail=$fail"
        return
    fi
    line="$(grep -aE '^test result:' "$log" | tail -1)"
    if [[ -n "$line" ]]; then
        pass="$(sed -E 's/.* ([0-9]+) passed.*/\1/' <<<"$line")"
        fail="$(sed -E 's/.* ([0-9]+) failed.*/\1/' <<<"$line")"
        skipped="$(grep -acE '!= 1 .*skipping$' "$log")"
        echo "pass=$pass fail=$fail skipped=$skipped"
        return
    fi
    echo "no counts"
}

# run NAME CMD...: run one suite, log to LOG_DIR/NAME.log, add its line.
run() {
    local name="$1"; shift
    local log="$LOG_DIR/$name.log" t0 rc
    t0="$(date +%s)"
    "$@" > "$log" 2>&1
    rc=$?
    [[ $rc -ne 0 ]] && failures=$((failures + 1))
    say "$(printf '%-28s rc=%-3s %4ss  %s' "$name" "$rc" "$(( $(date +%s) - t0 ))" "$(counts "$log")")"
}

if [[ $build_bin -eq 1 ]]; then
    (cd "$ROOT" && cargo build --locked --release) > "$LOG_DIR/build.log" 2>&1 \
        || { say "battery: cargo build --release failed, see $LOG_DIR/build.log"; exit 1; }
fi

say "battery: $($BIN --version 2>/dev/null || echo "no binary at $BIN") at $(git -C "$ROOT" rev-parse --short HEAD)"

if [[ $inventory -eq 1 ]]; then
    rm -rf "$LOG_DIR/inventory-before" "$LOG_DIR/inventory-after"
    "$SCRIPT_DIR/inventory.sh" "$LOG_DIR/inventory-before" > "$LOG_DIR/inventory-before.log" 2>&1 \
        || say "inventory before: $(tail -1 "$LOG_DIR/inventory-before.log")"
fi

for suite in test_run test_mutation test_state_mappings test_state_ha_rules test_reconcile_converge; do
    run "$suite" bash "$SCRIPT_DIR/$suite.sh"
done
run setup_demo_check bash "$SCRIPT_DIR/setup_demo.sh" --check

# cargo_suite TEST: one `#[ignore]`d live suite, with every gate open.
cargo_suite() {
    (cd "$ROOT" && PROXXX_E2E_ENABLE=1 PROXXX_E2E_FEATURE_COVERAGE_ENABLE=1 \
        PROXXX_E2E_ALLOW_DELETE=1 \
        cargo test --locked --release --test "$1" -- --ignored --test-threads=1 --nocapture)
}
for t in feature_coverage_live ssh_live e2e_beta e2e_alpha; do
    run "cargo_$t" cargo_suite "$t"
done

if [[ $inventory -eq 1 ]]; then
    "$SCRIPT_DIR/inventory.sh" "$LOG_DIR/inventory-after" > "$LOG_DIR/inventory-after.log" 2>&1 \
        || say "inventory after: $(tail -1 "$LOG_DIR/inventory-after.log")"
    if diff -r "$LOG_DIR/inventory-before" "$LOG_DIR/inventory-after" > "$LOG_DIR/inventory.diff"; then
        say "inventory: identical before and after"
    else
        failures=$((failures + 1))
        say "inventory: DIFFERS, see $LOG_DIR/inventory.diff ($(wc -l < "$LOG_DIR/inventory.diff" | tr -d ' ') lines)"
    fi
fi

say "battery: $failures failing (suites with a non-zero exit, plus an inventory difference)"
exit "$failures"
