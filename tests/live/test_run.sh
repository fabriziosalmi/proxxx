#!/usr/bin/env bash
# Live cluster test harness — proxxx against the real cluster.
# Logs all output to test_run.log and failures to test_run_errors.log.
# Runs from any cwd; defaults BIN to the repo's release build and writes
# logs alongside this script unless LOG_DIR overrides.

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel)"
BIN="${BIN:-$ROOT/target/release/proxxx}"
LOG_DIR="${LOG_DIR:-$SCRIPT_DIR}"
LOG="$LOG_DIR/test_run.log"
ERR="$LOG_DIR/test_run_errors.log"

# proxxx on macOS reads its config from
#   ~/Library/Application Support/dev.proxxx.proxxx/config.toml
# (per `directories::ProjectDirs::from("dev","proxxx","proxxx")`).
# We assume the caller has already written it pointing at the test
# cluster (see this file in /tmp/config.toml.bak for the snapshot).

: > "$LOG"
: > "$ERR"

PASS=0
FAIL=0

probe() {
    local label="$1"; shift
    {
        echo "═══════════════════════════════════════════════════════════"
        echo "[probe] $label"
        echo "[cmd]   $BIN $*"
        echo "═══════════════════════════════════════════════════════════"
    } | tee -a "$LOG"

    local out
    out=$(timeout 30 "$BIN" "$@" 2>&1)
    local rc=$?

    echo "$out" >> "$LOG"
    if [ $rc -eq 0 ]; then
        echo "[OK   ] exit=$rc" | tee -a "$LOG"
        PASS=$((PASS + 1))
    else
        echo "[FAIL ] exit=$rc" | tee -a "$LOG"
        FAIL=$((FAIL + 1))
        {
            echo
            echo "─── FAIL: $label (exit=$rc) ───"
            echo "[cmd] $BIN $*"
            echo "$out"
        } >> "$ERR"
    fi
    echo | tee -a "$LOG"
}

echo "═══════════════════════════════════════════════════════════"
echo "proxxx live cluster test run — $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "Target: pve-cluster (192.168.0.122-124) + pve-pbs (.125)"
echo "═══════════════════════════════════════════════════════════" | tee -a "$LOG"

# Discover the actual node names from the cluster (don't assume).
NODES=$(timeout 10 "$BIN" --format json ls nodes 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); print(' '.join(n['node'] for n in d))" 2>/dev/null)
echo "Discovered nodes: $NODES" | tee -a "$LOG"

# ── Phase 1: read-only inventory (table) ──
probe "ls nodes"            ls nodes
probe "ls guests"           ls guests
probe "ls storage"          ls storage
probe "ls nodes (alias get)" get nodes

# ── Phase 2: JSON contract ──
probe "ls nodes --format json"   --format json ls nodes
probe "ls guests --format json"  --format json ls guests
probe "ls storage --format json" --format json ls storage

# ── Phase 3: per-node read-only ──
for node in $NODES; do
    probe "hw pci --node $node"       hw pci --node "$node"
    probe "hw usb --node $node"       hw usb --node "$node"
    probe "hw conflicts --node $node" hw conflicts --node "$node"
    probe "replication status --node $node" replication status --node "$node"
done

# ── Phase 4: cluster-level introspection ──
probe "ha groups"      ha groups
probe "ha resources"   ha resources
probe "ha status"      ha status
probe "replication jobs"   replication jobs

# ── Phase 5: access control ──
probe "access acl"     access acl
probe "access users"   access users
probe "access groups"  access groups
probe "access roles"   access roles
probe "access realms"  access realms
probe "token list root@pam" token list "root@pam"

# ── Phase 6: PBS browse ──
probe "pbs datastores" pbs datastores

# ── Phase 7: ISO library ──
probe "iso list"               iso list
probe "iso list --format json" --format json iso list

# ── Phase 8: search ──
probe "search alpine"       search alpine
probe "search root --limit 5" search root --limit 5

# ── Phase 9: read-only patch / alerts ──
probe "patch plan" patch plan
probe "alerts test --route ntfy:proxxx-test" alerts test --route "ntfy:proxxx-test" --severity warning || true

# ── Phase 10: format consistency (json/table/plain — yaml NOT supported) ──
probe "ls guests --format plain" --format plain ls guests
probe "ls guests --format table" --format table ls guests

# ── Summary ──
{
    echo
    echo "═══════════════════════════════════════════════════════════"
    echo "Summary: PASS=$PASS  FAIL=$FAIL"
    echo "Log:    $LOG"
    echo "Errors: $ERR"
    echo "═══════════════════════════════════════════════════════════"
} | tee -a "$LOG"

exit $FAIL
