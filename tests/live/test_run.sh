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
echo "Target: PVE cluster + PBS (configured via env.local)"
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
# Opt-in via PROXXX_E2E_PBS_ENABLE=1 — clusters without a PBS
# server configured (no `[pbs]` block in config.toml) skip cleanly
# instead of failing the gate. Same pattern as the QGA probes in
# test_mutation.sh.
if [ "${PROXXX_E2E_PBS_ENABLE:-0}" = "1" ]; then
    probe "pbs datastores" pbs datastores
fi

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

# ── Phase 11: PVE API expansion — read-only probes ──
# Each region has a corresponding row in
# pre-commit/01-feature-coverage.md; these probes hit the read side
# of those rows live. Mutation lifecycle (CRUD round-trips) lives
# in test_mutation.sh.

# Foundationals — pve-version, cluster-resources (with + without kind), pool
probe "pve-version"                    pve-version
probe "cluster-resources"              cluster-resources
probe "cluster-resources --kind vm"    cluster-resources --kind vm
probe "cluster-resources --kind storage" cluster-resources --kind storage
probe "cluster-resources --kind node"  cluster-resources --kind node
probe "pool list"                      pool list

# Cluster config + log
probe "cluster-config get"             cluster-config get
probe "cluster-log --max 5"            cluster-log --max 5

# Storage definitions (cluster-wide CRUD; read side)
probe "storage-defs list"              storage-defs list

# Backup-jobs scheduler (recurring vzdump; read side)
probe "backup-jobs list"               backup-jobs list

# Notifications (PVE 8+ native)
probe "notifications targets"          notifications targets
probe "notifications endpoint list"    notifications endpoint list
probe "notifications matcher list"     notifications matcher list

# Cluster mapping (PCI/USB device pools)
probe "cluster-mapping pci list"       cluster-mapping pci list
probe "cluster-mapping usb list"       cluster-mapping usb list

# Cluster firewall CRUD (read side)
probe "firewall-cluster alias list"    firewall-cluster alias list
probe "firewall-cluster group list"    firewall-cluster group list
probe "firewall-cluster ipset list"    firewall-cluster ipset list
probe "firewall-cluster options get"   firewall-cluster options get

# ACME accounts + plugins + directories
probe "acme account list"              acme account list
probe "acme plugin list"               acme plugin list
probe "acme directories"               acme directories

# HA status-current — the PVE-9-friendly path. `ha groups-legacy`
# deliberately hits `/cluster/ha/groups` and PVE 9 returns 500 because
# the path moved to `/cluster/ha/rules`. We don't probe legacy here:
# it's documented as PVE 8 only and a 500 is the contract on PVE 9.
probe "ha status-current"              ha status-current

# Cluster bootstrap (corosync membership / qdevice / totem)
probe "cluster-bootstrap nodes list"   cluster-bootstrap nodes list
probe "cluster-bootstrap totem"        cluster-bootstrap totem
# qdevice get may surface "no qdevice configured" cleanly — that's the contract
probe "cluster-bootstrap qdevice get"  cluster-bootstrap qdevice get

# Per-node node-system layer (read-only resources)
for node in $NODES; do
    probe "node-system $node dns get"          node-system "$node" dns get
    probe "node-system $node hosts get"        node-system "$node" hosts get
    probe "node-system $node time get"         node-system "$node" time get
    probe "node-system $node subscription get" node-system "$node" subscription get
    probe "node-system $node cert info"        node-system "$node" cert info
done

# Top-tier 80/20 grab-bag (read-only)
probe "metric-servers list"            metric-servers list
probe "access permissions"             access permissions
# url-info preflight requires a node to do the HEAD request from. Pick the
# first cluster node — content of the URL doesn't matter beyond reachable.
FIRST_NODE=$(echo "$NODES" | awk '{print $1}')
probe "url-info --node $FIRST_NODE" url-info --node "$FIRST_NODE" --url "https://cloud-images.ubuntu.com/jammy/20260320/SHA256SUMS"
for node in $NODES; do
    probe "tasks --node $node"        tasks --node "$node"
    probe "aplinfo list --node $node" aplinfo list --node "$node"
done

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
