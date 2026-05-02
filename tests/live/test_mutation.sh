#!/usr/bin/env bash
# Mutation test harness — proxxx against the real cluster.
# Creates an LXC at VMID 9999 on pve-test-1, exercises the full
# lifecycle, then tears down. RAII via `trap EXIT`.
# Runs from any cwd; defaults BIN to the repo's release build and writes
# logs alongside this script unless LOG_DIR overrides.

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel)"
BIN="${BIN:-$ROOT/target/release/proxxx}"
LOG_DIR="${LOG_DIR:-$SCRIPT_DIR}"
LOG="$LOG_DIR/test_mutation.log"
ERR="$LOG_DIR/test_mutation_errors.log"

# Cluster details (from test_env.md).
NODE="pve-test-1"
VMID=9999
TEMPLATE="local:vztmpl/alpine-3.22-default_20250617_amd64.tar.xz"
STORAGE="local-lvm"
URL="https://192.168.0.122:8006"
TOKEN_HEADER="Authorization: PVEAPIToken=root@pam!proxxx=a754b304-6d19-40f4-bdfe-0087299b9e2b"

: > "$LOG"
: > "$ERR"

PASS=0
FAIL=0

log() {
    echo "$@" | tee -a "$LOG"
}

probe() {
    local label="$1"; shift
    {
        echo "═══════════════════════════════════════════════════════════"
        echo "[probe] $label"
        echo "[cmd]   $BIN $*"
        echo "═══════════════════════════════════════════════════════════"
    } | tee -a "$LOG"

    local out
    out=$(timeout 60 "$BIN" "$@" 2>&1)
    local rc=$?

    echo "$out" >> "$LOG"
    if [ $rc -eq 0 ]; then
        echo "[OK   ] exit=$rc" | tee -a "$LOG"
        PASS=$((PASS + 1))
        return 0
    else
        echo "[FAIL ] exit=$rc" | tee -a "$LOG"
        FAIL=$((FAIL + 1))
        {
            echo
            echo "─── FAIL: $label (exit=$rc) ───"
            echo "[cmd] $BIN $*"
            echo "$out"
        } >> "$ERR"
        return 1
    fi
}

# poll_status <expected_status> <timeout_secs>
# Returns 0 when the guest reaches the expected status, 1 on timeout.
poll_status() {
    local expected="$1"
    local max_wait="$2"
    local label="${3:-status check}"
    local start=$(date +%s)
    local last=""
    log "[poll] waiting for VMID $VMID to reach status=$expected (timeout ${max_wait}s)"
    while true; do
        local now=$(date +%s)
        local elapsed=$((now - start))
        if [ $elapsed -ge $max_wait ]; then
            log "[poll] TIMEOUT after ${elapsed}s — last seen: $last"
            return 1
        fi
        # JSON output → pluck status field. Single-element array.
        local resp
        resp=$("$BIN" --format json ls guests 2>/dev/null | python3 -c "
import sys, json
data = json.load(sys.stdin)
for g in data:
    if g.get('vmid') == $VMID:
        print(g.get('status', '?'))
        sys.exit(0)
print('NOT_FOUND')
" 2>/dev/null || echo "ERR")
        last="$resp"
        if [ "$resp" = "$expected" ]; then
            log "[poll] reached status=$expected after ${elapsed}s"
            return 0
        fi
        if [ "$expected" = "GONE" ] && [ "$resp" = "NOT_FOUND" ]; then
            log "[poll] guest 404'd after ${elapsed}s"
            return 0
        fi
        sleep 2
    done
}

# Teardown — runs on EXIT regardless of how we got here.
cleanup() {
    log ""
    log "═══════════════════════════════════════════════════════════"
    log "[cleanup] RAII teardown for VMID $VMID"
    log "═══════════════════════════════════════════════════════════"
    # Force-stop (silently OK if already stopped or 404).
    curl -k -s -X POST "$URL/api2/json/nodes/$NODE/lxc/$VMID/status/stop" \
        -H "$TOKEN_HEADER" -d "forceStop=1" -o /dev/null 2>&1 || true
    sleep 2
    # Delete (force=1 to skip confirmation, purge=1 for storage).
    local del_resp
    del_resp=$(curl -k -s -X DELETE "$URL/api2/json/nodes/$NODE/lxc/$VMID?force=1&purge=1" \
        -H "$TOKEN_HEADER" 2>&1)
    log "[cleanup] DELETE resp: $del_resp"
    # Final summary.
    log ""
    log "═══════════════════════════════════════════════════════════"
    log "Mutation summary: PASS=$PASS  FAIL=$FAIL"
    log "Log:    $LOG"
    log "Errors: $ERR"
    log "═══════════════════════════════════════════════════════════"
}
trap cleanup EXIT

log "═══════════════════════════════════════════════════════════"
log "proxxx mutation test run — $(date -u +%Y-%m-%dT%H:%M:%SZ)"
log "Target: VMID $VMID on $NODE (${URL})"
log "═══════════════════════════════════════════════════════════"

# ── Step 0: Verify VMID is free ──
log ""
log "[step 0] checking VMID $VMID is free"
existing=$("$BIN" --format json ls guests 2>/dev/null | python3 -c "
import sys, json
data = json.load(sys.stdin)
for g in data:
    if g.get('vmid') == $VMID:
        print('OCCUPIED')
        sys.exit(0)
print('FREE')
" 2>/dev/null || echo "ERR")
log "[step 0] VMID $VMID = $existing"
if [ "$existing" = "OCCUPIED" ]; then
    log "[step 0] VMID is occupied — running pre-cleanup"
    cleanup
    log "[step 0] re-checking after cleanup"
    sleep 3
fi

# ── Step 1: Create LXC via raw API (proxxx has no `create` subcommand) ──
log ""
log "[step 1] creating LXC $VMID on $NODE from $TEMPLATE"
create_resp=$(curl -k -s -X POST "$URL/api2/json/nodes/$NODE/lxc" \
    -H "$TOKEN_HEADER" \
    -d "vmid=$VMID" \
    -d "ostemplate=$TEMPLATE" \
    -d "hostname=proxxx-mutation-test" \
    -d "memory=256" \
    -d "swap=0" \
    -d "rootfs=$STORAGE:1" \
    -d "unprivileged=1" \
    -d "start=0" \
    -d "password=proxxx-test-$RANDOM" 2>&1)
log "[step 1] create resp: $create_resp"
if echo "$create_resp" | grep -q '"data":null'; then
    log "[step 1] CREATE FAILED — aborting"
    FAIL=$((FAIL + 1))
    echo "$create_resp" >> "$ERR"
    exit 1
fi
PASS=$((PASS + 1))

# ── Step 2: Poll until LXC visible + stopped ──
if ! poll_status "stopped" 60 "post-create"; then
    log "[step 2] FAIL: LXC didn't reach stopped within 60s"
    FAIL=$((FAIL + 1))
    exit 1
fi
PASS=$((PASS + 1))

# ── Step 3: Start via proxxx CLI ──
probe "proxxx start $VMID" start "$VMID"

# ── Step 4: Poll until running ──
if poll_status "running" 30 "post-start"; then
    PASS=$((PASS + 1))
else
    FAIL=$((FAIL + 1))
fi

# ── Step 5: Snapshot via raw API (proxxx snapshot create works too) ──
SNAP_NAME="proxxx-mut-$RANDOM"
log ""
log "[step 5] creating snapshot $SNAP_NAME"
probe "proxxx snapshot create" snapshot create --name "$SNAP_NAME" "$VMID"

# Wait for snapshot to appear
sleep 5

# Verify snapshot via raw API
snap_check=$(curl -k -s "$URL/api2/json/nodes/$NODE/lxc/$VMID/snapshot" \
    -H "$TOKEN_HEADER" 2>&1)
if echo "$snap_check" | grep -q "$SNAP_NAME"; then
    log "[step 5] snapshot $SNAP_NAME visible in /snapshot listing"
    PASS=$((PASS + 1))
else
    log "[step 5] snapshot NOT visible — listing: $snap_check"
    FAIL=$((FAIL + 1))
fi

# ── Step 6: Stop via proxxx CLI ──
probe "proxxx stop --force $VMID" stop --force "$VMID"

# ── Step 7: Poll until stopped ──
if poll_status "stopped" 30 "post-stop"; then
    PASS=$((PASS + 1))
else
    FAIL=$((FAIL + 1))
fi

# ── Step 8: Delete snapshot before delete (some PVE configs require it) ──
log ""
log "[step 8] deleting snapshot $SNAP_NAME"
del_snap=$(curl -k -s -X DELETE "$URL/api2/json/nodes/$NODE/lxc/$VMID/snapshot/$SNAP_NAME" \
    -H "$TOKEN_HEADER" 2>&1)
log "[step 8] delete-snapshot resp: $del_snap"

# Wait a bit for snapshot delete to complete
sleep 5

# ── Step 9: Delete LXC via proxxx CLI ──
probe "proxxx delete --yes $VMID" delete --yes "$VMID"

# ── Step 10: Poll until 404 ──
if poll_status "GONE" 30 "post-delete"; then
    PASS=$((PASS + 1))
else
    FAIL=$((FAIL + 1))
fi

log ""
log "[done] mutation lifecycle complete; trap will run final cleanup as a no-op"
exit 0
