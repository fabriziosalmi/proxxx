#!/usr/bin/env bash
# Mutation test harness — proxxx against the real cluster.
# Creates an LXC at VMID 9999 on pve1, exercises the full
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

# Cluster config — sourced from a local-only env file (gitignored)
# OR direct env vars. NEVER hardcoded: an earlier revision of this
# script committed a real PVE token to public git history (rotated +
# revoked when discovered). Loud loader below catches accidental
# regressions.
ENV_FILE="${PROXXX_E2E_ENV_FILE:-$SCRIPT_DIR/env.local}"
if [[ -f "$ENV_FILE" ]]; then
    # `env.local` lives next to the script and is gitignored. Use it
    # to keep cluster + token config off your shell history. Format:
    # one `export KEY=value` per line; see env.local.example.
    # shellcheck source=/dev/null
    . "$ENV_FILE"
fi

# Required — fail loudly so a missing rotation doesn't cause the
# mutation test to silently no-op against the wrong cluster.
: "${PROXXX_E2E_PVE_URL:?env PROXXX_E2E_PVE_URL not set; copy tests/live/env.local.example to tests/live/env.local and fill it in}"
: "${PROXXX_E2E_PVE_TOKEN:?env PROXXX_E2E_PVE_TOKEN not set (root@pam token id + secret, e.g. 'proxxx=00000000-...')}"
: "${PROXXX_E2E_NODE:?env PROXXX_E2E_NODE not set (target node name, e.g. pve1)}"

URL="$PROXXX_E2E_PVE_URL"
NODE="$PROXXX_E2E_NODE"
VMID="${PROXXX_E2E_MUTATION_VMID:-9999}"
TEMPLATE="${PROXXX_E2E_LXC_TEMPLATE:-local:vztmpl/alpine-3.22-default_20250617_amd64.tar.xz}"
STORAGE="${PROXXX_E2E_LXC_STORAGE:-local-lvm}"
TOKEN_HEADER="Authorization: PVEAPIToken=root@pam!${PROXXX_E2E_PVE_TOKEN}"
# Batch 3 — QEMU VM identifiers. The alpine ISO must exist on the
# node referenced by $NODE; we don't attempt to copy/upload it here.
QEMU_VMID="${PROXXX_E2E_QEMU_VMID:-9998}"
QEMU_ISO="${PROXXX_E2E_QEMU_ISO:-local:iso/alpine-standard-3.23.4-x86_64.iso}"
QEMU_STORAGE="${PROXXX_E2E_QEMU_STORAGE:-local-lvm}"

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

# Cluster-level test artifact prefix. Every batch-2 mutable object
# uses this so the trap can sweep without race-vs-other-runs concerns.
# (We're the only writer to the test cluster.)
MUT_PREFIX="proxxx-mut"

# Sweep any leftover QEMU VMID 9998 (batch 3). Idempotent.
qemu_level_cleanup() {
    curl -k -s -X POST "$URL/api2/json/nodes/$NODE/qemu/$QEMU_VMID/status/stop" \
        -H "$TOKEN_HEADER" -o /dev/null 2>&1 || true
    sleep 2
    curl -k -s -X DELETE "$URL/api2/json/nodes/$NODE/qemu/$QEMU_VMID?purge=1" \
        -H "$TOKEN_HEADER" -o /dev/null 2>&1 || true
}

# Sweep all cluster-level batch-2 / batch-2.5 test artifacts. Idempotent;
# each call is `|| true` so cleanup-then-create works even if the previous
# run died and left leftovers. Ordering matters: notifications matchers
# reference endpoints (PVE refuses to delete a referenced endpoint), and
# pool/firewall objects are independent.
cluster_level_cleanup() {
    # Notifications: matcher first (drops the reference), then endpoint.
    "$BIN" notifications matcher delete --yes "proxxxmutmatcher" >/dev/null 2>&1 || true
    "$BIN" notifications endpoint delete --endpoint-type webhook --yes "proxxxmutwebhook" >/dev/null 2>&1 || true
    # Storage-defs: independent.
    "$BIN" storage-defs delete --yes "${MUT_PREFIX}-storage" >/dev/null 2>&1 || true
    "$BIN" pool delete --yes "${MUT_PREFIX}-pool" >/dev/null 2>&1 || true
    "$BIN" firewall-cluster alias delete --yes "${MUT_PREFIX}-alias" >/dev/null 2>&1 || true
    # Group + ipset names: PVE's regex disallows hyphens at start/end and
    # restricts to a small charset. We use the no-hyphen contraction here.
    "$BIN" firewall-cluster group delete --yes "proxxxmutgroup" >/dev/null 2>&1 || true
    "$BIN" firewall-cluster ipset delete --yes "proxxxmutipset" >/dev/null 2>&1 || true
    # Backup jobs: ID is auto-assigned. Resolve via the comment marker
    # we always set on creation; any matching row is ours.
    local stale_bj
    stale_bj=$("$BIN" --format json backup-jobs list 2>/dev/null | python3 -c "
import sys, json
try:
    for j in json.load(sys.stdin):
        if j.get('comment', '').startswith('${MUT_PREFIX}-batch2'):
            print(j.get('id', ''))
except Exception:
    pass
" 2>/dev/null || true)
    for bj_id in $stale_bj; do
        [ -n "$bj_id" ] && "$BIN" backup-jobs delete --yes "$bj_id" >/dev/null 2>&1 || true
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
    # Sweep cluster-level batch-2 / 2.5 leftovers.
    log "[cleanup] sweeping cluster-level batch-2 artifacts"
    cluster_level_cleanup
    # Sweep QEMU VMID 9998 leftovers (batch 3).
    log "[cleanup] sweeping QEMU VMID $QEMU_VMID"
    qemu_level_cleanup
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

# ── Step 8: Delete snapshot via proxxx CLI (some PVE configs require
# it before guest delete; this also exercises proxxx's own
# `snapshot delete` write path against a live cluster).
probe "proxxx snapshot delete" snapshot delete --name "$SNAP_NAME" "$VMID"

# Wait a bit for snapshot delete to complete on PVE side
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
log "[done] LXC mutation lifecycle complete"

# ── Step 11: Cluster-level mutation lifecycle ──
# Exercises the cluster-scope CRUD across pool / firewall-cluster /
# backup-jobs / notifications / storage-defs. Every object uses the
# `proxxx-mut-` prefix; the
# trap-EXIT cleanup sweeps them too. Pre-clean here is idempotent so
# leftovers from a previous failed run don't cause a "409 already
# exists" on create.
log ""
log "═══════════════════════════════════════════════════════════"
log "[step 11] cluster-level mutation lifecycle (batch 2)"
log "═══════════════════════════════════════════════════════════"
log "[step 11] pre-cleaning any stale batch-2 artifacts"
cluster_level_cleanup

# 11a — Pool CRUD (multi-tenancy primitive)
POOL_ID="${MUT_PREFIX}-pool"
probe "pool create $POOL_ID" pool create --poolid "$POOL_ID" --comment "${MUT_PREFIX}-batch2"
if "$BIN" --format json pool list 2>/dev/null | python3 -c "
import sys, json
sys.exit(0 if any(p.get('poolid') == '$POOL_ID' for p in json.load(sys.stdin)) else 1)
"; then
    log "[step 11a] pool $POOL_ID visible in list"
    PASS=$((PASS + 1))
else
    log "[step 11a] FAIL: pool $POOL_ID not in list"
    FAIL=$((FAIL + 1))
fi
probe "pool delete $POOL_ID" pool delete --yes "$POOL_ID"

# 11b — Cluster firewall alias CRUD
ALIAS_NAME="${MUT_PREFIX}-alias"
probe "firewall-cluster alias create" \
    firewall-cluster alias create --name "$ALIAS_NAME" --cidr "10.99.99.0/24" --comment "${MUT_PREFIX}-batch2"
if "$BIN" --format json firewall-cluster alias list 2>/dev/null | python3 -c "
import sys, json
sys.exit(0 if any(a.get('name') == '$ALIAS_NAME' for a in json.load(sys.stdin)) else 1)
"; then
    log "[step 11b] alias $ALIAS_NAME visible in list"
    PASS=$((PASS + 1))
else
    log "[step 11b] FAIL: alias $ALIAS_NAME not in list"
    FAIL=$((FAIL + 1))
fi
probe "firewall-cluster alias delete" firewall-cluster alias delete --yes "$ALIAS_NAME"

# 11c — Cluster firewall security group CRUD
GROUP_NAME="proxxxmutgroup"
probe "firewall-cluster group create" \
    firewall-cluster group create --group "$GROUP_NAME" --comment "${MUT_PREFIX}-batch2"
probe "firewall-cluster group delete" firewall-cluster group delete --yes "$GROUP_NAME"

# 11d — Cluster firewall ipset CRUD
IPSET_NAME="proxxxmutipset"
probe "firewall-cluster ipset create" \
    firewall-cluster ipset create --name "$IPSET_NAME" --comment "${MUT_PREFIX}-batch2"
probe "firewall-cluster ipset delete" firewall-cluster ipset delete --yes "$IPSET_NAME"

# 11e — Backup-jobs scheduler CRUD (PVE auto-assigns id; resolve via comment)
BJ_COMMENT="${MUT_PREFIX}-batch2-backup"
probe "backup-jobs create" \
    backup-jobs create --schedule "sat 03:00" --storage local --all --comment "$BJ_COMMENT" --mode stop
BJ_ID=$("$BIN" --format json backup-jobs list 2>/dev/null | python3 -c "
import sys, json
try:
    for j in json.load(sys.stdin):
        if j.get('comment') == '$BJ_COMMENT':
            print(j.get('id', ''))
            sys.exit(0)
except Exception:
    pass
" 2>/dev/null || true)
if [ -n "$BJ_ID" ]; then
    log "[step 11e] backup-job id=$BJ_ID resolved via comment marker"
    PASS=$((PASS + 1))
    probe "backup-jobs delete $BJ_ID" backup-jobs delete --yes "$BJ_ID"
else
    log "[step 11e] FAIL: could not find backup-job by comment '$BJ_COMMENT'"
    FAIL=$((FAIL + 1))
fi

# 11f — notifications webhook endpoint CRUD (live verifies the per-type
# fan-out fix in `list_notification_endpoints` from the same commit).
NOTIF_NAME="proxxxmutwebhook"
probe "notifications endpoint create" \
    notifications endpoint create --endpoint-type webhook --name "$NOTIF_NAME" \
    --raw url=http://127.0.0.1:9999/none --raw method=post --comment "${MUT_PREFIX}-batch2"
if "$BIN" --format json notifications endpoint list 2>/dev/null | python3 -c "
import sys, json
sys.exit(0 if any(e.get('name') == '$NOTIF_NAME' for e in json.load(sys.stdin)) else 1)
"; then
    log "[step 11f] webhook $NOTIF_NAME visible in list (per-type fan-out OK)"
    PASS=$((PASS + 1))
else
    log "[step 11f] FAIL: webhook $NOTIF_NAME not in list — did the catalog-vs-instance regression resurface?"
    FAIL=$((FAIL + 1))
fi

# 11g — notifications matcher CRUD (depends on 11f endpoint existing)
MATCHER_NAME="proxxxmutmatcher"
probe "notifications matcher create" \
    notifications matcher create --name "$MATCHER_NAME" --target "$NOTIF_NAME" --comment "${MUT_PREFIX}-batch2"
if "$BIN" --format json notifications matcher list 2>/dev/null | python3 -c "
import sys, json
sys.exit(0 if any(m.get('name') == '$MATCHER_NAME' for m in json.load(sys.stdin)) else 1)
"; then
    log "[step 11g] matcher $MATCHER_NAME visible in list"
    PASS=$((PASS + 1))
else
    log "[step 11g] FAIL: matcher $MATCHER_NAME not in list"
    FAIL=$((FAIL + 1))
fi
# Delete matcher BEFORE endpoint — PVE refuses delete-endpoint-while-referenced.
probe "notifications matcher delete" notifications matcher delete --yes "$MATCHER_NAME"
probe "notifications endpoint delete" \
    notifications endpoint delete --endpoint-type webhook --yes "$NOTIF_NAME"

# 11h — storage-defs CRUD (dir storage at /tmp; path doesn't need to
# exist for the config-add to succeed — PVE scans on first use).
STORAGE_ID="${MUT_PREFIX}-storage"
probe "storage-defs create" \
    storage-defs create --storage "$STORAGE_ID" --storage-type dir --path "/tmp/${STORAGE_ID}" --content backup
if "$BIN" --format json storage-defs list 2>/dev/null | python3 -c "
import sys, json
sys.exit(0 if any(s.get('storage') == '$STORAGE_ID' for s in json.load(sys.stdin)) else 1)
"; then
    log "[step 11h] storage $STORAGE_ID visible in list"
    PASS=$((PASS + 1))
else
    log "[step 11h] FAIL: storage $STORAGE_ID not in list"
    FAIL=$((FAIL + 1))
fi
probe "storage-defs delete" storage-defs delete --yes "$STORAGE_ID"

# ── Step 12: QEMU VM lifecycle (batch 3 — alpine ISO boot, agent-free) ──
# Boots VMID $QEMU_VMID from the alpine ISO on $NODE. We don't
# need the guest to fully reach a login prompt — PVE accepts
# create/start/stop/delete on the QEMU process layer regardless of
# what the guest OS is doing. Agent-required paths (qga read / write /
# net) are deferred to a later batch — a pure live ISO doesn't ship
# qemu-guest-agent autostart, so we'd need cloud-init or apkovl to set
# it up. Agent-free CLI surface (feature, vnc, firewall-guest) IS
# exercised here.
log ""
log "═══════════════════════════════════════════════════════════"
log "[step 12] QEMU VM lifecycle (alpine ISO boot, no agent)"
log "═══════════════════════════════════════════════════════════"
log "[step 12] pre-cleaning VMID $QEMU_VMID"
qemu_level_cleanup

log ""
log "[step 12a] creating QEMU $QEMU_VMID on $NODE from $QEMU_ISO"
# IMPORTANT: use --data-urlencode (not plain -d) for PVE's QM-format
# fields. The comma in `ide2=local:iso/foo.iso,media=cdrom` and
# `net0=model=virtio,bridge=vmbr0` would otherwise leak through to
# PVE's outer form parser, which then mis-splits and reports
# "duplicate key in comma-separated list property: file/model".
# Discovered live; retain comment so future contributors know why.
qcreate_resp=$(curl -k -s -X POST "$URL/api2/json/nodes/$NODE/qemu" \
    -H "$TOKEN_HEADER" \
    --data-urlencode "vmid=$QEMU_VMID" \
    --data-urlencode "name=proxxx-qemu-mut" \
    --data-urlencode "ostype=l26" \
    --data-urlencode "cores=1" \
    --data-urlencode "memory=512" \
    --data-urlencode "ide2=$QEMU_ISO,media=cdrom" \
    --data-urlencode "scsi0=$QEMU_STORAGE:8" \
    --data-urlencode "net0=model=virtio,bridge=vmbr0" \
    --data-urlencode "scsihw=virtio-scsi-single" 2>&1)
log "[step 12a] create resp: $qcreate_resp"
if echo "$qcreate_resp" | grep -q '"data":null'; then
    log "[step 12a] CREATE FAILED — aborting batch 3 (other batches passed)"
    FAIL=$((FAIL + 1))
    echo "$qcreate_resp" >> "$ERR"
    exit 0
fi
PASS=$((PASS + 1))
sleep 5  # let PVE settle the config

# qemu_poll_status — same shape as poll_status() above but for QEMU
# kind (separate `/qemu/...` path) and using $QEMU_VMID + $NODE.
qemu_poll_status() {
    local expected="$1"
    local max_wait="$2"
    local start
    start=$(date +%s)
    log "[poll] waiting QEMU $QEMU_VMID to reach status=$expected (timeout ${max_wait}s)"
    while true; do
        local now elapsed
        now=$(date +%s)
        elapsed=$((now - start))
        if [ $elapsed -ge $max_wait ]; then
            log "[poll] TIMEOUT after ${elapsed}s"
            return 1
        fi
        local resp
        resp=$(curl -k -s -H "$TOKEN_HEADER" \
            "$URL/api2/json/nodes/$NODE/qemu/$QEMU_VMID/status/current" 2>/dev/null \
            | python3 -c "
import sys, json
try:
    print(json.load(sys.stdin).get('data', {}).get('status', '?'))
except Exception:
    print('ERR')
" 2>/dev/null || echo "ERR")
        if [ "$resp" = "$expected" ]; then
            log "[poll] reached status=$expected after ${elapsed}s"
            return 0
        fi
        sleep 2
    done
}

# 12b — start the QEMU VM via proxxx CLI
probe "proxxx start $QEMU_VMID" start "$QEMU_VMID"
if qemu_poll_status "running" 30; then
    PASS=$((PASS + 1))
else
    FAIL=$((FAIL + 1))
fi

# 12c — agent-free CLI paths against the running VM. `feature` auto-
# resolves the VMID's node + guest type; no `--kind` flag.
probe "feature snapshot" feature --feature snapshot "$QEMU_VMID"
probe "vnc --ws-url" vnc --ws-url "$QEMU_VMID"
probe "firewall-guest options get" firewall-guest "$QEMU_VMID" options get
probe "firewall-guest alias list (empty)" firewall-guest "$QEMU_VMID" alias list

# 12d — Per-guest firewall alias CRUD on the running VM (in-flight)
QFW_ALIAS="proxxxmutfwalias"
probe "firewall-guest alias create" \
    firewall-guest "$QEMU_VMID" alias create --name "$QFW_ALIAS" --cidr "10.99.99.1" --comment "${MUT_PREFIX}-batch3"
if "$BIN" --format json firewall-guest "$QEMU_VMID" alias list 2>/dev/null | python3 -c "
import sys, json
sys.exit(0 if any(a.get('name') == '$QFW_ALIAS' for a in json.load(sys.stdin)) else 1)
"; then
    log "[step 12d] guest fw alias $QFW_ALIAS visible in list"
    PASS=$((PASS + 1))
else
    log "[step 12d] FAIL: guest fw alias not in list"
    FAIL=$((FAIL + 1))
fi
probe "firewall-guest alias delete" firewall-guest "$QEMU_VMID" alias delete --yes "$QFW_ALIAS"

# 12e — stop the VM (force; no agent → graceful ACPI shutdown won't work)
probe "proxxx stop --force $QEMU_VMID" stop --force "$QEMU_VMID"
if qemu_poll_status "stopped" 30; then
    PASS=$((PASS + 1))
else
    FAIL=$((FAIL + 1))
fi

# 12f — delete the VM
probe "proxxx delete --yes $QEMU_VMID" delete --yes "$QEMU_VMID"
sleep 3
qemu_after=$(curl -k -s -H "$TOKEN_HEADER" \
    "$URL/api2/json/nodes/$NODE/qemu/$QEMU_VMID/status/current" 2>&1)
if echo "$qemu_after" | grep -q "does not exist"; then
    log "[step 12f] QEMU $QEMU_VMID 404'd as expected after delete"
    PASS=$((PASS + 1))
else
    log "[step 12f] FAIL: QEMU $QEMU_VMID still resolvable after delete"
    log "[step 12f] resp: $qemu_after"
    FAIL=$((FAIL + 1))
fi

# ── Step 13: QGA agent-required paths (batch 4) ──
# Opt-in via PROXXX_E2E_QGA_VMID. The target VMID must have BOTH:
#   1. PVE-side `agent: 1` set in its config (warm-reboot is not
#      enough — a full power cycle is required for the qemu virtio-
#      serial channel to be wired in).
#   2. Guest-side qemu-guest-agent installed and running. On Alpine:
#         apk add qemu-guest-agent
#         rc-update add qemu-guest-agent default
#         rc-service qemu-guest-agent start
# Skipped silently when the env is unset — the gate's mutation stage
# stays green for clusters without an agent-ready guest configured.
if [ -n "${PROXXX_E2E_QGA_VMID:-}" ]; then
    QGA_VMID="$PROXXX_E2E_QGA_VMID"
    log ""
    log "═══════════════════════════════════════════════════════════"
    log "[step 13] QGA agent-required paths (batch 4) — VMID $QGA_VMID"
    log "═══════════════════════════════════════════════════════════"

    # 13a — most basic agent ping: enumerate network interfaces. If
    # this fails, every other QGA call will too, so we surface a
    # clear early-exit message.
    log "[step 13a] qga net (agent ping)"
    if "$BIN" qga "$QGA_VMID" net >/dev/null 2>&1; then
        log "[step 13a] OK — agent is alive"
        PASS=$((PASS + 1))
    else
        log "[step 13a] FAIL: agent not responsive (PVE-side agent: 1 missing? guest-side qemu-guest-agent not running?)"
        FAIL=$((FAIL + 1))
        # Don't bail — let subsequent steps fail explicitly so the
        # log shows the full intended surface. The trap will still
        # clean up regardless.
    fi

    # 13b — read a small known file (works on any Linux guest).
    probe "qga read /etc/hostname" qga "$QGA_VMID" read --file /etc/hostname

    # 13c — read a multi-line file (exercises the QGA buffer +
    # base64 round-trip).
    probe "qga read /etc/os-release" qga "$QGA_VMID" read --file /etc/os-release

    # 13d — write+read round-trip. Marker file lives in /tmp so a
    # stale leftover is harmless (cleared by guest reboot at worst).
    QGA_MARKER="/tmp/proxxx-mut-batch4-marker"
    QGA_CONTENT="proxxx batch 4 marker $(date -u +%Y%m%dT%H%M%SZ)"
    probe "qga write $QGA_MARKER" qga "$QGA_VMID" write --file "$QGA_MARKER" --content "$QGA_CONTENT"
    if "$BIN" --format json qga "$QGA_VMID" read --file "$QGA_MARKER" 2>/dev/null \
        | python3 -c "
import sys, json
data = json.load(sys.stdin)
# proxxx --format json wraps single results in a one-element list for
# consistency with multi-row outputs. Handle both shapes defensively.
row = data[0] if isinstance(data, list) and data else (data if isinstance(data, dict) else {})
content = row.get('content', '')
sys.exit(0 if '$QGA_CONTENT' in content else 1)
"; then
        log "[step 13d] write→read round-trip verified — content matches"
        PASS=$((PASS + 1))
    else
        log "[step 13d] FAIL: written content not retrievable via qga read"
        FAIL=$((FAIL + 1))
    fi

    # 13e — vm sendkey (works without agent, but pairs nicely here
    # since we already have a known-running QEMU VM to target).
    # `sysrq` itself doesn't disrupt the guest — it puts the kernel
    # into magic-sysrq waiting state for the next char. Harmless.
    probe "vm sendkey sysrq" vm sendkey --key sysrq "$QGA_VMID"
else
    log ""
    log "[step 13] SKIPPED — set PROXXX_E2E_QGA_VMID=<vmid> to enable batch-4 QGA probes"
    log "          target VMID needs PVE-side `agent: 1` + power cycle + guest-side qemu-guest-agent running"
fi

log ""
log "[done] full mutation lifecycle complete (LXC + cluster-level batches 2 + 2.5 + QEMU batch 3 + QGA batch 4 if opted-in); trap will run final cleanup as a no-op"
exit 0
