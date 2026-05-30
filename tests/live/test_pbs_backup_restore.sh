#!/usr/bin/env bash
# PBS backup → list → restore live e2e — closes the #140 coverage gap.
#
# Drives a full PBS round-trip THROUGH proxxx against the test PVE
# cluster + the test PBS (`pve-pbs`, datastore `test-store`), using an
# existing connection profile (default `pvetest`) that already carries
# the PVE token AND the `[profiles.NAME.pbs]` block. No config swap.
#
#   ① pbs ping                  — PBS reachable + auth OK (ok:true)
#   ② pbs datastores            — the configured datastore is listed
#                                 (regression guard for the PBS-4.x
#                                 `comment:null` deserialize crash fixed
#                                 alongside this script)
#   ③ backup <vmid> --wait      — vzdump the throwaway guest to the
#                                 PBS-backed PVE storage (one-shot)
#   ④ pbs snapshots             — a FRESH snapshot for <vmid> appears
#   ⑤ pbs files                 — that snapshot's archives are listed
#   ⑥ pbs restore  (opt-in)     — pull one archive to a temp dir and
#                                 confirm a non-empty extraction.
#                                 LINUX-ONLY: needs `proxmox-backup-client`,
#                                 which upstream does NOT package for macOS
#                                 (run this step on the PBS host or a PVE
#                                 node). Gated behind PROXXX_E2E_PBS_RESTORE=1.
#                                 NOTE: against a self-signed PBS this only
#                                 succeeds where the cert is already trusted
#                                 (e.g. on the PBS host itself) — proxxx has
#                                 no PBS-fingerprint config field yet, so it
#                                 can't pass PBS_FINGERPRINT to the client.
#   ⑦ backup-verify             — the metadata probe rates <vmid> fresh/pass
#                                 (PBS-backed storage content can lag a few
#                                 seconds after the backup task returns; the
#                                 step retries briefly before failing)
#
# RAII via trap EXIT — forgets the test snapshot from PBS (proxxx has no
# `pbs forget` subcommand yet, so teardown goes through the PBS REST API
# directly; mirrors how test_state_ha_rules.sh uses curl for PVE-side
# teardown). Idempotent on a clean datastore. The throwaway guest is NOT
# created/destroyed here — it's a persistent fixture (see PROXXX_E2E_BACKUP_VMID).
#
# ─────────────────────────────────────────────────────────────────────
# Required: a working proxxx profile with a `[profiles.NAME.pbs]` block.
#   PROXXX_E2E_PROFILE        — profile name           (default: pvetest)
#   PROXXX_E2E_BACKUP_STORAGE — PVE storage id (type=pbs) to back up to;
#                               this is the vzdump target. Attach once with:
#                                 proxxx --profile <p> storage-defs create \
#                                   --storage <id> --storage-type pbs \
#                                   --server <pbs-host> --datastore <ds> \
#                                   --username '<user>!<tokenid>' \
#                                   --content backup --fingerprint <fp> \
#                                   --raw password=<secret>
#                               (default: pbs-e2e)
# Optional (sensible homelab defaults):
#   PROXXX_E2E_DATASTORE      — PBS datastore name      (default: test-store)
#   PROXXX_E2E_BACKUP_VMID    — throwaway guest vmid     (default: 7777)
#   PROXXX_E2E_BACKUP_KIND    — ct | vm                 (default: ct)
#   PROXXX_E2E_BACKUP_MODE    — snapshot|suspend|stop   (default: snapshot)
#   PROXXX_E2E_RESTORE_ARCHIVE— archive to restore      (default: root.pxar
#                               for ct; for vm use e.g. drive-scsi0.img)
#   PROXXX_E2E_PBS_RESTORE=1   — run step ⑥ (Linux + proxmox-backup-client)
# Teardown (forget the test snapshot) needs direct PBS API creds; skipped
# with a clear log if unset:
#   PROXXX_E2E_PBS_URL        — https://<pbs>:8007
#   PROXXX_E2E_PBS_AUTHID     — PBS token auth-id   (default: proxxx@pbs!auto)
#   PROXXX_E2E_PBS_SECRET     — the PBS API-token secret (uuid)
# ─────────────────────────────────────────────────────────────────────

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel)"
BIN="${BIN:-$ROOT/target/release/proxxx}"

ENV_FILE="${PROXXX_E2E_ENV_FILE:-$SCRIPT_DIR/env.local}"
# shellcheck source=/dev/null
[[ -f "$ENV_FILE" ]] && . "$ENV_FILE"

PROFILE="${PROXXX_E2E_PROFILE:-pvetest}"
STORAGE="${PROXXX_E2E_BACKUP_STORAGE:-pbs-e2e}"
STORE="${PROXXX_E2E_DATASTORE:-test-store}"
VMID="${PROXXX_E2E_BACKUP_VMID:-7777}"
KIND="${PROXXX_E2E_BACKUP_KIND:-ct}"
MODE="${PROXXX_E2E_BACKUP_MODE:-snapshot}"
ARCHIVE="${PROXXX_E2E_RESTORE_ARCHIVE:-root.pxar}"

PX=("$BIN" --profile "$PROFILE")

# Optional PBS direct-API creds (teardown only).
PBS_URL="${PROXXX_E2E_PBS_URL:-}"
PBS_AUTHID="${PROXXX_E2E_PBS_AUTHID:-proxxx@pbs!auto}"
PBS_SECRET="${PROXXX_E2E_PBS_SECRET:-}"

WORKDIR="$(mktemp -d -t proxxx-pbs-e2e.XXXXXX)"
RESTORE_DIR="$WORKDIR/restore"
mkdir -p "$RESTORE_DIR"

PASS=0
FAIL=0
log()  { echo "$@"; }
ok()   { log "  [OK   ] $*"; PASS=$((PASS + 1)); }
bad()  { log "  [FAIL ] $*"; FAIL=$((FAIL + 1)); }
skip() { log "  [SKIP ] $*"; }

pbs_api() {
    # $1 = method, $2 = path+query. Only used for snapshot teardown.
    curl -ks -X "$1" -H "Authorization: PBSAPIToken=${PBS_AUTHID}:${PBS_SECRET}" \
        "${PBS_URL%/}/api2/json/$2"
}

CREATED_SNAP_TIME=""

cleanup() {
    log ""
    log "═══════════════════════════════════════════════════════════"
    log "[cleanup] RAII teardown"
    log "═══════════════════════════════════════════════════════════"
    if [[ -n "$CREATED_SNAP_TIME" ]]; then
        if [[ -n "$PBS_URL" && -n "$PBS_SECRET" ]]; then
            pbs_api DELETE \
                "admin/datastore/$STORE/snapshots?backup-type=$KIND&backup-id=$VMID&backup-time=$CREATED_SNAP_TIME" \
                >/dev/null 2>&1 || true
            log "[cleanup] forgot snapshot $KIND/$VMID/$CREATED_SNAP_TIME from $STORE"
        else
            log "[cleanup] snapshot $KIND/$VMID/$CREATED_SNAP_TIME left on $STORE"
            log "          (set PROXXX_E2E_PBS_URL + PROXXX_E2E_PBS_SECRET to auto-forget)"
        fi
    fi
    rm -rf "$WORKDIR"
    log ""
    log "═══════════════════════════════════════════════════════════"
    log "PBS backup/restore e2e: PASS=$PASS  FAIL=$FAIL"
    log "═══════════════════════════════════════════════════════════"
}
trap cleanup EXIT

log "═══════════════════════════════════════════════════════════"
log "proxxx PBS backup/restore e2e — $(date -u +%Y-%m-%dT%H:%M:%SZ)"
log "profile=$PROFILE  vmid=$VMID ($KIND, mode=$MODE)"
log "PVE storage (vzdump target)=$STORAGE  →  PBS datastore=$STORE"
log "═══════════════════════════════════════════════════════════"

# ── ① ping ──
log ""
log "[step 1] proxxx pbs ping"
out=$("${PX[@]}" pbs ping 2>&1)
log "$out"
if echo "$out" | grep -qE '"ok": *true'; then
    ok "step 1: PBS reachable + authenticated"
else
    bad "step 1: pbs ping did not return ok:true"
fi

# ── ② datastores ──
log ""
log "[step 2] proxxx pbs datastores (expect $STORE listed)"
out=$("${PX[@]}" pbs datastores 2>&1)
log "$out"
if echo "$out" | grep -q "$STORE"; then
    ok "step 2: datastore '$STORE' visible (null-comment deserialize OK)"
else
    bad "step 2: datastore '$STORE' not in pbs datastores output"
fi

# ── pre-count snapshots for this vmid ──
pre_count=$("${PX[@]}" pbs snapshots --store "$STORE" --backup-id "$VMID" --format json 2>/dev/null \
    | grep -c '"backup-time"')
log ""
log "[setup] pre-existing $KIND/$VMID snapshots on $STORE: $pre_count"

# ── ③ backup ──
log ""
log "[step 3] proxxx backup $VMID --storage $STORAGE --mode $MODE --wait"
out=$("${PX[@]}" backup "$VMID" --storage "$STORAGE" --mode "$MODE" --wait 2>&1)
rc=$?
log "$out"
if [[ $rc -eq 0 ]] && echo "$out" | grep -q '"exitstatus": *"OK"'; then
    ok "step 3: backup task completed OK"
else
    bad "step 3: backup exited $rc (expected 0 + exitstatus OK)"
fi

# ── ④ snapshots (proxxx) + capture the new backup-time ──
log ""
log "[step 4] proxxx pbs snapshots --store $STORE --backup-id $VMID"
snap_json=$("${PX[@]}" pbs snapshots --store "$STORE" --backup-id "$VMID" --format json 2>&1)
log "$snap_json"
post_count=$(echo "$snap_json" | grep -c '"backup-time"')
CREATED_SNAP_TIME=$(echo "$snap_json" | grep -oE '"backup-time": *[0-9]+' | grep -oE '[0-9]+' | sort -n | tail -1)
if [[ "$post_count" -gt "$pre_count" && -n "$CREATED_SNAP_TIME" ]]; then
    ok "step 4: fresh snapshot present (count $pre_count → $post_count, time=$CREATED_SNAP_TIME)"
else
    bad "step 4: no new snapshot for $VMID (count $pre_count → $post_count)"
fi

# ── ⑤ files in the snapshot ──
if [[ -n "$CREATED_SNAP_TIME" ]]; then
    log ""
    log "[step 5] proxxx pbs files --store $STORE --type $KIND --backup-id $VMID --time $CREATED_SNAP_TIME"
    out=$("${PX[@]}" pbs files --store "$STORE" --type "$KIND" --backup-id "$VMID" --time "$CREATED_SNAP_TIME" 2>&1)
    log "$out"
    if echo "$out" | grep -qE '\.(pxar\.didx|img\.fidx|fidx|didx)'; then
        ok "step 5: snapshot lists data archive(s)"
    else
        bad "step 5: no data archive (*.didx/*.fidx) in files output"
    fi
else
    bad "step 5: skipped — no snapshot time captured in step 4"
fi

# ── ⑥ restore (opt-in, Linux + proxmox-backup-client) ──
log ""
if [[ "${PROXXX_E2E_PBS_RESTORE:-0}" != "1" ]]; then
    skip "step 6: restore not requested (set PROXXX_E2E_PBS_RESTORE=1 on a host w/ proxmox-backup-client — e.g. the PBS host)"
elif ! command -v proxmox-backup-client >/dev/null 2>&1; then
    skip "step 6: proxmox-backup-client not on PATH (apt install proxmox-backup-client — not packaged for macOS)"
elif [[ -z "$CREATED_SNAP_TIME" ]]; then
    bad "step 6: cannot restore — no snapshot time captured"
else
    snap_rfc=$(date -u -d "@$CREATED_SNAP_TIME" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
        || date -u -r "$CREATED_SNAP_TIME" +%Y-%m-%dT%H:%M:%SZ)
    log "[step 6] proxxx pbs restore --store $STORE --snapshot $KIND/$VMID/$snap_rfc --archive $ARCHIVE"
    out=$("${PX[@]}" pbs restore \
        --store "$STORE" \
        --snapshot "$KIND/$VMID/$snap_rfc" \
        --archive "$ARCHIVE" \
        --target "$RESTORE_DIR" \
        --yes 2>&1)
    rc=$?
    log "$out"
    extracted=$(find "$RESTORE_DIR" -mindepth 1 2>/dev/null | head -1)
    if [[ $rc -eq 0 && -n "$extracted" ]]; then
        ok "step 6: archive restored to a non-empty tree ($(find "$RESTORE_DIR" -type f | wc -l | tr -d ' ') files)"
    else
        bad "step 6: restore exit=$rc, target empty=$([[ -z "$extracted" ]] && echo yes || echo no)"
    fi
fi

# ── ⑦ backup-verify metadata probe (retry — PBS-backed content can lag) ──
log ""
log "[step 7] proxxx backup-verify (expect $VMID pass; retries for content-listing lag)"
verify_ok=0
for attempt in 1 2 3 4 5; do
    out=$("${PX[@]}" backup-verify 2>&1)
    if echo "$out" | grep -E "^$VMID[[:space:]]" | grep -q "pass"; then
        verify_ok=1
        break
    fi
    sleep 3
done
log "$out"
if [[ "$verify_ok" -eq 1 ]]; then
    ok "step 7: backup-verify rates $VMID as pass"
else
    bad "step 7: backup-verify did not rate $VMID pass after retries"
fi

if [[ "$FAIL" -gt 0 ]]; then
    exit 1
fi
exit 0
