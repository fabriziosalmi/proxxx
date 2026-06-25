#!/usr/bin/env bash
# reconcile converge (GitOps Layer 3) live e2e — the continuous-reconciliation
# WRITE half. Drives the full detect → converge round-trip against a real PVE
# cluster, end-to-end self-contained (the core uses an empty pool, so no guest
# fixtures are required):
#
#   ① out-of-band CREATE an empty pool (raw API) that the baseline lacks →
#      `reconcile run` MUST report drift (exit 2) with the pool as a delete.
#   ② `reconcile converge --dry-run` → the delete shows `skipped (dry_run)` and
#      the pool MUST still exist (drift still present, exit 2). Read-only.
#   ③ `reconcile converge` (no --prune) → delete shows `skipped (prune_policy)`;
#      the pool MUST still exist. The prune interlock holds.
#   ④ `reconcile converge --prune` → the pool is deleted (`— applied`).
#   ⑤ `reconcile run` → in sync (exit 0). Convergence achieved.
#   ⑥ `audit log` MUST carry a `reconcile_converge` entry (the unmanned-mutation
#      trail; the CLI converge writes one HMAC-chained entry per dispatched run).
#   ⑦ (opt-in, needs PROXXX_E2E_CONVERGE_MEMBER_VMID) Severe gate: a pool with a
#      guest member → delete is Severe (PoolDeleteNonEmpty). `converge --prune`
#      WITHOUT --allow-risk MUST refuse (exit 6, no deletion); WITH --allow-risk
#      MUST apply.
#
# Robustness: every cluster call goes through `retry()` (the nested .122 test
# cluster occasionally drops the first TLS/connection with a transient transport
# error). A baseline SELF-CHECK refuses to run unless live is in sync with its
# own fresh export — a flaky/incomplete export would otherwise diff as "delete
# everything" and (correctly) get Severe-refused, which is a false failure.
#
# RAII via trap EXIT — sweeps both test pools (idempotent, 404 fine) and restores
# the operator's config.
#
# Required env (sourced from tests/live/env.local if present):
#   PROXXX_E2E_PVE_URL    — https://192.168.0.122:8006   (pvetest / pve-test-1)
#   PROXXX_E2E_PVE_TOKEN  — tokenid=secret  (root@pam!proxxx=<uuid>)
#   PROXXX_E2E_NODE       — pve-test-1
# Optional:
#   PROXXX_E2E_CONVERGE_MEMBER_VMID — a VMID that exists on the cluster; enables
#                                     the Severe sub-case (step ⑦). Skipped if unset.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel)"
BIN="${BIN:-$ROOT/target/release/proxxx}"

ENV_FILE="${PROXXX_E2E_ENV_FILE:-$SCRIPT_DIR/env.local}"
# shellcheck source=/dev/null
[[ -f "$ENV_FILE" ]] && . "$ENV_FILE"

: "${PROXXX_E2E_PVE_URL:?env PROXXX_E2E_PVE_URL not set}"
: "${PROXXX_E2E_PVE_TOKEN:?env PROXXX_E2E_PVE_TOKEN not set — format: tokenid=secret}"
: "${PROXXX_E2E_NODE:?env PROXXX_E2E_NODE not set (target node name, e.g. pve-test-1)}"

URL="$PROXXX_E2E_PVE_URL"
T_H="Authorization: PVEAPIToken=root@pam!$PROXXX_E2E_PVE_TOKEN"

POOL="proxxx-e2e-conv"
SEVERE_POOL="proxxx-e2e-conv-severe"
MEMBER_VMID="${PROXXX_E2E_CONVERGE_MEMBER_VMID:-}"

WORKDIR="$(mktemp -d -t proxxx-reconcile-converge.XXXXXX)"
BASELINE="$WORKDIR/baseline.toml"

PASS=0
FAIL=0
log()   { echo "$@"; }
ok()    { log "  [OK   ] $*"; PASS=$((PASS + 1)); }
bad()   { log "  [FAIL ] $*"; FAIL=$((FAIL + 1)); }

# Retry a proxxx invocation up to 5× on TRANSIENT transport errors (the nested
# test cluster occasionally drops the first TLS/connection). Sets RETRY_OUT to
# the captured output and returns the command's own exit code. A non-transport
# non-zero exit (drift=2, preflight-refuse=6) is returned immediately — those are
# real results, not flakes.
RETRY_OUT=""
retry() {
    local attempt out rc
    for attempt in 1 2 3 4 5; do
        out="$("$@" 2>&1)"
        rc=$?
        if echo "$out" | grep -qiE 'transport error|error sending request|connection (closed|reset|refused)|timed out|operation timed out'; then
            sleep 2
            continue
        fi
        RETRY_OUT="$out"
        return "$rc"
    done
    RETRY_OUT="$out"
    return "$rc"
}

# Raw-API mutation with curl-level retry on transient errors.
api() { curl -ks --retry 3 --retry-all-errors --retry-delay 2 "$@"; }

# Temporary config switch — force token auth for the duration of the test
# (defensive fixture isolation, same rationale as test_state_ha_rules.sh).
PROXXX_CONFIG_DIR="${PROXXX_CONFIG_DIR:-$HOME/Library/Application Support/dev.proxxx.proxxx}"
if [[ ! -d "$PROXXX_CONFIG_DIR" ]]; then
    PROXXX_CONFIG_DIR="$HOME/.config/proxxx"   # Linux ProjectDirs path
fi
ORIG_CFG="$PROXXX_CONFIG_DIR/config.toml"
RESTORE_CFG=""

cleanup() {
    log ""
    log "═══════════════════════════════════════════════════════════"
    log "[cleanup] RAII teardown"
    log "═══════════════════════════════════════════════════════════"
    # Defensive sweep — idempotent (404 = already gone). A non-empty pool needs
    # its members detached before delete; PVE handles `delete` of an empty pool.
    for p in "$SEVERE_POOL" "$POOL"; do
        if [[ -n "$MEMBER_VMID" && "$p" == "$SEVERE_POOL" ]]; then
            api -X PUT "$URL/api2/json/pools/$p" -H "$T_H" \
                --data-urlencode "vms=$MEMBER_VMID" --data-urlencode "delete=1" >/dev/null 2>&1 || true
        fi
        api -X DELETE "$URL/api2/json/pools/$p" -H "$T_H" >/dev/null 2>&1 || true
    done
    if [[ -n "$RESTORE_CFG" && -f "$RESTORE_CFG" ]]; then
        mv "$RESTORE_CFG" "$ORIG_CFG"
        log "[cleanup] config.toml restored from backup"
    fi
    rm -rf "$WORKDIR"
    log ""
    log "═══════════════════════════════════════════════════════════"
    log "reconcile converge e2e: PASS=$PASS  FAIL=$FAIL"
    log "═══════════════════════════════════════════════════════════"
}
trap cleanup EXIT

if [[ -f "$ORIG_CFG" ]]; then
    RESTORE_CFG="$ORIG_CFG.proxxx-e2e-backup"
    cp "$ORIG_CFG" "$RESTORE_CFG"
fi
mkdir -p "$PROXXX_CONFIG_DIR"
TOKEN_ID="${PROXXX_E2E_PVE_TOKEN%%=*}"
TOKEN_SECRET="${PROXXX_E2E_PVE_TOKEN##*=}"
cat > "$ORIG_CFG" <<EOF
url = "$URL"
user = "root@pam"
auth = "token"
token_id = "$TOKEN_ID"
verify_tls = false
EOF
chmod 0600 "$ORIG_CFG"
export PROXXX_TOKEN_SECRET="$TOKEN_SECRET"

log "═══════════════════════════════════════════════════════════"
log "proxxx reconcile converge e2e — $(date -u +%Y-%m-%dT%H:%M:%SZ)"
log "Target: $URL"
log "═══════════════════════════════════════════════════════════"

# ── baseline = current live state (the desired state we converge TO) ──
log ""
log "[setup] capturing live baseline via state export (retried)"
# Pre-sweep any stale fixture so the baseline doesn't accidentally declare it.
api -X DELETE "$URL/api2/json/pools/$POOL" -H "$T_H" >/dev/null 2>&1 || true
retry "$BIN" state export --resource all
rc=$?
if [[ $rc -ne 0 ]]; then
    log "[setup] FATAL: baseline export failed after retries:"
    log "$RETRY_OUT"
    exit 1
fi
printf '%s\n' "$RETRY_OUT" > "$BASELINE"
# Self-check: live MUST be in sync with its OWN fresh export. If not, the export
# was incomplete (a transient flake) — bail rather than run a bogus
# "delete everything" diff that auto-converge would (correctly) Severe-refuse.
retry "$BIN" reconcile run --source "$BASELINE"
if [[ $? -ne 0 ]]; then
    log "[setup] FATAL: live is not in sync with its own baseline export"
    log "         (export flaky/incomplete) — aborting to avoid a false 'delete all' test:"
    log "$RETRY_OUT"
    exit 1
fi
log "[setup] baseline self-check OK — live matches its own export (in sync)"

# ── ① drift detection ──
log ""
log "[step 1] out-of-band CREATE pool '$POOL' (raw API) → reconcile run detects drift"
api -X POST "$URL/api2/json/pools" -H "$T_H" --data-urlencode "poolid=$POOL" >/dev/null 2>&1
retry "$BIN" reconcile run --source "$BASELINE"
rc=$?
log "$RETRY_OUT"
if [[ $rc -eq 2 ]] && echo "$RETRY_OUT" | grep -q "pool: $POOL"; then
    ok "step 1: reconcile run reports drift (exit 2) with '$POOL' as a delete"
else
    bad "step 1: expected exit 2 + '$POOL' drift, got exit=$rc"
fi

# ── ② dry-run converge (read-only) ──
log ""
log "[step 2] reconcile converge --dry-run → skipped(dry_run), pool MUST survive"
retry "$BIN" reconcile converge --source "$BASELINE" --dry-run
log "$RETRY_OUT"
out="$RETRY_OUT"
retry "$BIN" reconcile run --source "$BASELINE"; still_drift=$?
if echo "$out" | grep -q "pool: $POOL — skipped (dry_run)" && [[ $still_drift -eq 2 ]]; then
    ok "step 2: dry-run skipped the delete and mutated nothing (drift still present)"
else
    bad "step 2: expected skipped(dry_run) + surviving pool (drift exit 2), got drift=$still_drift"
fi

# ── ③ converge without --prune (prune interlock) ──
log ""
log "[step 3] reconcile converge (no --prune) → skipped(prune_policy), pool MUST survive"
retry "$BIN" reconcile converge --source "$BASELINE"
log "$RETRY_OUT"
out="$RETRY_OUT"
retry "$BIN" reconcile run --source "$BASELINE"; still_drift=$?
if echo "$out" | grep -q "pool: $POOL — skipped (prune_policy)" && [[ $still_drift -eq 2 ]]; then
    ok "step 3: prune interlock held the delete (drift still present)"
else
    bad "step 3: expected skipped(prune_policy) + surviving pool, got drift=$still_drift"
fi

# ── ④ converge --prune → applies ──
log ""
log "[step 4] reconcile converge --prune → pool deleted"
retry "$BIN" reconcile converge --source "$BASELINE" --prune
rc=$?
log "$RETRY_OUT"
if echo "$RETRY_OUT" | grep -q "pool: $POOL — applied"; then
    ok "step 4: '$POOL' pruned (delete applied)"
else
    bad "step 4: expected '$POOL — applied', got exit=$rc"
fi

# ── ⑤ in sync ──
log ""
log "[step 5] reconcile run → in sync (exit 0)"
retry "$BIN" reconcile run --source "$BASELINE"
rc=$?
log "$RETRY_OUT"
if [[ $rc -eq 0 ]]; then
    ok "step 5: live converged to baseline (exit 0, in sync)"
else
    bad "step 5: expected exit 0 (in sync), got exit=$rc"
fi

# ── ⑥ audit trail ──
log ""
log "[step 6] audit log carries a reconcile_converge entry"
retry "$BIN" audit log --limit 20
if echo "$RETRY_OUT" | grep -q "reconcile_converge"; then
    ok "step 6: unmanned-mutation audit entry present"
else
    bad "step 6: no reconcile_converge entry in audit log"
fi

# ── ⑦ Severe gate (opt-in) ──
if [[ -n "$MEMBER_VMID" ]]; then
    log ""
    log "[step 7] Severe gate — non-empty pool delete (member VMID $MEMBER_VMID)"
    api -X POST "$URL/api2/json/pools" -H "$T_H" --data-urlencode "poolid=$SEVERE_POOL" >/dev/null 2>&1
    api -X PUT "$URL/api2/json/pools/$SEVERE_POOL" -H "$T_H" --data-urlencode "vms=$MEMBER_VMID" >/dev/null 2>&1

    # 7a — WITHOUT --allow-risk → Severe refuse (exit 6), no deletion.
    retry "$BIN" reconcile converge --source "$BASELINE" --prune
    rc=$?
    log "$RETRY_OUT"
    pool_present=$(api "$URL/api2/json/pools/$SEVERE_POOL" -H "$T_H" | grep -c "$MEMBER_VMID")
    if [[ $rc -eq 6 && "$pool_present" -ge 1 ]]; then
        ok "step 7a: Severe (non-empty pool delete) refused unmanned (exit 6, pool intact)"
    else
        bad "step 7a: expected exit 6 + surviving pool, got exit=$rc present=$pool_present"
    fi

    # 7b — WITH --allow-risk → applies (operator override). Detach member first
    # so the empty-pool delete succeeds (PVE refuses deleting a non-empty pool).
    api -X PUT "$URL/api2/json/pools/$SEVERE_POOL" -H "$T_H" \
        --data-urlencode "vms=$MEMBER_VMID" --data-urlencode "delete=1" >/dev/null 2>&1
    retry "$BIN" reconcile converge --source "$BASELINE" --prune --allow-risk
    rc=$?
    log "$RETRY_OUT"
    if echo "$RETRY_OUT" | grep -q "pool: $SEVERE_POOL — applied"; then
        ok "step 7b: --allow-risk applied the delete (operator override)"
    else
        bad "step 7b: expected '$SEVERE_POOL — applied' with --allow-risk, got exit=$rc"
    fi
else
    log ""
    log "[step 7] SKIPPED — set PROXXX_E2E_CONVERGE_MEMBER_VMID to exercise the Severe gate"
fi

if [[ "$FAIL" -gt 0 ]]; then
    exit 1
fi
exit 0
