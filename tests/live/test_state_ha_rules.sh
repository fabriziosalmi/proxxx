#!/usr/bin/env bash
# HA-rules state-family live mutation test — runs the full GitOps
# round-trip against a real PVE 9.1.x cluster:
#
#   ① state apply (Create both rule types: node-affinity + resource-affinity)
#   ② state diff after a `strict` flip on the node-affinity rule
#   ③ state apply without --allow-risk → MUST refuse (Severe preflight)
#   ④ state apply --allow-risk → MUST succeed (the `type-on-PUT` fix path)
#   ⑤ state export → MUST round-trip strict=true persisted
#   ⑥ state apply baseline.toml --prune --allow-risk → delete both
#   ⑦ state export → final ha_rules section absent
#
# Plus pre-step ⓪: register ct:7777 + vm:8888 as HA *resources* via
# raw `/cluster/ha/resources` (proxxx doesn't yet manage HA resources
# as a state family — separate follow-up; the read side already exists
# via `list_ha_resources`). Without this, PVE rejects rule creates with
# `cannot use unmanaged resource(s) <sid>.\n` at the rule POST.
#
# RAII via trap EXIT — un-registers HA resources + restores the config
# regardless of how we got there. Idempotent on a clean cluster.
#
# Required env (sourced from tests/live/env.local if present):
#   PROXXX_E2E_PVE_URL    — https://192.168.0.122:8006
#   PROXXX_E2E_PVE_TOKEN  — tokenid=secret  (root@pam!proxxx=<uuid>)
#   PROXXX_E2E_NODE       — pve-test-1
#
# Auth note (live-caught — see § "PAM-vs-token POST quirk" in v0.7.1
# release notes): proxxx's `state apply` POST to /cluster/ha/rules
# succeeds with API-token auth but PVE returns "cannot use unmanaged
# resource(s) <sid>" when proxxx authenticates via PAM (ticket+cookie).
# Direct curl with the same params + PAM headers also reproduces. This
# script forces token auth by temporarily swapping config.toml.
# Investigation is tracked separately.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel)"
BIN="${BIN:-$ROOT/target/release/proxxx}"

ENV_FILE="${PROXXX_E2E_ENV_FILE:-$SCRIPT_DIR/env.local}"
[[ -f "$ENV_FILE" ]] && . "$ENV_FILE"

: "${PROXXX_E2E_PVE_URL:?env PROXXX_E2E_PVE_URL not set}"
: "${PROXXX_E2E_PVE_TOKEN:?env PROXXX_E2E_PVE_TOKEN not set — format: tokenid=secret}"
: "${PROXXX_E2E_NODE:?env PROXXX_E2E_NODE not set (target node name, e.g. pve-test-1)}"

URL="$PROXXX_E2E_PVE_URL"
NODE="$PROXXX_E2E_NODE"
T_H="Authorization: PVEAPIToken=root@pam!$PROXXX_E2E_PVE_TOKEN"

# Use existing test fixtures (memorialized in test_mutation.sh's batch
# 3/4 — alpine LXC 7777, alpine QEMU 8888, both kept stopped between runs).
LXC_SID="ct:7777"
VM_SID="vm:8888"

# Workdir
WORKDIR="$(mktemp -d -t proxxx-state-ha-rules.XXXXXX)"
BASELINE="$WORKDIR/baseline.toml"
DECL="$WORKDIR/with_ha_rules.toml"

PASS=0
FAIL=0
log()   { echo "$@"; }
ok()    { log "  [OK   ] $*"; PASS=$((PASS + 1)); }
bad()   { log "  [FAIL ] $*"; FAIL=$((FAIL + 1)); }

# Temporary config switch — force token auth for the duration of the
# test (see auth note in the header). Backup + restore in cleanup.
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
    # Sweep any leftover HA rules with the proxxx-e2e- prefix.
    for r in proxxx-e2e-pin proxxx-e2e-spread; do
        curl -ks -X DELETE "$URL/api2/json/cluster/ha/rules/$r" -H "$T_H" >/dev/null 2>&1 || true
    done
    # Un-manage the HA resources we registered.
    for sid in "$LXC_SID" "$VM_SID"; do
        curl -ks -X DELETE "$URL/api2/json/cluster/ha/resources/$sid" -H "$T_H" >/dev/null 2>&1 || true
    done
    # Restore the operator's original config.
    if [[ -n "$RESTORE_CFG" && -f "$RESTORE_CFG" ]]; then
        mv "$RESTORE_CFG" "$ORIG_CFG"
        log "[cleanup] config.toml restored from backup"
    fi
    rm -rf "$WORKDIR"
    log ""
    log "═══════════════════════════════════════════════════════════"
    log "HA-rules state mutation: PASS=$PASS  FAIL=$FAIL"
    log "═══════════════════════════════════════════════════════════"
}
trap cleanup EXIT

# Force token auth (see header — PAM auth fails on POST /cluster/ha/rules
# with "unmanaged resource", token auth succeeds with identical params).
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
log "proxxx HA-rules state mutation run — $(date -u +%Y-%m-%dT%H:%M:%SZ)"
log "Target: $URL"
log "Fixtures: $LXC_SID + $VM_SID on $NODE"
log "═══════════════════════════════════════════════════════════"

# ── ⓪ Pre-step: register HA resources (precondition for rule create) ──
log ""
log "[step 0] registering HA resources $LXC_SID + $VM_SID (state=stopped)"
for sid in "$LXC_SID" "$VM_SID"; do
    resp=$(curl -ks -X POST "$URL/api2/json/cluster/ha/resources" -H "$T_H" \
        --data-urlencode "sid=$sid" --data-urlencode "state=stopped" 2>&1)
    log "  POST $sid -> $resp"
done
# Verify both visible.
sids_visible=$(curl -ks -H "$T_H" "$URL/api2/json/cluster/ha/resources" | python3 -c "
import sys, json
data = json.load(sys.stdin)['data']
print(' '.join(sorted(e['sid'] for e in data)))
")
if [[ "$sids_visible" == *"$LXC_SID"* && "$sids_visible" == *"$VM_SID"* ]]; then
    ok "step 0: both HA resources registered"
else
    bad "step 0: expected both SIDs visible, got: $sids_visible"
    exit 1
fi

# ── Snapshot baseline + compose declared TOML ──
log ""
log "[setup] capturing live baseline + composing declared TOML"
"$BIN" state export --resource all > "$BASELINE"
cp "$BASELINE" "$DECL"
cat >> "$DECL" <<EOF

[[ha_rules]]
rule = "proxxx-e2e-pin"
type = "node-affinity"
resources = ["$LXC_SID"]
comment = "proxxx live e2e - node-affinity"
nodes = "$NODE"

[[ha_rules]]
rule = "proxxx-e2e-spread"
type = "resource-affinity"
resources = ["$LXC_SID", "$VM_SID"]
comment = "proxxx live e2e - resource-affinity"
affinity = "negative"
EOF

# ── ① CREATE both rules ──
log ""
log "[step 1] state apply: CREATE node-affinity + resource-affinity"
out=$("$BIN" state apply "$DECL" 2>&1)
log "$out"
applied=$(echo "$out" | grep -c "applied")
if [[ "$applied" -eq 2 ]]; then
    ok "step 1: both rules applied"
else
    bad "step 1: expected 2 applied, got $applied"
fi

# ── ② FLIP strict=true + diff ──
log ""
log "[step 2] flipping strict=true on proxxx-e2e-pin, state diff"
sed -i.bak '/rule = "proxxx-e2e-pin"/,/^$/ s/^nodes/strict = true\nnodes/' "$DECL"
out=$("$BIN" state diff "$DECL" 2>&1)
log "$out"
if echo "$out" | grep -q "^~ ha_rule: proxxx-e2e-pin"; then
    ok "step 2: strict-flip detected as Update"
else
    bad "step 2: expected ~ Update for proxxx-e2e-pin in diff"
fi

# ── ③ APPLY without --allow-risk → must refuse (Severe) ──
log ""
log "[step 3] state apply WITHOUT --allow-risk (expect Severe refuse, exit 6)"
out=$("$BIN" state apply "$DECL" 2>&1)
exit_code=$?
log "$out"
if [[ $exit_code -eq 6 ]] && echo "$out" | grep -q "\[SEVERE \] node-affinity rule \`proxxx-e2e-pin\` \`strict\` flag changed"; then
    ok "step 3: Severe preflight refused as expected (exit=6)"
else
    bad "step 3: expected exit 6 + Severe preflight, got exit=$exit_code"
fi

# ── ④ APPLY --allow-risk → the v0.7.1 type-on-PUT fix-verification ──
log ""
log "[step 4] state apply --allow-risk (the type-on-PUT fix path)"
out=$("$BIN" state apply "$DECL" --allow-risk 2>&1)
log "$out"
if echo "$out" | grep -q "^~ ha_rule: proxxx-e2e-pin — applied"; then
    ok "step 4: strict-flip PUT applied (type-on-PUT bug fixed)"
else
    bad "step 4: expected ~ applied for proxxx-e2e-pin"
fi

# ── ⑤ VERIFY strict=true persisted ──
log ""
log "[step 5] verify strict=true persisted via state export"
exported=$("$BIN" state export --resource ha-rules 2>&1)
log "$exported"
if echo "$exported" | grep -A 6 'rule = "proxxx-e2e-pin"' | grep -q "^strict = true$"; then
    ok "step 5: strict=true round-trips through export"
else
    bad "step 5: strict=true missing from re-exported rule"
fi

# ── ⑥ CLEANUP via --prune ──
log ""
log "[step 6] restore baseline (--prune --allow-risk)"
out=$("$BIN" state apply "$BASELINE" --prune --allow-risk 2>&1)
log "$out"
deleted=$(echo "$out" | grep -c "^- ha_rule:.*— applied")
if [[ "$deleted" -eq 2 ]]; then
    ok "step 6: both rules pruned"
else
    bad "step 6: expected 2 deleted, got $deleted"
fi

# ── ⑦ FINAL: no HA rules remain ──
log ""
log "[step 7] final state — ha_rules section absent"
final_export=$("$BIN" state export --resource ha-rules 2>&1)
log "$final_export"
if ! echo "$final_export" | grep -q "^\[\[ha_rules\]\]$"; then
    ok "step 7: no ha_rules sections present (clean)"
else
    bad "step 7: leftover ha_rules section"
fi

if [[ "$FAIL" -gt 0 ]]; then
    exit 1
fi
exit 0
