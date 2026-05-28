#!/usr/bin/env bash
# HA-rules + HA-resources state-family live mutation test — runs the
# full GitOps round-trip against a real PVE 9.1.x cluster, end-to-end
# self-contained (no raw-curl pre-registration as of v0.7.3 — HA
# resources is now its own state family, epic #74 epilogue at 7/6):
#
#   ① state apply: CREATE 2 HA resources (ct:7777, vm:8888) + 2 rules
#      (node-affinity + resource-affinity). Total 4 "applied" lines.
#      Inter-family ordering: resources flow BEFORE rules (rules
#      reference resource SIDs), so the diff order is
#      ha_resource creates → ha_rule creates.
#   ② state diff after a `strict` flip on the node-affinity rule.
#   ③ state apply without --allow-risk → MUST refuse (Severe preflight
#      on the strict flip — message verbatim from src/state/preflight.rs).
#   ④ state apply --allow-risk → MUST succeed (the `type`-on-PUT fix
#      from v0.7.1 keeps the field present on PUT).
#   ⑤ state export → MUST round-trip `strict = true` persisted.
#   ⑥ state apply baseline.toml --prune --allow-risk → delete all 4
#      (2 rules + 2 resources). PVE's resource-DELETE has `purge=1`
#      default which auto-cleans referencing rules; the v0.7.3 rule-
#      delete path is 404-tolerant so an already-purged rule shows up
#      as a clean idempotent delete. Cleanup triggers BOTH preflight
#      Severe (HaResourceDelete on each resource) AND Warning
#      (HaRuleDelete on each rule).
#   ⑦ state export → final ha_resources + ha_rules sections both absent.
#
# RAII via trap EXIT — restores the operator's config + sweeps any
# residual test artifacts on the cluster. Idempotent on a clean cluster.
#
# Required env (sourced from tests/live/env.local if present):
#   PROXXX_E2E_PVE_URL    — https://192.168.0.122:8006
#   PROXXX_E2E_PVE_TOKEN  — tokenid=secret  (root@pam!proxxx=<uuid>)
#   PROXXX_E2E_NODE       — pve-test-1
#
# Auth note (corrected in v0.7.2 — retracts a v0.7.1 false alarm):
# v0.7.1's CHANGELOG + this header originally claimed a "PAM-vs-token
# POST quirk" where state-apply POSTs supposedly failed under PAM auth.
# Sprint 2's deliberate matrix test (pools / firewall-alias /
# backup-jobs / notification-matchers / ha-rules, all five POST'd
# successfully under PAM auth on the same test cluster) disproved it.
# The original failure was config-URL drift between sessions, not auth:
# the operator's default config pointed at one cluster while
# tests/live/env.local's token addressed another, so a resource
# registered on cluster A via curl was genuinely unmanaged from
# cluster B's perspective.
#
# The script STILL swaps to token auth temporarily — but as a defensive
# fixture-isolation measure (a known-good auth flavor for the test), NOT
# because PAM is broken. Operators running with PAM auth against this
# same cluster + fixtures will see the same lifecycle pass.

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
    # Defensive sweep: belt-and-braces in case `state apply --prune`
    # itself failed mid-run. Step ⑥ should have done the work via
    # proxxx; these raw-API deletes only catch leaks. Idempotent (404
    # is fine — already gone).
    for r in proxxx-e2e-pin proxxx-e2e-spread; do
        curl -ks -X DELETE "$URL/api2/json/cluster/ha/rules/$r" -H "$T_H" >/dev/null 2>&1 || true
    done
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

# ── Snapshot baseline + compose declared TOML ──
log ""
log "[setup] capturing live baseline + composing declared TOML"
log "        (no raw-API HA-resource pre-registration — v0.7.3 state family handles it)"
"$BIN" state export --resource all > "$BASELINE"
cp "$BASELINE" "$DECL"
cat >> "$DECL" <<EOF

# HA resources first (state apply respects family ordering: resources
# are diff'd + applied BEFORE rules, so the create-then-reference
# dependency flows naturally).
[[ha_resources]]
sid = "$LXC_SID"
state = "stopped"

[[ha_resources]]
sid = "$VM_SID"
state = "stopped"

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

# ── ① CREATE 2 HA resources + 2 HA rules in one state apply ──
log ""
log "[step 1] state apply: CREATE 2 resources + 2 rules (single proxxx call)"
out=$("$BIN" state apply "$DECL" 2>&1)
log "$out"
applied=$(echo "$out" | grep -c "— applied")
if [[ "$applied" -eq 4 ]]; then
    ok "step 1: 2 resources + 2 rules applied (epic #74 epilogue: self-contained GitOps loop)"
else
    bad "step 1: expected 4 applied (2 resources + 2 rules), got $applied"
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
log "[step 6] restore baseline (--prune --allow-risk) — deletes 2 rules + 2 resources"
out=$("$BIN" state apply "$BASELINE" --prune --allow-risk 2>&1)
log "$out"
# Apply emits one `- <family>: <id> — applied` line per delete. The v0.7.3
# 404-tolerant `apply_ha_rule_delete` means an already-purged rule (PVE
# auto-cleaned it when its referenced resource was deleted first) still
# surfaces as `— applied` from proxxx's perspective.
deleted_rules=$(echo "$out" | grep -c "^- ha_rule:.*— applied")
deleted_resources=$(echo "$out" | grep -c "^- ha_resource:.*— applied")
total_deleted=$((deleted_rules + deleted_resources))
if [[ "$total_deleted" -eq 4 ]]; then
    ok "step 6: 2 rules + 2 resources pruned (total 4)"
else
    bad "step 6: expected 4 deletes (2 rules + 2 resources), got $total_deleted (rules=$deleted_rules resources=$deleted_resources)"
fi

# ── ⑦ FINAL: no HA rules + no HA resources remain ──
log ""
log "[step 7] final state — ha_rules + ha_resources sections both absent"
final_rules=$("$BIN" state export --resource ha-rules 2>&1)
final_resources=$("$BIN" state export --resource ha-resources 2>&1)
log "$final_rules"
log "$final_resources"
if ! echo "$final_rules" | grep -q "^\[\[ha_rules\]\]$" &&
    ! echo "$final_resources" | grep -q "^\[\[ha_resources\]\]$"; then
    ok "step 7: no ha_rules + no ha_resources sections present (clean)"
else
    bad "step 7: leftover HA family entries in final export"
fi

if [[ "$FAIL" -gt 0 ]]; then
    exit 1
fi
exit 0
