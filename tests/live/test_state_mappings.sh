#!/usr/bin/env bash
# Resource mappings (PCI / USB passthrough-as-code) live e2e — the v0.10.0 state
# family. Drives the full GitOps lifecycle for both mapping kinds against a real
# PVE cluster, end-to-end self-contained (a passthrough mapping needs no real
# device on the host — PVE accepts an arbitrary node/path/id triple, so the test
# requires no GPU/USB fixtures):
#
#   ① state diff  (baseline + 2 mappings) → 2 creates (mapping_pci + mapping_usb).
#   ② state apply (baseline + 2 mappings) → both created; `state export` round-
#      trips them (the `map` array is byte-stable) and the raw API confirms them.
#   ③ LEAK GUARD: the exported USB mapping MUST NOT carry an `mdev` field (it is
#      PCI-only) while the PCI mapping carries its `map`. The separate param
#      builders can never leak `mdev` into a USB mapping.
#   ④ state apply with a changed PCI `description` → Update applied (round-trips).
#   ⑤ SEVERE DELETE GATE: state apply baseline --prune (baseline lacks the two
#      mappings) WITHOUT --allow-risk → MUST refuse (exit 6 — MappingPciDelete /
#      MappingUsbDelete are unconditionally Severe: proxxx can't see which guests
#      reference a mapping). Both mappings MUST survive.
#   ⑥ state apply baseline --prune --allow-risk → both deleted (operator override).
#   ⑦ state diff baseline → in sync (exit 0). Lifecycle complete.
#
# Robustness: every proxxx call goes through `retry()` (the nested .122 test
# cluster occasionally drops the first TLS/connection with a transient transport
# error). A baseline SELF-CHECK refuses to run unless live is in sync with its
# own fresh export — a flaky/incomplete export would otherwise diff as "delete
# everything" and (correctly) get Severe-refused, a false failure.
#
# RAII via trap EXIT — sweeps both test mappings (idempotent, 404 fine) and
# restores the operator's config.
#
# Required env (sourced from tests/live/env.local if present):
#   PROXXX_E2E_PVE_URL    — https://192.168.0.122:8006   (pvetest / pve-test-1)
#   PROXXX_E2E_PVE_TOKEN  — tokenid=secret  (root@pam!proxxx=<uuid>)
#   PROXXX_E2E_NODE       — pve-test-1

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
NODE="$PROXXX_E2E_NODE"

MAP_PCI="proxxx-e2e-map-pci"
MAP_USB="proxxx-e2e-map-usb"

WORKDIR="$(mktemp -d -t proxxx-state-mappings.XXXXXX)"
BASELINE="$WORKDIR/baseline.toml"
DECL="$WORKDIR/declared.toml"
DECL2="$WORKDIR/declared-updated.toml"

PASS=0
FAIL=0
log()   { echo "$@"; }
ok()    { log "  [OK   ] $*"; PASS=$((PASS + 1)); }
bad()   { log "  [FAIL ] $*"; FAIL=$((FAIL + 1)); }

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

api() { curl -ks --retry 3 --retry-all-errors --retry-delay 2 "$@"; }

# Append the two declared mappings to a copy of the baseline, producing $1.
# $2 is the PCI description (lets step ④ re-emit with a changed value).
emit_decl() {
    local dest="$1" pci_desc="$2"
    cp "$BASELINE" "$dest"
    cat >> "$dest" <<EOF

[[mappings_pci]]
id = "$MAP_PCI"
description = "$pci_desc"
map = ["node=$NODE,path=0000:01:00.0,id=10de:2684"]

[[mappings_usb]]
id = "$MAP_USB"
description = "proxxx e2e USB"
map = ["node=$NODE,path=1-2,id=1050:0407"]
EOF
}

PROXXX_CONFIG_DIR="${PROXXX_CONFIG_DIR:-$HOME/Library/Application Support/dev.proxxx.proxxx}"
if [[ ! -d "$PROXXX_CONFIG_DIR" ]]; then
    PROXXX_CONFIG_DIR="$HOME/.config/proxxx"
fi
ORIG_CFG="$PROXXX_CONFIG_DIR/config.toml"
RESTORE_CFG=""

cleanup() {
    log ""
    log "═══════════════════════════════════════════════════════════"
    log "[cleanup] RAII teardown"
    log "═══════════════════════════════════════════════════════════"
    api -X DELETE "$URL/api2/json/cluster/mapping/pci/$MAP_PCI" -H "$T_H" >/dev/null 2>&1 || true
    api -X DELETE "$URL/api2/json/cluster/mapping/usb/$MAP_USB" -H "$T_H" >/dev/null 2>&1 || true
    if [[ -n "$RESTORE_CFG" && -f "$RESTORE_CFG" ]]; then
        mv "$RESTORE_CFG" "$ORIG_CFG"
        log "[cleanup] config.toml restored from backup"
    fi
    rm -rf "$WORKDIR"
    log ""
    log "═══════════════════════════════════════════════════════════"
    log "state mappings e2e: PASS=$PASS  FAIL=$FAIL"
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
log "proxxx state mappings (PCI/USB passthrough-as-code) e2e — $(date -u +%Y-%m-%dT%H:%M:%SZ)"
log "Target: $URL  node=$NODE"
log "═══════════════════════════════════════════════════════════"

# Pre-sweep any stale fixture so the baseline never declares it.
api -X DELETE "$URL/api2/json/cluster/mapping/pci/$MAP_PCI" -H "$T_H" >/dev/null 2>&1 || true
api -X DELETE "$URL/api2/json/cluster/mapping/usb/$MAP_USB" -H "$T_H" >/dev/null 2>&1 || true

log ""
log "[setup] capturing live baseline via state export (retried)"
retry "$BIN" state export --resource all
if [[ $? -ne 0 ]]; then
    log "[setup] FATAL: baseline export failed after retries:"; log "$RETRY_OUT"; exit 1
fi
printf '%s\n' "$RETRY_OUT" > "$BASELINE"
retry "$BIN" state diff "$BASELINE"
if [[ $? -ne 0 ]]; then
    log "[setup] FATAL: live is not in sync with its own baseline export"
    log "         (export flaky/incomplete) — aborting to avoid a false 'delete all' test:"
    log "$RETRY_OUT"; exit 1
fi
log "[setup] baseline self-check OK — live matches its own export (in sync)"

emit_decl "$DECL" "proxxx e2e GPU"

# ── ① diff → 2 creates ──
log ""
log "[step 1] state diff (baseline + 2 mappings) → 2 creates"
retry "$BIN" state diff "$DECL"; rc=$?
log "$RETRY_OUT"
if [[ $rc -eq 2 ]] \
   && echo "$RETRY_OUT" | grep -q "mapping_pci: $MAP_PCI" \
   && echo "$RETRY_OUT" | grep -q "mapping_usb: $MAP_USB"; then
    ok "step 1: diff reports both mappings as creates (exit 2)"
else
    bad "step 1: expected exit 2 + both mappings as creates, got exit=$rc"
fi

# ── ② apply → both created ──
log ""
log "[step 2] state apply → both mappings created (export + raw API confirm)"
retry "$BIN" state apply "$DECL"; rc=$?
log "$RETRY_OUT"
retry "$BIN" state export --resource mappings; exp="$RETRY_OUT"
# NB: GET-by-id does NOT echo the id (it's the URL segment); the LIST endpoint
# does. Grep the list for existence/survival assertions.
pci_live=$(api "$URL/api2/json/cluster/mapping/pci" -H "$T_H" | grep -c "$MAP_PCI")
usb_live=$(api "$URL/api2/json/cluster/mapping/usb" -H "$T_H" | grep -c "$MAP_USB")
if echo "$exp" | grep -q "id = \"$MAP_PCI\"" \
   && echo "$exp" | grep -q "id = \"$MAP_USB\"" \
   && echo "$exp" | grep -q "0000:01:00.0" \
   && [[ "$pci_live" -ge 1 && "$usb_live" -ge 1 ]]; then
    ok "step 2: both mappings applied + round-trip via export + raw API"
else
    bad "step 2: create/round-trip failed (exit=$rc pci_live=$pci_live usb_live=$usb_live)"
fi

# ── ③ leak guard: USB export carries NO mdev ──
log ""
log "[step 3] leak guard — exported USB mapping MUST NOT carry an mdev field"
usb_block=$(echo "$exp" | awk '/^\[\[mappings_usb\]\]/{f=1} f&&/^\[\[mappings_pci\]\]/{f=0} f')
if ! echo "$usb_block" | grep -q "mdev"; then
    ok "step 3: USB mapping has no mdev field (PCI-only field did not leak)"
else
    bad "step 3: LEAK — mdev appeared in the USB mapping block:"; log "$usb_block"
fi

# ── ④ update PCI description ──
log ""
log "[step 4] state apply with changed PCI description → Update applied"
emit_decl "$DECL2" "proxxx e2e GPU RENAMED"
retry "$BIN" state apply "$DECL2"; rc=$?
log "$RETRY_OUT"
new_desc=$(api "$URL/api2/json/cluster/mapping/pci/$MAP_PCI" -H "$T_H" | grep -c "RENAMED")
if echo "$RETRY_OUT" | grep -q "mapping_pci: $MAP_PCI — applied" && [[ "$new_desc" -ge 1 ]]; then
    ok "step 4: PCI description update applied + round-trips"
else
    bad "step 4: expected '$MAP_PCI — applied' + RENAMED live, got exit=$rc desc=$new_desc"
fi

# ── ⑤ Severe delete gate (no --allow-risk) ──
log ""
log "[step 5] state apply baseline --prune WITHOUT --allow-risk → Severe refuse (exit 6)"
retry "$BIN" state apply "$BASELINE" --prune; rc=$?
log "$RETRY_OUT"
pci_still=$(api "$URL/api2/json/cluster/mapping/pci" -H "$T_H" | grep -c "$MAP_PCI")
usb_still=$(api "$URL/api2/json/cluster/mapping/usb" -H "$T_H" | grep -c "$MAP_USB")
if [[ $rc -eq 6 && "$pci_still" -ge 1 && "$usb_still" -ge 1 ]]; then
    ok "step 5: mapping deletes refused unmanned (exit 6, both mappings intact)"
else
    bad "step 5: expected exit 6 + both surviving, got exit=$rc pci=$pci_still usb=$usb_still"
fi

# ── ⑥ operator override ──
log ""
log "[step 6] state apply baseline --prune --allow-risk → both deleted"
retry "$BIN" state apply "$BASELINE" --prune --allow-risk; rc=$?
log "$RETRY_OUT"
if echo "$RETRY_OUT" | grep -q "mapping_pci: $MAP_PCI — applied" \
   && echo "$RETRY_OUT" | grep -q "mapping_usb: $MAP_USB — applied"; then
    ok "step 6: --allow-risk applied both deletes (operator override)"
else
    bad "step 6: expected both mappings '— applied', got exit=$rc"
fi

# ── ⑦ in sync ──
log ""
log "[step 7] state diff baseline → in sync (exit 0)"
retry "$BIN" state diff "$BASELINE"; rc=$?
log "$RETRY_OUT"
if [[ $rc -eq 0 ]]; then
    ok "step 7: live converged back to baseline (exit 0, in sync)"
else
    bad "step 7: expected exit 0 (in sync), got exit=$rc"
fi

if [[ "$FAIL" -gt 0 ]]; then
    exit 1
fi
exit 0
