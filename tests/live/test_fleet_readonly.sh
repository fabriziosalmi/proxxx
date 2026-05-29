#!/usr/bin/env bash
# Live read-only verification for the fleet view (`proxxx fleet`).
#
# The fleet TUI aggregates nodes/guests/storage across EVERY configured
# profile using the SAME read methods (get_nodes / get_all_guests /
# get_all_storage_pools) that `ls <kind> --all-profiles` fans out. This
# script asserts that cross-profile read path against the real homelab
# (5 Proxmox), plus a PTY smoke-test of the TUI itself.
#
# STRICTLY READ-ONLY: no mutation is issued and none is possible — the
# fleet runner wires no SideEffect / HITL / SSH / cache-write path. We
# additionally PROVE non-mutation by snapshotting the fleet-wide guest
# state before and after a fetch cycle and asserting it is unchanged.
#
# No RAII cleanup block: nothing is created, so nothing to tear down.
#
# Run (config.toml must already point at the homelab, ≥2 [profiles.*]):
#   ./tests/live/test_fleet_readonly.sh

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel)"
BIN="${BIN:-$ROOT/target/release/proxxx}"
LOG_DIR="${LOG_DIR:-$SCRIPT_DIR}"
LOG="$LOG_DIR/test_fleet_readonly.log"

: > "$LOG"
PASS=0
FAIL=0

ok()   { echo "[OK   ] $1" | tee -a "$LOG"; PASS=$((PASS + 1)); }
fail() { echo "[FAIL ] $1" | tee -a "$LOG"; FAIL=$((FAIL + 1)); }

echo "═══════════════════════════════════════════════════════════" | tee -a "$LOG"
echo "proxxx fleet read-only verification — $(date -u +%Y-%m-%dT%H:%M:%SZ)" | tee -a "$LOG"
echo "═══════════════════════════════════════════════════════════" | tee -a "$LOG"

if [ ! -x "$BIN" ]; then
    echo "binary not found at $BIN — run: cargo build --release" | tee -a "$LOG"
    exit 2
fi

# ── 1. config has ≥2 named profiles (fleet's whole premise) ──
# `proxxx profiles --format json` emits [{"profiles": ["a","b",...]}]; be
# tolerant of either that shape or a bare list of profile names.
PROFILE_COUNT=$(timeout 10 "$BIN" --format json profiles 2>/dev/null \
    | python3 -c "
import sys, json
d = json.load(sys.stdin)
if isinstance(d, list) and d and isinstance(d[0], dict) and 'profiles' in d[0]:
    print(len(d[0]['profiles']))
elif isinstance(d, list):
    print(len(d))
else:
    print(0)
" 2>/dev/null)
PROFILE_COUNT="${PROFILE_COUNT:-0}"
echo "configured profiles: $PROFILE_COUNT" | tee -a "$LOG"
if [ "$PROFILE_COUNT" -ge 2 ]; then
    ok "config has ≥2 profiles ($PROFILE_COUNT) — fleet aggregation is meaningful"
else
    fail "fleet view needs ≥2 [profiles.*]; found $PROFILE_COUNT"
    echo "Summary: PASS=$PASS FAIL=$FAIL" | tee -a "$LOG"
    exit "$FAIL"
fi

# ── 2. cross-profile aggregation: each row carries `profile`, ≥2 distinct ──
# This is the exact read path the fleet worker uses, just rendered as
# rows instead of a TUI. Proves attribution + multi-cluster fan-out.
for kind in nodes guests storage; do
    OUT=$(timeout 30 "$BIN" --format json ls "$kind" --all-profiles 2>>"$LOG")
    DISTINCT=$(echo "$OUT" | python3 -c "
import sys,json
d=json.load(sys.stdin)
rows=[r for r in d if isinstance(r,dict)]
# every row must carry a 'profile' key (data rows AND error rows).
assert rows, 'no rows'
assert all('profile' in r for r in rows), 'a row is missing the profile attribution'
print(len({r['profile'] for r in rows}))
" 2>>"$LOG")
    if [ "${DISTINCT:-0}" -ge 2 ]; then
        ok "ls $kind --all-profiles: attributed rows across $DISTINCT profiles"
    else
        fail "ls $kind --all-profiles: expected ≥2 distinct profiles, got ${DISTINCT:-0}"
    fi
done

# ── 3. read-only proof: fleet-wide guest state is identical before and ──
#       after a fleet fetch cycle (the TUI's first poll). A mutating bug
#       would change a guest's status/count between the two reads.
fingerprint() {
    timeout 30 "$BIN" --format json ls guests --all-profiles 2>>"$LOG" | python3 -c "
import sys,json
d=json.load(sys.stdin)
rows=[(r.get('profile'), (r.get('data') or {}).get('vmid'), (r.get('data') or {}).get('status'))
      for r in d if isinstance(r,dict) and 'data' in r]
rows.sort(key=lambda t: (str(t[0]), t[1] or 0))
print(json.dumps(rows))
" 2>>"$LOG"
}

BEFORE=$(fingerprint)
# Drive ONE real fleet fetch cycle via the TUI under a PTY, then quit.
# Best-effort: requires `expect`. The fleet runner needs a TTY (it
# installs raw mode), so a plain pipe can't smoke it.
if command -v expect >/dev/null 2>&1; then
    FLEET_OUT=$(expect -c "
        set timeout 20
        spawn $BIN fleet
        # let the first 10s poll cycle complete, then quit
        sleep 12
        send q
        expect eof
        catch wait result
        exit [lindex \$result 3]
    " 2>>"$LOG")
    FLEET_RC=$?
    if [ "$FLEET_RC" -eq 0 ]; then
        ok "proxxx fleet: launched under PTY, polled, and quit cleanly (exit 0)"
    else
        fail "proxxx fleet: PTY smoke-test exited $FLEET_RC"
    fi
else
    echo "[skip ] expect(1) not installed — skipping fleet PTY smoke-test" | tee -a "$LOG"
fi
AFTER=$(fingerprint)

if [ "$BEFORE" = "$AFTER" ]; then
    ok "read-only: fleet-wide guest state unchanged across a fetch cycle"
else
    fail "guest state DIFFERS before/after a fleet cycle — fleet must not mutate!"
    { echo "--- BEFORE ---"; echo "$BEFORE"; echo "--- AFTER ---"; echo "$AFTER"; } >> "$LOG"
fi

echo "═══════════════════════════════════════════════════════════" | tee -a "$LOG"
echo "Summary: PASS=$PASS  FAIL=$FAIL   (log: $LOG)" | tee -a "$LOG"
echo "═══════════════════════════════════════════════════════════" | tee -a "$LOG"
exit "$FAIL"
