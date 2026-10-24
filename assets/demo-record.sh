#!/usr/bin/env bash
# Record assets/demo.cast: a real proxxx session against the LAB cluster.
#
#   PROXXX_BIN=target/release/proxxx assets/demo-record.sh
#   npx svg-term-cli@2.1.1 --in assets/demo.cast --out assets/demo.svg --window
#
# What the viewer sees is the real terminal: each command is typed out
# character by character and then run, and its output is whatever the
# binary prints. Nothing is edited afterwards.
#
# Off camera, before the recording: the lab env is loaded through
# tests/live/lib.sh (config, token, audit, log and cache in a private temp
# dir), HOME and the freeze lock are moved into the same dir, LXC 7777 is
# started, and the config gets one [[policies]] entry (stop, any guest, one
# approval, Telegram) with no [telegram] section. RUST_LOG=proxxx=error
# hides the tracing lines (connection, the offline lab node) on stderr.
# During the delete, an incident freeze is held as a safety net, so the
# guest cannot be deleted even if the pre-flight did not refuse; the
# pre-flight refuses first, so the freeze is never reached and prints
# nothing. After the recording, 7777 is stopped again.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${PROXXX_BIN:-$REPO/target/release/proxxx}"
OUT="${DEMO_CAST:-$REPO/assets/demo.cast}"
VMID="${PROXXX_E2E_DEMO_VMID_LXC:-7777}"

if [[ "${1:-}" == "--scene" ]]; then
    # On camera.
    p() { printf '\033[1;32m$\033[0m '; }
    say() { printf '\033[2m# %s\033[0m\n' "$1"; sleep 0.8; }
    type_run() {
        p
        sleep 0.4
        local s="$1" i
        for ((i = 0; i < ${#s}; i++)); do
            printf '%s' "${s:i:1}"
            sleep 0.06
        done
        sleep 0.4
        printf '\n'
        local -a args
        read -ra args <<<"${s#proxxx }"
        set +e
        "$BIN" "${args[@]}"
        rc=$?
        set -e
        sleep 1.2
        p; sleep 0.3; printf 'echo $?\n'; echo "$rc"
        sleep 2
    }
    clear
    say "delete a guest that is still running: the pre-flight refuses before anything is sent"
    "$BIN" incident freeze --reason "demo recording safety net" --ttl 10m >/dev/null 2>&1
    type_run "proxxx delete $VMID --yes"
    "$BIN" incident thaw --reason "demo recording" >/dev/null 2>&1
    say "a [[policies]] entry puts every stop behind one human approval; no channel, no run"
    type_run "proxxx stop $VMID"
    sleep 1
    exit 0
fi

SCRIPT_DIR="$REPO/tests/live"
# shellcheck source=SCRIPTDIR/../tests/live/lib.sh
. "$SCRIPT_DIR/lib.sh"
live_load_env
live_normalize_token
live_isolate
trap live_cleanup EXIT
export HOME="$LIVE_TMP/home" XDG_CONFIG_HOME="$LIVE_TMP/home/.config" XDG_DATA_HOME="$LIVE_TMP/home/.local/share"
export PROXXX_FREEZE_PATH="$LIVE_TMP/freeze/freeze.lock"
mkdir -p "$HOME" "$LIVE_TMP/freeze"
export RUST_LOG=proxxx=error BIN

cat >> "$PROXXX_CONFIG" <<'EOF'

[[policies]]
action = "stop"
target = "*"
require = 1
channel = "telegram"
EOF

"$BIN" start "$VMID" >/dev/null
for _ in $(seq 1 30); do
    st="$("$BIN" ls guests --format json | python3 -c "import json,sys; print(next((g['status'] for g in json.load(sys.stdin) if g['vmid']==$VMID), ''))")"
    [[ "$st" == running ]] && break
    sleep 2
done
[[ "$st" == running ]] || { echo "guest $VMID is not running; not recording" >&2; exit 1; }
sleep 20 # let the uptime read like a guest that has been up for a while

asciinema rec --overwrite --quiet --headless --window-size 100x24 \
    --output-format asciicast-v2 --idle-time-limit 2.5 \
    --title "proxxx: pre-flight risk gate and approval policy" \
    --command "$0 --scene" "$OUT"

# Restore the lab: stop 7777 again. The stop policy is in this config, so
# remove it first.
python3 - "$PROXXX_CONFIG" <<'EOF'
import sys
p = sys.argv[1]
s = open(p).read()
open(p, "w").write(s[: s.index("\n[[policies]]")] + "\n")
EOF
"$BIN" stop "$VMID" >/dev/null
echo "recorded $OUT; $VMID stopped" >&2
