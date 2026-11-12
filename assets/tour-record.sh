#!/usr/bin/env bash
# Record assets/tour.cast: a read-only tour of the CLI against the LAB cluster.
#
#   PROXXX_BIN=target/release/proxxx assets/tour-record.sh
#   npx svg-term-cli@2.1.1 --in assets/tour.cast --out assets/tour.svg --window
#
# What the viewer sees is the real terminal: each command is typed out
# character by character and then run, and its output is whatever the
# binary prints. Nothing is edited afterwards. Every command on camera is a
# read; nothing on the cluster changes during the recording.
#
# Off camera, before the recording: the lab env is loaded through
# tests/live/lib.sh (config, token, audit, log and cache in a private temp
# dir) and LXC 7777 is started, so the guest list has a running guest.
# RUST_LOG=proxxx=error hides the tracing lines on stderr, and TERM is fixed
# so the recording does not depend on the caller's terminal. After the
# recording, 7777 is stopped again.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${PROXXX_BIN:-$REPO/target/release/proxxx}"
OUT="${TOUR_CAST:-$REPO/assets/tour.cast}"
VMID="${PROXXX_E2E_DEMO_VMID_LXC:-7777}"

if [[ "${1:-}" == "--scene" ]]; then
    # On camera.
    p() { printf '\033[1;32m$\033[0m '; }
    say() { printf '\033[2m# %s\033[0m\n' "$1"; sleep 0.8; }
    typed() {
        p
        sleep 0.4
        local s="$1" i
        for ((i = 0; i < ${#s}; i++)); do
            printf '%s' "${s:i:1}"
            sleep 0.05
        done
        sleep 0.4
        printf '\n'
    }
    # Type a `proxxx ...` line and run it with the real binary.
    type_run() {
        typed "$1"
        local -a args
        read -ra args <<<"${1#proxxx }"
        "$BIN" "${args[@]}"
        sleep 2.2
    }
    clear
    say "nodes, guests and storage of a Proxmox VE cluster, over its API"
    type_run "proxxx ls nodes"
    type_run "proxxx ls guests"
    type_run "proxxx ls storage"
    say "the whole cluster in one digest"
    type_run "proxxx describe"
    say "piped, every command speaks JSON or TSV"
    typed "proxxx ls guests --format json | jq -r '.[] | select(.status == \"running\") | .name'"
    "$BIN" ls guests --format json | jq -r '.[] | select(.status == "running") | .name'
    sleep 3
    exit 0
fi

SCRIPT_DIR="$REPO/tests/live"
# shellcheck source=SCRIPTDIR/../tests/live/lib.sh
. "$SCRIPT_DIR/lib.sh"
live_load_env
live_normalize_token
live_isolate
trap live_cleanup EXIT
export RUST_LOG=proxxx=error TERM=xterm-256color BIN

"$BIN" start "$VMID" >/dev/null
for _ in $(seq 1 30); do
    st="$("$BIN" ls guests --format json | python3 -c "import json,sys; print(next((g['status'] for g in json.load(sys.stdin) if g['vmid']==$VMID), ''))")"
    [[ "$st" == running ]] && break
    sleep 2
done
[[ "$st" == running ]] || { echo "guest $VMID is not running; not recording" >&2; exit 1; }
sleep 65 # the uptime column counts whole minutes: let it read 1m, not 0m

asciinema rec --overwrite --quiet --headless --window-size 100x26 \
    --output-format asciicast-v2 --idle-time-limit 2.5 \
    --title "proxxx: a read-only tour of the CLI" \
    --command "$0 --scene" "$OUT"

"$BIN" stop "$VMID" >/dev/null
echo "recorded $OUT; $VMID stopped" >&2
