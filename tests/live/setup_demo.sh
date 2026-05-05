#!/usr/bin/env bash
# Pre-recording setup for the proxxx asciinema walkthrough cast.
#
# Brings the live test cluster to the launch-ramp state expected by the
# demo script:
#   - LXC 9999 exists, stopped, on the configured node
#   - QEMU 8888 (alpine-existing) exists, running, disk on local-lvm
#     (so the disk-move-to-NFS demo step is meaningful, not a no-op)
#   - At least one NFS storage is configured + reachable
#
# Sources `tests/live/env.local` for cluster credentials — same pattern
# as test_run.sh / test_mutation.sh. Touches only the test cluster.
# Never edits a tracked file.
#
# Usage:
#   tests/live/setup_demo.sh                  # default: set up + verify (idempotent)
#   tests/live/setup_demo.sh --teardown       # remove LXC 9999, leave 8888 alone
#   tests/live/setup_demo.sh --check          # read-only verification, no mutations
#   tests/live/setup_demo.sh --with-ssh       # check + verify SSH preflight for the
#                                             # ssh_live test suite + the demo's
#                                             # `proxxx perms` step (Act 6).
#                                             # Read-only: never deploys keys or
#                                             # mutates ~/.ssh — the operator owns
#                                             # SSH provisioning to their cluster.
#
# Exit codes:
#   0 — cluster is ready (setup mode) or all preconditions met (check mode)
#         or teardown completed cleanly
#   1 — a precondition failed and could not be auto-fixed; operator must
#         intervene before recording (e.g. VM 8888 missing, NFS storage
#         absent from cluster, alpine template not on local storage)
#   2 — invalid arguments / env file missing

set -u

# ── Colour helpers ─────────────────────────────────────────
# Only emit ANSI when stdout is a TTY; preserves clean logs when this
# script is captured by tee or run in CI-style environments.
if [ -t 1 ]; then
    GREEN=$'\033[0;32m'
    YELLOW=$'\033[0;33m'
    RED=$'\033[0;31m'
    DIM=$'\033[2m'
    BOLD=$'\033[1m'
    RESET=$'\033[0m'
else
    GREEN="" YELLOW="" RED="" DIM="" BOLD="" RESET=""
fi

ok()    { printf '%s✓%s %s\n' "$GREEN" "$RESET" "$*"; }
fix()   { printf '%s⟳%s %s\n' "$YELLOW" "$RESET" "$*"; }
fail()  { printf '%s✗%s %s\n' "$RED" "$RESET" "$*" >&2; }
info()  { printf '%s%s%s\n' "$DIM" "$*" "$RESET"; }
title() { printf '\n%s%s%s\n' "$BOLD" "$*" "$RESET"; }

# ── Argument parsing ───────────────────────────────────────
MODE=setup
WITH_SSH=0
case "${1:-}" in
    ""|setup) MODE=setup ;;
    --teardown|teardown) MODE=teardown ;;
    --check|check) MODE=check ;;
    --with-ssh|with-ssh) MODE=check; WITH_SSH=1 ;;
    -h|--help)
        sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'
        exit 0
        ;;
    *)
        fail "unknown argument: $1"
        echo "usage: $0 [--teardown|--check|--with-ssh]" >&2
        exit 2
        ;;
esac

# ── Load env.local + binary path ───────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel 2>/dev/null || echo "$SCRIPT_DIR/../..")"
BIN="${BIN:-$ROOT/target/release/proxxx}"

ENV_FILE="${PROXXX_E2E_ENV_FILE:-$SCRIPT_DIR/env.local}"
if [[ ! -f "$ENV_FILE" ]]; then
    fail "env file not found: $ENV_FILE"
    info "  copy tests/live/env.local.example to tests/live/env.local and fill it in"
    exit 2
fi
# shellcheck source=/dev/null
. "$ENV_FILE"

: "${PROXXX_E2E_PVE_URL:?env PROXXX_E2E_PVE_URL not set}"
: "${PROXXX_E2E_PVE_TOKEN:?env PROXXX_E2E_PVE_TOKEN not set}"
: "${PROXXX_E2E_NODE:?env PROXXX_E2E_NODE not set}"

URL="$PROXXX_E2E_PVE_URL"
NODE="$PROXXX_E2E_NODE"
LXC_VMID=9999
QEMU_VMID="${PROXXX_E2E_QEMU_VMID:-8888}"
LXC_TEMPLATE="${PROXXX_E2E_LXC_TEMPLATE:-local:vztmpl/alpine-3.22-default_20250617_amd64.tar.xz}"
LXC_STORAGE="${PROXXX_E2E_LXC_STORAGE:-local-lvm}"
TOKEN_HEADER="Authorization: PVEAPIToken=root@pam!${PROXXX_E2E_PVE_TOKEN}"

# ── Common checks shared between setup and check ───────────

check_binary() {
    if [[ ! -x "$BIN" ]]; then
        fail "proxxx binary not found at $BIN"
        info "  build with: cargo build --release"
        return 1
    fi
    ok "proxxx binary at $BIN"
}

check_cluster_reachable() {
    if ! "$BIN" ls nodes >/dev/null 2>&1; then
        fail "cluster not reachable (proxxx ls nodes failed)"
        info "  check $URL and $PROXXX_E2E_PVE_TOKEN"
        return 1
    fi
    local count
    count=$("$BIN" --format json ls nodes | python3 -c "
import sys, json
print(len(json.load(sys.stdin)))
")
    ok "cluster reachable ($count nodes)"
}

check_nfs_storage() {
    local nfs_id
    nfs_id=$("$BIN" --format json ls storage 2>/dev/null | python3 -c "
import sys, json
for s in json.load(sys.stdin):
    if s.get('type') == 'nfs':
        print(s.get('storage', ''))
        sys.exit(0)
print('')
" 2>/dev/null)
    if [[ -z "$nfs_id" ]]; then
        fail "no NFS storage found in the cluster"
        info "  the disk-move demo step needs an NFS storage to move TO"
        return 1
    fi
    ok "NFS storage available: ${BOLD}${nfs_id}${RESET}"
    printf '\n%s  → use this id in Act 5: proxxx disk move %d --disk scsi0 --storage %s --yes%s\n\n' \
        "$DIM" "$QEMU_VMID" "$nfs_id" "$RESET"
}

check_alpine_template() {
    local storage_id="${LXC_TEMPLATE%%:*}"
    local volid_check
    volid_check=$(curl -k -s -H "$TOKEN_HEADER" \
        "$URL/api2/json/nodes/$NODE/storage/$storage_id/content?content=vztmpl" 2>/dev/null \
        | TARGET_VOLID="$LXC_TEMPLATE" python3 -c "
import os, sys, json
target = os.environ['TARGET_VOLID']
try:
    data = json.load(sys.stdin).get('data', [])
    for v in data:
        if v.get('volid') == target:
            print('ok')
            sys.exit(0)
    print('missing')
except Exception:
    print('err')
" 2>/dev/null)
    if [[ "$volid_check" != "ok" ]]; then
        fail "alpine template not found at $LXC_TEMPLATE on $NODE"
        info "  download via:"
        info "  ssh root@$NODE 'pveam update && pveam download $storage_id alpine-3.22-default_20250617_amd64.tar.xz'"
        return 1
    fi
    ok "LXC template available: $LXC_TEMPLATE"
}

check_qemu_vm_state() {
    local resp
    resp=$("$BIN" --format json ls guests 2>/dev/null | python3 -c "
import sys, json
for g in json.load(sys.stdin):
    if g.get('vmid') == $QEMU_VMID:
        print(g.get('type', '?'), g.get('status', '?'), g.get('node', '?'), g.get('name', '?'))
        sys.exit(0)
print('MISSING')
" 2>/dev/null)
    if [[ "$resp" == "MISSING" ]]; then
        fail "QEMU $QEMU_VMID not found in the cluster"
        info "  the demo expects a pre-prepared QEMU VM (defaulting to vmid 8888)"
        info "  set PROXXX_E2E_QEMU_VMID in env.local to point at your demo VM"
        return 1
    fi
    local kind status node name
    read -r kind status node name <<<"$resp"
    if [[ "$kind" != "qemu" ]]; then
        fail "VMID $QEMU_VMID is a $kind, expected qemu"
        return 1
    fi
    ok "QEMU $QEMU_VMID ($name) on $node, status=$status"
    # Track for the disk-storage check below
    QEMU_NODE_ACTUAL="$node"
    QEMU_STATUS_ACTUAL="$status"
}

check_qemu_disk_on_local_lvm() {
    # Read the VM config and confirm scsi0 (the demo's target disk) is
    # NOT already on an NFS storage — otherwise Act 5's `disk move`
    # would be a no-op and the cast would lose its punch.
    local cfg disk_storage
    cfg=$(curl -k -s -H "$TOKEN_HEADER" \
        "$URL/api2/json/nodes/${QEMU_NODE_ACTUAL:-$NODE}/qemu/$QEMU_VMID/config" 2>/dev/null)
    disk_storage=$(echo "$cfg" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin).get('data', {})
    for key in ('scsi0', 'virtio0', 'sata0', 'ide0'):
        v = data.get(key)
        if v and ':' in v:
            print(v.split(':', 1)[0])
            sys.exit(0)
    print('none')
except Exception:
    print('err')
" 2>/dev/null)
    if [[ "$disk_storage" == "none" || "$disk_storage" == "err" ]]; then
        fail "could not determine primary-disk storage of QEMU $QEMU_VMID"
        return 1
    fi
    if [[ "$disk_storage" == nfs* || "$disk_storage" == *-nfs* ]]; then
        # Heuristic: name suggests NFS; warn but don't fail
        printf '%s⚠%s primary disk of QEMU %d is on storage %s — looks like NFS\n' \
            "$YELLOW" "$RESET" "$QEMU_VMID" "$disk_storage"
        info "  Act 5 (disk move to NFS) will be a no-op or fail with 'same storage'"
        info "  consider moving back to local-lvm before recording"
        return 1
    fi
    ok "QEMU $QEMU_VMID primary disk on $disk_storage (good — Act 5 will move it)"
}

# ── SSH preflight (--with-ssh / ssh_live opt-in) ───────────
#
# Verifies the operator's machine can SSH into the PVE node BEFORE
# the ssh_live test suite tries — failures here surface as a clear
# "set this env var" / "fix this permission" message instead of a
# russh handshake error mid-test.
#
# Reads:
#   PROXXX_E2E_SSH_HOST     PVE node hostname/IP for the SSH layer
#   PROXXX_E2E_SSH_USER     defaults to "root"
#   PROXXX_E2E_SSH_KEY_PATH path to the private key (absolute or ~)
#
# This function is read-only: it never deploys keys, never edits
# ~/.ssh, never modifies the operator's known_hosts. Provisioning
# SSH access to a cluster is the operator's responsibility — same
# stance as the RBAC fixture's "you provision pveum, the script
# verifies".
check_ssh_preflight() {
    : "${PROXXX_E2E_SSH_HOST:?env PROXXX_E2E_SSH_HOST not set (e.g. \"10.0.0.1\")}"
    : "${PROXXX_E2E_SSH_KEY_PATH:?env PROXXX_E2E_SSH_KEY_PATH not set (e.g. \"\$HOME/.ssh/proxxx_e2e_ed25519\")}"
    local ssh_user="${PROXXX_E2E_SSH_USER:-root}"
    # Tilde-expand the key path so the operator can write
    # ~/.ssh/proxxx_e2e_ed25519 without having to manually expand.
    local key_path="${PROXXX_E2E_SSH_KEY_PATH/#~\//$HOME/}"

    # 1. Key file present + 0600. SSH refuses to use a world-readable
    # key — better to surface that here than as a russh "permissions
    # too open" error.
    if [[ ! -f "$key_path" ]]; then
        fail "SSH key not found at $key_path"
        info "  set PROXXX_E2E_SSH_KEY_PATH to your provisioned ed25519 key"
        return 1
    fi
    local mode
    # `stat` differs between BSD (macOS) and GNU; try both.
    mode=$(stat -f '%A' "$key_path" 2>/dev/null || stat -c '%a' "$key_path" 2>/dev/null || echo "?")
    if [[ "$mode" != "600" && "$mode" != "400" ]]; then
        fail "SSH key $key_path has mode $mode — must be 600 or 400"
        info "  fix: chmod 600 $key_path"
        return 1
    fi
    ok "SSH key at $key_path (mode $mode)"

    # 2. Round-trip a trivial command. We DON'T hit ~/.ssh/known_hosts
    # — `-o UserKnownHostsFile=/dev/null` keeps the operator's host
    # key store untouched, mirroring what ssh_live.rs does with its
    # per-test temp known_hosts.
    local out
    if ! out=$(ssh -o BatchMode=yes \
                   -o ConnectTimeout=5 \
                   -o StrictHostKeyChecking=accept-new \
                   -o UserKnownHostsFile=/dev/null \
                   -o LogLevel=ERROR \
                   -i "$key_path" \
                   "${ssh_user}@${PROXXX_E2E_SSH_HOST}" \
                   'uname -a' 2>&1); then
        fail "ssh ${ssh_user}@${PROXXX_E2E_SSH_HOST} failed:"
        echo "$out" | sed 's/^/    /' >&2
        info "  verify: the public key is in ${ssh_user}@${PROXXX_E2E_SSH_HOST}:~/.ssh/authorized_keys"
        info "  verify: the host is reachable on TCP port 22"
        return 1
    fi
    if [[ "$out" != Linux* ]]; then
        fail "uname -a returned unexpected output (PVE node should be Linux):"
        echo "$out" | sed 's/^/    /' >&2
        return 1
    fi
    ok "SSH round-trip works (${ssh_user}@${PROXXX_E2E_SSH_HOST}: $(echo "$out" | awk '{print $1, $3}'))"

    # 3. Confirm pveum is on PATH for the user — the live test runs
    # `pveum user permissions root@pam`, so this preflights the same
    # call. ENOENT here means the SSH user lacks the PVE-server PATH
    # (rare — almost always root@pam on a real PVE node).
    if ! ssh -o BatchMode=yes \
             -o ConnectTimeout=5 \
             -o StrictHostKeyChecking=accept-new \
             -o UserKnownHostsFile=/dev/null \
             -o LogLevel=ERROR \
             -i "$key_path" \
             "${ssh_user}@${PROXXX_E2E_SSH_HOST}" \
             'command -v pveum' >/dev/null 2>&1; then
        fail "pveum not on PATH for ${ssh_user}@${PROXXX_E2E_SSH_HOST}"
        info "  the ssh_live test runs 'pveum user permissions root@pam' — needs PVE-server PATH"
        return 1
    fi
    ok "pveum reachable on the remote shell"
}

check_lxc_state() {
    local resp
    resp=$("$BIN" --format json ls guests 2>/dev/null | python3 -c "
import sys, json
for g in json.load(sys.stdin):
    if g.get('vmid') == $LXC_VMID:
        print(g.get('type', '?'), g.get('status', '?'))
        sys.exit(0)
print('MISSING')
" 2>/dev/null)
    case "$resp" in
        "MISSING")          LXC_STATE_ACTUAL=missing ;;
        "lxc stopped")      LXC_STATE_ACTUAL=stopped ;;
        "lxc running")      LXC_STATE_ACTUAL=running ;;
        "qemu "*)
            fail "VMID $LXC_VMID exists but is qemu, expected lxc"
            return 1
            ;;
        *)
            fail "VMID $LXC_VMID in unexpected state: $resp"
            return 1
            ;;
    esac
}

# ── Mutating helpers (setup + teardown) ────────────────────

ensure_qemu_running() {
    if [[ "${QEMU_STATUS_ACTUAL:-}" == "running" ]]; then
        return 0
    fi
    fix "QEMU $QEMU_VMID is stopped — starting"
    "$BIN" start "$QEMU_VMID" >/dev/null 2>&1 || {
        fail "could not start QEMU $QEMU_VMID"
        return 1
    }
    # Wait briefly for status to flip
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        sleep 1
        local s
        s=$("$BIN" --format json ls guests 2>/dev/null \
            | python3 -c "
import sys, json
for g in json.load(sys.stdin):
    if g.get('vmid') == $QEMU_VMID:
        print(g.get('status', '?'))
        sys.exit(0)" 2>/dev/null)
        if [[ "$s" == "running" ]]; then
            ok "QEMU $QEMU_VMID now running"
            QEMU_STATUS_ACTUAL=running
            return 0
        fi
    done
    fail "QEMU $QEMU_VMID did not reach running state within 10s"
    return 1
}

teardown_lxc_9999() {
    # Idempotent: silent if 404.
    curl -k -s -X POST "$URL/api2/json/nodes/$NODE/lxc/$LXC_VMID/status/stop" \
        -H "$TOKEN_HEADER" -o /dev/null 2>&1 || true
    sleep 2
    curl -k -s -X DELETE "$URL/api2/json/nodes/$NODE/lxc/$LXC_VMID?force=1&purge=1" \
        -H "$TOKEN_HEADER" -o /dev/null 2>&1 || true
    sleep 2
}

create_lxc_9999_stopped() {
    fix "creating LXC $LXC_VMID on $NODE from $LXC_TEMPLATE (stopped)"
    local create_resp
    create_resp=$(curl -k -s -X POST "$URL/api2/json/nodes/$NODE/lxc" \
        -H "$TOKEN_HEADER" \
        -d "vmid=$LXC_VMID" \
        -d "ostemplate=$LXC_TEMPLATE" \
        -d "hostname=proxxx-demo-lxc" \
        -d "memory=256" \
        -d "swap=0" \
        -d "rootfs=$LXC_STORAGE:1" \
        -d "unprivileged=1" \
        -d "start=0" \
        -d "password=proxxx-demo-$RANDOM")
    if echo "$create_resp" | grep -q '"data":null'; then
        fail "LXC create failed:"
        echo "$create_resp" >&2
        return 1
    fi
    # Wait for the create task to complete + the guest to appear stopped
    for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
        sleep 2
        local s
        s=$("$BIN" --format json ls guests 2>/dev/null \
            | python3 -c "
import sys, json
for g in json.load(sys.stdin):
    if g.get('vmid') == $LXC_VMID:
        print(g.get('status', '?'))
        sys.exit(0)" 2>/dev/null)
        if [[ "$s" == "stopped" ]]; then
            ok "LXC $LXC_VMID created, stopped, ready"
            return 0
        fi
    done
    fail "LXC $LXC_VMID did not reach stopped state within 30s"
    return 1
}

# ── Mode dispatch ──────────────────────────────────────────

case "$MODE" in
    setup|check)
        title "proxxx demo setup ($MODE mode$([[ "$WITH_SSH" == "1" ]] && echo " + ssh"))"
        info "Cluster: $URL  ·  Node: $NODE  ·  QEMU VMID: $QEMU_VMID  ·  LXC VMID: $LXC_VMID"

        title "Preconditions"
        check_binary || exit 1
        check_cluster_reachable || exit 1
        check_nfs_storage || exit 1
        check_alpine_template || exit 1
        check_qemu_vm_state || exit 1
        check_qemu_disk_on_local_lvm || true   # warn-only
        check_lxc_state || exit 1

        if [[ "$WITH_SSH" == "1" ]]; then
            title "SSH preflight (--with-ssh)"
            check_ssh_preflight || exit 1
        fi

        if [[ "$MODE" == "check" ]]; then
            title "Check complete"
            case "$LXC_STATE_ACTUAL" in
                missing) info "  LXC $LXC_VMID does NOT exist (setup will create)" ;;
                stopped) ok   "LXC $LXC_VMID exists and is stopped (ready)" ;;
                running) info "  LXC $LXC_VMID is running (setup will recreate to start clean)" ;;
            esac
            if [[ "${QEMU_STATUS_ACTUAL:-}" != "running" ]]; then
                info "  QEMU $QEMU_VMID is $QEMU_STATUS_ACTUAL (setup will start)"
            fi
            exit 0
        fi

        title "Bringing cluster to launch-ramp state"
        # 1. Ensure QEMU is running
        ensure_qemu_running || exit 1
        # 2. Recreate LXC fresh — clears any stale state from a prior take
        case "$LXC_STATE_ACTUAL" in
            missing)
                ok "LXC $LXC_VMID absent — fresh create"
                create_lxc_9999_stopped || exit 1
                ;;
            stopped|running)
                fix "LXC $LXC_VMID exists ($LXC_STATE_ACTUAL) — recreating for clean state"
                teardown_lxc_9999
                create_lxc_9999_stopped || exit 1
                ;;
        esac

        title "Ready to record"
        cat <<EOF

  ${BOLD}Open a fresh terminal${RESET} (so the cast doesn't include this script's
  output), then:

    ${GREEN}export PS1='\$ '${RESET}
    ${GREEN}tput civis${RESET}    # hide cursor for the recording

    ${GREEN}asciinema rec proxxx-walkthrough.cast \\
        --title "proxxx — Terminal cockpit for Proxmox VE & PBS" \\
        --idle-time-limit 2 \\
        --cols 120 --rows 32 \\
        --command 'bash --noprofile --norc -i'${RESET}

  When done:

    ${GREEN}tput cnorm${RESET}    # restore cursor

  Then run sed-scrub on the .cast file (replace lab hostnames + IPs)
  before uploading or committing.

  Between takes, run this script again — it cleans LXC $LXC_VMID
  and recreates fresh, leaves QEMU $QEMU_VMID untouched.

EOF
        ;;

    teardown)
        title "Tearing down demo state"
        check_binary || exit 1
        check_cluster_reachable || exit 1

        check_lxc_state || true
        if [[ "${LXC_STATE_ACTUAL:-missing}" == "missing" ]]; then
            ok "LXC $LXC_VMID already absent"
        else
            fix "removing LXC $LXC_VMID ($LXC_STATE_ACTUAL)"
            teardown_lxc_9999
            ok "LXC $LXC_VMID removed"
        fi

        info "  QEMU $QEMU_VMID left untouched (operator-owned)"
        info "  No tracked files were modified"
        ;;
esac
