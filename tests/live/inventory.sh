#!/usr/bin/env bash
# Read-only snapshot of a cluster's configuration, for a before/after
# comparison around the live battery (#543). GET requests only.
#
# Usage:
#   tests/live/inventory.sh <outdir>
#   diff -r <before> <after>        # an unchanged cluster compares equal
#
# One JSON file per endpoint, normalized so that only a change of state shows
# up in a diff: resource metrics in cluster/resources (cpu, mem, uptime, I/O,
# pressure), every `digest` (it changes on any write to the file, even one
# that leaves the content as it was), list order, and the order inside a
# storage `content` list are dropped or sorted.
#
# The URL and token come from the env file, through lib.sh. The token is
# passed to curl on stdin, so it is not in the process listing.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=tests/live/lib.sh
. "$SCRIPT_DIR/lib.sh"

OUT="${1:?usage: inventory.sh <outdir>}"
mkdir -p "$OUT"

live_load_env
live_normalize_token || exit 1
: "${PROXXX_E2E_PVE_URL:?env PROXXX_E2E_PVE_URL not set}"
URL="${PROXXX_E2E_PVE_URL%/}"

ENDPOINTS=(
    cluster/resources
    pools
    storage
    cluster/ha/resources
    cluster/ha/rules
    cluster/mapping/pci
    cluster/mapping/usb
    cluster/firewall/options
    cluster/firewall/aliases
    cluster/firewall/ipset
    cluster/firewall/groups
    access/users
    access/groups
    access/acl
    cluster/backup
    cluster/replication
    cluster/notifications/matchers
)

failed=0
for ep in "${ENDPOINTS[@]}"; do
    file="$OUT/${ep//\//_}.json"
    raw="$file.raw"
    if ! printf 'header = "Authorization: PVEAPIToken=root@pam!%s"\n' "$PROXXX_E2E_PVE_TOKEN" \
        | curl -sk --fail --max-time 20 --config - "$URL/api2/json/$ep" > "$raw"; then
        echo "inventory: GET $ep failed" >&2
        printf '{"error": "GET failed"}\n' > "$raw"
        failed=$((failed + 1))
    fi
    python3 -I - "$raw" "$file" "$ep" <<'PY'
import json
import sys

raw, out, ep = sys.argv[1:4]
try:
    with open(raw) as f:
        data = json.load(f).get("data")
except (OSError, ValueError, AttributeError) as e:
    data = {"unparsable": str(e)}

# Fields of cluster/resources that move while nothing is changed.
METRICS = {
    "cpu", "mem", "maxmem", "maxcpu", "disk", "maxdisk", "diskuse", "memhost",
    "uptime", "netin", "netout", "diskread", "diskwrite", "level", "cgroup-mode",
    "pressurecpusome", "pressurecpufull", "pressureiosome", "pressureiofull",
    "pressurememorysome", "pressurememoryfull",
}


def norm(x):
    if isinstance(x, dict):
        out = {}
        for k, v in sorted(x.items()):
            if k == "digest" or (ep == "cluster/resources" and k in METRICS):
                continue
            if k == "content" and isinstance(v, str):
                out[k] = ",".join(sorted(v.split(",")))
            else:
                out[k] = norm(v)
        return out
    if isinstance(x, list):
        return sorted((norm(i) for i in x), key=lambda i: json.dumps(i, sort_keys=True))
    return x


with open(out, "w") as f:
    json.dump(norm(data), f, indent=1, sort_keys=True)
    f.write("\n")
PY
    rm -f "$raw"
done

echo "inventory: ${#ENDPOINTS[@]} endpoints in $OUT ($failed failed)"
exit "$failed"
