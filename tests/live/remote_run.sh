#!/usr/bin/env bash
# Drive the live tier on the LAN e2e box and bring the record back.
#
# Why not GitHub Actions: proxxx is a public repo, and any self-hosted
# runner attached to it can be named by a fork's own workflow file
# (`runs-on: [self-hosted, ...]`). The live tier needs real PVE
# credentials, so neither the runner nor the credentials go to GitHub.
# The box is reached over the LAN via the hypervisor — no inbound
# tunnel, nothing exposed to the internet.
#
# Usage:
#   tests/live/remote_run.sh [<git-ref>] [--mutations]
#
# Overrides:
#   PROXXX_LIVE_HYPERVISOR   ssh target of the PVE node (default root@192.168.0.204)
#   PROXXX_LIVE_CTID         container id of the e2e box (default 210)
set -euo pipefail

HV="${PROXXX_LIVE_HYPERVISOR:-root@192.168.0.204}"
CTID="${PROXXX_LIVE_CTID:-210}"
REF="${1:-$(git rev-parse HEAD)}"
[ "${REF#--}" != "$REF" ] && REF="$(git rev-parse HEAD)"

MUTATE=""
for a in "$@"; do [ "$a" = "--mutations" ] && MUTATE="--mutations"; done

echo "==> live tier: ref=$REF box=$HV/ct$CTID mutations=${MUTATE:-none}"
[ -n "$MUTATE" ] && echo "    WARNING: the mutating suites create and destroy real guests."

set +e
ssh "$HV" "pct exec $CTID -- /usr/local/bin/proxxx-live-run '$REF' $MUTATE"
rc=$?
set -e

SHA=$(git rev-parse "$REF" 2>/dev/null || echo "$REF")
mkdir -p tests/live/records
if ssh "$HV" "pct exec $CTID -- cat /opt/proxxx-live/records/live-tier-$SHA.md" \
     > "tests/live/records/live-tier-$SHA.md" 2>/dev/null; then
  echo "==> record saved: tests/live/records/live-tier-$SHA.md"
else
  rm -f "tests/live/records/live-tier-$SHA.md"
  echo "==> no record produced (the run did not get far enough)" >&2
fi
exit $rc
