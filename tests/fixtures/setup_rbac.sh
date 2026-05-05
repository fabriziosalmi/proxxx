#!/usr/bin/env bash
# Phase 7 RBAC fixture provisioner.
#
# Idempotent: safe to re-run. Every `pveum` invocation either succeeds
# or produces a "already exists" message we treat as success. Tokens
# are NEW each run — if you need stable secrets across runs, capture
# them once and store in env vars (see README.md, "Multi-token E2E
# env injection").
#
# Provisions 4 personas on the target PVE cluster:
#
#   root@pam        already exists; this script grants nothing extra
#   operator@pve    PVEVMAdmin on /vms/${OP_VMID:-8888}
#                   → can start/stop/restart that ONE VM, nothing else
#   auditor@pve     PVEAuditor on /
#                   → read-only across the whole cluster
#   blind@pve       PVEVMUser on /vms/${BLIND_VMID:-9999}
#                   → scoped to a single (possibly nonexistent) VMID;
#                     /cluster/resources etc. return [] for this user
#
# Each non-root persona gets a privsep=1 API token (`proxxx-rbac`) so
# the token's ACL is independent of the user's. We grant the same role
# to the TOKEN (not just the user) — without that, privsep tokens have
# zero effective permissions and every call returns 403, which is NOT
# the behavior we want to test.
#
# Run on a PVE node (root@pam shell). Outputs token secrets to stdout.
# Capture them and `export` as PROXXX_E2E_TOKEN_{OPERATOR,AUDITOR,BLIND}
# before running `cargo test --test rbac_live --ignored`.
#
# Cleanup: re-run with `--teardown` to remove all 3 personas + tokens
# + ACLs in one shot.

set -euo pipefail

# ── Configurable knobs ─────────────────────────────────────────
OP_VMID="${OP_VMID:-8888}"
BLIND_VMID="${BLIND_VMID:-9999}"
TOKEN_NAME="${TOKEN_NAME:-proxxx-rbac}"

OP_USER="operator@pve"
AUDIT_USER="auditor@pve"
BLIND_USER="blind@pve"

# ── Helpers ────────────────────────────────────────────────────
have_pveum() {
    command -v pveum >/dev/null 2>&1
}

# Print to stderr so token-capture pipelines don't get noise.
log() {
    printf '%s\n' "$*" >&2
}

# Run pveum, treating "already exists" as success.
pveum_idempotent() {
    if pveum "$@" 2>/tmp/pveum_err; then
        return 0
    fi
    if grep -qiE "already (exists|registered)" /tmp/pveum_err; then
        log "  (already exists, skipping)"
        return 0
    fi
    cat /tmp/pveum_err >&2
    return 1
}

# Create user + privsep token; emit:
#     PERSONA=<persona> USERID=<user> TOKENID=<id> SECRET=<secret>
# on stdout, one line per persona. Caller parses.
create_persona_with_token() {
    local persona="$1" userid="$2"
    log "→ Provisioning ${persona} (${userid})"

    log "  • adding user"
    pveum_idempotent useradd "$userid" --comment "Phase 7 RBAC test fixture (${persona})"

    log "  • removing any pre-existing token (so secret is regenerated)"
    pveum user token remove "$userid" "$TOKEN_NAME" 2>/dev/null || true

    log "  • creating privsep token ${TOKEN_NAME}"
    # `pveum user token add` with --output-format=json gives us the
    # secret in a parseable shape. Without it, the secret is interleaved
    # with a human-readable table.
    local payload
    payload=$(pveum user token add "$userid" "$TOKEN_NAME" \
                  --privsep 1 \
                  --output-format json)
    local secret
    secret=$(printf '%s' "$payload" | python3 -c "import json,sys; print(json.load(sys.stdin)['value'])")
    if [[ -z "$secret" ]]; then
        log "  ✗ failed to extract token secret from: $payload"
        return 1
    fi
    printf 'PERSONA=%s USERID=%s TOKENID=%s SECRET=%s\n' \
           "$persona" "$userid" "$TOKEN_NAME" "$secret"
}

# Grant role to BOTH the user AND the token (privsep tokens need
# explicit token-level ACL; without it, the token has zero perms
# regardless of the user's permissions).
grant_acl_user_and_token() {
    local userid="$1" path="$2" role="$3"
    log "  • ACL: grant ${role} on ${path} to user ${userid}"
    pveum_idempotent acl modify "$path" -user "$userid" -role "$role"
    log "  • ACL: grant ${role} on ${path} to token ${userid}!${TOKEN_NAME}"
    pveum_idempotent acl modify "$path" -token "${userid}!${TOKEN_NAME}" -role "$role"
}

# Revoke ACL + delete token + delete user.
teardown_persona() {
    local persona="$1" userid="$2"
    log "→ Tearing down ${persona} (${userid})"
    # Revoke all ACLs by removing the user — PVE cascades.
    pveum user token remove "$userid" "$TOKEN_NAME" 2>/dev/null || true
    pveum userdel "$userid" 2>/dev/null || true
}

# ── Main ───────────────────────────────────────────────────────
if ! have_pveum; then
    log "✗ pveum not on PATH. Run this script on a PVE node."
    exit 1
fi

if [[ "${1:-}" == "--teardown" ]]; then
    log "==== Phase 7 RBAC fixture teardown ===="
    teardown_persona operator "$OP_USER"
    teardown_persona auditor  "$AUDIT_USER"
    teardown_persona blind    "$BLIND_USER"
    log "==== done ===="
    exit 0
fi

log "==== Phase 7 RBAC fixture provisioning ===="
log "    operator gets PVEVMAdmin on /vms/${OP_VMID}"
log "    auditor  gets PVEAuditor  on /"
log "    blind    gets PVEVMUser   on /vms/${BLIND_VMID}"
log ""

# operator
create_persona_with_token operator "$OP_USER"
grant_acl_user_and_token "$OP_USER" "/vms/${OP_VMID}" "PVEVMAdmin"

# auditor
create_persona_with_token auditor "$AUDIT_USER"
grant_acl_user_and_token "$AUDIT_USER" "/" "PVEAuditor"

# blind
create_persona_with_token blind "$BLIND_USER"
grant_acl_user_and_token "$BLIND_USER" "/vms/${BLIND_VMID}" "PVEVMUser"

log ""
log "==== done — capture the lines above as PROXXX_E2E_TOKEN_* env vars ===="
