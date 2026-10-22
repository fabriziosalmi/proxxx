# shellcheck shell=bash
# Shared setup for the live harness scripts. Source it after the script has
# loaded its env file:
#
#   . "$SCRIPT_DIR/lib.sh"
#   live_normalize_token
#   live_isolate
#
# Every script drives two clients at the same cluster: curl, which reads
# PROXXX_E2E_PVE_URL and PROXXX_E2E_PVE_TOKEN, and the proxxx binary. The
# binary must never fall back to the caller's own config, which may point at
# production nodes (#479), and the caller's config file must never be
# rewritten. live_isolate builds a private config from the same URL and token
# and gives the binary its own audit, log and cache directories.

# Source the env file: PROXXX_E2E_ENV_FILE, else ~/.config/proxxx/live-env,
# else tests/live/env.local (gitignored). Needs SCRIPT_DIR.
live_load_env() {
    local env_file="${PROXXX_E2E_ENV_FILE:-}"
    if [[ -z "$env_file" ]]; then
        if [[ -f "${XDG_CONFIG_HOME:-$HOME/.config}/proxxx/live-env" ]]; then
            env_file="${XDG_CONFIG_HOME:-$HOME/.config}/proxxx/live-env"
        else
            env_file="$SCRIPT_DIR/env.local"
        fi
    fi
    # shellcheck source=/dev/null
    [[ -f "$env_file" ]] && . "$env_file"
    return 0
}

# Accept PROXXX_E2E_PVE_TOKEN as `<id>=<secret>` or `root@pam!<id>=<secret>`.
# The scripts send `PVEAPIToken=root@pam!$PROXXX_E2E_PVE_TOKEN`, so the prefix
# is stripped; a token of another user is refused instead of being sent as
# root@pam.
live_normalize_token() {
    local tok="${PROXXX_E2E_PVE_TOKEN:?env PROXXX_E2E_PVE_TOKEN not set (format: <id>=<secret>)}"
    if [[ "$tok" == *'!'* ]]; then
        local user="${tok%%!*}"
        if [[ "$user" != "root@pam" ]]; then
            echo "live harness: PROXXX_E2E_PVE_TOKEN belongs to $user; the scripts authenticate as root@pam" >&2
            return 1
        fi
        tok="${tok#*!}"
    fi
    if [[ "$tok" != *=* || -z "${tok%%=*}" || -z "${tok#*=}" ]]; then
        echo "live harness: PROXXX_E2E_PVE_TOKEN must be <id>=<secret>" >&2
        return 1
    fi
    export PROXXX_E2E_PVE_TOKEN="$tok"
}

# Point the proxxx binary at the cluster curl talks to. Exports PROXXX_CONFIG
# (a 0600 config in a 0700 temp dir, secret in a separate 0600 file) and the
# audit, log and cache directories. LIVE_TMP holds them; live_cleanup removes
# it, so call it from the script's EXIT trap.
live_isolate() {
    : "${PROXXX_E2E_PVE_URL:?env PROXXX_E2E_PVE_URL not set}"
    : "${PROXXX_E2E_PVE_TOKEN:?env PROXXX_E2E_PVE_TOKEN not set}"
    LIVE_TMP="$(mktemp -d "${TMPDIR:-/tmp}/proxxx-live.XXXXXX")" || return 1
    chmod 700 "$LIVE_TMP"
    local secret_file="$LIVE_TMP/token_secret"
    (umask 077 && printf '%s' "${PROXXX_E2E_PVE_TOKEN#*=}" > "$secret_file")
    (umask 077 && cat > "$LIVE_TMP/config.toml" <<EOF
url = "$PROXXX_E2E_PVE_URL"
user = "root@pam"
auth = "token"
token_id = "${PROXXX_E2E_PVE_TOKEN%%=*}"
token_secret_file = "$secret_file"
verify_tls = false
EOF
    )
    export PROXXX_CONFIG="$LIVE_TMP/config.toml"
    export PROXXX_AUDIT_DIR="$LIVE_TMP/audit"
    export PROXXX_LOG_DIR="$LIVE_TMP/log"
    export PROXXX_CACHE_DIR="$LIVE_TMP/cache"
    unset PROXXX_TOKEN_SECRET PROXXX_PROFILE
}

live_cleanup() {
    [[ -n "${LIVE_TMP:-}" && -d "$LIVE_TMP" ]] && rm -rf "$LIVE_TMP"
    return 0
}

# run_timeout SECS CMD [ARGS...]: run CMD with a time limit. macOS ships no
# `timeout`; use coreutils' `gtimeout` when present, else a perl alarm (exit
# 142 on expiry instead of 124).
run_timeout() {
    local secs="$1"; shift
    if command -v timeout >/dev/null 2>&1; then
        timeout "$secs" "$@"
    elif command -v gtimeout >/dev/null 2>&1; then
        gtimeout "$secs" "$@"
    else
        perl -e 'alarm shift; exec @ARGV or exit 127' "$secs" "$@"
    fi
}
