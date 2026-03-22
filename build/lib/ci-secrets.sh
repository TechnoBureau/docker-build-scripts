#!/usr/bin/env bash
# lib/ci-secrets.sh
#
# Purpose:
#   Centralized secret resolution and secure secret temporary file creation.
#
# Usage:
#   source lib/ci-secrets.sh
#
# Functions:
#   ci_resolve_secret_value <id> -> prints value or empty
#   ci_secret_to_file <id> <value> -> prints path to temp file (0600) for build --secret mount
#
# WHY: Separate secret logic so callers don't access raw secrets in logs. Prefer pipelinectl get_env when available.
#
# Example:
#   val=$(ci_resolve_secret_value "MYSECRET")
#   file=$(ci_secret_to_file "MYSECRET" "$val")
#

# Source dependencies
if [[ -z "${CI_CORE_LOADED:-}" ]]; then
    LIB_DIR="${LIB_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
    # shellcheck source=/dev/null
    source "${LIB_DIR}/ci-core.sh"
fi

# resolve secret value: pipelinectl get_env -> get_env -> env var
ci_resolve_secret_value(){
    local id="$1"
    local val=""

    # get_env helper (IBM Cloud)
    if command -v get_env >/dev/null 2>&1; then
        val="$(get_env "$id" "" 2>/dev/null || true)"
        [[ -n "$val" ]] && { printf '%s\n' "$val"; return 0; }
    fi

    # fallback to direct env var
    val="${!id:-}"
    printf '%s\n' "$val"
}

# create secure temp file from secret value
ci_secret_to_file(){
    local id="$1" val="$2"
    if [[ -z "$id" || -z "${val:-}" ]]; then
        log_error "ci_secret_to_file: id and value required"
        return 1
    fi
    local tmp
    tmp="$(ci_create_temp_file "secret_${id}")"
    printf '%s' "$val" > "$tmp"
    chmod 600 "$tmp"
    printf '%s\n' "$tmp"
}

# =============================================================================
# auto_add_secrets_from_dockerfile
# Purpose:
#   Automatically add every detected secret (CONFIG[SECRET_*]) that has a
#   matching environment variable to CONFIG[BUILD_SECRETS]
# Input:
#   None (reads from global CONFIG array)
# Output:
#   Updates CONFIG[BUILD_SECRETS] with comma-separated id=env pairs
# WHY:
#   Allows Dockerfile to declare secrets and auto-mount them if env vars exist
# Example:
#   # Dockerfile has: RUN --mount=type=secret,id=NPM_TOKEN
#   # If NPM_TOKEN env var exists, it will be auto-added to build secrets
# =============================================================================
auto_add_secrets_from_dockerfile() {
    local id env_val
    # Iterate over CONFIG keys to find SECRET_* entries
    for key in "${!CONFIG[@]}"; do
        [[ "$key" =~ ^SECRET_([^=]+)$ ]] || continue
        id="${BASH_REMATCH[1]}"
        
        # Look for environment variable with same name
        env_val="${!id:-}"
        if [[ -n "$env_val" ]]; then
            # Add to BUILD_SECRETS if not already present
            if [[ ! "${CONFIG[BUILD_SECRETS]:-}" =~ (^|,)${id}= ]]; then
                CONFIG[BUILD_SECRETS]="${CONFIG[BUILD_SECRETS]:+${CONFIG[BUILD_SECRETS]},}${id}=${id}"
                log_info "Auto-added secret $id (from env $id)"
            fi
        else
            log_debug "Secret $id found in Dockerfile but no matching env var"
        fi
    done
}
