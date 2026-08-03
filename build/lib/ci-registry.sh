#!/usr/bin/env bash
# lib/ci-registry.sh
#
# Purpose:
#   Registry credential discovery and login helpers (supports AWS ECR, ICR, docker.io, ghcr, quay)
#
# Usage:
#   source lib/ci-registry.sh
#
# Functions:
#   ci_get_registry_crs <registry> -> prints user:pass (or returns 1)
#   ci_get_raw_aws_credentials <registry> -> prints access_key:secret_key (or returns 1)
#   ci_aws_login <access_key> <secret_key> [region] -> returns 0 on success
#   ci_login_to_registry <registry> -> returns 0 on success (no-ops for local registries)
#   ci_resolve_authfile -> prints auth file path (or returns 1)
#
# Example:
#   creds=$(ci_get_registry_crs "docker.io")
#   ci_login_to_registry "docker.io"
#   aws_creds=$(ci_get_raw_aws_credentials "123.dkr.ecr.us-east-1.amazonaws.com")
#   ci_aws_login "$access_key" "$secret_key" "us-east-1"
#

# Prevent double-sourcing
[[ -n "${CI_REGISTRY_LOADED:-}" ]] && return 0
declare -g CI_REGISTRY_LOADED=1

# Source dependencies
if [[ -z "${CI_CORE_LOADED:-}" ]]; then
    LIB_DIR="${LIB_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
    # shellcheck source=/dev/null
    source "${LIB_DIR}/ci-core.sh"
fi

# Source ECR module for repository creation
if [[ -z "${CI_ECR_LOADED:-}" ]]; then
    # shellcheck source=/dev/null
    source "${LIB_DIR}/ci-ecr.sh" 2>/dev/null || true
fi



# ci_get_raw_aws_credentials
# Purpose:
#   Get raw AWS access key and secret key from environment (before token conversion)
# Input:
#   $1 - AWS ECR registry (e.g., 123456789012.dkr.ecr.us-east-1.amazonaws.com)
# Output:
#   Prints "access_key:secret_key" to stdout
# Returns:
#   0 on success, 1 if credentials not found
# WHY:
#   ci_get_registry_crs converts AWS keys to AWS:token format for docker login
#   but AWS CLI commands need the original access_key:secret_key pair
# Example:
#   creds=$(ci_get_raw_aws_credentials "123456789012.dkr.ecr.us-east-1.amazonaws.com")
#   access_key="${creds%%:*}"
#   secret_key="${creds#*:}"
ci_get_raw_aws_credentials() {
    local registry="$1"
    [[ -z "$registry" ]] && { log_debug "ci_get_raw_aws: registry required" >&2; return 1; }

    # WHY: Build credential key from registry name (same logic as ci_get_registry_crs)
    local key_base
    key_base="$(printf '%s' "$registry" | tr -cs '[:alnum:]' '_' | sed 's/^_*//; s/_*$//')"
    [[ -z "$key_base" ]] && key_base="$(printf '%s' "$registry" | tr -cs '[:alnum:]' '_')"

    local user_key="user_${key_base}"
    local pass_key="password_${key_base}"

    local user pass

    # WHY: Try get_env first (IBM Cloud Toolchain), then environment variables
    if command -v get_env >/dev/null 2>&1; then
        user="$(get_env "$user_key" "" 2>/dev/null || true)"
        pass="$(get_env "$pass_key" "" 2>/dev/null || true)"
    fi

    # Fallback to direct environment variables
    [[ -z "$user" ]] && user="${!user_key:-}"
    [[ -z "$pass" ]] && pass="${!pass_key:-}"

    # WHY: Return credentials only if both are present
    [[ -n "$user" && -n "$pass" ]] && { printf '%s:%s\n' "$user" "$pass"; return 0; }
    return 1
}

# ci_aws_login
# Purpose:
#   Authenticate to AWS using access key and secret key (validates credentials)
# Input:
#   $1 - AWS access key ID (AKIA*)
#   $2 - AWS secret access key
#   $3 - AWS region (optional, defaults to us-east-1)
# Output:
#   Logs authentication status
# Returns:
#   0 on success, 1 on failure
# WHY:
#   Centralized AWS authentication function for reuse across scripts
#   Validates credentials using aws sts get-caller-identity
#   Uses inline environment variables for security (no export)
# Example:
#   ci_aws_login "$access_key" "$secret_key" "us-east-1"
ci_aws_login() {
    local access_key="$1"
    local secret_key="$2"
    local region="${3:-us-east-1}"

    [[ -z "$access_key" || -z "$secret_key" ]] && {
        log_debug "ci_aws_login: access_key and secret_key required" >&2
        return 1
    }

    command -v aws >/dev/null 2>&1 || {
        log_debug "ci_aws_login: aws cli not found" >&2
        return 1
    }

    # WHY: Use inline environment variables for security - credentials only visible to this command
    # No export means credentials don't persist in the shell environment
    if ! AWS_ACCESS_KEY_ID="$access_key" AWS_SECRET_ACCESS_KEY="$secret_key" AWS_DEFAULT_REGION="$region" \
         aws sts get-caller-identity --region "$region" >/dev/null 2>&1; then
        log_debug "ci_aws_login: authentication failed - invalid credentials" >&2
        return 1
    fi

    return 0
}

# ci_generate_ecr_token
# Purpose:
#   Generate AWS ECR authentication token using AWS credentials
# Input:
#   $1 - AWS region (e.g., us-west-2)
#   $2 - AWS access key ID (optional, uses env if not provided)
#   $3 - AWS secret access key (optional, uses env if not provided)
# Output:
#   Prints ECR token to stdout
# Returns:
#   0 on success, 1 on failure
# WHY:
#   Modular function to handle ECR token generation with proper credential handling
ci_generate_ecr_token() {
    local region="$1"
    local access_key="${2:-}"
    local secret_key="${3:-}"

    [[ -z "$region" ]] && { log_debug "ci_generate_ecr_token: region required" >&2; return 1; }

    command -v aws >/dev/null 2>&1 || { log_debug "ci_generate_ecr_token: aws cli not found" >&2; return 1; }

    # WHY: Temporarily disable debug tracing to prevent pollution of token output
    local xtrace_state=""
    [[ $- =~ x ]] && xtrace_state="on" && set +x

    local token
    if [[ -n "$access_key" && -n "$secret_key" ]]; then
        # WHY: Use explicit credentials when provided
        token="$(AWS_ACCESS_KEY_ID="$access_key" AWS_SECRET_ACCESS_KEY="$secret_key" \
                aws ecr get-login-password --region "$region" 2>/dev/null || true)"
    else
        # WHY: Fallback to default AWS CLI credentials (IAM role, env vars, config file)
        token="$(aws ecr get-login-password --region "$region" 2>/dev/null || true)"
    fi

    # WHY: Restore debug tracing if it was enabled
    [[ "$xtrace_state" == "on" ]] && set -x

    [[ -n "$token" ]] && { printf '%s\n' "$token"; return 0; }
    return 1
}


ci_get_registry_crs() {
    local registry="$1"
    [[ -z "$registry" ]] && return 1

    local key_base
    key_base="$(printf '%s' "$registry" | tr -cs '[:alnum:]' '_' | sed 's/^_*//; s/_*$//')"
    [[ -z "$key_base" ]] && key_base="$(printf '%s' "$registry" | tr -cs '[:alnum:]' '_')"

    local user="" token="" _uk="" _tk="" _pair=""
    local _use_get_secret=false
    local _use_get_env=false
    command -v get_secret >/dev/null 2>&1 && _use_get_secret=true
    command -v get_env >/dev/null 2>&1 && _use_get_env=true

    # PRIORITY 0: Try dockerconfigjson first (single unified credential source)
    # WHY: Supports standard Kubernetes dockerconfigjson secret format
    # Matches registry by longest path first (most specific wins)
    local dockerconfig_json=""
    if $_use_get_secret; then
        dockerconfig_json="$(get_secret "dockerconfigjson" "" 2>/dev/null || true)"
    fi
    [[ -z "$dockerconfig_json" ]] && dockerconfig_json="${DOCKERCONFIG_JSON:-}"

    if [[ -n "$dockerconfig_json" ]]; then
        # WHY: Temporarily disable debug to avoid polluting credential extraction
        local xtrace_state=""
        [[ $- =~ x ]] && xtrace_state="on" && set +x

        local decoded_config
        decoded_config="$(echo "${dockerconfig_json}" | base64 --decode 2>/dev/null || true)"

        if [[ -n "$decoded_config" ]] && command -v jq >/dev/null 2>&1; then
            # WHY: Sort keys by length descending to match most specific path first
            # Example: "us.icr.io/namespace" matches before "us.icr.io"
            local keys
            keys="$(echo "${decoded_config}" | jq -r '.auths | keys[]' 2>/dev/null | \
                    awk '{ print length, $0 }' | sort -rn | awk '{print $2}' || true)"

            while IFS= read -r auth_key; do
                [[ -z "$auth_key" ]] && continue
                # WHY: Match registry URL against auth key (prefix match)
                if [[ "${registry}" == "${auth_key}"* ]]; then
                    user="$(echo "${decoded_config}" | jq -r --arg repo "${auth_key}" '.auths[$repo].username // empty' 2>/dev/null || true)"
                    token="$(echo "${decoded_config}" | jq -r --arg repo "${auth_key}" '.auths[$repo].password // empty' 2>/dev/null || true)"
                    [[ -n "$user" && -n "$token" ]] && break
                fi
            done <<< "$keys"
        fi

        # WHY: Restore debug tracing if it was enabled
        [[ "$xtrace_state" == "on" ]] && set -x

        # WHY: For ECR registries, check if we got AWS access keys that need token conversion
        # If so, don't return yet - let the ECR logic below handle token generation
        if [[ -n "$user" && -n "$token" ]]; then
            if [[ "$registry" =~ ^[0-9]{12}\.dkr\.ecr(-fips)?\.([a-z0-9-]+)\.amazonaws\.com$ ]]; then
                # WHY: Got credentials from dockerconfigjson for ECR registry
                # Check if it's AWS access keys (need conversion) or pre-generated token (ready to use)
                if [[ "$user" =~ ^AKIA && "$token" =~ ^[a-zA-Z0-9/+]{40}$ ]]; then
                    # WHY: AWS access keys - let ECR logic below convert to token
                    :
                elif [[ "$user" == "AWS" ]]; then
                    # WHY: Pre-generated ECR token - return immediately
                    printf '%s:%s\n' "$user" "$token"
                    return 0
                else
                    # WHY: Unknown credential format for ECR - try it anyway
                    printf '%s:%s\n' "$user" "$token"
                    return 0
                fi
            else
                # WHY: Non-ECR registry - return credentials as-is
                printf '%s:%s\n' "$user" "$token"
                return 0
            fi
        fi
    fi

    # Lookup chain: registry-specific → SRC → DST → generic
    # Fills missing user/token from each source in priority order
    for _pair in \
        "user_${key_base}:password_${key_base}" \
        "SRC_REGISTRY_USER:SRC_REGISTRY_PASS" \
        "DST_REGISTRY_USER:DST_REGISTRY_PASS"; do

        _uk="${_pair%%:*}"
        _tk="${_pair#*:}"

        if [[ -z "$user" ]]; then
            if $_use_get_env; then
                user="$(get_env "$_uk" "" 2>/dev/null || true)"
            else
                user="${!_uk-}"
            fi
        fi
        if [[ -z "$token" ]]; then
            if $_use_get_secret; then
                token="$(get_secret "$_tk" "" 2>/dev/null || true)"
            else
                token="${!_tk-}"
            fi
        fi
        [[ -n "$user" && -n "$token" ]] && break
    done

    # ECR: token-based auth (sequential fallthrough — NOT elif)
    if [[ "$registry" =~ ^[0-9]{12}\.dkr\.ecr(-fips)?\.([a-z0-9-]+)\.amazonaws\.com$ ]]; then
        local region="${BASH_REMATCH[2]}" ecr_tok=""

        # AWS access keys → generate ECR auth token
        if [[ -n "$user" && -n "$token" \
              && "$user" =~ ^AKIA \
              && "$token" =~ ^[a-zA-Z0-9/+]{40}$ ]]; then
            ecr_tok="$(ci_generate_ecr_token "$region" "$user" "$token")" || true
        fi
        # Pre-generated token (user=AWS)
        if [[ -z "$ecr_tok" && "$user" == "AWS" && -n "$token" ]]; then
            ecr_tok="$token"
        fi
        # Fallback: default AWS CLI credentials
        if [[ -z "$ecr_tok" ]]; then
            ecr_tok="$(ci_generate_ecr_token "$region")" || true
        fi

        user="" token=""
        [[ -n "$ecr_tok" ]] && { printf 'AWS:%s\n' "$ecr_tok"; ecr_tok=""; return 0; }
        return 1
    fi

    # ICR: default username "iamapikey"
    if [[ "$registry" =~ ^(.*\.)?icr\.io(/|$) ]]; then
        [[ -z "$user" ]] && user="iamapikey"
        if [[ -n "$token" ]]; then
            printf '%s:%s\n' "$user" "$token"
            user="" token=""
            return 0
        fi
        user="" token=""
        return 1
    fi

    # Other registries: assign default username when only token is available
    if [[ -z "$user" && -n "$token" ]]; then
        case "$registry" in
            docker.io) user="docker"    ;;
            ghcr.io)   user="ghcr"      ;;
            quay.io)   user="quay"      ;;
            *)         user="anonymous" ;;
        esac
    fi

    if [[ -n "$user" && -n "$token" ]]; then
        printf '%s:%s\n' "$user" "$token"
        user="" token=""
        return 0
    fi
    user="" token=""
    return 1
}

# Attempt login (best-effort). Skip local registries.
ci_login_to_registry(){
    local registry="${1:-docker.io}"
    local engine
    engine="$(detect_container_engine 2>/dev/null || echo docker)"

    # Skip login for obvious local registries
    if [[ "$registry" =~ ^localhost($|:|/) ]] || [[ "$registry" =~ ^127\.0\.0\.1 ]] || [[ "$registry" =~ ^10\.|^172\.|^192\. ]]; then
        log_debug "ci_login_to_registry: skipping login for local registry $registry"
        return 0
    fi

    # WHY: Call credential lookup WITHOUT suppressing stderr so debug logs are visible
    log_info "Looking up credentials for registry: $registry"
    local cs
    cs="$(ci_get_registry_crs "$registry" || true)"
    if [[ -z "$cs" ]]; then
        log_warn "No credentials found for $registry - allowing anonymous access"
        return 0
    fi

    local user="${cs%%:*}" pass="${cs#*:}"
    log_info "Logging into $registry (user=${user})"

    # WHY: Use --password-stdin for security and proper handling of special characters
    case "$engine" in
        docker)
            if [[ "$user" == "AWS" ]]; then
                printf '%s' "$pass" | docker login --username AWS --password-stdin "$registry" >/dev/null 2>&1
            else
                docker login "$registry" -u "$user" -p "$pass" >/dev/null 2>&1
            fi
            ;;
        podman)
            if [[ "$user" == "AWS" ]]; then
                printf '%s' "$pass" | podman login --username AWS --password-stdin "$registry" >/dev/null 2>&1
            else
                podman login "$registry" -u "$user" -p "$pass" >/dev/null 2>&1
            fi
            ;;
        *)
            log_warn "Unknown engine ${engine}"
            return 1
            ;;
    esac

    # WHY: Check login result and provide clear feedback
    if [[ $? -eq 0 ]]; then
        log_info "  ✓ Successfully logged into $registry"
        return 0
    else
        log_warn "  ✗ Login failed for $registry (continuing anyway)"
        return 1
    fi
}

# Resolve auth file path for skopeo/other tools
ci_resolve_authfile(){
    local engine
    engine="$(detect_container_engine 2>/dev/null || echo podman)"
    case "$engine" in
        docker)
            local docker_auth="${DOCKER_CONFIG:-$HOME/.docker/config.json}"
            [[ -f "$docker_auth" ]] && { printf '%s\n' "$docker_auth"; return 0; }
            ;;
        podman)
            local xdg_auth="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/containers/auth.json"
            [[ -f "$xdg_auth" ]] && { printf '%s\n' "$xdg_auth"; return 0; }
            local home_auth="$HOME/.config/containers/auth.json"
            [[ -f "$home_auth" ]] && { printf '%s\n' "$home_auth"; return 0; }
            ;;
    esac

    for p in "$HOME/.docker/config.json" "$HOME/.config/containers/auth.json" "/root/.docker/config.json" "/root/.config/containers/auth.json"; do
        [[ -f "$p" ]] && { printf '%s\n' "$p"; return 0; }
    done
    return 1
}

# =============================================================================
# ci_login_all_registries
# Purpose:
#   Login to all registries in prioritized order: FROM registries first, then push registries
# Input:
#   None (uses CONFIG[FROM_REGISTRY_*] and REGISTRIES array)
# Output:
#   Logs login status for each registry
# Returns:
#   0 always (best-effort login)
# WHY:
#   Centralize registry login logic with proper priority ordering
#   FROM registries need to be logged in first for pulling base images
# =============================================================================
ci_login_all_registries() {
    log_info "Logging into registries..."
    local login_list=()

    # PRIORITY 1: Add FROM registries from Dockerfile (for pulling base images)
    local i=0
    while true; do
        local from_reg="${CONFIG[FROM_REGISTRY_${i}]:-}"
        [[ -z "$from_reg" ]] && break
        log_debug "Adding FROM registry to login list (priority): $from_reg"
        login_list+=("$from_reg")
        ((i++))
    done

    # PRIORITY 2: Add push registries from REGISTRIES array
    for reg_entry in "${REGISTRIES[@]:-}"; do
        local reg_name
        reg_name="$(echo "$reg_entry" | cut -d, -f1)"
        [[ -n "$reg_name" ]] && login_list+=("$reg_name")
    done

    # Deduplicate registry list while preserving order
    if [[ ${#login_list[@]} -gt 0 ]]; then
        local -a unique_list=()
        local -A seen=()
        for r in "${login_list[@]}"; do
            if [[ -z "${seen[$r]:-}" ]]; then
                unique_list+=("$r")
                seen[$r]=1
            fi
        done
        login_list=("${unique_list[@]}")
        log_debug "Unique registries to login (in order): ${login_list[*]}"

        for r in "${login_list[@]}"; do
            log_info "Logging into registry: $r"
            ci_login_to_registry "$r" || true
        done
    else
        log_warn "No registries configured for login"
    fi
}

# =============================================================================
# ci_prepull_from_images
# Purpose:
#   Pre-pull all FROM images from Dockerfile to handle ICR namespace credentials
# Input:
#   $1 - Dockerfile path
#   $2 - Container engine (docker/podman)
# Output:
#   Prints array of pulled image references (one per line)
# Returns:
#   0 on success
# WHY:
#   Docker build may not properly authenticate to ICR with namespace/prefix in registry
#   Pre-pulling ensures images are available locally with correct credentials
# =============================================================================
ci_prepull_from_images() {
    local dockerfile="$1"
    local engine="$2"

    log_info "Pre-pulling FROM images..."
    local -a pulled_images=()

    while IFS= read -r line || [[ -n "$line" ]]; do
        # Skip comments
        [[ "$line" =~ ^[[:space:]]*# ]] && continue

        # Match FROM statement
        if [[ "$line" =~ ^[[:space:]]*FROM[[:space:]]+(.+)$ ]]; then
            local from_clause="${BASH_REMATCH[1]}"

            # Remove --platform=... if present
            from_clause=$(echo "$from_clause" | sed -E 's/--platform=[^[:space:]]+[[:space:]]+//')

            # Extract image reference
            local image_ref
            image_ref=$(echo "$from_clause" | awk '{print $1}')

            # Skip scratch and build stage references
            [[ "$image_ref" =~ ^(scratch|[a-z][a-z0-9_-]*)$ ]] && continue

            log_info "Pre-pulling: $image_ref"
            if [[ "$engine" == "docker" ]]; then
                if docker pull "$image_ref" 2>&1 | grep -v '^[a-f0-9]\{64\}$'; then
                    pulled_images+=("$image_ref")
                    log_success "Pulled: $image_ref"
                else
                    log_warn "Failed to pull: $image_ref (build may fail)"
                fi
            else
                if podman pull "$image_ref" 2>&1 | grep -v '^[a-f0-9]\{64\}$'; then
                    pulled_images+=("$image_ref")
                    log_success "Pulled: $image_ref"
                else
                    log_warn "Failed to pull: $image_ref (build may fail)"
                fi
            fi
        fi
    done < "$dockerfile"

    # Return pulled images as space-separated string
    printf '%s\n' "${pulled_images[@]}"
}

# =============================================================================
# ci_cleanup_pulled_images
# Purpose:
#   Remove pre-pulled FROM images to free disk space
# Input:
#   $1 - Container engine (docker/podman)
#   $@ - List of image references to remove
# Output:
#   Logs cleanup status
# Returns:
#   0 always (best-effort cleanup)
# WHY:
#   Free disk space after successful build
# =============================================================================
ci_cleanup_pulled_images() {
    local engine="$1"
    shift
    local -a images=("$@")

    [[ ${#images[@]} -eq 0 ]] && return 0

    log_info "Cleaning up pre-pulled FROM images..."
    for img in "${images[@]}"; do
        log_debug "Removing pre-pulled image: $img"
        if [[ "$engine" == "docker" ]]; then
            docker rmi "$img" >/dev/null 2>&1 || log_debug "Failed to remove: $img (may be in use)"
        else
            podman rmi "$img" >/dev/null 2>&1 || log_debug "Failed to remove: $img (may be in use)"
        fi
    done
    log_info "Cleaned up ${#images[@]} pre-pulled image(s)"
}

# Export functions for use in other scripts
export -f ci_get_raw_aws_credentials
export -f ci_aws_login
export -f ci_login_all_registries
export -f ci_prepull_from_images
export -f ci_cleanup_pulled_images