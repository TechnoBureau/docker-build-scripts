#!/usr/bin/env bash
# lib/ci-config.sh
#
# Purpose:
#   Configuration loading, merging, and registry array building.
#   Implements priority-based config: Dockerfile > YAML > ENV > defaults
#
# Usage:
#   source lib/ci-config.sh
#
# Functions:
#   load_config <dockerfile> <config_yaml>
#   build_registries_array
#   auto_add_secrets_from_dockerfile
#   extract_git_info [dir]
#
# Example:
#   load_config /path/to/Dockerfile /path/to/config.yaml
#

# Source dependencies
if [[ -z "${CI_CORE_LOADED:-}" ]]; then
    LIB_DIR="${LIB_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
    # shellcheck source=/dev/null
    source "${LIB_DIR}/ci-core.sh"
    # shellcheck source=/dev/null
    source "${LIB_DIR}/ci-dockerfile.sh"
    # shellcheck source=/dev/null
    source "${LIB_DIR}/ci-yaml.sh"
fi

# Ensure CONFIG and REGISTRIES arrays exist
declare -gA CONFIG 2>/dev/null || true
declare -ga REGISTRIES 2>/dev/null || true

# =============================================================================
# auto_add_secrets_from_dockerfile
# Purpose:
#   Automatically add secrets detected in Dockerfile to BUILD_SECRETS
#   if matching environment variables exist
# Input:
#   Uses CONFIG[SECRET_*] entries populated by parse_dockerfile_secrets
# Output:
#   Updates CONFIG[BUILD_SECRETS] with id=ENV_VAR pairs
# WHY:
#   Reduces manual configuration - auto-mount secrets when env vars present
# =============================================================================
auto_add_secrets_from_dockerfile() {
    local id env_val
    for key in "${!CONFIG[@]}"; do
        [[ "$key" =~ ^SECRET_([^=]+)$ ]] || continue
        id="${BASH_REMATCH[1]}"
        # Look for an environment variable with the same name
        env_val="${!id:-}"
        if [[ -n "$env_val" ]]; then
            CONFIG[BUILD_SECRETS]="${CONFIG[BUILD_SECRETS]:+${CONFIG[BUILD_SECRETS]},}${id}=${id}"
            log_info "Auto-added secret $id (from env $id)"
        else
            log_debug "Secret $id found in Dockerfile but no matching env var"
        fi
    done
}

# =============================================================================
# build_registries_array
# Purpose:
#   Build unified REGISTRIES array from Dockerfile, YAML, and ENV sources
#   Priority: Dockerfile > YAML > ENV > default (docker.io)
# Input:
#   Uses CONFIG[DF_REGISTRY_*], CONFIG[YAML_REGISTRY_*], CONFIG[ENV_REGISTRY_*]
# Output:
#   Populates global REGISTRIES array with entries: "registry,prefix,push"
# WHY:
#   Centralize registry configuration with clear precedence rules
# =============================================================================
build_registries_array() {
    REGISTRIES=()

    # --- 1️⃣ From Dockerfile comments ---
    local i=0
    while true; do
        local name prefix push
        name="${CONFIG[DF_REGISTRY_${i}]:-${CONFIG[DF_REGISTRY${i}]:-}}"
        [[ -z "$name" ]] && break  # stop when no more entries

        prefix="${CONFIG[DF_REGISTRY_${i}_PREFIX]:-${CONFIG[DF_REGISTRY${i}_PREFIX]:-}}"
        push="${CONFIG[DF_REGISTRY_${i}_PUSH]:-${CONFIG[DF_REGISTRY${i}_PUSH]:-true}}"

        push=$(echo "$push" | tr '[:upper:]' '[:lower:]')
        [[ "$push" =~ ^(true|yes|1)$ ]] && push="true" || push="false"

        REGISTRIES+=("${name},${prefix},${push}")
        i=$((i+1))
    done

    # --- 2️⃣ From YAML (if not already found) ---
    if [[ ${#REGISTRIES[@]} -eq 0 ]]; then
        i=0
        while true; do
            local name prefix push
            name="${CONFIG[YAML_REGISTRY_${i}]:-${CONFIG[YAML_REGISTRY${i}]:-}}"
            [[ -z "$name" ]] && break

            prefix="${CONFIG[YAML_REGISTRY_${i}_PREFIX]:-${CONFIG[YAML_REGISTRY${i}_PREFIX]:-}}"
            push="${CONFIG[YAML_REGISTRY_${i}_PUSH]:-${CONFIG[YAML_REGISTRY${i}_PUSH]:-true}}"

            push=$(echo "$push" | tr '[:upper:]' '[:lower:]')
            [[ "$push" =~ ^(true|yes|1)$ ]] && push="true" || push="false"

            REGISTRIES+=("${name},${prefix},${push}")
            i=$((i+1))
        done
    fi

    # --- 3️⃣ Fallback single registry (env or default) ---
    if [[ ${#REGISTRIES[@]} -eq 0 ]]; then
        local reg="${CONFIG[DF_REGISTRY]:-${CONFIG[YAML_REGISTRY]:-${CONFIG[ENV_REGISTRY]:-docker.io}}}"
        local prefix="${CONFIG[DF_REGISTRY_PREFIX]:-${CONFIG[YAML_REGISTRY_PREFIX]:-${CONFIG[ENV_REGISTRY_PREFIX]:-}}}"
        local push="${CONFIG[DF_REGISTRY_PUSH]:-${CONFIG[YAML_REGISTRY_PUSH]:-${CONFIG[ENV_REGISTRY_PUSH]:-true}}}"

        push=$(echo "$push" | tr '[:upper:]' '[:lower:]')
        [[ "$push" =~ ^(true|yes|1)$ ]] && push="true" || push="false"

        REGISTRIES+=("${reg},${prefix},${push}")
    fi

    # --- Log summary ---
    log_info "Registry list (${#REGISTRIES[@]} entries):"
    for entry in "${REGISTRIES[@]}"; do
        IFS=',' read -r reg pre push <<< "$entry"
        log_info "  ${reg}/${pre} → push=$push"
    done
}

# =============================================================================
# load_config
# Purpose:
#   Load and merge configuration from Dockerfile, YAML, and environment
#   Implements priority: Dockerfile > YAML > ENV > defaults
# Input:
#   $1 - Dockerfile path
#   $2 - config YAML path (optional)
# Output:
#   Populates CONFIG array and REGISTRIES array
# WHY:
#   Single entry point for all configuration loading
# =============================================================================
load_config() {
    local dockerfile="$1"
    local config_yaml="$2"

    # 1️⃣ Parse Dockerfile comments, secrets, and FROM registries
    parse_dockerfile_comments "$dockerfile"
    parse_dockerfile_secrets "$dockerfile"
    parse_dockerfile_from_images "$dockerfile"
    auto_add_secrets_from_dockerfile

    # 2️⃣ Parse YAML if exists
    if [[ -f "$config_yaml" ]]; then
        parse_yaml_registries "$config_yaml"
        for key in VERSION TAG_STRATEGY BUILD_SECRETS PLATFORMS DEBUG TITLE DESCRIPTION IMAGE_NAME BUILDER_CONTEXTS; do
            parse_yaml_scalar "$config_yaml" "$key" "$key"
        done
    fi

    # 3️⃣ Pull ENV vars (highest priority)
    for var in VERSION TAG_STRATEGY BUILD_SECRETS PLATFORMS DEBUG PUSH REGISTRY IMAGE_PREFIX IMAGE_NAME TITLE DESCRIPTION BUILDER_CONTEXTS; do
        [[ -n "${!var:-}" ]] && CONFIG["ENV_$var"]="${!var}"
    done

    # 4️⃣ Priority merge (Dockerfile > YAML > ENV > default)
    CONFIG[DEBUG]="${CONFIG[DF_DEBUG]:-${CONFIG[YAML_DEBUG]:-${CONFIG[ENV_DEBUG]:-false}}}"
    CONFIG[VERSION]="${CONFIG[DF_VERSION]:-${CONFIG[YAML_VERSION]:-${CONFIG[ENV_VERSION]:-latest}}}"
    CONFIG[IMAGE_NAME]="${CONFIG[DF_IMAGE_NAME]:-${CONFIG[YAML_IMAGE_NAME]:-${CONFIG[ENV_IMAGE_NAME]:-${CONFIG[IMAGE_NAME]:-unnamed}}}}"
    CONFIG[IMAGE_PREFIX]="${CONFIG[DF_IMAGE_PREFIX]:-${CONFIG[YAML_IMAGE_PREFIX]:-${CONFIG[ENV_IMAGE_PREFIX]:-}}}"
    CONFIG[TAG_STRATEGY]="${CONFIG[DF_TAG_STRATEGY]:-${CONFIG[YAML_TAG_STRATEGY]:-${CONFIG[ENV_TAG_STRATEGY]:-version-latest}}}"
    CONFIG[PLATFORMS]="${CONFIG[DF_PLATFORMS]:-${CONFIG[YAML_PLATFORMS]:-${CONFIG[ENV_PLATFORMS]:-}}}"
    CONFIG[BUILD_SECRETS]="${CONFIG[DF_BUILD_SECRETS]:-${CONFIG[YAML_BUILD_SECRETS]:-${CONFIG[ENV_BUILD_SECRETS]:-}}}"
    CONFIG[TITLE]="${CONFIG[DF_TITLE]:-${CONFIG[YAML_TITLE]:-${CONFIG[ENV_TITLE]:-${CONFIG[IMAGE_NAME]}}}}"
    CONFIG[DESCRIPTION]="${CONFIG[DF_DESCRIPTION]:-${CONFIG[YAML_DESCRIPTION]:-${CONFIG[ENV_DESCRIPTION]:-}}}"
    CONFIG[BUILDER_CONTEXTS]="${CONFIG[DF_BUILDER_CONTEXTS]:-${CONFIG[YAML_BUILDER_CONTEXTS]:-${CONFIG[ENV_BUILDER_CONTEXTS]:-}}}"

    local push_val="${CONFIG[DF_PUSH]:-${CONFIG[YAML_PUSH]:-${CONFIG[ENV_PUSH]:-true}}}"
    push_val=$(echo "$push_val" | tr '[:upper:]' '[:lower:]')
    [[ "$push_val" =~ ^(true|yes|1)$ ]] && CONFIG[PUSH]="true" || CONFIG[PUSH]="false"

    # 5️⃣ Build combined REGISTRIES array
    build_registries_array

    # 6️⃣ Final summary
    log_info "Active image: ${CONFIG[IMAGE_NAME]}"
}

# =============================================================================
# extract_git_info
# Purpose:
#   Extract Git metadata from repository (SHA, branch, author, remote, etc.)
#   Also handles Git tag version incrementing logic
# Input:
#   $1 - directory path (defaults to SOURCE_DIR)
# Output:
#   Populates CONFIG[GIT_*] keys
# WHY:
#   Embed Git metadata in OCI labels and tags
# =============================================================================
extract_git_info() {
    local dir="${1:-$SOURCE_DIR}"
    [[ ! -d "$dir/.git" ]] && return

    pushd "$dir" >/dev/null || return

    CONFIG[GIT_SHA]=${COMMIT_SHORT_SHA:-$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")}
    CONFIG[GIT_BRANCH]=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "")
    CONFIG[GIT_COMMIT_MSG]=$(git log -1 --pretty=%s 2>/dev/null || echo "")
    CONFIG[GIT_AUTHOR]=${REPO_OWNER:-$(git log -1 --pretty=%an 2>/dev/null || echo "")}
    CONFIG[GIT_REMOTE]=${REPO_FULL:-$(git config --get remote.origin.url 2>/dev/null | sed -E 's#https://[^@]+@#https://#' || echo "")}
    CONFIG[GIT_SOURCE_URL]="${CONFIG[GIT_REMOTE]%.git}"
    CONFIG[GIT_OWNER]="${REPO_OWNER:-}"

    ### Get the latest git tag from repository
    local git_tag
    git_tag=$(git describe --tags --abbrev=0 2>/dev/null || echo "")
    git_tag=$(echo "$git_tag" | tr -d '[:space:]')
    
    # WHY: If git tag exists, calculate next version based on CONFIG[VERSION]
    if [[ -n "$git_tag" ]]; then
        local git_version=${git_tag#v}
        
        # Split git version into major, minor, patch
        local git_major git_minor git_patch
        IFS='.' read -r git_major git_minor git_patch <<< "$git_version"
        
        # Get configured version and normalize
        local config_version="${CONFIG[VERSION]:-latest}"
        config_version=$(echo "$config_version" | tr -d '[:space:]')
        config_version=${config_version#v}
        
        # WHY: Only calculate new tag if VERSION is not "latest"
        if [[ "$config_version" != "latest" ]]; then
            local docker_major docker_minor docker_patch
            IFS='.' read -r docker_major docker_minor docker_patch <<< "$config_version"
            
            # Compare major and minor versions
            if [[ "$git_major" == "$docker_major" && "$git_minor" == "$docker_minor" ]]; then
                # Same major.minor, increment patch
                local new_patch=$((git_patch + 1))
                CONFIG[GIT_TAG]="$git_major.$git_minor.$new_patch"
                log_debug "Calculated next tag: ${CONFIG[GIT_TAG]} (incremented from $git_tag)"
            else
                # Different major.minor, start with patch 0
                CONFIG[GIT_TAG]="$docker_major.$docker_minor.0"
                log_debug "Calculated next tag: ${CONFIG[GIT_TAG]} (new version from $config_version)"
            fi
        else
            # WHY: If VERSION is "latest", use the current git tag as-is
            CONFIG[GIT_TAG]="$git_tag"
            log_debug "Using current git tag: ${CONFIG[GIT_TAG]}"
        fi
    else
        # WHY: No git tags exist, use VERSION if available
        if [[ -n "${CONFIG[VERSION]:-}" && "${CONFIG[VERSION]}" != "latest" ]]; then
            CONFIG[GIT_TAG]="${CONFIG[VERSION]}"
            log_debug "No git tags found, using VERSION: ${CONFIG[GIT_TAG]}"
        fi
    fi

    popd >/dev/null || return
}

