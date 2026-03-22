#!/usr/bin/env bash
# lib/ci-dockerfile.sh
#
# Purpose:
#   Dockerfile comment and secret parsing utilities.
#   Extracts metadata from Dockerfile comments (# KEY: value format)
#   and detects BuildKit secrets (--mount=type=secret,id=NAME).
#
# Usage:
#   source lib/ci-dockerfile.sh
#
# Functions:
#   parse_dockerfile_comments <file> -> populates CONFIG[DF_*] keys
#   parse_dockerfile_secrets <file> -> populates CONFIG[SECRET_*] keys
#
# Input parameters:
#   $1 - path to Dockerfile
#
# Output:
#   Populates global CONFIG associative array
#
# Example:
#   parse_dockerfile_comments /path/to/Dockerfile
#   echo "${CONFIG[DF_VERSION]}"
#

# Source dependencies
if [[ -z "${CI_CORE_LOADED:-}" ]]; then
    LIB_DIR="${LIB_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
    # shellcheck source=/dev/null
    source "${LIB_DIR}/ci-core.sh"
fi

# Ensure CONFIG array exists
declare -gA CONFIG 2>/dev/null || true

# =============================================================================
# parse_dockerfile_comments
# Purpose:
#   Parse Dockerfile comments in format: # KEY: value
#   Stores results in CONFIG[DF_KEY] (uppercase key)
# Input:
#   $1 - Dockerfile path
# Output:
#   Populates CONFIG array with DF_* keys
# WHY:
#   Allows embedding build metadata directly in Dockerfile
# =============================================================================
parse_dockerfile_comments() {
    local file="$1"
    [[ ! -f "$file" ]] && { log_warn "Dockerfile not found: $file"; return 0; }

    local line key value
    while IFS= read -r line || [[ -n "$line" ]]; do
        # Only process comment lines
        [[ "$line" =~ ^[[:space:]]*# ]] || continue

        # Strip leading # and surrounding whitespace
        line="${line#\#}"
        line="${line#"${line%%[![:space:]]*}"}"   # left trim
        line="${line%"${line##*[![:space:]]}"}"   # right trim

        # Match KEY: value (case-insensitive key)
        if [[ "$line" =~ ^([A-Za-z_][A-Za-z0-9_]*):[[:space:]]*(.+)$ ]]; then
            key="${BASH_REMATCH[1]}"
            value="${BASH_REMATCH[2]}"
            value="${value%"${value##*[![:space:]]}"}"
            CONFIG["DF_${key^^}"]="$value"
            log_info "Dockerfile comment → ${key^^} = ${CONFIG["DF_${key^^}"]}"
        fi
    done < "$file"
}

# =============================================================================
# parse_dockerfile_secrets
# Purpose:
#   Scan Dockerfile for BuildKit secret mounts: --mount=type=secret,id=NAME
#   Handles line continuations (backslash at end of line)
# Input:
#   $1 - Dockerfile path
# Output:
#   Populates CONFIG[SECRET_NAME] = "present" for each detected secret
# WHY:
#   Auto-detect required secrets so they can be mounted during build
# =============================================================================
parse_dockerfile_secrets() {
    local file="$1"
    [[ ! -f "$file" ]] && { log_warn "Dockerfile not found for secret scan: $file"; return 0; }

    # Normalize line continuations (replace \<newline> with a single space)
    local content
    content=$(awk '
        { gsub(/\\$/, ""); line = line $0 " " }
        /\\$/ { next }
        { print line; line="" }
        END { if (line) print line }
    ' "$file")

    local secret_id
    # Match: --mount=type=secret,id=NAME   (anywhere on the line)
    while [[ $content =~ --mount=type=secret,[^,]*id=([A-Za-z0-9_][A-Za-z0-9_.-]*) ]]; do
        secret_id="${BASH_REMATCH[1]}"
        CONFIG["SECRET_${secret_id^^}"]="present"
        log_info "Dockerfile secret → ${secret_id^^}"
        # Remove the matched portion so we can find the next one
        content="${content#*--mount=type=secret,*id=${secret_id}}"
    done
}

# =============================================================================
# parse_dockerfile_from_images
# Purpose:
#   Extract base image registries from FROM statements in Dockerfile
#   Handles multi-stage builds and special ICR registry format
# Input:
#   $1 - Dockerfile path
# Output:
#   Populates CONFIG[FROM_REGISTRY_*] keys with unique registries
# Returns:
#   0 on success
# WHY:
#   Auto-detect registries needed for pulling base images during build
#   Enables automatic login before docker build
# =============================================================================
parse_dockerfile_from_images() {
    local file="$1"
    [[ ! -f "$file" ]] && { log_warn "Dockerfile not found for FROM scan: $file"; return 0; }

    # Normalize line continuations and extract FROM statements
    local content
    content=$(awk '
        { gsub(/\\$/, ""); line = line $0 " " }
        /\\$/ { next }
        { print line; line="" }
        END { if (line) print line }
    ' "$file")

    local -A seen_registries=()
    local registry_index=0

    # Match FROM statements: FROM [--platform=...] registry/image:tag
    while read -r line; do
        # Skip comments
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        
        # Match FROM statement (case-insensitive)
        if [[ "$line" =~ ^[[:space:]]*FROM[[:space:]]+(.+)$ ]]; then
            local from_clause="${BASH_REMATCH[1]}"
            
            # Remove --platform=... if present
            from_clause=$(echo "$from_clause" | sed -E 's/--platform=[^[:space:]]+[[:space:]]+//')
            
            # Extract image reference (first word after FROM)
            local image_ref
            image_ref=$(echo "$from_clause" | awk '{print $1}')
            
            # Skip scratch and build stage references
            [[ "$image_ref" =~ ^(scratch|[a-z][a-z0-9_-]*)$ ]] && continue
            
            # Extract registry from image reference
            local registry=""
            local namespace=""
            
            # WHY: Handle different image reference formats:
            # - registry.io/namespace/image:tag
            # - registry.io/image:tag
            # - image:tag (defaults to docker.io)
            if [[ "$image_ref" =~ ^([^/]+\.[^/]+)/(.+)$ ]]; then
                # Has registry with dot (e.g., icr.io/namespace/image)
                local reg_part="${BASH_REMATCH[1]}"
                local path_part="${BASH_REMATCH[2]}"
                
                # WHY: Special handling for ICR - extract namespace/prefix as part of registry
                # ICR format: icr.io/namespace/prefix/image:tag
                # We want: registry=icr.io/namespace/prefix, not just icr.io
                if [[ "$reg_part" =~ icr\.io$ ]]; then
                    # Extract first TWO path components (namespace/prefix)
                    if [[ "$path_part" =~ ^([^/]+)/([^/]+)/(.+)$ ]]; then
                        # Has namespace/prefix/image format
                        local ns="${BASH_REMATCH[1]}"
                        local prefix="${BASH_REMATCH[2]}"
                        registry="${reg_part}/${ns}/${prefix}"
                        log_debug "FROM image → ICR registry: $registry (namespace=$ns, prefix=$prefix)"
                    elif [[ "$path_part" =~ ^([^/]+)/(.+)$ ]]; then
                        # Has only namespace/image format
                        namespace="${BASH_REMATCH[1]}"
                        registry="${reg_part}/${namespace}"
                        log_debug "FROM image → ICR registry: $registry (namespace only)"
                    else
                        # No path components
                        registry="$reg_part"
                        log_debug "FROM image → ICR registry (no namespace): $registry"
                    fi
                else
                    registry="$reg_part"
                    log_debug "FROM image → registry: $registry"
                fi
            elif [[ "$image_ref" =~ ^([^/]+)/([^/]+)/(.+)$ ]]; then
                # Format: namespace/repo/image (assume docker.io)
                registry="docker.io"
                log_debug "FROM image → default registry: $registry"
            elif [[ "$image_ref" =~ / ]]; then
                # Has slash but no dot - likely docker.io/library or docker.io/user
                registry="docker.io"
                log_debug "FROM image → default registry: $registry"
            else
                # No registry specified - defaults to docker.io
                registry="docker.io"
                log_debug "FROM image → default registry: $registry"
            fi
            
            # Store unique registries
            if [[ -n "$registry" && -z "${seen_registries[$registry]:-}" ]]; then
                seen_registries[$registry]=1
                CONFIG["FROM_REGISTRY_${registry_index}"]="$registry"
                log_info "Dockerfile FROM → registry: $registry"
                ((registry_index++))
            fi
        fi
    done <<< "$content"
    
    return 0
}

# =============================================================================
# find_dockerfile
# Purpose:
#   Search for Dockerfile in standard locations with priority order
# Input:
#   $1 - optional image name (used for pattern matching)
# Output:
#   Prints path to found Dockerfile
# Returns:
#   0 if found, 1 if not found
# WHY:
#   Centralize Dockerfile discovery logic
# =============================================================================
find_dockerfile() {
    local name="${1:-}"
    local found=""

    search() {
        local d="$1" pat="$2"
        [[ -d "$d" ]] || return 1
        find "$d" -type f -name "$pat" -print -quit 2>/dev/null || true
    }

    try_search() {
        local r
        r="$(search "$@")"
        if [[ -n "$r" ]]; then
            echo "$r"
            found=1
            return 0
        fi
        return 1
    }

    # Priority 1-3: BUILDERS_DIR/name patterns
    if [[ -n "$BUILDERS_DIR" && -n "$name" ]]; then
        try_search "$BUILDERS_DIR/$name" "Dockerfile" && return 0
        try_search "$BUILDERS_DIR/$name" "${name}.Dockerfile" && return 0
        try_search "$BUILDERS_DIR/$name" '*.Dockerfile' && return 0
    fi

    # Priority 4-6: SOURCE_DIR
    if [[ -n "$SOURCE_DIR" ]]; then
        try_search "$SOURCE_DIR" "Dockerfile" && return 0
        try_search "$SOURCE_DIR" "${name}.Dockerfile" && return 0
        try_search "$SOURCE_DIR" '*.Dockerfile' && return 0
    fi

    # Fallback: any in BUILDERS_DIR
    if [[ -n "$BUILDERS_DIR" ]]; then
        try_search "$BUILDERS_DIR" "${name}.Dockerfile" && return 0
        try_search "$BUILDERS_DIR" '*.Dockerfile' && return 0
    fi

    return 1
}

