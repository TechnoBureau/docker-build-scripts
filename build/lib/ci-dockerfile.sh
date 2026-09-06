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
        CONFIG["SECRET_${secret_id}"]="present"
        log_info "Dockerfile secret → ${secret_id}"
        # Remove the matched portion so we can find the next one
        content="${content#*--mount=type=secret,*id=${secret_id}}"
    done
}

# =============================================================================
# parse_dockerfile_args
# Purpose:
#   Scan Dockerfile for ARG declarations to auto-detect build arguments
#   Handles line continuations and ARG with default values
# Input:
#   $1 - Dockerfile path
# Output:
#   Populates CONFIG[ARG_NAME] = "present" for each detected ARG
# WHY:
#   Auto-detect required build args so they can be passed during build
# =============================================================================
parse_dockerfile_args() {
    local file="$1"
    [[ ! -f "$file" ]] && { log_warn "Dockerfile not found for ARG scan: $file"; return 0; }

    # Normalize line continuations (replace \<newline> with a single space)
    local content
    content=$(awk '
        { gsub(/\\$/, ""); line = line $0 " " }
        /\\$/ { next }
        { print line; line="" }
        END { if (line) print line }
    ' "$file")

    local arg_name
    # Match: ARG NAME or ARG NAME=default_value
    while read -r line; do
        # Skip comments
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        
        # Match ARG declaration (case-insensitive)
        if [[ "$line" =~ ^[[:space:]]*ARG[[:space:]]+([A-Za-z_][A-Za-z0-9_]*)(=.*)?$ ]]; then
            arg_name="${BASH_REMATCH[1]}"
            CONFIG["ARG_${arg_name}"]="present"
            log_info "Dockerfile ARG → ${arg_name}"
        fi
    done <<< "$content"
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
# Return the credential scope of an actual image reference, preserving ports.
ci_image_source_registry() {
    local image_ref="${1%%@*}" host path parent
    [[ -n "$image_ref" && "$image_ref" != scratch && "$image_ref" != oci-archive:* ]] || return 0
    host="${image_ref%%/*}"
    if [[ "$image_ref" != */* || ( "$host" != *.* && "$host" != *:* && "$host" != localhost ) ]]; then
        printf 'docker.io\n'
        return 0
    fi
    if [[ "$host" == *icr.io ]]; then
        # ICR credentials can be scoped to namespace/prefix (not just host).
        path="${image_ref#*/}"
        if [[ "$path" == */* ]]; then
            parent="${path%/*}"
            local -a parts=()
            IFS=/ read -r -a parts <<< "$parent"
            host+="/${parts[0]}"
            [[ ${#parts[@]} -lt 2 ]] || host+="/${parts[1]}"
        fi
    fi
    printf '%s\n' "$host"
}

parse_dockerfile_from_images() {
    local file="$1" key line word declaration name value ref registry
    local index=0
    local -a words=()
    local -A defaults=() stages=() seen=()
    [[ -f "$file" ]] || { log_warn "Dockerfile not found for FROM scan: $file"; return 0; }
    for key in "${!CONFIG[@]}"; do
        [[ "$key" != FROM_REGISTRY_* ]] || unset "CONFIG[$key]"
    done
    while IFS= read -r line; do
        read -r -a words <<< "$line"
        [[ ${#words[@]} -gt 0 ]] || continue
        word="${words[0]^^}"
        if [[ "$word" == ARG && ${#words[@]} -gt 1 ]]; then
            declaration="${words[1]}"
            name="${declaration%%=*}"
            [[ "$name" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || continue
            value=""
            [[ "$declaration" != *=* ]] || value="${declaration#*=}"
            value="${value#[\"\']}"; value="${value%[\"\']}"
            defaults[$name]="${!name:-$value}"
            continue
        fi
        [[ "$word" == FROM ]] || continue
        words=("${words[@]:1}")
        [[ ${#words[@]} -gt 0 ]] || continue
        [[ "${words[0]}" != --platform=* ]] || words=("${words[@]:1}")
        [[ ${#words[@]} -gt 0 ]] || continue
        ref="${words[0]}"
        # Resolve simple ARG references as text, never eval Dockerfile content.
        for name in "${!defaults[@]}"; do
            ref="${ref//\$\{$name\}/${defaults[$name]}}"
            [[ "$ref" != "\$$name" ]] || ref="${defaults[$name]}"
        done
        if [[ -n "$ref" && "$ref" != *'$'* && -z "${stages[${ref,,}]:-}" ]]; then
            registry="$(ci_image_source_registry "$ref")"
            if [[ -n "$registry" && -z "${seen[$registry]:-}" ]]; then
                seen[$registry]=1
                CONFIG[FROM_REGISTRY_${index}]="$registry"
                index=$((index + 1))
                log_info "Dockerfile image source → registry: $registry"
            fi
        fi
        if [[ ${#words[@]} -ge 3 && "${words[1]^^}" == AS ]]; then
            stages[${words[2],,}]=1
        fi
    done < <(awk '
        sub(/\\[[:space:]]*$/, "") { line=line $0 " "; next }
        { print line $0; line="" }
        END { if (line) print line }
    ' "$file")
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
    # WHY ${VAR:-} and not "$VAR": ci-core.sh normally defines both, but a
    # consumer that pre-sets CI_CORE_LOADED (or supplies its own core) skips
    # that sourcing. Under the `set -u` such consumers run with, the bare
    # "$BUILDERS_DIR" then aborts their whole job instead of falling through to
    # the next search location. Verified: original exit=1 and silent, this
    # version returns 1 and lets the caller continue.
    local builders_dir="${BUILDERS_DIR:-}"
    local source_dir="${SOURCE_DIR:-}"
    local -a candidates=()
    local entry dir pattern result

    # Search order is the contract: most specific first, so an explicit
    # per-image directory always wins over a repository-wide match.
    if [[ -n "$builders_dir" && -n "$name" ]]; then
        candidates+=("$builders_dir/$name|Dockerfile")
        candidates+=("$builders_dir/$name|${name}.Dockerfile")
        candidates+=("$builders_dir/$name|*.Dockerfile")
    fi
    if [[ -n "$source_dir" ]]; then
        candidates+=("$source_dir|Dockerfile")
        candidates+=("$source_dir|${name}.Dockerfile")
        candidates+=("$source_dir|*.Dockerfile")
    fi
    if [[ -n "$builders_dir" ]]; then
        candidates+=("$builders_dir|${name}.Dockerfile")
        candidates+=("$builders_dir|*.Dockerfile")
    fi

    # WHY a flat loop instead of nested helper functions: a function defined
    # inside a function body becomes GLOBAL on first call in bash, so the old
    # `search`/`try_search` helpers leaked into the consumer's namespace and
    # could shadow their own functions of the same name.
    for entry in "${candidates[@]+"${candidates[@]}"}"; do
        dir="${entry%%|*}"
        pattern="${entry#*|}"
        [[ -d "$dir" ]] || continue
        result="$(find "$dir" -type f -name "$pattern" -print -quit 2>/dev/null || true)"
        if [[ -n "$result" ]]; then
            printf '%s\n' "$result"
            return 0
        fi
    done

    return 1
}

