#!/usr/bin/env bash
# lib/ci-utils.sh
#
# Purpose:
#   Utility functions for image signing, repository loading, and image cleanup
#   operations.
#
# Usage:
#   source lib/ci-utils.sh
#
# Functions:
#   sign_with_cosign <image>
#   remove_docker_images <image1> [image2...]
#   load_repository <repo> [branch] [dir] [token_var]
#   extract_host_and_path <url>
#
# Example:
#   sign_with_cosign "docker.io/myimage:latest"
#

# Source dependencies
if [[ -z "${CI_CORE_LOADED:-}" ]]; then
    LIB_DIR="${LIB_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
    # shellcheck source=/dev/null
    source "${LIB_DIR}/ci-core.sh"
fi


# Define Safe Regex Patterns for Input Validation (Security)
readonly REGEX_IMAGE_NAME="^[a-zA-Z0-9/_.-]+$"
readonly REGEX_URL="^[a-zA-Z0-9/._:-]+$"
readonly REGEX_TAG="^[a-zA-Z0-9._-]+$"

# =============================================================================
# sign_with_cosign
# Purpose:
#   Sign container image using cosign (keyless or with private key)
# Input:
#   $1 - image reference
# Output:
#   Logs signing status
# Returns:
#   0 on success or if cosign not available
# WHY:
#   Image signing for supply chain security
# =============================================================================
sign_with_cosign() {
    local image="$1"

    if ! command -v cosign >/dev/null 2>&1; then
        log_info "cosign not installed → skipping signing"
        return 0
    fi

    local key="${COSIGN_PRIVATE_KEY:-${COSIGN_KEY:-}}"
    local password="${COSIGN_PASSWORD:-}"

    if [[ -n "$key" ]]; then
        local keyfile
        if command -v ci_create_temp_file >/dev/null 2>&1; then
            keyfile=$(ci_create_temp_file "cosign_key")
        else
            keyfile=$(mktemp --tmpdir "${TMPDIR:-/tmp}/cosign_key.XXXXXX")
        fi

        # Handle PEM format or base64 encoded key
        if [[ "$key" =~ -----BEGIN ]]; then
            echo "$key" > "$keyfile"
        else
            echo "$key" | base64 -d > "$keyfile" 2>/dev/null || echo "$key" > "$keyfile"
        fi
        chmod 600 "$keyfile"

        if COSIGN_PASSWORD="$password" cosign sign --key "$keyfile" "$image" 2>/dev/null; then
            log_success "Signed: $image"
        else
            log_warn "Signing failed for $image"
        fi
    elif [[ "${CONFIG[COSIGN_KEYLESS]:-false}" == "true" ]]; then
        if cosign sign --yes "$image" 2>/dev/null; then
            log_success "Keyless signed: $image"
        else
            log_warn "Keyless signing failed for $image"
        fi
    else
        log_info "No cosign key configured → skipping signing"
    fi

    return 0
}

# =============================================================================
# remove_docker_images
# Purpose:
#   Remove local container images to free disk space
# Input:
#   $@ - list of image references
# Output:
#   Logs removal status for each image
# Returns:
#   0 always (best-effort cleanup)
# WHY:
#   Clean up local storage after successful push to registry
# =============================================================================
remove_docker_images() {
    local images=("$@")
    local engine
    engine=$(detect_container_engine 2>/dev/null || echo "docker")

    if [[ ${#images[@]} -eq 0 ]]; then
        log_info "No images to remove"
        return 0
    fi

    log_info "Removing ${#images[@]} image(s) from local ${engine} storage"

    for image in "${images[@]}"; do
        # Skip empty entries
        [[ -z "$image" ]] && continue

        log_info "Removing image: $image"
        if [[ "$engine" == "docker" ]]; then
            if docker rmi "$image" >/dev/null 2>&1; then
                log_info "Removed: $image"
            else
                log_warn "Failed to remove: $image"
            fi
        else
            if podman rmi "$image" >/dev/null 2>&1; then
                log_info "Removed: $image"
            else
                log_warn "Failed to remove: $image"
            fi
        fi
    done

    log_success "Image cleanup completed"
    return 0
}

# =============================================================================
# extract_host_and_path
# Purpose:
#   Parse Git repository URL and extract host and path components
# Input:
#   $1 - repository URL (git@, https://, or shorthand)
# Output:
#   Prints "host path" (space-separated)
# Returns:
#   0 on success, 1 on invalid URL
# WHY:
#   Normalize different Git URL formats for cloning
# =============================================================================
extract_host_and_path() {
    local url="$1"
    local host path

    # git@github.com:user/repo.git
    if [[ "$url" =~ ^git@([^:]+):(.*)$ ]]; then
        host="${BASH_REMATCH[1]}"
        path="/${BASH_REMATCH[2]}"
    # https://github.com/user/repo.git
    elif [[ "$url" =~ ^https?://([^/]+)(/.*)$ ]]; then
        host="${BASH_REMATCH[1]}"
        path="${BASH_REMATCH[2]}"
    # user/repo (assume github.com)
    elif [[ "$url" =~ ^([^/]+)(/.*)$ ]]; then
        local first_part="${BASH_REMATCH[1]}"
        if [[ "$first_part" == *.* ]]; then
            host="$first_part"
            path="${BASH_REMATCH[2]}"
        else
            host="github.com"
            path="/$url"
        fi
    else
        log_error "Invalid repo URL: $url"
        return 1
    fi

    echo "$host $path"
    return 0
}

# =============================================================================
# load_repository
# Purpose:
#   Clone Git repository with authentication support
# Input:
#   $1 - repository URL
#   $2 - branch (default: main)
#   $3 - target directory (default: REPO_ROOT)
#   $4 - token variable name (auto-detected if empty)
# Output:
#   Clones repository to target directory
# Returns:
#   0 on success, 1 on failure
# WHY:
#   Load source code from Git for building
# =============================================================================

load_repository() {
    local repo="$1"
    local branch="${2:-main}"
    local dir="${3:-$REPO_ROOT}"
    local token_var="${4:-}"
    local depth_option="--depth 1"

    # Extract host and path
    local host_path
    host_path=$(extract_host_and_path "$repo") || return 1
    read -r host path <<< "$host_path"

    # Auto-detect token_var if not provided
    if [[ -z "$token_var" ]]; then
        if [[ "$host" == "github.com" ]]; then
            token_var="GH_TOKEN"
        else
            token_var="GHE_TOKEN"
        fi
    fi

    local token="${!token_var:-}"

    # Remove existing directory (destructive - consider adding safety check)
    if [[ -d "$dir" ]]; then
        log_warn "Removing existing directory: $dir"
        rm -rf "$dir"
    fi

    # Build clone URL with token if available
    local clone_url="$repo"
    if [[ -n "$token" ]]; then
        clone_url="https://${token}@${host}${path}"
        log_info "Cloning with authentication: ${host}${path}"
    else
        log_info "Cloning without authentication: $repo"
    fi

    # Clone repository
    if git clone -b "$branch" $depth_option "$clone_url" "$dir" 2>/dev/null; then
        log_success "Repository cloned to: $dir"

        # Fetch tags
        git -C "$dir" fetch --tags --quiet 2>/dev/null

        return 0
    else
        log_error "Failed to clone repository: $repo"
        return 1
    fi
}
