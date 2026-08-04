#!/usr/bin/env bash
# lib/ci-core.sh
#
# Purpose:
#   Core CI utilities: logging, temp management, path resolution, container engine detection,
#   OCI labels, and full tag generation matrix.
#
# Usage:
#   source lib/ci-core.sh
#
# Note: This is the base library with no dependencies
#
# Functions:
#   ci_resolve_path(path) -> prints abs path
#   ci_create_temp_file(prefix) -> prints path (0600)
#   ci_create_temp_dir() -> prints path (0700)
#   ci_cleanup_temp() -> cleans temps
#   detect_container_engine() -> prints 'podman' or 'docker'
#   ci_generate_tag() -> prints tags (space separated) (preserves full case matrix)
#   ci_generate_oci_labels() -> prints OCI labels (one per line)
#
# Example:
#   source lib/ci-core.sh
#   detect_container_engine
#

# Mark as loaded to prevent circular sourcing
CI_CORE_LOADED=true
#IFS=$'\n\t'

# global arrays (caller may rely on these)
declare -gA CONFIG 2>/dev/null || true
declare -ga CI_TEMP_FILES=() 2>/dev/null || true
declare -ga CI_TEMP_DIRS=() 2>/dev/null || true
declare -ga REGISTRIES=() 2>/dev/null || true
declare -ga CI_BUILT_IMAGES=() 2>/dev/null || true
declare -ga CI_LAST_BUILT_IMAGES=() 2>/dev/null || true

# Initialize directory paths (only if not already set by caller)
# WHY: These paths are used by find_dockerfile() and other functions
# NOTE: Caller scripts (like build.sh) can pre-set these variables

# Only determine REPO_ROOT if not already set
if [[ -z "${REPO_ROOT:-}" ]]; then
    # Try to determine REPO_ROOT from script location (2 levels up from lib/)
    REPO_ROOT="$(cd "${REPO_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)}" && pwd)"
fi

# Set defaults only if not already defined (using := parameter expansion)
: "${SOURCE_DIR:=${SCRIPT_DIR:-${REPO_ROOT}/source}}"
: "${BUILDERS_DIR:=${REPO_ROOT}/builders}"
: "${DOCKERFILES_DIR:=${REPO_ROOT}/dockerfiles}"
: "${SCRIPTS_DIR:=${REPO_ROOT}/scripts}"
: "${ROOTFS_DIR:=${SOURCE_DIR}/rootfs}"
: "${PREBUILD_DIR:=${SCRIPTS_DIR}/prebuildfs}"
: "${DOCKER_DIR:=${SCRIPTS_DIR}/docker}"

# Export for use in subshells (preserves existing values)
export REPO_ROOT SOURCE_DIR BUILDERS_DIR DOCKERFILES_DIR SCRIPTS_DIR ROOTFS_DIR PREBUILD_DIR DOCKER_DIR

# Logging helpers
log_info(){ printf '[INFO] %s\n' "$*"; }
log_warn(){ printf '[WARN] %s\n' "$*' >&2"; }  # shellcheck disable=SC2016
log_error(){ printf '[ERROR] %s\n' "$*" >&2; }
log_success(){ printf '[SUCCESS] %s\n' "$*"; }
log_debug(){
    if [[ -n "${DEBUG:-}" && ! "${DEBUG,,}" =~ ^(0|false|no|off)$ ]]; then
        printf '[DEBUG] %s\n' "$*" >&2
    fi
}

# Path resolver - create dir if needed
ci_resolve_path(){
    local path="$1"
    if [[ -z "$path" ]]; then
        log_error "ci_resolve_path: empty path"
        return 1
    fi
    if [[ -d "$path" ]]; then (cd "$path" && pwd); else mkdir -p -- "$path" && (cd "$path" && pwd); fi
}

# Temp helpers - secure perms
ci_create_temp_file(){
    local prefix="${1:-ci}"
    local f
    f="$(mktemp "${TMPDIR:-/tmp}/${prefix}.XXXXXX")"
    chmod 600 "$f"
    CI_TEMP_FILES+=("$f")
    printf '%s\n' "$f"
}

ci_create_temp_dir(){
    local d
    d="$(mktemp -d "${TMPDIR:-/tmp}/ci.XXXXXX")"
    chmod 700 "$d"
    CI_TEMP_DIRS+=("$d")
    printf '%s\n' "$d"
}



ci_cleanup_temp() {
    # Purpose: Securely remove temporary files and directories without affecting script exit status
    # Inputs: CI_TEMP_FILES (array), CI_TEMP_DIRS (array)
    # Output: Always returns 0
    # Usage: trap ci_cleanup_temp EXIT

    set +e  # Disable 'exit on error' inside cleanup
    local rc=0

    # Clean up files
    if [[ "${#CI_TEMP_FILES[@]}" -gt 0 ]]; then
        for f in "${CI_TEMP_FILES[@]}"; do
            if [[ -n "$f" && -f "$f" ]]; then
                shred -u -- "$f" 2>/dev/null || rm -f -- "$f" || rc=1
            fi
        done
    fi

    # Clean up directories
    if [[ "${#CI_TEMP_DIRS[@]}" -gt 0 ]]; then
        for d in "${CI_TEMP_DIRS[@]}"; do
            if [[ -n "$d" && -d "$d" ]]; then
                rm -rf -- "$d" || rc=1
            fi
        done
    fi

    if [[ "$rc" -ne 0 ]]; then
        printf '[WARN] %s Some cleanup operations failed; ignoring for exit code.\n' "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" >&2
    fi

    return 0
}



# Ensure cleanup on caller exit (caller script may set trap again)
trap ci_cleanup_temp EXIT

# Container engine detection
detect_container_engine(){
    if [[ -n "${CONTAINER_ENGINE:-}" ]]; then printf '%s\n' "$CONTAINER_ENGINE"; return 0; fi
    if command -v podman >/dev/null 2>&1; then printf 'podman\n'; return 0; fi
    if command -v docker >/dev/null 2>&1; then
        if docker version --format '{{.Server.Version}}' 2>/dev/null | grep -qi podman; then printf 'podman\n'; else printf 'docker\n'; fi
        return 0
    fi
    log_error "No container engine (docker|podman) found"
    return 1
}

# Full tag generation preserving original full set
ci_generate_tag(){
    # WHY: Use CONFIG array values consistently for all variables
    local V="${CONFIG[VERSION]:-latest}"
    local S="${CONFIG[TAG_STRATEGY]:-version-latest}"
    local R="${CONFIG[RUNNER_ID]:-1}"
    local H="${CONFIG[GIT_SHA]:-unknown}"
    local GIT_TAG_VAL="${CONFIG[GIT_TAG]:-}"
    local primary secondary

    case "$S" in
        version)             echo "$V" ;;
        runner)              echo "$R" ;;
        sha)                 echo "$H" ;;
        latest)              echo "latest" ;;
        runner-latest)
            if [[ "$R" == "latest" ]]; then
                echo "latest"
            else
                echo "$R latest"
            fi
            ;;
        sha-latest)
            if [[ "$H" == "latest" ]]; then
                echo "latest"
            else
                echo "$H latest"
            fi
            ;;
        version-latest)
            if [[ "$V" == "latest" ]]; then
                echo "latest"
            else
                echo "$V latest"
            fi
            ;;
        version-runner)      echo "${V}.${R}" ;;
        version-sha)         echo "${V}.${H}" ;;
        tag)
            if [[ -n "$GIT_TAG_VAL" ]]; then
                echo "$GIT_TAG_VAL"
            else
                echo "latest"
            fi
            ;;
        tag-latest)
            if [[ -n "$GIT_TAG_VAL" && "$GIT_TAG_VAL" != "latest" ]]; then
                echo "$GIT_TAG_VAL latest"
            else
                echo "latest"
            fi
            ;;
        version-runner-latest)
            if [[ "$V" == "latest" ]]; then
                echo "latest"
            else
                primary="${V}.${R}"
                secondary="latest"
                echo "$primary $secondary"
            fi
            ;;
        version-sha-latest)
            if [[ "$V" == "latest" ]]; then
                echo "latest"
            else
                primary="${V}.${H}"
                secondary="latest"
                echo "$primary $secondary"
            fi
            ;;
        tag)
            if [[ -n "$GIT_TAG_VAL" ]]; then
                echo "$GIT_TAG_VAL"
            else
                echo "latest"
            fi
            ;;
        tag-latest)
            if [[ -n "$GIT_TAG_VAL" && "$GIT_TAG_VAL" != "latest" ]]; then
                echo "$GIT_TAG_VAL latest"
            else
                echo "latest"
            fi
            ;;
        version-runner-latest)
            if [[ "$V" == "latest" ]]; then
                echo "latest"
            else
                primary="${V}.${R}"
                secondary="latest"
                echo "$primary $secondary"
            fi
            ;;
        version-sha-latest)
            if [[ "$V" == "latest" ]]; then
                echo "latest"
            else
                primary="${V}.${H}"
                secondary="latest"
                echo "$primary $secondary"
            fi
            ;;
        custom)
            echo "${CONFIG[CUSTOM_TAGS]:-latest}"
            ;;
        *)
            # If unknown, provide reasonable defaults preserving previous behaviour
            echo "latest"
            ;;
    esac
}

# =============================================================================
# get_runner_id
# Purpose:
#   Detect CI runner/build ID from various CI platforms
# Output:
#   Prints runner/build ID or timestamp if none found
# WHY:
#   Used for unique tagging in CI environments
# =============================================================================
get_runner_id() {
    [[ -n "${PR_NUMBER:-}" ]] && echo "$PR_NUMBER" && return
    [[ -n "${ISSUE_NUMBER:-}" ]] && echo "$ISSUE_NUMBER" && return
    [[ -n "${CONFIG[GIT_COMMIT_ID]:-}" ]] && echo "${CONFIG[GIT_COMMIT_ID]}" && return
    [[ -n "${GITHUB_RUN_ID:-}" ]] && echo "$GITHUB_RUN_ID" && return
    [[ -n "${GITHUB_RUN_NUMBER:-}" ]] && echo "$GITHUB_RUN_NUMBER" && return
    [[ -n "${CI_JOB_ID:-}" ]] && echo "$CI_JOB_ID" && return
    [[ -n "${CI_PIPELINE_IID:-}" ]] && echo "$CI_PIPELINE_IID" && return
    [[ -n "${CIRCLE_BUILD_NUM:-}" ]] && echo "$CIRCLE_BUILD_NUM" && return
    [[ -n "${BUILD_ID:-}" ]] && echo "$BUILD_ID" && return
    [[ -n "${BUILD_NUMBER:-}" ]] && echo "$BUILD_NUMBER" && return
    [[ -n "${BITBUCKET_BUILD_NUMBER:-}" ]] && echo "$BITBUCKET_BUILD_NUMBER" && return
    [[ -n "${BUILD_BUILDID:-}" ]] && echo "$BUILD_BUILDID" && return
    [[ -n "${CODEBUILD_BUILD_ID:-}" ]] && echo "${CODEBUILD_BUILD_ID##*:}" && return
    date +%s
}

# OCI labels generator
ci_generate_oci_labels(){
    local now
    now="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
    printf 'org.opencontainers.image.created=%s\n' "$now"
    # WHY: Use CONFIG array values consistently for all variables
    [[ -n "${CONFIG[GIT_SHA]:-}" ]] && printf 'org.opencontainers.image.revision=%s\n' "${CONFIG[GIT_SHA]}"
    [[ -n "${CONFIG[VERSION]:-}" ]] && printf 'org.opencontainers.image.version=%s\n' "${CONFIG[VERSION]}"
    [[ -n "${CONFIG[IMAGE_NAME]:-}" ]] && printf 'org.opencontainers.image.title=%s\n' "${CONFIG[IMAGE_NAME]}"
    [[ -n "${CONFIG[GIT_SOURCE_URL]:-}" ]] && printf 'org.opencontainers.image.source=%s\n' "${CONFIG[GIT_SOURCE_URL]}"
    [[ -n "${CONFIG[GIT_OWNER]:-}" ]] && printf 'org.opencontainers.image.vendor=%s\n' "${CONFIG[GIT_OWNER]}"
}
