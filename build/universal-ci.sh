#!/usr/bin/env bash
# ci-main.sh
#
# Purpose:
#   Main build orchestration function that coordinates the entire CI pipeline.
#   Integrates all other modules: config loading, git info, buildx setup,
#   build/push, SBOM, signing, and artifact management.
#
# Usage:
#   source build/ci-main.sh
#
# Functions:
#   main_build [options]
#
# Options:
#   -d, --dockerfile FILE    Path to Dockerfile
#   -c, --config FILE        Path to config YAML
#   -i, --image NAME         Image name
#   -r, --repo URL           Git repository URL
#   -b, --branch NAME        Git branch (default: main)
#
# Example:
#   main_build -d /path/to/Dockerfile -i myimage
#

# =============================================================================
# DEBUG MODE DETECTION - Must be before sourcing other modules
# =============================================================================
# Robust debug detection: accepts 1, true, TRUE, yes, on, etc. (case-insensitive)
if [[ -n "${DEBUG:-}" ]] && ! [[ "${DEBUG,,}" =~ ^(0|false|no|off)$ ]]; then
    set -x
fi

# Source dependencies from lib directory
CI_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${CI_SCRIPT_DIR}/lib"

# Source core if not loaded
if [[ -z "${CI_CORE_LOADED:-}" ]]; then
    # shellcheck source=/dev/null
    source "${LIB_DIR}/ci-core.sh"
fi

# Always source these libraries (they have their own guards or are idempotent)
# shellcheck source=/dev/null
source "${LIB_DIR}/ci-dockerfile.sh" 2>/dev/null || true
# shellcheck source=/dev/null
source "${LIB_DIR}/ci-yaml.sh" 2>/dev/null || true
# shellcheck source=/dev/null
source "${LIB_DIR}/ci-secrets.sh" 2>/dev/null || true
# shellcheck source=/dev/null
source "${LIB_DIR}/ci-registry.sh" 2>/dev/null || true
# shellcheck source=/dev/null
source "${LIB_DIR}/ci-config.sh" 2>/dev/null || true
# shellcheck source=/dev/null
source "${LIB_DIR}/ci-build.sh" 2>/dev/null || true
# shellcheck source=/dev/null
source "${LIB_DIR}/ci-artifacts.sh" 2>/dev/null || true
# shellcheck source=/dev/null
source "${LIB_DIR}/ci-utils.sh" 2>/dev/null || true
# shellcheck source=/dev/null
source "${LIB_DIR}/ci-sbom.sh" 2>/dev/null || true
# shellcheck source=/dev/null
source "${LIB_DIR}/ci-hummingbird.sh" 2>/dev/null || true
# shellcheck source=/dev/null
source "${LIB_DIR}/ci-vuln.sh" 2>/dev/null || true

# =============================================================================
# main_build
# Purpose:
#   Main entry point for CI build pipeline
#   Orchestrates: config loading, git info, registry login, build, SBOM,
#   signing, artifact saving, and cleanup
# Input:
#   Command-line arguments (see usage above)
# Output:
#   Builds and pushes container images, generates artifacts
# Returns:
#   0 on success, non-zero on failure
# WHY:
#   Single function to execute complete CI pipeline
# =============================================================================
main_build() {
    local dockerfile="" config_yaml="" image_name="" git_repo="" branch="" flavor=""

    # Parse command-line arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -d|--dockerfile) dockerfile="$2"; shift 2 ;;
            -c|--config) config_yaml="$2"; shift 2 ;;
            -i|--image) image_name="$2"; shift 2 ;;
            -r|--repo) git_repo="$2"; shift 2 ;;
            -b|--branch) branch="$2"; shift 2 ;;
            -f|--flavor) flavor="$2"; shift 2 ;;
            *) log_error "Unknown argument: $1"; return 1 ;;
        esac
    done

    # Load repository if specified
    if [[ -n "$git_repo" ]]; then
        log_info "Loading repository: $git_repo"
        load_repository "$git_repo" "${branch:-main}" "$SOURCE_DIR" || {
            log_error "Failed to load repository"
            return 1
        }
    fi

    # Resolve the image directory (used for flavor detection and context)
    local image_dir=""
    if [[ -n "$image_name" ]]; then
        image_dir=$(ci_hummingbird_find_image "$image_name" || true)
    elif [[ -n "${SOURCE_DIR:-}" ]]; then
        image_dir="$SOURCE_DIR"
    fi

    # Detect flavor: FLAVOR env / --flavor override wins over auto-detection
    flavor="${flavor:-${FLAVOR:-}}"
    if [[ -z "$flavor" && -n "$image_dir" ]]; then
        flavor="$(ci_hummingbird_detect_flavor "$image_dir")"
    fi
    log_info "Detected flavor: ${flavor:-none}"

    if [[ "$flavor" == "hummingbird" ]]; then
        log_info "Loading configuration (hummingbird properties.yml)..."
        log_info "Extracting Git information..."
        [[ -d "${SOURCE_DIR:-}/.git" ]] && extract_git_info "$SOURCE_DIR"

        ci_hummingbird_build "$image_dir"
        local build_status=$?
        if [[ $build_status -ne 0 ]]; then
            log_error "Hummingbird build failed with status $build_status"
            export exit_code="$build_status"
            return $build_status
        fi

        # Post-build operations (SBOM, vulnerability reports, cleanup)
        if [[ ${#CI_BUILT_IMAGES[@]} -gt 0 ]]; then
            local img
            for img in "${CI_BUILT_IMAGES[@]}"; do
                log_info "Post-build artifacts for image: $img"
                ci_generate_and_attach_sbom "$img" || log_warn "SBOM generation/attachment failed for $img"
                ci_generate_and_attach_vuln_report "$img" || log_warn "Vulnerability report generation/attachment failed for $img"
            done
            if [[ "${REMOVE_LOCAL_IMAGES:-true}" == "true" ]]; then
                log_info "Removing local images (REMOVE_LOCAL_IMAGES=true)"
                remove_docker_images "${CI_BUILT_IMAGES[@]}"
            fi
        else
            log_warn "No images were built"
        fi

        log_success "Build pipeline completed successfully"
        return 0
    fi

    # Find Dockerfile if not specified
    if [[ -z "$dockerfile" ]]; then
        log_info "Searching for Dockerfile..."
        dockerfile=$(find_dockerfile "${image_name:-}")
        if [[ -z "$dockerfile" ]]; then
            log_error "Dockerfile not found"
            return 1
        fi
        log_info "Found Dockerfile: $dockerfile"
    fi

    # Validate Dockerfile exists
    if [[ ! -f "$dockerfile" ]]; then
        log_error "Dockerfile not found: $dockerfile"
        return 1
    fi

    # Set image name
    if [[ -n "$image_name" ]]; then
        CONFIG[IMAGE_NAME]="$image_name"
    else
        # Derive from Dockerfile directory name
        CONFIG[IMAGE_NAME]=$(basename "$(dirname "$dockerfile")" 2>/dev/null || echo "unnamed")
    fi

    # Find config YAML if not specified
    if [[ -z "$config_yaml" && -n "${BUILDERS_DIR:-}" ]]; then
        config_yaml=$(find "$BUILDERS_DIR" -name build.yaml -o -name config.yaml 2>/dev/null | head -1)
        [[ -n "$config_yaml" ]] && log_info "Found config: $config_yaml"
    fi

    # Load configuration (Dockerfile + YAML + ENV)
    log_info "Loading configuration..."
    load_config "$dockerfile" "$config_yaml"

    # Extract Git information
    if [[ -d "${SOURCE_DIR:-}/.git" ]]; then
        log_info "Extracting Git information..."
        extract_git_info "$SOURCE_DIR"
    fi

    # Get runner ID for tagging
    if [[ -z "${CONFIG[RUNNER_ID]:-}" ]]; then
        CONFIG[RUNNER_ID]=$(get_runner_id)
    fi
    log_info "Runner ID: ${CONFIG[RUNNER_ID]}"

    # Login to primary registry
    if [[ ${#REGISTRIES[@]} -gt 0 ]]; then
        local primary_registry
        primary_registry=$(echo "${REGISTRIES[0]}" | cut -d, -f1)
        log_info "Logging into primary registry: $primary_registry"
        #ci_login_to_registry "$primary_registry" || log_warn "Registry login failed (continuing anyway)"
    fi

    # Determine build context - resolve to absolute path
    local build_context
    if [[ -n "${SOURCE_DIR:-}" ]]; then
        build_context="$SOURCE_DIR"
    else
        # Resolve dockerfile directory to absolute path
        build_context="$(cd "$(dirname "$dockerfile")" && pwd)"
    fi
    log_info "Using build context: $build_context"

    # Merge additional folders if needed (docker, prebuildfs, rootfs)
    local additional_folders="${DOCKER_DIR:-},${PREBUILD_DIR:-},${ROOTFS_DIR:-}"
    if [[ -n "$additional_folders" && "$additional_folders" != ",," ]]; then
        log_info "Merging additional folders into build context"
        local temp_context
        if command -v ci_create_temp_dir >/dev/null 2>&1; then
            temp_context=$(ci_create_temp_dir)
        else
            temp_context=$(mktemp -d)
        fi

        # Copy primary context
        cp -r "$build_context"/. "$temp_context"/ 2>/dev/null || true

        # Copy additional folders
        IFS=',' read -ra FOLDERS <<< "$additional_folders"
        for folder in "${FOLDERS[@]}"; do
            folder="${folder%"${folder##*[![:space:]]}"}"  # trim whitespace
            if [[ -n "$folder" && -d "$folder" ]]; then
                local folder_name
                folder_name=$(basename "$folder")
                log_info "Copying $folder → $temp_context/$folder_name"
                cp -r "$folder" "$temp_context/$folder_name" 2>/dev/null || true
            fi
        done

        build_context="$temp_context"
        log_info "Using merged build context: $build_context"
    fi

    # Build and push images
    log_info "Starting build and push..."
    ci_build_and_push "$dockerfile" "$build_context"
    local build_status=$?

    # Handle build failure
    if [[ $build_status -ne 0 ]]; then
        log_error "Build and push failed with status $build_status"

        # Set failure status for CI
        if command -v set_env >/dev/null 2>&1; then
            set_env exit_code "$build_status"
        else
            export exit_code="$build_status"
        fi

        return $build_status
    fi

    # Post-build operations (SBOM, vulnerability reports, cleanup)
    if [[ ${#CI_BUILT_IMAGES[@]} -gt 0 ]]; then
        local primary_img="${CI_BUILT_IMAGES[0]}"
        log_info "Primary image: $primary_img"

        # Generate and attach SBOM + vulnerability report for every built image
        local img
        for img in "${CI_BUILT_IMAGES[@]}"; do
            log_info "Post-build artifacts for image: $img"
            ci_generate_and_attach_sbom "$img" || log_warn "SBOM generation/attachment failed for $img"
            ci_generate_and_attach_vuln_report "$img" || log_warn "Vulnerability report generation/attachment failed for $img"
        done

        # Sign image
        #sign_with_cosign "$primary_img"

        # Remove local images if requested
        if [[ "${REMOVE_LOCAL_IMAGES:-true}" == "true" ]]; then
            log_info "Removing local images (REMOVE_LOCAL_IMAGES=true)"
            remove_docker_images "${CI_BUILT_IMAGES[@]}"
        fi
    else
        log_warn "No images were built"
    fi

    log_success "Build pipeline completed successfully"
    return 0
}

