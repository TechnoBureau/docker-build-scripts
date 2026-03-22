#!/usr/bin/env bash
# promotion.sh
#
# Purpose:
#   Promote container images from source to target registry using skopeo
#   Supports bulk image promotion with parallel processing and digest preservation
#
# Input Parameters:
#   -s, --source-registry   Source registry URL (e.g., icr.io/namespace)
#   -r, --target-registry   Target registry URL (e.g., ECR URL)
#   -p, --prefix            Source registry prefix/path
#   -d, --dst-prefix        Target registry prefix/path
#   -l, --image-list        Space-separated image list (format: "image:tag image2:tag")
#   --parallel N            Parallel workers (default: 2, max: 16)
#
# Output:
#   - Promoted images in target registry with preserved digests
#   - Returns 0 on success, 1 on failure
#
# Usage Example:
#   ./promotion.sh -s icr.io/namespace -r 123.dkr.ecr.us-east-1.amazonaws.com \
#                  -p source-path -d target-path -l "image1:v1.0 image2:v2.0" --parallel 4

set -euo pipefail
IFS=$'\n\t'

# =============================================================================
# DEBUG MODE DETECTION - Must be before sourcing other modules
# =============================================================================
# WHY: Robust debug detection accepts 1, true, TRUE, yes, on, etc. (case-insensitive)
if [[ -n "${DEBUG:-}" ]] && ! [[ "${DEBUG,,}" =~ ^(0|false|no|off)$ ]]; then
    set -x
fi

# =============================================================================
# SOURCE MODULAR LIBRARIES
# =============================================================================
CI_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${LIB_DIR:-${CI_SCRIPT_DIR}/lib}"

# Core CI libraries (self-sourcing)
# shellcheck source=/dev/null
source "${LIB_DIR}/ci-core.sh"
# shellcheck source=/dev/null
source "${LIB_DIR}/ci-registry.sh"
# shellcheck source=/dev/null
source "${LIB_DIR}/ci-ecr.sh"
# shellcheck source=/dev/null
source "${LIB_DIR}/ci-promote.sh"

# =============================================================================
# GLOBAL VARIABLES AND DEFAULTS
# =============================================================================
SOURCE_REGISTRY=""
TARGET_REGISTRY=""
SOURCE_PREFIX=""
TARGET_PREFIX=""
IMAGE_LIST=""
PARALLEL=2

# =============================================================================
# DISPLAY USAGE INFORMATION
# =============================================================================
# Purpose: Show command-line options and examples
# Input: None
# Output: Prints usage information to stdout
usage() {
    cat <<'EOF'
Usage: promotion.sh -s <source-registry> -r <target-registry> -l <image-list> [options]

Required:
  -s, --source-registry   Source registry URL (e.g., icr.io/namespace)
  -r, --target-registry   Target registry URL (e.g., ECR URL)
  -l, --image-list        Space-separated image list (quoted string)

Optional:
  -p, --prefix            Source registry prefix/path (default: empty)
  -d, --dst-prefix        Target registry prefix/path (default: empty)
  --parallel N            Parallel workers (default: 2, max: 16)
  -h, --help              Show this help message

Image List Format:
  Space-separated string with images in format: image:tag or image
  Examples:
    "pipelines-controller:v1.20.1 pipelines-webhook:v1.20.1"
    "image1:v1.0 image2:v2.0 image3"
    "openshift-pipelines/controller:v1.0 operator:v2.0"

Example:
  ./promotion.sh -s icr.io/ipaas-non-prod/wm-int -r 123.dkr.ecr.us-east-1.amazonaws.com \
                 -p openshift-pipelines -d ibm-pipelines \
                 -l "pipelines-controller:v1.20.1 pipelines-webhook:v1.20.1" --parallel 4
EOF
    exit 2
}

# =============================================================================
# PARSE COMMAND LINE ARGUMENTS
# =============================================================================
while [[ $# -gt 0 ]]; do
    case "$1" in
        -s|--source-registry) SOURCE_REGISTRY="$2"; shift 2;;
        -r|--target-registry) TARGET_REGISTRY="$2"; shift 2;;
        -p|--prefix) SOURCE_PREFIX="$2"; shift 2;;
        -d|--dst-prefix) TARGET_PREFIX="$2"; shift 2;;
        -l|--image-list) IMAGE_LIST="$2"; shift 2;;
        --parallel) PARALLEL="$2"; shift 2;;
        -h|--help) usage;;
        *) log_error "Unknown argument: $1"; usage;;
    esac
done

# =============================================================================
# VALIDATE REQUIRED PARAMETERS
# =============================================================================
[[ -z "$SOURCE_REGISTRY" ]] && { log_error "Source registry required (-s)"; usage; }
[[ -z "$TARGET_REGISTRY" ]] && { log_error "Target registry required (-r)"; usage; }
[[ -z "$IMAGE_LIST" ]] && { log_error "Image list required (-l)"; usage; }

# WHY: Validate and cap parallel workers to prevent resource exhaustion
if ! [[ "$PARALLEL" =~ ^[1-9][0-9]*$ ]]; then
    log_warn "Invalid parallel value: $PARALLEL, using default: 2"
    PARALLEL=2
fi
(( PARALLEL = PARALLEL > 16 ? 16 : PARALLEL ))

# =============================================================================
# DISPLAY CONFIGURATION SUMMARY
# =============================================================================
log_info "=== Image Promotion Configuration ==="
log_info "Source registry: ${SOURCE_REGISTRY}"
log_info "Source prefix: ${SOURCE_PREFIX:-<none>}"
log_info "Target registry: ${TARGET_REGISTRY}"
log_info "Target prefix: ${TARGET_PREFIX:-<none>}"
log_info "Image list: ${IMAGE_LIST}"
log_info "Parallel workers: ${PARALLEL}"
log_info "======================================"

# =============================================================================
# PARSE IMAGE LIST AND SEGREGATE INTO ARRAYS
# =============================================================================
# Purpose: Parse space-separated image list and separate image names, tags, and digests
# Input: image_list_string (string) - space-separated image list
# Output: Populates IMAGE_NAMES, IMAGE_TAGS, IMAGE_DIGESTS arrays
# WHY: ci_promote_image requires separate parameters for image_name and dest_tag
parse_image_list() {
    local image_list_string="$1"

    # WHY: Initialize arrays to store parsed image components
    IMAGE_NAMES=()
    IMAGE_TAGS=()
    IMAGE_DIGESTS=()

    log_info "Parsing image list: ${image_list_string}"

    # WHY: Split space-separated string into array
    # Temporarily set IFS to space for proper splitting
    local -a images
    local old_ifs="$IFS"
    IFS=' '
    read -ra images <<< "$image_list_string"
    IFS="$old_ifs"

    # WHY: Parse each image entry
    for image_entry in "${images[@]}"; do
        # Skip empty entries
        [[ -z "$image_entry" ]] && continue

        local image_name tag digest=""

        # WHY: Parse format: image:tag@digest or image:tag or image@digest
        if [[ "$image_entry" =~ ^([^:@]+):([^@]+)@(.+)$ ]]; then
            # Format: image:tag@digest
            image_name="${BASH_REMATCH[1]}"
            tag="${BASH_REMATCH[2]}"
            digest="${BASH_REMATCH[3]}"
        elif [[ "$image_entry" =~ ^([^:@]+):(.+)$ ]]; then
            # Format: image:tag
            image_name="${BASH_REMATCH[1]}"
            tag="${BASH_REMATCH[2]}"
        elif [[ "$image_entry" =~ ^([^@]+)@(.+)$ ]]; then
            # Format: image@digest (no tag)
            image_name="${BASH_REMATCH[1]}"
            digest="${BASH_REMATCH[2]}"
            tag="latest"
        else
            # Format: image (no tag or digest)
            image_name="$image_entry"
            tag="latest"
        fi

        # WHY: Store parsed components in parallel arrays
        IMAGE_NAMES+=("$image_name")
        IMAGE_TAGS+=("$tag")
        IMAGE_DIGESTS+=("$digest")

        log_debug "Parsed: image=$image_name, tag=$tag, digest=${digest:-<none>}"
    done

    local total="${#IMAGE_NAMES[@]}"
    if [[ "$total" -eq 0 ]]; then
        log_error "No valid images found in image list"
        return 1
    fi

    log_success "Parsed ${total} images from list"
    return 0
}

# =============================================================================
# PROMOTE SINGLE IMAGE
# =============================================================================
# Purpose: Promote a single image from source to target registry
# Input: index (int) - index into IMAGE_NAMES/IMAGE_TAGS/IMAGE_DIGESTS arrays
# Output: Returns 0 on success, 1 on failure
# WHY: Worker function for parallel processing
promote_single_image() {
    local index="$1"

    local image_name="${IMAGE_NAMES[$index]}"
    local tag="${IMAGE_TAGS[$index]}"
    local digest="${IMAGE_DIGESTS[$index]}"

    # WHY: Build source image reference with full path
    # Format: registry/prefix/image:tag or registry/prefix/image@digest
    local source_image
    if [[ -n "$SOURCE_PREFIX" ]]; then
        source_image="${SOURCE_REGISTRY}/${SOURCE_PREFIX}/${image_name}"
    else
        source_image="${SOURCE_REGISTRY}/${image_name}"
    fi

    # WHY: Append digest if available, otherwise use tag
    if [[ -n "$digest" ]]; then
        source_image="${source_image}@${digest}"
    else
        source_image="${source_image}:${tag}"
    fi

    # WHY: Extract base image name (without path) for target
    local base_image_name="${image_name##*/}"

    log_info "Promoting image [$((index + 1))/${#IMAGE_NAMES[@]}]: ${image_name}"
    log_debug "  Source: ${source_image}"
    log_debug "  Target: ${TARGET_REGISTRY}/${TARGET_PREFIX:+${TARGET_PREFIX}/}${base_image_name}:${tag}"

    # WHY: Call ci_promote_image with all required parameters
    # Parameters: source_image, dest_registry, dest_prefix, image_name, dest_tag, source_registry
    if ci_promote_image "$source_image" "$TARGET_REGISTRY" "$TARGET_PREFIX" \
                        "$base_image_name" "$tag" "$SOURCE_REGISTRY"; then
        log_success "Promoted: ${image_name}:${tag}"
        return 0
    else
        log_error "Failed to promote: ${image_name}:${tag}"
        return 1
    fi
}

# =============================================================================
# PROCESS IMAGES IN PARALLEL
# =============================================================================
# Purpose: Promote multiple images concurrently with worker pool
# Input: None (uses global IMAGE_NAMES, IMAGE_TAGS, IMAGE_DIGESTS arrays)
# Output: Returns 0 if all succeed, 1 if any fail
# WHY: Parallel processing significantly reduces total promotion time
process_images_parallel() {
    local total="${#IMAGE_NAMES[@]}"

    log_info "Processing ${total} images with ${PARALLEL} workers"

    # WHY: Worker pool variables for parallel job management
    local -a pids=()
    local success_count=0
    local fail_count=0
    local index=0

    # WHY: Process images with parallel workers (similar to operator-image.sh)
    while (( index < total )); do
        # WHY: Start workers up to parallel limit
        while (( ${#pids[@]} < PARALLEL && index < total )); do
            # WHY: Start worker in background subshell
            (
                promote_single_image "$index"
            ) &
            pids+=("$!")
            ((index++))
        done

        # WHY: Check completed workers and collect results
        for i in "${!pids[@]}"; do
            local pid="${pids[i]}"
            if ! kill -0 "${pid}" 2>/dev/null; then
                # WHY: Worker completed, check exit status
                if wait "${pid}"; then
                    ((success_count++))
                else
                    ((fail_count++))
                fi
                unset 'pids[i]'
            fi
        done

        # WHY: Rebuild pids array without gaps
        pids=("${pids[@]}")
        sleep 0.1
    done

    # WHY: Wait for remaining workers to complete
    for pid in "${pids[@]}"; do
        if wait "${pid}"; then
            ((success_count++))
        else
            ((fail_count++))
        fi
    done

    log_info "Image promotion complete: ${success_count} succeeded, ${fail_count} failed"

    if (( fail_count > 0 )); then
        log_error "Some images failed to promote"
        return 1
    fi

    return 0
}

# =============================================================================
# MAIN EXECUTION
# =============================================================================
main() {
    log_info "Starting image promotion process..."

    # WHY: Login to source and target registries before promotion
    log_info "Logging into source registry: ${SOURCE_REGISTRY}"
    ci_login_to_registry "$SOURCE_REGISTRY" || log_warn "Source registry login failed (may work anonymously)"

    log_info "Logging into target registry: ${TARGET_REGISTRY}"
    ci_login_to_registry "$TARGET_REGISTRY" || {
        log_error "Target registry login failed"
        exit 1
    }

    # WHY: Parse image list string and segregate into component arrays
    if ! parse_image_list "$IMAGE_LIST"; then
        log_error "Failed to parse image list"
        exit 1
    fi

    # WHY: Process images in parallel for efficiency
    if ! process_images_parallel; then
        log_error "Image promotion failed"
        exit 1
    fi

    log_success "All images promoted successfully!"
    return 0
}

# WHY: Execute main function and exit with its status
main
exit $?


