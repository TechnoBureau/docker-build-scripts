#!/usr/bin/env bash
# lib/ci-build.sh
#
# Purpose:
#   Build orchestration (setup_buildx, builder contexts, tag generation, build_and_push).
#   Preserves Buildx/podman parity, secrets, labels and tagging mechanics from original scripts.
#
# Usage:
#   source lib/ci-build.sh
#
# Functions:
#   ci_setup_buildx
#   ci_add_context <name> <path> (internal)
#   ci_setup_builder_contexts
#   ci_build_and_push <Dockerfile> <context>
#
# Example:
#   ci_build_and_push /repo/docker/Dockerfile /repo
#

# Source dependencies
if [[ -z "${CI_CORE_LOADED:-}" ]]; then
    LIB_DIR="${LIB_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
    # shellcheck source=/dev/null
    source "${LIB_DIR}/ci-core.sh"
    # shellcheck source=/dev/null
    source "${LIB_DIR}/ci-secrets.sh"
    # shellcheck source=/dev/null
    source "${LIB_DIR}/ci-registry.sh"
    # shellcheck source=/dev/null
    source "${LIB_DIR}/ci-ecr.sh"
fi

# Ensure CONFIG is declared as associative array
declare -gA CONFIG 2>/dev/null || true

# Setup buildx / podman configuration for multi-arch builds
ci_setup_buildx(){
    local container_engine
    container_engine="$(detect_container_engine 2>/dev/null || echo docker)"
    # WHY: Use CONFIG[PLATFORMS] from parsed config, not env var PLATFORMS
    local platforms="${CONFIG[PLATFORMS]:-}"
    local builder_name="${BUILDX_BUILDER_NAME:-ci-builder}"
    local driver_image="${BUILDX_BUILDKIT_IMAGE:-}"
    local install_binfmt="${INSTALL_BINFMT:-auto}"

    # best-effort install qemu/binfmt (only when multi-arch requested and not disabled)
    if [[ -n "$platforms" && "$install_binfmt" != "0" ]]; then
        local img="docker.io/tonistiigi/binfmt:latest"
        if [[ "$container_engine" == "docker" ]]; then
            docker run --privileged --rm "$img" --install all >/dev/null 2>&1 || true
        else
            podman run --privileged --rm "$img" --install all >/dev/null 2>&1 || true
        fi
    fi

    if [[ "$container_engine" == "docker" ]]; then
        if ! docker buildx version >/dev/null 2>&1; then
            log_warn "docker buildx not available - fall back to docker build"
            return 0
        fi
        # Use builder when multi-arch required
        if [[ -n "$platforms" ]]; then
            if ! docker buildx inspect "$builder_name" >/dev/null 2>&1; then
                docker buildx create --name "$builder_name" --driver docker-container --use >/dev/null 2>&1 || true
            else
                docker buildx use "$builder_name" >/dev/null 2>&1 || true
            fi
            docker buildx inspect --bootstrap >/dev/null 2>&1 || true
        fi
        return 0
    fi

    # Podman path - no buildx; rely on podman build with --platform when supported
    return 0
}

# add builder contexts (internal)
ci_add_context(){
    local name="$1" path="$2"
    [[ -z "$name" || -z "$path" ]] && return 0
    [[ ! -d "$path" ]] && { log_debug "ci_add_context: path not found: $path"; return 0; }
    # callers will build build_args list and ignore unsupported --context flags for some engines
    BUILD_CONTEXTS="${BUILD_CONTEXTS:-},${name}=${path}"
}

# populate default contexts
ci_setup_builder_contexts(){
    # Add common directories if present
    if [[ -d "${SCRIPTS_DIR:-./scripts}/build" ]]; then ci_add_context build "${SCRIPTS_DIR:-./scripts}/build"; fi
    if [[ -d "${DOCKER_DIR:-./docker}" ]]; then ci_add_context docker "${DOCKER_DIR:-./docker}"; fi
    if [[ -d "${PREBUILD_DIR:-./prebuildfs}" ]]; then ci_add_context prebuildfs "${PREBUILD_DIR:-./prebuildfs}"; fi
    # any additional contexts via CONFIG[BUILDER_CONTEXTS] (CSV of name=path)
    # WHY: Use CONFIG[BUILDER_CONTEXTS] from parsed config, not env var
    if [[ -n "${CONFIG[BUILDER_CONTEXTS]:-}" ]]; then
        IFS=',' read -r -a arr <<< "${CONFIG[BUILDER_CONTEXTS]}"
        for c in "${arr[@]:-}"; do
            if [[ "$c" =~ ^([^=]+)=(.+)$ ]]; then ci_add_context "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}"; fi
        done
    fi
}

# Main build and push function. Respects REGISTRIES array entries (name,prefix,push)
# Usage: ci_build_and_push <Dockerfile> <context>
ci_build_and_push(){
    local dockerfile="$1"
    local context="${2:-$(cd "$(dirname "$dockerfile")" && pwd)}"
    [[ ! -f "$dockerfile" ]] && { log_error "ci_build_and_push: Dockerfile not found: $dockerfile"; return 1; }

    local engine
    engine="$(detect_container_engine)"

    ci_setup_buildx || { log_error "ci_setup_buildx failed"; return 1; }

    # base args
    # WHY: Use CONFIG[VERSION] from parsed Dockerfile comments, not env var VERSION
    local -a build_args=("--file" "$dockerfile" "--build-arg" "VERSION=${CONFIG[VERSION]:-latest}")

    # add labels
    while IFS= read -r l; do [[ -n "$l" ]] && build_args+=("--label" "$l"); done < <(ci_generate_oci_labels)

    # secrets processing: explicit BUILD_SECRETS from CONFIG like "ID=ENVVAR,ID2=ENV2"
    # WHY: Use CONFIG[BUILD_SECRETS] from parsed config, not env var
    local explicit=()
    IFS=',' read -ra explicit <<< "${CONFIG[BUILD_SECRETS]:-}"

    for pair in "${explicit[@]:-}"; do
        [[ "$pair" =~ ^([^=]+)=(.+)$ ]] || continue
        local id="${BASH_REMATCH[1]}"
        local envv="${BASH_REMATCH[2]}"
        local val="${!envv:-}"
        if [[ -z "$val" ]]; then log_warn "Secret $id env $envv empty - skipping"; continue; fi
        local tmp
        tmp="$(ci_secret_to_file "$id" "$val")"
        build_args+=("--secret" "id=$id,src=$tmp")
    done

    # auto-detected dockerfile secrets
    # WHY: Cannot use ${!CONFIG[@]:-} - the :- default syntax is incompatible with ! key expansion
    # The array will be empty if not set, so no need for :- default
    for k in "${!CONFIG[@]}"; do
        [[ "$k" =~ ^SECRET_ ]] || continue
        local id="${k#SECRET_}"
        # skip if already supplied
        if [[ " ${explicit[*]:-} " == *" ${id}="* ]]; then log_debug "Secret $id supplied explicitly - skip auto"; continue; fi
        local val
        val="$(ci_resolve_secret_value "$id")"
        if [[ -z "$val" ]]; then log_info "Secret $id detected but no value - skipped"; continue; fi
        local tmp
        tmp="$(ci_secret_to_file "$id" "$val")"
        build_args+=("--secret" "id=$id,src=$tmp")
    done

    # generate tags per REGISTRIES
    # WHY: Declare as global array only if not already declared, preserve existing values
    declare -ga CI_BUILT_IMAGES 2>/dev/null || true
    CI_BUILT_IMAGES=()  # Reset for this build
    local reg_entry

    # WHY: Log image tags and registries before building for better visibility
    log_info "═══════════════════════════════════════════════════════════"
    log_info "Image Build Configuration:"
    log_info "  Image Name: ${CONFIG[IMAGE_NAME]:-unnamed}"
    log_info "  Version: ${CONFIG[VERSION]:-latest}"
    log_info "  Tag Strategy: ${CONFIG[TAG_STRATEGY]:-version-latest}"

    # Generate and display tags
    local all_tags
    all_tags="$(ci_generate_tag)"
    log_info "  Generated Tags: $all_tags"

    # Display registries and full image references
    log_info "Target Registries:"
    log_debug "REGISTRIES array size: ${#REGISTRIES[@]}"
    log_debug "REGISTRIES content: ${REGISTRIES[*]}"


    # Login to all registries (FROM registries first, then push registries)
    ci_login_all_registries
    
    # Pre-pull FROM images to handle ICR namespace-level credentials
    local -a pulled_images=()
    mapfile -t pulled_images < <(ci_prepull_from_images "$dockerfile" "$engine")

    for reg_entry in "${REGISTRIES[@]:-}"; do
        IFS=',' read -r reg pref push <<< "$reg_entry"
        log_debug "Processing registry: reg=$reg, pref=$pref, push=$push"

        local repo="${reg}"
        [[ -n "$pref" ]] && repo="${repo%/}/${pref}"
        repo="${repo%/}/${CONFIG[IMAGE_NAME]:-unnamed}"

        if [[ "${push:-true}" == "true" ]]; then
            log_info "  ✓ ${repo} (push enabled)"
            for t in $all_tags; do
                log_info "    → ${repo}:${t}"
                build_args+=("--tag" "${repo}:${t}")
                CI_BUILT_IMAGES+=("${repo}:${t}")
                log_debug "Added to CI_BUILT_IMAGES: ${repo}:${t} (total: ${#CI_BUILT_IMAGES[@]})"
            done
            ci_ensure_ecr_repository "${reg}" "${pref}" "${CONFIG[IMAGE_NAME]:-}" || log_warn "Repo prep failed for $reg/$pref/${CONFIG[IMAGE_NAME]:-} (continuing)"
        else
            log_info "  ✗ ${repo} (push disabled)"
        fi
    done
    log_info "═══════════════════════════════════════════════════════════"
    log_debug "Total images in CI_BUILT_IMAGES after loop: ${#CI_BUILT_IMAGES[@]}"


    # contexts handling - attempt to use buildx --context if supported
    ci_setup_builder_contexts
    # expand BUILD_CONTEXTS to --context args, but avoid passing them to engines that do not support them:
    if [[ "$engine" == "docker" ]]; then
        # WHY: Use --push to push images to registry, not --load which only loads locally
        local push_or_load="--push"
        # WHY: If no remote registries configured, use --load for local testing
        if [[ ${#CI_BUILT_IMAGES[@]} -eq 0 ]]; then
            push_or_load="--load"
        fi

        if docker buildx build --help 2>/dev/null | grep -q -- '--context'; then
            IFS=',' read -r -a ctxs <<< "${BUILD_CONTEXTS:-}"
            for c in "${ctxs[@]:-}"; do
                [[ -z "$c" ]] && continue
                build_args+=(--context "$c")
            done
            docker buildx build "${build_args[@]}" "$push_or_load" "$context" 2>&1 | grep -v '^[a-f0-9]\{64\}$' || return 1
        else
            # remove context args and run buildx
            local docker_args=()
            local prev=""
            for a in "${build_args[@]:-}"; do
                if [[ "$a" == "--context" ]]; then prev="--context"; continue; fi
                if [[ "$prev" == "--context" ]]; then prev=""; continue; fi
                docker_args+=("$a")
            done
            docker buildx build "${docker_args[@]}" "$push_or_load" "$context" 2>&1 | grep -v '^[a-f0-9]\{64\}$' || return 1
        fi
    else
        # podman - remove context flags and use podman build
        local podman_args=()
        local prev=""
        for a in "${build_args[@]:-}"; do
            if [[ "$a" == "--context" ]]; then prev="--context"; continue; fi
            if [[ "$prev" == "--context" ]]; then prev=""; continue; fi
            podman_args+=("$a")
        done

        # podman supports --platform on a per-build basis, check PODMAN_BUILD_PLATFORMS
        if [[ -n "${PODMAN_BUILD_PLATFORMS:-}" && "${PODMAN_BUILD_PLATFORMS}" == *","* ]]; then
            # build per-platform and create manifest - best-effort
            local manifest="localhost/${CONFIG[IMAGE_NAME]:-unnamed}-manifest:latest"
            podman manifest create "$manifest" >/dev/null 2>&1 || true
            for plat in $(echo "${PODMAN_BUILD_PLATFORMS}" | tr ',' ' '); do
                podman build "${podman_args[@]}" --platform "$plat" --manifest "$manifest" "$context" 2>&1 | grep -v '^[a-f0-9]\{64\}$' || return 1
            done
            # WHY: Push manifest to all tagged images, not just the first one
            if [[ "${#CI_BUILT_IMAGES[@]}" -gt 0 ]]; then
                for img in "${CI_BUILT_IMAGES[@]}"; do
                    log_info "Pushing manifest to: $img"
                    podman manifest push --all "$manifest" "$img" || log_warn "Failed to push manifest to $img"
                done
            fi
        else
            # WHY: Build image with all tags, then explicitly push each one
            podman build "${podman_args[@]}" "$context" 2>&1 | grep -v '^[a-f0-9]\{64\}$' || return 1

            # WHY: Explicitly push each tagged image to registry
            if [[ "${#CI_BUILT_IMAGES[@]}" -gt 0 ]]; then
                for img in "${CI_BUILT_IMAGES[@]}"; do
                    log_info "Pushing image to registry: $img"
                    podman push "$img" || { log_error "Failed to push $img"; return 1; }
                done
            fi
        fi
    fi

    # Print SHA digest and summary for built images
    if [[ "${#CI_BUILT_IMAGES[@]}" -gt 0 ]]; then
        local primary_img="${CI_BUILT_IMAGES[0]}"
        local digest=""

        # WHY: Get digest from registry (most reliable) or local inspection
        if command -v skopeo >/dev/null 2>&1; then
            digest="$(skopeo inspect --format '{{.Digest}}' "docker://${primary_img}" 2>/dev/null || echo "")"
        fi
        if [[ -z "$digest" ]]; then
            if [[ "$engine" == "docker" ]]; then
                digest="$(docker inspect --format='{{index .RepoDigests 0}}' "$primary_img" 2>/dev/null | cut -d'@' -f2 || echo "")"
            else
                digest="$(podman inspect --format='{{index .RepoDigests 0}}' "$primary_img" 2>/dev/null | cut -d'@' -f2 || echo "")"
            fi
        fi

        # WHY: Display build results in a clear, structured format
        log_info "═══════════════════════════════════════════════════════════"
        log_info "Build Complete - Image Details:"
        log_info "  Primary Image: ${primary_img}"
        if [[ -n "$digest" ]]; then
            log_info "  SHA Digest: ${digest}"
        else
            log_warn "  SHA Digest: Not available yet (will be available after push)"
        fi

        if [[ "${#CI_BUILT_IMAGES[@]}" -gt 1 ]]; then
            log_info "  Additional Tags (${#CI_BUILT_IMAGES[@]} total):"
            for img in "${CI_BUILT_IMAGES[@]:1}"; do
                log_info "    → ${img}"
            done
        fi
        log_info "═══════════════════════════════════════════════════════════"
    fi

    # === ARTIFACT SAVE ===
    # WHY: Only save artifact for primary image (registry_0), not for all registries
    if [[ ${#CI_BUILT_IMAGES[@]} -gt 0 && -n "${CI_BUILT_IMAGES[0]}" ]]; then
        ci_store_artifact "${CI_BUILT_IMAGES[0]}"
    fi

    # Cleanup pre-pulled FROM images
    ci_cleanup_pulled_images "$engine" "${pulled_images[@]}"

    CI_LAST_BUILT_IMAGES=("${CI_BUILT_IMAGES[@]}")
    log_success "Built images: ${#CI_BUILT_IMAGES[@]}"
    return 0
}
