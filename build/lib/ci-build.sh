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
declare -ga CI_BUILD_ARCHES 2>/dev/null || true

# Setup buildx / podman configuration for multi-arch builds
ci_setup_buildx(){
    local container_engine
    container_engine="$(detect_container_engine 2>/dev/null || echo docker)"
    # WHY: Use CONFIG[PLATFORMS] from parsed config, not env var PLATFORMS
    local platforms="${CONFIG[PLATFORMS]:-}"
    local install_binfmt="${INSTALL_BINFMT:-auto}"
    local dind_image="${DIND_IMAGE:-${dind_image:-}}"

    ci_get_required_binfmt_arches() {
        local requested_platforms="$1"
        local native_arch=""
        local -a required_arches=()
        local -A seen_arches=()

        native_arch="$(uname -m 2>/dev/null || echo "")"
        case "$native_arch" in
            x86_64|amd64) native_arch="amd64" ;;
            aarch64|arm64) native_arch="arm64" ;;
            armv7l|armv7|armhf) native_arch="arm" ;;
            ppc64le) native_arch="ppc64le" ;;
            s390x) native_arch="s390x" ;;
        esac

        IFS=',' read -ra requested_platform_list <<< "$requested_platforms"
        for req_plat in "${requested_platform_list[@]}"; do
            req_plat="$(echo "$req_plat" | tr -d ' ')"
            [[ -z "$req_plat" ]] && continue
            [[ "$req_plat" != linux/* ]] && continue

            local req_arch="${req_plat#linux/}"
            case "$req_arch" in
                amd64|386) ;;
                arm64|arm/v8) req_arch="arm64" ;;
                arm/v7|arm/v6|arm) req_arch="arm" ;;
                ppc64le|s390x|riscv64) ;;
            esac

            [[ "$req_arch" == "$native_arch" ]] && continue
            [[ -n "${seen_arches[$req_arch]:-}" ]] && continue
            seen_arches["$req_arch"]=1
            required_arches+=("$req_arch")
        done

        printf '%s\n' "${required_arches[*]}"
    }

    ci_check_binfmt_platforms() {
        local binfmt_dir="/proc/sys/fs/binfmt_misc"
        local -a supported_platforms=()
        local native_arch=""

        # Get native architecture
        native_arch="$(uname -m 2>/dev/null || echo "unknown")"
        case "$native_arch" in
            x86_64|amd64) native_arch="amd64" ;;
            aarch64|arm64) native_arch="arm64" ;;
            armv7l|armv7|armhf) native_arch="arm" ;;
            ppc64le) native_arch="ppc64le" ;;
            s390x) native_arch="s390x" ;;
        esac

        log_info "Native platform: linux/${native_arch}"

        if [[ ! -d "$binfmt_dir" ]]; then
            log_info "binfmt_misc directory not available"
            return 0
        fi

        # Check for registered QEMU interpreters
        for entry in "$binfmt_dir"/qemu-*; do
            [[ -f "$entry" ]] || continue
            local arch="${entry##*/qemu-}"
            supported_platforms+=("$arch")
        done

        if [[ ${#supported_platforms[@]} -gt 0 ]]; then
            log_info "Emulation platforms registered: ${supported_platforms[*]}"
        else
            log_info "No emulation platforms currently registered"
        fi
    }

    ci_ensure_binfmt_support() {
        local requested_platforms="$1"
        local runtime_image="$2"
        local required_arches=""
        local install_targets=""
        local register_path="/proc/sys/fs/binfmt_misc/register"

        required_arches="$(ci_get_required_binfmt_arches "$requested_platforms")"
        required_arches="$(echo "$required_arches" | xargs 2>/dev/null || true)"

        if [[ -z "$required_arches" ]]; then
            log_info "No non-native emulation required for platforms: $requested_platforms"
            return 0
        fi

        if [[ ! -f "$register_path" ]]; then
            log_info "binfmt_misc not mounted - mounting /proc/sys/fs/binfmt_misc"
            mount binfmt_misc -t binfmt_misc /proc/sys/fs/binfmt_misc >/dev/null 2>&1 || \
                log_warn "Failed to mount binfmt_misc (continuing)"
        fi

        install_targets="${required_arches// /,}"
        log_info "Ensuring binfmt emulation for required architectures: ${install_targets}"

        # Check supported platforms before installation
        log_info "Platform support status BEFORE binfmt installation:"
        ci_check_binfmt_platforms

        # WHY: Check if required emulators are already registered before attempting installation
        # Map Docker arch names to QEMU binfmt file names to prevent false warnings
        local binfmt_dir="/proc/sys/fs/binfmt_misc"
        local -a missing_arches=()
        IFS=',' read -ra required_arch_list <<< "$install_targets"

        for arch in "${required_arch_list[@]}"; do
            arch="$(echo "$arch" | tr -d ' ')"
            [[ -z "$arch" ]] && continue

            # Map Docker arch names to QEMU binfmt file names
            local qemu_arch="$arch"
            case "$arch" in
                amd64) qemu_arch="x86_64" ;;
                arm64) qemu_arch="aarch64" ;;
                arm) qemu_arch="arm" ;;
                ppc64le) qemu_arch="ppc64le" ;;
                s390x) qemu_arch="s390x" ;;
                riscv64) qemu_arch="riscv64" ;;
                386) qemu_arch="i386" ;;
            esac

            # Check if qemu-$qemu_arch is registered
            if [[ ! -f "$binfmt_dir/qemu-$qemu_arch" ]]; then
                missing_arches+=("$arch")
            fi
        done

        if [[ ${#missing_arches[@]} -eq 0 ]]; then
            log_info "All required emulators already registered - skipping installation"
        else
            log_info "Missing emulators: ${missing_arches[*]} - attempting installation"

            # WHY: Use detected container engine instead of hardcoded docker
            local container_engine_cmd
            container_engine_cmd="$(detect_container_engine 2>/dev/null || echo docker)"

            # Try installation with two different command formats
            if $container_engine_cmd run --rm --privileged \
                -v /proc/sys/fs/binfmt_misc:/proc/sys/fs/binfmt_misc \
                "$runtime_image" \
                /binfmt-check.sh --install "${install_targets}" >/dev/null 2>&1; then
                log_info "Successfully installed binfmt emulators via /binfmt-check.sh"
            elif $container_engine_cmd run --rm --privileged \
                -v /proc/sys/fs/binfmt_misc:/proc/sys/fs/binfmt_misc \
                "$runtime_image" \
                --install "${install_targets}" >/dev/null 2>&1; then
                log_info "Successfully installed binfmt emulators"
            else
                log_warn "Failed to install binfmt emulators via ${runtime_image} - may already be installed or require manual setup"
            fi
        fi

        # Check supported platforms after installation
        log_info "Platform support status AFTER binfmt installation:"
        ci_check_binfmt_platforms
    }

    if [[ -z "$dind_image" ]]; then
        if [[ "$container_engine" == "docker" ]]; then
            dind_image="docker.io/tonistiigi/binfmt:latest"
        else
            dind_image="quay.io/podman/stable:latest"
        fi
    fi

    if [[ "$container_engine" == "docker" ]]; then
        if ! $container_engine buildx version >/dev/null 2>&1; then
            log_warn "docker buildx not available - fall back to docker build"
            return 0
        fi

        if [[ -z "$platforms" || "$platforms" != *","* ]]; then
            # Single-platform build - just show native platform
            local native_arch=""
            native_arch="$(uname -m 2>/dev/null || echo "unknown")"
            case "$native_arch" in
                x86_64|amd64) native_arch="amd64" ;;
                aarch64|arm64) native_arch="arm64" ;;
                armv7l|armv7|armhf) native_arch="arm" ;;
                ppc64le) native_arch="ppc64le" ;;
                s390x) native_arch="s390x" ;;
            esac
            log_info "Single-platform build - using native platform: linux/${native_arch}"
            return 0
        fi

        # Multi-platform build - install binfmt emulation only
        log_info "Installing binfmt emulation for multi-platform build"
        ci_ensure_binfmt_support "$platforms" "$dind_image"

        log_info "Using native Docker with binfmt for multi-platform build"

        return 0
    fi

    # Podman path - no buildx; rely on podman build with --platform when supported
    return 0
}

# add builder contexts (internal)
ci_add_context(){
    local name="$1" path="$2"
    [[ -z "$name" || -z "$path" ]] && return 0
    [[ "$path" != /* ]] && path="$(realpath -m "$path" 2>/dev/null || echo "$PWD/$path")"
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

    # WHY: Helper function to export build arg as environment variable
    # Exports to both shell env and IBM Cloud Toolchain (set_env) if available
    ci_export_build_arg() {
        local arg_name="$1"
        local arg_value="$2"

        # Export to shell environment
        export "${arg_name}=${arg_value}"

        # Export to IBM Cloud Toolchain if set_env is available
        if command -v set_env >/dev/null 2>&1; then
            set_env "${arg_name}" "${arg_value}" 2>/dev/null || true
        fi

        log_debug "Exported build arg: ${arg_name}=${arg_value}"
    }

    # base args
    # WHY: Use CONFIG[VERSION] from parsed Dockerfile comments, not env var VERSION
    local version_val="${CONFIG[VERSION]:-latest}"
    local -a build_args=("--file" "$dockerfile" "--build-arg" "VERSION=${version_val}")
    ci_export_build_arg "VERSION" "${version_val}"


    local platforms="${CONFIG[PLATFORMS]:-}"
    local image_format="${CONFIG[IMAGE_FORMAT]:-oci}"
    local build_arch=""
    CI_BUILD_ARCHES=()
    [[ -n "$platforms" ]] && build_args+=("--platform" "$platforms")

    # WHY: Add IMAGE_NAME as build arg (commonly used in Dockerfiles)
    local image_name_val="${CONFIG[IMAGE_NAME]:-unnamed}"
    build_args+=("--build-arg" "IMAGE_NAME=${image_name_val}")
    ci_export_build_arg "IMAGE_NAME" "${image_name_val}"

    # WHY: Generate and add TAG as build arg (first tag from strategy)
    local generated_tags
    generated_tags="$(ci_generate_tag)"
    local first_tag
    first_tag=$(echo "$generated_tags" | awk '{print $1}')
    if [[ -n "$first_tag" ]]; then
        build_args+=("--build-arg" "TAG=${first_tag}")
        ci_export_build_arg "TAG" "${first_tag}"
        log_info "Build arg: TAG=${first_tag}"
    fi

    # WHY: Add primary registry (REGISTRY_0) info as build args
    if [[ ${#REGISTRIES[@]} -gt 0 ]]; then
        local primary_reg_entry="${REGISTRIES[0]}"
        IFS=',' read -r primary_reg primary_prefix primary_push <<< "$primary_reg_entry"
        if [[ -n "$primary_reg" ]]; then
            build_args+=("--build-arg" "REGISTRY=${primary_reg}")
            ci_export_build_arg "REGISTRY" "${primary_reg}"
            log_info "Build arg: REGISTRY=${primary_reg}"
        fi
        if [[ -n "$primary_prefix" ]]; then
            build_args+=("--build-arg" "REGISTRY_PREFIX=${primary_prefix}")
            ci_export_build_arg "REGISTRY_PREFIX" "${primary_prefix}"
            log_info "Build arg: REGISTRY_PREFIX=${primary_prefix}"
        fi
    fi

    # WHY: Process BUILD_ARG from CONFIG like "ARG1=ENV1,ARG2=ENV2"
    # Similar to BUILD_SECRETS, but uses --build-arg instead of --secret
    local build_arg_pairs=()
    IFS=',' read -ra build_arg_pairs <<< "${CONFIG[BUILD_ARG]:-}"

    for pair in "${build_arg_pairs[@]:-}"; do
        [[ "$pair" =~ ^([^=]+)=(.+)$ ]] || continue
        local arg_name="${BASH_REMATCH[1]}"
        local env_name="${BASH_REMATCH[2]}"
        local arg_value="${!env_name:-}"

        # WHY: Try get_env if direct env var is empty (IBM Cloud Toolchain support)
        if [[ -z "$arg_value" ]] && command -v get_env >/dev/null 2>&1; then
            arg_value="$(get_env "$env_name" "" 2>/dev/null || true)"
        fi

        if [[ -n "$arg_value" ]]; then
            build_args+=("--build-arg" "${arg_name}=${arg_value}")
            ci_export_build_arg "${arg_name}" "${arg_value}"
            log_info "Build arg: ${arg_name} (from ${env_name})"
        else
            log_warn "Build arg $arg_name env $env_name empty - skipping"
        fi
    done

    # WHY: Auto-detect ARG declarations from Dockerfile and add if env vars exist
    # Similar to auto-detected secrets, but for build args
    for k in "${!CONFIG[@]}"; do
        [[ "$k" =~ ^ARG_ ]] || continue
        local arg_name="${k#ARG_}"

        # Skip if already supplied via BUILD_ARG
        if [[ " ${build_arg_pairs[*]:-} " == *" ${arg_name}="* ]]; then
            log_debug "Build arg $arg_name supplied explicitly - skip auto"
            continue
        fi

        # Skip VERSION, IMAGE_NAME, TAG, REGISTRY, REGISTRY_PREFIX as they're already added
        [[ "$arg_name" == "VERSION" || "$arg_name" == "IMAGE_NAME" || "$arg_name" == "TAG" || "$arg_name" == "REGISTRY" || "$arg_name" == "REGISTRY_PREFIX" ]] && continue

        # Try to get value from env var with same name
        local arg_value="${!arg_name:-}"

        # WHY: Try get_env if direct env var is empty
        if [[ -z "$arg_value" ]] && command -v get_env >/dev/null 2>&1; then
            arg_value="$(get_env "$arg_name" "" 2>/dev/null || true)"
        fi

        if [[ -n "$arg_value" ]]; then
            build_args+=("--build-arg" "${arg_name}=${arg_value}")
            ci_export_build_arg "${arg_name}" "${arg_value}"
            log_info "Build arg (auto): ${arg_name}"
        else
            log_debug "ARG $arg_name detected but no value - skipped"
        fi
    done


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
        build_args+=("--secret" "id=$id,src=$tmp,type=file")
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
        build_args+=("--secret" "id=$id,src=$tmp,type=file")
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

    if [[ -n "$platforms" ]]; then
        IFS=',' read -ra CI_BUILD_ARCHES <<< "$platforms"
        for i in "${!CI_BUILD_ARCHES[@]}"; do
            CI_BUILD_ARCHES[$i]="$(echo "${CI_BUILD_ARCHES[$i]#linux/}" | tr -d ' ')"
        done
    else
        case "$(uname -m 2>/dev/null || echo unknown)" in
            x86_64|amd64) build_arch="amd64" ;;
            aarch64|arm64) build_arch="arm64" ;;
            armv7l|armv7|armhf) build_arch="arm" ;;
            ppc64le) build_arch="ppc64le" ;;
            s390x) build_arch="s390x" ;;
            i386|i686) build_arch="386" ;;
            riscv64) build_arch="riscv64" ;;
            *) build_arch="" ;;
        esac
        [[ -n "$build_arch" ]] && CI_BUILD_ARCHES=("$build_arch")
    fi


    # contexts handling - attempt to use buildx --context if supported
    ci_setup_builder_contexts
    # expand BUILD_CONTEXTS to --context args, but avoid passing them to engines that do not support them:
    if [[ "$engine" == "docker" ]]; then
        # WHY: Multi-platform build with configurable parallelism
        if [[ -n "$platforms" && "$platforms" == *","* ]]; then
            IFS=',' read -ra platform_list <<< "$platforms"
            log_info "Building ${#platform_list[@]} platform(s): ${platform_list[*]}"

            local -a build_pids=()

            # WHY: PARALLEL_PLATFORMS flag controls sequential vs parallel builds
            if [[ "${PARALLEL_PLATFORMS:-true}" == "true" ]]; then
                log_info "Building platforms in parallel"

                # Start all platform builds in parallel
                for plat in "${platform_list[@]}"; do
                    plat="$(echo "$plat" | tr -d ' ')"
                    [[ -z "$plat" ]] && continue

                    log_info "Starting build for platform: $plat"
                    (
                        local arch="${plat##*/}"

                        # Build for specific platform
                        local platform_args=("${build_args[@]}")
                        # Replace --platform with single platform
                        local -a filtered_args=()
                        local skip_next=0
                        for arg in "${platform_args[@]}"; do
                            if [[ $skip_next -eq 1 ]]; then
                                skip_next=0
                                continue
                            fi
                            if [[ "$arg" == "--platform" ]]; then
                                skip_next=1
                                continue
                            fi
                            filtered_args+=("$arg")
                        done
                        filtered_args+=("--platform" "$plat")

                        # Remove --context args
                        local docker_args=()
                        local prev=""
                        for a in "${filtered_args[@]}"; do
                            if [[ "$a" == "--context" ]]; then prev="--context"; continue; fi
                            if [[ "$prev" == "--context" ]]; then prev=""; continue; fi
                            docker_args+=("$a")
                        done

                        # Build image
                        $engine build "${docker_args[@]}" "$context" 2>&1 | grep -vE '^#[0-9]+ (pushing layer|exporting layers|writing image|pushing manifest)' || exit 1

                        # Push and save artifacts
                        local primary_registry=""
                        local primary_prefix=""
                        if [[ ${#REGISTRIES[@]} -gt 0 ]]; then
                            IFS=',' read -r primary_registry primary_prefix _ <<< "${REGISTRIES[0]}"
                        fi

                        for img in "${CI_BUILT_IMAGES[@]}"; do
                            log_info "Pushing $img for platform $plat"
                            $engine push "$img" 2>&1 | grep -vE '^(The push refers to|Preparing|Waiting|Layer already exists|Pushed)' || exit 1

                            local is_primary="false"
                            [[ -n "$primary_registry" && "$img" == "${primary_registry}"* ]] && is_primary="true"

                            log_info "Saving artifact: $img (arch: $arch, primary: $is_primary)"
                            ci_ibmcloud_save_artifact "$img" "$arch" "$is_primary"
                        done
                    ) &
                    build_pids+=($!)
                done
            else
                log_info "Building platforms sequentially"

                # Build platforms one at a time
                for plat in "${platform_list[@]}"; do
                    plat="$(echo "$plat" | tr -d ' ')"
                    [[ -z "$plat" ]] && continue

                    local arch="${plat##*/}"
                    log_info "Building platform: $plat"

                    # Build for specific platform
                    local platform_args=("${build_args[@]}")
                    local -a filtered_args=()
                    local skip_next=0
                    for arg in "${platform_args[@]}"; do
                        if [[ $skip_next -eq 1 ]]; then
                            skip_next=0
                            continue
                        fi
                        if [[ "$arg" == "--platform" ]]; then
                            skip_next=1
                            continue
                        fi
                        filtered_args+=("$arg")
                    done
                    filtered_args+=("--platform" "$plat")

                    # Remove --context args
                    local docker_args=()
                    local prev=""
                    for a in "${filtered_args[@]}"; do
                        if [[ "$a" == "--context" ]]; then prev="--context"; continue; fi
                        if [[ "$prev" == "--context" ]]; then prev=""; continue; fi
                        docker_args+=("$a")
                    done

                    # Build and push
                    $engine build "${docker_args[@]}" "$context" 2>&1 | grep -vE '^#[0-9]+ (pushing layer|exporting layers|writing image|pushing manifest)' || {
                        log_error "Platform build failed: $plat"
                        return 1
                    }

                    local primary_registry=""
                    local primary_prefix=""
                    if [[ ${#REGISTRIES[@]} -gt 0 ]]; then
                        IFS=',' read -r primary_registry primary_prefix _ <<< "${REGISTRIES[0]}"
                    fi

                    for img in "${CI_BUILT_IMAGES[@]}"; do
                        log_info "Pushing $img for platform $plat"
                        $engine push "$img" 2>&1 | grep -vE '^(The push refers to|Preparing|Waiting|Layer already exists|Pushed)' || {
                            log_error "Push failed: $img"
                            return 1
                        }

                        local is_primary="false"
                        [[ -n "$primary_registry" && "$img" == "${primary_registry}"* ]] && is_primary="true"

                        log_info "Saving artifact: $img (arch: $arch, primary: $is_primary)"
                        ci_ibmcloud_save_artifact "$img" "$arch" "$is_primary"
                    done

                    log_success "Platform build completed: $plat"
                done

                # Skip wait logic for sequential builds
                build_pids=()
            fi

            # Wait for parallel builds if any
            if [[ ${#build_pids[@]} -gt 0 ]]; then
                local build_failed=0
                local idx=0
                for pid in "${build_pids[@]}"; do
                    local plat="${platform_list[$idx]}"
                    plat="$(echo "$plat" | tr -d ' ')"

                    if wait "$pid"; then
                        log_success "Platform build completed: $plat"
                    else
                        log_error "Platform build failed: $plat"
                        build_failed=1
                    fi
                    ((idx++))
                done

                [[ $build_failed -eq 1 ]] && return 1
            fi

            log_success "All ${#platform_list[@]} platform builds completed"
        else
            # Single platform build
            local docker_args=()
            local prev=""
            for a in "${build_args[@]}"; do
                if [[ "$a" == "--context" ]]; then prev="--context"; continue; fi
                if [[ "$prev" == "--context" ]]; then prev=""; continue; fi
                docker_args+=("$a")
            done
            log_info "Building single platform image with Docker"
            $engine build "${docker_args[@]}" "$context" 2>&1 | grep -vE '^#[0-9]+ (pushing layer|exporting layers|writing image|pushing manifest)' || return 1

            for img in "${CI_BUILT_IMAGES[@]}"; do
                log_info "Pushing $img"
                $engine push "$img" 2>&1 | grep -vE '^(The push refers to|Preparing|Waiting|Layer already exists|Pushed)' || return 1
            done
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

        # WHY: Add --network=host for Podman to enable network access during build
        podman_args+=("--network=host")

        podman_args+=("--format" "${image_format}")



        # podman supports --platform on a per-build basis, check platforms from CONFIG
        if [[ -n "${platforms:-}" && "${platforms}" == *","* ]]; then
            # WHY: Parallel builds for each platform to save time (podman builds sequentially by default)
            local manifest="${CONFIG[IMAGE_NAME]:-unnamed}:latest"
            podman manifest rm "$manifest" >/dev/null 2>&1 || true
            podman manifest create "$manifest" >/dev/null 2>&1 || true
            # WHY: Control layer build parallelism
            # BUILD_JOBS: layer parallelism (default: auto-detect, capped at 4 for safety)
            local cpu_count
            cpu_count=$(nproc 2>/dev/null || grep -c ^processor /proc/cpuinfo 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo "4")
            local build_jobs="${BUILD_JOBS:-${cpu_count}}"

            # WHY: Cap at 4 for safety (higher values may cause issues)
            if [[ $build_jobs -gt 4 ]]; then
                build_jobs=4
                log_warn "BUILD_JOBS capped at 4 for stability"
            fi

            log_info "Using ${build_jobs} parallel jobs for layer builds (CPUs: ${cpu_count})"

            # WHY: Remove --tag and --platform from manifest_args:
            # --tag is not supported on manifest builds
            # --platform is added per-iteration by the loop below; keeping the
            # comma-separated value here would cause every per-platform build to
            # build all 3 arches instead of just its own.
            local -a manifest_args=()
            local skip_next=0
            for arg in "${podman_args[@]}"; do
                if [[ $skip_next -eq 1 ]]; then
                    skip_next=0
                    continue
                fi
                if [[ "$arg" == "--tag" || "$arg" == "--platform" ]]; then
                    skip_next=1
                    continue
                fi
                manifest_args+=("$arg")
            done

            local -a platform_pids=()
            local -a platform_list=()

            # Split platforms
            IFS=',' read -ra platform_list <<< "${platforms}"
            log_info "Building ${#platform_list[@]} platform(s): ${platform_list[*]}"

            # WHY: PARALLEL_PLATFORMS flag controls sequential vs parallel builds
            # Default: true (parallel) for speed, set to false for stability
            if [[ "${PARALLEL_PLATFORMS:-true}" == "true" ]]; then
                log_info "Building platforms in parallel"

                # Start all platform builds in parallel
                for plat in "${platform_list[@]}"; do
                    log_info "Starting build for platform: $plat"
                    (
                        # WHY: Build with optimizations
                        # --jobs: parallel layer builds
                        # --layers: enable layer caching
                        # --force-rm: cleanup intermediate containers
                        podman build "${manifest_args[@]}" \
                            --platform "$plat" \
                            --manifest "$manifest" \
                            --jobs="${build_jobs}" \
                            --layers=true \
                            --force-rm \
                            "$context" 2>&1 | \
                        grep -vE '^#[0-9]+ (pushing layer|exporting layers|writing image|pushing manifest)'
                        exit ${PIPESTATUS[0]}
                    ) &
                    platform_pids+=($!)
                done
            else
                log_info "Building platforms sequentially"

                # Build platforms one at a time
                for plat in "${platform_list[@]}"; do
                    log_info "Building platform: $plat"
                    podman build "${manifest_args[@]}" \
                        --platform "$plat" \
                        --manifest "$manifest" \
                        --jobs="${build_jobs}" \
                        --layers=true \
                        --force-rm \
                        "$context" 2>&1 | \
                    grep -vE '^#[0-9]+ (pushing layer|exporting layers|writing image|pushing manifest)' || {
                        log_error "Platform build failed: $plat"
                        return 1
                    }
                    log_success "Platform build completed: $plat"
                done

                # Skip wait logic for sequential builds
                platform_pids=()
            fi

            # Wait for all builds and check status
            local build_failed=0
            local idx=0
            for pid in "${platform_pids[@]}"; do
                local plat="${platform_list[$idx]}"

                if wait "$pid"; then
                    log_success "Platform build completed: $plat"
                    platform_status+=("success")
                else
                    log_error "Platform build failed: $plat"
                    platform_status+=("failed")
                    build_failed=1
                fi
                ((idx++))
            done

            if [[ $build_failed -eq 1 ]]; then
                log_error "One or more platform builds failed"
                return 1
            fi

            log_success "All ${#platform_list[@]} platform builds completed successfully"

            # WHY: Push manifest to all tagged images, not just the first one
            local primary_registry=""
            local primary_prefix=""
            if [[ ${#REGISTRIES[@]} -gt 0 ]]; then
                IFS=',' read -r primary_registry primary_prefix _ <<< "${REGISTRIES[0]}"
            fi

            if [[ "${#CI_BUILT_IMAGES[@]}" -gt 0 ]]; then
                for img in "${CI_BUILT_IMAGES[@]}"; do
                    log_info "Pushing manifest to: $img"
                    podman manifest push --format "${image_format}" --all "$manifest" "$img" || log_warn "Failed to push manifest to $img"

                    local is_primary="false"
                    [[ -n "$primary_registry" && "$img" == "${primary_registry}"* ]] && is_primary="true"

                    log_info "Saving artifact: $img (primary: $is_primary, multi-arch podman)"
                    ci_ibmcloud_save_artifact "$img" "" "$is_primary"
                done
            fi
        else
            # WHY: Control layer build parallelism
            log_info "no platforms specified or single platform - building with podman build with native architecture"
            local cpu_count
            cpu_count=$(nproc 2>/dev/null || grep -c ^processor /proc/cpuinfo 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo "4")
            local build_jobs="${BUILD_JOBS:-${cpu_count}}"

            # WHY: Cap at 4 for safety
            if [[ $build_jobs -gt 4 ]]; then
                build_jobs=4
                log_warn "BUILD_JOBS capped at 4 for stability"
            fi

            log_info "Using ${build_jobs} parallel jobs for layer builds (CPUs: ${cpu_count})"

            # WHY: Build single-arch output into a manifest/index too so push flow matches
            # multi-arch behavior and can carry manifest-level attestation metadata.

            podman build "${podman_args[@]}" \
                --jobs="${build_jobs}" \
                --layers=true \
                --force-rm \
                "$context" 2>&1 | grep -vE '^#[0-9]+ (pushing layer|exporting layers|writing image|pushing manifest)' || return 1

            # WHY: Push single-arch image through image path as well
            if [[ "${#CI_BUILT_IMAGES[@]}" -gt 0 ]]; then
                for img in "${CI_BUILT_IMAGES[@]}"; do
                    log_info "Pushing single-arch image to registry: $img"
                    podman push --format "${image_format}" "$img" || { log_error "Failed to push $img"; return 1; }
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
            digest="$($engine inspect --format='{{index .RepoDigests 0}}' "$primary_img" 2>/dev/null | cut -d'@' -f2 || echo "")"
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
    # WHY: Save artifacts for single-platform builds only.
    # Docker multi-platform: saved per-platform inside the build loop above.
    # Podman multi-platform: saved per-image after manifest push above.
    if [[ ${#CI_BUILT_IMAGES[@]} -gt 0 && -n "${CI_BUILT_IMAGES[0]}" ]]; then
        # Only save for single-platform builds (multi-platform saves in their respective sections)
        if [[ -z "$platforms" || "$platforms" != *","* ]]; then

            # WHY: Extract primary registry info
            local primary_registry=""
            local primary_prefix=""
            if [[ ${#REGISTRIES[@]} -gt 0 ]]; then
                IFS=',' read -r primary_registry primary_prefix _ <<< "${REGISTRIES[0]}"
            fi

            for img in "${CI_BUILT_IMAGES[@]}"; do
                local is_primary="false"
                [[ -n "$primary_registry" && "$img" == "${primary_registry}"* ]] && is_primary="true"

                local artifact_arch="${CI_BUILD_ARCHES[0]:-}"
                log_info "Saving artifact: $img (arch: ${artifact_arch:-unknown}, primary: $is_primary)"
                ci_ibmcloud_save_artifact "$img" "$artifact_arch" "$is_primary"
            done
        fi
    fi

    # Cleanup pre-pulled FROM images
    ci_cleanup_pulled_images "$engine" "${pulled_images[@]}"

    CI_LAST_BUILT_IMAGES=("${CI_BUILT_IMAGES[@]}")
    log_success "Built images: ${#CI_BUILT_IMAGES[@]}"
    return 0
}
