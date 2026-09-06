#!/usr/bin/env bash
# Platform execution shared by both build flavours. Configuration/tags/credentials
# remain in ci-build.sh; this module only builds and publishes the selected targets.

ci_native_platform() {
    local arch
    arch="$(uname -m)"
    case "$arch" in
        x86_64) arch=amd64 ;;
        aarch64) arch=arm64 ;;
        armv7l|armhf) arch=arm/v7 ;;
        i386|i686) arch=386 ;;
    esac
    printf 'linux/%s\n' "$arch"
}

ci_normalize_platforms() {
    local value="${1:-}" item arch joined=""
    local -a items=()
    local -A seen=()
    [[ -n "$value" ]] || return 0
    value="${value//,/ }"
    value="${value//$'\n'/ }"
    value="${value//$'\t'/ }"
    read -r -a items <<< "$value"
    for item in "${items[@]}"; do
        arch="${item#linux/}"
        case "$arch" in
            x86_64) arch=amd64 ;;
            aarch64|arm64/v8) arch=arm64 ;;
            amd64|arm64|386|arm/v6|arm/v7|ppc64le|s390x|riscv64) ;;
            *) log_error "Unsupported platform '$item' (expected a Linux OCI platform)"; return 1 ;;
        esac
        [[ -z "${seen[$arch]:-}" ]] || continue
        seen[$arch]=1
        joined+="${joined:+,}linux/$arch"
    done
    [[ -n "$joined" ]] || { log_error 'PLATFORMS is empty after parsing'; return 1; }
    printf '%s\n' "$joined"
}

ci_save_manifest_artifacts() {
    local img primary="" is_primary
    # Standalone consumers may use the engine without the artifact module.
    declare -F ci_ibmcloud_save_artifact >/dev/null || return 0
    if [[ ${#REGISTRIES[@]} -gt 0 ]]; then
        IFS=',' read -r primary _ _ <<< "${REGISTRIES[0]}"
    fi
    for img in "${CI_BUILT_IMAGES[@]}"; do
        is_primary=false
        [[ -n "$primary" && "$img" == "${primary%/}/"* ]] && is_primary=true
        ci_ibmcloud_save_artifact "$img" "" "$is_primary" || return 1
    done
}

ci_build_docker_platforms() {
    local context="$1" platforms="$2"
    shift 2
    local -a args=("$@")
    local img
    if [[ "${CONFIG[CHUNKAH]:-false}" == true ]]; then
        log_error 'chunkah/oci-archive requires Podman; use chunkah: false (portable assembly) for Docker'
        return 1
    fi
    [[ -z "$platforms" ]] || args+=(--platform "$platforms")
    if [[ "$platforms" == *,* ]]; then
        # WHY one buildx invocation: independent `docker build; docker push`
        # calls under the same tag overwrite each other; they do not create an
        # index. Buildx publishes the index only after every target succeeds.
        docker buildx version >/dev/null 2>&1 || {
            log_error 'Docker multi-platform builds require buildx'; return 1;
        }
        local builder="${BUILDX_BUILDER:-docker-build-scripts}"
        if [[ -z "${BUILDX_BUILDER:-}" ]] && ! docker buildx inspect "$builder" >/dev/null 2>&1; then
            docker buildx create --name "$builder" --driver docker-container >/dev/null || return 1
        fi
        args=(--builder "$builder" "${args[@]}")
        if [[ ${#CI_BUILT_IMAGES[@]} -gt 0 ]]; then
            args+=(--push)
        else
            # Classic Docker cannot --load a multi-arch index. Preserve all
            # architectures in an OCI archive instead of silently loading one.
            local output_dir="${BUILD_OUTPUT_DIR:-$context/.ci-output}"
            mkdir -p "$output_dir" || return 1
            output_dir="$(cd "$output_dir" && pwd)"
            CI_IMAGE_ARCHIVE="$output_dir/${CONFIG[IMAGE_NAME]//\//_}.oci.tar"
            args+=(--output "type=oci,dest=$CI_IMAGE_ARCHIVE")
            log_info "Multi-platform build without push: OCI archive $CI_IMAGE_ARCHIVE"
        fi
        docker buildx build "${args[@]}" "$context" || return 1
        ci_save_manifest_artifacts || return 1
    else
        if [[ ${#CI_BUILT_IMAGES[@]} -eq 0 ]]; then
            args+=(--tag "localhost/${CONFIG[IMAGE_NAME]:-unnamed}:${CONFIG[VERSION]:-latest}")
        fi
        # Do not pipe through grep: grep exits 1 for quiet successful commands
        # and can hide a failed build when the caller has not set pipefail.
        docker build "${args[@]}" "$context" || return 1
        for img in "${CI_BUILT_IMAGES[@]}"; do
            docker push "$img" || return 1
        done
    fi
}

ci_podman_platform_build() {
    local context="$1" platform="$2" iidfile="$3"
    shift 3
    local arch="${platform#linux/}" variant=""
    if [[ "$arch" == */* ]]; then
        variant="${arch#*/}"
        arch="${arch%%/*}"
    fi
    # Explicit automatic args also support Podman releases that leave ARG
    # TARGETARCH empty. Never pass the host's architecture for a foreign target.
    podman build "$@" --platform "$platform" \
        --build-arg "TARGETARCH=$arch" --build-arg TARGETOS=linux \
        --build-arg "TARGETVARIANT=$variant" --build-arg "TARGETPLATFORM=$platform" \
        --iidfile "$iidfile" "$context"
}

ci_build_podman_platforms() {
    local context="$1" platforms="$2"
    shift 2
    local -a args=("$@" --network=host --format "${CONFIG[IMAGE_FORMAT]:-oci}" --layers=true --force-rm)
    local -a targets=() pids=() ids=()
    local target id img tmp manifest instance index=0 failed=0
    local parallel="${PARALLEL_PLATFORMS:-true}" jobs="${BUILD_JOBS:-4}"
    [[ "$jobs" =~ ^[1-9][0-9]*$ ]] || { log_error 'BUILD_JOBS must be a positive integer'; return 1; }
    ((jobs <= 4)) || jobs=4
    if [[ "${CONFIG[CHUNKAH]:-false}" == true ]]; then
        # A bind-mounted archive is not a cached layer output. Replaying a RUN
        # for amd64 after arm64 could reuse the wrong archive, even if it still
        # exists. Disable replay and serialize this explicit legacy mode.
        parallel=false
        args+=(--no-cache --skip-unused-stages=false --cap-add=SYS_ADMIN
               -v "$context:/run/src" --security-opt=label=disable)
        # --jobs makes Buildah resolve the not-yet-written oci-archive early.
    else
        args+=("--jobs=$jobs")
    fi
    IFS=',' read -r -a targets <<< "${platforms:-$(ci_native_platform)}"
    tmp="$(mktemp -d)" || return 1
    if [[ ${#targets[@]} -eq 1 ]]; then
        if [[ ${#CI_BUILT_IMAGES[@]} -eq 0 ]]; then
            args+=(--tag "localhost/${CONFIG[IMAGE_NAME]:-unnamed}:${CONFIG[VERSION]:-latest}")
        fi
        if ! ci_podman_platform_build "$context" "${targets[0]}" "$tmp/image.iid" "${args[@]}"; then
            rm -rf "$tmp"; return 1
        fi
        rm -rf "$tmp"
        for img in "${CI_BUILT_IMAGES[@]}"; do
            podman push --format "${CONFIG[IMAGE_FORMAT]:-oci}" "$img" || return 1
        done
        return 0
    fi

    # Each worker gets a private iidfile and NO shared tag/manifest. Assemble
    # the manifest serially after all workers succeed, avoiding update races.
    local -a untagged=()
    local arg skip=0
    for arg in "${args[@]}"; do
        if ((skip)); then skip=0; continue; fi
        if [[ "$arg" == --tag ]]; then skip=1; continue; fi
        untagged+=("$arg")
    done
    for target in "${targets[@]}"; do
        id="$tmp/$index.iid"
        ids+=("$id")
        if [[ "$parallel" == true ]]; then
            ci_podman_platform_build "$context" "$target" "$id" "${untagged[@]}" &
            pids+=("$!")
        elif ! ci_podman_platform_build "$context" "$target" "$id" "${untagged[@]}"; then
            failed=1
            break
        fi
        index=$((index + 1))
    done
    for id in "${pids[@]}"; do
        wait "$id" || failed=1
    done
    if ((failed)); then
        log_error 'One or more platform builds failed; no manifest will be published'
        rm -rf "$tmp"; return 1
    fi
    manifest="localhost/${CONFIG[IMAGE_NAME]:-unnamed}:ci-${BASHPID}-${RANDOM}"
    if ! podman manifest create "$manifest"; then rm -rf "$tmp"; return 1; fi
    index=0
    for id in "${ids[@]}"; do
        instance="$manifest-$index"
        # `manifest add` defaults to the docker:// registry transport. Give
        # each completed local ID a private tag and name containers-storage
        # explicitly; otherwise it can try to pull the ID from a registry.
        if [[ ! -s "$id" ]] || ! podman tag "$(cat "$id")" "$instance" ||
            ! podman manifest add "$manifest" "containers-storage:$instance"; then
            log_error "Could not assemble manifest from $id"
            podman manifest rm "$manifest" >/dev/null 2>&1 || true
            rm -rf "$tmp"; return 1
        fi
        index=$((index + 1))
    done
    rm -rf "$tmp"
    export CI_LOCAL_MANIFEST="$manifest"
    for img in "${CI_BUILT_IMAGES[@]}"; do
        if ! podman manifest push --format "${CONFIG[IMAGE_FORMAT]:-oci}" --all "$manifest" "docker://$img"; then
            log_error "Failed to push manifest to $img"
            return 1
        fi
    done
    ci_save_manifest_artifacts || return 1
    log_info "Local multi-platform manifest: $manifest"
}
