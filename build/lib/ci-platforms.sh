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

# Runtime requirements are inferred from the actual recipe, not from chunkah or
# the selected CPU. Native RPM scriptlets also need the installroot's /proc/dev.
ci_requires_rootfs_mounts() {
    # No grep | grep -q pipeline: an early match gives the upstream process
    # SIGPIPE on larger recipes, making detection fail under pipefail.
    awk '
        /^[[:space:]]*#/ { next }
        /(^|[[:space:]])hb-rootfs[[:space:]]+exec([[:space:]]|$)/ { found=1 }
        END { exit !found }
    ' "$1"
}

ci_require_rootfs_entitlement() {
    [[ "$1" == docker && "${CONFIG[ROOTFS_MOUNTS]:-false}" == true ]] || return 0
    local allowed="${ALLOW_INSECURE_ROOTFS:-false}"
    case "${allowed,,}" in
        true|yes|1|on) return 0 ;;
        *)
            log_error 'Rootfs mounts need explicit ALLOW_INSECURE_ROOTFS=true for Docker security.insecure; otherwise use Podman'
            return 1
            ;;
    esac
}

ci_prepare_buildkit_rootfs_recipe() {
    # Generated macros use ordinary continued RUN instructions. Only those
    # invoking the mount wrapper get the privileged entitlement; compiler and
    # other unrelated stages stay sandboxed. Never edit the caller's file.
    awk '
        BEGIN { print "# syntax=docker/dockerfile:1-labs" }
        function flush() {
            if (block ~ /^[[:space:]]*[Rr][Uu][Nn][[:space:]]/ &&
                block ~ /hb-rootfs[[:space:]]+exec[[:space:]]/) {
                if (block !~ /--security=insecure/) {
                    sub(/^[[:space:]]*[Rr][Uu][Nn][[:space:]]+/, "RUN --security=insecure ", block)
                }
            }
            printf "%s", block
            block=""
        }
        /^[[:space:]]*#[[:space:]]*syntax[[:space:]]*=/ { next }
        { block=block $0 "\n" }
        /\\[[:space:]]*$/ { next }
        { flush() }
        END { if (block != "") flush() }
    ' "$1" > "$2"
}

ci_run_docker_buildx() (
    local -a args=("$@")
    local temp="" file index
    if [[ "${CONFIG[ROOTFS_MOUNTS]:-false}" == true ]]; then
        temp="$(mktemp -d)" || exit 1
        trap 'rm -rf "$temp"' EXIT
        trap 'exit 130' INT
        trap 'exit 143' TERM
        file=""
        for ((index=0; index<${#args[@]}-1; index++)); do
            if [[ "${args[$index]}" == --file ]]; then
                file="${args[$((index+1))]}"
                args[$((index+1))]="$temp/Containerfile"
                break
            fi
        done
        [[ -n "$file" ]] || { log_error 'BuildKit rootfs build needs a --file recipe'; exit 1; }
        ci_prepare_buildkit_rootfs_recipe "$file" "$temp/Containerfile" || exit 1
        if [[ -f "$file.dockerignore" ]]; then
            cp "$file.dockerignore" "$temp/Containerfile.dockerignore" || exit 1
        fi
    fi
    docker buildx build "${args[@]}"
)

ci_build_docker_platforms() {
    local context="$1" platforms="$2"
    shift 2
    local -a args=("$@")
    local img rootfs_mounts="${CONFIG[ROOTFS_MOUNTS]:-false}"
    if [[ "${CONFIG[CHUNKAH]:-false}" == true ]]; then
        log_error 'chunkah/oci-archive requires Podman; use chunkah: false (portable assembly) for Docker'
        return 1
    fi
    [[ -z "$platforms" ]] || args+=(--platform "$platforms")
    if [[ "$platforms" == *,* || "$rootfs_mounts" == true ]]; then
        # One buildx invocation publishes a multi-arch index only after every
        # target succeeds. Mount-enabled single targets also need BuildKit.
        docker buildx version >/dev/null 2>&1 || {
            log_error 'Docker multi-platform/rootfs builds require buildx'; return 1;
        }
        local default_builder=docker-build-scripts
        local -a builder_flags=()
        if [[ "$rootfs_mounts" == true ]]; then
            ci_require_rootfs_entitlement docker || return 1
            default_builder=docker-build-scripts-rootfs
            builder_flags+=(--buildkitd-flags '--allow-insecure-entitlement security.insecure')
            args+=(--allow=security.insecure)
        fi
        local builder="${BUILDX_BUILDER:-$default_builder}"
        if [[ -z "${BUILDX_BUILDER:-}" ]] && ! docker buildx inspect "$builder" >/dev/null 2>&1; then
            docker buildx create --name "$builder" --driver docker-container "${builder_flags[@]}" >/dev/null || return 1
        fi
        args=(--builder "$builder" "${args[@]}")
        if [[ "$platforms" != *,* ]]; then
            args+=(--load)
            if [[ ${#CI_BUILT_IMAGES[@]} -eq 0 ]]; then
                args+=(--tag "localhost/${CONFIG[IMAGE_NAME]:-unnamed}:${CONFIG[VERSION]:-latest}")
            fi
        elif [[ ${#CI_BUILT_IMAGES[@]} -gt 0 ]]; then
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
        ci_run_docker_buildx "${args[@]}" "$context" || return 1
        if [[ "$platforms" == *,* ]]; then
            ci_save_manifest_artifacts || return 1
        else
            for img in "${CI_BUILT_IMAGES[@]}"; do
                docker push "$img" || return 1
            done
        fi
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
    # Mount permissions belong to RPM transactions, not to image assembly.
    # Portable COPY builds need this as much as the optional chunkah mode.
    if [[ "${CONFIG[ROOTFS_MOUNTS]:-false}" == true || "${CONFIG[CHUNKAH]:-false}" == true ]]; then
        args+=(--cap-add=SYS_ADMIN)
    fi
    if [[ "${CONFIG[CHUNKAH]:-false}" == true ]]; then
        # A bind-mounted archive is not a cached layer output. Replaying a RUN
        # for amd64 after arm64 could reuse the wrong archive, even if it still
        # exists. Disable replay and serialize this explicit legacy mode.
        parallel=false
        args+=(--no-cache --skip-unused-stages=false
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
