#!/usr/bin/env bash
# lib/ci-hummingbird.sh
#
# Purpose:
#   Hummingbird flavour of the unified image build system.
#
#   A hummingbird builder is a directory holding `properties.yml` (what the image
#   is) and `Containerfile.j2` (how it is built). One definition fans out into a
#   matrix of distro x variant images. This module reconstructs the upstream
#   hummingbird work tree in `<builder>/.hbgen`, renders the matrix with the
#   vendored generators, and builds every row through the shared engine
#   (ci_build_and_push).
#
# Usage:
#   source lib/ci-hummingbird.sh
#
# Public functions:
#   ci_hummingbird_detect_flavor <dir>        -> 'hummingbird' | 'dockerfile' | ''
#   ci_hummingbird_find_image [name]          -> builder directory path
#   ci_hummingbird_distros <builder_dir>      -> distro names (one per line)
#   ci_hummingbird_variants <builder_dir>     -> variant names (one per line)
#   ci_hummingbird_matrix <builder_dir>       -> "<distro>\t<variant>\t<image>" rows
#   ci_hummingbird_generate <builder_dir>     -> renders the whole matrix in .hbgen
#   ci_hummingbird_configure <dir> <d> <v>    -> fills CONFIG for one row
#   ci_hummingbird_build <builder_dir>        -> runs the full pipeline
#
# Path helpers (used by every function, so the layout is written down once):
#   ci_hummingbird_worktree <builder_dir>      -> <builder_dir>/.hbgen
#   ci_hummingbird_context  <builder_dir>      -> .hbgen/images/<image>  (build context)
#   ci_hummingbird_variant_dir <dir> <d> <v>   -> .hbgen/images/<image>/<d>/<v>
#
# Environment:
#   HB_DISTROS             Distros to build, comma/space separated ("ubi9",
#                          "hummingbird ubi9"). Default: properties.yml
#                          `distros:` > variables.yml `default_distros` > hummingbird.
#   HB_VARIANTS            Variants to build, comma/space separated. Default: the
#                          aggregated variant list (variants + additional_variants).
#   HB_VERSION             Override the version resolved from the package repos.
#   HB_TAGS                Override the generated tag list (space separated).
#   HB_REGISTRIES          Comma separated registries (overrides variables.yml).
#   HB_SKIP_RPM_VERSIONS   'true' skips the dnf repoquery stage (offline renders,
#                          or images that carry rpms/rpms.lock.yaml).
#   HB_RPM_VERSIONS_TTL    Reuse .cache/rpm-versions.yml younger than N seconds.
#   HB_PYTHON              Python interpreter for the generators (default: python3).
#   HUMMINGBIRD_DIR        Vendored machinery (default: build/lib/hummingbird).
#   SKIP_PUSH / PLATFORMS / REGISTRY / IMAGE_PREFIX / SOURCE_DATE_EPOCH
#                          Shared engine overrides; see ci_hummingbird_configure.
#
# Design note:
#   All YAML/JSON handling lives in hbgen.py — one Python entry point with one
#   subcommand per pipeline stage. Bash owns orchestration, logging and the
#   container engine. That split is why this file has no inline Python and why
#   every stage can be re-run by hand when debugging a build.
#

# Source dependencies
if [[ -z "${CI_CORE_LOADED:-}" ]]; then
    LIB_DIR="${LIB_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
    # shellcheck source=/dev/null
    source "${LIB_DIR}/ci-core.sh"
fi

# Vendored hummingbird machinery (generators, macros, templates, yum repos).
HUMMINGBIRD_DIR="${HUMMINGBIRD_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/hummingbird" && pwd)}"

# Name of the generated work tree inside a builder directory (gitignored).
HB_WORK_TREE=".hbgen"

# =============================================================================
# Path helpers
# =============================================================================

# ci_hummingbird_worktree <builder_dir> -> <builder_dir>/.hbgen
ci_hummingbird_worktree() {
    printf '%s/%s\n' "${1%/}" "${HB_WORK_TREE}"
}

# ci_hummingbird_context <builder_dir> -> the build context of every variant
ci_hummingbird_context() {
    local builder_dir="${1:?missing builder directory}"
    printf '%s/images/%s\n' "$(ci_hummingbird_worktree "${builder_dir}")" "$(basename "${builder_dir}")"
}

# ci_hummingbird_variant_dir <builder_dir> <distro> <variant>
ci_hummingbird_variant_dir() {
    local builder_dir="${1:?missing builder directory}"
    printf '%s/%s/%s\n' "$(ci_hummingbird_context "${builder_dir}")" "${2:?missing distro}" "${3:?missing variant}"
}

# =============================================================================
# ci_hummingbird_python
# Purpose:
#   Run one vendored generator. Centralises the interpreter choice so a venv or
#   a pinned python can be used without touching every call site.
# Input:
#   $1 - script name inside HUMMINGBIRD_DIR; rest passed through
# =============================================================================
ci_hummingbird_python() {
    local script="${1:?missing generator script}"
    shift
    "${HB_PYTHON:-python3}" "${HUMMINGBIRD_DIR}/${script}" "$@"
}

# =============================================================================
# ci_hummingbird_detect_flavor
# Purpose:
#   Classify a directory so the driver can pick the hummingbird or the plain
#   Dockerfile pipeline.
# Input:
#   $1 - directory
# Output:
#   'hummingbird' (Containerfile.j2 + properties.yml), 'dockerfile' (Dockerfile),
#   or '' when neither
# =============================================================================
ci_hummingbird_detect_flavor() {
    local dir="${1:-}"
    [[ -n "${dir}" && -d "${dir}" ]] || { echo ""; return 0; }

    if [[ -f "${dir}/Containerfile.j2" && -f "${dir}/properties.yml" ]]; then
        echo "hummingbird"
    elif [[ -f "${dir}/Dockerfile" ]]; then
        echo "dockerfile"
    else
        echo ""
    fi
}

# =============================================================================
# ci_hummingbird_find_image
# Purpose:
#   Locate a hummingbird builder directory. Search order:
#     1. BUILDERS_DIR/<name>   (the builders repo layout)
#     2. SOURCE_DIR            (the checked-out source repo is the builder)
# Input:
#   $1 - optional image/builder name
# Output:
#   Prints the builder directory
# Returns:
#   0 when found, 1 otherwise
# =============================================================================
ci_hummingbird_find_image() {
    local name="${1:-}"
    local candidate

    if [[ -n "${name}" && -n "${BUILDERS_DIR:-}" ]]; then
        candidate="${BUILDERS_DIR%/}/${name}"
        if [[ "$(ci_hummingbird_detect_flavor "${candidate}")" == "hummingbird" ]]; then
            echo "${candidate}"
            return 0
        fi
    fi

    if [[ -n "${SOURCE_DIR:-}" ]]; then
        candidate="${SOURCE_DIR}"
        if [[ "$(ci_hummingbird_detect_flavor "${candidate}")" == "hummingbird" ]]; then
            echo "${candidate}"
            return 0
        fi
    fi

    return 1
}

# =============================================================================
# ci_hummingbird_require_builder
# Purpose:
#   Validate the builder directory before any work happens.
#   WHY a function and not `${1:?...}`: an unset-parameter expansion inside a
#   sourced function terminates the caller's shell, which would kill the CI job
#   instead of returning an error the driver can report.
# Input:
#   $1 - builder directory
# Output:
#   Prints the validated directory
# Returns:
#   0 when usable, 1 with an explanatory error otherwise
# =============================================================================
ci_hummingbird_require_builder() {
    local dir="${1:-}"
    if [[ -z "${dir}" ]]; then
        log_error "No hummingbird builder directory given (pass -i <name>, or set SOURCE_DIR to a directory holding properties.yml + Containerfile.j2)"
        return 1
    fi
    if [[ ! -d "${dir}" ]]; then
        log_error "Builder directory not found: ${dir}"
        return 1
    fi
    if [[ "$(ci_hummingbird_detect_flavor "${dir}")" != "hummingbird" ]]; then
        log_error "Not a hummingbird builder: ${dir} (needs properties.yml + Containerfile.j2)"
        return 1
    fi
    echo "${dir}"
}

# =============================================================================
# ci_hummingbird_distros
# Purpose:
#   Print the distros that would be built, without generating anything.
#   HB_DISTROS wins; otherwise properties.yml `distros:` > variables.yml
#   `default_distros` > 'hummingbird'.
# Input:
#   $1 - builder directory
# Output:
#   Distro names, one per line
# =============================================================================
ci_hummingbird_distros() {
    local builder_dir
    builder_dir="$(ci_hummingbird_require_builder "${1:-}")" || return 1

    local -a args=(distros --image-dir "${builder_dir}")
    [[ -n "${BUILDERS_DIR:-}" ]] && args+=(--builders-dir "${BUILDERS_DIR}")
    [[ -n "${HB_DISTROS:-}" ]] && args+=(--requested "${HB_DISTROS}")

    ci_hummingbird_python hbgen.py "${args[@]}"
}

# =============================================================================
# ci_hummingbird_variants
# Purpose:
#   Print the aggregated variant list (properties.yml `variants` plus
#   `additional_variants`). Requires .hbgen to exist — run generate first.
# Input:
#   $1 - builder directory
# Output:
#   Variant names, one per line
# =============================================================================
ci_hummingbird_variants() {
    local builder_dir
    builder_dir="$(ci_hummingbird_require_builder "${1:-}")" || return 1

    local -a args=(variants --hbgen "$(ci_hummingbird_worktree "${builder_dir}")" --image "$(basename "${builder_dir}")")
    [[ -n "${HB_VARIANTS:-}" ]] && args+=(--variants "${HB_VARIANTS}")

    ci_hummingbird_python hbgen.py "${args[@]}"
}

# =============================================================================
# ci_hummingbird_matrix
# Purpose:
#   Print the rows to build: "<distro>\t<variant>\t<image-name>" per line.
#   This is the single place that decides WHAT is built:
#     - distro selection  (HB_DISTROS / properties.yml / variables.yml)
#     - variant selection (HB_VARIANTS / aggregated list, validated)
#     - per-variant distro restrictions from additional_variants
#     - the published image name (hb_variant.resolve_image_name)
# Input:
#   $1 - builder directory
# Output:
#   One TAB-separated row per build
# =============================================================================
ci_hummingbird_matrix() {
    local builder_dir
    builder_dir="$(ci_hummingbird_require_builder "${1:-}")" || return 1

    local -a args=(matrix
        --hbgen "$(ci_hummingbird_worktree "${builder_dir}")"
        --image "$(basename "${builder_dir}")")
    [[ -n "${HB_DISTROS:-}" ]] && args+=(--distros "${HB_DISTROS}")
    [[ -n "${HB_VARIANTS:-}" ]] && args+=(--variants "${HB_VARIANTS}")

    ci_hummingbird_python hbgen.py "${args[@]}"
}

# =============================================================================
# ci_hummingbird_generate
# Purpose:
#   Render the whole matrix into <builder_dir>/.hbgen.
#
#   Stages (each one is a separate command so it can be re-run while debugging):
#     1. hbgen.py prepare             work tree, merged variables.yml, context
#     2. aggregate_properties.py      .cache/properties.json (variant matrix)
#     3. hbgen.py rpms                rpms.in.yaml per distro/variant
#     4. ci/get_rpm_versions.sh       .cache/rpm-versions.yml (needs an engine)
#     5. hbgen.py render              VERSION, TAGS, tailoring, Containerfile
#
# Input:
#   $1 - builder directory
# Returns:
#   0 on success, non-zero on the first failing stage
# =============================================================================
ci_hummingbird_generate() {
    local builder_dir
    builder_dir="$(ci_hummingbird_require_builder "${1:-}")" || return 1

    local image_name work_tree
    image_name="$(basename "${builder_dir}")"
    work_tree="$(ci_hummingbird_worktree "${builder_dir}")"

    local -a selection=()
    [[ -n "${HB_DISTROS:-}" ]] && selection+=(--distros "${HB_DISTROS}")
    [[ -n "${HB_VARIANTS:-}" ]] && selection+=(--variants "${HB_VARIANTS}")

    # 1. Work tree (also resolves and logs the distro selection)
    local -a prepare_args=(prepare
        --image-dir "${builder_dir}"
        --hbgen "${work_tree}"
        --image "${image_name}")
    [[ -n "${BUILDERS_DIR:-}" ]] && prepare_args+=(--builders-dir "${BUILDERS_DIR}")
    [[ -n "${HB_DISTROS:-}" ]] && prepare_args+=(--distros "${HB_DISTROS}")
    ci_hummingbird_python hbgen.py "${prepare_args[@]}" >/dev/null || {
        log_error "hummingbird prepare failed for ${image_name}"
        return 1
    }

    # 2. Aggregate properties: the authoritative variant list lives in its cache
    ( cd "${work_tree}" && ci_hummingbird_python aggregate_properties.py ) || {
        log_error "aggregate_properties.py failed for ${image_name}"
        return 1
    }

    # 3. rpms.in.yaml for every matrix row
    ci_hummingbird_python hbgen.py rpms --hbgen "${work_tree}" --image "${image_name}" \
        "${selection[@]}" >/dev/null || {
        log_error "generate_rpms_in failed for ${image_name}"
        return 1
    }

    # 4. Package versions from each distro's repositories
    ci_hummingbird_resolve_rpm_versions "${builder_dir}" || return 1

    # 5. Render the per-variant files
    ci_hummingbird_python hbgen.py render --hbgen "${work_tree}" --image "${image_name}" \
        "${selection[@]}" >/dev/null || {
        log_error "render failed for ${image_name}"
        return 1
    }

    log_info "Generated hummingbird work tree: ${work_tree}"
    return 0
}

# =============================================================================
# ci_hummingbird_resolve_rpm_versions
# Purpose:
#   Stage 4 of generation: resolve package versions with `dnf repoquery` inside
#   the builder image, so VERSION/TAGS carry real versions instead of "unknown".
#   Skippable, because it is the only stage that needs a container engine and
#   network access to the package repositories.
# Input:
#   $1 - builder directory
# Environment:
#   HB_SKIP_RPM_VERSIONS  'true' skips the stage entirely
#   HB_RPM_VERSIONS_TTL   reuse a cache younger than N seconds (handled by the
#                         vendored script)
# =============================================================================
ci_hummingbird_resolve_rpm_versions() {
    local builder_dir="${1:?missing builder directory}"
    local work_tree image_name
    work_tree="$(ci_hummingbird_worktree "${builder_dir}")"
    image_name="$(basename "${builder_dir}")"

    if [[ "${HB_SKIP_RPM_VERSIONS:-false}" == "true" ]]; then
        log_warn "HB_SKIP_RPM_VERSIONS=true: skipping package version resolution; VERSION/TAGS fall back to 'latest' unless rpms.lock.yaml or HB_VERSION/HB_TAGS are provided"
        return 0
    fi

    # WHY export: the vendored script defaults to podman; the driver already
    # detected which engine this host has.
    local engine
    engine="$(detect_container_engine 2>/dev/null || echo docker)"

    ( cd "${work_tree}" && CONTAINER_ENGINE="${engine}" ci/get_rpm_versions.sh ) || {
        log_error "get_rpm_versions.sh failed for ${image_name} (engine: ${engine}); set HB_SKIP_RPM_VERSIONS=true to render without package versions"
        return 1
    }
    return 0
}

# =============================================================================
# ci_hummingbird_reset_config
# Purpose:
#   Drop the CONFIG keys this module owns before filling them again.
#   WHY: CONFIG is a process-wide associative array reused for every row of the
#   matrix. build_registries_array walks DF_REGISTRY_0, _1, _2 ... until it finds
#   a gap, so a row with fewer registries than the previous one would silently
#   inherit (and push to) the leftover entries. Same for PLATFORMS and
#   CUSTOM_TAGS.
# =============================================================================
ci_hummingbird_reset_config() {
    local key
    for key in "${!CONFIG[@]}"; do
        case "${key}" in
            DF_REGISTRY_*|CUSTOM_TAGS|PLATFORMS|CHUNKAH|VARIANT|DISTRO|TAG_STRATEGY)
                unset "CONFIG[${key}]"
                ;;
        esac
    done
}

# =============================================================================
# ci_hummingbird_configure
# Purpose:
#   Fill CONFIG for one matrix row. hbgen.py resolves every value and its
#   precedence (documented in hbgen.py:cmd_config); this function only maps the
#   result onto the shared engine's CONFIG keys.
# Input:
#   $1 - builder directory
#   $2 - distro
#   $3 - variant
# Returns:
#   0 on success, non-zero when the row was not rendered or config failed
# =============================================================================
ci_hummingbird_configure() {
    local builder_dir distro variant
    builder_dir="$(ci_hummingbird_require_builder "${1:-}")" || return 1
    distro="${2:-}"
    variant="${3:-}"
    if [[ -z "${distro}" || -z "${variant}" ]]; then
        log_error "ci_hummingbird_configure needs a distro and a variant"
        return 1
    fi

    local variant_dir
    variant_dir="$(ci_hummingbird_variant_dir "${builder_dir}" "${distro}" "${variant}")"
    if [[ ! -f "${variant_dir}/Containerfile" ]]; then
        log_error "No rendered Containerfile for $(basename "${builder_dir}")/${distro}/${variant} (run ci_hummingbird_generate first)"
        return 1
    fi

    # Read hbgen's TAB-separated key/value output into a local map. TAB (not
    # shell quoting) keeps this free of eval: values are copied verbatim.
    local -a config_args=(config
        --hbgen "$(ci_hummingbird_worktree "${builder_dir}")"
        --image "$(basename "${builder_dir}")"
        --distro "${distro}"
        --variant "${variant}"
        --image-dir "${builder_dir}")

    local -a lines=()
    mapfile -t lines < <(ci_hummingbird_python hbgen.py "${config_args[@]}")
    if [[ ${#lines[@]} -eq 0 ]]; then
        log_error "hbgen.py config produced no output for ${distro}/${variant}"
        return 1
    fi

    local -A hb=()
    local line key value
    for line in "${lines[@]}"; do
        [[ -n "${line}" ]] || continue
        key="${line%%$'\t'*}"
        value="${line#*$'\t'}"
        hb["${key}"]="${value}"
    done

    ci_hummingbird_reset_config

    CONFIG[IMAGE_NAME]="${hb[HBGEN_IMAGE_NAME]}"
    CONFIG[DISTRO]="${hb[HBGEN_DISTRO]}"
    CONFIG[VARIANT]="${hb[HBGEN_VARIANT]}"
    CONFIG[VERSION]="${hb[HBGEN_VERSION]}"
    CONFIG[TAG_STRATEGY]="${hb[HBGEN_TAG_STRATEGY]}"
    [[ -n "${hb[HBGEN_TAGS]}" ]] && CONFIG[CUSTOM_TAGS]="${hb[HBGEN_TAGS]}"
    CONFIG[CHUNKAH]="${hb[HBGEN_CHUNKAH]}"
    [[ -n "${hb[HBGEN_PLATFORMS]}" ]] && CONFIG[PLATFORMS]="${hb[HBGEN_PLATFORMS]}"

    # Registries -> the DF_REGISTRY_* keys the shared engine understands
    local i registry_count entry reg prefix push
    registry_count="${hb[HBGEN_REGISTRY_COUNT]:-0}"
    for ((i = 0; i < registry_count; i++)); do
        entry="${hb[HBGEN_REGISTRY_${i}]:-}"
        [[ -n "${entry}" ]] || continue
        IFS='|' read -r reg prefix push <<< "${entry}"
        CONFIG[DF_REGISTRY_${i}]="${reg}"
        CONFIG[DF_REGISTRY_${i}_PREFIX]="${prefix}"
        CONFIG[DF_REGISTRY_${i}_PUSH]="${push:-true}"
    done

    # WHY checked explicitly: build_registries_array lives in ci-config.sh. If it
    # is missing and the call is skipped silently, REGISTRIES stays empty and the
    # engine falls back to its own default registry — pushing to the wrong place
    # instead of failing.
    if ! command -v build_registries_array >/dev/null 2>&1; then
        log_error "build_registries_array not found: source lib/ci-config.sh before running the hummingbird pipeline"
        return 1
    fi
    build_registries_array

    # Reproducible builds: the rendered Containerfile declares
    # ARG SOURCE_DATE_EPOCH and the engine passes CONFIG[ARG_*] from the
    # environment, so the value has to be exported, not only stored.
    export SOURCE_DATE_EPOCH="${hb[HBGEN_SOURCE_DATE_EPOCH]}"
    CONFIG[ARG_SOURCE_DATE_EPOCH]="present"

    log_info "Hummingbird config: image=${CONFIG[IMAGE_NAME]} distro=${distro} variant=${variant} version=${CONFIG[VERSION]} tags='${CONFIG[CUSTOM_TAGS]:-}' registries=${registry_count} platforms=${CONFIG[PLATFORMS]:-native} skip_push=${hb[HBGEN_SKIP_PUSH]} chunkah=${CONFIG[CHUNKAH]}"
    return 0
}

# =============================================================================
# ci_hummingbird_cleanup_archives
# Purpose:
#   Remove the chunkah rootfs archives left in the build context.
#   WHY here and not per build: the final stage reads
#   `FROM oci-archive:out.ociarchive` from the build context. When the engine
#   replays that RUN from its layer cache the archive is not rewritten, so
#   deleting it after every single build would break the next one with
#   "archive file not found". Deleting once, after the last row, reclaims the
#   disk without that hazard.
# Input:
#   $1 - build context directory
# =============================================================================
ci_hummingbird_cleanup_archives() {
    local context="${1:-}"
    [[ -n "${context}" && -d "${context}" ]] || return 0

    local archive removed=0
    for archive in "${context}"/out*.ociarchive; do
        [[ -e "${archive}" ]] || continue
        rm -f -- "${archive}" && removed=$((removed + 1))
    done
    if ((removed > 0)); then
        log_info "Removed ${removed} chunkah archive(s) from ${context}"
    fi
    return 0
}

# =============================================================================
# ci_hummingbird_build
# Purpose:
#   Run the full hummingbird pipeline for one builder directory:
#   generate -> resolve matrix -> configure + build each row.
# Input:
#   $1 - builder directory
# Output:
#   HB_BUILT_IMAGES (global array) accumulates every image reference built, for
#   the driver's post-build cleanup. WHY accumulated: ci_build_and_push resets
#   CI_BUILT_IMAGES on every call, i.e. once per matrix row.
# Returns:
#   0 on success, non-zero on the first failing row
# =============================================================================
ci_hummingbird_build() {
    local builder_dir
    builder_dir="$(ci_hummingbird_require_builder "${1:-}")" || return 1

    declare -ga HB_BUILT_IMAGES 2>/dev/null || true
    HB_BUILT_IMAGES=()

    ci_hummingbird_generate "${builder_dir}" || return 1

    # Read the matrix into an array. WHY not `while read`: the loop body calls
    # the build engine, and any command in it that reads stdin would consume the
    # remaining rows — silently building only part of the matrix.
    local -a rows=()
    mapfile -t rows < <(ci_hummingbird_matrix "${builder_dir}") || {
        log_error "Failed to resolve the build matrix for $(basename "${builder_dir}")"
        return 1
    }
    if [[ ${#rows[@]} -eq 0 ]]; then
        log_error "Empty build matrix for $(basename "${builder_dir}"): nothing to build"
        return 1
    fi

    if ! command -v ci_build_and_push >/dev/null 2>&1; then
        log_error "ci_build_and_push not found: source lib/ci-build.sh before running the hummingbird pipeline"
        return 1
    fi

    local context image_name
    image_name="$(basename "${builder_dir}")"
    context="$(ci_hummingbird_context "${builder_dir}")"
    log_info "Building ${#rows[@]} hummingbird row(s) for ${image_name}"

    local row distro variant row_image variant_dir
    for row in "${rows[@]}"; do
        [[ -n "${row}" ]] || continue
        IFS=$'\t' read -r distro variant row_image <<< "${row}"

        log_info "=== Building hummingbird image: ${distro}/${variant} -> ${row_image} ==="

        ci_hummingbird_configure "${builder_dir}" "${distro}" "${variant}" || return 1

        variant_dir="$(ci_hummingbird_variant_dir "${builder_dir}" "${distro}" "${variant}")"
        ci_build_and_push "${variant_dir}/Containerfile" "${context}" || {
            log_error "Build failed for ${CONFIG[IMAGE_NAME]} (distro: ${distro}, variant: ${variant})"
            return 1
        }

        if [[ ${#CI_BUILT_IMAGES[@]} -gt 0 ]]; then
            HB_BUILT_IMAGES+=("${CI_BUILT_IMAGES[@]}")
        fi
        log_success "Built hummingbird image: ${CONFIG[IMAGE_NAME]} (${distro}/${variant})"
    done

    ci_hummingbird_cleanup_archives "${context}"
    return 0
}
