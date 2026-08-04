#!/usr/bin/env bash
# lib/ci-hummingbird.sh
#
# Purpose:
#   Hummingbird flavor pipeline for the unified image build system.
#   Detects hummingbird image definitions (Containerfile.j2 + properties.yml),
#   reconstructs the hummingbird source tree in a per-build work dir (.hbgen),
#   renders the variant files with the vendored generators, and builds each
#   variant through the shared engine (ci_build_and_push).
#
# Usage:
#   source lib/ci-hummingbird.sh
#
# Functions:
#   ci_hummingbird_detect_flavor <dir>       -> prints 'hummingbird' | 'dockerfile' | ''
#   ci_hummingbird_generate <image_dir>      -> renders variants into <image_dir>/.hbgen
#   ci_hummingbird_variants <image_dir>      -> prints variant names (one per line)
#   ci_hummingbird_configure <image_dir>     -> sets CONFIG for one variant
#   ci_hummingbird_build <image_dir>         -> runs the full hummingbird pipeline
#
# Environment:
#   HUMMINGBIRD_DIR   Override vendored hummingbird/ location (default: build/lib/hummingbird)
#

# Source dependencies
if [[ -z "${CI_CORE_LOADED:-}" ]]; then
    LIB_DIR="${LIB_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
    # shellcheck source=/dev/null
    source "${LIB_DIR}/ci-core.sh"
fi

# Vendored hummingbird machinery (defaults to build/lib/hummingbird)
HUMMINGBIRD_DIR="${HUMMINGBIRD_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/hummingbird" && pwd)}"

# =============================================================================
# ci_hummingbird_detect_flavor
# Purpose:
#   Detect the flavor of an image directory
# Input:
#   $1 - image directory
# Output:
#   Prints 'hummingbird' (Containerfile.j2 + properties.yml),
#   'dockerfile' (Dockerfile), or empty
# =============================================================================
ci_hummingbird_detect_flavor() {
    local dir="${1:?missing image directory}"
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
#   Resolve the hummingbird image directory (Containerfile.j2 + properties.yml)
#   in standard locations with priority order (mirrors find_dockerfile)
# Input:
#   $1 - optional image name (used for pattern matching)
# Output:
#   Prints path to image directory
# Returns:
#   0 if found, 1 if not found
# =============================================================================
ci_hummingbird_find_image() {
    local name="${1:-}"

    search_dir() {
        local d="$1"
        [[ -d "$d" ]] || return 1
        if [[ -f "$d/Containerfile.j2" && -f "$d/properties.yml" ]]; then
            echo "$d"
            return 0
        fi
        return 1
    }

    # Priority 1: BUILDERS_DIR/<name>
    if [[ -n "$BUILDERS_DIR" && -n "$name" ]]; then
        search_dir "$BUILDERS_DIR/$name" && return 0
    fi

    # Priority 2: SOURCE_DIR
    if [[ -n "$SOURCE_DIR" ]]; then
        search_dir "$SOURCE_DIR" && return 0
    fi

    # Priority 3: any image dir under BUILDERS_DIR
    if [[ -n "$BUILDERS_DIR" && -n "$name" ]]; then
        local d
        for d in "$BUILDERS_DIR"/*; do
            [[ "$(basename "$d")" == "$name" ]] || continue
            search_dir "$d" && return 0
        done
    fi

    return 1
}

# =============================================================================
# ci_hummingbird_variants
# Purpose:
#   Resolve the variant list for an image from its properties.json cache
# Input:
#   $1 - image directory (containing .hbgen/.cache/properties.json)
# Output:
#   Prints variant names (one per line)
# =============================================================================
ci_hummingbird_variants() {
    local image_dir="${1:?missing image directory}"
    local cache="${image_dir}/.hbgen/.cache/properties.json"
    [[ -f "${cache}" ]] || { log_error "properties.json not found: ${cache}"; return 1; }

    python3 -c '
import json, sys
cache = json.load(open(sys.argv[1], encoding="utf-8"))
image_name = sys.argv[2]
variants = cache["images"][image_name]["properties"].get("variants", ["default"])
print("\n".join(variants))
' "${cache}" "$(basename "${image_dir}")"
}

# =============================================================================
# ci_hummingbird_generate
# Purpose:
#   Reconstruct the hummingbird source tree in <image_dir>/.hbgen and render
#   all variant files (rpms.in.yaml, VERSION, TAGS, Containerfile, oscap-tailoring).
#   The vendored generators run unmodified against the reconstructed tree,
#   exactly as they do in the containers repo.
# Input:
#   $1 - image directory (must contain properties.yml + Containerfile.j2)
# Output:
#   .hbgen/ work tree with rendered variant files; FROM oci-archive rewritten
#   to an absolute path inside the tree
# Returns:
#   0 on success, non-zero on any generation failure
# =============================================================================
ci_hummingbird_generate() {
    local image_dir="${1:?missing image directory}"
    local image_name
    image_name="$(basename "${image_dir}")"

    local hbgen="${image_dir}/.hbgen"
    rm -rf "${hbgen}"
    mkdir -p "${hbgen}/images/${image_name}/hummingbird" \
             "${hbgen}/ci" \
             "${hbgen}/.cache"

    # Image definition files
    cp "${image_dir}/properties.yml" "${hbgen}/images/${image_name}/properties.yml"
    cp "${image_dir}/Containerfile.j2" "${hbgen}/images/${image_name}/Containerfile.j2"
    cp "${HUMMINGBIRD_DIR}/variables.yml" "${hbgen}/images/variables.yml"

    # Vendored machinery: symlink so scripts stay pure copies
    ln -s "${HUMMINGBIRD_DIR}/macros" "${hbgen}/macros"
    ln -s "${HUMMINGBIRD_DIR}/templates" "${hbgen}/templates"
    ln -s "${HUMMINGBIRD_DIR}/yum-repos" "${hbgen}/yum-repos"
    ln -s "${HUMMINGBIRD_DIR}/get_rpm_versions.sh" "${hbgen}/ci/get_rpm_versions.sh"

    local hbgen_dir="${hbgen}/images/${image_name}"
    local gen
    for gen in aggregate_properties generate_rpms_in generate_jinja2; do
        [[ -x "${HUMMINGBIRD_DIR}/${gen}.py" ]] || chmod +x "${HUMMINGBIRD_DIR}/${gen}.py"
    done

    # 1. Aggregate properties (scans images/*/properties.yml from CWD)
    ( cd "${hbgen}" && python3 "${HUMMINGBIRD_DIR}/aggregate_properties.py" ) || {
        log_error "aggregate_properties.py failed for ${image_name}"
        return 1
    }

    # 2. Generate rpms.in.yaml per variant (get_rpm_versions.sh needs these)
    local variant
    local variants
    variants="$(ci_hummingbird_variants "${image_dir}")" || return 1
    while IFS= read -r variant; do
        [[ -n "${variant}" ]] || continue
        local vdir="${hbgen_dir}/hummingbird/${variant}"
        mkdir -p "${vdir}/rpms"

        ( cd "${hbgen}" && python3 "${HUMMINGBIRD_DIR}/generate_rpms_in.py" \
            "images/${image_name}/hummingbird/${variant}/rpms/rpms.in.yaml" ) || {
            log_error "generate_rpms_in.py failed for ${image_name}/${variant}"
            return 1
        }
    done <<< "${variants}"

    # 3. Resolve RPM versions when any tag uses a package version macro
    if python3 -c '
import json, sys
cache = json.load(open(sys.argv[1], encoding="utf-8"))
tags = cache["images"][sys.argv[2]]["properties"].get("tags", [])
sys.exit(0 if any("package_" in str(t.get("value", "")) for t in tags) else 1)
' "${hbgen}/.cache/properties.json" "${image_name}"; then
        ( cd "${hbgen}" && ci/get_rpm_versions.sh ) || {
            log_error "get_rpm_versions.sh failed for ${image_name}"
            return 1
        }
    fi

    # 4. Render per variant
    while IFS= read -r variant; do
        [[ -n "${variant}" ]] || continue
        local vdir="${hbgen_dir}/hummingbird/${variant}"

        local template
        local rendered
        for template in templates/VERSION.j2 templates/TAGS.j2 templates/oscap-tailoring.xml.j2; do
            case "${template}" in
                *VERSION.j2) rendered="images/${image_name}/hummingbird/${variant}/VERSION" ;;
                *TAGS.j2)    rendered="images/${image_name}/hummingbird/${variant}/TAGS" ;;
                *)           rendered="images/${image_name}/hummingbird/${variant}/oscap-tailoring.xml" ;;
            esac
            ( cd "${hbgen}" && python3 "${HUMMINGBIRD_DIR}/generate_jinja2.py" \
                "${template}" "${rendered}" ) || {
                log_error "generate_jinja2.py failed rendering ${template} for ${image_name}/${variant}"
                return 1
            }
        done

        # 5. Render the Containerfile
        ( cd "${hbgen}" && python3 "${HUMMINGBIRD_DIR}/generate_jinja2.py" \
            "images/${image_name}/Containerfile.j2" \
            "images/${image_name}/hummingbird/${variant}/Containerfile" ) || {
            log_error "Containerfile render failed for ${image_name}/${variant}"
            return 1
        }

        # 6. Rewrite FROM oci-archive to an absolute path inside the work tree
        #    (ci_build_and_push cannot pushd; buildah resolves the archive
        #    relative to CWD). chunkah writes /run/src/out.ociarchive which is
        #    the build context (= hbgen_dir) via the bind mount.
        local containerfile="${vdir}/Containerfile"
        if grep -q '^FROM oci-archive:' "${containerfile}"; then
            sed -i '' "s|^FROM oci-archive:.*|FROM oci-archive:${hbgen_dir}/out.ociarchive|" "${containerfile}"
        fi
        log_info "Rendered hummingbird variant: ${image_name}/${variant}"
    done <<< "${variants}"

    return 0
}

# =============================================================================
# ci_hummingbird_configure
# Purpose:
#   Populate CONFIG for one variant build (image name, version, custom tags,
#   registries, chunkah flag)
# Input:
#   $1 - image directory
#   $2 - variant name
# Returns:
#   0 on success, non-zero when variant files are missing
# =============================================================================
ci_hummingbird_configure() {
    local image_dir="${1:?missing image directory}"
    local variant="${2:?missing variant}"
    local image_base_name
    image_base_name="$(basename "${image_dir}")"

    local vdir="${image_dir}/.hbgen/images/${image_base_name}/hummingbird/${variant}"
    [[ -f "${vdir}/Containerfile" ]] || { log_error "No rendered Containerfile for ${image_base_name}/${variant}"; return 1; }

    # Image name follows the canonical hummingbird convention (-builder suffix)
    if [[ "${variant}" == "builder" ]]; then
        CONFIG[IMAGE_NAME]="${image_base_name}-builder"
    else
        CONFIG[IMAGE_NAME]="${image_base_name}"
    fi
    CONFIG[VARIANT]="${variant}"

    # Version + tags from the rendered files
    CONFIG[VERSION]="$(cat "${vdir}/VERSION" 2>/dev/null || echo latest)"
    local tags_file="${vdir}/TAGS"
    if [[ -f "${tags_file}" ]]; then
        CONFIG[TAG_STRATEGY]="custom"
        mapfile -t tag_list < "${tags_file}"
        CONFIG[CUSTOM_TAGS]="${tag_list[*]}"
    else
        CONFIG[TAG_STRATEGY]="version-latest"
    fi

    # Registries: env override wins, else variables.yml registry
    local registry="${REGISTRY:-}"
    local prefix="${IMAGE_PREFIX:-}"
    if [[ -z "${registry}" ]]; then
        registry="$(grep -m1 '^registry:' "${HUMMINGBIRD_DIR}/variables.yml" | awk '{print $2}')"
        registry="${registry//\"/}"
        registry="${registry//\'/}"
    fi
    CONFIG[DF_REGISTRY_0]="${registry}"
    CONFIG[DF_REGISTRY_0_PREFIX]="${prefix}"
    CONFIG[DF_REGISTRY_0_PUSH]="true"
    [[ "${SKIP_PUSH:-false}" == "true" ]] && CONFIG[DF_REGISTRY_0_PUSH]="false"
    if command -v build_registries_array >/dev/null 2>&1; then
        build_registries_array
    fi

    # Chunkah build: engine applies the workaround flags (Phase 2 hook)
    CONFIG[CHUNKAH]="true"

    log_info "Hummingbird config: image=${CONFIG[IMAGE_NAME]} version=${CONFIG[VERSION]} tags='${CONFIG[CUSTOM_TAGS]:-}' registry=${registry}"
    return 0
}

# =============================================================================
# ci_hummingbird_build
# Purpose:
#   Full hummingbird pipeline: generate, then build every variant
# Input:
#   $1 - image directory (with properties.yml + Containerfile.j2)
# Returns:
#   0 on success, non-zero on first failing step
# =============================================================================
ci_hummingbird_build() {
    local image_dir="${1:?missing image directory}"
    [[ "$(ci_hummingbird_detect_flavor "${image_dir}")" == "hummingbird" ]] || {
        log_error "Not a hummingbird image: ${image_dir}"
        return 1
    }

    ci_hummingbird_generate "${image_dir}" || return 1

    # WHY: ci_build_and_push resets CI_BUILT_IMAGES per variant, so accumulate
    # the images of every variant here for the driver-level post-build loop
    declare -ga HB_BUILT_IMAGES 2>/dev/null || true
    HB_BUILT_IMAGES=()

    local variant
    local variants
    variants="$(ci_hummingbird_variants "${image_dir}")" || return 1
    while IFS= read -r variant; do
        [[ -n "${variant}" ]] || continue
        log_info "=== Building hummingbird variant: ${variant} ==="

        ci_hummingbird_configure "${image_dir}" "${variant}" || return 1

        local vdir image_base
        vdir="${image_dir}/.hbgen/images/$(basename "${image_dir}")/hummingbird/${variant}"
        image_base="$(basename "${image_dir}")"
        ci_build_and_push "${vdir}/Containerfile" "${image_dir}/.hbgen/images/${image_base}" || {
            log_error "Build failed for ${CONFIG[IMAGE_NAME]} (variant: ${variant})"
            return 1
        }
        HB_BUILT_IMAGES+=("${CI_BUILT_IMAGES[@]}")
        log_success "Built hummingbird variant: ${CONFIG[IMAGE_NAME]}"
    done <<< "${variants}"

    return 0
}
