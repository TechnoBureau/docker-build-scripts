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
    # Copy .gitmodules for source-build templates that reference submodule paths
    [[ -f "${image_dir}/.gitmodules" ]] && \
        cp "${image_dir}/.gitmodules" "${hbgen}/images/${image_name}/.gitmodules"
    # variables.yml is configuration and lives in the builders repo, not in
    # the code repo. Base: <BUILDERS_DIR>/variables.yml (shared defaults for
    # all builders), overridden by <image_dir>/variables.yml (per-image
    # additional/override values). At least one of the two must exist.
    local repo_vars=""
    if [[ -n "${BUILDERS_DIR:-}" ]]; then
        repo_vars="${BUILDERS_DIR}/variables.yml"
    fi
    local builder_vars="${image_dir}/variables.yml"
    local vars_base=""
    if [[ -f "${repo_vars}" ]]; then
        vars_base="${repo_vars}"
    elif [[ -f "${builder_vars}" ]]; then
        vars_base="${builder_vars}"
    else
        log_error "No variables.yml for ${image_name}: create ${builder_vars} (per-image overrides) or ${repo_vars:-<builders>/variables.yml} (shared defaults)"
        return 1
    fi
    cp "${vars_base}" "${hbgen}/images/variables.yml"
    if [[ -f "${builder_vars}" && "${builder_vars}" != "${vars_base}" ]]; then
        python3 - "${vars_base}" "${builder_vars}" "${hbgen}/images/variables.yml" <<'PY'
import sys, yaml

base_file, overlay_file, out_file = sys.argv[1], sys.argv[2], sys.argv[3]
base = yaml.safe_load(open(base_file, encoding="utf-8")) or {}
overlay = yaml.safe_load(open(overlay_file, encoding="utf-8")) or {}

def merge(dst, src):
    for key, value in src.items():
        if isinstance(value, dict) and isinstance(dst.get(key), dict):
            merge(dst[key], value)
        else:
            dst[key] = value
    return dst

with open(out_file, "w", encoding="utf-8") as f:
    yaml.safe_dump(merge(base, overlay), f, sort_keys=False, allow_unicode=True)
PY
        rc=$?
        if [[ ${rc} -ne 0 ]]; then
            log_error "variables.yml merge failed for ${image_name}"
            return 1
        fi
    fi

    # Vendored machinery: symlink so scripts stay pure copies
    ln -s "${HUMMINGBIRD_DIR}/macros" "${hbgen}/macros"
    ln -s "${HUMMINGBIRD_DIR}/templates" "${hbgen}/templates"
    ln -s "${HUMMINGBIRD_DIR}/yum-repos" "${hbgen}/yum-repos"
    ln -s "${HUMMINGBIRD_DIR}/get_rpm_versions.sh" "${hbgen}/ci/get_rpm_versions.sh"

    local hbgen_dir="${hbgen}/images/${image_name}"

    # Extra build-context files (rootfs for config/scripts, src for source
    # builds) land in the hbgen image tree, which is the build context.
    # prebuildfs is the shared library set vendored alongside the machinery;
    # it is copied only when the image builder references it.
    local extra
    for extra in rootfs src prebuildfs; do
        if [[ -d "${image_dir}/${extra}" ]]; then
            cp -R "${image_dir}/${extra}" "${hbgen_dir}"
        elif [[ "${extra}" == "prebuildfs" && -d "${HUMMINGBIRD_DIR}/prebuildfs" ]]; then
            cp -R "${HUMMINGBIRD_DIR}/prebuildfs" "${hbgen_dir}"
        fi
    done

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

    # 3. Resolve RPM versions (needed for the VERSION file and any tag using
    # a package version macro; always resolved so latest-only images get a
    # meaningful version)
    # WHY: Export CONTAINER_ENGINE so get_rpm_versions.sh uses the detected
    # engine (podman or docker) rather than falling back to a hardcoded default.
    local _rpm_engine
    _rpm_engine="$(detect_container_engine 2>/dev/null || echo docker)"
    ( cd "${hbgen}" && CONTAINER_ENGINE="${_rpm_engine}" ci/get_rpm_versions.sh ) || {
        log_error "get_rpm_versions.sh failed for ${image_name}"
        return 1
    }

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
        #    WHY: Use portable sed -i.bak + rm to support both GNU sed (Linux)
        #    and BSD sed (macOS); 'sed -i ""' works only on macOS.
        local containerfile="${vdir}/Containerfile"
        if grep -q '^FROM oci-archive:' "${containerfile}"; then
            sed -i.bak "s|^FROM oci-archive:.*|FROM oci-archive:${hbgen_dir}/out.ociarchive|" "${containerfile}"
            rm -f "${containerfile}.bak"
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
    # HB_VERSION overrides the auto-detected package version
    CONFIG[VERSION]="${HB_VERSION:-${CONFIG[VERSION]}}"
    local tags_file="${vdir}/TAGS"
    if [[ -f "${tags_file}" ]]; then
        CONFIG[TAG_STRATEGY]="custom"
        mapfile -t tag_list < "${tags_file}"
        CONFIG[CUSTOM_TAGS]="${tag_list[*]}"
    else
        CONFIG[TAG_STRATEGY]="version-latest"
    fi
    # HB_TAGS overrides the auto-generated tag list (space-separated, e.g.
    # "latest 8.21.0" or "8.21.0" to skip the moving tags)
    if [[ -n "${HB_TAGS:-}" ]]; then
        CONFIG[TAG_STRATEGY]="custom"
        CONFIG[CUSTOM_TAGS]="${HB_TAGS}"
    fi

    # Merged variables (shared builders/variables.yml deep-merged with the
    # per-image overrides during generate; the single variables.yml source)
    local merged_vars="${image_dir}/.hbgen/images/variables.yml"
    [[ -f "${merged_vars}" ]] || merged_vars="${image_dir}/variables.yml"

    # Global push control: env SKIP_PUSH wins, else variables.yml skip_push
    local skip_push="false"
    if [[ "${SKIP_PUSH:-false}" == "true" ]]; then
        skip_push="true"
    else
        skip_push="$(python3 - "${merged_vars}" <<'PY'
import sys, yaml

data = yaml.safe_load(open(sys.argv[1], encoding="utf-8")) or {}
print("true" if data.get("skip_push") else "false")
PY
)"
    fi

    # Registries (all are built/pushed; push can be disabled globally via
    # skip_push/SKIP_PUSH or per registry via the push key):
    #   HB_REGISTRIES   env, comma-separated (highest priority)
    #   REGISTRY        env, single registry (legacy override)
    #   registries:     list in variables.yml — strings ("name") or maps
    #                   (name/prefix/push); builder file overrides project
    #   registry:       scalar in variables.yml (fallback)
    local registry_list="${HB_REGISTRIES:-${REGISTRY:-}}"
    local prefix="${IMAGE_PREFIX:-}"
    local -a reg_entries=()
    if [[ -n "${registry_list}" ]]; then
        local reg
        while IFS= read -r reg; do
            [[ -n "${reg}" ]] || continue
            reg_entries+=("${reg}|${prefix}|")
        done <<< "${registry_list//,/$'\n'}"
    else
        mapfile -t reg_entries < <(python3 - "${merged_vars}" <<'PY'
import sys, yaml

data = yaml.safe_load(open(sys.argv[1], encoding="utf-8")) or {}
registries = data.get("registries")
entries = []
if isinstance(registries, list):
    for reg in registries:
        if isinstance(reg, dict):
            push = reg.get("push", "")
            if isinstance(push, bool) or push in ("true", "yes", "1"):
                push = "true" if push else "false"
            entries.append(f"{reg.get('name', '')}|{reg.get('prefix', '')}|{push}")
        else:
            entries.append(f"{str(reg)}|")
elif isinstance(registries, str):
    entries.append(f"{registries}|")
elif isinstance(data.get("registry"), str):
    entries.append(f"{data['registry']}|")
print("\n".join(entries))
PY
)
    fi

    local i=0
    local entry reg prefix2 push2
    for entry in "${reg_entries[@]:-}"; do
        IFS='|' read -r reg prefix2 push2 <<< "${entry}"
        [[ -n "${reg}" ]] || continue
        CONFIG[DF_REGISTRY_${i}]="${reg}"
        CONFIG[DF_REGISTRY_${i}_PREFIX]="${prefix2}"
        local reg_push="true"
        [[ "${skip_push}" == "true" ]] && reg_push="false"
        if [[ -n "${push2}" ]] && [[ "$(echo "${push2}" | tr '[:upper:]' '[:lower:]')" =~ ^(false|no|0)$ ]]; then
            reg_push="false"
        fi
        CONFIG[DF_REGISTRY_${i}_PUSH]="${reg_push}"
        i=$((i+1))
    done
    if command -v build_registries_array >/dev/null 2>&1; then
        build_registries_array
    fi

    # Arch/platforms: env PLATFORMS wins, else variables.yml platforms
    # (comma-separated string or list, e.g. "linux/amd64,linux/arm64")
    local platforms="${PLATFORMS:-}"
    if [[ -z "${platforms}" ]]; then
        platforms="$(python3 - "${merged_vars}" <<'PY'
import sys, yaml

data = yaml.safe_load(open(sys.argv[1], encoding="utf-8")) or {}
platforms = data.get("platforms")
if isinstance(platforms, list):
    print(",".join(str(p) for p in platforms))
elif platforms:
    print(platforms)
PY
)"
    fi
    [[ -n "${platforms}" ]] && CONFIG[PLATFORMS]="${platforms}"

    # Chunkah build: engine applies the workaround flags (Phase 2 hook)
    CONFIG[CHUNKAH]="true"

    local registry_summary="${registry_list:-$(IFS=,; echo "${reg_entries[*]}")}"
    log_info "Hummingbird config: image=${CONFIG[IMAGE_NAME]} version=${CONFIG[VERSION]} tags='${CONFIG[CUSTOM_TAGS]:-}' registries=${registry_summary} platforms=${platforms:-native} skip_push=${skip_push}"
    return 0
}

# =============================================================================
# ci_hummingbird_read_variants
# Purpose:
#   Read variant list directly from properties.yml (before .hbgen is created).
#   Used for early validation and pre-selection of HB_VARIANTS before the
#   expensive generation step runs.
# Input:
#   $1 - image directory (must contain properties.yml)
# Output:
#   Prints variant names (one per line); falls back to "default" if none declared
# =============================================================================
ci_hummingbird_read_variants() {
    local image_dir="${1:?missing image directory}"
    local props="${image_dir}/properties.yml"
    [[ -f "${props}" ]] || { log_error "properties.yml not found: ${props}"; return 1; }

    python3 - "${props}" <<'PY'
import sys, yaml
data = yaml.safe_load(open(sys.argv[1], encoding="utf-8")) or {}
variants = data.get("variants", ["default"])
if isinstance(variants, list) and variants:
    print("\n".join(str(v) for v in variants))
else:
    print("default")
PY
}

# =============================================================================
# ci_hummingbird_build
# Purpose:
#   Full hummingbird pipeline: pre-select variants, generate, then build each
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

    # WHY: Read and filter variants BEFORE expensive generation so invalid
    # HB_VARIANTS names are caught early and only selected variants are built.
    local variants
    variants="$(ci_hummingbird_read_variants "${image_dir}")" || return 1

    if [[ -n "${HB_VARIANTS:-}" ]]; then
        local -a all_variants selected=()
        mapfile -t all_variants <<< "${variants}"
        local requested v ok
        for requested in ${HB_VARIANTS//,/ }; do
            ok="false"
            for v in "${all_variants[@]}"; do
                [[ "$v" == "$requested" ]] && ok="true" && break
            done
            [[ "$ok" == "true" ]] || {
                log_error "Unknown variant '${requested}' for $(basename "${image_dir}"); valid: ${all_variants[*]}"
                return 1
            }
            selected+=("$requested")
        done
        variants="$(printf '%s\n' "${selected[@]}")"
        log_info "Building variants (HB_VARIANTS): ${selected[*]}"
    fi

    # Generate the work tree for all variants (generation is not per-variant)
    ci_hummingbird_generate "${image_dir}" || return 1

    # WHY: ci_build_and_push resets CI_BUILT_IMAGES per variant, so accumulate
    # the images of every variant here for the driver-level post-build loop
    declare -ga HB_BUILT_IMAGES 2>/dev/null || true
    HB_BUILT_IMAGES=()

    local variant
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

