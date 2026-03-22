#!/usr/bin/env bash
# lib/ci-artifacts.sh
#
# Purpose:
#   Artifact management helpers that wrap existing toolchain commands when present,
#   and fall back to a local artifact store otherwise. Exposes safe, non-colliding
#   functions prefixed with `ci_` so we do not shadow standard commands.
#
# Design goals:
#   - Do NOT redefine standard commands: save_artifact, list_artifacts, load_artifact
#   - Prefer built-in pipeline/toolchain commands when present
#   - Fall back to a local artifact store with the same file layout as original code
#   - Always capture image digest and human-readable size (same logic as original)
#   - Provide summary output (markdown default, csv/json optional)
#   - Produce artifacts with restrictive perms (0600), temp files 0600/0700
#
# Usage:
#   source lib/ci-artifacts.sh
#
# Functions (public):
#   ci_collect_image_metadata <image> -> prints "NAME|IMAGE|DIGEST|SIZE" (stdout)
#   ci_store_artifact --name NAME --value IMAGE [--digest DIG] [--size SIZE] [--ibmkey KEY]
#       -> stores via built-in save_artifact if available, else writes local .artifact file
#   ci_save_local_artifact_fallback <name> <image> <digest> <size> <ibmkey?>
#       -> writes the fallback artifact file (used by ci_store_artifact)
#   ci_list_local_artifacts [store_dir] -> prints local artifact file paths
#   ci_read_artifacts_unified [store_dir]
#       -> prints lines "ARTIFACT_ID|NAME|IMAGE|DIGEST|SIZE"
#          where ARTIFACT_ID is pipelinectl id or filepath
#   ci_generate_artifact_summary [title] [store_dir] [format]
#       -> default format 'markdown' (supports 'csv' and 'json')
#
# Examples:
#   ci_collect_image_metadata "docker.io/library/alpine:3.18"
#   ci_store_artifact --name alpine --value "docker.io/library/alpine:3.18" --digest "sha256:..."
#   ci_generate_artifact_summary "My Images" "./artifacts" "json"
#
# WHY: centralize artifact operations so other modules can rely on consistent metadata format
#

# Source dependencies
if [[ -z "${CI_CORE_LOADED:-}" ]]; then
    LIB_DIR="${LIB_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
    # shellcheck source=/dev/null
    source "${LIB_DIR}/ci-core.sh"
fi

# Source registry module for credential extraction
if [[ -z "${CI_REGISTRY_LOADED:-}" ]]; then
    LIB_DIR="${LIB_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
    # shellcheck source=/dev/null
    source "${LIB_DIR}/ci-registry.sh" 2>/dev/null || true
fi

# Ensure CONFIG arrays are present if other modules rely on them
declare -gA CONFIG 2>/dev/null || true

# --- Helper: human-readable size function (same algorithm as original) ---
# Input: bytes (integer)
# Output: human-readable string (e.g. "12.34 MB")
_ci_humanize_size() {
    local bytes="$1"
    if [[ -z "$bytes" || ! "$bytes" =~ ^[0-9]+$ ]]; then
        printf 'N/A'
        return 0
    fi
    # Use awk identical to original for consistent units
    awk -v b="$bytes" 'BEGIN{
        split("B KB MB GB TB PB EB ZB YB", v);
        s=1;
        while(b>=1024 && s<length(v)){ b=b/1024; s++ }
        printf "%.2f %s", b, v[s]
    }'
}

# ---------------------------------------------------------------------------
# ci_collect_image_metadata
# Purpose:
#   Collect digest and size for a given image reference.
# Input:
#   $1 image reference (e.g. registry/repo/image:tag or repo/image@sha)
# Output:
#   prints single line: NAME|IMAGE|DIGEST|SIZE_HR
#   returns 0 on success, non-zero on failure
# WHY:
#   centralizes logic for digest + size calculation; preserves original skopeo/docker/podman logic.
# Example:
#   ci_collect_image_metadata "docker.io/library/alpine:3.18"
# ---------------------------------------------------------------------------
ci_collect_image_metadata() {
    local image="$1"
    if [[ -z "$image" ]]; then
        log_error "ci_collect_image_metadata: image required"
        return 1
    fi

    local engine
    engine="$(detect_container_engine 2>/dev/null || echo docker)"

    # 1) Obtain digest: prefer skopeo inspect for remote registry
    local digest="N/A"
    if command -v skopeo >/dev/null 2>&1; then
        # best-effort: if skopeo fails, fallback quietly
        digest="$(skopeo inspect --format '{{.Digest}}' "docker://${image}" 2>/dev/null || echo "N/A")"
    fi

    # 2) Obtain size in bytes: try docker/podman inspect (local) or skopeo
    local size_bytes=""
    # Try docker/podman inspect for remote:build or local references (best-effort)
    if command -v docker >/dev/null 2>&1 && [[ "$engine" == "docker" ]]; then
        size_bytes="$(docker inspect --format='{{.Size}}' "$image" 2>/dev/null || echo "")"
    elif command -v podman >/dev/null 2>&1 && [[ "$engine" == "podman" ]]; then
        size_bytes="$(podman inspect --format='{{.Size}}' "$image" 2>/dev/null || echo "")"
    fi

    # If size_bytes still empty and skopeo present, get size from registry
    if [[ -z "$size_bytes" && -n "$(command -v skopeo 2>/dev/null)" ]]; then
        if command -v jq >/dev/null 2>&1; then
            # WHY: skopeo inspect provides .Size field which is the total uncompressed size
            # This matches docker/podman inspect behavior for consistency
            local sk_inspect
            sk_inspect="$(skopeo inspect "docker://${image}" 2>/dev/null || echo "")"
            if [[ -n "$sk_inspect" ]]; then
                # Try .Size first (total uncompressed size)
                size_bytes="$(printf '%s' "$sk_inspect" | jq -r '.Size // empty' 2>/dev/null || echo "")"
                
                # If .Size not available, try LayersData
                if [[ -z "$size_bytes" ]]; then
                    size_bytes="$(printf '%s' "$sk_inspect" | jq -r '
                        if .LayersData then
                            [.LayersData[].Size] | add
                        else
                            empty
                        end
                    ' 2>/dev/null || echo "")"
                fi
                
                # Last resort: use VirtualSize if available
                if [[ -z "$size_bytes" ]]; then
                    size_bytes="$(printf '%s' "$sk_inspect" | jq -r '.VirtualSize // empty' 2>/dev/null || echo "")"
                fi
            fi
        fi
    fi

    # Convert to human-readable size
    local size_hr="N/A"
    if [[ -n "$size_bytes" && "$size_bytes" =~ ^[0-9]+$ ]]; then
        size_hr="$(_ci_humanize_size "$size_bytes")"
    else
        size_hr="N/A"
    fi

    # Normalise image name key to the "image_name" used in your existing artifacts:
    # use last two path elements when available as original code does.
    local image_path image_name
    image_path="$(printf '%s' "$image" | sed -E 's#^[^/]+/##; s#[:@].*##')"
    image_name="$(printf '%s' "$image_path" | awk -F'/' '{ if (NF>=2) print $(NF-1)"/"$NF; else print $NF }')"

    # Output a single line, pipe-safe
    printf '%s|%s|%s|%s\n' "$image_name" "$image" "${digest:-N/A}" "$size_hr"
    return 0
}

# =============================================================================
# ci_collect_sbom_evidence
# Purpose:
#   Collects and registers SBOM evidence using the 'collect-evidence' CLI tool
#   when it is available in the environment. Uses the artifact name from
#   ci_store_artifact as the asset-key for load_artifact integration.
# Input:
#   $1 - sbom_file     : Path to the SBOM file on disk
#   $2 - image_ref     : Fully-qualified image reference the SBOM describes
#   $3 - artifact_name : (optional) Artifact name from ci_store_artifact
# Output:
#   Registers evidence via 'collect-evidence'; logs success or skip/failure.
# Returns:
#   0 on success or when 'collect-evidence' is not available (non-fatal),
#   non-zero if 'collect-evidence' is present but returns an error.
# WHY:
#   Provides a reusable, auditable evidence-collection step for SBOM artifacts
#   that integrates with IBM Cloud toolchains and promotion pipelines.
# =============================================================================
ci_collect_sbom_evidence() {
    local sbom_file="${1:-}"
    local image_ref="${2:-}"
    local artifact_name="${3:-}"

    if [[ -z "$sbom_file" ]]; then
        log_warn "ci_collect_sbom_evidence: no SBOM file provided; skipping evidence collection"
        return 0
    fi

    if [[ ! -f "$sbom_file" ]]; then
        log_warn "ci_collect_sbom_evidence: SBOM file not found on disk: $sbom_file"
        return 0
    fi

    # Only proceed if the collect-evidence CLI is available
    if ! command -v collect-evidence >/dev/null 2>&1; then
        log_info "collect-evidence not found; skipping SBOM evidence collection"
        return 0
    fi

    # Use artifact_name if provided, otherwise derive from image_ref
    if [[ -z "$artifact_name" && -n "$image_ref" ]]; then
        # Extract artifact name using same logic as ci_collect_image_metadata
        local image_path
        image_path="$(printf '%s' "$image_ref" | sed -E 's#^[^/]+/##; s#[:@].*##')"
        artifact_name="$(printf '%s' "$image_path" | awk -F'/' '{ if (NF>=2) print $(NF-1)"/"$NF; else print $NF }')"
    fi

    if [[ -z "$artifact_name" ]]; then
        log_warn "ci_collect_sbom_evidence: could not determine artifact name; skipping"
        return 0
    fi

    log_info "Collecting SBOM evidence: asset-key=$artifact_name image=${image_ref:-<unspecified>}"

    local cmd_args=(
        collect-evidence
        --evidence-type "com.ibm.code_bom_check"
        --tool-type      "cyclonedx"
        --asset-type "artifact"
        --asset-key "$artifact_name"
        --status "success"
        --attachment  "$sbom_file"
    )

    if "${cmd_args[@]}"; then
        log_success "SBOM evidence collected successfully for artifact: $artifact_name"
        return 0
    else
        local rc=$?
        log_error "collect-evidence failed for SBOM '$sbom_file' (exit code $rc)"
        return $rc
    fi

}

# ---------------------------------------------------------------------------
# ci_sanitize_artifact_name
# Purpose:
#   Convert a logical artifact "name" into a filesystem-safe filename
#   so that the filename can always be re-derived from the name.
# Input:
#   $1 - raw name (e.g., "repo/image")
# Output:
#   sanitized name (e.g., "repo_image")
# WHY:
#   Ensures that artifacts can be reliably found later using only the name.
# ---------------------------------------------------------------------------
ci_sanitize_artifact_name() {
    local raw="$1"
    # Replace slash and spaces, remove unsafe chars
    raw="${raw//\//_}"
    raw="${raw// /_}"
    raw="$(printf '%s' "$raw" | sed 's/[^A-Za-z0-9._-]/_/g')"
    printf '%s' "$raw"
}

# ---------------------------------------------------------------------------
# Updated ci_save_local_artifact_fallback
# ---------------------------------------------------------------------------
ci_save_local_artifact_fallback() {
    local name="$1" image="$2" digest="$3" size_hr="$4" ibm_api_key="${5:-}"

    [[ -z "$name" || -z "$image" ]] && {
        log_error "ci_save_local_artifact_fallback: name and image required"
        return 1
    }

    local store="${ARTIFACT_STORE:-${SOURCE_DIR:-.}/artifacts}"
    mkdir -p -- "$store"

    # NEW: filename must be deterministically derived from the name
    local sanitized
    sanitized="$(ci_sanitize_artifact_name "$name")"
    local fpath="${store}/${sanitized}.artifact"

    {
        printf 'IMAGE_NAME="%s"\n' "$name"
        printf 'IMAGE="%s"\n' "$image"
        printf 'DIGEST="%s"\n' "${digest:-}"
        printf 'SIZE="%s"\n' "${size_hr:-}"
        printf 'IBM_API_KEY="%s"\n' "${ibm_api_key:-}"
    } > "$fpath"

    chmod 600 "$fpath"

    log_info "Local artifact written: $fpath"
    printf '%s\n' "$fpath"
    return 0
}


# ---------------------------------------------------------------------------
# ci_store_artifact
# Purpose:
#   Save an artifact using pipeline/toolchain save_artifact if available,
#   otherwise fallback to writing a local artifact file (ci_save_local_artifact_fallback).
# Inputs (CLI style):
#   --name NAME
#   --value IMAGE
#   [--digest DIG]
#   [--size SIZE]
#   [--ibmkey KEY]
# Output:
#   returns 0 on success
# WHY:
#   Respect existing toolchain commands (do not reimplement them) and ensure size/digest are stored.
# Example:
#   ci_store_artifact --name repo/image --value registry/repo:tag --digest sha256:... --size "12.3 MB"
# ---------------------------------------------------------------------------
ci_store_artifact() {
    local name="" value="" digest="" size_hr="" ibmkey=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --name) name="$2"; shift 2;;
            --value) value="$2"; shift 2;;
            --digest) digest="$2"; shift 2;;
            --size) size_hr="$2"; shift 2;;
            --ibmkey) ibmkey="$2"; shift 2;;
            *) shift ;;
        esac
    done

    if [[ -z "$name" || -z "$value" ]]; then
        log_error "ci_store_artifact: --name and --value are required"
        return 1
    fi

    # If there is a native save_artifact command (pipelinectl or environment), prefer it.
    if command -v save_artifact >/dev/null 2>&1; then
        # WHY: Try save_artifact first, but fall back to local save if it fails
        if save_artifact "$name" type=image name="$value" digest="$digest" size="$size_hr" 2>/dev/null; then
            log_info "Saved artifact via save_artifact: name=$name image=$value"
            return 0
        else
            log_warn "save_artifact command failed, falling back to local save"
            # Fall through to local save
        fi
    fi

    # Fallback to artifact store (either no save_artifact command, or it failed)
    ci_save_local_artifact_fallback "$name" "$value" "$digest" "$size_hr" "$ibmkey"
    return $?
}


# ---------------------------------------------------------------------------
# ci_read_artifacts_unified
# Purpose:
#   Unified artifact reader:
#   - Prefer IBM/pipelinectl list_artifacts + load_artifact
#   - Fallback to local artifact files (*.artifact)
#
# Output format (per line):
#   ARTIFACT_ID|NAME|IMAGE|DIGEST|SIZE
#
# WHY:
#   This function replaces ci_list_local_artifacts() entirely.
#   All callers (summary, bundle updater, operator code) should use ONLY this.
# ---------------------------------------------------------------------------
ci_read_artifacts_unified() {
    local store="${1:-${ARTIFACT_STORE:-${SOURCE_DIR:-.}/artifacts}}"

    # 1. Try pipelinectl/list_artifacts first
    if command -v list_artifacts >/dev/null 2>&1 && \
       command -v load_artifact >/dev/null 2>&1; then

        for art_id in $(list_artifacts 2>/dev/null || true); do
            local name image digest size

            name="$(load_artifact "$art_id" name 2>/dev/null || echo "")"
            image="$(load_artifact "$art_id" value 2>/dev/null || echo "")"
            digest="$(load_artifact "$art_id" digest 2>/dev/null || echo "")"
            size="$(load_artifact "$art_id" size 2>/dev/null || echo "")"

            # Emit only real entries
            if [[ -n "$name" || -n "$image" ]]; then
                printf '%s|%s|%s|%s|%s\n' \
                    "$art_id" "$name" "$image" "$digest" "$size"
            fi
        done
        return 0
    fi

    # 2. Local fallback: read *.artifact files
    if [[ -d "$store" ]]; then
        shopt -s nullglob
        for f in "$store"/*.artifact; do
            [[ -f "$f" ]] || continue

            local NAME="" IMAGE="" DIGEST="" SIZE=""
            while IFS= read -r ln; do
                case "$ln" in
                    IMAGE_NAME=*) NAME="${ln#IMAGE_NAME=}"; NAME="${NAME%\"}"; NAME="${NAME#\"}" ;;
                    IMAGE=*) IMAGE="${ln#IMAGE=}"; IMAGE="${IMAGE%\"}"; IMAGE="${IMAGE#\"}" ;;
                    DIGEST=*) DIGEST="${ln#DIGEST=}"; DIGEST="${DIGEST%\"}"; DIGEST="${DIGEST#\"}" ;;
                    SIZE=*) SIZE="${ln#SIZE=}"; SIZE="${SIZE%\"}"; SIZE="${SIZE#\"}" ;;
                esac
            done < "$f"

            [[ -n "$NAME" || -n "$IMAGE" ]] && \
            printf '%s|%s|%s|%s|%s\n' \
                "$f" "$NAME" "$IMAGE" "$DIGEST" "$SIZE"
        done
        shopt -u nullglob
        return 0
    fi

    return 1
}


# ---------------------------------------------------------------------------
# ci_render_summary_markdown
# Purpose:
#   Render artifacts into a markdown table saved to a temp file and optionally set
#   GITHUB_BUILD_SUMMARY via set_env.
# Inputs:
#   $1 - title
#   $2 - array of artifact lines (ARTIFACT_ID|NAME|IMAGE|DIGEST|SIZE)
# Output:
#   prints path to markdown summary file
# WHY:
#   matches original behaviour where summary is provided to CI via GITHUB_STEP_SUMMARY
# ---------------------------------------------------------------------------
ci_render_summary_markdown() {
    local title="$1"
    shift
    local -a lines=("$@")

    # temp file for summary
    local summary_file
    if command -v ci_create_temp_file >/dev/null 2>&1; then
        summary_file="$(ci_create_temp_file "github_step_summary")"
    else
        summary_file="$(mktemp --tmpdir "${TMPDIR:-/tmp}/github_step_summary.XXXXXX")"
        chmod 600 "$summary_file"
    fi

    printf '## %s\n\n' "$title" > "$summary_file"
    printf '| # | Image | Digest | Size |\n' >> "$summary_file"
    printf '|---|-------|--------|------|\n' >> "$summary_file"

    local count=1
    local ld artifact_id name image digest size
    for ld in "${lines[@]:-}"; do
        # WHY: Format is ARTIFACT_ID|NAME|IMAGE|DIGEST|SIZE (5 fields)
        IFS='|' read -r artifact_id name image digest size <<< "$ld"
        # WHY: Use image as display if name is empty
        local display="${image:-$name}"
        printf '| %d | %s | %s | %s |\n' "$count" "$display" "${digest:-N/A}" "${size:-N/A}" >> "$summary_file"
        count=$((count + 1))
    done

    # Expose location to CI environment if set_env exists (IBM Cocoa)
    if command -v set_env >/dev/null 2>&1; then
        set_env GITHUB_BUILD_SUMMARY "$summary_file" 2>/dev/null || true
    else
        # fallback export for callers to read
        export GITHUB_BUILD_SUMMARY="$summary_file"
    fi

    printf '%s\n' "$summary_file"
    return 0
}

# ---------------------------------------------------------------------------
# ci_render_summary_csv
# Purpose:
#   Render artifact lines to CSV and print path to file
# Inputs:
#   $1 - title (unused for CSV)
#   rest - artifact lines
# Output:
#   prints path to CSV file
# ---------------------------------------------------------------------------
ci_render_summary_csv() {
    local title="$1"
    shift
    local -a lines=("$@")

    local tmp
    if command -v ci_create_temp_file >/dev/null 2>&1; then
        tmp="$(ci_create_temp_file "artifact_summary_csv")"
    else
        tmp="$(mktemp --tmpdir "${TMPDIR:-/tmp}/artifact_summary.XXXXXX")"
        chmod 600 "$tmp"
    fi

    # header
    printf 'index,name,image,digest,size\n' > "$tmp"
    local i=1 ld name image digest size
    for ld in "${lines[@]:-}"; do
        IFS='|' read -r _ id name image digest size <<< "$ld"
        local display="${name:-$image}"
        # Escape double quotes by doubling them
        display="${display//\"/\"\"}"
        image="${image//\"/\"\"}"
        digest="${digest//\"/\"\"}"
        size="${size//\"/\"\"}"
        printf '%d,"%s","%s","%s","%s"\n' "$i" "$display" "$image" "$digest" "$size" >> "$tmp"
        i=$((i+1))
    done
    printf '%s\n' "$tmp"
    return 0
}

# ---------------------------------------------------------------------------
# ci_render_summary_json
# Purpose:
#   Render artifact lines to JSON array and print path to file
# Inputs:
#   $1 - title (unused)
#   rest - artifact lines
# Output:
#   prints path to JSON file
# ---------------------------------------------------------------------------
ci_render_summary_json() {
    local title="$1"
    shift
    local -a lines=("$@")

    local tmp
    if command -v ci_create_temp_file >/dev/null 2>&1; then
        tmp="$(ci_create_temp_file "artifact_summary_json")"
    else
        tmp="$(mktemp --tmpdir "${TMPDIR:-/tmp}/artifact_summary.XXXXXX")"
        chmod 600 "$tmp"
    fi

    printf '[\n' > "$tmp"
    local first=true ld id name image digest size
    for ld in "${lines[@]:-}"; do
        IFS='|' read -r id name image digest size <<< "$ld"
        # produce JSON-safe strings (minimal escaping)
        name="${name//\\/\\\\}"
        name="${name//\"/\\\"}"
        image="${image//\\/\\\\}"
        image="${image//\"/\\\"}"
        digest="${digest//\\/\\\\}"
        digest="${digest//\"/\\\"}"
        size="${size//\\/\\\\}"
        size="${size//\"/\\\"}"
        if [[ "$first" == true ]]; then
            first=false
        else
            printf ',\n' >> "$tmp"
        fi
        printf '  {"artifact":"%s","name":"%s","image":"%s","digest":"%s","size":"%s"}' "$id" "$name" "$image" "$digest" "$size" >> "$tmp"
    done
    printf '\n]\n' >> "$tmp"
    printf '%s\n' "$tmp"
    return 0
}

# ---------------------------------------------------------------------------
# ci_generate_artifact_summary
# Purpose:
#   Produce an artifact summary in markdown (default), csv, or json.
# Inputs:
#   $1 title (optional) - default "Docker Image Information"
#   $2 artifact_store (optional) - fallback store dir
#   $3 format (optional) - one of markdown|csv|json (default markdown)
# Output:
#   prints path to generated summary file (and for markdown sets GITHUB_BUILD_SUMMARY)
# Example:
#   ci_generate_artifact_summary "Images" "./artifacts" "json"
# ---------------------------------------------------------------------------
ci_generate_artifact_summary() {
    local title="${1:-Docker Image Information}"
    local artifact_store="${2:-}"
    local format="${3:-markdown}"

    # Collect unified artifact lines
    local -a lines=()
    while IFS= read -r ln; do
        [[ -z "$ln" ]] && continue
        lines+=("$ln")
    done < <(ci_read_artifacts_unified "${artifact_store:-}" 2>/dev/null || true)

    if [[ ${#lines[@]} -eq 0 ]]; then
        log_warn "ci_generate_artifact_summary: no artifacts found"
        return 1
    fi

    case "${format,,}" in
        markdown)
            local out
            out="$(ci_render_summary_markdown "$title" "${lines[@]}")"
            printf '%s\n' "$out"
            ;;
        csv)
            local out
            out="$(ci_render_summary_csv "$title" "${lines[@]}")"
            printf '%s\n' "$out"
            ;;
        json)
            local out
            out="$(ci_render_summary_json "$title" "${lines[@]}")"
            printf '%s\n' "$out"
            ;;
        *)
            log_warn "Unknown format: $format (use markdown|csv|json)"
            return 2
            ;;
    esac
    return 0
}

# EOF
