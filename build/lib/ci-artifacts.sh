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
#   ci_get_image_digest <image>
#       -> prints "sha256:<hex>" for the image ref directly (no manifest-list traversal)
#   ci_list_manifest_architectures <image>
#       -> prints "arch|digest" lines for every architecture in the remote manifest list
#   ci_read_artifacts_unified [store_dir]
#       -> prints lines "ARTIFACT_ID|DISPLAY_NAME|ARCH|DIGEST|SIZE|PRIMARY|MANIFEST_TYPE"
#          where ARTIFACT_ID is pipelinectl id or filepath
#   ci_generate_artifact_summary [title] [store_dir] [format]
#       -> default format 'markdown' (supports 'csv' and 'json')
#   ci_ibmcloud_save_artifact <image> [arch] [primary]
#       -> when arch is empty: queries manifest list and saves one artifact per architecture
#       -> when arch is provided: saves a single artifact for that architecture
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
declare -ga SIGN_REGISTRIES 2>/dev/null || true

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
# ci_extract_short_image_name
# Purpose:
#   Extract short image name from full image reference for display in summaries
#   Example: icr.io/ipaas-non-prod/wm-e2em/ibm-integration-monitoring-operator-catalog:v1.1.0
#            → wm-e2em/ibm-integration-monitoring-operator-catalog:v1.1.0
# Input:
#   $1 - full image reference
# Output:
#   short image name (last two path components with tag/digest)
# WHY:
#   Summaries should show concise image names, not full registry paths
# ---------------------------------------------------------------------------
ci_extract_short_image_name() {
    local full_image="$1"
    [[ -z "$full_image" ]] && return 1

    # Remove registry (everything before first slash after ://)
    # Handle both registry.io/path/image:tag and path/image:tag formats
    local without_registry="$full_image"
    if [[ "$full_image" =~ ^[^/]+\.[^/]+/ ]]; then
        # Has registry (contains dot before first slash)
        without_registry="${full_image#*/}"  # Remove first component (registry)
    fi

    # Extract last two path components with tag/digest
    # Examples:
    #   wm-e2em/ibm-integration-monitoring-operator-catalog:v1.1.0 → wm-e2em/ibm-integration-monitoring-operator-catalog:v1.1.0
    #   a/b/c/image:tag → c/image:tag
    #   image:tag → image:tag
    local path_part="${without_registry%%:*}"  # Everything before :
    local path_part="${path_part%%@*}"         # Everything before @ (for digest)
    local tag_part="${without_registry#*:}"    # Everything after first :
    if [[ "$tag_part" == "$without_registry" ]]; then
        # No tag, check for digest
        tag_part="${without_registry#*@}"
        if [[ "$tag_part" != "$without_registry" ]]; then
            tag_part="@${tag_part}"
        else
            tag_part=""
        fi
    else
        tag_part=":${tag_part}"
    fi

    # Get last two path components
    local short_path
    if [[ "$path_part" == */* ]]; then
        # Has at least one slash - get last two components
        short_path="${path_part##*/}"           # Last component
        local parent="${path_part%/*}"          # Remove last component
        if [[ "$parent" == */* ]]; then
            parent="${parent##*/}"              # Get second-to-last component
            short_path="${parent}/${short_path}"
        else
            short_path="${parent}/${short_path}"
        fi
    else
        # No slash - just the image name
        short_path="$path_part"
    fi

    printf '%s%s\n' "$short_path" "$tag_part"
}

# ---------------------------------------------------------------------------
# Updated ci_save_local_artifact_fallback
# WHY: Enhanced to preserve architecture, primary registry flag, type, mediatype, and sign flag in artifact files
# ---------------------------------------------------------------------------
ci_save_local_artifact_fallback() {
    local name="$1" image="$2" digest="$3" size_hr="$4" arch="${5:-}" tag="${6:-}" primary="${7:-false}" type="${8:-}" mediatype="${9:-}" sign="${10:-false}"

    [[ -z "$name" || -z "$image" ]] && {
        log_error "ci_save_local_artifact_fallback: name and image required"
        return 1
    }

    local store="${ARTIFACT_STORE:-${SOURCE_DIR:-.}/artifacts}"
    mkdir -p -- "$store"

    # Use provided architecture or extract from name if present (format: name-arch)
    if [[ -z "$arch" ]]; then
        if [[ "$name" =~ -(amd64|arm64|arm|ppc64le|s390x|386|riscv64)$ ]]; then
            arch="${BASH_REMATCH[1]}"
        fi
    fi

    # WHY: Use the artifact name as-is (already constructed by caller with arch and digest)
    # No need to append digest or arch again - that's done in ci_ibmcloud_save_artifact
    local artifact_name="$name"

    # NEW: filename must be deterministically derived from the artifact name
    local sanitized
    sanitized="$(ci_sanitize_artifact_name "$artifact_name")"
    local fpath="${store}/${sanitized}.artifact"

    {
        printf 'IMAGE_NAME="%s"\n' "$name"
        printf 'IMAGE="%s"\n' "$image"
        printf 'TAG="%s"\n' "${tag:-latest}"
        printf 'DIGEST="%s"\n' "${digest:-}"
        printf 'SIZE="%s"\n' "${size_hr:-}"
        printf 'ARCHITECTURE="%s"\n' "${arch:-unknown}"
        printf 'PRIMARY="%s"\n' "${primary:-false}"
        printf 'SIGN="%s"\n'    "${sign:-false}"
        [[ -n "$type" ]]      && printf 'TYPE="%s"\n'      "$type"
        [[ -n "$mediatype" ]] && printf 'MEDIATYPE="%s"\n' "$mediatype"
    } > "$fpath"

    chmod 600 "$fpath"

    log_info "Local artifact written: $fpath (tag: ${tag:-latest}, arch: ${arch:-unknown}, primary: ${primary:-false}, sign: ${sign:-false}, type: ${type:-}, mediatype: ${mediatype:-})"
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
#   [--primary true|false]
#   [--sign true|false]      whether this artifact is a sign-registry record (default false)
#   [--type image|docker-index|oci-index]  pipelinectl artifact type (coarse)
#   [--mediatype docker|oci|docker-index|oci-index|image]  human-readable media type
# Output:
#   returns 0 on success
# WHY:
#   Respect existing toolchain commands (do not reimplement them) and ensure size/digest are stored.
# Example:
#   ci_store_artifact --name repo/image --value registry/repo:tag --digest sha256:... --size "12.3 MB" --type docker-index --mediatype docker-index --primary true --sign false
# ---------------------------------------------------------------------------
ci_store_artifact() {
    local name="" value="" digest="" size_hr="" arch="" tag="" primary="false" sign="false" type="" mediatype=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --name)      name="$2";      shift 2;;
            --value)     value="$2";     shift 2;;
            --digest)    digest="$2";    shift 2;;
            --size)      size_hr="$2";   shift 2;;
            --arch)      arch="$2";      shift 2;;
            --tag)       tag="$2";       shift 2;;
            --primary)   primary="$2";   shift 2;;
            --sign)      sign="$2";      shift 2;;
            --type)      type="$2";      shift 2;;
            --mediatype) mediatype="$2"; shift 2;;
            *) shift ;;
        esac
    done

    if [[ -z "$name" || -z "$value" ]]; then
        log_error "ci_store_artifact: --name and --value are required"
        return 1
    fi

    # If there is a native save_artifact command (pipelinectl or environment), prefer it.
    if command -v save_artifact >/dev/null 2>&1; then

        # WHY: avoid double-digest when value already carries @sha256: (e.g. OCI index refs)
        local name_with_digest
        if [[ "$value" == *"@sha256:"* ]]; then
            name_with_digest="$value"
        else
            name_with_digest="$value@$digest"
        fi
        local save_cmd=(save_artifact "$name" type="${type:-image}" name="$name_with_digest")
        [[ -n "$digest" ]]    && save_cmd+=(digest="$digest")
        [[ -n "$size_hr" ]]   && save_cmd+=(size="$size_hr")
        [[ -n "$tag" ]]       && save_cmd+=(tag="$tag")
        [[ -n "$arch" ]]      && save_cmd+=(architecture="$arch")
        [[ -n "$primary" ]]   && save_cmd+=(primary="$primary")
        [[ -n "$sign" ]]      && save_cmd+=(sign="$sign")
        [[ -n "$mediatype" ]] && save_cmd+=(mediatype="$mediatype")

        if "${save_cmd[@]}" 2>/dev/null; then
            log_info "Saved artifact via save_artifact: name=$name value=$value digest=${digest}... tag=$tag arch=$arch type=${type:-image} mediatype=${mediatype:-} primary=$primary sign=$sign"
            return 0
        else
            log_warn "save_artifact command failed, falling back to local save"
            # Fall through to local save
        fi
    fi

    # Fallback to artifact store (either no save_artifact command, or it failed)
    ci_save_local_artifact_fallback "$name" "$value" "$digest" "$size_hr" "$arch" "$tag" "$primary" "$type" "$mediatype" "$sign"
    return $?
}

# ---------------------------------------------------------------------------
# ci_get_platform_digest
# Purpose:
#   Extract architecture-specific digest from a multi-platform manifest
# Inputs:
#   $1 - image reference
#   $2 - architecture (e.g., amd64, arm64)
# Output:
#   prints SHA256 digest for the specific architecture
# WHY:
#   Multi-platform images have per-architecture digests that need to be tracked separately
# ---------------------------------------------------------------------------
ci_get_platform_digest() {
    local image="$1"
    local arch="$2"

    [[ -z "$image" || -z "$arch" ]] && return 1

    # Try skopeo first (most reliable for multi-platform)
    if command -v skopeo >/dev/null 2>&1; then
        local platform_digest
        platform_digest="$(skopeo inspect --raw "docker://${image}" 2>/dev/null | \
            jq -r --arg arch "$arch" '.manifests[] | select(.platform.architecture == $arch) | .digest' 2>/dev/null || echo "")"

        if [[ -n "$platform_digest" ]]; then
            printf '%s\n' "$platform_digest"
            return 0
        fi
    fi

    # Fallback: try docker/podman manifest inspect
    local engine
    engine="$(detect_container_engine 2>/dev/null || echo docker)"

    if [[ "$engine" == "docker" ]] && command -v docker >/dev/null 2>&1; then
        local platform_digest
        platform_digest="$(docker manifest inspect "$image" 2>/dev/null | \
            jq -r --arg arch "$arch" '.manifests[] | select(.platform.architecture == $arch) | .digest' 2>/dev/null || echo "")"

        if [[ -n "$platform_digest" ]]; then
            printf '%s\n' "$platform_digest"
            return 0
        fi
    elif [[ "$engine" == "podman" ]] && command -v podman >/dev/null 2>&1; then
        local platform_digest
        platform_digest="$(podman manifest inspect "$image" 2>/dev/null | \
            jq -r --arg arch "$arch" '.manifests[] | select(.platform.architecture == $arch) | .digest' 2>/dev/null || echo "")"

        if [[ -n "$platform_digest" ]]; then
            printf '%s\n' "$platform_digest"
            return 0
        fi
    fi

    return 1
}

# ---------------------------------------------------------------------------
# ci_get_image_digest
# Purpose:
#   Fetch the content digest of an image reference directly — without walking
#   a manifest list or selecting by architecture.  Use this when you already
#   have a fully-resolved single-platform image ref and simply need its sha256.
#
#   Contrast with ci_get_platform_digest, which walks a multi-arch manifest
#   index to find the digest for a *named* architecture.  This function skips
#   that traversal entirely and asks the registry (or local daemon) for the
#   digest of the image reference as given.
#
# Inputs:
#   $1 - image reference (tag or digest ref, single-platform or manifest list)
# Output:
#   prints "sha256:<hex>" to stdout
#   returns 0 on success, 1 if no tooling can resolve the digest
# WHY:
#   Callers that push a per-arch image via "docker buildx build --push
#   --platform linux/amd64 -t repo/img:tag" get back a single-manifest ref.
#   ci_get_platform_digest would fail on it (no .manifests[] array); this
#   function handles both single-manifest and manifest-list refs uniformly
#   by letting the tool resolve whatever the ref points to.
# ---------------------------------------------------------------------------
ci_get_image_digest() {
    local image="$1"
    [[ -z "$image" ]] && return 1

    local digest=""

    # 1. skopeo inspect (no --raw) resolves the ref and returns its digest
    #    directly — works for both single-manifest and manifest-list refs.
    if command -v skopeo >/dev/null 2>&1; then
        digest="$(skopeo inspect --format '{{.Digest}}' "docker://${image}" 2>/dev/null || echo "")"
        if [[ "$digest" == sha256:* ]]; then
            printf '%s\n' "$digest"
            return 0
        fi
    fi

    # 2. docker inspect — works for locally present images; RepoDigests holds
    #    the registry-assigned content digest.
    if command -v docker >/dev/null 2>&1; then
        # RepoDigests entries look like "registry/repo@sha256:hex"; extract the sha256 part.
        local raw
        raw="$(docker inspect --format '{{index .RepoDigests 0}}' "$image" 2>/dev/null || echo "")"
        digest="${raw##*@}"
        if [[ "$digest" == sha256:* ]]; then
            printf '%s\n' "$digest"
            return 0
        fi

        # Fallback within docker: use image ID as digest (local builds without push)
        digest="$(docker inspect --format '{{.Id}}' "$image" 2>/dev/null || echo "")"
        if [[ "$digest" == sha256:* ]]; then
            printf '%s\n' "$digest"
            return 0
        fi
    fi

    # 3. podman inspect — same RepoDigests field layout as docker.
    if command -v podman >/dev/null 2>&1; then
        local raw
        raw="$(podman inspect --format '{{index .RepoDigests 0}}' "$image" 2>/dev/null || echo "")"
        digest="${raw##*@}"
        if [[ "$digest" == sha256:* ]]; then
            printf '%s\n' "$digest"
            return 0
        fi

        digest="$(podman inspect --format '{{.Id}}' "$image" 2>/dev/null || echo "")"
        if [[ "$digest" == sha256:* ]]; then
            printf '%s\n' "$digest"
            return 0
        fi
    fi

    return 1
}

# ---------------------------------------------------------------------------
# _ci_get_manifest_type
# Purpose:
#   Inspect the raw manifest of an image and return a human-readable media
#   type label derived from the OCI/Docker mediaType field.
#
# Output (stdout, one word):
#   "oci-index"    – OCI image index         (vnd.oci.image.index.v1+json)
#   "oci"          – OCI single image        (vnd.oci.image.manifest.v1+json)
#   "docker-index" – Docker manifest list    (vnd.docker.distribution.manifest.list.v2+json)
#   "docker"       – Docker v2 schema2 image (vnd.docker.distribution.manifest.v2+json)
#   "image"        – Docker v1 / v1+prettyjws (legacy schema, no schema version)
#   "unknown"      – manifest could not be fetched or parsed
#
# Returns 0 in all cases (type is always printed).
#
# WHY:
#   Storing the raw mediaType MIME string is verbose and opaque in artifact
#   records.  A short human-readable label is easier to read in summaries,
#   pipelines, and signing tooling while still being precise enough to drive
#   downstream behaviour.
# ---------------------------------------------------------------------------
_ci_get_manifest_type() {
    local image="$1"
    [[ -z "$image" ]] && { printf 'unknown'; return 0; }

    local raw=""

    if command -v skopeo >/dev/null 2>&1; then
        raw="$(skopeo inspect --raw "docker://${image}" 2>/dev/null || echo "")"
    fi
    if [[ -z "$raw" ]] && command -v docker >/dev/null 2>&1; then
        raw="$(docker manifest inspect "$image" 2>/dev/null || echo "")"
    fi
    if [[ -z "$raw" ]] && command -v podman >/dev/null 2>&1; then
        raw="$(podman manifest inspect "$image" 2>/dev/null || echo "")"
    fi

    if [[ -z "$raw" ]]; then
        printf 'unknown'
        return 0
    fi

    # Extract the top-level mediaType field from the raw manifest JSON.
    # OCI image indexes often omit mediaType entirely; we fall back to
    # checking for a non-empty manifests[] array in that case.
    local media_type=""
    if command -v jq >/dev/null 2>&1; then
        media_type="$(printf '%s' "$raw" | jq -r '.mediaType // ""' 2>/dev/null || echo "")"
    fi

    case "$media_type" in
        # ── OCI ──────────────────────────────────────────────────────────────
        "application/vnd.oci.image.index.v1+json")
            printf 'oci-index' ;;
        "application/vnd.oci.image.manifest.v1+json")
            printf 'oci' ;;
        # ── Docker ───────────────────────────────────────────────────────────
        "application/vnd.docker.distribution.manifest.list.v2+json")
            printf 'docker-index' ;;
        "application/vnd.docker.distribution.manifest.v2+json")
            printf 'docker' ;;
        "application/vnd.docker.distribution.manifest.v1+json" | \
        "application/vnd.docker.distribution.manifest.v1+prettyjws")
            printf 'image' ;;
        # ── mediaType absent (OCI index without explicit mediaType field) ────
        "")
            if command -v jq >/dev/null 2>&1; then
                local has_manifests
                has_manifests="$(printf '%s' "$raw" | \
                    jq -r 'if (.manifests | length) > 0 then "yes" else "no" end' \
                    2>/dev/null || echo "no")"
                [[ "$has_manifests" == "yes" ]] && printf 'oci-index' || printf 'oci'
            else
                printf 'oci'
            fi ;;
        # ── anything else ────────────────────────────────────────────────────
        *)
            printf 'image' ;;
    esac
    return 0
}

# ---------------------------------------------------------------------------
# ci_list_manifest_architectures
# Purpose:
#   List all architectures present in a multi-platform manifest index.
#   For each architecture, prints one line: arch|digest
# Inputs:
#   $1 - image reference (tag or digest)
# Output:
#   Lines of "arch|digest" for every architecture entry in the manifest list.
#   Returns non-zero (and prints nothing) if the image is not a manifest list
#   or if no tooling is available to inspect it.
# WHY:
#   Allows ci_ibmcloud_save_artifact to iterate all architectures automatically
#   when the caller has not specified a single arch (e.g. promote flow).
# ---------------------------------------------------------------------------
ci_list_manifest_architectures() {
    local image="$1"
    [[ -z "$image" ]] && return 1

    local raw_manifest=""

    # 1. Prefer skopeo --raw (works without daemon, handles auth transparently)
    if command -v skopeo >/dev/null 2>&1 && command -v jq >/dev/null 2>&1; then
        raw_manifest="$(skopeo inspect --raw "docker://${image}" 2>/dev/null || echo "")"
    fi

    # 2. Fallback: docker manifest inspect (requires experimental or buildx)
    if [[ -z "$raw_manifest" ]] && command -v docker >/dev/null 2>&1 && command -v jq >/dev/null 2>&1; then
        raw_manifest="$(docker manifest inspect "$image" 2>/dev/null || echo "")"
    fi

    # 3. Fallback: podman manifest inspect
    if [[ -z "$raw_manifest" ]] && command -v podman >/dev/null 2>&1 && command -v jq >/dev/null 2>&1; then
        raw_manifest="$(podman manifest inspect "$image" 2>/dev/null || echo "")"
    fi

    [[ -z "$raw_manifest" ]] && return 1

    # Parse manifests[] array — present in OCI index and Docker manifest list
    # Output one "arch|digest" line per architecture entry; skip attestation/unknown entries
    local parsed
    parsed="$(printf '%s' "$raw_manifest" | jq -r '
        .manifests[]?
        | select(
            .platform != null
            and .platform.architecture != null
            and .platform.architecture != "unknown"
            and (.platform.os // "linux") == "linux"
            and ((.mediaType // "") | test("manifest|image"; "i"))
          )
        | "\(.platform.architecture)|\(.digest)"
    ' 2>/dev/null || echo "")"

    [[ -z "$parsed" ]] && return 1

    printf '%s\n' "$parsed"
    return 0
}

# ---------------------------------------------------------------------------
# ci_ibmcloud_save_artifact
# Purpose:
#   Save artifact via IBM Cloud Toolchain (pipelinectl save_artifact) when available,
#   otherwise fallback to ci_store_artifact while preserving all metadata fields:
#   name, image, digest, size, primary flag, sign flag, type (pipelinectl coarse), and mediatype.
#
#   Stores exactly one artifact for the image reference as received.
#   type      – coarse pipelinectl value (image / docker-index / oci-index), unchanged
#   mediatype – precise human-readable label auto-detected from the manifest:
#               docker | oci | docker-index | oci-index | image | unknown
#   sign      – "true" when this artifact is a sign-registry record (mirroring target
#               for a later signing stage); "false" for all normal-registry artifacts
#
#   Every call stores the artifact — the primary/sign flags are recorded as metadata
#   for downstream stages (e.g. summary rendering, signing) but do not gate
#   whether the artifact is saved.
#
# Inputs:
#   $1 image reference
#   $2 architecture (optional) - passed through to the artifact metadata if provided
#   $3 primary (optional) - "true" if this is the primary registry, "false" otherwise
#   $4 sign    (optional) - "true" if this is a sign-registry artifact, "false" otherwise
# Output:
#   returns 0 on success
# ---------------------------------------------------------------------------
ci_ibmcloud_save_artifact() {
    local image="$1"
    local arch="${2:-}"
    local primary="${3:-false}"
    local sign="${4:-false}"

    [[ -z "$image" ]] && {
        log_error "ci_ibmcloud_save_artifact: image required"
        return 1
    }

    # 1. Collect base image metadata (NAME|IMAGE|DIGEST|SIZE)
    local meta
    meta="$(ci_collect_image_metadata "$image")" || {
        log_error "ci_ibmcloud_save_artifact: failed to collect metadata for $image"
        return 1
    }

    local meta_name meta_image meta_digest meta_size
    IFS='|' read -r meta_name meta_image meta_digest meta_size <<< "$meta"

    # 2. Extract tag from the image reference.
    # WHY: strip @sha256: before :tag so the colon inside "sha256:hex" is never
    # mistaken for a tag separator, which would truncate the registry hostname.
    local meta_tag=""
    local image_without_tag
    # Step 1 – remove the digest suffix (@sha256:…) if present
    image_without_tag="${image%%@sha256:*}"
    # Step 2 – remove the tag suffix (:tag) only when it appears after the last slash
    #          so that registry:port prefixes (e.g. registry.example.com:5000) are preserved.
    local _path_after_last_slash="${image_without_tag##*/}"
    if [[ "$_path_after_last_slash" == *:* ]]; then
        image_without_tag="${image_without_tag%:*}"
    fi

    if [[ "$image" == *":"* && "$image" != *"@"* ]]; then
        meta_tag="${image##*:}"
    elif [[ "$image" == *"@"* ]]; then
        local before_digest="${image%%@*}"
        if [[ "$before_digest" == *":"* ]]; then
            meta_tag="${before_digest##*:}"
        fi
    fi

    # WHY: latest-tagged images must not create versioned artifact variants
    if [[ "$meta_tag" == "latest" ]]; then
        log_info "skipping artifact save for latest image: $image"
        return 0
    fi

    # 3. Resolve the content digest for the image as received.
    local img_digest
    img_digest="$(ci_get_image_digest "$image" 2>/dev/null || echo "")"
    if [[ -n "$img_digest" ]]; then
        meta_digest="$img_digest"
    else
        log_warn "Could not resolve digest for $image; using metadata digest"
    fi

    # 4. Detect the precise human-readable mediatype label from the manifest.
    # WHY: _ci_get_manifest_type returns one of:
    #   docker-index | docker | oci-index | oci | image | unknown
    # This is stored as 'mediatype' (new field, exact/readable).
    # The coarse pipelinectl 'type' is derived separately below.
    local mediatype
    mediatype="$(_ci_get_manifest_type "$image" 2>/dev/null || echo "unknown")"


    log_info "Artifact name:      $image_without_tag"
    log_info "Artifact tag:       $meta_tag"
    log_info "Artifact digest:    $meta_digest"
    log_info "Artifact mediatype: $mediatype"
    log_info "Artifact sign:      $sign"

    if [[ $primary == "true" ]]; then
        for sign_reg in "${SIGN_REGISTRIES[@]}"; do
        [[ -z "$sign_reg" ]] && continue
            IFS=',' read -r reg prefix <<< "$sign_reg"
            local sign_image="${reg%/}${prefix:+/${prefix%/}}/${CONFIG[IMAGE_NAME]:-unnamed}"
            ci_store_artifact \
            --name      "$sign_image" \
            --value     "$sign_image" \
            --digest    "$meta_digest" \
            --size      "$meta_size" \
            --tag       "$meta_tag" \
            --arch      "${arch:-}" \
            --type      "image" \
            --mediatype "$mediatype" \
            --primary   "false" \
            --sign      "true"
        done
    fi
    ci_store_artifact \
        --name      "$image_without_tag" \
        --value     "$image_without_tag" \
        --digest    "$meta_digest" \
        --size      "$meta_size" \
        --tag       "$meta_tag" \
        --arch      "${arch:-}" \
        --type      "image" \
        --mediatype "$mediatype" \
        --primary   "$primary" \
        --sign      "$sign"
}


# ---------------------------------------------------------------------------
# _ci_build_display_name
# Purpose:
#   Construct a concise, display-ready image reference from a raw image name,
#   a separate tag field, and a separate digest field.
#
# Normalisation (applied before any assembly):
#   N1. Strip any embedded "@sha256:…" from name — digest is shown in its own
#       table column, so it must not appear in the display name.
#   N2. Shorten the path portion to the last two components only.
#       e.g. "icr.io/ns/wm-common/nginx:v1" → path becomes "wm-common/nginx",
#       tag ":v1" is preserved and re-attached after shortening.
#
# Assembly rules (applied in order after normalisation):
#   1. Name already carries a tag (":" present) → use as-is.
#   2. Bare name + non-empty tag              → "short-name:tag".
#   3. Bare name + empty tag                  → "short-name" (no suffix added).
#
# Inputs:
#   $1 - name   : raw image path (may carry :tag and/or @sha256:…)
#   $2 - tag    : tag string (may be empty)
#   $3 - digest : sha256:… string (unused for display; kept for API compatibility)
# Output:
#   prints the short display name to stdout
# WHY:
#   Digest is redundant in display name (separate column); full registry prefix
#   adds noise. Last two path components give enough context (namespace/image).
# ---------------------------------------------------------------------------
_ci_build_display_name() {
    local name="$1"
    local tag="$2"
    # $3 digest intentionally unused — shown in its own column

    # Strip leading/trailing whitespace (defensive)
    name="${name#"${name%%[! ]*}"}"; name="${name%"${name##*[! ]}"}"
    tag="${tag#"${tag%%[! ]*}"}";   tag="${tag%"${tag##*[! ]}"}"

    # N1. Remove any embedded digest ("@sha256:…") from name
    name="${name%%@sha256:*}"

    # N2. Split off the tag suffix before shortening the path, then re-attach.
    #     A ":" that appears after the last "/" is a tag, not a port number.
    local path_part tag_suffix=""
    if [[ "$name" == */* && "$name" =~ : ]]; then
        # Tag is after the last slash's component
        local after_last_slash="${name##*/}"
        if [[ "$after_last_slash" == *:* ]]; then
            tag_suffix=":${name##*:}"   # everything after the last ":"
            path_part="${name%:*}"      # everything before the last ":"
        else
            path_part="$name"
        fi
    elif [[ "$name" == *:* && "$name" != */* ]]; then
        # Simple "image:tag" with no slashes
        tag_suffix=":${name##*:}"
        path_part="${name%:*}"
    else
        path_part="$name"
    fi

    # Shorten path to last two components: "a/b/c/d" → "c/d"
    local short_path="$path_part"
    if [[ "$path_part" == */*/* ]]; then
        # Three or more components — keep only last two
        local last="${path_part##*/}"           # rightmost component
        local parent="${path_part%/*}"          # everything except rightmost
        local second_last="${parent##*/}"       # second-to-last component
        short_path="${second_last}/${last}"
    elif [[ "$path_part" == */* ]]; then
        # Exactly two components already — use as-is
        short_path="$path_part"
    fi
    # Single component (no slash) — short_path stays as path_part

    # Reassemble: use preserved tag suffix from the name if present,
    # otherwise fall back to the separate $tag argument.
    if [[ -n "$tag_suffix" ]]; then
        printf '%s%s' "$short_path" "$tag_suffix"
    elif [[ -n "$tag" ]]; then
        printf '%s:%s' "$short_path" "$tag"
    else
        printf '%s' "$short_path"
    fi
    return 0
}

# ---------------------------------------------------------------------------
# ci_read_artifacts_unified
# Purpose:
#   Unified artifact reader:
#   - Prefer IBM/pipelinectl list_artifacts + load_artifact
#   - Fallback to local artifact files (*.artifact)
#
# Output format (per line):
#   ARTIFACT_ID|DISPLAY_NAME|ARCH|DIGEST|SIZE|PRIMARY|TYPE|MEDIATYPE|SIGN|IMAGE_REF
#
# WHY:
#   This function replaces ci_list_local_artifacts() entirely.
#   All callers (summary, bundle updater, operator code) should use ONLY this.
#   Enhanced to include architecture, primary flag, artifact type, mediatype, sign flag,
#   and a full pullable IMAGE_REF used by the markdown renderer for manifest-list expansion.
# ---------------------------------------------------------------------------
ci_read_artifacts_unified() {
    local store="${1:-${ARTIFACT_STORE:-${SOURCE_DIR:-.}/artifacts}}"

    # 1. Try pipelinectl/list_artifacts first
    if command -v list_artifacts >/dev/null 2>&1 && \
       command -v load_artifact >/dev/null 2>&1; then

        for art_id in $(list_artifacts 2>/dev/null || true); do
            local artifact_name image digest size arch tag primary type mediatype sign

            artifact_name="$(load_artifact "$art_id" name      2>/dev/null || echo "")"
            digest="$(       load_artifact "$art_id" digest    2>/dev/null || echo "")"
            size="$(         load_artifact "$art_id" size      2>/dev/null || echo "")"
            tag="$(          load_artifact "$art_id" tag       2>/dev/null || echo "")"
            primary="$(      load_artifact "$art_id" primary   2>/dev/null || echo "false")"
            sign="$(         load_artifact "$art_id" sign      2>/dev/null || echo "false")"
            type="$(         load_artifact "$art_id" type      2>/dev/null || echo "")"
            mediatype="$(    load_artifact "$art_id" mediatype 2>/dev/null || echo "")"

            # Try to load architecture directly from artifact
            arch="$(load_artifact "$art_id" architecture 2>/dev/null || echo "")"

            # If not available, extract from artifact ID or detect from system
            if [[ -z "$arch" || "$arch" == "unknown" ]]; then
                if [[ "$art_id" =~ -(amd64|arm64|arm|ppc64le|s390x|386|riscv64)$ ]]; then
                    arch="${BASH_REMATCH[1]}"
                else
                    case "$(uname -m)" in
                        x86_64)  arch="amd64"  ;;
                        aarch64) arch="arm64"  ;;
                        s390x)   arch="s390x"  ;;
                        ppc64le) arch="ppc64le";;
                        *)       arch=""       ;;
                    esac
                fi
            fi

            # Output format: ARTIFACT_ID|DISPLAY_NAME|ARCH|DIGEST|SIZE|PRIMARY|TYPE|MEDIATYPE|SIGN|IMAGE_REF
            local display_name image_ref
            display_name="$(_ci_build_display_name "$artifact_name" "$tag" "$digest")"
            # Build a digest-pinned ref (repo@sha256:…) for manifest-list expansion.
            # This is stable — immune to tag re-pointing between artifact-save and render.
            # Strip any @sha256:… and :tag already embedded in artifact_name first.
            local _name_bare="${artifact_name%%@*}"; _name_bare="${_name_bare%%:*}"
            if [[ "$digest" == sha256:* ]]; then
                image_ref="${_name_bare}@${digest}"
            else
                image_ref="${_name_bare}"
            fi

            if [[ -n "$artifact_name" ]]; then
                printf '%s|%s|%s|%s|%s|%s|%s|%s|%s|%s\n' \
                    "$art_id" "$display_name" "$arch" "$digest" "$size" "$primary" "$type" "$mediatype" "$sign" "$image_ref"
            fi
        done
        return 0
    fi

    # 2. Local fallback: read *.artifact files
    if [[ -d "$store" ]]; then
        shopt -s nullglob
        for f in "$store"/*.artifact; do
            [[ -f "$f" ]] || continue

            local NAME="" IMAGE="" TAG="" DIGEST="" SIZE="" ARCH="" PRIMARY="false" SIGN="false" TYPE="" MEDIATYPE=""
            while IFS= read -r ln; do
                case "$ln" in
                    IMAGE_NAME=*)   NAME="${ln#IMAGE_NAME=}";     NAME="${NAME%\"}";         NAME="${NAME#\"}"         ;;
                    IMAGE=*)        IMAGE="${ln#IMAGE=}";          IMAGE="${IMAGE%\"}";       IMAGE="${IMAGE#\"}"       ;;
                    TAG=*)          TAG="${ln#TAG=}";              TAG="${TAG%\"}";           TAG="${TAG#\"}"           ;;
                    DIGEST=*)       DIGEST="${ln#DIGEST=}";        DIGEST="${DIGEST%\"}";     DIGEST="${DIGEST#\"}"     ;;
                    SIZE=*)         SIZE="${ln#SIZE=}";            SIZE="${SIZE%\"}";         SIZE="${SIZE#\"}"         ;;
                    ARCHITECTURE=*) ARCH="${ln#ARCHITECTURE=}";   ARCH="${ARCH%\"}";         ARCH="${ARCH#\"}"         ;;
                    PRIMARY=*)      PRIMARY="${ln#PRIMARY=}";      PRIMARY="${PRIMARY%\"}";   PRIMARY="${PRIMARY#\"}"   ;;
                    SIGN=*)         SIGN="${ln#SIGN=}";            SIGN="${SIGN%\"}";         SIGN="${SIGN#\"}"         ;;
                    TYPE=*)         TYPE="${ln#TYPE=}";            TYPE="${TYPE%\"}";         TYPE="${TYPE#\"}"         ;;
                    MEDIATYPE=*)    MEDIATYPE="${ln#MEDIATYPE=}";  MEDIATYPE="${MEDIATYPE%\"}"; MEDIATYPE="${MEDIATYPE#\"}" ;;
                esac
            done < "$f"

            [[ -z "$ARCH" ]]    && ARCH=""
            [[ -z "$PRIMARY" ]] && PRIMARY="false"
            [[ -z "$SIGN" ]]    && SIGN="false"

            # Output format: ARTIFACT_ID|DISPLAY_NAME|ARCH|DIGEST|SIZE|PRIMARY|TYPE|MEDIATYPE|SIGN|IMAGE_REF
            local DISPLAY_NAME IMAGE_REF
            DISPLAY_NAME="$(_ci_build_display_name "$IMAGE" "$TAG" "$DIGEST")"
            # Build a digest-pinned ref (repo@sha256:…) for manifest-list expansion.
            # This is stable — immune to tag re-pointing between artifact-save and render.
            # Strip any @sha256:… and :tag already embedded in IMAGE first.
            local _img_bare="${IMAGE%%@*}"; _img_bare="${_img_bare%%:*}"
            if [[ "$DIGEST" == sha256:* ]]; then
                IMAGE_REF="${_img_bare}@${DIGEST}"
            else
                IMAGE_REF="${_img_bare}"
            fi

            [[ -n "$NAME" || -n "$IMAGE" ]] && \
            printf '%s|%s|%s|%s|%s|%s|%s|%s|%s|%s\n' \
                "$f" "$DISPLAY_NAME" "$ARCH" "$DIGEST" "$SIZE" "$PRIMARY" "$TYPE" "$MEDIATYPE" "$SIGN" "$IMAGE_REF"
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
#   GITHUB_BUILD_SUMMARY via set_env. Only renders artifacts with primary=true.
# Inputs:
#   $1 - title
#   $2 - array of artifact lines (ARTIFACT_ID|DISPLAY_NAME|ARCH|DIGEST|SIZE|PRIMARY|TYPE|MEDIATYPE|SIGN|IMAGE_REF)
# Output:
#   prints path to markdown summary file
# Table format: | Image | Type | Digest | Size |
#   Type column shows the mediatype value (docker/oci/docker-index/oci-index/image/unknown).
#   For index types (oci-index, docker-index) the index image row is followed by one
#   additional row per architecture inside the SAME table. Each manifest row reuses the
#   index image name, type, and size — only Arch and Digest differ (taken from
#   ci_list_manifest_architectures). No secondary tables or sub-sections are emitted.
# WHY:
#   Keeping a single flat table preserves readability and tool compatibility (GitHub
#   summary renderer, CSV imports). Arch+Digest per manifest improves traceability
#   without breaking the table structure.
# ---------------------------------------------------------------------------
ci_render_summary_markdown() {
    local title="$1"
    shift
    local -a lines=("$@")

    local summary_file
    if command -v ci_create_temp_file >/dev/null 2>&1; then
        summary_file="$(ci_create_temp_file "github_step_summary")"
    else
        summary_file="$(mktemp --tmpdir "${TMPDIR:-/tmp}/github_step_summary.XXXXXX")"
        chmod 600 "$summary_file"
    fi

    printf '## %s\n\n' "$title" > "$summary_file"
    printf '| Image | Type | Arch | Digest | Size |\n' >> "$summary_file"
    printf '|-------|------|------|--------|------|\n' >> "$summary_file"

    local ld artifact_id display_name arch digest size primary type mediatype sign image_ref
    for ld in "${lines[@]:-}"; do
        # Format: ARTIFACT_ID|DISPLAY_NAME|ARCH|DIGEST|SIZE|PRIMARY|TYPE|MEDIATYPE|SIGN|IMAGE_REF (10 fields)
        IFS='|' read -r artifact_id display_name arch digest size primary type mediatype sign image_ref <<< "$ld"

        [[ "$primary" != "true" ]] && continue

        local display_type="${mediatype:-${type:-}}"

        # Index image: one row for the index itself (arch/digest from artifact metadata)
        printf '| `%s` | %s | %s | `%s` | %s |\n' \
            "$display_name" "$display_type" "${arch:-}" "${digest:-N/A}" "${size:-N/A}" >> "$summary_file"

        # For index types, add one row per manifest in the SAME table.
        # Each manifest row keeps Image/Size from the index; Arch and Digest come from the
        # manifest entry. Type is the single-platform equivalent: docker-index→docker, oci-index→oci.
        if [[ "$display_type" == "oci-index" || "$display_type" == "docker-index" ]]; then
            local manifest_type
            [[ "$display_type" == "docker-index" ]] && manifest_type="docker" || manifest_type="oci"
            local ref_to_query="${image_ref:-$display_name}"
            if [[ -n "$ref_to_query" ]]; then
                local manifest_lines
                manifest_lines="$(ci_list_manifest_architectures "$ref_to_query" 2>/dev/null || true)"
                if [[ -n "$manifest_lines" ]]; then
                    while IFS='|' read -r m_arch m_digest; do
                        [[ -z "$m_arch" && -z "$m_digest" ]] && continue
                        printf '| `%s` | %s | %s | `%s` | %s |\n' \
                            "$display_name" "$manifest_type" "${m_arch:-unknown}" "${m_digest:-N/A}" "${size:-N/A}" >> "$summary_file"
                    done <<< "$manifest_lines"
                fi
            fi
        fi
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
#   Render artifact lines to CSV and print path to file. Only renders artifacts
#   with primary=true.
# Inputs:
#   $1 - title (unused for CSV)
#   rest - artifact lines (ARTIFACT_ID|DISPLAY_NAME|ARCH|DIGEST|SIZE|PRIMARY|TYPE|MEDIATYPE|SIGN)
# Output:
#   prints path to CSV file
# Columns: index, image, type, arch, digest, size
#   type column value is mediatype (docker/oci/docker-index/oci-index/image/unknown).
# WHY:
#   Only primary=true artifacts are rendered. mediatype is used as the type column
#   value because it is more precise than the coarse pipelinectl type field.
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

    printf 'index,image,type,arch,digest,size\n' > "$tmp"
    local i=1 ld display_name arch digest size primary type mediatype sign _image_ref
    for ld in "${lines[@]:-}"; do
        IFS='|' read -r _ display_name arch digest size primary type mediatype sign _image_ref <<< "$ld"

        [[ "$primary" != "true" ]] && continue

        local display_type="${mediatype:-${type:-}}"
        display_name="${display_name//\"/\"\"}"
        display_type="${display_type//\"/\"\"}"
        arch="${arch//\"/\"\"}"
        digest="${digest//\"/\"\"}"
        size="${size//\"/\"\"}"
        printf '%d,"%s","%s","%s","%s","%s"\n' \
            "$i" "$display_name" "$display_type" "${arch:-}" "$digest" "$size" >> "$tmp"
        i=$((i+1))
    done
    printf '%s\n' "$tmp"
    return 0
}

# ---------------------------------------------------------------------------
# ci_render_summary_json
# Purpose:
#   Render artifact lines to JSON array and print path to file. Only renders
#   artifacts with primary=true.
# Inputs:
#   $1 - title (unused)
#   rest - artifact lines (ARTIFACT_ID|DISPLAY_NAME|ARCH|DIGEST|SIZE|PRIMARY|TYPE|MEDIATYPE|SIGN)
# Output:
#   prints path to JSON file
# Fields: artifact, image, type, arch, digest, size
#   type field value is mediatype (docker/oci/docker-index/oci-index/image/unknown).
# WHY:
#   Only primary=true artifacts are rendered. mediatype is used as the type field
#   value because it is more precise than the coarse pipelinectl type field.
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
    local first=true ld id display_name arch digest size primary type mediatype sign _image_ref
    for ld in "${lines[@]:-}"; do
        IFS='|' read -r id display_name arch digest size primary type mediatype sign _image_ref <<< "$ld"

        [[ "$primary" != "true" ]] && continue

        local display_type="${mediatype:-${type:-}}"
        display_name="${display_name//\\/\\\\}"; display_name="${display_name//\"/\\\"}"
        display_type="${display_type//\\/\\\\}"; display_type="${display_type//\"/\\\"}"
        arch="${arch:-}";  arch="${arch//\\/\\\\}";  arch="${arch//\"/\\\"}"
        digest="${digest//\\/\\\\}";            digest="${digest//\"/\\\"}"
        size="${size//\\/\\\\}";                size="${size//\"/\\\"}"
        if [[ "$first" == true ]]; then
            first=false
        else
            printf ',\n' >> "$tmp"
        fi
        printf '  {"artifact":"%s","image":"%s","type":"%s","arch":"%s","digest":"%s","size":"%s"}' \
            "$id" "$display_name" "$display_type" "$arch" "$digest" "$size" >> "$tmp"
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
