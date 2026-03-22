#!/usr/bin/env bash
# lib/ci-promote.sh
#
# PURPOSE: Image promotion (copy) with digest/manifest/signature preservation.
# USAGE: source lib/ci-promote.sh && ci_promote_image <source@digest> <dest_reg> <prefix> [tag]
# EXAMPLE: ci_promote_image "icr.io/org/image@sha:abc" "ecr.com" "myorg" "v1.20.1"
# INTEGRATION: Called from parallel promote; ECR auto-create via ci-ecr.sh.
# EXTENSION: Add --dry-run flag; dispatch for ACR/GCR via ci_copy_image generic.


[[ -n "${CI_PROMOTE_LOADED:-}" ]] && return 0

declare -g CI_PROMOTE_LOADED=1

LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${LIB_DIR}/ci-core.sh"
source "${LIB_DIR}/ci-registry.sh"
source "${LIB_DIR}/ci-ecr.sh" 2>/dev/null || true  # Idempotent
source "${LIB_DIR}/ci-artifacts.sh" 2>/dev/null || true  # For artifact saving
# shellcheck source=/dev/null
source "${LIB_DIR}/ci-utils.sh" 2>/dev/null || true

# ————————————————————————————————————————————————————————————————————————————————
# ci_promote_image
# ————————————————————————————————————————————————————————————————————————————————
# PURPOSE: Copy image cross-registry; preserves @digest, multi-arch, signatures.
# INPUTS: $1=source_image (full@digest), $2=dest_registry, $3=dest_prefix, $4=dest_tag (opt)
# OUTPUTS: Logs full dest ref; returns 0/1. Tags dest if $4 provided.
# FIXES: Uses $4 for precise tagging; robust image_name extract (handles paths/tags).
# EXTENSION: Fallback tag=${CONFIG[VERSION]:-latest} if $4 empty.
# ————————————————————————————————————————————————————————————————————————————————
# Updated ci_promote_image signature/params (full function; replace existing)
# WHY: Separate $4=image_name, $5=dest_tag (from worker); avoids re-parsing.
#      full_dest now: reg / prefix / image_name : dest_tag (correct: ecr/org/pipelines-controller-rhel9:v1.20.1)
#      ECR call: Uses passed image_name (no extraction bug).

# Updated ci_promote_image (full function; replace existing)
# WHY: $6=source_registry (input-passed; used directly for login, no extract). Modular: Optional $7=version (for future use, e.g., label injection).
#      Tagging: Uses passed $5=dest_tag (from worker's BUNDLE_VERSION/CONFIG); agnostic to CI (env/CONFIG fallback in caller).
#      Login: Direct "$source_registry" (e.g., "icr.io/ipaas-non-prod/wm-int" → ci_login_to_registry handles base).
#      EXTENSION: $7=version → inject as label in skopeo (e.g., --label "version=$7").
ci_promote_image() {
    local source_image="$1"
    local dest_registry="$2"
    local dest_prefix="${3:-}"
    local image_name="$4"        # e.g., "pipelines-controller-rhel9"
    local dest_tag="$5"          # e.g., "v1.20.1" or "latest"
    local source_registry="$6"   # Passed input (e.g., "icr.io/ipaas-non-prod/wm-int")

    [[ -z "$source_image" || -z "$dest_registry" || -z "$image_name" || -z "$dest_tag" || -z "$source_registry" ]] && {
        log_error "ci_promote_image: Missing core args (source, reg, image_name, dest_tag, source_registry)"
        return 1
    }

    command -v skopeo >/dev/null 2>&1 || { log_error "skopeo unavailable"; return 1; }

    # Login: Use passed source_registry directly (handles path; ci_login_to_registry extracts base if needed)
    ci_login_to_registry "$source_registry" || log_warn "Source login skipped (anonymous may work)"
    ci_login_to_registry "$dest_registry" || return 1

    # === ECR PREP: prefix + image_name (precise; e.g., "openshift-pipelines/pipelines-controller-rhel9") ===
    ci_ensure_ecr_repository "$dest_registry" "$dest_prefix" "$image_name" || log_warn "ECR prep skipped"

    # Build full_dest (uniform: reg/prefix/image_name:dest_tag)
    local full_dest="${dest_registry}/${dest_prefix:+${dest_prefix}/}${image_name}:${dest_tag}"
    local authfile="$(ci_resolve_authfile || true)"

    log_info "Promoting ${source_image} → ${full_dest} (digests + signatures)"

    local skopeo_args=(--all --preserve-digests)
    [[ -n "$authfile" ]] && skopeo_args+=(--authfile "$authfile")

    if skopeo copy "${skopeo_args[@]}" "docker://${source_image}" "docker://${full_dest}" >/dev/null 2>&1; then
        log_success "Promoted → ${full_dest}"
    else
        log_error "Copy failed → ${full_dest}"
        return 1
    fi

    # Signatures (non-blocking; per full_dest)
    if command -v cosign >/dev/null 2>&1; then
        cosign copy "${source_image}" "${full_dest}" >/dev/null 2>&1 && \
            log_info "Signatures copied → ${full_dest}" || \
            log_warn "Signature copy failed → ${full_dest} (non-critical)"
    fi

    # === ARTIFACT SAVE ===
    # WHY: Save promoted image artifact for downstream stages (similar to build_and_push)
    # Only save artifact if ci_store_artifact function is available
    ci_store_artifact "${full_dest}" || log_warn "Failed to save artifact for ${full_dest}"

    #### Collect SBOM as part of Promotion as well
    # Generate SBOM
    local sbom_file
    sbom_file=$(generate_sbom "${full_dest}")
    if [[ -n "$sbom_file" && -f "$sbom_file" ]]; then
        log_info "SBOM: $sbom_file"
        ci_collect_sbom_evidence "$sbom_file" "${full_dest}"
    elif [[ -n "$sbom_file" ]]; then
        log_warn "SBOM generation reported file '$sbom_file' but it was not found on disk"
    else
        log_warn "SBOM generation failed"
    fi
    ####

    return 0
}
export -f ci_promote_image
