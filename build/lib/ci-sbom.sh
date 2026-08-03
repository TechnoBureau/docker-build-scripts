#!/usr/bin/env bash
# lib/ci-sbom.sh
#
# Purpose:
#   SBOM (Software Bill of Materials) generation and attachment for container images
#   Supports Syft, Trivy, and Docker Scout for SBOM generation
#   Attaches SBOM to images for Prisma Cloud and other security scanners
#
# Usage:
#   source lib/ci-sbom.sh
#
# Functions:
#   ci_generate_sbom <image> [format] -> generates SBOM file
#   ci_attach_sbom <image> <sbom_file> -> attaches SBOM to image
#   ci_generate_and_attach_sbom <image> -> complete workflow
#
# Example:
#   ci_generate_and_attach_sbom "myregistry/myapp:1.0.0"
#

# Source dependencies
if [[ -z "${CI_CORE_LOADED:-}" ]]; then
    LIB_DIR="${LIB_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
    # shellcheck source=/dev/null
    source "${LIB_DIR}/ci-core.sh"
fi

# =============================================================================
# ci_detect_sbom_tool
# Purpose:
#   Detect available SBOM generation tool
# Output:
#   Prints tool name (syft, trivy, docker-scout) or empty if none found
# =============================================================================
ci_detect_sbom_tool() {
    if command -v syft >/dev/null 2>&1; then
        echo "syft"
    elif command -v trivy >/dev/null 2>&1; then
        echo "trivy"
    elif docker scout version >/dev/null 2>&1; then
        echo "docker-scout"
    else
        echo ""
    fi
}

# =============================================================================
# ci_generate_sbom
# Purpose:
#   Generate SBOM for container image using available tool
# Input:
#   $1 - Image reference (e.g., myregistry/myapp:1.0.0)
#   $2 - Format (optional: spdx-json, cyclonedx-json, syft-json) default: spdx-json
# Output:
#   Prints path to generated SBOM file
# Returns:
#   0 on success, 1 on failure
# =============================================================================
ci_generate_sbom() {
    local image="${1:?missing image reference}"
    local format="${2:-spdx-json}"
    local tool
    local sbom_file
    local engine
    
    tool=$(ci_detect_sbom_tool)
    if [[ -z "$tool" ]]; then
        log_warn "No SBOM tool found (syft, trivy, or docker scout). Skipping SBOM generation."
        return 1
    fi
    
    engine="$(detect_container_engine 2>/dev/null || echo docker)"
    sbom_file="$(ci_create_temp_file "sbom")"
    
    log_info "Generating SBOM for $image using $tool (format: $format)"
    
    case "$tool" in
        syft)
            # Syft supports multiple formats
            case "$format" in
                spdx-json)
                    syft "$image" -o spdx-json > "$sbom_file" 2>/dev/null || {
                        log_error "Syft SBOM generation failed"
                        return 1
                    }
                    ;;
                cyclonedx-json)
                    syft "$image" -o cyclonedx-json > "$sbom_file" 2>/dev/null || {
                        log_error "Syft SBOM generation failed"
                        return 1
                    }
                    ;;
                syft-json)
                    syft "$image" -o syft-json > "$sbom_file" 2>/dev/null || {
                        log_error "Syft SBOM generation failed"
                        return 1
                    }
                    ;;
                *)
                    log_warn "Unknown format $format, using spdx-json"
                    syft "$image" -o spdx-json > "$sbom_file" 2>/dev/null || {
                        log_error "Syft SBOM generation failed"
                        return 1
                    }
                    ;;
            esac
            ;;
            
        trivy)
            # Trivy SBOM generation
            case "$format" in
                spdx-json)
                    trivy image --format spdx-json --output "$sbom_file" "$image" >/dev/null 2>&1 || {
                        log_error "Trivy SBOM generation failed"
                        return 1
                    }
                    ;;
                cyclonedx-json|cyclonedx)
                    trivy image --format cyclonedx --output "$sbom_file" "$image" >/dev/null 2>&1 || {
                        log_error "Trivy SBOM generation failed"
                        return 1
                    }
                    ;;
                *)
                    log_warn "Unknown format $format, using spdx-json"
                    trivy image --format spdx-json --output "$sbom_file" "$image" >/dev/null 2>&1 || {
                        log_error "Trivy SBOM generation failed"
                        return 1
                    }
                    ;;
            esac
            ;;
            
        docker-scout)
            # Docker Scout SBOM
            docker scout sbom "$image" --format spdx --output "$sbom_file" >/dev/null 2>&1 || {
                log_error "Docker Scout SBOM generation failed"
                return 1
            }
            ;;
            
        *)
            log_error "Unknown SBOM tool: $tool"
            return 1
            ;;
    esac
    
    if [[ ! -f "$sbom_file" || ! -s "$sbom_file" ]]; then
        log_error "SBOM file not generated or empty"
        return 1
    fi
    
    log_success "SBOM generated: $sbom_file ($(wc -c < "$sbom_file") bytes)"
    echo "$sbom_file"
    return 0
}

# =============================================================================
# ci_attach_sbom
# Purpose:
#   Attach SBOM to container image as OCI artifact or annotation
# Input:
#   $1 - Image reference
#   $2 - SBOM file path
# Returns:
#   0 on success, 1 on failure
# WHY:
#   Security scanners expect SBOM to be attached to image as OCI artifact or attestation
# =============================================================================
ci_attach_sbom() {
    local image="${1:?missing image reference}"
    local sbom_file="${2:?missing SBOM file}"
    local engine
    
    if [[ ! -f "$sbom_file" ]]; then
        log_error "SBOM file not found: $sbom_file"
        return 1
    fi
    
    engine="$(detect_container_engine 2>/dev/null || echo docker)"
    
    log_info "Attaching SBOM to image $image"
    
    # WHY: Try native attestation methods that embed SBOM in image metadata
    # These do NOT create separate registry entries or artifacts
    if ci_attach_sbom_attestation "$image" "$sbom_file"; then
        return 0
    fi
    
    # WHY: If native attestation fails, save as local artifact for manual attachment
    # This is a fallback only - SBOM should be attached to image when possible
    local artifact_dir="${ARTIFACT_DIR:-./artifacts}"
    mkdir -p "$artifact_dir"
    
    local image_name
    image_name=$(echo "$image" | tr '/:' '_')
    local sbom_artifact="${artifact_dir}/${image_name}_sbom.json"
    
    cp "$sbom_file" "$sbom_artifact" && {
        log_warn "SBOM saved as local artifact (native attachment not available): $sbom_artifact"
        log_info "To attach manually: cosign attest --predicate $sbom_artifact --type spdxjson $image"
        
        # Export for CI/CD pipeline
        if command -v set_env >/dev/null 2>&1; then
            set_env "SBOM_FILE" "$sbom_artifact" 2>/dev/null || true
        fi
        export SBOM_FILE="$sbom_artifact"
        
        return 0
    }
    
    log_error "Could not attach or save SBOM"
    return 1
}

# =============================================================================
# ci_generate_and_attach_sbom
# Purpose:
#   Complete SBOM workflow: generate and attach
# Input:
#   $1 - Image reference
#   $2 - Format (optional)
# Returns:
#   0 on success, 1 on failure
# =============================================================================
ci_generate_and_attach_sbom() {
    local image="${1:?missing image reference}"
    local format="${2:-spdx-json}"
    local sbom_file
    
    # Generate SBOM
    sbom_file=$(ci_generate_sbom "$image" "$format") || {
        log_warn "SBOM generation failed for $image"
        return 1
    }
    
    # Attach SBOM
    ci_attach_sbom "$image" "$sbom_file" || {
        log_warn "SBOM attachment failed for $image"
        return 1
    }
    
    log_success "SBOM workflow completed for $image"
    return 0
}

# =============================================================================
# ci_attach_sbom_attestation
# Purpose:
#   Attach SBOM as native Docker/OCI attestation (in-toto format)
# Input:
#   $1 - Image reference
#   $2 - SBOM file path
# Returns:
#   0 on success, 1 on failure
# WHY:
#   Native attestations are the standard way to attach SBOM to images
#   Creates a separate attestation manifest, not a new image entry
# =============================================================================
ci_attach_sbom_attestation() {
    local image="${1:?missing image reference}"
    local sbom_file="${2:?missing SBOM file}"
    local engine
    
    if [[ ! -f "$sbom_file" ]]; then
        log_error "SBOM file not found: $sbom_file"
        return 1
    fi
    
    engine="$(detect_container_engine 2>/dev/null || echo docker)"
    
    log_info "Attaching SBOM as native attestation to $image"
    
    # Method 1: Docker buildx attestation (embeds in image metadata)
    if [[ "$engine" == "docker" ]] && docker buildx version >/dev/null 2>&1; then
        log_info "Using Docker buildx to embed SBOM attestation"
        
        # WHY: Docker buildx embeds attestation in image manifest annotations
        # No separate registry entry created - attestation is part of image metadata
        docker buildx imagetools create \
            --annotation "sbom=$(cat "$sbom_file")" \
            "$image" >/dev/null 2>&1 && {
            log_success "SBOM embedded in image metadata via Docker buildx"
            return 0
        }
        log_warn "Docker buildx attestation failed, trying cosign"
    fi
    
    # Method 2: Cosign attestation (linked attestation, minimal overhead)
    if command -v cosign >/dev/null 2>&1; then
        log_info "Using cosign to attach SBOM attestation"
        
        # WHY: Cosign creates a cryptographically signed attestation
        # Stored as: <image>:sha256-<digest>.att (attestation reference, not a full image)
        # Minimal registry overhead, standard OCI attestation format
        cosign attest --yes \
            --predicate "$sbom_file" \
            --type spdxjson \
            "$image" >/dev/null 2>&1 && {
            log_success "SBOM attached as cosign attestation"
            return 0
        }
        log_warn "Cosign attestation failed"
    fi
    
    log_info "Native attestation tools not available (install docker buildx or cosign)"
    return 1
}

# Export functions
export -f ci_detect_sbom_tool
export -f ci_generate_sbom
export -f ci_attach_sbom
export -f ci_attach_sbom_attestation
export -f ci_generate_and_attach_sbom
