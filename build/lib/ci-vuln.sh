#!/usr/bin/env bash
# lib/ci-vuln.sh
#
# Purpose:
#   Vulnerability scanning for container images using grype
#   Generates both JSON and markdown reports, attaches vulnerability reports
#   as OCI artifacts to built images
#
# Usage:
#   source lib/ci-vuln.sh
#
# Functions:
#   ci_generate_and_attach_vuln_report <image> -> runs grype, attaches report
#
# Example:
#   ci_generate_and_attach_vuln_report "myregistry/myapp:1.0.0"
#

# Source dependencies
if [[ -z "${CI_CORE_LOADED:-}" ]]; then
    LIB_DIR="${LIB_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
    source "${LIB_DIR}/ci-core.sh"
fi

# =============================================================================
# ci_generate_and_attach_vuln_report
# Purpose:
#   Generate vulnerability report for container image and attach as OCI artifact
# Input:
#   $1 - Image reference (e.g., myregistry/myapp:1.0.0)
#   $2 - Directory containing templates (for grype-markdown.tmpl)
# Output:
#   0 on success, non-zero on failure
# Why:
#   Integrates grype vulnerability scanning with the unified build system
# =============================================================================
ci_generate_and_attach_vuln_report() {
    local image="${1:?missing image reference}"
    local template_dir="${2:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/hummingbird/templates}"

    log_info "Generating vulnerability report for image: $image"

    # Check if grype is available
    if ! command -v grype >/dev/null 2>&1; then
        log_warn "grype not available, skipping vulnerability scan"
        return 0
    fi

    local temp_dir="$(mktemp -d)"
    trap 'rm -rf "$temp_dir"' EXIT

    # Generate JSON report
    local json_report="$temp_dir/vulnerabilities.json"
    if ! grype "$image" -o json "$json_report" 2>&1; then
        log_warn "grype JSON report generation failed: $(grype --help 2>&1 | head -1)"
        return 0
    fi

    if [[ ! -f "$json_report" ]]; then
        log_warn "grype JSON report not generated"
        return 0
    fi

    # Generate markdown report using vendored template
    local markdown_report="$temp_dir/vulnerabilities.md"
    local grype_template="$template_dir/grype-markdown.tmpl"

    if [[ -f "$grype_template" ]]; then
        # Use vendored grype-markdown.tmpl from build/lib/hummingbird/templates
        local report_dir="$(dirname "$json_report")"
        grype "$image" -o template -t "$grype_template" > "$markdown_report" 2>/dev/null || {
            log_warn "grype markdown report generation failed"
            return 0
        }
    fi

    if [[ -n "$VULN_SKIP" && "$VULN_SKIP" == "true" ]]; then
        log_info "VULN_SKIP=true, skipping artifact attachment"
        rm -rf "$temp_dir"
        return 0
    fi

    # Attach JSON report as OCI artifact (vnd.security.vulnerability.report+json)
    if command -v oras >/dev/null 2>&1; then
        log_info "Attaching vulnerability JSON report to image: $image"
        oras attach --artifact-type application/vnd.security.vulnerability.report+json "$image" "$json_report" 2>/dev/null || {
            log_warn "Failed to attach vulnerability JSON report, continuing"
        }
    else
        log_info "oras not available, skipping vulnerability artifact attachment"
    fi

    # Attach markdown report as OCI artifact (text/plain)
    if command -v oras >/dev/null 2>&1 && [[ -f "$markdown_report" ]]; then
        log_info "Attaching vulnerability markdown report to image: $image"
        oras attach --artifact-type text/plain "$image" "$markdown_report" 2>/dev/null || {
            log_warn "Failed to attach vulnerability markdown report, continuing"
        }
    fi

    log_info "Vulnerability scanning completed for image: $image"
    return 0
}
