# Updated lib/ci-ecr.sh (minor: idempotent sourcing, robust parsing; no functional changes needed)
#!/usr/bin/env bash
# lib/ci-ecr.sh
# PURPOSE: ECR repo auto-create (best-effort; for all registries in loops).
# USAGE: ci_ensure_ecr_repository <reg> <prefix> <image_name>
# EXAMPLE: ci_ensure_ecr_repository "ecr.com" "org" "image" → "org/image"
# FIXES: Handles empty prefix (just image_name); MUTABLE tags default.
# EXTENSION: Add --immutable flag via $4; multi-region via env REGION.

LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[[ -n "${CI_ECR_LOADED:-}" ]] && return 0
declare -g CI_ECR_LOADED=1

if [[ -z "${CI_CORE_LOADED:-}" ]]; then
    source "${LIB_DIR}/ci-core.sh" 2>/dev/null
fi

# WHY: Load registry module for AWS credential resolution and login
if [[ -z "${CI_REGISTRY_LOADED:-}" ]]; then
    source "${LIB_DIR}/ci-registry.sh" 2>/dev/null
fi

# ————————————————————————————————————————————————————————————————————————————————
# ci_ensure_ecr_repository
# ————————————————————————————————————————————————————————————————————————————————
# PURPOSE: Create ECR repo if missing (handles 404); scanning enabled.
# INPUTS: $1=registry, $2=prefix (opt), $3=image_name
# OUTPUTS: Logs status; returns 0 (skip/exists/create), 1 (fail, non-blocking).
# FIXES: Robust repo_name (empty prefix → no /); aws check early.
# EXTENSION: $4=mutability (MUTABLE/IMMU); dispatch in ci_ensure_repository.
# ————————————————————————————————————————————————————————————————————————————————
# WHY: Explicit log with full repo_name (e.g., "openshift-pipelines/pipelines-controller-rhel9").
#      Handles empty prefix gracefully (repo_name=image_name only).

ci_ensure_ecr_repository() {
    local registry="$1"
    local prefix="$2"
    local image_name="${3:-}"
    local mutability="${4:-MUTABLE}"

    log_info "Registry=$registry, prefix=$prefix , image_name=$image_name"

    # WHY: Enhanced ECR registry detection - supports both standard and FIPS endpoints
    # Matches: 123456789012.dkr.ecr.us-east-1.amazonaws.com
    #          123456789012.dkr.ecr-fips.us-east-1.amazonaws.com
    if ! [[ "$registry" =~ ^[0-9]{12}\.dkr\.ecr(-fips)?\.([a-z0-9-]+)\.amazonaws\.com$ ]]; then
        log_info "Not an ECR registry - $registry"
        return 0
    fi

    [[ -z "$image_name" ]] && { log_info "Image Name required to check and create ECR repo "; return 0; }

    # WHY: Extract region from regex match - BASH_REMATCH[2] contains region (after optional -fips)
    local region="${BASH_REMATCH[2]}"
    local repo_name="${prefix:+${prefix}/}${image_name}"
    [[ -z "$repo_name" ]] && { log_error "Empty repo_name (prefix: ${prefix}, image: ${image_name})"; return 1; }

    command -v aws >/dev/null 2>&1 || { log_info "aws unavailable → skip ECR ${repo_name}"; return 0; }

    # --- AWS CREDENTIAL RESOLUTION AND LOGIN START ---
    local creds access_key secret_key aws_env_prefix
    creds="$(ci_get_raw_aws_credentials "$registry" 2>/dev/null || true)"

    if [[ -n "$creds" ]]; then
        # WHY: Extract access key and secret key from credentials
        access_key="${creds%%:*}"
        secret_key="${creds#*:}"

        # WHY: Authenticate to AWS using modular ci_aws_login function (validates credentials)
        log_info "Logging into AWS with provided credentials...(access_key=${access_key})"
        if ! ci_aws_login "$access_key" "$secret_key" "$region"; then
            log_warn "AWS authentication failed. Unable to locate credentials or invalid keys."
            log_warn "Please ensure credentials are valid: user_<registry>=AKIA... and password_<registry>=..."
            return 0
        fi
        log_info "AWS authentication successful"
        
        # WHY: Build environment variable prefix for inline credential passing to AWS CLI commands
        aws_env_prefix="AWS_ACCESS_KEY_ID='$access_key' AWS_SECRET_ACCESS_KEY='$secret_key' AWS_DEFAULT_REGION='$region'"
    else
        # WHY: No explicit credentials - check if already logged in (IAM Role/Instance Profile)
        log_info "No explicit credentials found. Checking for existing IAM Role/Env configuration..."

        # WHY: Validate existing AWS credentials (IAM role or environment)
        if ! aws sts get-caller-identity --region "$region" >/dev/null 2>&1; then
            log_warn "AWS authentication failed. No credentials found and no IAM role available."
            log_warn "Configure credentials via environment variables or use IAM role."
            return 0
        fi
        log_info "Using existing AWS credentials (IAM role or environment)"
        
        # WHY: Use empty prefix - AWS CLI will use default credentials (IAM role or environment)
        aws_env_prefix=""
    fi

    # --- AWS CREDENTIAL RESOLUTION AND LOGIN END ---

    # WHY: Check if repository exists using inline credentials (no export)
    if eval "${aws_env_prefix} aws ecr describe-repositories --region '$region' --repository-names '$repo_name' >/dev/null 2>&1"; then
        log_info "ECR exists: ${repo_name} (${region})"
        return 0
    fi

    log_info "Creating ECR: ${repo_name} (${region})"
    local create_output
    create_output=$(eval "${aws_env_prefix} aws ecr create-repository \
        --region '$region' \
        --repository-name '$repo_name' \
        --image-tag-mutability '${mutability}' \
        2>&1")
    local exit_code=$?

    if [[ $exit_code -eq 0 ]]; then
        log_success "Created ECR: ${repo_name}"
    else
        log_warn "ECR create failed: ${repo_name}"

        log_error "$create_output"

        log_warn "Continuing despite ECR creation failure..."
        return 1
    fi
    return 0
}

export -f ci_ensure_ecr_repository