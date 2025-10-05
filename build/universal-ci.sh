#!/usr/bin/env bash
# =============================================================================
# Universal CI Pipeline Script
#
# This script provides a universal CI pipeline for building and pushing Docker/Podman images.
# It supports various registries, image namespaces, and tagging strategies.
#
# Features:
# - Multi-registry support (docker.io, icr.io, gcr.io, ghcr.io, quay.io, etc.)
# - Image namespace and prefix support with registry-specific formatting
# - Registry-specific namespace and prefix configuration
# - IBM Cloud Registry namespace-specific API keys
# - Support for additional login namespaces with separate API keys
# - Flexible tagging strategies with configurable additional tags
# - Secret management for builds
# - CI runner detection (GitHub Actions, Jenkins, Travis, GitLab, CircleCI, etc.)
# - Debug mode with safe secret logging
# - Common build.yaml support (builders/build.yaml for shared settings)
# =============================================================================

set -Eeo pipefail
#set -x
# =============================================================================
# Configuration and Environment Variables
# =============================================================================

# Script location
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
# Note: All functions from libci.sh have been moved into this script

# Debug mode (set to "true" to enable)
# This can be overridden by --debug or --no-debug command line options
DEBUG="${DEBUG:-false}"

# Define basic logging functions first so they can be used by other functions
log() {
    echo -e "\033[1;34m[INFO]\033[0m $*"
}

debug() {
    if [[ "${DEBUG}" == "true" ]]; then
        echo -e "\033[1;36m[DEBUG]\033[0m $*" >&2
    fi
}

warn() {
    echo -e "\033[1;33m[WARN]\033[0m $*"
}

error() {
    echo -e "\033[1;31m[ERROR]\033[0m $*" >&2
}

success() {
    echo -e "\033[1;32m[SUCCESS]\033[0m $*"
}

# Check if a command exists - needed by other functions
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Define get_yaml_value function first since it's used by get_env_var
get_yaml_value() {
  local yaml_file=$1
  local key=$2
  local value=""

  if [ -z "$yaml_file" ] || [ -z "$key" ]; then
    echo "Usage: get_yaml_value <yaml_file> <dot/bracket path>" >&2
    return 2
  fi

  if [[ "${DEBUG}" == "true" ]]; then
    debug "get_yaml_value: Looking for key '$key' in file '$yaml_file'"
    if [ ! -f "$yaml_file" ]; then
      debug "get_yaml_value: WARNING - File does not exist: $yaml_file"
    fi
  fi

  if command_exists yq; then
    ver=$(yq --version 2>&1 | awk '{print $NF}' | sed 's/^v//')
    major_ver=$(echo "$ver" | cut -d. -f1)


    if [ "$major_ver" -eq 4 ]; then
      # ---- mikefarah/yq v4 ----
      value=$(yq eval -r ".${key}" "$yaml_file" 2>/dev/null)
      # if the result is a map/array, -r prints empty; try non-raw:
      if [ -z "$value" ]; then
        if [[ "${DEBUG}" == "true" ]]; then
          debug "get_yaml_value: Raw output empty, trying non-raw: yq eval \".${key}\" \"$yaml_file\""
        fi
        value=$(yq eval ".${key}" "$yaml_file" 2>/dev/null)
      fi
    else
      # ---- mikefarah/yq v3.x ----
      # v3 queries do NOT start with a leading dot
      local k=${key#.}
      # Plain read (YAML out). For JSON-ish output on complex types, add -j.
      value=$(yq r "$yaml_file" "$k" 2>/dev/null)
    fi

  elif command_exists python3 && python3 -c "import yaml" 2>/dev/null; then
    # ---- Python-only fallback (no jq) ----
    value=$(
      python3 - "$yaml_file" "$key" <<'PY'
import sys, json, yaml, re

yaml_file, path = sys.argv[1], sys.argv[2]
with open(yaml_file, 'r', encoding='utf-8') as f:
    data = yaml.safe_load(f)

# jq-like path parser: .a.b[0], ["a.b"], ["x\"y"], supports negative indices
token_re = re.compile(r'''
    (?:\["((?:[^"\\]|\\.)*)"\]) |     # ["quoted key"]
    (?:\[(\-?\d+)\]) |                # [index]
    (?:\.([A-Za-z_][A-Za-z0-9_-]*))   # .simple_key
''', re.VERBOSE)

def parse_path(p):
    norm = p if p.startswith('.') or p.startswith('[') else '.' + p
    pos, toks = 0, []
    while pos < len(norm):
        m = token_re.match(norm, pos)
        if not m:
            if pos == 0 and '.' not in norm and '[' not in norm and ']' not in norm:
                toks.append(('key', norm))
                break
            sys.exit(0)  # "not found" → empty output
        q, idx, simple = m.groups()
        if q is not None:
            toks.append(('key', bytes(q, 'utf-8').decode('unicode_escape')))
        elif idx is not None:
            toks.append(('idx', int(idx)))
        else:
            toks.append(('key', simple))
        pos = m.end()
    return toks

def get_value(obj, p):
    for typ, tok in parse_path(p):
        if typ == 'key':
            if not isinstance(obj, dict) or tok not in obj:
                return None
            obj = obj[tok]
        else:
            if not isinstance(obj, list):
                return None
            i = tok if tok >= 0 else len(obj) + tok
            if i < 0 or i >= len(obj):
                return None
            obj = obj[i]
    return obj
val = get_value(data, path)
if val is None:
    sys.exit(0)

if isinstance(val, str):
    print(val)
else:
    print(json.dumps(val, ensure_ascii=False))
PY
    )
  else
    # Fallback: grep + awk (supports simple dot notation)

    local regex='([a-zA-Z0-9_-]+)(\[[0-9]+\])?'
    local part index
    local -a parts

    while [[ $key =~ $regex ]]; do
        part="${BASH_REMATCH[1]}"
        parts+=("$part")
        if [[ -n ${BASH_REMATCH[2]} ]]; then
        index="${BASH_REMATCH[2]//[\[\]]/}"
        parts+=("$index")
        fi
        key="${key:${#BASH_REMATCH[0]}}"
        [[ $key == .* ]] && key="${key:1}"
    done

    # Handle simple top-level key: e.g. version: "9.latest"
    if [[ ${#parts[@]} -eq 1 ]]; then
        local line
        while IFS= read -r line; do
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        [[ -z "$line" ]] && continue
        local trimmed="${line#"${line%%[![:space:]]*}"}"
        if [[ "$trimmed" =~ ^${parts[0]}:[[:space:]]*(.*)$ ]]; then
            echo "${BASH_REMATCH[1]}" | sed -E 's/^"(.*)"$/\1/'
            return 0
        fi
        done < "$yaml_file"
    else
        # Handle nested keys with one level of array indexing
        # For nested paths like REGISTRY[0].name
        local level=0
        local indent=""
        local current_index=-1
        local inside_list=false
        local line

        while IFS= read -r line; do
            [[ "$line" =~ ^[[:space:]]*# ]] && continue
            [[ -z "$line" ]] && continue

            local trimmed="${line#"${line%%[![:space:]]*}"}"

            if [[ $level -eq 0 ]]; then
            if [[ "$trimmed" == "${parts[0]}:" ]]; then
                indent=$(echo "$line" | sed -n 's/^\([[:space:]]*\).*/\1/p')
                level=1
                continue
            fi
            elif [[ $level -eq 1 ]]; then
            if [[ "${parts[1]}" =~ ^[0-9]+$ ]]; then
                if [[ "$trimmed" =~ ^-[[:space:]] ]]; then
                ((current_index++))
                if [[ $current_index -eq ${parts[1]} ]]; then
                    level=2
                    if [[ "$trimmed" =~ -[[:space:]]*${parts[2]}:[[:space:]]*(.*)$ ]]; then
                    echo "${BASH_REMATCH[1]}" | sed -E 's/^"(.*)"$/\1/'
                    return 0
                    fi
                fi
                fi
                continue
            fi
            elif [[ $level -eq 2 ]]; then
            if [[ "$trimmed" =~ ^${parts[2]}:[[:space:]]*(.*)$ ]]; then
                echo "${BASH_REMATCH[1]}" | sed -E 's/^"(.*)"$/\1/'
                return 0
            fi
            fi
        done < "$yaml_file"
    fi
  fi

  [[ "$value" == "null" ]] && value=""

  if [[ "${DEBUG}" == "true" ]]; then
    debug "get_yaml_value: Final value for key '$key' in '$yaml_file': '$value'"
  fi

  echo "$value"
}

# Define get_env_var function since it's used early in the script
# Enhanced get_env_var function that uses the merged YAML file
get_env_var() {
  local var_name="$1"
  local default_value="${2:-}"
  local value=""

  if [[ "${DEBUG}" == "true" ]]; then
    debug "get_env_var: Looking for '$var_name' (default: '$default_value')"
  fi

  # Try get_env if available (pipelinectl)
  if command_exists get_env; then
    value=$(get_env "$var_name" "")
    if [[ "${DEBUG}" == "true" && -n "$value" ]]; then
      debug "get_env_var: Found '$var_name' from pipelinectl: '$value'"
    fi
  fi

  # Try to get from config file if it exists and is defined
  # Note: config is already the merged YAML from common build.yaml and image-specific build.yaml
  if [ -z "$value" ] && [ -n "${config:-}" ] && [ -f "${config:-}" ]; then
    if [[ "${DEBUG}" == "true" ]]; then
      debug "get_env_var: Looking for '$var_name' in config file: $config"
    fi
    value=$(get_yaml_value "$config" "$var_name")
    if [[ "${DEBUG}" == "true" && -n "$value" ]]; then
      debug "get_env_var: Found '$var_name' in YAML: '$value'"
    fi
  fi

  # If still no value, try environment variables
  if [ -z "$value" ]; then
    if [[ "$var_name" == *"-"* ]]; then
      # Use env for hyphenated variable names
      value=$(env | grep "^$var_name=" | cut -d= -f2-)
      if [[ "${DEBUG}" == "true" && -n "$value" ]]; then
        debug "get_env_var: Found hyphenated '$var_name' in environment: '$value'"
      fi
    else
      # Use standard environment variable
      value="${!var_name:-}"
      if [[ "${DEBUG}" == "true" && -n "$value" ]]; then
        debug "get_env_var: Found '$var_name' in environment: '$value'"
      fi
    fi
  fi

  # Final fallback to default value
  local result="${value:-$default_value}"
  if [[ "${DEBUG}" == "true" ]]; then
    if [ -z "$value" ]; then
      debug "get_env_var: Using default value for '$var_name': '$default_value'"
    fi
    debug "get_env_var: Final value for '$var_name': '$result'"
  fi

  echo "$result"
}

# Debug mode (set to "true" to enable)
# Only update DEBUG from config if it wasn't explicitly set via command line
if [[ "$DEBUG" != "true" && "$DEBUG" != "false" ]]; then
    DEBUG=$(get_env_var "DEBUG" "false")
fi

# Default image settings
DEFAULT_VERSION="latest"

# Set the context to the source directory
export CONTEXT=""
GITHUB_REF=""

# Initialize temp variables to avoid "unbound variable" errors
export temp_context=""
config=""

# Temporary files and directories tracking
declare -a TEMP_FILES=()
declare -a TEMP_DIRS=()

# =============================================================================
# Helper Functions
# =============================================================================

# Detect if we're using Docker or Podman
detect_container_engine() {
    # Prefer real Docker if available and not aliased to Podman
    if command -v docker >/dev/null 2>&1; then
        if docker version --format '{{.Server.Version}}' 2>/dev/null | grep -qi "podman"; then
            debug "detect_container_engine: docker command points to Podman"
            echo "podman"
            return 0
        fi
        debug "detect_container_engine: docker is real Docker"
        echo "docker"
        return 0
    fi

    # If Docker not found, try Podman
    if command -v podman >/dev/null 2>&1; then
        debug "detect_container_engine: using podman"
        echo "podman"
        return 0
    fi

    error "Neither Docker nor Podman found. Please install one of them."
    exit 1
}


# In-case of platform not provided through build configuration it will detect OS platform to be pass to docker build
detect_platform() {
    local arch platform engine

    # --- Docker case ---
    if command -v docker >/dev/null && docker buildx version >/dev/null 2>&1; then
        platforms=$(docker buildx inspect --bootstrap --format '{{join .Platforms ","}}' 2>/dev/null)
        if [[ -n "$platforms" ]]; then
            debug "detect_platform: buildx supports platforms='$platforms'"
            echo "$platforms"
            return 0
        fi
    fi

    # Fallback to Podman if available
    if command -v podman >/dev/null; then
        local arch os
        arch=$(podman info --format '{{.host.arch}}' 2>/dev/null || uname -m)
        os=$(podman info --format '{{.host.os}}' 2>/dev/null || echo "linux")
        if [[ -n "$arch" && -n "$os" ]]; then
            echo "${os}/${arch}"
            return 0
        fi
    fi

    # Final fallback to uname
    local arch
    arch="$(uname -m 2>/dev/null || echo x86_64)"
    case "$arch" in
        x86_64 | amd64)   echo "linux/amd64" ;;
        arm64 | aarch64)  echo "linux/arm64" ;;
        *)                echo "linux/amd64" ;;
    esac
}


resolve_file() {
  local type="$1"                # e.g., "config", "dockerfile"
  local input="${2:-}"           # optional: specific file path or name
  local image="${image_name:-}"  # image name from context
  local base_dir

  # 0) Establish base_dir (repo root)
  if [[ -n "${REPO_ROOT:-}" ]]; then
    base_dir="$REPO_ROOT"
  else
    case "$PWD" in
      */builders/"$image") base_dir="$(cd "$PWD/../.." && pwd)" ;;
      */builders)          base_dir="$(cd "$PWD/.."   && pwd)" ;;
      */source)            base_dir="$(cd "$PWD/.."   && pwd)" ;;
      *)                   base_dir="$PWD" ;;
    esac
  fi

  base_dir="$(cd "$base_dir" && pwd)"

  # 1) Absolute path provided
  if [[ -n "$input" && "$input" = /* ]]; then
    if [[ -f "$input" ]]; then
      echo "$input"
      return 0
    else
      echo "ERROR: File not found: $input" >&2
      return 1
    fi
  fi

  # 2) Build candidate list
  local candidates=()
  local name
  name="$(basename -- "$input")"

  case "$type" in
    config)
      if [[ -n "$input" ]]; then
        [[ -n "$image" ]] && candidates+=("$base_dir/builders/$image/$name")
        candidates+=("$base_dir/config/$name")
      else
        [[ -n "$image" ]] && candidates+=("$base_dir/builders/$image/build.yaml")
        [[ -n "$image" ]] && candidates+=("$base_dir/builders/$image/${image}.yaml")
        candidates+=("$base_dir/config/${image}.yaml")
      fi
      ;;
    dockerfile)
      if [[ -n "$input" ]]; then
        [[ -n "$image" ]] && candidates+=("$base_dir/builders/$image/$name")
        candidates+=("$base_dir/source/$name")
      else
        [[ -n "$image" ]] && candidates+=("$base_dir/builders/$image/Dockerfile")
        [[ -n "$image" ]] && candidates+=("$base_dir/builders/$image/${image}.Dockerfile")
        candidates+=("$base_dir/source/Dockerfile")
        candidates+=("$base_dir/source/${image}.Dockerfile")
      fi
      ;;
    *)
      echo "ERROR: Unknown file type '$type'" >&2
      return 1
      ;;
  esac

  # 3) Return first match
  for f in "${candidates[@]}"; do
    if [[ -f "$f" ]]; then
      echo "$f"
      return 0
    fi
  done
  echo "ERROR: No $type file found. Searched: ${candidates[*]}" >&2
  return 1
}



# Create a temporary file and track it for cleanup
create_temp_file() {
    local prefix="${1:-secret_}"
    local temp_file

    temp_file=$(mktemp "/tmp/${prefix}.XXXXXX")
    TEMP_FILES+=("$temp_file")

    echo "$temp_file"
}

# Create a temporary directory and track it for cleanup
create_temp_dir() {
    local temp_dir

    temp_dir=$(mktemp -d)
    TEMP_DIRS+=("$temp_dir")

    echo "$temp_dir"
}

# Clean up all temporary files and directories
cleanup_temp_files() {
    debug "Cleaning up temporary files and directories"

    # Clean up temp files
    for file in "${TEMP_FILES[@]}"; do
        if [[ -f "$file" ]]; then
            debug "Removing temporary file: $file"
            rm -f "$file"
        fi
    done

    # Clean up temp directories
    for dir in "${TEMP_DIRS[@]}"; do
        if [[ -d "$dir" ]]; then
            debug "Removing temporary directory: $dir"
            rm -rf "$dir"
        fi
    done

    # Also clean up any leftover secret files
    for f in /tmp/secret_*.??????; do
        if [[ -f "$f" ]]; then
            debug "Removing leftover secret file: $f"
            rm -f "$f"
        fi
    done

    # Also clean up any leftover merged_yaml files
    for f in /tmp/merged_yaml.??????; do
        if [[ -f "$f" ]]; then
            debug "Removing leftover merged YAML file: $f"
            rm -f "$f"
        fi
    done

    # Also clean up any leftover temp directories
    for d in /tmp/tmp.*; do
        if [[ -d "$d" && "$d" == /tmp/tmp.* ]]; then
            debug "Removing leftover temp directory: $d"
            rm -rf "$d"
        fi
    done
}

# Detect CI environment
detect_ci_environment() {
    if [[ -n "${GITHUB_ACTIONS:-}" ]]; then
        echo "github"
    elif [[ -n "${JENKINS_URL:-}" ]]; then
        echo "jenkins"
    elif [[ -n "${TRAVIS:-}" ]]; then
        echo "travis"
    elif [[ -n "${GITLAB_CI:-}" ]]; then
        echo "gitlab"
    elif [[ -n "${CIRCLECI:-}" ]]; then
        echo "circle"
    elif [[ -n "${BITBUCKET_BUILD_NUMBER:-}" ]]; then
        echo "bitbucket"
    elif [[ -n "${TEAMCITY_VERSION:-}" ]]; then
        echo "teamcity"
    elif [[ -n "${CODEBUILD_BUILD_ID:-}" ]]; then
        echo "codebuild"
    elif [[ -n "${IDS_PROJECT_ID:-}" || -n "${PIPELINE_ID:-}" ]]; then
        # IBM Cloud Toolchain detection
        echo "ibmcloud"
    elif [[ -n "${BUILD_ID:-}" && -n "${BUILD_NUMBER:-}" ]]; then
        # Generic CI detection
        echo "generic"
    else
        echo "local"
    fi
}

# Get CI runner ID
get_ci_runner_id() {
    local ci_env=$(detect_ci_environment)

    case "$ci_env" in
        github)
            echo "${GITHUB_RUN_ID:-unknown}"
            ;;
        jenkins)
            echo "${BUILD_ID:-unknown}"
            ;;
        travis)
            echo "${TRAVIS_BUILD_ID:-unknown}"
            ;;
        gitlab)
            echo "${CI_PIPELINE_ID:-unknown}"
            ;;
        circle)
            echo "${CIRCLE_BUILD_NUM:-unknown}"
            ;;
        bitbucket)
            echo "${BITBUCKET_BUILD_NUMBER:-unknown}"
            ;;
        teamcity)
            echo "${BUILD_NUMBER:-unknown}"
            ;;
        codebuild)
            echo "${CODEBUILD_BUILD_ID:-unknown}"
            ;;
        ibmcloud)
            echo "${BUILD_NUMBER:-${IDS_PROJECT_ID:-unknown}}"
            ;;
        *)
            echo "$(date +%s)"
            ;;
    esac
}

# Get Git SHA if available
get_git_sha() {
    local source_dir="${1:-$REPO_ROOT/source}"
    local short="${2:-true}"

    if [[ -d "$source_dir/.git" ]]; then
        if [[ "$short" == "true" ]]; then
            git -C "$source_dir" rev-parse --short HEAD 2>/dev/null || echo "unknown"
        else
            git -C "$source_dir" rev-parse HEAD 2>/dev/null || echo "unknown"
        fi
    elif [[ -n "${GITHUB_SHA:-}" ]]; then
        if [[ "$short" == "true" ]]; then
            echo "${GITHUB_SHA:0:7}"
        else
            echo "$GITHUB_SHA"
        fi
    else
        echo "unknown"
    fi
}

# Load repository using pipelinectl if available
load_repository() {
    local repo_url="$1"
    local branch="${2:-main}"
    local target_dir="${3:-$REPO_ROOT/source}"
    local token_name="${4:-}"
    local token=""

    # Get token if token_name is provided
    if [ -n "$token_name" ]; then
        token=$(get_env_var "$token_name" "")
    fi

    # if command_exists load_repo; then
    #     log "Loading repository using pipelinectl: $repo_url"
    #     if [ -n "$token" ]; then
    #         load_repo --url "$repo_url" --branch "$branch" --dir "$target_dir" --token "$token"
    #     else
    #         load_repo --url "$repo_url" --branch "$branch" --dir "$target_dir"
    #     fi
    #     return $?
    # else
        log "Cloning repository using git: $repo_url"
        if [ -d "$target_dir" ]; then
            warn "Target directory already exists, removing it"
            rm -rf "$target_dir"
        fi

        mkdir -p "$target_dir"

        # Clone with token if provided
        if [ -n "$token" ]; then
            # Extract domain from repo URL
            local domain=$(echo "$repo_url" | sed -E 's|^(https?://)?([^/]+).*|\2|')
            # Create URL with token
            local auth_url="https://${token}@${domain}$(echo "$repo_url" | sed -E 's|^(https?://)?[^/]+(.*)|\2|')"
            git clone -b "$branch" --depth 1 "$auth_url" "$target_dir"
        else
            git clone -b "$branch" --depth 1 "$repo_url" "$target_dir"
        fi

        if [ -f "$target_dir/.gitmodules" ]; then
            log "Initializing git submodules"
            cd "$target_dir" && git submodule update --init --recursive
            cd "$REPO_ROOT"
        fi

        return $?
    # fi
}

# Strip transport/scheme
normalize_registry() {
    local r="$1"
    printf '%s' "$r" | sed -e 's|^docker://||' -e 's|^https://||' -e 's|^http://||'
}

# Safe masking in logs
mask_value() {
    local s="$1"
    local n=${#s}
    if [ "$n" -le 4 ]; then printf '****'; else printf '%s' "${s:0:2}****${s: -2}"; fi
}

# Make an env-safe key for a registry hostname: "ghcr.io" -> "ghcr_io"
registry_key_for_env() {
    printf '%s' "$1" | sed 's/[^a-zA-Z0-9]/_/g'
}

# Skopeo auth file discovery
resolve_authfile() {
    if [ -n "${REGISTRY_AUTH_FILE:-}" ] && [ -f "$REGISTRY_AUTH_FILE" ]; then
        printf '%s\n' "$REGISTRY_AUTH_FILE"; return 0
    fi
    local uid; uid="$(id -u)"
    local xdg="${XDG_RUNTIME_DIR:-/run/user/${uid}}"
    local podman_auth="${xdg}/containers/auth.json"
    if [ -f "$podman_auth" ]; then printf '%s\n' "$podman_auth"; return 0; fi
    if [ -f "$HOME/.config/containers/auth.json" ]; then
        printf '%s\n' "$HOME/.config/containers/auth.json"; return 0
    fi
    if [ -f "$HOME/.docker/config.json" ]; then
        printf '%s\n' "$HOME/.docker/config.json"; return 0
    fi
    return 1
}

# ECR region extractor: <acct>.dkr.ecr.<region>.amazonaws.com -> <region>
ecr_region_from_registry() {
    local host="$1"
    echo "$host" | sed -n 's/^[0-9]\{12\}\.dkr\.ecr\.\([a-z0-9-]\+\)\.amazonaws\.com$/\1/p'
}

# COMMON AUTH RESOLVER
# Usage: get_registry_auth "<registry>" "<user_override>" "<prefix>"
# Exports variables via <prefix>:
#   <prefix>REGISTRY  - normalized hostname
#   <prefix>USERNAME  - final username (may be empty for ECR)
#   <prefix>PASSWORD  - final password/secret (may be empty for ECR)
#   <prefix>SCHEME    - one of: docker_like | ecr | icr | icr_cp | ghcr | gcr
get_registry_auth() {
    local raw_registry="$1" user_override="$2" prefix="${3:-AUTH_}"

    local registry; registry="$(normalize_registry "$raw_registry")"
    local rk; rk="$(registry_key_for_env "$registry")"

    local username="" password="" scheme="docker_like"

    # (1) explicit override
    if [ -n "$user_override" ]; then
        username="$user_override"
    fi

    # (2) registry-scoped env (your requested format)
    #     e.g., user_ghcr_io / password_ghcr_io
    if [ -z "$username" ]; then username="$(get_env_var "user_${rk}" "")"; fi
    if [ -z "$password" ]; then password="$(get_env_var "password_${rk}" "")"; fi

    # Detect registry scheme
    case "$registry" in
        cp.icr.io)
            scheme="icr_cp"
            ;;
        *.icr.io|icr.io|icr.io*|*.icr.io*)
            scheme="icr"
            ;;
        *.amazonaws.com)
            scheme="ecr"
            ;;
        ghcr.io)
            scheme="ghcr"
            ;;
        gcr.io|*.gcr.io)
            scheme="gcr"
            ;;
        *)
            scheme="docker_like"
            ;;
    esac

    # (3) scheme-specific defaults (only if still missing)
    case "$scheme" in
        icr_cp)
            [ -z "$username" ] && username="cp"
            [ -z "$password" ] && {
                password="$(get_env_var "ENTITLED_REGISTRY_KEY" "")"
                [ -z "$password" ] && password="$(get_env_var "IBM_ENTITLEMENT_KEY" "")"
            }
            ;;
        icr)
            [ -z "$username" ] && username="iamapikey"
            [ -z "$password" ] && password="$(get_env_var "IBM_CLOUD_API_KEY" "")"
            ;;
        ghcr)
            [ -z "$username" ] && username="$(get_env_var "GITHUB_ACTOR" "")"
            if [ -z "$password" ]; then
                password="$(get_env_var "GHCR_TOKEN" "")"
                [ -z "$password" ] && password="$(get_env_var "GITHUB_TOKEN" "")"
                [ -z "$password" ] && password="$(get_env_var "CR_PAT" "")"
            fi
            ;;
        gcr)
            [ -z "$username" ] && username="_json_key"
            if [ -z "$password" ]; then
                local gcloud_key; gcloud_key="$(get_env_var "GCLOUD_SERVICE_KEY" "")"
                [ -n "$gcloud_key" ] && password="$(printf '%s' "$gcloud_key" | base64 -d)"
            fi
            ;;
        ecr)
            # For ECR: we typically mint a token via AWS CLI in login_to_registry.
            # If user_<rk>/password_<rk> were provided, we pass them along so the
            # login function can export AWS_ACCESS_KEY_ID/SECRET_ACCESS_KEY.
            ;;
        docker_like)
            # nothing special here
            ;;
    esac

    # (4) generic fallbacks (only if still empty)
    [ -z "$username" ] && username="$(get_env_var "REGISTRYUSER" "")"
    [ -z "$password" ] && password="$(get_env_var "REGISTRYPASS" "")"

    # Export via prefix variables
    printf -v "${prefix}REGISTRY"  '%s' "$registry"
    printf -v "${prefix}USERNAME"  '%s' "$username"
    printf -v "${prefix}PASSWORD"  '%s' "$password"
    printf -v "${prefix}SCHEME"    '%s' "$scheme"

    debug "AuthResolver: registry=${registry} scheme=${scheme} user=$(mask_value "$username") pass=$( [ -n "$password" ] && echo '****' || echo '(none)' ) (order: override > user_${rk}/password_${rk} > scheme defaults > REGISTRYUSER/REGISTRYPASS)"
}

# Login to registry with standardized credentials
login_to_registry() {
    local registry="$1"
    local user_override="${2:-}"
    local container_engine; container_engine="$(detect_container_engine)"

    registry="$(normalize_registry "$registry")"
    debug "Attempting to login to registry: $registry (engine: $container_engine)"

    # Resolve credentials and scheme
    get_registry_auth "$registry" "$user_override" "LRAUTH_"
    local scheme="$LRAUTH_SCHEME" username="$LRAUTH_USERNAME" password="$LRAUTH_PASSWORD"

    # If no credentials, try generic fallback envs (backward compat)
    if [ -z "$username" ] && [ -z "$password" ] && [ "$scheme" != "ecr" ]; then
        warn "No credentials found for ${registry}; attempting anonymous access"
        return 0
    fi

    # ECR: use AWS CLI to mint an auth token; username is 'AWS'
    if [ "$scheme" = "ecr" ]; then
        local region; region="$(ecr_region_from_registry "$registry")"
        [ -z "$region" ] && region="$(get_env_var "AWS_DEFAULT_REGION" "")"
        [ -z "$region" ] && region="us-east-1"  # safe default

        if ! command_exists aws; then
            error "AWS CLI not found; required for ECR login to ${registry}"
            return 1
        fi

        # If caller passed AK/SK in user/pass, set them so AWS CLI can use them
        if [ -n "$username" ] && [ -n "$password" ]; then
            export AWS_ACCESS_KEY_ID="$username"
            export AWS_SECRET_ACCESS_KEY="$password"
        fi
        # Optional session token
        if [ -n "$(get_env_var "AWS_SESSION_TOKEN" "")" ]; then
            export AWS_SESSION_TOKEN="$(get_env_var "AWS_SESSION_TOKEN" "")"
        fi

        log "Logging into AWS ECR: ${registry} (region: ${region})"
        debug "aws ecr get-login-password --region ${region} | ${container_engine} login --username AWS --password-stdin ${registry}"
        if aws ecr get-login-password --region "$region" | \
           $container_engine login --username AWS --password-stdin "$registry"; then
            return 0
        else
            return 1
        fi
    fi

    # Docker-like registries (includes ICR, GHCR, GCR, etc.)
    if [ -n "$username" ] && [ -n "$password" ]; then
        log "Logging into registry ${registry} as $(mask_value "$username")"
        debug "echo **** | ${container_engine} login ${registry} -u $(mask_value "$username") --password-stdin"
        # shellcheck disable=SC2005
        echo "$password" | $container_engine login "$registry" -u "$username" --password-stdin
        return $?
    fi

    warn "No credentials resolved for registry: ${registry}; attempting anonymous access"
    return 0
}



# Login to all registries
login_to_registries() {
    # Check if we have a YAML configuration for registries
    if [ -n "${config:-}" ] && [ -f "${config:-}" ]; then
        # Get registry list from YAML
        local registry_list=$(get_yaml_value "$config" "REGISTRY")

        if [[ "${DEBUG}" == "true" ]]; then
            debug "Registry list from YAML: $registry_list"
        fi

        # If registry list is in YAML format, process each registry
        if [ -n "$registry_list" ]; then
            # Get the number of registries in the list
            local registry_count=$(echo "$registry_list" | grep -c "name:")

            if [[ "${DEBUG}" == "true" ]]; then
                debug "Found $registry_count registries in YAML"
            fi

            # Process each registry
            for ((i=0; i<registry_count; i++)); do
                local registry_name=$(get_yaml_value "$config" "REGISTRY[$i].name")
                local registry_user=$(get_yaml_value "$config" "REGISTRY[$i].user")

                if [[ "${DEBUG}" == "true" ]]; then
                    debug "Processing registry: $registry_name, user: $registry_user"
                fi

                if [ -n "$registry_name" ]; then
                    # Login to registry with user from YAML if specified
                    login_to_registry "$registry_name" "$registry_user"
                fi
            done
        else
            # Fallback to primary registry if REGISTRY list is not found
            local primary_registry="${REGISTRY}"

            debug "Primary registry value: '$primary_registry'"

            # Login to primary registry only if it's not empty
            if [ -n "$primary_registry" ]; then
                login_to_registry "$primary_registry"
            else
                warn "Primary registry is empty, skipping login"
            fi
        fi
    else
        # Fallback to primary registry if config file is not found
        local primary_registry="${REGISTRY}"

        debug "Primary registry value: '$primary_registry'"

        # Login to primary registry only if it's not empty
        if [ -n "$primary_registry" ]; then
            login_to_registry "$primary_registry"
        else
            warn "Primary registry is empty, skipping login"
        fi
    fi
}

# Setup Docker/Podman Buildx
setup_buildx() {
    log "Setting up Buildx"

    local container_engine
    container_engine="$(detect_container_engine)"  # docker|podman

    # ---- knobs ----
    local builder_name="${BUILDX_BUILDER_NAME:-ci-builder}"                 # for docker-container driver
    local builder_name_docker="${BUILDX_DOCKER_BUILDER_NAME:-${builder_name}-docker}"  # for docker driver
    local driver_image="${BUILDX_BUILDKIT_IMAGE:-}"          # only used if docker-container fallback is needed
    local force_buildx="${FORCE_BUILDX:-0}"                  # 1 = force buildx path even for single arch
    local platforms="${PLATFORMS:-}"                         # e.g., "linux/amd64,linux/arm64"
    local skip_login="${SKIP_REGISTRY_LOGIN:-0}"
    local avoid_bk_image="${AVOID_BUILDKIT_IMAGE:-0}"        # 1 = fail instead of pulling BuildKit image
    local install_binfmt="${INSTALL_BINFMT:-auto}"           # auto|1|0 (auto tries if privileged)

    # ---- login first ----
    if [ "$skip_login" -ne 1 ]; then
        log "Logging into registries (pre-build)"
        login_to_registries
    else
        log "Skipping registry login (SKIP_REGISTRY_LOGIN=1)"
    fi

    # ---- helpers ----
    _needs_multi_platform() {
        # multi-arch if PLATFORMS has comma or differs from daemon's native platform
        if [ -n "$platforms" ]; then
            if [[ "$platforms" == *","* ]]; then
                return 0
            fi
            if [ "$container_engine" = "docker" ] && command -v docker >/dev/null 2>&1; then
                local native
                native="$(docker version --format '{{.Server.Os}}/{{.Server.Arch}}' 2>/dev/null || true)"
                if [ -n "$native" ] && [ "$platforms" != "$native" ]; then
                    return 0
                fi
            fi
        fi
        return 1
    }

    _builder_supports_platforms() {
        # $1 = builder name; returns 0 if all PLATFORMS are supported by the builder
        local name="$1"
        local have
        have="$(docker buildx inspect "$name" 2>/dev/null | awk -F': ' '/Platforms/ {print $2}' | tr -d ' ')"
        [ -z "$have" ] && return 1
        IFS=',' read -r -a want_arr <<< "$platforms"
        for p in "${want_arr[@]}"; do
            case ",$have," in
                *,"$p",*) ;;
                *) return 1 ;;
            esac
        done
        return 0
    }

    _ensure_binfmt() {
        # Install QEMU/binfmt only if we're likely privileged (DinD) and not explicitly disabled
        if [ "$install_binfmt" = "0" ]; then
            return 0
        fi
        # Try once; ignore failures on non-privileged runners
        log "Ensuring QEMU binfmt is installed (requires privileged)"
        docker run --privileged --rm tonistiigi/binfmt --install all >/dev/null 2>&1 || true
    }

    # ---- docker path ----
    if [ "$container_engine" = "docker" ]; then
        if ! docker buildx version >/dev/null 2>&1; then
            error "docker buildx is not available. Install Docker Buildx and retry."
            exit 1
        fi

        # single-arch fast path (unless forced)
        if [ "$force_buildx" -ne 1 ] && ! _needs_multi_platform; then
            log "Using native BuildKit (DOCKER_BUILDKIT=1) for single-arch"
            export DOCKER_BUILDKIT=1
            return 0
        fi

        # multi-arch path
        if _needs_multi_platform; then
            # 1) Try driver=docker first (no BuildKit image pulled)
            if ! docker buildx inspect "$builder_name_docker" >/dev/null 2>&1; then
                log "Creating buildx builder '$builder_name_docker' (driver=docker)"
                docker buildx create --name "$builder_name_docker" --driver docker --use >/dev/null
            else
                docker buildx use "$builder_name_docker" >/dev/null
            fi
            docker buildx inspect --bootstrap >/dev/null 2>&1 || true

            if _builder_supports_platforms "$builder_name_docker"; then
                log "Using buildx driver=docker (native BuildKit) for multi-platform: $platforms"
                export DOCKER_BUILDKIT=1
                return 0
            fi

            # 2) Fallback: docker-container (will pull BuildKit image)
            if [ "$avoid_bk_image" -eq 1 ]; then
                error "Requested platforms '$platforms' not supported by driver=docker and AVOID_BUILDKIT_IMAGE=1 is set. Aborting."
                exit 1
            fi
            # Attempt to enable emulation for cross-arch in DinD (best-effort)
            _ensure_binfmt

            if ! docker buildx inspect "$builder_name" >/dev/null 2>&1; then
                log "Creating buildx builder '$builder_name' (driver=docker-container) ${driver_image:+with image: $driver_image}"
                if [ -n "$driver_image" ]; then
                    docker buildx create \
                        --name "$builder_name" \
                        --driver docker-container \
                        --driver-opt "image=${driver_image}" \
                        --use >/dev/null
                else
                    docker buildx create \
                        --name "$builder_name" \
                        --driver docker-container \
                        --use >/dev/null
                fi
            else
                docker buildx use "$builder_name" >/dev/null
            fi

            docker buildx inspect --bootstrap >/dev/null
            log "Using buildx driver=docker-container for multi-platform: $platforms"
            return 0
        fi

        # forced buildx for single-arch
        log "FORCE_BUILDX=1 set: using buildx driver=docker (no BuildKit image)"
        if ! docker buildx inspect "$builder_name_docker" >/dev/null 2>&1; then
            docker buildx create --name "$builder_name_docker" --driver docker --use >/dev/null
        else
            docker buildx use "$builder_name_docker" >/dev/null
        fi
        docker buildx inspect --bootstrap >/dev/null 2>&1 || true
        export DOCKER_BUILDKIT=1
        return 0
    fi

    # ---- podman path (best-effort) ----
    if [ "$container_engine" = "podman" ]; then
        if ! command -v podman >/dev/null 2>&1; then
            error "podman CLI not found on PATH"
            exit 1
        fi

        # FYI: Podman does NOT support buildx builder instances (no 'create', '--name', '--driver').
        # 'podman buildx build' is an alias of 'podman build', and not all Docker buildx features exist.
        # See: podman-build man page and upstream issues.  # docs & issues cited in explanation
        log "Podman detected; skipping Buildx builder creation (no builder instances in Podman)."

        # Optional: Best-effort QEMU/binfmt setup for cross-arch (requires privileged runner).
        # For Podman, prefer host packages (qemu-user-static) when possible; fallback to the binfmt container.
        if [ "$install_binfmt" != "0" ]; then
            log "Ensuring QEMU binfmt is available (best-effort; requires privileged)"
            # Try containerized install; ignore failures on non-privileged runners
            podman run --privileged --rm docker.io/tonistiigi/binfmt --install all >/dev/null 2>&1 || true
            # Note: On many distros, installing 'qemu-user-static' on the host is the recommended approach.
        fi

        # Nothing else to do here. Use 'podman build' (or 'podman buildx build') in subsequent steps.
        # For multi-arch, prefer: podman build --platform ... --manifest <name>, then podman manifest push --all ...
        return 0
    fi


    error "Unsupported container engine: $container_engine"
    exit 1
}

# Load common build.yaml from builders folder and merge with image-specific YAML
load_common_build_yaml() {
    local common_yaml="${REPO_ROOT}/builders/build.yaml"
    local image_yaml="$1"
    local merged_yaml

    # Always create a merged YAML file, even if common build.yaml doesn't exist
    # Use create_temp_file to ensure it's tracked for cleanup
    merged_yaml=$(create_temp_file "merged_yaml")
    debug "Created merged YAML file: $merged_yaml"

    # Check if common build.yaml exists
    if [[ -f "$common_yaml" ]]; then
        debug "Found common build.yaml at $common_yaml"
        debug "Common build.yaml content:"
        if [[ "${DEBUG}" == "true" ]]; then
            cat "$common_yaml" >&2
        fi

        debug "Image-specific build.yaml content:"
        if [[ "${DEBUG}" == "true" ]]; then
            cat "$image_yaml" >&2
        fi

        # If we have yq, use it for proper YAML merging
        if command_exists yq; then
            debug "Using yq to merge YAML files"

            # Check yq version to use the appropriate command
            ver=$(yq --version 2>&1 | awk '{print $NF}' | sed 's/^v//')
            major_ver=$(echo "$ver" | cut -d. -f1)

            if [ "$major_ver" -eq 4 ]; then
                # yq v4 uses eval-all
                debug "Using yq v4 syntax for merging"
                if yq --help | grep -q "eval-all"; then
                    yq eval-all 'select(fileIndex == 0) * select(fileIndex == 1)' "$common_yaml" "$image_yaml" > "$merged_yaml"
                else
                    # Some v4 versions use different syntax
                    yq eval '. as $item ireduce ({}; . * $item )' "$common_yaml" "$image_yaml" > "$merged_yaml"
                fi
            elif [ "$major_ver" -eq 3 ]; then
                # yq v3 uses merge
                debug "Using yq v3 syntax for merging"
                yq merge "$common_yaml" "$image_yaml" > "$merged_yaml"
            else
                # Fallback for other versions - simple concatenation
                debug "Unknown yq version, using simple concatenation"
                cat "$common_yaml" "$image_yaml" > "$merged_yaml"
            fi

            # Show the merged result for debugging
            debug "Merged YAML content:"
            if [[ "${DEBUG}" == "true" ]]; then
                cat "$merged_yaml" >&2
            fi
        else
            # Simple fallback: concatenate files and let later values override earlier ones
            debug "Using simple concatenation for YAML merging"
            cat "$common_yaml" "$image_yaml" > "$merged_yaml"

            # Show the merged result for debugging
            debug "Merged YAML content (concatenated):"
            if [[ "${DEBUG}" == "true" ]]; then
                cat "$merged_yaml" >&2
            fi
        fi
    else
        # No common build.yaml, just copy the image yaml
        debug "No common build.yaml found, using only image-specific YAML"
        cp "$image_yaml" "$merged_yaml"
    fi

    echo "$merged_yaml"
}

# Format image name based on registry
format_image_name() {
    local registry="$1"
    local image_name="$2"
    # prefix is the 3rd argument (was incorrectly $4)
    local prefix="${3:-}"
    local result=""

    # Remove any leading/trailing slashes from components
    registry="${registry%/}"
    prefix="${prefix%/}"
    prefix="${prefix#/}"

    # Check if we have a YAML configuration for registries
    if [ -n "${config:-}" ] && [ -f "${config:-}" ]; then
        # Try to find the registry in the YAML configuration
        local registry_list=$(get_yaml_value "$config" "REGISTRY")
        if [ -n "$registry_list" ]; then
            # Get the number of registries in the list
            local registry_count=$(echo "$registry_list" | grep -c "name:")

            # Find the registry in the list
            for ((i=0; i<registry_count; i++)); do
                local registry_name=$(get_yaml_value "$config" "REGISTRY[$i].name")
                if [ "$registry_name" = "$registry" ]; then
                    # Found the registry, get its prefix
                    local yaml_prefix=$(get_yaml_value "$config" "REGISTRY[$i].prefix")
                    if [ -n "$yaml_prefix" ]; then
                        prefix="$yaml_prefix"
                        debug "Using prefix from YAML for $registry: $prefix"
                    fi
                    break
                fi
            done
        fi
    fi

    if [[ "${DEBUG}" == "true" ]]; then
        echo "DEBUG: Formatting image name for registry: $registry" >&2
        echo "DEBUG:   Image name: $image_name" >&2
        echo "DEBUG:   Prefix: $prefix" >&2
    fi

    # Simple format: registry/[prefix/]name
    # The registry itself (like icr.io/webmethods) already includes any namespace
    if [[ -n "$prefix" ]]; then
        result="${registry}/${prefix}/${image_name}"
    else
        result="${registry}/${image_name}"
    fi

    debug "Formatted image name: $result"

    echo "$result"
}

# -----------------------------------------------------------------------------
# SBOM generation helper
# -----------------------------------------------------------------------------
generate_sbom_for_image() {
    local image="$1"
    local sbom_tool; sbom_tool="$(get_env_var "SBOM_TOOL" "syft")"
    local sbom_format; sbom_format="$(get_env_var "SBOM_FORMAT" "spdx-json")"
    local sbom_file

    if [[ -z "$image" ]]; then
        warn "generate_sbom_for_image: no image supplied"
        return 1
    fi

    sbom_file=$(create_temp_file "sbom")
    if [[ "$sbom_tool" == "syft" ]]; then
        if ! command_exists syft; then
            warn "syft not found; cannot generate SBOM for ${image}"
            return 1
        fi
        log "Generating SBOM (syft, format=${sbom_format}) for ${image} -> ${sbom_file}"
        # syft supports output formats like spdx-json, cyclonedx-json, json
        if ! syft "${image}" -o "${sbom_format}" > "${sbom_file}" 2>/dev/null; then
            warn "syft failed to generate SBOM for ${image}"
            return 1
        fi
    else
        warn "SBOM tool '${sbom_tool}' not implemented; please install syft or set SBOM_TOOL=syft"
        return 1
    fi

    log "SBOM generated: ${sbom_file}"
    echo "${sbom_file}"
    return 0
}

# -----------------------------------------------------------------------------
# Image signing helper (cosign)
# -----------------------------------------------------------------------------
sign_image_with_cosign() {
    local image="$1"
    local keyfile=""
    local pubfile=""
    local cosign_cmd="cosign"

    if [[ -z "$image" ]]; then
        warn "sign_image_with_cosign: no image supplied"
        return 1
    fi

    if ! command_exists "${cosign_cmd}"; then
        warn "cosign not found; skipping signing for ${image}"
        return 1
    fi

    # Prefer secrets from config/CI: COSIGN_PRIVATE_KEY, COSIGN_PUBLIC_KEY, COSIGN_PASSWORD
    local cosign_private cosign_public cosign_password
    cosign_private="$(get_env_var "COSIGN_PRIVATE_KEY" "")"
    cosign_public="$(get_env_var "COSIGN_PUBLIC_KEY" "")"
    cosign_password="$(get_env_var "COSIGN_PASSWORD" "")"

    # If COSIGN_PRIVATE_KEY provided (preferred)
    if [[ -n "${cosign_private}" ]]; then
        keyfile=$(create_temp_file "cosign_key")
        # If it looks like PEM, write as-is; otherwise try base64 decode, fallback to raw
        if printf '%s' "${cosign_private}" | grep -q "-----BEGIN"; then
            printf '%s' "${cosign_private}" > "${keyfile}"
        else
            if printf '%s' "${cosign_private}" | base64 -d > "${keyfile}" 2>/dev/null; then
                :
            else
                printf '%s' "${cosign_private}" > "${keyfile}"
            fi
        fi
        chmod 600 "${keyfile}"

        # Optional public key write (not required for signing but store if provided)
        if [[ -n "${cosign_public}" ]]; then
            pubfile=$(create_temp_file "cosign_pub")
            if printf '%s' "${cosign_public}" | grep -q "-----BEGIN"; then
                printf '%s' "${cosign_public}" > "${pubfile}"
            else
                if printf '%s' "${cosign_public}" | base64 -d > "${pubfile}" 2>/dev/null; then
                    :
                else
                    printf '%s' "${cosign_public}" > "${pubfile}"
                fi
            fi
            chmod 600 "${pubfile}"
        fi

        # Export COSIGN_PASSWORD if provided so cosign can use it for encrypted keys
        local old_cosign_password_value=""
        if [[ -n "${cosign_password}" ]]; then
            old_cosign_password_value="${COSIGN_PASSWORD:-}"
            export COSIGN_PASSWORD="${cosign_password}"
        fi

        log "Signing image ${image} with COSIGN_PRIVATE_KEY (temp: ${keyfile})"
        if "${cosign_cmd}" sign --key "${keyfile}" "${image}"; then
            success "Image signed: ${image}"
            # unset temporary COSIGN_PASSWORD if we set it
            if [[ -n "${cosign_password}" ]]; then
                if [[ -n "${old_cosign_password_value}" ]]; then
                    export COSIGN_PASSWORD="${old_cosign_password_value}"
                else
                    unset COSIGN_PASSWORD
                fi
            fi
            return 0
        else
            warn "cosign sign failed for ${image} using COSIGN_PRIVATE_KEY"
            if [[ -n "${cosign_password}" ]]; then
                if [[ -n "${old_cosign_password_value}" ]]; then
                    export COSIGN_PASSWORD="${old_cosign_password_value}"
                else
                    unset COSIGN_PASSWORD
                fi
            fi
            return 1
        fi
    fi

    # Prefer explicit key path
    local cosign_key_path
    cosign_key_path="$(get_env_var "COSIGN_KEY_PATH" "")"
    local cosign_key_env
    cosign_key_env="$(get_env_var "COSIGN_KEY" "")"
    local cosign_keyless
    cosign_keyless="$(get_env_var "COSIGN_KEYLESS" "false")"

    if [[ -n "${cosign_key_path}" && -f "${cosign_key_path}" ]]; then
        log "Signing image ${image} with cosign key at ${cosign_key_path}"
        if "${cosign_cmd}" sign --key "${cosign_key_path}" "${image}"; then
            success "Image signed: ${image}"
            return 0
        else
            warn "cosign sign failed for ${image} with key ${cosign_key_path}"
            return 1
        fi
    fi

    # If COSIGN_KEY provided inline (base64 or PEM), write to temp file
    if [[ -n "${cosign_key_env}" ]]; then
        keyfile=$(create_temp_file "cosign_key")
        # Try to detect PEM header, otherwise attempt base64 decode and fallback to raw write
        if printf '%s' "${cosign_key_env}" | grep -q "-----BEGIN"; then
            printf '%s' "${cosign_key_env}" > "${keyfile}"
        else
            if printf '%s' "${cosign_key_env}" | base64 -d > "${keyfile}" 2>/dev/null; then
                :
            else
                # fallback: write raw content
                printf '%s' "${cosign_key_env}" > "${keyfile}"
            fi
        fi
        chmod 600 "${keyfile}"
        log "Signing image ${image} with cosign key from COSIGN_KEY (temp: ${keyfile})"
        if "${cosign_cmd}" sign --key "${keyfile}" "${image}"; then
            success "Image signed: ${image}"
            return 0
        else
            warn "cosign sign failed for ${image} using COSIGN_KEY"
            return 1
        fi
    fi

    # Keyless signing
    if [[ "${cosign_keyless}" == "true" ]]; then
        log "Performing keyless cosign signing for ${image}"
        if "${cosign_cmd}" sign --keyless "${image}"; then
            success "Image keyless-signed: ${image}"
            return 0
        else
            warn "cosign keyless sign failed for ${image}"
            return 1
        fi
    fi

    warn "No cosign key provided and keyless not enabled; skipping signing for ${image}"
    return 1
}

# =============================================================================
# Core Functions
# =============================================================================

# Initialize the build environment
initialize() {
    log "Initializing build environment"

    # Set up cleanup trap for both normal and abnormal exits
    trap cleanup_temp_files EXIT INT TERM

    # Detect CI environment
    CI_ENV=$(detect_ci_environment)
    log "Detected CI environment: $CI_ENV"

    # Resolve dockerfile and config
    if [[ -n "$dockerfile_rel_location" && -f "$dockerfile_rel_location" ]]; then
        # Use the explicitly provided dockerfile path
        dockerfile="$dockerfile_rel_location"
    else
        # Try to resolve the dockerfile
        dockerfile="$(resolve_file dockerfile)" || exit 1
    fi
    log "Using Dockerfile: $dockerfile"

    # Resolve config
    if [[ -n "$definition" && -f "$definition" ]]; then
        # Use the explicitly provided config path
        config="$definition"
    else
        # Try to resolve the config
        config="$(resolve_file config)" || exit 1
    fi
    log "Using Config: $config"

    # Check for common build.yaml and merge if exists
    if [[ -f "${REPO_ROOT}/builders/build.yaml" ]]; then
        log "Found common build.yaml, merging with image config"
        config=$(load_common_build_yaml "$config")
    fi

    # Set default version and tag if not provided
    if [ -z "$version" ]; then
        version=$(get_version "$config" "$REPO_ROOT/source")
        log "Determined version: $version"
    fi

    # Get primary registry from YAML if available
    local primary_registry=""
    if [ -f "$config" ]; then
        primary_registry=$(get_yaml_value "$config" "REGISTRY[0].name")
        log "Primary registry from YAML: $primary_registry"
    fi

    # Set REGISTRY to the primary registry from YAML or environment variable
    if [ -n "$primary_registry" ]; then
        REGISTRY="$primary_registry"
    elif [ -z "${REGISTRY:-}" ]; then
        REGISTRY=$(get_env_var "REGISTRY" "docker.io")
    fi

    debug "Registry value: $REGISTRY"
    log "Using registry: $REGISTRY"

    # Add standard build folders to ADDITIONAL_BUILD_FOLDERS if they exist
    local standard_folders=""
    if [ -d "${REPO_ROOT}/scripts/docker" ]; then
        standard_folders="${REPO_ROOT}/scripts/docker"
    fi
    if [ -d "${REPO_ROOT}/scripts/prebuildfs" ]; then
        if [ -n "$standard_folders" ]; then
            standard_folders="${standard_folders},${REPO_ROOT}/scripts/prebuildfs"
        else
            standard_folders="${REPO_ROOT}/scripts/prebuildfs"
        fi
    fi

    if [ -d "${BUILD_IMG_PATH}/rootfs" ]; then
        if [ -n "$standard_folders" ]; then
            standard_folders="${standard_folders},${BUILD_IMG_PATH}/rootfs"
        else
            standard_folders="${BUILD_IMG_PATH}/rootfs"
        fi
    fi

    # Get ADDITIONAL_BUILD_FOLDERS from environment or config
    if [ -z "${ADDITIONAL_BUILD_FOLDERS:-}" ]; then
        ADDITIONAL_BUILD_FOLDERS=$(get_env_var "ADDITIONAL_BUILD_FOLDERS" "")
    fi

    # Append standard folders to existing ADDITIONAL_BUILD_FOLDERS if any
    if [ -n "${ADDITIONAL_BUILD_FOLDERS:-}" ]; then
        export ADDITIONAL_BUILD_FOLDERS="${ADDITIONAL_BUILD_FOLDERS},${standard_folders}"
        debug "Added standard folders to additional build folders: $ADDITIONAL_BUILD_FOLDERS"
    else
        export ADDITIONAL_BUILD_FOLDERS="$standard_folders"
        debug "Using standard folders as additional build folders: $ADDITIONAL_BUILD_FOLDERS"
    fi

    # Get registry credentials
    REGISTRYUSER=$(get_env_var "REGISTRYUSER" "")
    REGISTRYPASS=$(get_env_var "REGISTRYPASS" "")

    # Only get PUSH from environment/config if it wasn't explicitly set via command line
    if [ -z "${PUSH:-}" ]; then
        PUSH=$(get_env_var "PUSH" "true")
    else
        # Convert string values to lowercase for consistent comparison
        PUSH=$(echo "$PUSH" | tr '[:upper:]' '[:lower:]')
        # Normalize values to ensure proper boolean interpretation
        if [[ "$PUSH" == "false" || "$PUSH" == "0" || "$PUSH" == "no" ]]; then
            PUSH="false"
        else
            PUSH="true"
        fi
        debug "Using PUSH value from command line: $PUSH"
    fi

    # Get CI run number for tagging
    GITHUB_RUN_NUMBER=$(get_env_var "GITHUB_RUN_NUMBER" "1")

    # Handle platform architecture
    PLATFORM=$(get_env_var "PLATFORM" "")
    if [ -z "${PLATFORM:-}" ]; then
        PLATFORM=$(detect_platform)
    fi

    # Get image namespace and prefix
    IMAGE_PREFIX=$(get_env_var "REGISTRY[0].prefix" "")

    # Set up tagging strategy
    TAG_STRATEGY=$(get_env_var "TAG_STRATEGY" "version-runner")

    # Options:
    # - version-only: Just the version number
    # - latest-only: Just "latest"
    # - version-latest: Version as main tag, "latest" as additional (if ADD_LATEST_TAG=true)
    # - version-runner: Version.runner_id as main tag, version as additional (if ADD_VERSION_TAG=true)
    # - version-sha: Version.git_sha as main tag, version as additional (if ADD_VERSION_TAG=true)
    # - runner-only: Just the runner ID
    # - sha-only: Just the git SHA

    # Get runner ID and git SHA for tagging
    local runner_id=$(get_ci_runner_id)
    local git_sha=$(get_git_sha)

    # Get additional tag options
    local add_latest=$(get_env_var "ADD_LATEST_TAG" "false")
    local add_version=$(get_env_var "ADD_VERSION_TAG" "false")
    local add_sha=$(get_env_var "ADD_SHA_TAG" "false")
    local add_runner=$(get_env_var "ADD_RUNNER_TAG" "false")

    ##
    init_git_variables "$REPO_ROOT/source"
    ##

    if [ -z "$tag" ]; then
        case "$TAG_STRATEGY" in
            version-only)
                tag="$version"
                ;;
            latest-only)
                tag="latest"
                ;;
            version-latest)
                if [ "$version" == "latest" ]; then
                    tag="latest"
                else
                    tag="$version"
                    if [[ "$add_latest" == "true" ]]; then
                        ADDITIONAL_TAGS="${ADDITIONAL_TAGS:-},latest"
                    fi
                fi
                ;;
            version-runner)
                if [ "$version" == "latest" ]; then
                    tag="latest"
                else
                    # Generate tag from version and runner ID
                    tag="${version}.${runner_id}"
                    if [[ "$add_version" == "true" ]]; then
                        ADDITIONAL_TAGS="${ADDITIONAL_TAGS:-},${version}"
                    fi
                fi
                ;;
            version-sha)
                if [ "$version" == "latest" ]; then
                    tag="latest"
                else
                    # Generate tag from version and git SHA
                    tag="${version}.${git_sha}"
                    if [[ "$add_version" == "true" ]]; then
                        ADDITIONAL_TAGS="${ADDITIONAL_TAGS:-},${version}"
                    fi
                fi
                ;;
            runner-only)
                # Just use the runner ID as the tag
                tag="${runner_id}"
                ;;
            sha-only)
                # Just use the git SHA as the tag
                tag="${git_sha}"
                ;;
            *)
                tag="latest"
                ;;
        esac
    fi

    # Add git SHA to additional tags if requested
    if [[ "$add_sha" == "true" && "$git_sha" != "unknown" && "$TAG_STRATEGY" != "sha-only" ]]; then
        ADDITIONAL_TAGS="${ADDITIONAL_TAGS:-},${git_sha}"
    fi

    # Add CI runner ID to additional tags if requested
    if [[ "$add_runner" == "true" && "$runner_id" != "unknown" && "$TAG_STRATEGY" != "runner-only" ]]; then
        ADDITIONAL_TAGS="${ADDITIONAL_TAGS:-},${runner_id}"
    fi

    # Add latest tag if requested (and not already using latest as primary tag)
    if [[ "$add_latest" == "true" && "$tag" != "latest" && "$TAG_STRATEGY" != "latest-only" ]]; then
        ADDITIONAL_TAGS="${ADDITIONAL_TAGS:-},latest"
    fi

    # Clean up ADDITIONAL_TAGS (remove leading comma if present)
    if [[ "${ADDITIONAL_TAGS:-}" == ,* ]]; then
        ADDITIONAL_TAGS="${ADDITIONAL_TAGS:1}"
    fi

    # Create temp directory for build artifacts
    BUILD_TMP_DIR=$(create_temp_dir)

    log "Build initialized with:"
    log "  platform: $PLATFORM"
    log "  Image Name: ${IMAGE_NAME}"
    log "  Version: ${version}"
    log "  Tag: ${tag}"
    log "  Registry: ${REGISTRY}"
    log "  Image Prefix: ${IMAGE_PREFIX:-none}"
    log "  Additional Tags: ${ADDITIONAL_TAGS:-none}"

    # Log registry configuration from YAML if available
    if [ -f "$config" ]; then
        local registry_yaml=$(get_yaml_value "$config" "REGISTRY")
        if [ -n "$registry_yaml" ]; then
            log "  Registry Configuration:"
            echo "$registry_yaml" | sed 's/^/    /'
        fi
    fi
    log "  Tag Strategy: ${TAG_STRATEGY}"
    log "  Add Version Tag: $(get_env_var "ADD_VERSION_TAG" "false")"
    log "  Add Latest Tag: $(get_env_var "ADD_LATEST_TAG" "false")"
    log "  Add SHA Tag: $(get_env_var "ADD_SHA_TAG" "false")"
    log "  Add Runner Tag: $(get_env_var "ADD_RUNNER_TAG" "false")"
    log "  Push: ${PUSH}"
    log "  Additional Build Folders: ${ADDITIONAL_BUILD_FOLDERS:-none}"
    log "  Container Engine: $(detect_container_engine)"
    log "  CI Environment: ${CI_ENV}"
}

init_git_variables() {
    local repo_dir="$1"

    # Default to empty values
    export SOURCE_GIT_REPO_URL=""
    export SOURCE_GIT_BRANCH=""
    export SOURCE_GIT_COMMIT=""
    export SOURCE_GIT_COMMIT_SHORT=""
    export SOURCE_GIT_COMMIT_DATE=""
    export SOURCE_GIT_TAG=""
    export SOURCE_GIT_DESCRIBE=""

    # If the directory is missing or not a git repo → just return
    if [ ! -d "$repo_dir/.git" ]; then
        echo "Not a git repo: $repo_dir"
        return 0
    fi

    pushd "$repo_dir" > /dev/null || return 1

    # Safely grab git values
    export SOURCE_GIT_REPO_URL=$(git config --get remote.origin.url 2>/dev/null || echo "")
    export SOURCE_GIT_BRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "")
    export SOURCE_GIT_COMMIT=$(git rev-parse HEAD 2>/dev/null || echo "")
    export SOURCE_GIT_COMMIT_SHORT=$(git rev-parse --short HEAD 2>/dev/null || echo "")
    export SOURCE_GIT_COMMIT_DATE=$(git show -s --format=%ci HEAD 2>/dev/null || echo "")
    export SOURCE_GIT_TAG=$(git describe --tags --abbrev=0 2>/dev/null || echo "")
    export SOURCE_GIT_DESCRIBE=$(git describe --always --dirty --tags 2>/dev/null || echo "")

    popd > /dev/null || return 1

    # Optional debug log
    echo "Git repo detected: $repo_dir"
    echo "  URL:     $SOURCE_GIT_REPO_URL"
    echo "  Branch:  $SOURCE_GIT_BRANCH"
    echo "  Commit:  $SOURCE_GIT_COMMIT"
    echo "  Short:   $SOURCE_GIT_COMMIT_SHORT"
    echo "  Date:    $SOURCE_GIT_COMMIT_DATE"
    echo "  Tag:     $SOURCE_GIT_TAG"
    echo "  Describe:$SOURCE_GIT_DESCRIBE"
}

# Build Docker/Podman image
build_docker_image() {
    local dockerfile="$1"
    local image_name="$2"
    local version="$3"
    local tag="$4"
    local prefix="${6:-}"
    local git_repo="${7:-}"
    local extra_args=("${@:8}")
    local container_engine=$(detect_container_engine)
    local temp_context=""
    local build_context=""

    # Ensure version/tag fallbacks so we use resolved values when not explicitly passed
    if [ -z "$version" ]; then
        # try to resolve from config/source
        version=$(get_version "${config:-}" "${REPO_ROOT}/source")
    fi
    if [ -z "$tag" ]; then
        # default tag uses version when available
        if [ -n "$version" ]; then
            tag="$version"
        else
            tag="latest"
        fi
    fi

    # Determine the build context
    if [[ -n "$git_repo" ]]; then
        build_context="$REPO_ROOT/source"
    else
        build_context="${CONTEXT:-$(dirname "$dockerfile")}"
    fi
    log "Using build context: $build_context"

    # Check for additional folders to include in the build context
    local additional_folders="${ADDITIONAL_BUILD_FOLDERS:-}"
    if [ -n "$additional_folders" ]; then
        log "Including additional folders in build context: $additional_folders"

        # Create a temporary directory for the build context
        temp_context=$(create_temp_dir)

        # Copy the original context to the temp directory
        cp -r "$build_context"/* "$temp_context"/ 2>/dev/null || true

        # Copy each additional folder to the temp directory
        IFS=',' read -ra FOLDERS <<< "$additional_folders"
        for folder in "${FOLDERS[@]}"; do
            if [ -d "$folder" ]; then
                local folder_name=$(basename "$folder")
                log "Copying $folder to build context as $folder_name"
                cp -r "$folder" "$temp_context"/ 2>/dev/null || true
            else
                warn "Additional folder not found: $folder"
            fi
        done

        # Use the temporary directory as the build context
        build_context="$temp_context"
        log "Using temporary build context: $build_context"
    fi

    # Docker metadata (labels)
    local labels=(
        "--label" "maintainer=WebM-DevOps"
        "--label" "org.opencontainers.image.title=${image_name}"
        "--label" "org.opencontainers.image.version=${version}"
        "--label" "org.opencontainers.image.revision=${tag}"
        "--label" "org.opencontainers.image.created=$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
        "--label" "org.opencontainers.image.description=${image_name}"
    )

    # Format the image name based on registry type
    local formatted_image_name
    formatted_image_name=$(format_image_name "$REGISTRY" "$image_name" "$prefix")

    # Compose tag list for primary registry
    local tag_args=()
    tag_args+=("--tag" "${formatted_image_name}:${tag}")

    # Add additional tags
    local additional_tags=$(get_env_var "ADDITIONAL_TAGS" "")
    if [ -n "${additional_tags:-}" ]; then
        IFS=',' read -ra TAGS <<< "${additional_tags}"
        for additional_tag in "${TAGS[@]}"; do
            if [ -n "$additional_tag" ]; then
                tag_args+=("--tag" "${formatted_image_name}:${additional_tag}")
                log "Added additional tag: ${additional_tag}"
            fi
        done
    fi

    # Note: We only push to primary registry during build
    # Additional registries will be handled by retag_image function if needed

    local build_args=( "--build-arg" "VERSION=${version}" "--build-arg" "REGISTRY=${REGISTRY}" )

    # Add any additional build args from environment
    local additional_build_args=$(get_env_var "ADDITIONAL_BUILD_ARGS" "")
    if [ -n "${additional_build_args:-}" ]; then
        IFS=',' read -ra ARGS <<< "${additional_build_args}"
        for arg in "${ARGS[@]}"; do
            if [[ "$arg" =~ ^([^=]+)=(.*)$ ]]; then
                local key="${BASH_REMATCH[1]}"
                local value="${BASH_REMATCH[2]}"
                # If value looks like $SOMETHING, resolve it
                if [[ "$value" =~ ^\$([A-Za-z_][A-Za-z0-9_]*)$ ]]; then
                    local var_name="${BASH_REMATCH[1]}"
                    value=$(get_env_var "$var_name" "")
                fi
                build_args+=( "--build-arg" "${key}=${value}" )
                debug "Added build arg: ${key}"
            fi
        done
    fi

    # Handle secrets dynamically
    local secret_args=()

    # Get BUILD_SECRETS from environment or config
    # Format: "secret_id1=env_var1,secret_id2=env_var2"
    local build_secrets=$(get_env_var "BUILD_SECRETS" "")

    if [ -n "$build_secrets" ]; then
        log "Processing build secrets from BUILD_SECRETS variable"
        IFS=',' read -ra SECRET_PAIRS <<< "$build_secrets"

        for pair in "${SECRET_PAIRS[@]}"; do
            if [[ "$pair" =~ ^([^=]+)=(.+)$ ]]; then
                local secret_id="${BASH_REMATCH[1]}"
                local env_var="${BASH_REMATCH[2]}"

                # Get the secret value
                local secret_value=""
                secret_value=$(get_env_var "$env_var" "")

                if [ -z "$secret_value" ]; then
                    secret_value="${!env_var:-}"
                    if [ -z "$secret_value" ]; then
                        warn "Secret is empty for $env_var"
                        continue
                    fi
                fi

                if [ -n "$secret_value" ]; then
                    # Write to temp file
                    local secret_file=$(create_temp_file "secret_${secret_id}")
                    echo -n "$secret_value" > "$secret_file"

                    # Add to build args
                    secret_args+=( "--secret" "id=${secret_id},src=${secret_file}" )
                    debug "Added secret: ${secret_id} from ${env_var}"
                fi
            fi
        done
    fi

    local platform_args=()
    if [ -n "${PLATFORM:-}" ]; then
        platform_args=( "--platform" "$PLATFORM" )
    fi

    local push_args=()

    # Handle push differently for podman vs docker
    if [ "${PUSH}" == "true" ]; then
        if [ "$container_engine" = "podman" ]; then
            # Podman doesn't support --push flag in the same way
            push_args=()
            # We'll handle the push separately after build
        else
            # Docker supports --push flag
            push_args=( "--push" )
        fi
    else
        if [ "$container_engine" = "podman" ]; then
            # Podman may not support --load either
            push_args=()
        else
            push_args=( "--load" )
        fi
        warn "PUSH=false -> building locally (no push)."
    fi

    # Decide SBOM generation method (buildx vs external)
    # - GENERATE_SBOM=true requests SBOM generation
    # - USE_BUILDX_SBOM=true (default) will try to use buildx --sbom if supported by the engine
    # - Buildx SBOM is only useful when pushing (image/artifacts available in registry)
    local do_sbom_env; do_sbom_env="$(get_env_var "GENERATE_SBOM" "false")"
    local use_buildx_sbom; use_buildx_sbom="$(get_env_var "USE_BUILDX_SBOM" "true")"
    # Global-ish flag to indicate buildx handled SBOM generation for this build
    BUILDX_SBOM_USED="false"

    if [[ "${do_sbom_env}" == "true" && "${use_buildx_sbom}" == "true" && "${PUSH}" == "true" ]]; then
        # Probe buildx support on the detected engine (docker or podman)
        if command_exists "${container_engine}"; then
            if "${container_engine}" buildx build --help 2>/dev/null | grep -q -- '--sbom'; then
                debug "Buildx SBOM support detected for ${container_engine}; enabling buildx SBOM"
                # buildx expects a value; use canonical true value. We add it to extra_args so it is included in the build invocation.
                extra_args+=( "--sbom=true" )
                BUILDX_SBOM_USED="true"
            else
                debug "Buildx SBOM not supported by ${container_engine}; will use external SBOM tool (syft) after push"
            fi
        fi
    fi

    # Log the actual command for debugging
    if [[ "${DEBUG}" == "true" ]]; then
        echo "DEBUG: Build command: $container_engine buildx build" >&2
        echo "DEBUG:   Platform args: ${platform_args[*]}" >&2
        echo "DEBUG:   Tag args: ${tag_args[*]}" >&2
        echo "DEBUG:   Labels: ${labels[*]}" >&2
        echo "DEBUG:   Build args: ${build_args[*]}" >&2
        echo "DEBUG:   Secret args: ${secret_args[*]}" >&2
        echo "DEBUG:   Push args: ${push_args[*]}" >&2
        echo "DEBUG:   Extra args: ${extra_args[*]}" >&2
        echo "DEBUG:   Dockerfile: $dockerfile" >&2
        echo "DEBUG:   Build context: $build_context" >&2
    fi

    # We're already logged in to the registry during setup_buildx, no need to login again
    debug "Using registry credentials from previous login"

    # Build and (optionally) push
    $container_engine buildx build \
        "${platform_args[@]}" \
        "${tag_args[@]}" \
        "${labels[@]}" \
        "${build_args[@]}" \
        "${secret_args[@]}" \
        "${push_args[@]}" \
        "${extra_args[@]}" \
        --file "$dockerfile" \
        "$build_context"

    local build_status=$?
    if [ ${build_status} -eq 0 ]; then
        success "Successfully built: ${image_name}"

        # For podman, we need to manually push if PUSH=true
        if [ "${PUSH}" == "true" ] && [ "$container_engine" = "podman" ]; then
            log "Manually pushing image with podman: ${formatted_image_name}:${tag}"
            $container_engine push "${formatted_image_name}:${tag}"

            # Push any additional tags
            if [ -n "${additional_tags}" ]; then
                log "Pushing additional tags with podman"
                IFS=',' read -ra TAGS <<< "${additional_tags}"
                for additional_tag in "${TAGS[@]}"; do
                    if [ -n "$additional_tag" ]; then
                        log "Pushing additional tag: ${formatted_image_name}:${additional_tag}"
                        $container_engine push "${formatted_image_name}:${additional_tag}"
                    fi
                done
            fi
        fi

        # --- NEW: generate SBOM and sign images if requested (primary + additional tags) ---
        local do_sbom; do_sbom="$(get_env_var "GENERATE_SBOM" "false")"
        local do_sign; do_sign="$(get_env_var "SIGN_IMAGE" "false")"

        if [ "${PUSH}" == "true" ]; then
            # Only attempt SBOM/sign after push (image available in registry)
            local main_ref="${formatted_image_name}:${tag}"

            if [[ "${do_sbom}" == "true" ]]; then
                if [[ "${BUILDX_SBOM_USED}" == "true" ]]; then
                    log "SBOM generation was requested and buildx produced SBOM artifacts for ${main_ref} (attached/pushed by buildx)."
                    log "If you need the SBOM locally, set USE_BUILDX_SBOM=false and GENERATE_SBOM=true to force syft fallback."
                else
                    debug "Request to generate SBOM for ${main_ref} using external tool"
                    sbom_file="$(generate_sbom_for_image "${main_ref}" || true)"
                    if [ -n "${sbom_file}" ]; then
                        log "SBOM available at: ${sbom_file} (not uploaded)"
                    fi
                fi
            fi

            if [[ "${do_sign}" == "true" ]]; then
                debug "Request to sign image ${main_ref}"
                sign_image_with_cosign "${main_ref}" || warn "Signing failed for ${main_ref}"
            fi

            # Additional tags
            if [ -n "${additional_tags}" ]; then
                IFS=',' read -ra TAGS <<< "${additional_tags}"
                for additional_tag in "${TAGS[@]}"; do
                    if [ -n "$additional_tag" ]; then
                        local ref="${formatted_image_name}:${additional_tag}"
                        if [[ "${do_sbom}" == "true" ]]; then
                            if [[ "${BUILDX_SBOM_USED}" == "true" ]]; then
                                log "SBOM (buildx) should also be attached/pushed for tag ${ref} when buildx performed multi-tag push."
                            else
                                debug "Generating SBOM for ${ref} using external tool"
                                sbom_file="$(generate_sbom_for_image "${ref}" || true)"
                                if [ -n "${sbom_file}" ]; then
                                    log "SBOM for ${ref}: ${sbom_file}"
                                fi
                            fi
                        fi
                        if [[ "${do_sign}" == "true" ]]; then
                            debug "Signing ${ref}"
                            sign_image_with_cosign "${ref}" || warn "Signing failed for ${ref}"
                        fi
                    fi
                done
            fi
        else
            debug "PUSH!=true, skipping SBOM/signing since image is not pushed to registry"
        fi
        # --- END NEW ---

        # Promote to additional registries if needed and if we have a YAML config
        if [ "${PUSH}" == "true" ] && [ -n "${config:-}" ] && [ -f "${config:-}" ]; then
            promote_to_additional_registries "$image_name" "$tag" "$version" "$prefix"
        fi
    else
        error "Failed to build image: ${image_name}"
        return ${build_status}
    fi

    return 0
}

# Retag/promote an existing image using skopeo to preserve SHA IDs and digests
retag_image() {
    local source_image="$1"
    local target_image="$2"
    local copy_signatures="${3:-true}"

    log "Retagging/promoting image: ${source_image} -> ${target_image}"

    # ---- derive registries and repos ----
    local src_registry dest_registry dest_repo_path dest_repo dest_region
    src_registry="$(printf '%s' "$source_image" | sed -e 's|^docker://||' -e 's|^https\?://||' | cut -d'/' -f1)"
    dest_registry="$(printf '%s' "$target_image" | sed -e 's|^docker://||' -e 's|^https\?://||' | cut -d'/' -f1)"
    dest_repo_path="$(printf '%s' "$target_image" | sed -e 's|^docker://||' -e 's|^https\?://||' -e "s|^${dest_registry}/||")"
    dest_repo="${dest_repo_path%%@*}"; dest_repo="${dest_repo%%:*}"
    dest_region="$(ecr_region_from_registry "$dest_registry")"

    # ---- login (engine), so skopeo can reuse authfile ----
    if [ "${SKIP_REGISTRY_LOGIN:-0}" -ne 1 ]; then
        debug "Ensuring login to source registry: ${src_registry}"
        login_to_registry "$src_registry" || warn "Login to $src_registry failed; will try authfile/defaults"
        debug "Ensuring login to destination registry: ${dest_registry}"
        login_to_registry "$dest_registry" || warn "Login to $dest_registry failed; will try authfile/defaults"
    else
        debug "SKIP_REGISTRY_LOGIN=1 set; assuming prior login / anonymous access"
    fi

    # ---- optional: auto-create ECR repo ----
    if [[ "$dest_registry" == *.amazonaws.com ]] && [ "${ECR_AUTO_CREATE:-0}" -eq 1 ] && command_exists aws; then
        if [ -z "$dest_region" ]; then
            dest_region="$(get_env_var "AWS_DEFAULT_REGION" "us-east-1")"
        fi
        debug "ECR_AUTO_CREATE=1: ensuring ECR repo exists: ${dest_repo} (region: ${dest_region})"
        # Try to create; if it exists, AWS returns RepositoryAlreadyExistsException and exits non‑zero,
        # so first check, then create (or you can attempt create and ignore that one specific error).
        if ! aws ecr describe-repositories --region "$dest_region" --repository-names "$dest_repo" >/dev/null 2>&1; then
            aws ecr create-repository --region "$dest_region" --repository-name "$dest_repo" >/dev/null 2>&1 || true
        fi
    fi
    # (AWS docs and examples show creating the repository first; nested names like "project-a/sample-repo" are valid.)  # FYI
    #                                                                                                                # [1](https://docs.aws.amazon.com/AmazonECR/latest/userguide/example_ecr_CreateRepository_section.html)

    # ---- build skopeo options ----
    local skopeo_global=()
    local skopeo_opts=("--preserve-digests")

    [[ "${DEBUG}" == "true" ]] && skopeo_global+=("--debug")

    if skopeo copy --help | grep -q "\-\-multi-arch"; then
        skopeo_opts+=("--multi-arch" "all")
    elif skopeo copy --help | grep -q "\-\-all[^-]"; then
        skopeo_opts+=("--all")
    fi

    skopeo_opts+=("--retry-times" "${SKOPEO_RETRY_TIMES:-3}")
    if skopeo copy --help | grep -q "\-\-retry-delay"; then
        skopeo_opts+=("--retry-delay" "${SKOPEO_RETRY_DELAY:-5s}")  # requires a time unit like 's' or 'm'
    fi

    local authfile=""
    if authfile="$(resolve_authfile)"; then
        skopeo_opts+=("--authfile" "$authfile")
        export REGISTRY_AUTH_FILE="$authfile"
        debug "Skopeo authfile: $authfile"
    else
        warn "No authfile found; Skopeo may try anonymous or other defaults"
    fi

    # ---- run skopeo; capture stderr to detect actionable errors ----
    local errfile; errfile="$(mktemp)"
    local show_cmd="skopeo ${skopeo_global[*]} copy ${skopeo_opts[*]} docker://${source_image} docker://${target_image}"
    debug "Executing: $show_cmd"

    if ! skopeo "${skopeo_global[@]}" copy "${skopeo_opts[@]}" "docker://${source_image}" "docker://${target_image}" 2>"$errfile"; then
        # If the error is clearly "repo not found", do NOT retry without preserve-digests; fail fast with guidance.
        if grep -qiE 'name unknown.*repository|repository.*does not exist' "$errfile"; then
            error "Destination repository '${dest_repo}' does not exist in ${dest_registry}. Create it first, e.g.:
  aws ecr create-repository --repository-name ${dest_repo} --region ${dest_region:-<your-region>}"
            # (ECR requires the repository to exist before a push.)  # [1](https://docs.aws.amazon.com/AmazonECR/latest/userguide/example_ecr_CreateRepository_section.html)
            cat "$errfile" >&2; rm -f "$errfile"; return 1
        fi

        warn "Skopeo copy with --preserve-digests failed; retrying without it (only for compatibility)"
        # SAFELY drop the flag WITHOUT leaving empty entries (fixes: 'Exactly two arguments expected')
        local _new_opts=() x
        for x in "${skopeo_opts[@]}"; do
            [ "$x" != "--preserve-digests" ] && _new_opts+=("$x")
        done
        skopeo_opts=("${_new_opts[@]}")

        show_cmd="skopeo ${skopeo_global[*]} copy ${skopeo_opts[*]} docker://${source_image} docker://${target_image}"
        debug "Retrying: $show_cmd"

        if ! skopeo "${skopeo_global[@]}" copy "${skopeo_opts[@]}" "docker://${source_image}" "docker://${target_image}"; then
            cat "$errfile" >&2; rm -f "$errfile"; return 1
        fi
    fi
    rm -f "$errfile"

    # ---- optional: cosign signatures ----
    if [ "$copy_signatures" = "true" ]; then
        if command_exists cosign; then
            log "Copying cosign signatures (best-effort)"
            if cosign verify "$source_image" &>/dev/null; then
                if [ -f "cosign.key" ]; then
                    log "Signing target image with cosign key"
                    cosign sign --key cosign.key "$target_image" 2>/dev/null || true
                else
                    log "Attempting direct signature copy"
                    cosign copy "$source_image" "$target_image" 2>/dev/null || true
                fi
            else
                warn "No signatures found for $source_image"
            fi
        else
            warn "cosign not found; skipping signature copy"
        fi
    fi

    success "Successfully retagged/promoted image: ${target_image}"
}



# Promote images to additional registries
promote_to_additional_registries() {
    local image_name="$1"
    local tag="$2"
    local version="$3"
    local prefix="${4:-}"

    # Check if we have a YAML configuration for registries
    if [ -n "${config:-}" ] && [ -f "${config:-}" ]; then
        # Get registry list from YAML
        local registry_list=$(get_yaml_value "$config" "REGISTRY")

        if [[ "${DEBUG}" == "true" ]]; then
            debug "Registry list from YAML: $registry_list"
        fi

        # If registry list is in YAML format, process each registry
        if [ -n "$registry_list" ]; then
            # Get the number of registries in the list
            local registry_count=$(echo "$registry_list" | grep -c "name:")

            if [[ "${DEBUG}" == "true" ]]; then
                debug "Found $registry_count registries in YAML"
            fi

            # Get primary registry (first one in the list)
            local primary_registry=$(get_yaml_value "$config" "REGISTRY[0].name")
            local primary_prefix=$(get_yaml_value "$config" "REGISTRY[0].prefix")

            # Format source image using format_image_name to ensure consistency
            # pass prefix as 3rd arg (was incorrectly passed as 4th)
            local source_image
            source_image=$(format_image_name "$primary_registry" "$image_name" "$primary_prefix")

            debug "Source image for promotion: $source_image"

            # Process each registry for push
            for ((i=1; i<registry_count; i++)); do
                local registry_name=$(get_yaml_value "$config" "REGISTRY[$i].name")
                local registry_prefix=$(get_yaml_value "$config" "REGISTRY[$i].prefix")
                local registry_push=$(get_yaml_value "$config" "REGISTRY[$i].push")

                if [[ "${DEBUG}" == "true" ]]; then
                    debug "Processing registry for push: $registry_name, prefix: $registry_prefix, push: $registry_push"
                fi

                # Only push to registries with push=true
                if [ "$registry_push" == "true" ] && [ "${PUSH}" == "true" ]; then
                    log "Promoting image to registry: $registry_name"

                    # Format target image using format_image_name to ensure consistency
                    # pass prefix as 3rd arg (was incorrectly passed as 4th)
                    local target_image
                    target_image=$(format_image_name "$registry_name" "$image_name" "$registry_prefix")

                    debug "Target image for promotion: $target_image"

                    # Promote main tag
                    retag_image "${source_image}:${tag}" "${target_image}:${tag}"

                    # Promote additional tags if any
                    local additional_tags=$(get_env_var "ADDITIONAL_TAGS" "")
                    if [ -n "${additional_tags:-}" ]; then
                        IFS=',' read -ra TAGS <<< "${additional_tags}"
                        for additional_tag in "${TAGS[@]}"; do
                            if [ -n "$additional_tag" ]; then
                                retag_image "${source_image}:${additional_tag}" "${target_image}:${additional_tag}"
                            fi
                        done
                    fi
                fi
            done
        fi
    fi
}

# Get version from various sources
get_version() {
    local config="$1"
    local source_dir="$2"
    local version=""

    # 1. YAML config version
    version=$(get_env_var "version" "")
    if [[ -n "$version" && "$version" != "null" ]]; then
        echo "$version"
        return
    fi

    # 2. GitHub tag (e.g., refs/tags/v1.2.3 or refs/tags/1.2.3-beta)
    if [[ "$GITHUB_REF" =~ ^refs/tags/v?([0-9]+(\.[0-9]+){1,2}([-a-zA-Z0-9\.]*)?)$ ]]; then
        version="${BASH_REMATCH[1]}"
        echo "$version"
        return
    fi

    # 3. GitHub branch (e.g., refs/heads/release/1.2.3 or refs/heads/v1.0.0)
    if [[ "$GITHUB_REF" =~ ^refs/heads/(release/)?v?([0-9]+(\.[0-9]+){1,2}([-a-zA-Z0-9\.]*)?)$ ]]; then
        version="${BASH_REMATCH[2]}"
        echo "$version"
        return
    fi

    # 4. GitHub branch is main or master → latest
    if [[ "$GITHUB_REF" =~ ^refs/heads/(main|master)$ ]]; then
        echo "latest"
        return
    fi

    # 5. Local Git branch (e.g., release/1.2.3, v1.0.0, 2.3.4-rc1)
    if [[ -d "$source_dir/.git" ]]; then
        local branch
        branch=$(git -C "$source_dir" rev-parse --abbrev-ref HEAD 2>/dev/null)

        if [[ "$branch" =~ ^(release/)?v?([0-9]+(\.[0-9]+){1,2}([-a-zA-Z0-9\.]*)?)$ ]]; then
            version="${BASH_REMATCH[2]}"
            echo "$version"
            return
        elif [[ "$branch" == "main" || "$branch" == "master" ]]; then
            echo "latest"
            return
        fi
    fi

    # 6. Fallback to env var, DEFAULT_VERSION, or 'latest'
    version="${VERSION:-${DEFAULT_VERSION:-latest}}"
    echo "$version"
}

# =============================================================================
# Main Functions
# =============================================================================

# Main function for building images
main_build() {
    local git_repo=""
    local dockerfile_rel_location=""
    local git_branch=""
    local version=""
    local tag=""
    local image_name=""
    local image_prefix=""
    local config_path=""
    local definition=""
    local extra_args=()
    local additional_registries=""
    local retag_source_target=""
    local copy_signatures="true"

    # Debug: Print all arguments received
    if [[ "${DEBUG}" == "true" ]]; then
        echo "DEBUG: main_build received arguments: $*" >&2
        echo "DEBUG: argument count: $#" >&2
    fi

    # Check if first argument is not an option (doesn't start with -), treat it as image_name
    if [[ $# -gt 0 && ! "$1" == -* ]]; then
        image_name="$1"
        export IMAGE_NAME="$image_name"
        echo "DEBUG: Setting image_name to first positional argument: $image_name"
        shift
    fi

    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -c|--git-repo)
                git_repo="$2"
                shift 2
                ;;
            -i|--dockerfile)
                dockerfile_rel_location="$2"
                shift 2
                ;;
            -b|--branch)
                git_branch="$2"
                shift 2
                ;;
            -v|--version)
                version="$2"
                shift 2
                ;;
            -t|--tag)
                tag="$2"
                shift 2
                ;;
            -r|--registry)
                REGISTRY="$2"
                # If empty, we'll set it during initialization using common build.yaml
                if [ -z "$REGISTRY" ]; then
                    log "Empty registry provided, will check common build.yaml during initialization"
                fi
                shift 2
                ;;
            -p|--push)
                PUSH="$2"
                # Convert to lowercase for consistent comparison
                PUSH=$(echo "$PUSH" | tr '[:upper:]' '[:lower:]')
                debug "Setting PUSH from command line: $PUSH"
                shift 2
                ;;
            -s|--secrets)
                # Parse secrets and set them as environment variables
                IFS=',' read -ra SECRETS <<< "$2"
                for secret in "${SECRETS[@]}"; do
                    if [[ "$secret" =~ ^([^=]+)=(.*)$ ]]; then
                        local key="${BASH_REMATCH[1]}"
                        local value="${BASH_REMATCH[2]}"
                        export "$key"="$value"
                        debug "Set secret environment variable: $key"
                    fi
                done
                shift 2
                ;;
            -d|--definition)
                definition=$2
                log "Using definition: $definition"
                shift 2
                ;;
            -e|--extra-args)
                # Parse extra args for docker build
                IFS=',' read -ra ARGS <<< "$2"
                for arg in "${ARGS[@]}"; do
                    extra_args+=("$arg")
                done
                shift 2
                ;;
            --prefix)
                image_prefix="$2"
                # Also set the environment variable for consistency
                export IMAGE_PREFIX="$image_prefix"
                log "Using image prefix: $image_prefix"
                shift 2
                ;;
            -f|--additional-folders)
                # Set additional folders to include in build context
                export ADDITIONAL_BUILD_FOLDERS="$2"
                log "Using additional build folders: $ADDITIONAL_BUILD_FOLDERS"
                shift 2
                ;;
            --retag)
                retag_source_target="$2"
                shift 2
                ;;
            --copy-signatures)
                copy_signatures="$2"
                shift 2
                ;;
            --debug)
                DEBUG="true"
                shift
                ;;
            --no-debug)
                DEBUG="false"
                shift
                ;;
            -*)
                error "Unknown option: $1"
                exit 1
                ;;
            *)
                # Always use the first positional argument as image_name
                # This makes the script more predictable
                if [ -z "$image_name" ]; then
                    image_name="$1"
                    export IMAGE_NAME="$image_name"
                    log "Using positional argument '$1' as image name"
                    shift
                else
                    # If image_name is already set, this is an unexpected argument
                    error "Unexpected argument: $1 (image name is already set to '$image_name')"
                    exit 1
                fi
                ;;
        esac
    done

    # Only initialize once
    if [ -z "${INITIALIZED:-}" ]; then
        # Mark as initialized to prevent duplicate initialization
        INITIALIZED=true

        # Set config path from definition if provided
        if [[ -n "$definition" ]]; then
            config="$definition"
        fi

        # Get git branch if not provided
        if [[ -z "$git_branch" ]]; then
            # Try to get from YAML if config exists
            if [[ -n "$config" && -f "$config" ]]; then
                git_branch=$(get_yaml_value "$config" "branch")
            fi

            # Fallback to default
            if [[ -z "$git_branch" ]]; then
                git_branch="main"
            fi
        fi

        # Clone repository if specified
        if [[ -n "$git_repo" ]]; then
            log "Cloning repository: $git_repo (branch: $git_branch)"
            load_repository "$git_repo" "$git_branch" "$REPO_ROOT/source" "GITHUB_TOKEN"
        fi

        # Initialize build environment
        initialize

        # Setup buildx (this will also handle login to registries)
        setup_buildx
    else
        debug "Environment already initialized, skipping initialization"
    fi

    # Handle retag operation if specified
    if [ -n "$retag_source_target" ]; then
        log "Performing image retag/promotion operation"

        # Parse source and target from the format "source:target"
        if [[ "$retag_source_target" =~ ^(.+):(.+)$ ]]; then
            local source_image="${BASH_REMATCH[1]}"
            local target_image="${BASH_REMATCH[2]}"

            # Login to registries (needed for both source and target)
            login_to_registries

            # Perform the retag operation
            retag_image "$source_image" "$target_image" "$copy_signatures"

            # Exit after retag operation
            exit $?
        else
            error "Invalid retag format. Use --retag 'source_image:target_image'"
            exit 1
        fi
    fi


    # Get image prefix from environment if not set via command line
    if [[ -z "$image_prefix" ]]; then
        image_prefix=$(get_env_var "IMAGE_PREFIX" "")
        if [[ -n "$image_prefix" ]]; then
            log "Using image prefix from environment: $image_prefix"
        fi
    fi

    # Get image name from environment if not set via command line
    if [ -z "$image_name" ]; then
        image_name=$(get_env_var "IMAGE_NAME" "")
        if [[ -n "$image_name" ]]; then
            log "Using image name from environment: $image_name"
        else
            error "Image name not provided. Use positional argument or set IMAGE_NAME environment variable."
            exit 1
        fi
    fi

    # Git branch has already been determined earlier

    # Build the image with enhanced information
    build_docker_image "$dockerfile" "$image_name" "$version" "$tag" "" "$image_prefix" "$git_repo" "${extra_args[@]}"
}
