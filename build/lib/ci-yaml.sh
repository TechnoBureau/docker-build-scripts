#!/usr/bin/env bash
# lib/ci-yaml.sh
#
# Purpose:
#   YAML scalar parsing with fallback (yq -> python -> awk). Registry parsing helper.
#
# Usage:
#   source lib/ci-yaml.sh
#
# Functions:
#   parse_yaml_scalar <file> <yaml_key> <out_key> -> writes result to CONFIG["YAML_<out_key>"]
#   parse_yaml_registries <file> -> populates REGISTRIES (if empty)
#
# Example:
#   parse_yaml_scalar operator-config.yaml "operator.name" "OP_NAME"
#   echo "${CONFIG[YAML_OP_NAME]}"
#

# Source dependencies
if [[ -z "${CI_CORE_LOADED:-}" ]]; then
    LIB_DIR="${LIB_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
    # shellcheck source=/dev/null
    source "${LIB_DIR}/ci-core.sh"
fi

declare -gA CONFIG 2>/dev/null || true
declare -ga REGISTRIES 2>/dev/null || true

parse_yaml_scalar(){
    local file="$1" yaml_key="$2" out_key="$3"
    [[ ! -f "$file" ]] && return 0
    local value=""
    # prefer mikefarah yq
    if command -v yq >/dev/null 2>&1 && [[ $(yq --version 2>/dev/null) == *"mikefarah"* ]]; then
        value="$(yq eval -r ".$yaml_key // \"\"" "$file" 2>/dev/null || echo "")"
        [[ -n "$value" ]] && { CONFIG["YAML_$out_key"]="$value"; return 0; }
    fi

    # try python yaml.safe_load if python3 exists and yaml module is available
    if command -v python3 >/dev/null 2>&1; then
        value="$(python3 - <<PY 2>/dev/null
import sys
try:
    import yaml
    data=yaml.safe_load(open('$file')) or {}
    keys='$yaml_key'.split('.')
    cur=data
    for k in keys:
        if isinstance(cur, dict) and k in cur:
            cur=cur[k]
        else:
            cur=None
            break
    print(cur if cur is not None else '')
except ImportError:
    # yaml module not available, skip this method
    sys.exit(1)
except Exception:
    sys.exit(1)
PY
)" || true
        if [[ -n "$value" ]]; then CONFIG["YAML_$out_key"]="$value"; return 0; fi
    fi

    # awk fallback for simple top-level keys
    local awk_script='
    $0 ~ /^[[:space:]]*'"$yaml_key"'[[:space:]]*:/{ sub(/^[[:space:]]*'"$yaml_key"'[[:space:]]*:[[:space:]]*/,""); gsub(/^[\"\047]/,""); gsub(/[\"\047].*$/,""); gsub(/^[[:space:]]+|[[:space:]]+$/,""); print $0; exit }
    '
    value="$(awk "$awk_script" "$file" 2>/dev/null || echo "")"
    [[ -n "$value" ]] && CONFIG["YAML_$out_key"]="$value"
}

parse_yaml_registries(){
    local file="$1"
    [[ ! -f "$file" ]] && return 0
    local i=0
    while true; do
        parse_yaml_scalar "$file" "REGISTRY[$i].name" "REG_${i}_NAME"
        parse_yaml_scalar "$file" "REGISTRY[$i].prefix" "REG_${i}_PREFIX"
        parse_yaml_scalar "$file" "REGISTRY[$i].push" "REG_${i}_PUSH"
        local name="${CONFIG[YAML_REG_${i}_NAME]:-}"
        [[ -z "$name" ]] && break
        local prefix="${CONFIG[YAML_REG_${i}_PREFIX]:-}"
        local push="${CONFIG[YAML_REG_${i}_PUSH]:-true}"
        push="$(printf '%s' "$push" | tr '[:upper:]' '[:lower:]')"
        if [[ "$push" =~ ^(true|yes|1)$ ]]; then push="true"; else push="false"; fi
        REGISTRIES+=("$name,$prefix,$push")
        ((i++))
    done
}
