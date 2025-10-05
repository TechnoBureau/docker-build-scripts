#!/usr/bin/env bash
set -euo pipefail

# ========= DEFAULTS =========
DEFAULT_HOME="$HOME"
DEFAULT_VENV="$DEFAULT_HOME/.venv"
DEFAULT_REQUIREMENTS=""
DEFAULT_UNINSTALL=""

# ========= INPUT PARSING =========
VENV_PATH=""
TARGET_HOME=""
REQUIREMENTS_FILE=""
UNINSTALL_FILE=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --venv)
            VENV_PATH="$2"
            shift 2
            ;;
        --home)
            TARGET_HOME="$2"
            shift 2
            ;;
        --requirements)
            REQUIREMENTS_FILE="$2"
            shift 2
            ;;
        --uninstall)
            UNINSTALL_FILE="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# ========= FALLBACKS =========
TARGET_HOME="${TARGET_HOME:-$DEFAULT_HOME}"
VENV_PATH="${VENV_PATH:-$DEFAULT_VENV}"

# If VENV_PATH is a name like ".env" or "venv", treat as relative to TARGET_HOME
if [[ "$VENV_PATH" != /* ]]; then
    VENV_PATH="$TARGET_HOME/$VENV_PATH"
fi

# Fallbacks for optional files
REQUIREMENTS_FILE="${REQUIREMENTS_FILE:-$TARGET_HOME/tmp/requirements.txt}"
UNINSTALL_FILE="${UNINSTALL_FILE:-$TARGET_HOME/tmp/requirements-uninstall.txt}"


# ========= LOGGING UTILS =========
log_info()    { echo -e "\033[1;34m[INFO]\033[0m $1"; }
log_success() { echo -e "\033[1;32m[SUCCESS]\033[0m $1"; }
log_error()   { echo -e "\033[1;31m[ERROR]\033[0m $1" >&2; }

# ========= PYTHON DETECTION =========
detect_python() {
    local python_candidates=("python3.13" "python3.12" "python3.11" "python3.10" "python3.9" "python3" "python")
    for cmd in "${python_candidates[@]}"; do
        if command -v "$cmd" >/dev/null 2>&1; then
            "$cmd" -c "import sys; exit(0) if sys.version_info >= (3, 7) else exit(1)" && {
                echo "$cmd"
                return
            }
        fi
    done
    log_error "No suitable Python 3.7+ interpreter found."
    exit 1
}

# ========= FUNCTIONS =========
create_venv() {
    log_info "Creating virtual environment at: $VENV_PATH"
    "$PYTHON_BIN" -m venv --copies --upgrade-deps "$VENV_PATH"
    source "$VENV_PATH/bin/activate"
}

install_requirements() {
    if [[ -f "$REQUIREMENTS_FILE" ]]; then
        log_info "Installing Python packages from: $REQUIREMENTS_FILE"
        pip install --no-cache-dir -r "$REQUIREMENTS_FILE"
    else
        log_info "No requirements file found at: $REQUIREMENTS_FILE — skipping"
    fi
}
uninstall_packages() {
    if [[ ! -f "$UNINSTALL_FILE" ]]; then
        log_info "No uninstall file found at: $UNINSTALL_FILE — skipping uninstallation"
        return
    fi

    log_info "Uninstalling packages from: $UNINSTALL_FILE"

    while IFS= read -r package || [[ -n "$package" ]]; do
        package=$(echo "$package" | xargs)  # Trim whitespace
        [[ -z "$package" ]] && continue

        log_info "Attempting to uninstall: $package"
        if pip uninstall -y "$package"; then
            log_info "Successfully uninstalled: $package"
        else
            log_info "Standard uninstall failed for: $package — retrying with --break-system-packages"
            if ! pip uninstall -y --break-system-packages "$package"; then
                log_error "Failed to uninstall package: $package (even with --break-system-packages)"
            fi
        fi
    done < "$UNINSTALL_FILE"
}

cleanup_pip() {
    log_info "Uninstalling pip from virtual environment"
    pip uninstall -y pip || log_info "pip already removed or not found"
}

# ========= MAIN =========
main() {
    mkdir -p "$(dirname "$VENV_PATH")"
    mkdir -p "$TARGET_HOME/tmp"

    PYTHON_BIN=$(detect_python)
    log_info "Using Python interpreter: $PYTHON_BIN"

    create_venv
    install_requirements
    uninstall_packages
    cleanup_pip
    deactivate

    log_success "Virtual environment setup complete!"
    log_info "Venv Path     : $VENV_PATH"
    log_info "Target Home   : $TARGET_HOME"
    log_info "Requirements  : $REQUIREMENTS_FILE"
    log_info "Uninstall List: $UNINSTALL_FILE"
    
}

main
