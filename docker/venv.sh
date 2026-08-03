#!/usr/bin/env bash
set -euo pipefail
# ========= DEFAULTS =========
DEFAULT_HOME="$HOME"
DEFAULT_VENV="$DEFAULT_HOME/.venv"
DEFAULT_PYTHON_VERSION="3.14"
DEFAULT_INSTALL_DIR="/usr/local"

# ========= INPUT PARSING =========
VENV_PATH=""
TARGET_HOME=""
REQUIREMENTS_FILE=""
UNINSTALL_FILE=""
MIN_PYTHON_VERSION=""
PYTHON_INSTALL_DIR=""
NO_DEPS=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --venv)           VENV_PATH="$2"; shift 2 ;;
        --home)           TARGET_HOME="$2"; shift 2 ;;
        --requirements)   REQUIREMENTS_FILE="$2"; shift 2 ;;
        --uninstall)      UNINSTALL_FILE="$2"; shift 2 ;;
        --python-version) MIN_PYTHON_VERSION="$2"; shift 2 ;;
        --install-dir)    PYTHON_INSTALL_DIR="$2"; shift 2 ;;
        --no-deps)        NO_DEPS="true"; shift ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

# ========= FALLBACKS =========
TARGET_HOME="${TARGET_HOME:-$DEFAULT_HOME}"
VENV_PATH="${VENV_PATH:-$DEFAULT_VENV}"
MIN_PYTHON_VERSION="${MIN_PYTHON_VERSION:-$DEFAULT_PYTHON_VERSION}"
PYTHON_INSTALL_DIR="${PYTHON_INSTALL_DIR:-$DEFAULT_INSTALL_DIR}"

[[ "$VENV_PATH" != /* ]] && VENV_PATH="$TARGET_HOME/$VENV_PATH"

REQUIREMENTS_FILE="${REQUIREMENTS_FILE:-$TARGET_HOME/tmp/requirements.txt}"
UNINSTALL_FILE="${UNINSTALL_FILE:-$TARGET_HOME/tmp/requirements-uninstall.txt}"

# ========= LOGGING UTILS =========
log_info()    { echo -e "\033[1;34m[INFO]\033[0m $1"; }
log_success() { echo -e "\033[1;32m[SUCCESS]\033[0m $1"; }
log_error()   { echo -e "\033[1;31m[ERROR]\033[0m $1" >&2; }
log_warning() { echo -e "\033[1;33m[WARNING]\033[0m $1"; }

# ========= HELPER FUNCTIONS =========
version_compare() {
    local IFS='.'
    read -ra ver1 <<< "$1"
    read -ra ver2 <<< "$2"

    for ((i=0; i<${#ver1[@]} || i<${#ver2[@]}; i++)); do
        local v1="${ver1[i]:-0}" v2="${ver2[i]:-0}"
        ((v1 > v2)) && return 0
        ((v1 < v2)) && return 1
    done
    return 0
}

create_symlink() {
    local target="$1" link_name="$2"
    if [[ -e "$link_name" ]] && [[ ! -L "$link_name" ]]; then
        log_warning "Existing binary at $link_name, skipping symlink" >&2
        return 1
    else
        # Use absolute paths to avoid "File name too long" errors
        local target_path="$(realpath "$target" 2>/dev/null || echo "$target")"
        ln -sf "$target_path" "$link_name" 2>/dev/null && {
            log_info "Created symlink: $(basename "$link_name") -> $(basename "$target_path")" >&2
            return 0
        } || {
            log_warning "Failed to create symlink $link_name -> $target_path" >&2
            return 1
        }
    fi
}

detect_openssl_path() {
    local search_paths=("/usr" "/usr/local" "/opt/openssl" "/usr/local/ssl")

    if pkg-config --exists openssl 2>/dev/null; then
        pkg-config --variable=prefix openssl
        return 0
    fi

    for path in "${search_paths[@]}"; do
        if [[ -f "${path}/include/openssl/ssl.h" ]]; then
            if [[ -f "${path}/lib/libssl.so" ]] || [[ -f "${path}/lib64/libssl.so" ]] || \
               [[ -f "${path}/lib/libssl.a" ]] || [[ -f "${path}/lib64/libssl.a" ]]; then
                echo "$path"
                return 0
            fi
        fi
    done
    echo ""
}

install_rhel_packages() {
    local pkg_manager="$1"
    "$pkg_manager" groupinstall -y -q "Development Tools" 2>/dev/null || true

    local packages=(
        "openssl-devel" "openssl-libs" "bzip2-devel" "libffi-devel"
        "zlib-devel" "readline-devel" "sqlite-devel" "tk-devel"
        "xz-devel" "wget" "curl" "ca-certificates" "mpdecimal-devel"
    )
    for pkg in "${packages[@]}"; do
        "$pkg_manager" install -y -q "$pkg" 2>/dev/null || log_warning "Package $pkg not available" >&2
    done
}

# ========= PYTHON DETECTION =========
detect_or_install_python() {
    local min_major="${MIN_PYTHON_VERSION%%.*}"
    local min_minor="${MIN_PYTHON_VERSION#*.}"
    min_minor="${min_minor%%.*}"

    log_info "Searching for Python ${MIN_PYTHON_VERSION}+..." >&2

    local python_candidates=("python3.20" "python3.19" "python3.18" "python3.17" "python3.16" "python3.15" "python3.14" "python3.13" "python3.12" "python3" "python")
    local found_without_ssl=""

    for cmd in "${python_candidates[@]}"; do
        if command -v "$cmd" >/dev/null 2>&1; then
            local version
            version=$("$cmd" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}')" 2>/dev/null || echo "0.0.0")

            if version_compare "$version" "${MIN_PYTHON_VERSION}"; then
                if "$cmd" -c "import ssl" 2>/dev/null; then
                    log_success "Found Python: $cmd (v$version) with SSL" >&2
                    echo "$cmd"
                    return 0
                elif [[ -z "$found_without_ssl" ]]; then
                    found_without_ssl="$cmd"
                    log_warning "Found $cmd (v$version) but SSL missing" >&2
                fi
            fi
        fi
    done

    [[ -n "$found_without_ssl" ]] && log_warning "Will rebuild Python with SSL..." >&2

    log_warning "Python ${MIN_PYTHON_VERSION}+ not found. Installing..." >&2
    install_python_from_source

    # Try multiple possible binary names after installation
    local installed_python=""
    for python_bin in "${PYTHON_INSTALL_DIR}/bin/python${MIN_PYTHON_VERSION}" "${PYTHON_INSTALL_DIR}/bin/python3" "${PYTHON_INSTALL_DIR}/bin/python"; do
        if [[ -x "$python_bin" ]]; then
            installed_python="$python_bin"
            break
        fi
    done

    if [[ -x "$installed_python" ]]; then
        log_success "Python installed: $installed_python" >&2
        echo "$installed_python"
    else
        log_error "Python installation failed - no binary found" >&2
        exit 1
    fi
}

# ========= PYTHON INSTALLATION =========
install_python_from_source() {
    local original_dir="$PWD"
    local temp_dir=$(mktemp -d)

    # Cleanup function to ensure we return to original directory and remove temp
    cleanup_python_install() {
        cd "$original_dir" 2>/dev/null || cd /
        rm -rf "$temp_dir"
    }


    local python_version
    python_version=$(curl -sL https://www.python.org/ftp/python/ | \
        grep -oP ">${MIN_PYTHON_VERSION}\.\d+/" | \
        sed 's/[>/]//g' | sort -V | tail -n1)

    python_version="${python_version:-${MIN_PYTHON_VERSION}.0}"

    local download_url="https://www.python.org/ftp/python/${python_version}/Python-${python_version}.tgz"
    cd "$temp_dir" || { cleanup_python_install; exit 1; }

    # Install build dependencies
    if command -v microdnf >/dev/null 2>&1; then
        install_rhel_packages "microdnf" >&2
    elif command -v dnf >/dev/null 2>&1; then
        install_rhel_packages "dnf" >&2
    elif command -v yum >/dev/null 2>&1; then
        install_rhel_packages "yum" >&2
    else
        log_error "Unsupported package manager" >&2
        cleanup_python_install
        exit 1
    fi

    # Detect OpenSSL
    local openssl_dir
    openssl_dir=$(detect_openssl_path)

    if [[ -z "$openssl_dir" ]]; then
        log_error "OpenSSL not found. Please install openssl-devel or libssl-dev" >&2
        cleanup_python_install
        exit 1
    fi


    # Determine lib directory (lib vs lib64)
    local lib_dir="lib"
    [[ -d "${openssl_dir}/lib64" ]] && lib_dir="lib64"

    # Download Python
    local download_file="Python-${python_version}.tgz"
    local max_retries=3 attempt=1

    while [[ $attempt -le $max_retries ]]; do
        if curl -fL --progress-bar --connect-timeout 30 --max-time 300 \
                --tlsv1.2 --proto '=https' -o "$download_file" "$download_url" 2>&2; then
            [[ -s "$download_file" ]] && break
        fi
        log_warning "Download attempt $attempt failed" >&2
        rm -f "$download_file"
        ((attempt++))
        [[ $attempt -le $max_retries ]] && sleep 5
    done

    [[ ! -s "$download_file" ]] && { log_error "Download failed after $max_retries attempts" >&2; cleanup_python_install; exit 1; }

    tar -xzf "$download_file" >&2
    cd "Python-${python_version}" || { cleanup_python_install; exit 1; }

    export LD_RUN_PATH="${openssl_dir}/${lib_dir}:${PYTHON_INSTALL_DIR}/lib"

    local configure_flags=(
        "--prefix=${PYTHON_INSTALL_DIR}"
        "--enable-ipv6"
        "--enable-shared"
        "--with-computed-gotos=yes"
        "--enable-loadable-sqlite-extensions"
        "--with-openssl=${openssl_dir}"
        "--with-openssl-rpath=auto"
        "--with-ssl-default-suites=openssl"
    )

    # Use system libmpdec if available
    if pkg-config --exists libmpdec 2>/dev/null || [[ -f "/usr/include/mpdecimal.h" ]]; then
        configure_flags+=("--with-system-libmpdec")
    fi

    ./configure "${configure_flags[@]}" \
        CPPFLAGS="-I${openssl_dir}/include" \
        LDFLAGS="-L${openssl_dir}/${lib_dir} -Wl,-rpath,${openssl_dir}/${lib_dir} -Wl,-rpath,${PYTHON_INSTALL_DIR}/lib" \
        CFLAGS="-fPIC" >&2

    make -j"$(nproc)" >&2

    make altinstall >&2

    # Verify SSL
    local python_binary="${PYTHON_INSTALL_DIR}/bin/python${MIN_PYTHON_VERSION}"
    if [[ -x "$python_binary" ]] && "$python_binary" -c "import ssl; print('SSL OK')" >/dev/null 2>&1; then
        log_success "SSL module available" >&2
    else
        log_error "SSL module not available - check OpenSSL installation" >&2
        # Don't exit here - continue with installation
    fi

    # Create symlinks (non-critical - continue even if they fail)
    local bin_dir="${PYTHON_INSTALL_DIR}/bin"
    create_symlink "python${MIN_PYTHON_VERSION}" "${bin_dir}/python3" || true
    create_symlink "python3" "${bin_dir}/python" || true
    create_symlink "pip${MIN_PYTHON_VERSION}" "${bin_dir}/pip3" || true
    create_symlink "pip3" "${bin_dir}/pip" || true

    log_success "Python ${python_version} installed to ${PYTHON_INSTALL_DIR}" >&2

    # Cleanup temp directory and return to original location
    cleanup_python_install
}

# ========= VENV FUNCTIONS =========
create_venv() {
    log_info "Creating virtual environment at: $VENV_PATH"
    if ! "$PYTHON_BIN" -m venv --copies --upgrade-deps "$VENV_PATH"; then
        log_error "Failed to create virtual environment" >&2
        exit 1
    fi

    # Copy Python shared libraries to venv lib directory
    # This is necessary when using --copies flag to ensure the copied Python binary can find its libraries
    local venv_lib_dir="${VENV_PATH}/lib"
    mkdir -p "$venv_lib_dir"

    # Copy libpython shared libraries from the installation directory
    if [[ -d "${PYTHON_INSTALL_DIR}/lib" ]]; then
        cp -f "${PYTHON_INSTALL_DIR}/lib/libpython${MIN_PYTHON_VERSION}.so"* "$venv_lib_dir/" 2>/dev/null || true
    fi

    # Copy the entire Python standard library including lib-dynload
    if [[ -d "${PYTHON_INSTALL_DIR}/lib/python${MIN_PYTHON_VERSION}" ]]; then
        cp -r "${PYTHON_INSTALL_DIR}/lib/python${MIN_PYTHON_VERSION}" "$venv_lib_dir/" 2>/dev/null || true
    fi

    # chroot python-libs copy
    if [[ ! -z "${chroot}" ]]; then
        mkdir -p "${chroot}/${PYTHON_INSTALL_DIR}/lib/python${MIN_PYTHON_VERSION}"
        cp -f "${PYTHON_INSTALL_DIR}/lib/libpython${MIN_PYTHON_VERSION}.so"* "${chroot}/${PYTHON_INSTALL_DIR}/lib/" 2>/dev/null || true
        cp -r "${PYTHON_INSTALL_DIR}/lib/python${MIN_PYTHON_VERSION}" "${chroot}/${PYTHON_INSTALL_DIR}/lib/" 2>/dev/null || true
    fi

    source "$VENV_PATH/bin/activate"
}

install_requirements() {
    if [[ -f "$REQUIREMENTS_FILE" ]]; then
        log_info "Installing from: $REQUIREMENTS_FILE"
        PIP_ARGS="--no-cache-dir"
        if [[ $NO_DEPS = true ]]; then
            PIP_ARGS+=" --no-deps "
        fi
        pip install $PIP_ARGS -r "$REQUIREMENTS_FILE"

    else
        log_info "No requirements file found, skipping"
    fi
}

uninstall_packages() {
    [[ ! -f "$UNINSTALL_FILE" ]] && { log_info "No uninstall file, skipping"; return; }

    log_info "Uninstalling packages from: $UNINSTALL_FILE"
    while IFS= read -r package || [[ -n "$package" ]]; do
        package=$(echo "$package" | xargs)
        [[ -z "$package" ]] && continue

        if ! pip uninstall -y "$package" 2>/dev/null; then
            pip uninstall -y --break-system-packages "$package" 2>/dev/null || \
                log_error "Failed to uninstall: $package" >&2
        fi
    done < "$UNINSTALL_FILE"
}

cleanup_pip() {
    log_info "Removing pip from venv"
    pip uninstall -y pip 2>/dev/null || true
    # Remove pip package files from site-packages to address security vulnerabilities
    local site_packages_dir="${VENV_PATH}/lib/python${MIN_PYTHON_VERSION}/site-packages"
    if [[ -d "$site_packages_dir" ]]; then
        log_info "Removing pip package files from ${site_packages_dir}"
        rm -rf "${site_packages_dir}/pip"* 2>/dev/null || true
        rm -rf "${site_packages_dir}/setuptools"* 2>/dev/null || true
        log_success "Removed pip and related package files from site-packages"
    fi
}

cleanup_system_python() {
    log_info "Removing Python binaries and pip from system installation"

    # Remove Python binaries from system installation directory
    local bin_dir="${PYTHON_INSTALL_DIR}/bin"
    if [[ -d "$bin_dir" ]]; then
        rm -f "${bin_dir}/python${MIN_PYTHON_VERSION}" 2>/dev/null || true
        rm -f "${bin_dir}/python3" 2>/dev/null || true
        rm -f "${bin_dir}/python" 2>/dev/null || true
        rm -f "${bin_dir}/pip${MIN_PYTHON_VERSION}" 2>/dev/null || true
        rm -f "${bin_dir}/pip3" 2>/dev/null || true
        rm -f "${bin_dir}/pip" 2>/dev/null || true
        rm -f "${bin_dir}/python${MIN_PYTHON_VERSION}-config" 2>/dev/null || true
        rm -f "${bin_dir}/python3-config" 2>/dev/null || true
        rm -f "${bin_dir}/pydoc${MIN_PYTHON_VERSION}" 2>/dev/null || true
        rm -f "${bin_dir}/pydoc3" 2>/dev/null || true
        rm -f "${bin_dir}/idle${MIN_PYTHON_VERSION}" 2>/dev/null || true
        rm -f "${bin_dir}/idle3" 2>/dev/null || true
        rm -f "${bin_dir}/2to3-${MIN_PYTHON_VERSION}" 2>/dev/null || true
        rm -f "${bin_dir}/2to3" 2>/dev/null || true
        log_success "Removed Python binaries from ${bin_dir}"
    fi

    # Remove pip package files from site-packages to address security vulnerabilities
    local site_packages_dir=""
    if [[ ! -z "${chroot}" ]]; then
        site_packages_dir="${chroot}/${PYTHON_INSTALL_DIR}/lib/python${MIN_PYTHON_VERSION}/site-packages"
    else
        site_packages_dir="${PYTHON_INSTALL_DIR}/lib/python${MIN_PYTHON_VERSION}/site-packages"
    fi
    if [[ -d "$site_packages_dir" ]]; then
        log_info "Removing pip package files from ${site_packages_dir}"
        rm -rf "${site_packages_dir}/pip"* 2>/dev/null || true
        rm -rf "${site_packages_dir}/setuptools"* 2>/dev/null || true
        rm -rf "${site_packages_dir}/_distutils_hack"* 2>/dev/null || true
        log_success "Removed pip and related package files from site-packages"
    fi

    # Keep the shared libraries in ${PYTHON_INSTALL_DIR}/lib as they are needed by venv
    log_info "Keeping Python shared libraries in ${PYTHON_INSTALL_DIR}/lib for venv usage"
}

# ========= MAIN =========
main() {
    mkdir -p "$(dirname "$VENV_PATH")" "$TARGET_HOME/tmp"

    PYTHON_BIN=$(detect_or_install_python)
    log_info "Using: $PYTHON_BIN"

    local python_version
    python_version=$("$PYTHON_BIN" --version 2>&1 | head -n1)
    log_info "Version: $python_version"

    create_venv
    install_requirements
    uninstall_packages
    cleanup_pip
    cleanup_system_python
    deactivate

    log_success "Setup complete!"
    log_info "Venv: $VENV_PATH"
    log_info "Python: $python_version"
}

main