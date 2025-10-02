#!/bin/bash

# ========= CONFIG =========
INSTALL_DIR="${1:-${HOME}/common/bin/}"  # Destination directory as first argument

# ========= LOGGING UTILS =========
log_info()    { echo -e "\033[1;34m[INFO]\033[0m $1"; }
log_error()   { echo -e "\033[1;31m[ERROR]\033[0m $1" >&2; }
log_success() { echo -e "\033[1;32m[SUCCESS]\033[0m $1"; }

# ========= DETECT ARCH =========
detect_arch() {
    local arch
    arch="$(uname -m)"
    case "$arch" in
        x86_64) echo "x86_64" ;;
        arm64|aarch64) echo "aarch64" ;;
        *) log_error "Unsupported architecture: $arch" && exit 1 ;;
    esac
}

# ========= FETCH LATEST VERSION =========
get_latest_version() {
    curl -s https://api.github.com/repos/aptible/supercronic/releases/latest | \
        grep -oP '"tag_name": "\K(.*)(?=")'
}

# ========= INSTALL SUPERCORNIC =========
install_supercronic() {
    local version="$1"
    local dest_dir="$2"
    local arch
    arch=$(detect_arch)

    local binary="supercronic-linux-${arch}"
    local url="https://github.com/aptible/supercronic/releases/download/${version}/${binary}"

    mkdir -p "$dest_dir"

    log_info "Downloading Supercronic $version for $arch"
    curl -fsSL "$url" -o "${dest_dir}/${binary}" || {
        log_error "Download failed from $url"
        exit 1
    }

    chmod +x "${dest_dir}/${binary}"
    ln -sf "${dest_dir}/${binary}" "${dest_dir}/supercronic"

    log_success "Supercronic installed at ${dest_dir}/supercronic"
}

# ========= MAIN =========
main() {
    local dest_dir="$INSTALL_DIR"
    local latest_version
    latest_version=$(get_latest_version)

    if [ -z "$latest_version" ]; then
        log_error "Failed to fetch latest Supercronic version"
        exit 1
    fi

    install_supercronic "$latest_version" "$dest_dir"
}

main "$@"
