#!/usr/bin/env bash

set -euo pipefail

# ========= CONFIG =========
KUBECTL_VERSION="${1:-latest}"         # Can be passed as first argument
INSTALL_DIR="${2:-/usr/local/bin}"     # Optional second argument

# ========= LOGGING UTILS =========
log_info() {
    echo -e "\033[1;34m[INFO]\033[0m $1"
}

log_error() {
    echo -e "\033[1;31m[ERROR]\033[0m $1" >&2
}

log_success() {
    echo -e "\033[1;32m[SUCCESS]\033[0m $1"
}

# ========= FUNCTION: Detect OS =========
detect_os() {
    local os
    os="$(uname | tr '[:upper:]' '[:lower:]')"
    case "$os" in
        linux|darwin) echo "$os" ;;
        *) log_error "Unsupported OS: $os" && exit 1 ;;
    esac
}

# ========= FUNCTION: Detect ARCH =========
detect_arch() {
    local arch
    arch="$(uname -m)"
    case "$arch" in
        x86_64) echo "amd64" ;;
        arm64|aarch64) echo "arm64" ;;
        *) log_error "Unsupported architecture: $arch" && exit 1 ;;
    esac
}

# ========= FUNCTION: Get latest version =========
get_latest_version() {
    curl -sL https://dl.k8s.io/release/stable.txt
}

# ========= FUNCTION: Download kubectl =========
download_kubectl() {
    local os="$1"
    local arch="$2"
    local version="$3"
    local dest="$4"

    local download_url="https://dl.k8s.io/release/${version}/bin/${os}/${arch}/kubectl"
    log_info "Downloading kubectl from: $download_url"

    curl -Lo "$dest" "$download_url"
    chmod +x "$dest"
}


# ========= MAIN INSTALL FUNCTION =========
install_kubectl() {
    local install_dir="${1:-$DEFAULT_INSTALL_DIR}"
    local os arch version tmp_file

    os=$(detect_os)
    arch=$(detect_arch)

    if [[ "$KUBECTL_VERSION" == "latest" ]]; then
        version=$(get_latest_version)
    else
        version="$KUBECTL_VERSION"
    fi

    log_info "Installing kubectl version: $version for $os/$arch"

    tmp_file="$(mktemp)"
    download_kubectl "$os" "$arch" "$version" "$tmp_file"


    mv "$tmp_file" "$install_dir/kubectl"
    log_success "kubectl installed at $install_dir/kubectl"
    $install_dir/kubectl version --client
}

# ========= EXECUTE =========
install_kubectl "$INSTALL_DIR"
