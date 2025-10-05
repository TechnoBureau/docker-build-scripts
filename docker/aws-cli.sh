#!/usr/bin/env bash
set -euo pipefail

# ========= CONFIG =========
INSTALL_DIR="${1:-/usr/local/bin}"
TMP_DIR="$(mktemp -d)"
AWS_CLI_ZIP="awscliv2.zip"

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
        x86_64) echo "x86_64" ;;
        arm64|aarch64) echo "aarch64" ;;
        *) log_error "Unsupported architecture: $arch" && exit 1 ;;
    esac
}

# ========= FUNCTION: Download AWS CLI =========
download_awscli() {
    local os="$1"
    local arch="$2"
    local url

    if [[ "$os" == "linux" ]]; then
        url="https://awscli.amazonaws.com/awscli-exe-linux-${arch}.zip"
    elif [[ "$os" == "darwin" ]]; then
        url="https://awscli.amazonaws.com/AWSCLIV2.pkg"  # macOS uses .pkg installer
    else
        log_error "Unsupported OS for AWS CLI: $os"
        exit 1
    fi

    log_info "Downloading AWS CLI from: $url"
    curl -sSL "$url" -o "$TMP_DIR/$AWS_CLI_ZIP"
}

# ========= FUNCTION: Install AWS CLI =========
install_awscli() {
    local os="$1"
    local install_dir="$2"

    if [[ "$os" == "linux" ]]; then
        unzip -qq "$TMP_DIR/$AWS_CLI_ZIP" -d "$TMP_DIR"
        sudo "$TMP_DIR/aws/install" --bin-dir "$install_dir" --install-dir /usr/local/aws-cli --update
    elif [[ "$os" == "darwin" ]]; then
        log_info "Installing AWS CLI on macOS using .pkg installer"
        sudo installer -pkg "$TMP_DIR/$AWS_CLI_ZIP" -target /
    fi

    log_success "AWS CLI installed successfully"
}

# ========= FUNCTION: Clean up =========
cleanup() {
    log_info "Cleaning up temporary files"
    rm -rf "$TMP_DIR"
    sudo rm -rf /usr/local/aws-cli/v2/*/dist/cryptography-*.dist-info/METADATA 2>/dev/null || true
    sudo chmod +rx "$INSTALL_DIR"/aws*
}

# ========= MAIN =========
main() {
    os=$(detect_os)
    arch=$(detect_arch)

    log_info "Detected OS: $os"
    log_info "Detected Architecture: $arch"
    log_info "Installing AWS CLI to: $INSTALL_DIR"

    download_awscli "$os" "$arch"
    install_awscli "$os" "$INSTALL_DIR"
    cleanup

    log_success "You can now run: aws --version"
    aws --version
}

main
