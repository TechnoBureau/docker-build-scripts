#!/usr/bin/env bash
set -euo pipefail

PREFIX="${1:-/tmp/chroot/usr/local}"

BIN_DIR="${PREFIX}/bin"
AWS_INSTALL_DIR="${PREFIX}/aws-cli"

TMP_DIR="$(mktemp -d)"
AWS_CLI_ZIP="awscliv2.zip"

log_info() {
    echo -e "\033[1;34m[INFO]\033[0m $1"
}

log_error() {
    echo -e "\033[1;31m[ERROR]\033[0m $1" >&2
}

log_success() {
    echo -e "\033[1;32m[SUCCESS]\033[0m $1"
}

cleanup() {
    rm -rf "$TMP_DIR"
}

trap cleanup EXIT

detect_arch() {
    local arch
    arch="$(uname -m)"

    case "$arch" in
        x86_64) echo "x86_64" ;;
        arm64|aarch64) echo "aarch64" ;;
        *)
            log_error "Unsupported architecture: $arch"
            exit 1
            ;;
    esac
}

main() {
    local arch
    arch="$(detect_arch)"

    mkdir -p "$BIN_DIR" "$AWS_INSTALL_DIR"

    local url="https://awscli.amazonaws.com/awscli-exe-linux-${arch}.zip"

    log_info "Downloading AWS CLI from: $url"
    curl -fsSL "$url" -o "$TMP_DIR/$AWS_CLI_ZIP"

    log_info "Extracting AWS CLI"
    unzip -qq "$TMP_DIR/$AWS_CLI_ZIP" -d "$TMP_DIR"

    log_info "Installing AWS CLI into staging root: $PREFIX"

    "$TMP_DIR/aws/install" \
        --install-dir "$AWS_INSTALL_DIR" \
        --bin-dir "$BIN_DIR" \
        --update

    # Important:
    # The AWS installer creates symlinks using the staging path:
    #
    # /tmp/chroot/usr/local/bin/aws -> /tmp/chroot/usr/local/aws-cli/...
    #
    # That will be broken inside the final image.
    # Replace them with final-container-correct symlinks.
    rm -f "$BIN_DIR/aws" "$BIN_DIR/aws_completer"

    ln -s "${PREFIX}/aws-cli/v2/current/bin/aws" "$BIN_DIR/aws"
    ln -s "${PREFIX}/aws-cli/v2/current/bin/aws_completer" "$BIN_DIR/aws_completer"

    log_success "AWS CLI staged successfully under: $PREFIX"

}

main