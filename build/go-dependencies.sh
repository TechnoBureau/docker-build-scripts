#!/bin/bash

# Enable debug mode if PIPELINE_DEBUG is set
[[ -n ${PIPELINE_DEBUG} || -n ${DEBUG} ]] && set -x

# Configuration
SCRIPT_DIR="/shared"
GO_VERSION="${1:-1.23.1}"  # Accept version as argument, default to 1.23.1
GO_INSTALL_DIR="${SCRIPT_DIR}/usr/local/go"
GOPATH="${SCRIPT_DIR}/go"

# Detect system architecture and OS
detect_system() {
    echo "Detecting system architecture and OS..."

    OS=$(uname | tr '[:upper:]' '[:lower:]')
    ARCH=$(uname -m)

    case "$ARCH" in
        x86_64) GOARCH="amd64" ;;
        aarch64 | arm64) GOARCH="arm64" ;;
        *) GOARCH="$ARCH" ;;
    esac

    GOOS="$OS"
    CGO_ENABLED=0

    GO_TAR="go${GO_VERSION}.${GOOS}-${GOARCH}.tar.gz"
    GO_URL="https://go.dev/dl/${GO_TAR}"
}

download_go() {
    echo "Downloading Go ${GO_VERSION} for ${GOOS}/${GOARCH}..."
    wget -q "${GO_URL}" -O "${GO_TAR}"
}

extract_go() {
    echo "Extracting Go archive..."
    tar -xzf "${GO_TAR}" >/dev/null 2>&1
}

install_go() {
    echo "Installing Go to ${GO_INSTALL_DIR}..."
    mkdir -p "$(dirname "${GO_INSTALL_DIR}")"
    mv go "${GO_INSTALL_DIR}"
}

configure_env() {
    echo "Configuring environment variables..."
    {
        echo "export GOROOT=${GO_INSTALL_DIR}"
        echo "export GOPATH=${GOPATH}"
        echo "export PATH=\$PATH:${GO_INSTALL_DIR}/bin:${GOPATH}/bin"
        echo "export GOOS=${GOOS}"
        echo "export GOARCH=${GOARCH}"
        echo "export CGO_ENABLED=${CGO_ENABLED}"
    } >> "$BASH_ENV"
}

cleanup() {
    echo "Cleaning up..."
    rm -f "${GO_TAR}"
}

# Execution
cd "${SCRIPT_DIR}" || exit 1
detect_system
download_go
extract_go
install_go
configure_env
cleanup

echo "✅ Go ${GO_VERSION} setup complete for ${GOOS}/${GOARCH} with CGO_ENABLED=${CGO_ENABLED}"
