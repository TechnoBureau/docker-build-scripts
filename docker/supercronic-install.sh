#!/bin/bash

# This script downloads and installs the latest version of Supercronic.

set -e

install_supercronic() {
    echo "Installing Supercronic..."

    # Get the latest version of Supercronic from GitHub
    SUPERCRONIC_VERSION=$(curl -s https://api.github.com/repos/aptible/supercronic/releases/latest | grep '"tag_name":' | sed -E 's/.*"v([0-9.]+)".*/\1/')

    # Use the Docker-provided build argument TARGETARCH to automatically detect the architecture
    SUPERCRONIC_URL="https://github.com/aptible/supercronic/releases/download/v${SUPERCRONIC_VERSION}/supercronic-linux-${TARGETARCH}"
    SUPERCRONIC="supercronic-linux-${TARGETARCH}"

    mkdir -p "${HOME}/common/bin"

    # Download the binary
    curl -fsSLO "$SUPERCRONIC_URL"

    # Make it executable
    chmod +x "$SUPERCRONIC"

    # Move it to the bin directory
    mv "$SUPERCRONIC" "${HOME}/common/bin/${SUPERCRONIC}"

    # Create a symlink for easy access
    ln -s "${HOME}/common/bin/${SUPERCRONIC}" "${HOME}/common/bin/supercronic"
}

install_supercronic