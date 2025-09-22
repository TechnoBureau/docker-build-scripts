#!/bin/sh

# This script installs the latest version of the AWS CLI.

set -e

install_aws_cli() {
    echo "Installing AWS CLI..."

    # Download the latest AWS CLI v2
    curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"

    # Unzip the installer
    unzip -qq awscliv2.zip

    # Run the installer
    ./aws/install

    # Clean up the downloaded zip file and installation files
    rm -rf awscliv2.zip
    rm -rf /usr/local/aws-cli/v2/*/dist/cryptography-*.dist-info/METADATA
    chmod +rx /usr/local/bin/aws*
    rm -rf aws
}

install_aws_cli