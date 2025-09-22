#!/bin/sh

# This script sets up a Go module, tidies the dependencies, and builds the project.
#
# It assumes that the script is run from a directory containing the Go source code.

# Add the Go binary to the path
export PATH=$PATH:${HOME}/go-pkg/go/bin

setup_go_module() {
    echo "Setting up Go module..."

    # Change to the home directory
    cd ${HOME}/go

    # Print the Go version
    go version

    # Initialize the Go module
    go mod init sgo

    # Tidy the dependencies, which will install any missing modules
    go mod tidy

    # Build the project
    go build -ldflags="-s -w" -o $HOME/bin/sgo main.go
}

setup_go_module
