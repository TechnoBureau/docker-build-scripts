# Build Scripts

This directory contains scripts for building, CI/CD operations, and development environment setup.

## Overview

The build scripts provide utilities for:
- Setting up Go development environments
- Managing CI/CD pipelines for Docker/Podman images
- Re-sourcing environment variables
- Automating build processes

## Scripts

### go-dependencies.sh

A script for installing Go language dependencies with specific version control.

#### Features:
- Cross-platform support (Linux, macOS)
- Architecture detection (amd64, arm64)
- Configurable installation directory
- Environment variable setup

#### Usage:
```bash
./go-dependencies.sh [version]
```

#### Parameters:
- `version`: (Optional) Go version to install (default: 1.23.1)

#### Environment Variables:
- `PIPELINE_DEBUG` or `DEBUG`: Enable debug mode
- `SCRIPT_DIR`: Script directory (default: "/shared")
- `GO_INSTALL_DIR`: Go installation directory (default: "${SCRIPT_DIR}/usr/local/go")
- `GOPATH`: Go path (default: "${SCRIPT_DIR}/go")

### re-source.sh

A utility script for re-sourcing environment variables, useful in CI/CD pipelines and development environments.

#### Usage:
```bash
source ./re-source.sh
```

### universal-ci.sh

A comprehensive CI pipeline script for building and pushing Docker/Podman images with support for various registries, image namespaces, and tagging strategies.

#### Features:
- Multi-registry support (docker.io, icr.io, gcr.io, ghcr.io, quay.io, etc.)
- Image namespace and prefix support with registry-specific formatting
- Registry-specific namespace and prefix configuration
- IBM Cloud Registry namespace-specific API keys
- Support for additional login namespaces with separate API keys
- Flexible tagging strategies with configurable additional tags
- Secret management for builds
- CI runner detection (GitHub Actions, Jenkins, Travis, GitLab, CircleCI, etc.)
- Debug mode with safe secret logging
- Common build.yaml support (builders/build.yaml for shared settings)

#### Usage:
```bash
./universal-ci.sh [image_name] [options]
```

#### Options:
- `-c, --git-repo`: Git repository URL
- `-i, --dockerfile`: Path to Dockerfile
- `-b, --branch`: Git branch (default: main)
- `-v, --version`: Image version
- `-t, --tag`: Image tag
- `-r, --registry`: Container registry (default: docker.io)
- `-p, --push`: Whether to push the image (true/false)
- `-s, --secrets`: Build secrets in format "key1=value1,key2=value2"
- `-d, --definition`: Path to build definition YAML file
- `-e, --extra-args`: Extra arguments for docker build
- `--prefix`: Image prefix
- `-f, --additional-folders`: Additional folders to include in build context
- `--retag`: Retag source:target format
- `--copy-signatures`: Whether to copy signatures (true/false)
- `--debug`: Enable debug mode
- `--no-debug`: Disable debug mode

#### Environment Variables:
- `DEBUG`: Enable debug mode (true/false)
- `REGISTRY`: Container registry
- `IMAGE_PREFIX`: Image prefix
- `IMAGE_NAME`: Image name
- `PUSH`: Whether to push the image (true/false)
- `TAG_STRATEGY`: Tagging strategy (version-only, latest-only, version-latest, version-runner, version-sha, runner-only, sha-only)
- `ADD_LATEST_TAG`: Add latest tag (true/false)
- `ADD_VERSION_TAG`: Add version tag (true/false)
- `ADD_SHA_TAG`: Add git SHA tag (true/false)
- `ADD_RUNNER_TAG`: Add runner ID tag (true/false)
- `ADDITIONAL_TAGS`: Additional tags to apply
- `ADDITIONAL_BUILD_ARGS`: Additional build arguments
- `BUILD_SECRETS`: Build secrets in format "secret_id1=env_var1,secret_id2=env_var2"
- `ADDITIONAL_BUILD_FOLDERS`: Additional folders to include in build context

## Common Use Cases

### Building and Pushing a Docker Image

```bash
./universal-ci.sh my-image \
  --registry docker.io \
  --dockerfile ./Dockerfile \
  --version 1.0.0 \
  --push true
```

### Building with Multiple Registries

Create a `build.yaml` file:

```yaml
REGISTRY:
  - name: docker.io
    prefix: myorg
    push: true
  - name: ghcr.io
    prefix: myorg
    push: true
```

Then run:

```bash
./universal-ci.sh my-image \
  --definition ./build.yaml \
  --version 1.0.0
```

### Building with Secrets

```bash
./universal-ci.sh my-image \
  --secrets "NPM_TOKEN=MY_NPM_TOKEN,GITHUB_TOKEN=MY_GITHUB_TOKEN" \
  --push true
```

### Setting Up Go Environment

```bash
./go-dependencies.sh 1.22.0
source ./re-source.sh
```

## Configuration

### build.yaml

The `build.yaml` file can be used to configure the build process. It supports:

```yaml
# Registry configuration
REGISTRY:
  - name: docker.io
    prefix: myorg
    push: true
  - name: ghcr.io
    prefix: myorg
    push: true

# Default settings
DEFAULT_VERSION: latest
DEFAULT_PLATFORM: amd64

# Build configuration
version: 1.0.0
tag: latest
PUSH: true
TAG_STRATEGY: version-latest
ADD_LATEST_TAG: true
ADD_VERSION_TAG: true
ADD_SHA_TAG: false
ADD_RUNNER_TAG: false
```

## Best Practices

1. Use a common `build.yaml` in the builders directory for shared settings
2. Use environment variables for sensitive information
3. Use the `--debug` flag for troubleshooting
4. Use the `--retag` option for promoting images between registries
5. Use the `--additional-folders` option to include additional files in the build context