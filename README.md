# Common DevOps Scripts Collection

A comprehensive collection of enterprise-grade Bash scripts designed for building, deploying, and managing containerized environments.

## Table of Contents

- [Overview](#overview)
- [Repository Structure](#repository-structure)
- [Core Technologies](#core-technologies)
- [Quick Start](#quick-start)
- [Build Scripts](#build-scripts)
- [Docker Scripts](#docker-scripts)
- [Prebuildfs Libraries](#prebuildfs-libraries)
- [Development Conventions](#development-conventions)
- [Configuration Management](#configuration-management)
- [Best Practices](#best-practices)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)

---

## Overview

This repository provides three main categories of utilities:

1. **Build Scripts** - CI/CD automation for container images and Kubernetes operators
2. **Docker Scripts** - Container image creation, configuration, and security hardening
3. **Prebuildfs Library Scripts** - Reusable shell libraries for container initialization and runtime

### Core Technologies

- **Shell Scripting**: Bash scripts with modular library architecture
- **Container Technologies**: Docker, Podman, multi-architecture builds
- **Kubernetes**: Operator Lifecycle Manager (OLM), operator bundles, catalog generation
- **Security**: DISA STIG compliance, FIPS mode, OSCAP hardening
- **Registries**: Multi-registry support (Docker Hub, Cloud Registry, GitHub Container Registry, AWS ECR, Quay.io)
- **CI/CD**: Universal pipeline with image signing and artifact management

---

## Repository Structure

The repository follows a modular design pattern:

```
wm-scripts/
├── build/              # CI/CD and operator management scripts
│   ├── lib/           # Modular libraries (ci-*.sh, operator-*.sh)
│   └── *.sh           # Main executables (universal-ci.sh, operator-rebundle.sh, etc.)
├── docker/            # Container setup and hardening scripts
│   └── *.sh           # Standalone installation scripts
└── prebuildfs/        # Container runtime libraries
└── opt/scripts/
        └── lib*.sh    # Reusable shell libraries
```

**Key Design Principles:**
- **Modularity**: Functionality split into focused library files (e.g., `ci-registry.sh`, `operator-bundle.sh`)
- **Reusability**: Common utilities abstracted into `lib*.sh` files
- **Configuration Flexibility**: Support for both Dockerfile comments and YAML configuration
- **Security First**: Built-in STIG compliance and security hardening
- **Multi-platform**: Cross-platform support (Linux, macOS) with architecture detection

---

## Quick Start

### Prerequisites

- Bash 4.0+
- Docker or Podman
- For multi-arch builds: QEMU (`docker run --privileged --rm tonistiigi/binfmt --install all`)
- For operator tools: `opm`, `kubectl`, `yq`, `jq`

### Basic Usage

```bash
# Simple build with Dockerfile comments
./build/universal-ci.sh -d /path/to/Dockerfile -i myimage

# Multi-registry deployment
./build/universal-ci.sh -c build.yaml -d ./Dockerfile -v 1.0.0

# Multi-architecture build
./build/universal-ci.sh -d ./Dockerfile -i myapp --platforms linux/amd64,linux/arm64

# Test without pushing
./build/universal-ci.sh -d ./Dockerfile --skip-push
```

---

## Build Scripts

The `build/` directory contains scripts for CI/CD operations. See [Build Scripts Documentation](build/README.md) for complete details.

### Universal CI Pipeline

**universal-ci.sh** - Main CI/CD pipeline for container builds

**Configuration Methods:**

1. **Dockerfile Comments** (recommended):
```dockerfile
# IMAGE_NAME: myapp
# REGISTRY_0: docker.io
# REGISTRY_0_PREFIX: myorg
# REGISTRY_0_PUSH: true
# TAG_STRATEGY: version-latest
# PLATFORMS: linux/amd64,linux/arm64
# VERSION: 1.0.0
```

2. **YAML Configuration**:
```yaml
IMAGE_NAME: myapp
version: 1.0.0
REGISTRY:
  - name: docker.io
    prefix: myorg
    push: true
PLATFORMS: linux/amd64,linux/arm64
TAG_STRATEGY: version-latest
```

**Tag Strategies:**
- `version-latest`: Creates both versioned tag (e.g., `1.0.0`) and `latest`
- `version-only`: Creates only versioned tag
- `latest-only`: Creates only `latest` tag
- `git-sha`: Uses git commit SHA as tag
- `version-runner`: Combines version with CI runner ID

### Operator Management

Complete lifecycle: Rebundle → Catalog → Promotion

```bash
# Step 1: Harden and rebundle operator with STIG compliance
./build/operator-rebundle.sh \
  -c operator-config.yaml \
  -i operational-images.lst \
  -v v1.19.3 \
  --parallel 4

# Step 2: Generate OLM catalog
./build/operator-catalog.sh \
  -s us.icr.io \
  -t us.icr.io \
  -n staging-namespace \
-p pipelines

# Step 3: Promote images between registries
./build/promotion.sh \
  -s icr.io/staging-namespace \
  -r 123.dkr.ecr.us-east-1.amazonaws.com \
  -p source-path \
  -d target-path \
  -l "image1:v1.0 image2:v2.0" \
  --parallel 8
```

### Key Build Scripts

- **universal-ci.sh**: Main CI/CD pipeline for container builds ([detailed guide](build/universal-ci.md))
- **operator-rebundle.sh**: Operator hardening and rebundling ([guide](build/operator-rebundle.md))
- **operator-catalog.sh**: OLM catalog generation ([guide](build/operator-catalog.md))
- **promotion.sh**: Image promotion between registries ([guide](build/promotion.md))
- **go-dependencies.sh**: Installs Go language dependencies with version control
- **re-source.sh**: Utility for re-sourcing environment variables

### Build Libraries (`build/lib/`)

- **ci-*.sh**: Modular CI/CD libraries (config, registry, build, artifacts)
- **operator-*.sh**: Operator management libraries (bundle, catalog, CSV, image)

---

## Docker Scripts

The `docker/` directory contains scripts for Docker image creation and configuration. See [Docker Scripts Documentation](docker/README.md) for complete details.

### Security Hardening

**docker-hardening-oscap.sh** - Applies DISA STIG security hardening (46 rules)

Features:
- FIPS crypto policy configuration
- SSH hardening (ciphers, MACs, key exchange algorithms)
- PAM configuration for secure authentication
- Password policy enforcement (complexity, history, age)
- Core dump and backtraces disabling
- Kernel module hardening (USB storage, Bluetooth, etc.)
- File permissions and ownership fixes
- User session timeout configuration

**Usage in Dockerfiles:**
```dockerfile
COPY docker/docker-hardening-oscap.sh /tmp/
RUN /tmp/docker-hardening-oscap.sh
```

### Tool Installation Scripts

- **aws-cli.sh**: AWS CLI installation with cross-platform support ([usage](docker/README.md#aws-clish))
- **kubectl-install.sh**: kubectl installation with version control ([usage](docker/README.md#kubectl-installsh))
- **supercronic-install.sh**: Supercronic (cron for containers) ([usage](docker/README.md#supercronic-installsh))
- **go-setup.sh**: Go environment setup and compilation
- **venv.sh**: Python virtual environment setup ([usage](docker/README.md#venvsh))
- **instana-plugin-install.sh**: Instana monitoring plugins
- **nginx-plugin-instana-install.sh**: Nginx Instana plugin
- **older-support-nginx.sh**: Nginx configuration for legacy support

### Example Dockerfile

```dockerfile
FROM registry.access.redhat.com/ubi9/ubi-minimal:latest

# Apply DISA STIG security hardening
COPY docker/docker-hardening-oscap.sh /tmp/
RUN /tmp/docker-hardening-oscap.sh

# Install kubectl
COPY docker/kubectl-install.sh /tmp/
RUN /tmp/kubectl-install.sh v1.26.0 /usr/local/bin

# Install AWS CLI
COPY docker/aws-cli.sh /tmp/
RUN /tmp/aws-cli.sh /usr/local/bin

# Install Supercronic for cron jobs
COPY docker/supercronic-install.sh /tmp/
RUN /tmp/supercronic-install.sh v0.2.1 /usr/local/bin

# Cleanup
RUN rm -rf /tmp/*.sh
```

---

## Prebuildfs Libraries

The `prebuildfs/opt/scripts/` directory contains reusable shell libraries for container initialization and runtime:

- **liblog.sh**: Structured JSON logging (info, warn, error, debug)
- **libcommon.sh**: Common utilities and welcome messages
- **libentrypoint.sh**: Container entry point utilities
- **libenv.sh**: Environment variable management
- **libfile.sh**: File operations
- **libfs.sh**: Filesystem utilities
- **libhook.sh**: Hook script utilities
- **libnet.sh**: Network utilities
- **libos.sh**: Operating system utilities
- **libpersistence.sh**: Data persistence utilities
- **libservice.sh**: Service management
- **libvalidations.sh**: Input validation utilities
- **libversion.sh**: Version management utilities
- **libwebserver.sh**: Web server utilities

### Library Usage Example

```bash
# Source required libraries
. /opt/scripts/liblog.sh
. /opt/scripts/libcommon.sh

# Use logging functions
info "Informational message"
warn "Warning message"
error "Error message"
debug "Debug message (only shown when DEBUG=true)"
```

**JSON Logging**: All log functions output structured JSON:
```json
{"level": "info", "ts": "2026-05-31T09:55:23Z", "msg": "Build completed"}
```

---

## Development Conventions

### Script Structure

All scripts follow a consistent structure:

```bash
#!/bin/bash
# Copyright and license header
# Script description

# Source required libraries
. /path/to/lib/liblog.sh
. /path/to/lib/libcommon.sh

# Constants and global variables
readonly SCRIPT_NAME="script-name"

# Functions (one per logical operation)
function_name() {
    local param="${1:?missing param}"
    # Implementation
}

# Main execution
main() {
    # Parse arguments
    # Validate inputs
    # Execute operations
}

main "$@"
```

### Error Handling

Scripts use consistent error handling patterns:

```bash
# Exit on error
set -e

# Validate required parameters
local param="${1:?missing required parameter}"

# Check command success
if ! command -v tool &> /dev/null; then
    error "Required tool 'tool' not found"
    exit 1
fi
```

### Parallel Processing

Operator scripts support parallel processing for performance:

```bash
# Process 4 images concurrently
./build/operator-rebundle.sh -c config.yaml -i images.lst --parallel 4

# Process 8 images concurrently for promotion
./build/promotion.sh -s source-registry -r target-registry -l "image1:v1.0 image2:v2.0" --parallel 8
```

---

## Configuration Management

### Environment Variables for Authentication

```bash
# Docker Hub
export DOCKER_USERNAME="myuser"
export DOCKER_PASSWORD="mytoken"

# Cloud Registry
export CLOUD_API_KEY="your-api-key"

# GitHub Container Registry
export GITHUB_TOKEN="ghp_xxxxx"

# AWS ECR
export AWS_ACCESS_KEY_ID="your-key"
export AWS_SECRET_ACCESS_KEY="your-secret"
export AWS_REGION="us-east-1"
```

### Registry-Specific Credentials

For ICR with namespace paths, use the **full path** in credential keys:

```bash
# For: icr.io/ipaas-non-prod/wm-common
export user_icr_io_ipaas_non_prod_wm_common="iamapikey"
export password_icr_io_ipaas_non_prod_wm_common="your-api-key"
```

### Debug Mode

```bash
export DEBUG=true          # Enable debug output
export DEBUG=true          # Enable library debug logging
export QUIET=false         # Ensure logging is not suppressed
```

### Multi-Registry Configuration

```yaml
REGISTRY:
  - name: docker.io
    prefix: myorg
    push: true
  - name: ghcr.io
    prefix: mycompany
    push: true
  - name: us.icr.io
    prefix: myorg
    push: true
```

---

## Best Practices

1. **Version Pinning**: Always specify exact versions for reproducible builds
2. **Layer Optimization**: Combine RUN commands to reduce image layers
3. **Cleanup**: Remove temporary files and installation artifacts
4. **Non-root Users**: Run containers as non-root users when possible
5. **Use Parallel Processing**: Speed up operator operations with `--parallel`
6. **Test Locally First**: Use `--skip-push` for testing before deployment
7. **Separate Environments**: Use promotion workflow for staging → production
8. **Monitor Resources**: Watch disk space and network during builds
9. **Security Hardening**: Apply DISA STIG compliance using `docker-hardening-oscap.sh`
10. **Multi-Architecture**: Build for multiple platforms when targeting diverse infrastructure

### Testing Strategy

```bash
# Enable debug mode for any script
export DEBUG=true

# Test builds without pushing
./build/universal-ci.sh -d ./Dockerfile --skip-push

# Test operator rebundle without pushing
./build/operator-rebundle.sh -c config.yaml -i images.lst --skip-push --skip-bundle
```

---

## Troubleshooting

### Common Issues

**Registry authentication fails**
- Verify credentials are set correctly in environment variables
- Check registry permissions and access rights
- Ensure API keys/tokens are not expired

**Multi-arch build fails**
- Install QEMU: `docker run --privileged --rm tonistiigi/binfmt --install all`
- Verify Docker buildx is installed and configured
- Check platform syntax: `linux/amd64,linux/arm64`
- Ensure `privileged: true` in Tekton/Kubernetes tasks

**Build context too large**
- Add `.dockerignore` file to exclude unnecessary files
- Use `--additional-folders` to include only required directories

**Operator bundle extraction fails**
- Verify source registry credentials
- Check operator version exists in source registry
- Ensure network connectivity to registry

**Parallel processing issues**
- Reduce `--parallel` value if hitting resource limits
- Monitor disk space during parallel operations
- Check for registry rate limiting

**Duplicate artifacts in multi-arch builds**
- Fixed in latest version: artifact saving now happens only once per architecture
- Each platform gets its own artifact with platform-specific SHA digest

### Debug Mode

Enable detailed logging for troubleshooting:

```bash
export DEBUG=true
export DEBUG=true
./build/universal-ci.sh -d ./Dockerfile -i myapp
```

This will output detailed information about:
- Configuration parsing
- Registry authentication
- Build steps
- Push operations
- Error stack traces

---

## Architecture and Implementation Details

### Modular Library Design

Functions are split across focused library files to enable:
- Independent testing and maintenance
- Selective sourcing based on script needs
- Clear separation of concerns (registry, build, artifacts, etc.)

### Configuration Priority

Dockerfile Comments > YAML Config > Environment Variables > Defaults

### Artifact Management

- **Single-arch builds**: One artifact with manifest digest
- **Multi-arch builds**: Per-architecture artifacts with platform-specific digests
- Artifacts saved via `ci_save_artifact()` in `ci-build.sh`
- No duplicate saves in `universal-ci.sh` (fixed in latest version)

### Registry Authentication

- Key-based credential lookup using registry URL patterns
- Automatic ECR token generation from AWS credentials
- Support for both generic and registry-specific environment variables

### Multi-Platform Builds

- Automatic QEMU/binfmt installation when needed
- Smart builder detection (uses cloud-based DinD when available)
- Parallel platform builds for Podman
- Per-architecture artifact tracking with SHA digests

### Common Patterns

When modifying build scripts:
1. Always preserve WHY comments explaining non-obvious logic
2. Use `ci_` prefix for new CI/CD functions to avoid naming conflicts
3. Maintain backward compatibility with existing configurations
4. Add debug logging for troubleshooting
5. Update both inline documentation and external guides

When working with operators:
1. Follow the rebundle → catalog → promotion workflow
2. Use parallel processing for performance (`--parallel` flag)
3. Preserve STIG compliance during image modifications
4. Track all image references for promotion

When adding new features:
1. Create modular library functions in `build/lib/`
2. Follow existing naming conventions (`ci_*`, `operator_*`)
3. Add comprehensive error handling
4. Include usage examples in documentation
5. Test with both Docker and Podman

---

## Documentation References

- [Build Scripts Documentation](build/README.md)
- [Universal CI Pipeline Guide](build/universal-ci.md)
- [Operator Rebundle Guide](build/operator-rebundle.md)
- [Operator Catalog Guide](build/operator-catalog.md)
- [Image Promotion Guide](build/promotion.md)
- [Registry Credentials Guide](build/registry-credentials.md)
- [Docker Scripts Documentation](docker/README.md)

---

## Contributing

1. Fork the repository
2. Create a feature branch
3. Follow the development conventions outlined above
4. Add tests for new functionality
5. Update documentation as needed
6. Submit a pull request

### Code Review Checklist

- [ ] Follows script structure conventions
- [ ] Includes proper error handling
- [ ] Uses consistent logging (JSON format)
- [ ] Includes WHY comments for non-obvious logic
- [ ] Updates relevant documentation
- [ ] Tested locally with debug mode
- [ ] No hardcoded credentials or secrets

---

## License

See the [LICENSE](LICENSE) file for details.
