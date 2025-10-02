# Docker Scripts

This directory contains scripts for Docker/container image creation, configuration, and hardening for docker environments.

## Overview

The Docker scripts provide utilities for:
- Installing common tools and dependencies in containers
- Hardening container images for security compliance
- Setting up development environments
- Configuring services within containers

## Scripts

### aws-cli.sh

A script for installing AWS CLI with cross-platform support.

#### Features:
- Cross-platform support (Linux, macOS)
- Architecture detection (x86_64, arm64/aarch64)
- Configurable installation directory

#### Usage:
```bash
./aws-cli.sh [install_dir]
```

#### Parameters:
- `install_dir`: (Optional) Installation directory (default: /usr/local/bin)

#### Example in Dockerfile:
```dockerfile
COPY docker/aws-cli.sh /tmp/
RUN /tmp/aws-cli.sh /usr/local/bin
```

### docker-hardening-oscap.sh

Applies DISA STIG security hardening for RHEL 9 containers, implementing 46 security rules.

#### Features:
- FIPS crypto policy configuration
- SSH hardening (ciphers, MACs)
- PAM configuration for secure authentication
- Password policy enforcement
- Core dump and backtraces disabling
- Kernel module hardening
- File permissions and ownership fixes
- User session timeout configuration

#### Usage:
```bash
./docker-hardening-oscap.sh
```

#### Example in Dockerfile:
```dockerfile
COPY docker/docker-hardening-oscap.sh /tmp/
RUN /tmp/docker-hardening-oscap.sh
```

### go-setup.sh

Sets up Go environment and builds Go applications.

#### Features:
- Path configuration
- Go module initialization
- Binary compilation with size optimization

#### Usage:
```bash
./go-setup.sh
```

#### Example in Dockerfile:
```dockerfile
COPY docker/go-setup.sh /home/user/
RUN /home/user/go-setup.sh
```

### instana-plugin-install.sh

Installs Instana monitoring plugins for container observability.

#### Usage:
```bash
./instana-plugin-install.sh
```

### kubectl-install.sh

Installs kubectl with version control.

#### Features:
- Cross-platform support (Linux, macOS)
- Architecture detection (amd64, arm64)
- Version selection (specific or latest)
- Configurable installation directory

#### Usage:
```bash
./kubectl-install.sh [version] [install_dir]
```

#### Parameters:
- `version`: (Optional) kubectl version (default: latest)
- `install_dir`: (Optional) Installation directory (default: /usr/local/bin)

#### Example in Dockerfile:
```dockerfile
COPY docker/kubectl-install.sh /tmp/
RUN /tmp/kubectl-install.sh v1.26.0 /usr/local/bin
```

### older-support-nginx.sh

Configures Nginx for legacy support scenarios.

#### Usage:
```bash
./older-support-nginx.sh
```

### supercronic-install.sh

Installs Supercronic, a cron implementation for containers that addresses common issues with traditional cron in containerized environments.

#### Features:
- Logs to stdout/stderr
- No daemon process
- Proper signal handling
- Designed for containers

#### Usage:
```bash
./supercronic-install.sh [version] [install_dir]
```

#### Parameters:
- `version`: (Optional) Supercronic version (default: latest)
- `install_dir`: (Optional) Installation directory (default: /usr/local/bin)

#### Example in Dockerfile:
```dockerfile
COPY docker/supercronic-install.sh /tmp/
RUN /tmp/supercronic-install.sh v0.2.1 /usr/local/bin
```

### venv.sh

Sets up Python virtual environments for isolated Python dependencies.

#### Features:
- Virtual environment creation
- Package installation
- Environment activation

#### Usage:
```bash
./venv.sh [python_version] [venv_path]
```

#### Parameters:
- `python_version`: (Optional) Python version (default: system default)
- `venv_path`: (Optional) Virtual environment path (default: ./venv)

#### Example in Dockerfile:
```dockerfile
COPY docker/venv.sh /tmp/
RUN /tmp/venv.sh 3.9 /app/venv
```

## Common Use Cases

### Creating a Hardened Base Image

```dockerfile
FROM registry.access.redhat.com/ubi9/ubi-minimal:latest

# Apply security hardening
COPY docker/docker-hardening-oscap.sh /tmp/
RUN /tmp/docker-hardening-oscap.sh

# Install common tools
COPY docker/kubectl-install.sh /tmp/
RUN /tmp/kubectl-install.sh latest /usr/local/bin

COPY docker/aws-cli.sh /tmp/
RUN /tmp/aws-cli.sh /usr/local/bin
```

### Creating a Development Environment

```dockerfile
FROM python:3.9-slim

# Set up Python environment
COPY docker/venv.sh /tmp/
RUN /tmp/venv.sh 3.9 /app/venv

# Set up Go environment
COPY docker/go-setup.sh /tmp/
RUN /tmp/go-setup.sh

# Install development tools
COPY docker/kubectl-install.sh /tmp/
RUN /tmp/kubectl-install.sh latest /usr/local/bin
```

### Setting Up a Cron Job in a Container

```dockerfile
FROM alpine:latest

# Install Supercronic for cron jobs
COPY docker/supercronic-install.sh /tmp/
RUN /tmp/supercronic-install.sh latest /usr/local/bin

# Add crontab file
COPY crontab /etc/crontab

# Run Supercronic as the entrypoint
ENTRYPOINT ["supercronic", "/etc/crontab"]
```

## Best Practices

1. **Layer Optimization**: Combine RUN commands where possible to reduce image layers
2. **Security First**: Apply hardening scripts early in your Dockerfile
3. **Cleanup**: Remove temporary files and installation artifacts
4. **Non-root Users**: Run containers as non-root users when possible
5. **Version Pinning**: Specify exact versions for reproducible builds

Example of optimized Dockerfile:

```dockerfile
FROM registry.access.redhat.com/ubi9/ubi-minimal:latest

# Copy all scripts at once
COPY docker/*.sh /tmp/

# Run installations in a single layer
RUN /tmp/docker-hardening-oscap.sh && \
    /tmp/kubectl-install.sh v1.26.0 /usr/local/bin && \
    /tmp/aws-cli.sh /usr/local/bin && \
    rm -rf /tmp/*.sh

# Create and use non-root user
RUN useradd -r -u 1000 -g 0 appuser
USER 1000
```

## Integration with CI/CD

These scripts are designed to work seamlessly with the build scripts in the `../build/` directory, particularly with `universal-ci.sh` for automated image building and pushing.

Example integration:

```bash
../build/universal-ci.sh my-image \
  --dockerfile ./Dockerfile \
  --version 1.0.0 \
  --push true \
  --additional-folders ./docker
```

This will include the docker scripts in the build context, making them available during the image build process.