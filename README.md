# Docker Common Scripts for DevOps

A collection of utility scripts for Docker/container builds, CI/CD pipelines, and infrastructure automation for Docker environments.

## Overview

This repository contains a collection of scripts organized into different categories to support DevOps operations for Docker environments. These scripts help with tasks such as:

- Building and hardening Docker images
- Setting up development environments
- Installing common tools and dependencies
- Configuring CI/CD pipelines
- Automating infrastructure tasks

## Repository Structure

The repository is organized into the following main directories:

- **[build/](build/README.md)**: Scripts for building and CI/CD operations
- **[docker/](docker/README.md)**: Scripts for Docker image creation and configuration
- **prebuildfs/**: Pre-build filesystem scripts and libraries for container images

## Build Scripts

The `build/` directory contains scripts for building and CI/CD operations ([more details](build/README.md)):

- **go-dependencies.sh**: Installs Go language dependencies with specific version control
- **re-source.sh**: Utility for re-sourcing environment variables
- **universal-ci.sh**: Universal CI pipeline script for building and pushing Docker/Podman images ([detailed usage](build/README.md#universal-cish))

## Docker Scripts

The `docker/` directory contains scripts for Docker image creation and configuration ([more details](docker/README.md)):

- **aws-cli.sh**: Installs AWS CLI with cross-platform support ([usage](docker/README.md#aws-clish))
- **docker-hardening-oscap.sh**: Applies DISA STIG security hardening for RHEL 9 ([usage](docker/README.md#docker-hardening-oscapsh))
- **go-setup.sh**: Sets up Go environment and builds Go applications
- **instana-plugin-install.sh**: Installs Instana monitoring plugins
- **kubectl-install.sh**: Installs kubectl with version control ([usage](docker/README.md#kubectl-installsh))
- **older-support-nginx.sh**: Configures Nginx for legacy support
- **supercronic-install.sh**: Installs Supercronic (cron for containers) ([usage](docker/README.md#supercronic-installsh))
- **venv.sh**: Sets up Python virtual environments ([usage](docker/README.md#venvsh))

## Prebuildfs Scripts

The `prebuildfs/` directory contains pre-build filesystem scripts and libraries:

- **opt/nonroot/scripts/**: Library scripts for container initialization and runtime
  - **libentrypoint.sh**: Entry point script utilities
  - **libenv.sh**: Environment variable utilities
  - **libfile.sh**: File operation utilities
  - **libfs.sh**: Filesystem utilities
  - **libhook.sh**: Hook script utilities
  - **libcommon.sh**: Custom utilities
  - **liblog.sh**: Logging utilities
  - **libnet.sh**: Network utilities
  - **libos.sh**: Operating system utilities
  - **libpersistence.sh**: Data persistence utilities
  - **libservice.sh**: Service management utilities
  - **libvalidations.sh**: Validation utilities
  - **libversion.sh**: Version management utilities
  - **libwebserver.sh**: Web server utilities

## Usage

### Build Scripts

To use the build scripts:

```bash
# Install Go dependencies
./build/go-dependencies.sh [version]

# Run the universal CI pipeline
./build/universal-ci.sh [image_name] [options]
```

For detailed options and examples, see the [Build Scripts Documentation](build/README.md#common-use-cases).

### Docker Scripts

To use the Docker scripts:

```bash
# Install AWS CLI
./docker/aws-cli.sh [install_dir]

# Apply Docker hardening
./docker/docker-hardening-oscap.sh

# Install kubectl
./docker/kubectl-install.sh [version] [install_dir]
```

For detailed options, examples, and best practices, see the [Docker Scripts Documentation](docker/README.md#common-use-cases).

### In Dockerfiles

You can use these scripts in your Dockerfiles:

```dockerfile
# Example Dockerfile using the scripts
FROM registry.access.redhat.com/ubi9/ubi-minimal:latest

COPY docker/docker-hardening-oscap.sh /tmp/
RUN /tmp/docker-hardening-oscap.sh

COPY docker/kubectl-install.sh /tmp/
RUN /tmp/kubectl-install.sh v1.26.0 /usr/local/bin
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## License

See the [LICENSE](LICENSE) file for details.
