# Common DevOps Scripts Collection

A comprehensive collection of enterprise-grade Bash scripts designed for building, deploying, and managing containerized environments.

## Table of Contents

- [Overview](#overview)
- [Repository Structure](#repository-structure)
- [Core Technologies](#core-technologies)
- [Quick Start](#quick-start)
- [Build Scripts](#build-scripts)
- [Hummingbird Builder](#hummingbird-builder)
- [Agent & Contributor Documentation](#agent--contributor-documentation)
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
docker-build-scripts/
├── build/                  # CI/CD and operator management scripts
│   ├── lib/                # Modular libraries (ci-*.sh, operator-*.sh)
│   │   ├── ci-hummingbird.sh   # hummingbird flavour driver
│   │   └── hummingbird/        # generators, macros, templates, vendored build inputs
│   └── *.sh                # Main executables (universal-ci.sh, promotion.sh, ...)
├── docker/                 # Container setup and hardening scripts
│   └── *.sh                # Standalone installation scripts
├── tests/hummingbird/      # Offline regression suite for the hummingbird pipeline
├── context/                # Agent & contributor knowledge base
├── AGENTS.md               # Entry point for AI agents (hooks, invariants, ownership map)
└── prebuildfs/             # Container runtime libraries
    └── opt/scripts/
        └── lib*.sh         # Reusable shell libraries
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

- Bash 4.4+ (associative arrays and modern array handling)
- Docker or Podman
- For multi-arch builds: QEMU (`docker run --privileged --rm tonistiigi/binfmt --install all`)
- For operator tools: `opm`, `kubectl`, `yq`, `jq`

### Basic Usage

The universal engine is a **source-and-call library**:

```bash
source ./build/universal-ci.sh

# Simple Dockerfile build
main_build -d /path/to/Dockerfile -i myimage

# Version and registry settings (subject to configuration precedence)
VERSION=1.0.0 REGISTRY=quay.io/acme main_build -d ./Dockerfile -i myapp

# Multi-architecture build
PLATFORMS=linux/amd64,linux/arm64 main_build -d ./Dockerfile -i myapp

# Build without publishing image tags
SKIP_PUSH=true main_build -d ./Dockerfile -i myapp
```

---

## Build Scripts

The `build/` directory contains scripts for CI/CD operations. Each script documents its own usage in its header comments; see [Architecture](context/architecture.md) for how the libraries fit together and [Hummingbird Builder](#hummingbird-builder) for the declarative RPM pipeline.

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

**Tag Strategies** (implemented in `ci_generate_tag()`, `build/lib/ci-core.sh`):

| Strategy | Tags produced |
| --- | --- |
| `version` | `1.0.0` |
| `latest` | `latest` |
| `version-latest` (default) | `1.0.0` and `latest` |
| `runner` / `sha` | CI runner id / git short SHA |
| `runner-latest` / `sha-latest` | runner id or SHA, plus `latest` |
| `version-runner` / `version-sha` | `1.0.0.<runner>` / `1.0.0.<sha>` |
| `version-runner-latest` / `version-sha-latest` | the above, plus `latest` |
| `tag` / `tag-latest` | from `CONFIG[GIT_TAG]`, optionally plus `latest` |
| `custom` | the space-separated list in `CONFIG[CUSTOM_TAGS]` |

> There is **no** `version-only`, `latest-only` or `git-sha` strategy — use
> `version`, `latest` and `sha`. An unrecognised value logs a warning and falls
> back to `latest` rather than failing the build.

### Operator Management

Complete lifecycle: Rebundle → Catalog → Promotion

> **Note:** `operator-rebundle.sh` and `operator-catalog.sh` (and the
> `operator-*.sh` libraries they use) are **not part of this repository** — they
> live in the companion operator tooling repo. The commands below are kept
> because the promotion step *is* here and the three are normally run in
> sequence. Only `promotion.sh` will resolve in this checkout.

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

- **universal-ci.sh**: Main CI/CD pipeline for container builds — `main_build()` is sourced by consumer repos ([architecture](context/architecture.md))
- **promotion.sh**: Image promotion between registries (`./build/promotion.sh --help`)
- **go-dependencies.sh**: Installs Go language dependencies with version control
- **re-source.sh**: Utility for re-sourcing environment variables
- **market-actions.py**: Bulk GitHub Enterprise workflow management. Fill in `REPO_OWNER` / `REPO_NAMES` and supply `GITHUB_TOKEN` from the environment before running — the checked-in value is a placeholder
- **ci-hummingbird.sh** + **hummingbird/**: declarative RPM image builder ([Hummingbird Builder](#hummingbird-builder))
- *(not in this repo)* **operator-rebundle.sh**, **operator-catalog.sh**: operator hardening and OLM catalog generation

### Build Libraries (`build/lib/`)

- **ci-*.sh**: Modular CI/CD libraries (core, config, registry, build, artifacts, secrets)
- **ci-hummingbird.sh**: hummingbird flavour driver (see [Hummingbird Builder](#hummingbird-builder))
- **hummingbird/**: declarative image generators, Jinja macros/templates and vendored build inputs
- **ci-promote.sh**: helpers used by `promotion.sh`

---

## Hummingbird Builder

The **hummingbird** flavour builds RPM images for Hummingbird, UBI 9 and UBI 10
from a declarative definition, with FIPS-enabled defaults and optional OSCAP scans. One builder
directory fans out into a matrix of distro × variant images:

```
builders/curl/                        .hbgen/images/curl/
├── properties.yml      what          ├── hummingbird/default/  → curl:8.21.0
├── Containerfile.j2    how           ├── hummingbird/builder/  → curl-builder:8.21.0-builder
├── variables.yml       overrides     ├── hummingbird/fips/     → curl:8.21.0-fips
├── rootfs/  src/       context       ├── ubi9/default/         → curl:8.10.1
└── .gitmodules         submodules    └── ubi9/builder/         → curl-builder:8.10.1-builder
```

### Usage

```bash
source ./build/universal-ci.sh
# Auto-detected from properties.yml + Containerfile.j2 under BUILDERS_DIR/SOURCE_DIR
main_build -i curl

# Single or multi-arch on either distro; default already includes FIPS
HB_DISTROS=ubi9 HB_VARIANTS=default PLATFORMS=linux/arm64 main_build -i curl
HB_DISTROS=hummingbird HB_VARIANTS=default \
    PLATFORMS=linux/amd64,linux/arm64 main_build -i curl

# Skip repository version queries (the actual image build still needs an engine)
HB_SKIP_RPM_VERSIONS=true HB_VERSION=8.21.0 SKIP_PUSH=true main_build -i curl
```

### FIPS, platforms and base images

`default` and `builder` are FIPS-enabled without needing an `oscap` section or a
separate `-fips` variant. The resolver adds crypto-policy/OpenSSL/FIPS-provider
packages for each distro; Hummingbird also receives `openssl-config-fips`.
Contradictory policy settings and missing providers fail rather than silently
producing an image labelled FIPS.

Newroot **always starts empty**. An optional `base_image` supplies filesystem
content; inherited packages are upgraded before the requested packages are installed:

```yaml
# properties.yml additions
platforms: [linux/amd64, linux/arm64]  # one entry for single-arch; omit for native
base_image:
  ubi9: registry.access.redhat.com/ubi9/ubi-minimal:latest
  ubi10: registry.access.redhat.com/ubi10/ubi-minimal:latest
  # Hummingbird is unseeded in this example.
rpm_packages:
  all: [curl, ca-certificates]
```

Use a distro-compatible base with the selected architectures; pin approved
references for releases. Base `ENV`, `USER` and `ENTRYPOINT` metadata is not inherited
by a filesystem copy. Build dependencies stay in the tooling stage.

Default final assembly is portable `FROM scratch` + `COPY --from=builder`.
`chunkah: true` remains an explicit Podman-only option, serialized and uncached
so archive side effects cannot cross architectures. Docker multi-arch uses buildx
indexes; Podman joins per-platform image IDs into one manifest. With no push,
Docker saves an OCI archive (`BUILD_OUTPUT_DIR`, default `.ci-output/`) and Podman
keeps a local manifest.

**FIPS packages/policy are not a certification claim.** Validate module versions,
application crypto use, and FIPS host/runtime configuration before deployment.
Full settings and package lists: [Hummingbird pipeline](context/hummingbird-pipeline.md).

### Pipeline

```
1 prepare    hbgen.py            → .hbgen/ work tree (vendored generator layout)
2 aggregate  aggregate_properties.py → variants, distros, per-variant distro restrictions
3 rpms       hbgen.py            → <distro>/<variant>/rpms/rpms.in.yaml
4 versions   get_rpm_versions.sh → .cache/rpm-versions.yml (per distro/architecture; needs an engine)
5 render     hbgen.py            → Containerfile, VERSION, TAGS, oscap-tailoring.xml
6 build      ci_build_and_push   → one image per matrix row (shared engine)
```

Every stage is a standalone command, so a failure can be reproduced without
running the whole pipeline:

```bash
python3 build/lib/hummingbird/hbgen.py matrix  --hbgen <builder>/.hbgen --image curl
python3 build/lib/hummingbird/hbgen.py config  --hbgen <builder>/.hbgen --image curl \
        --distro ubi9 --variant default        # prints the exact CONFIG pairs
```

### Modules

| Module | Owns |
| --- | --- |
| `build/lib/ci-hummingbird.sh` | Bash orchestration only: paths, logging, matrix loop, `CONFIG` |
| `hummingbird/hbgen.py` | Pipeline CLI: `prepare`, `rpms`, `matrix`, `render`, `config`, `vars`, `distros`, `variants` |
| `hummingbird/hb_variant.py` | Variant decomposition (`fips-builder` → base/modifiers) and image naming |
| `hummingbird/hb_config.py` | YAML loading, deep merge, required-key validation, actionable errors |
| `hummingbird/hb_packages.py` | Runtime/build package sets — one rule for RPM inputs and install commands |
| `hummingbird/hb_rootfs.py`, `rootfs.sh` | FIPS/base-image policy and image-side rootfs lifecycle |
| `hummingbird/hb_platforms.py`, `hb_versions.py` | Target architecture selection, version-query plan/cache validation |
| `build/lib/ci-platforms.sh` | Docker/Podman builds, manifest assembly, no-push output |
| `hummingbird/generate_jinja2.py` | Template context, labels, tags, rendering |
| `hummingbird/macros/`, `templates/` | Jinja building blocks for the generated Containerfile |

Design rule: **bash orchestrates, Python decides.** No YAML parsing in bash, no
container-engine calls in Python.

### Environment knobs

| Variable | Effect |
| --- | --- |
| `HB_DISTROS` / `HB_VARIANTS` | Select distros / variants (validated against the definition) |
| `HB_VERSION` / `HB_TAGS` | Override the resolved version / tag list |
| `HB_REGISTRIES` | Comma-separated push targets (with `IMAGE_PREFIX`) |
| `HB_SKIP_RPM_VERSIONS` | `true` skips stage 4 (versions fall back to `latest`) |
| `HB_RPM_VERSIONS_TTL` | Reuse a version cache younger than N seconds |
| `HB_PYTHON` | Interpreter for all generators (venv / pinned python) |
| `HUMMINGBIRD_DIR` | Vendored machinery location (default `build/lib/hummingbird`) |

### Tests

```bash
HB_PYTHON=python3 ./tests/run-tests.sh      # all offline regression/contract suites
```

No container engine, network, builder image or package repository required —
`tests/hummingbird/stubs/podman` answers the `dnf repoquery` calls. See
[tests/README.md](tests/README.md).

### Documentation

- [context/hummingbird-pipeline.md](context/hummingbird-pipeline.md) — concepts, stages, configuration keys, macros, invariants
- [context/extension-guide.md](context/extension-guide.md) — add a distro, variant, package group, macro or knob
- [context/troubleshooting.md](context/troubleshooting.md) — message → cause → fix

---

## Agent & Contributor Documentation

This repository is written to be operated by AI agents as well as humans.

| File | Purpose |
| --- | --- |
| [`AGENTS.md`](AGENTS.md) | Entry point: runnable lifecycle hooks (`on_session_start`, `before_edit`, `after_edit`, `before_commit`, `on_failure`), the behaviour-ownership map, and the non-negotiable invariants |
| [`context/README.md`](context/README.md) | Index of the knowledge base — load on demand, not all at once |
| [`context/architecture.md`](context/architecture.md) | Module map, call graph, the shared `CONFIG` contract, registry precedence |
| [`context/conventions.md`](context/conventions.md) | Bash / Python / Jinja style, `WHY:` comments, determinism rules |
| [`context/extension-guide.md`](context/extension-guide.md) | Step-by-step recipes for the ten most common extensions |
| [`context/troubleshooting.md`](context/troubleshooting.md) | Real messages, causes and fixes |
| [`tests/README.md`](tests/README.md) | How the offline suite works and how to extend it |
| [`CLAUDE.md`](CLAUDE.md) | Repository guide for Claude Code |

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

### Build Behaviour

```bash
export INSTALL_BINFMT=auto   # auto (default) | false | force
export DIND_IMAGE=""         # override the binfmt/runtime helper image
export SOURCE_DATE_EPOCH=0   # reproducible image timestamps
```

`INSTALL_BINFMT` controls QEMU installation for non-native targets, including a
single foreign architecture, on Docker and Podman:

| Value | Behaviour |
| --- | --- |
| `auto` (default) | Install only the emulators that are missing |
| `false` | Never install; log what is missing and continue. Use on runners without `--privileged` |
| `force` | Install even when the emulator is already registered |

An unrecognised value warns and falls back to `auto`.

### Debug Mode

```bash
export DEBUG=true          # Enable debug output
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
source ./build/universal-ci.sh
SKIP_PUSH=true main_build -d ./Dockerfile -i myapp

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
source ./build/universal-ci.sh
main_build -d ./Dockerfile -i myapp
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

- [Docker Scripts Documentation](docker/README.md)
- [Architecture](context/architecture.md) — module map, call graph, `CONFIG` contract, registry precedence
- [Hummingbird Pipeline](context/hummingbird-pipeline.md) — concepts, stages, configuration keys, macros
- [Conventions](context/conventions.md) — bash / Python / Jinja style and determinism rules
- [Extension Guide](context/extension-guide.md) — add a distro, variant, package group, macro or knob
- [Troubleshooting](context/troubleshooting.md) — message → cause → fix
- Registry credentials: see `build/lib/ci-registry.sh` and [Configuration Management](#configuration-management)
- Universal CI usage: see [Build Scripts](#build-scripts) and the header comments in `build/universal-ci.sh`
- [Agent Operating Manual](AGENTS.md) — hooks, invariants, behaviour-ownership map
- [Context Knowledge Base](context/README.md) — architecture, hummingbird pipeline, conventions, extension guide, troubleshooting
- [Test Suite](tests/README.md) — offline regression tests

---

## Contributing

1. Fork the repository
2. Create a feature branch
3. Follow the development conventions outlined above
4. Add tests for new functionality
5. Update documentation as needed
6. Submit a pull request

### Code Review Checklist

- [ ] Follows script structure conventions ([context/conventions.md](context/conventions.md))
- [ ] Behaviour changed in its single owner only ([AGENTS.md](AGENTS.md) §2.2)
- [ ] Includes proper error handling (libraries return non-zero; never `exit` or `${1:?}`)
- [ ] Uses consistent logging (JSON format)
- [ ] Includes WHY comments for non-obvious logic
- [ ] Updates relevant documentation (`context/` and this README)
- [ ] Adds/updates a regression assertion in [tests/hummingbird](tests/README.md)
- [ ] Tested locally with debug mode
- [ ] No hardcoded credentials or secrets

---

## License

See the [LICENSE](LICENSE) file for details.
