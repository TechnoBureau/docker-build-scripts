# Common DevOps Scripts Collection

A comprehensive collection of enterprise-grade Bash scripts designed for building, deploying, and managing containerized environments.

## Table of Contents

- [Overview](#overview)
- [Repository Structure](#repository-structure)
- [Core Technologies](#core-technologies)
- [Quick Start](#quick-start)
- [Build Scripts](#build-scripts)
- [Hummingbird Builder](#hummingbird-builder)
- [AI Agent Operating Manual](#ai-agent-operating-manual)
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
├── build/                  # CI/CD and image promotion scripts
│   ├── lib/                # Modular libraries (ci-*.sh; operator-*.sh live in a companion repo)
│   │   ├── ci-hummingbird.sh   # hummingbird flavour driver
│   │   └── hummingbird/        # generators, macros, templates, vendored build inputs
│   │       └── prebuildfs/     # runtime libraries copied into built images
│   └── *.sh                # Main executables (universal-ci.sh, promotion.sh, ...)
├── docker/                 # Container setup and hardening scripts
│   └── *.sh                # Standalone installation scripts
├── tests/                  # Offline regression suites (no engine or network needed)
│   └── hummingbird/        # Shell and Python suites for the hummingbird pipeline
├── context/                # Agent & contributor knowledge base
├── README.md               # Single source of truth for humans and all AI agents
├── AGENTS.md → README.md   # Symlink: generic agent entry point
└── CLAUDE.md → README.md   # Symlink: Claude Code entry point
```

**Key Design Principles:**
- **Modularity**: Functionality split into focused library files (e.g., `ci-registry.sh`, `ci-build.sh`)
- **Reusability**: Common utilities abstracted into the extensionless `lib*` runtime libraries
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

RPM scriptlets need runtime filesystems inside newroot. Transactions use
`hb-rootfs exec` to mount `/proc`, `/sys`, `/dev` and temporary runtime directories
inside a transaction-private mount namespace. The caller never sees those mounts,
and cleanup does not depend on permission to unmount protected proc/sys trees.
This supplies `/proc/self/exe` for chrooted execution without copying builder
content or disabling scripts. The runner must support mount-only `unshare`; no
new user or PID namespace is requested.
Podman builds receive `--cap-add=SYS_ADMIN` automatically, independent of chunkah.
Docker requires **explicit** `ALLOW_INSECURE_ROOTFS=true` for trusted builds on an
isolated runner; the engine prepares the entitled BuildKit builder and limits
insecure RUN flags to rootfs transactions. Custom `BUILDX_BUILDER` instances need
the matching daemon entitlement. See the pipeline document for the security boundary.

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

## AI Agent Operating Manual

> **Single source of truth.** This README is the canonical documentation for
> every AI agent (Claude Code, Codex, Cursor, Copilot, …) and every engineer
> working in **docker-build-scripts**. [`AGENTS.md`](AGENTS.md) and
> [`CLAUDE.md`](CLAUDE.md) are **symbolic links to this file** — edit this
> README, never the links, so every agent sees the same contract.
>
> Read this manual first, then load only the relevant documents in
> [`context/`](context/README.md). Context describes current code, not one-time
> reviews or task-completion reports.

### 1. Repository surfaces

| Surface | Location | Responsibility |
| --- | --- | --- |
| Build engine | `build/universal-ci.sh`, `build/lib/ci-*.sh` | Dockerfile and Hummingbird flavours share config, registry, build and artifact machinery |
| Declarative RPM builder | `build/lib/hummingbird/` | One definition → Hummingbird/UBI distro × variant × platform builds |
| Image provisioning | `docker/` | Scripts copied into images for installation/hardening |
| Runtime libraries | `build/lib/hummingbird/prebuildfs/` | Entrypoint, logging and hook libraries inside built images |
| Image promotion | `build/promotion.sh`, `build/lib/ci-promote.sh` | skopeo-based promotion between registries; runs outside `main_build` |

`universal-ci.sh` is a source-and-call library: `source build/universal-ci.sh`,
then `main_build ...`. Running the file directly does not invoke a build.

### 2. Lifecycle hooks

#### 2.1 `on_session_start`

```bash
git status --short && git log --oneline -5
ls build/lib build/lib/hummingbird
bash --version | head -1; python3 -VV
command -v podman docker shellcheck || true
```

Preserve unrelated working-tree changes. Identify the available toolchain before
claiming runtime verification.

| Task | Load |
| --- | --- |
| Hummingbird/UBI, FIPS, rootfs, base images, packages/platforms | `context/hummingbird-pipeline.md` |
| Build/push/config/registry/artifact behavior | `context/architecture.md` |
| Editing or reviewing code | `context/conventions.md` |
| Extending capabilities | `context/extension-guide.md` |
| A failing command | `context/troubleshooting.md` |
| Tests | `tests/README.md` |

#### 2.2 `before_edit` — find the owner

| Behavior | Single owner |
| --- | --- |
| Variant **name** decomposition and repository naming | `hb_variant.py` |
| Effective FIPS policy/packages, base-image selection, assembly mode | `hb_rootfs.py` |
| YAML load/merge, required keys, distro repos/release versions | `hb_config.py` |
| Hummingbird/UBI target selection and RPM/OCI arch aliases | `hb_platforms.py` |
| Runtime/build/arch-specific package sets | `hb_packages.py` |
| Version query plan, validation, cache fingerprint | `hb_versions.py` |
| Container calls for version queries | `get_rpm_versions.sh` |
| Image-side reset, temporary transaction mounts, base validation, policy, cleanup | `rootfs.sh` |
| Work tree, matrix, per-row config | `hbgen.py` |
| Jinja context, labels/tags/tailoring | `generate_jinja2.py` |
| Flavor orchestration and per-row state | `ci-hummingbird.sh` |
| Tag strategies, logging, engine discovery | `ci-core.sh` |
| Registry/config precedence | `ci-config.sh`; FROM credential scopes in `ci-dockerfile.sh` |
| Build flags/registries | `ci-build.sh` |
| Shared Docker/Podman platform execution and manifests | `ci-platforms.sh` |
| Artifact records, digests and summaries | `ci-artifacts.sh` |
| Registry logins and credential lookup | `ci-registry.sh` |
| Build secrets (`--secret` materialisation) | `ci-secrets.sh` |
| YAML config-file parsing | `ci-yaml.sh` |
| Repo loading, image removal, cosign signing | `ci-utils.sh` |
| ECR repository auto-create | `ci-ecr.sh` |
| Promotion between registries | `ci-promote.sh` (entry point `build/promotion.sh`) |
| Vendored property aggregation (`.cache/properties.json`) | `aggregate_properties.py` |
| Vendored RPM input generation (`rpms.in.yaml`) | `generate_rpms_in.py` |

Python filenames above are under `build/lib/hummingbird/`; CI libraries are
under `build/lib/`.

Rules: bash orchestrates, Python resolves structured data, Jinja renders resolved
values. Preserve public function names. Keep useful `WHY:` comments; update them
when behavior changes. Do not commit credentials, `.hbgen/`, `.venv/` or image output.

#### 2.3 `after_edit` — fast to slow

```bash
python3 -m py_compile build/lib/hummingbird/*.py
shellcheck -x -S warning build/lib/ci-hummingbird.sh build/lib/ci-build.sh \
    build/lib/ci-platforms.sh build/lib/hummingbird/get_rpm_versions.sh \
    build/lib/hummingbird/rootfs.sh

# Needs PyYAML/Jinja2; see tests/README.md for isolated dependency setup.
HB_PYTHON=python3 ./tests/run-tests.sh
# While iterating:
HB_PYTHON=python3 ./tests/hummingbird/run-tests.sh -k matrix
```

For generated-output debugging, use the copy-and-run sequence in
`context/troubleshooting.md` §1. Stages are cumulative:
prepare → aggregate → rpms → optional versions → render → config.

No real container engine is required by the offline tests. Stubbed engine tests
verify commands, not actual image builds, RPM transactions or FIPS certification.
A separate native Linux mount/chroot probe runs when user/mount namespaces are
available; it does not emulate Rosetta or execute RPM. Report that boundary explicitly.

#### 2.4 `before_commit`

```bash
git status --short
git diff --check
git diff --stat
HB_PYTHON=python3 ./tests/run-tests.sh
```

- [ ] Behavior changed in its owner, not duplicated in a second layer
- [ ] Tests cover changed behavior and failure paths
- [ ] Context/README describe current code; no task report added
- [ ] Destructive operations validate their paths
- [ ] No generated output, credentials or virtualenv in the change
- [ ] Compatibility changes described in the change/release notes

#### 2.5 `on_failure`

1. Start with the real error, not a guess about the failing stage.
2. Reproduce with the smallest stage/test possible.
3. Inspect `.hbgen/images/<image>/<distro>/<variant>/Containerfile`, its RPM
   input, and `hbgen.py config` output rather than only the source template.
4. Add a test before fixing the behavior; rerun the whole suite afterward.

### 3. Required invariants

1. **Explicit variant distro restrictions apply.** FIPS itself is supported on
   Hummingbird, UBI9 and UBI10; use a separate restricted fixture to test filters.
   *(B2, B11, F12)*
2. **`default` is FIPS-enabled**, even with no OSCAP section. Mandatory packages,
   policy and labels agree; a FIPS-named variant cannot opt out.
   *(BuildContractTests: default/FIPS cases)*
3. **Every build starts with an empty newroot.** Only `base_image` seeds it;
   seeded packages are upgraded before requested packages are installed.
   *(RootfsHelperTests; BuildContractTests: seed/upgrade order)*
4. **Runtime and build dependencies remain separate**, including arch-specific
   entries. RPM inputs and rendered install sets use the same resolver.
   *(D2–D3; BuildContractTests: package/arch cases)*
5. **Versions are distro AND architecture scoped.** Cache TTL cannot hide a
   changed package/repo/platform request. *(C3–C7; VersionTests)*
6. **One selected platform set feeds all stages.** Unset means native;
   single-arm64 must not silently query/build amd64. *(BuildContractTests;
   VersionTests; EngineTests)*
7. **Multi-arch tags reference a manifest**, never whichever architecture
   finished last. Failed builds/pushes return non-zero. *(EngineTests)*
8. **`is_builder` uses shared variant semantics.** Composite builders retain
   their packages, defaults, licences and repository suffix. *(B5, D2–D11)*
9. **The `name=` label matches the published repository.** *(D8–D9)*
10. **`oscap` is always defined; FIPS does not depend on scanning.** *(E1–E4;
    BuildContractTests)*
11. **No stdin-consuming matrix loop or stale per-row config.** *(F9, F19)*
12. **Sourced functions return errors instead of exiting the caller.** *(F7;
    EngineTests: hummingbird helpers)*
13. **Chunkah side effects cannot be replayed from layer cache.** Explicit
    chunkah builds are uncached/serial; portable assembly needs no host archive.
    *(EngineTests: chunkah; F26)*
14. **Only selected SCAP datastreams enter the context.** *(A8–A9)*
15. **Unresolved version tags are not published.** `unknown` and `unknown-*`
    are filtered before `TAG_STRATEGY=custom`. *(F28–F32)*

16. **RPM transactions use a private mount namespace with proc/dev/runtime views.**
    Use `hb-rootfs exec`, not bare installroot transactions, disabled scriptlets or
    shared-namespace unmount retries. No nested user/PID namespace is requested.
    Preserve command failures and verify no runtime mounts are visible to the
    caller. Namespace failures must not replay the RPM command without isolation.
    Permissions are independent of chunkah; Docker elevation requires explicit
    opt-in. *(RootfsTransactionTests; RootfsMountNamespaceTests; EngineTests)*

Python test classes are in `tests/hummingbird/test_*.py` and
`tests/test_build_engine.py`. A–F identifiers belong to the shell suite.

### 4. Operational entry points

```bash
source ./build/universal-ci.sh

# Dockerfile flavour; native build with no publishing
SKIP_PUSH=true main_build -d ./Dockerfile -i myimage

# Declarative RPM builder; default variant already includes FIPS
HB_DISTROS=ubi9 HB_VARIANTS=default PLATFORMS=linux/arm64 main_build -i curl
HB_DISTROS=hummingbird HB_VARIANTS=default \
    PLATFORMS=linux/amd64,linux/arm64 main_build -i curl

# Verbose operation
DEBUG=true main_build -i curl
```

`-i` resolves under `BUILDERS_DIR`, then `SOURCE_DIR`. Supported `main_build`
options are `-d/--dockerfile`, `-i/--image`, `-r/--repo`, `-b/--branch`,
`-f/--flavor`. Other settings are environment/config values, not CLI flags.

Hummingbird knobs: `HB_DISTROS`, `HB_VARIANTS`, `HB_VERSION`, `HB_TAGS`,
`HB_REGISTRIES`, `HB_SKIP_RPM_VERSIONS`, `HB_RPM_VERSIONS_TTL`, `HB_PYTHON`,
`HUMMINGBIRD_DIR`. Shared engine knobs include `PLATFORMS`, `SKIP_PUSH`,
`INSTALL_BINFMT=auto|false|force`, `DIND_IMAGE`, `SOURCE_DATE_EPOCH`, `DEBUG`,
`BUILD_OUTPUT_DIR`, `BUILDX_BUILDER`, `ALLOW_INSECURE_ROOTFS` (Docker mount-aware
recipes; trusted builds only), and Podman's `PARALLEL_PLATFORMS`/`BUILD_JOBS`.

FIPS-ready userspace is not proof of validated FIPS operation. Verify approved
modules, host FIPS mode and application behavior on the deployment platform.

### 5. Context documents

Every agentic-AI context document in this repository, in load order. The
knowledge base under [`context/`](context/README.md) is loaded on demand, not
all at once.

| Document | What it owns |
| --- | --- |
| [`README.md`](README.md) (this file) | Single source of truth: user documentation + this agent operating manual |
| [`AGENTS.md`](AGENTS.md) | Symlink → `README.md`; generic agent entry point (same content) |
| [`CLAUDE.md`](CLAUDE.md) | Symlink → `README.md`; Claude Code entry point (same content) |
| [`context/README.md`](context/README.md) | Knowledge-base index and maintenance rules |
| [`context/architecture.md`](context/architecture.md) | Module map, call graph, the shared `CONFIG` contract, registry precedence |
| [`context/hummingbird-pipeline.md`](context/hummingbird-pipeline.md) | Hummingbird/UBI distros, FIPS, rootfs, base images, platforms, package queries |
| [`context/conventions.md`](context/conventions.md) | Bash / Python / Jinja style, `WHY:` comments, determinism rules |
| [`context/extension-guide.md`](context/extension-guide.md) | Recipes: add a distro, variant, package group, macro or knob |
| [`context/troubleshooting.md`](context/troubleshooting.md) | Real error messages, causes and fixes |
| [`tests/README.md`](tests/README.md) | How the offline suite works and how to extend it |
| [`docker/README.md`](docker/README.md) | The standalone `docker/*.sh` image-provisioning scripts |

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

The `build/lib/hummingbird/prebuildfs/` tree is copied into images built by the
hummingbird flavour. It provides reusable shell libraries for container
initialization and runtime. The libraries are extensionless and are sourced
from their installed location, e.g. `. /usr/local/bin/liblog`.

| Library | Purpose |
| --- | --- |
| `usr/local/bin/liblog` | JSON-stream logging (`log`, `info`, `warn`, `error`, `debug`) — one JSON object per line |
| `usr/local/bin/libjson` | Pure-bash JSON reader (`json_get`, `json_has`) with no jq/grep/sed/awk dependency |
| `usr/local/bin/libfs` | Filesystem helpers safe for non-root users on read-only filesystems |
| `usr/local/bin/libenv` | Environment helpers; `env_dump` degrades to a no-op on read-only filesystems |
| `usr/local/bin/libhook` | Runs lifecycle hooks with output redirected to PID 1 so it lands in the container log stream |
| `usr/local/bin/libwatch` | File watcher that runs a reload/custom hook when watched config changes |
| `usr/local/bin/libentrypoint` | Runs user init scripts from `INITSCRIPTS_DIR` with no ownership changes |
| `usr/sbin/run-script` | POSIX wrapper for running a script with arguments |
| `usr/sbin/install_packages_chroot` | Installs packages into a chroot (Hummingbird/UBI release argument) |

### Library Usage Example

```bash
# Source required libraries
. /usr/local/bin/liblog
. /usr/local/bin/libjson

# Use logging functions
info "Informational message"
warn "Warning message"
error "Error message"
debug "Debug message (only shown when DEBUG=true)"
```

**JSON Logging**: All log functions output structured JSON:
```json
{"level":"info","ts":"2026-05-31T09:55:23Z","msg":"Build completed"}
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
- Add a `.dockerignore` file to exclude unnecessary files
- Use `DOCKER_DIR` / `PREBUILD_DIR` / `ROOTFS_DIR` to merge only the required
  extra folders (`docker/`, the prebuildfs tree, `rootfs/`) into the build context

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
- Artifacts saved via `ci_store_artifact()` in `ci-artifacts.sh`
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
- [AI Agent Operating Manual](#ai-agent-operating-manual) — hooks, invariants,
  behaviour-ownership map (this file; `AGENTS.md`/`CLAUDE.md` are symlinks to it)
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
- [ ] Behaviour changed in its single owner only ([README.md](#ai-agent-operating-manual) §2.2)
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
