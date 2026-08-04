# Unified Image Build System Design

Date: 2026-08-04
Status: Proposed
Repos involved: `docker-build-scripts` (scripts, driver), `docker-builds` (monorepo of image definitions), `containers` (source of truth for hummingbird pipeline machinery)

## Overview

`docker-build-scripts` currently builds classic Dockerfile-based images (e.g. `FROM ubi9 + install_packages_chroot`) in a CI-agnostic way. The `containers` repo builds images with the Hummingbird pipeline (jinja2 generation, dnf repos in a builder image, chunkah rootfs, `oci-archive` import, FIPS packages, rpm-derived version tags).

This project unifies both into one build system: a single driver (`universal-ci.sh`) that auto-detects the image flavor and builds, tags, pushes, and attaches SBOM/vulnerability artifacts for both flavors, from either a monorepo layout or a remote git repository.

Decisions confirmed with the user:

- The unified system lives in `docker-build-scripts` (flavor plugin approach).
- The Hummingbird flavor consumes a full Hummingbird definition (`properties.yml` + `Containerfile.j2` + optional `rpms.in.yaml`).
- Flavor is auto-detected from the files present in the image directory (no `--flavor` flag required, though an override flag exists).
- No `build.yaml` anywhere: configuration comes from Dockerfile comments (ubi9 flavor), `properties.yml` (Hummingbird flavor), environment variables, and `build.sh` wrapper arguments.
- Tagging is hybrid: rpm-version tags when `properties.yml` declares package-based tags, otherwise `TAG_STRATEGY`; git-tag auto-increment (semantic versioning) supported in both flavors; multiple tags per image supported.
- Variants (default/builder) exist in the Hummingbird flavor only.
- The post-build stage generates and attaches an SBOM and a vulnerability report to the registry.
- One generated Containerfile serves all variants and all architectures; variant selection happens at build time via build arguments.
- Multi-arch builds reuse the existing `ci_build_and_push` machinery: per-arch builds, per-arch artifact save (`ci_ibmcloud_save_artifact`), and manifest/index push for all tags.

## Repository Layout

### docker-build-scripts (this repo)

```
docker-build-scripts/
├── build/
│   ├── universal-ci.sh          # driver (modified: flavor detection, dispatch, post-build artifacts)
│   └── lib/
│       ├── ci-core.sh           # existing (unchanged)
│       ├── ci-config.sh         # existing; YAML path unused (no build.yaml), comment/env path active
│       ├── ci-build.sh          # existing (unchanged; multi-arch engine reused by both flavors)
│       ├── ci-dockerfile.sh     # existing (unchanged)
│       ├── ci-registry.sh       # existing (unchanged)
│       ├── ci-sbom.sh           # existing; re-enabled from universal-ci.sh
│       ├── ci-vuln.sh           # NEW: grype vulnerability scan + oras attach
│       └── ci-hummingbird.sh    # NEW: Hummingbird flavor pipeline
├── hummingbird/
│   ├── variables.yml            # vendored: registry/labels/FIPS defaults
│   ├── macros/                  # vendored: *.yml.j2 macros
│   ├── templates/               # vendored: oscap-tailoring.xml.j2, grype-markdown.tmpl
│   ├── generate_jinja2.py       # vendored
│   ├── generate_rpms_in.py      # vendored
│   ├── aggregate_properties.py  # vendored
│   └── get_rpm_versions.sh      # vendored: rpm-version resolution
└── tools/
    └── sync-hummingbird.sh      # NEW: syncs hummingbird/ from the containers repo
```

`hummingbird/` is fully self-contained: docker-build-scripts works standalone without the containers repo. The containers repo remains the source of truth for the vendored files.

### docker-builds (image definitions monorepo)

```
docker-builds/
└── builders/
    └── <image>/
        ├── build.sh             # thin wrapper (existing pattern)
        ├── Dockerfile           # ubi9 flavor (Dockerfile comments carry config)
        ├── Containerfile.j2     # Hummingbird flavor (optional)
        ├── properties.yml       # Hummingbird flavor (optional)
        ├── rpms.in.yaml         # Hummingbird flavor (optional)
        └── rootfs/              # optional shared rootfs content (both flavors)
```

An image directory may define one flavor or both. No `build.yaml` files.

### Remote repositories

A remote repo contains the same per-image directory layout as the monorepo (or a single image definition at its root). It is cloned by the existing `-r/--repo` mechanism in `universal-ci.sh`; flavor detection runs on the cloned directory.

## tools/sync-hummingbird.sh

Developer tool; never runs during image builds. Copies the Hummingbird pipeline machinery from a local checkout of the `containers` repo into `hummingbird/`:

- `images/variables.yml` → `hummingbird/variables.yml`
- `macros/` → `hummingbird/macros/`
- `templates/` → `hummingbird/templates/` (grype-markdown.tmpl, oscap-tailoring.xml.j2, TAGS.j2, VERSION.j2; readme templates are not used)
- `ci/internal/generate_jinja2.py`, `ci/internal/generate_rpms_in.py`, `ci/internal/aggregate_properties.py` → `hummingbird/`
- `ci/get_rpm_versions.sh` → `hummingbird/`

Usage: `tools/sync-hummingbird.sh [--from /path/to/containers]`. Default source is a sibling checkout (`../containers`). After sync, the diff is inspected and committed manually.

## Driver Changes (universal-ci.sh)

### Flavor detection

New `ci_detect_flavor <dir>` (in `ci-hummingbird.sh`):

1. `Containerfile.j2` + `properties.yml` present → `hummingbird`
2. `Dockerfile` present → `dockerfile` (classic/ubi9)
3. Otherwise error: no recognizable image definition.

Overrides: `--flavor hummingbird|dockerfile` argument, or `FLAVOR` environment variable. `FLAVOR` wins over auto-detection; auto-detection wins when no override is given.

### Dispatch

`main_build` flow (post-source-resolution):

1. Resolve source: monorepo builder dir, or `-r`-cloned repository (existing behavior).
2. Detect flavor in the source dir.
3. Extract git info from the source dir (`extract_git_info`, existing).
4. `dockerfile` flavor → existing `ci_build_and_push` path unchanged.
5. `hummingbird` flavor → `ci_hummingbird_build "$SOURCE_DIR"` (Section: Hummingbird pipeline).
6. Post-build stage runs for both flavors (Section: Post-build artifacts).

### Configuration model (no build.yaml)

- ubi9 flavor: Dockerfile comments (`# IMAGE_NAME:`, `# REGISTRY_0:`, `# REGISTRY_0_PREFIX:`, `# TAG_STRATEGY:`, `# VERSION:`, `# PLATFORMS:`, ...), env vars, `build.sh` args. YAML config loading in `ci-config.sh` is simply never invoked.
- Hummingbird flavor: `properties.yml` (packages, tags, variants, stream, repository, summary/description/url), `Containerfile.j2` (structure), vendored `hummingbird/variables.yml` (registry/label defaults), env vars, `build.sh` args.
- Registry array (`REGISTRIES`) and tag generation (`ci_generate_tag`) stay the shared pipeline for both flavors.

## Hummingbird Pipeline (ci-hummingbird.sh)

### Version resolution (hybrid, multiple tags)

`ci_hummingbird_resolve_versions <dir>` produces the tag set for the image:

1. **RPM-version tags**: if `properties.yml` declares a `tags:` block with package macros, resolve versions via `get_rpm_versions.sh` (vendored) and expand (e.g. `latest`, `8`, `8.21`, `8.21.0`).
2. **Git-info tags**: `extract_git_info` on the source dir provides the auto-incremented semantic version (git tag + 1 patch), git SHA, and branch. If the properties tags block is absent, the git-derived version feeds `TAG_STRATEGY` (default `version-latest`).
3. **Union**: when both sources exist, the tag set is the union (rpm-derived tags plus git-derived tags as configured). `CONFIG[VERSION]` is set to the highest/preferred semantic version for labels.

The tag set feeds the existing registry loop, so every registry receives every tag.

### Single Containerfile for all variants and architectures

Generation produces exactly one `Containerfile` per image (arch-neutral). Variant selection is entirely build-time:

- `ARG MAIN_PACKAGES="<default variant packages>"` (already exists) — builder variant passes its extended package list.
- `ARG VARIANT=default` — used in shell conditionals:
  - default-only: erase `grep findutils bash coreutils-single`, locale/license cleanup
  - builder-only: write `/etc/dnf/libdnf5.conf.d/90-builder-defaults.conf`
- `ARG VARIANT_PATH` — relative path used by `verify-compliance` and the tailoring file reference.
- `ARG ARCHIVE_PATH=out-${VARIANT}-${TARGETARCH}.ociarchive` — unique per variant+arch to avoid collisions on the shared `/run/src` bind mount during parallel multi-arch builds; used both in the chunkah redirect and in `FROM oci-archive:${ARCHIVE_PATH}`.
- Variant labels (`io.hummingbird-project.variant`, `variant.base`, `variant.builder`, `name=...-builder`) are passed via `--label` at build time, not baked into the file.
- `ENV CONTAINER_DEFAULT_USER` set from an ARG default (applies to all variants).

No per-arch Containerfiles exist: chunkah builds the rootfs for the target architecture inside the build (`TARGETARCH`/`--platform`).

### Generation

`ci_hummingbird_generate <dir> <variant-config>` runs the vendored generator:

1. `aggregate_properties.py` → `.cache/properties.json` (build.yaml-free; reads properties.yml + variables.yml)
2. `get_rpm_versions.sh` → `.cache/rpm-versions.yml` (when the tags block uses package versions)
3. `generate_rpms_in.py` → `rpms.in.yaml` (when absent)
4. `generate_jinja2.py` → one `Containerfile` (+ `oscap-tailoring.xml` as configured)

Git metadata (`GIT_SHA`, `GIT_SOURCE_URL`, `GIT_BRANCH`) is fed into the generator so OCI labels carry revision/source, matching the ubi9 path.

### Build

`ci_hummingbird_build <dir>`:

1. For each variant declared in `properties.yml` (default; default+builder):
   - compute tags (variant suffix `-builder` appended for builder variants)
   - set build args: `VARIANT`, `MAIN_PACKAGES`, `VARIANT_PATH`, `ARCHIVE_PATH`, labels
2. Call `ci_build_and_push` once per variant with the generated Containerfile.
   - docker: per-platform parallel builds (existing), per-arch artifact save via `ci_ibmcloud_save_artifact`, index push for all tags.
   - podman: `podman manifest create` + per-`--platform` builds into `--manifest` (existing), per-arch artifact save, `podman manifest push --all` for every tag in `CI_BUILT_IMAGES`.
3. Built images registered in `CI_BUILT_IMAGES` so the shared push/artifact stages apply.

The ubi9 flavor keeps its current single-variant behavior (no builder variant).

## Post-build Artifacts

Re-enabled in `main_build` for both flavors:

1. **SBOM**: `ci_generate_sbom` (syft, fallback trivy) → `ci_attach_sbom` (cosign attest → docker buildx annotation → local artifacts dir fallback, existing `ci-sbom.sh` behavior).
2. **Vulnerability report** (new `ci-vuln.sh`): grype via `docker.io/anchore/grype:latest` (proven working in the containers session) → report (JSON + markdown via vendored `grype-markdown.tmpl`) → `oras attach --artifact-type application/vnd.security.vulnerability.report+json` to each built image.
3. Env flags: `SBOM_SKIP=true`, `VULN_SKIP=true`, `REMOVE_LOCAL_IMAGES` (existing). Missing tools degrade to warnings, never failures (existing style).

## Error Handling

- Unknown flavor → clear error listing detected files.
- Missing builder image / dnf repoquery failure → error with remedy message (existing pattern).
- chained operations use `|| { log_error ...; return 1; }` (existing repo style).
- Failed variant build aborts that variant; other variants are not attempted; exit code reflects failure.
- Artifact attachment failures are warnings (registry attach must not fail the build).

## Testing

1. `tools/sync-hummingbird.sh` smoke: run with the containers checkout, verify generated `hummingbird/` passes `generate_jinja2.py --help`.
2. ubi9 regression: `builders/curl` (existing Dockerfile path) builds with `--skip-push`; tag/label checks.
3. Hummingbird single-variant: a builder with `properties.yml` + `Containerfile.j2` builds with `--skip-push`; version tags match `rpm-versions` output; git labels present.
4. Hummingbird two-variant: same image with variants declared; `-builder` tags exist; default image lacks bash/dnf5, builder image has them.
5. Multi-arch: `--platforms linux/amd64,linux/arm64` on podman; manifest/index has both arches; per-arch artifacts recorded.
6. Remote repo: `universal-ci.sh -r <test-repo-url>` clones and builds both flavors.
7. SBOM/vuln attach: with cosign/oras installed, artifacts appear in the registry (retrieve via `cosign download sbom` / `oras manifest fetch`).

## Non-goals

- No `build.yaml` support (removed by decision).
- No operator/OLM functionality changes (`operator-*` scripts untouched).
- No changes to the ubi9 Dockerfile building semantics.
- The containers repo keeps its own `hb-build.sh`; the unified system does not call it.
