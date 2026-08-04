# Unified Image Build System — Implementation Plan

Date: 2026-08-04
Status: Proposed
Spec: [2026-08-04-unified-image-build-system-design.md](../specs/2026-08-04-unified-image-build-system-design.md)

## Verified integration points (read from source)

| Component | Location | Notes |
|-----------|----------|-------|
| Driver | `build/universal-ci.sh:79` `main_build` | Dockerfile search → `load_config` → `extract_git_info` → `ci_build_and_push` → post-build (SBOM commented out at lines 222–232) |
| Build engine | `build/lib/ci-build.sh:279` `ci_build_and_push` | Tags from `ci_generate_tag` output (space-separated); per-registry repo loop; multi-platform parallel/sequential; `ci_ibmcloud_save_artifact` per arch; `CI_BUILT_IMAGES` global |
| Tag strategy | `build/lib/ci-core.sh:154` `ci_generate_tag` | `version`, `runner`, `sha`, `latest`, `version-latest`, `tag`-family strategies |
| Config | `build/lib/ci-config.sh:199` `load_config` | Dockerfile comments → YAML → ENV priority merge; `build_registries_array` at line 86 reads `CONFIG[DF_REGISTRY_0]` family |
| OCI labels | `build/lib/ci-core.sh:257` `ci_generate_oci_labels` | from `CONFIG[GIT_*]`, `VERSION`, `IMAGE_NAME` |
| SBOM | `build/lib/ci-sbom.sh` | `ci_detect_sbom_tool` (:35), `ci_generate_sbom` (:59), `ci_attach_sbom` (:170), `ci_generate_and_attach_sbom` (:226), `ci_attach_sbom_attestation` (:260) |
| Remote clone | `build/lib/ci-utils.sh:266` `load_repository` | existing `-r/--repo` flow; flavor detection runs on clone |

Hummingbird machinery in the containers repo (source of truth):

| Piece | Location | CLI |
|-------|----------|-----|
| Property aggregation | `ci/internal/aggregate_properties.py` | writes `.cache/properties.json` + `.cache/properties.mk` |
| RPM version resolution | `ci/get_rpm_versions.sh` | writes `.cache/rpm-versions.yml` |
| rpms.in.yaml generation | `ci/internal/generate_rpms_in.py` | `generate_rpms_in.py <output>` |
| Template rendering | `ci/internal/generate_jinja2.py` | `generate_jinja2.py <template> <output>` |
| Variant render context | `ImageContext` | output path `images/<group>/<distro>/<variant>/<file>`; finds base dir via `.cache/properties.json` |
| Macro set | `macros/*.yml.j2` | `is_builder_variant()`, `main_packages_arg()`, `cleanup_newroot()`, `verify_compliance()`, `final_stage()` |
| Templates | `templates/{TAGS,VERSION,oscap-tailoring}.j2` | TAGS.j2 renders the `tags:` block of `properties.yml` |
| Variant paths | `verify_compliance.yml.j2:2` | hardcodes `/run/src/{{ distro }}/{{ variant }}` |
| Chunkah archive | `final_stage.yml.j2:2` | `> /run/src/out.ociarchive`; `FROM oci-archive:out.ociarchive` |
| Variant-only steps | `cleanup_newroot.yml.j2`, `setup_newroot.yml.j2` | render-time `{% if is_builder_variant() %}` conditionals |
| Build-time workarounds | `ci/build_images.sh:597–604,617,662` | for chunkah: `--skip-unused-stages=false`, `-v <image_dir>:/run/src --security-opt=label=disable`, `pushd <image_dir>` (so `FROM oci-archive:` resolves), archive cleanup after |

## Key design decision: per-variant Containerfile, arch-neutral

The original Hummingbird generation is kept: one rendered Containerfile per
variant (no upstream macro changes, pure vendoring). Multi-arch does not need
per-arch Containerfiles — chunkah builds the rootfs for `TARGETARCH` inside
the build. Multi-arch support comes from engine-level adjustments for chunkah
images:

1. **Absolute `FROM oci-archive:` path**: `ci_build_and_push` runs the engine
   from a fixed CWD and parallel subshells make `pushd` impossible. The
   hummingbird driver rewrites the `FROM oci-archive:out.ociarchive` line in
   its generated copy to `FROM oci-archive:<abs image-dir>/out.ociarchive`
   (matches upstream semantics: the final stage is imported after the builder
   stage wrote the archive; the user's on-disk Containerfile in the containers
   repo already uses an absolute path successfully).
2. **Sequential platform builds** for chunkah (`PARALLEL_PLATFORMS=false`):
   platform builds share the `/run/src` bind mount; a single `out.ociarchive`
   is safe only when builds do not overlap. podman builds platforms
   sequentially anyway; docker buildx defaults to parallel, so the hook forces
   sequential.
3. **Chunkah engine flags** (from `build_images.sh`): `--skip-unused-stages=false`,
   `-v <context>:/run/src --security-opt=label=disable`.
4. Archive cleanup after each variant build (upstream does `rm -f`).

Variant build args/labels come from the variant's rendered output (no
render-time-to-runtime macro conversion).

## Phase 0 — Vendoring + sync tool

Files: `tools/sync-hummingbird.sh` (new), `hummingbird/` (vendored copy)

1. `tools/sync-hummingbird.sh`: copies from `--from <containers>` (default
   sibling `../containers`):
   - `images/variables.yml` → `hummingbird/variables.yml`
   - `macros/` → `hummingbird/macros/`
   - `templates/{TAGS,VERSION,oscap-tailoring}.j2`, `templates/grype-markdown.tmpl` → `hummingbird/templates/`
   - `ci/internal/{aggregate_properties,generate_jinja2,generate_rpms_in}.py` → `hummingbird/`
   - `ci/get_rpm_versions.sh` → `hummingbird/`
2. Pure copy (no patches, no macro adaptations).
3. Self-check after copy: run `hummingbird/generate_jinja2.py --help` and a
   smoke render of `templates/TAGS.j2`.
4. Commit the vendored tree; record the source commit SHA in the commit body.

Acceptance: `tools/sync-hummingbird.sh && tools/sync-hummingbird.sh` is
idempotent (second run produces no diff).

## Phase 1 — ci-hummingbird.sh (flavor pipeline)

File: `build/lib/ci-hummingbird.sh` (new)

Functions (all prefixed `ci_hummingbird_`):

- `ci_hummingbird_detect_flavor <dir>` → `hummingbird` | `dockerfile` | empty
  (Containerfile.j2 + properties.yml → hummingbird; Dockerfile → dockerfile).
- `ci_hummingbird_configure <dir>`: set `CONFIG[IMAGE_NAME]` (from
  `properties.yml` `repository` key or dir name), `CONFIG[VERSION]` (from
  rendered VERSION), `CONFIG[TAG_STRATEGY]="custom"`,
  `CONFIG[CUSTOM_TAGS]`, `CONFIG[PLATFORMS]` (env/flag override),
  `CONFIG[IMAGE_FORMAT]`, then registries: set `CONFIG[DF_REGISTRY_0]` /
  `_PREFIX` / `_PUSH` from `hummingbird/variables.yml` registry + env
  `REGISTRY`/`IMAGE_PREFIX`, then call `build_registries_array` (ci-config.sh:86).
- `ci_hummingbird_generate <dir>`: renders per variant (original upstream
  flow) into `<dir>/.hbgen/` (gitignored):
  1. `aggregate_properties.py` → `<dir>/.hbgen/.cache/properties.json`
     (requires properties + variables.yml; the generator discovers base_dir by
     walking up for `.cache/properties.json`, so the `.hbgen/` tree must hold it)
  2. `get_rpm_versions.sh` → `<dir>/.hbgen/.cache/rpm-versions.yml`
  3. `generate_rpms_in.py` per variant → variant dir
  4. `generate_jinja2.py` renders TAGS, VERSION, Containerfile, oscap-tailoring
     into the variant subdirs of `.hbgen/`
  5. For each variant Containerfile: rewrite the `FROM oci-archive:...` line
     to the absolute `.hbgen` archive path
  Git metadata: export `GIT_SHA`/`GIT_SOURCE_URL`/`GIT_BRANCH` (from
  `extract_git_info` results) for label injection.
- `ci_hummingbird_resolve_versions <dir>`: read rendered `TAGS` (tag list).
  If empty, fall back to `CONFIG[VERSION]` with `TAG_STRATEGY=version-latest`.
  Git-info tags appended per spec (SHA/branch, auto-increment semver via
  `extract_git_info`).
- `ci_hummingbird_build <dir>`: for each variant from `properties.yml`
  (`default` always; `builder` when declared or when `builder` key present):
  1. resolve tags; append `-builder` suffix to each tag for builder variants
  2. set `CONFIG[CUSTOM_TAGS]` and variant build args (VERSION, IMAGE_NAME,
     labels from the variant's rendered output)
  3. call `ci_build_and_push` with the variant Containerfile + context `<dir>`
  4. on failure: log error, stop remaining variants, return non-zero
  ubi9 keeps its current single-variant path.

Dependencies: `hummingbird/` scripts need python3 + PyYAML (generate_jinja2);
`get_rpm_versions.sh` needs podman + the hummingbird-builder image.

## Phase 2 — shared engine hooks

Files: `build/lib/ci-core.sh`, `build/lib/ci-build.sh` (small additions)

1. `ci_generate_tag` (ci-core.sh:154): add `custom` strategy —
   `echo "${CONFIG[CUSTOM_TAGS]:-latest}"`.
2. `ci_build_and_push` (ci-build.sh): add a chunkah hook driven by
   `CONFIG[CHUNKAH]=true` (set by the hummingbird configure step):
   - add engine flags `--skip-unused-stages=false`
     `-v <context>:/run/src --security-opt=label=disable` (podman/buildah only;
     matches containers `build_images.sh` workarounds)
   - force `PARALLEL_PLATFORMS=false` (shared `/run/src` bind mount; platform
     builds must not overlap)
   - after the build loop, `rm -f <context>/out.ociarchive` (archive cleanup,
     matching upstream)
   The absolute `FROM oci-archive:` path rewrite happens in the hummingbird
   generator (Phase 1), not here.

## Phase 3 — driver dispatch + post-build artifacts

Files: `build/universal-ci.sh`, `build/lib/ci-vuln.sh` (new)

1. `main_build` (universal-ci.sh:79): after image-name resolution, run
   `ci_hummingbird_detect_flavor` on the resolved source dir:
   - hummingbird: skip Dockerfile search and `load_config`; call
     `ci_hummingbird_build`; continue to the existing post-build block.
   - dockerfile: current flow unchanged.
   - unknown flavor: `log_error` with the list of files found; return 1.
2. Post-build block (universal-ci.sh:217–245): replace the commented-out SBOM
   with:
   - `ci_generate_and_attach_sbom` per `CI_BUILT_IMAGES` entry (guarded by
     `SBOM_SKIP`; missing tools → warn, continue)
   - `ci_generate_and_attach_vuln_report` per entry (new `ci-vuln.sh`):
     grype via `docker.io/anchore/grype:latest`, markdown report via vendored
     `hummingbird/templates/grype-markdown.tmpl`, JSON for attach,
     `oras attach --artifact-type application/vnd.security.vulnerability.report+json`
     (guarded by `VULN_SKIP`; missing oras → warn, continue).

## Phase 4 — example image + tests

1. `docker-builds/builders/curl/`: hummingbird definition (`Containerfile.j2`
   adapted from containers `images/curl/`, `properties.yml` with the same
   `tags:` block, `rpms.in.yaml` optional) next to the existing Dockerfile
   build; `build.sh` passes through to the driver.
2. Tests (from the spec's Testing section):
   - sync idempotency (Phase 0)
   - ubi9 regression: `builders/curl` `--skip-push`
   - hummingbird single + two-variant, multi-arch (`--platforms
     linux/amd64,linux/arm64`), remote-repo clone, SBOM/vuln attach

## Risks / open items

1. `FROM oci-archive:<abs path>`: buildah must read the absolute host path when
   the final stage is imported. The user's on-disk Containerfile in the
   containers repo already uses an absolute path and builds successfully —
   treat as verified; re-verify in Phase 4.
2. Multi-platform sequential builds: podman builds platforms sequentially by
   default; docker buildx defaults to parallel — the hook forces
   `PARALLEL_PLATFORMS=false` for chunkah images. Overlap would corrupt the
   shared `out.ociarchive`.
3. `generate_jinja2.py` base-dir discovery requires `.cache/properties.json`
   above the output file; the `.hbgen/` tree layout must satisfy this (verify
   in Phase 1).
4. TAGS/`custom` strategy interaction with `ci_generate_tag` — `custom` must
   not fall back to `latest` for empty tag lists; hummingbird driver supplies
   `latest` explicitly when appropriate.
5. cosign/oras are not installed locally; SBOM/vuln attach is tested with
   `SBOM_SKIP`/`VULN_SKIP` or in CI until the tools are available.
6. The user's on-disk Containerfile (absolute FROM) differs from the pristine
   generated file (`Containerfile.bak`) — absolute-path builds are assumed to
   be the validated variant; confirmed by a rebuild in Phase 4.

## Commit sequence

1. docker-build-scripts: `tools/sync-hummingbird.sh` + vendored `hummingbird/`
2. docker-build-scripts: `ci-core.sh` custom strategy + `ci-hummingbird.sh`
3. docker-build-scripts: `ci-build.sh` chunkah hook + driver dispatch
4. docker-build-scripts: `ci-vuln.sh` + SBOM re-enable
5. docker-builds: `builders/curl` hummingbird definition
6. docker-builds: test results / fixes
