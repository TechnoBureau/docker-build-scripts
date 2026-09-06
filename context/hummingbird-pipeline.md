# Hummingbird pipeline

Current build contract for the declarative RPM builder. The **flavour** is named
`hummingbird`; its supported **distros** are `hummingbird`, `ubi9` and `ubi10`.
UBI is not a separate build flavour.

## 1. Definitions and defaults

A builder contains `properties.yml` and `Containerfile.j2`, plus shared and/or
per-image `variables.yml`. One definition becomes distro × variant rows. Each
row can produce one architecture or a manifest containing both supported arches.

| Concept | Meaning |
| --- | --- |
| distro | Package repository/release policy, independent of architecture |
| variant | `default`, `builder`, `fips`, `fips-builder`, or an image-defined name |
| modifier | A name suffix parsed by `hb_variant`, e.g. `builder` or `fips` |
| newroot / newrootfs | The target filesystem at `${NEWROOT}` (default `/new-root-fs`) inside the builder stage |
| base image | An explicitly selected filesystem seed; **not** the tooling image |
| tooling image | `quay.io/hummingbird-ci/hummingbird-builder:latest`, which supplies DNF and build tools |

The **`default` variant is FIPS-enabled**, as are other variants unless explicitly
opted out. Its name and unsuffixed tags are preserved. Omitting `default_variants`
and `variants` selects `[default]`; it does not omit security packages.

Name decomposition and effective security policy are separate:

- `hb_variant.decompose_variant` parses suffixes and the base name.
- `hb_rootfs.resolve_rootfs` resolves effective `is_fips`, packages and crypto policy.
- Builder modifiers publish `<image>-builder`; other variants share `<image>`
  and use variant-suffixed tags. The `name=` label uses that same repository rule.
- Explicit `additional_variants[].distros` restrictions still apply. Do not add a
  Hummingbird-only restriction to `fips` if it should also build for UBI.

## 2. Stages and work tree

```
prepare → aggregate → rpms → versions → render → configure/build each matrix row
```

| Stage | Command | Output / requirement |
| --- | --- | --- |
| prepare | `hbgen.py prepare --image-dir D --builders-dir B` | Recreates `D/.hbgen`, merges variables, copies context and builder helpers |
| aggregate | `aggregate_properties.py` with cwd `.hbgen` | `.cache/properties.json`: variants and distro restrictions |
| rpms | `hbgen.py rpms --hbgen H --image N` | Per-row `rpms/rpms.in.yaml`, with the selected RPM architectures |
| versions | `ci/get_rpm_versions.sh` with cwd `.hbgen` | Queries packages per distro **and target architecture**; requires an engine/network |
| render | `hbgen.py render --hbgen H --image N` | `Containerfile`, `VERSION`, `TAGS`, optional tailoring file |
| configure | `hbgen.py config --hbgen H --image N --distro D --variant V` | TAB-separated values for the bash `CONFIG` array |
| build | `ci_build_and_push Containerfile context` | Shared Docker/Podman engine, one or multiple architectures |

Stages are cumulative: `matrix` needs prepare + aggregate; render also needs
rpms. For offline inspection render may omit versions; unresolved tags are
removed by config with a warning. See the runnable sequence in
[troubleshooting](troubleshooting.md).

```
<builder>/.hbgen/
├── ci/get_rpm_versions.sh, ci/internal/  links to vendored tools
├── macros/, templates/, yum-repos/      generator inputs
├── images/variables.yml                 merged defaults + selected platforms
├── images/<image>/                     actual engine build context
│   ├── properties.yml, Containerfile.j2
│   ├── hb-scripts/rootfs.sh             builder-only operations
│   ├── yum-repos/, oscap/               only selected datastreams are copied
│   ├── rootfs/, src/, prebuildfs/       optional template inputs
│   └── <distro>/<variant>/             generated Containerfile, tags, RPM inputs
└── .cache/                             properties and version caches
```

`.hbgen/` is disposable and gitignored. Context `rootfs/` files are available to
custom templates but are **not automatically copied into newroot**.

## 3. Module ownership

| Owner | Behaviour |
| --- | --- |
| `ci-hummingbird.sh` | Paths, orchestration, per-row config reset, engine hand-off |
| `hbgen.py` | Work tree, selection/matrix, render stages, per-row config |
| `hb_config.py` | YAML/merges, repo filenames, distro release versions |
| `hb_variant.py` | Variant name decomposition and published image name |
| `hb_rootfs.py` | Base-image selection, FIPS package baseline, crypto policy, assembly mode |
| `hb_platforms.py` | Hummingbird/UBI target selection and OCI ↔ RPM architecture names |
| `hb_packages.py` | Runtime/build package groups, including architecture constraints |
| `hb_versions.py` | Version-query plan, result validation and request-scoped cache |
| `get_rpm_versions.sh` | Executes that query plan with the container engine |
| `generate_jinja2.py` | Template context, labels, tags, OSCAP tailoring |
| `rootfs.sh` | Image-side reset, base validation, crypto-policy setup and cleanup |
| `ci-platforms.sh` | Shared Docker/Podman platform execution and manifests |

Bash orchestrates; Python resolves structured data. Macros render already-resolved
values rather than recomputing package sets or security policy.

## 4. Configuration

Shared `builders/variables.yml` + per-image `variables.yml` use **list replace**
semantics. Image properties overlay the resulting defaults; package groups and
OSCAP lists accumulate through `hb_config.effective_section`.

### Core keys

| Key | Contract |
| --- | --- |
| `default_distros`, `distros` | Default and per-image distro selection; `HB_DISTROS` overrides |
| `default_variants`, `variants`, `additional_variants` | Default/image variants and optional distro restrictions |
| `fips` | Defaults to `true`; boolean or a scoped mapping. FIPS-named variants cannot disable it |
| `base_image` | Absent/`scratch` → empty start. Otherwise a reference or scoped mapping |
| `platforms` | String/list of `linux/amd64`, `linux/arm64`; omission → runner native |
| `chunkah` | Defaults to `false`. Explicit `true` selects legacy Podman archive assembly |
| `rpm_packages`, `default_rpm_packages` | Image/shared groups (`all`, distro, variant, distro/variant, modifiers, base, `build-deps`) |
| `default_variant_repos`, `additional_repos` | Repo filenames used identically for queries and installation; built-in distro repo defaults exist |
| `oscap` | Scan enablement/profiles/rule exclusions/datastreams; does **not** switch FIPS off |
| `registry`, `registries`, `skip_push` | Push defaults; shared engine/HB environment overrides apply |
| `default_user`, `user` | Default UID and variant/user mapping |

`base_image` and `fips` mappings resolve `distro/variant` > distro > variant >
`default`. Image-level settings override shared settings. Required properties
for rendering labels/tags remain `description`, `summary`, `url`, `stream`, `tags`.

### FIPS baseline

Every FIPS-enabled rootfs includes:

- `crypto-policies`, `crypto-policies-scripts`
- `openssl`, `openssl-libs`
- `openssl-fips-provider`, `openssl-fips-provider-so`
- Hummingbird only: `openssl-config-fips`

Additional `fips` and `<distro>/fips` package groups extend that baseline, including
for `default` and composite builder variants. `fips: false` is an explicit opt-out
for non-FIPS-named variants. Contradictory crypto policies are rejected.

The rootfs helper installs the selected distro's policy definitions without
executing foreign rootfs binaries; it fails if FIPS definitions/provider are
missing. Scanning and FIPS policy selection are independent. **FIPS packages and
policy are not a certification claim**: validated module versions, application
crypto usage, and a suitably configured FIPS host/runtime still need verification.

### Base-image example

```yaml
# properties.yml (in addition to description/summary/url/stream/tags)
distros: [hummingbird, ubi9, ubi10]
platforms: [linux/amd64, linux/arm64]
fips: true
base_image:
  ubi9: registry.access.redhat.com/ubi9/ubi-minimal:latest
  ubi10: registry.access.redhat.com/ubi10/ubi-minimal:latest
  # No hummingbird entry: that row starts empty.
rpm_packages:
  all: [curl, ca-certificates]
  build-deps:
    - name: gcc
      arches: {only: aarch64}
```

For repeatable releases, pin base/tooling references and package repositories to
approved versions. A multi-arch base digest must identify a multi-arch index, or
build just the architecture that digest supplies. The seed must match the target
RPM distro/release; existing `os-release` metadata is checked before updating it.
Only filesystem content is inherited: define `USER`, `ENV`, `ENTRYPOINT`, etc.
in the template, not by relying on base-image metadata.

## 5. Rootfs lifecycle and macros

```text
blank root → optional base COPY → distro check → filesystem bootstrap
           → upgrade inherited packages (base only)
           → install selected runtime + FIPS + arch packages
           → policy + optional scan → cleanup → final image
```

| Macro | Emits |
| --- | --- |
| `setup_newroot()` | Optional base stage, tooling stage, isolated distro repos, **reset**, seed COPY, build deps, filesystem bootstrap |
| `install_newroot()` | Seed upgrade if present, runtime/architecture packages, crypto policy, optional compliance scan |
| `cleanup_newroot()` | Optional runtime removals, licence/locale policy, actual database cleanup, FIPS presence recheck |
| `final_stage()` | Default `FROM scratch` + `COPY --from=builder ${NEWROOT}/ /`, then labels/user environment |
| `main_packages_arg()` / `build_packages_arg()` | Deterministically resolved package ARGs |
| `set_user()` | Selected final `USER` |

Build dependencies—including architecture-specific ones—stay out of the runtime
rootfs. DNF metadata caches are separate from newroot and scoped by distro/arch.
The portable final stage creates an explicit dependency on the builder; it never
reads a shared host-side OCI archive.

With `chunkah: true`, the engine requires Podman, serializes architectures and
disables layer-cache replay because a bind-mount archive is not a cached layer
output. Docker rejects that mode with an actionable error.

## 6. Platform and version contract

`PLATFORMS` > `properties.yml platforms` > merged `variables.yml platforms` >
runner native. OCI/RPM aliases (`amd64`/`x86_64`, `arm64`/`aarch64`) are accepted;
unknown or empty selections fail rather than silently building native.

`rpms.in.yaml` and queries use the same selected architectures. Repoquery runs
native with `--forcearch`/`--arch` selecting target packages, so it needs no QEMU.
Image builds do need native workers or emulation for each target. `INSTALL_BINFMT`
(`auto|false|force`) applies to a single foreign target too.

The version cache contains `distros`, `architectures`, and a request fingerprint.
TTL reuse requires matching packages, repositories, builder reference and arches.
Missing packages fail by distro/arch; conflicting versions across a requested
manifest fail rather than choosing whichever result happened to be last. Older
flat/per-distro caches remain readable, but cannot attest architecture coverage.

Docker multi-arch uses one buildx build/index push. Podman builds separate image
IDs and assembles/pushes one manifest after all workers succeed. Without push,
Docker retains an OCI archive (`BUILD_OUTPUT_DIR`, default `.ci-output/`);
Podman retains a local manifest (`CI_LOCAL_MANIFEST`).

## 7. Integration contracts when re-vendoring

Keep the shared resolver imports in all three generators, the normalized
`ImageContext` fields (`is_fips`, `base_image`, `crypto_policy`, `chunkah_enabled`,
`distro_repos`, `releasever`, both arch-specific package maps), and the image-side
`rootfs.sh` context copy. `ci/internal` exposes the version tooling from a prepared
tree. Re-run [all offline tests](../tests/README.md) before using new upstream code.
