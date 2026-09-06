# Hummingbird pipeline

The hummingbird flavour builds **reproducible, compliance-scanned RPM images**
from a declarative definition, instead of hand-writing a Dockerfile.

One builder directory → a matrix of images:

```
builders/curl/                       .hbgen/images/curl/
├── properties.yml      what         ├── hummingbird/default/   → curl:8.21.0
├── Containerfile.j2    how          ├── hummingbird/builder/   → curl-builder:8.21.0-builder
├── variables.yml       overrides    ├── hummingbird/fips/      → curl:8.21.0-fips
├── rootfs/  src/       context      ├── ubi9/default/          → curl:8.10.1
└── .gitmodules         submodules   └── ubi9/builder/          → curl-builder:8.10.1-builder
```

## 1. Concepts

| Term | Meaning | Declared in |
| --- | --- | --- |
| **builder** | A directory with `properties.yml` + `Containerfile.j2` | — (detected) |
| **distro** | Package universe the newroot is installed from: `hummingbird`, `ubi9`, `ubi10` | `default_distros` / `distros:` |
| **variant** | Build flavour of one definition: `default`, `builder`, `fips`, composites like `fips-builder`, `fpm-fips-builder` | `default_variants`, `variants:`, `additional_variants:` |
| **modifier** | Suffix of a variant name that changes behaviour: `builder`, `fips` | `hb_variant.MODIFIER_SUFFIXES` |
| **newroot** | The image filesystem assembled by `dnf-installroot` inside a builder stage | `macros/setup_newroot.yml.j2` |
| **chunkah** | Tool that flattens the newroot into an OCI archive (`out.ociarchive`), consumed by `FROM oci-archive:` | `macros/final_stage.yml.j2` |
| **work tree** | `.hbgen/` — a reconstruction of the upstream hummingbird repo layout | `hbgen.py prepare` |

Variant names decompose (see `hb_variant.decompose_variant`):

```
default          → base=default          builder=false fips=false
builder          → base=default          builder=true
fips             → base=default          fips=true
fpm              → base=fpm
fpm-fips-builder → base=fpm              builder=true  fips=true   (order-independent)
```

Only `builder` changes the published repository name (`curl` → `curl-builder`).
Every other variant shares the repository and is distinguished by its **tag**
(`TAGS.j2` appends `-<variant>`), which keeps `name=` labels truthful.

## 2. Pipeline stages

`ci_hummingbird_generate` runs five stages; each is a separate command you can
re-run by hand while debugging.

```
 builder dir ──► 1 prepare ──► 2 aggregate ──► 3 rpms ──► 4 versions ──► 5 render ──► build loop
                   hbgen.py      aggregate_      hbgen.py    get_rpm_       hbgen.py     ci_build_
                                 properties.py               versions.sh                 and_push
                   needs:        needs:          needs:      needs:         needs:       needs:
                   pyyaml        pyyaml          pyyaml      engine+network jinja2       engine
```

| # | Command | Input | Output | Why it exists |
| --- | --- | --- | --- | --- |
| 1 | `hbgen.py prepare --image-dir D --builders-dir B` | builder dir, `variables.yml` | `.hbgen/` tree, merged `images/variables.yml`, context files, selected SCAP datastreams | Reconstructs the upstream layout so vendored generators run unchanged |
| 2 | `aggregate_properties.py` (cwd = `.hbgen`) | `images/*/properties.yml` | `.cache/properties.json`, `.cache/properties.mk` | Computes the authoritative variant list (`variants` + `additional_variants`) and the distro restrictions |
| 3 | `hbgen.py rpms --hbgen H --image N` | properties cache | `<distro>/<variant>/rpms/rpms.in.yaml` per row | Input for lockfiles and version resolution |
| 4 | `ci/get_rpm_versions.sh` (cwd = `.hbgen`) | `rpms.in.yaml`, distro repos | `.cache/rpm-versions.yml` (per distro) | Real package versions → real version tags |
| 5 | `hbgen.py render --hbgen H --image N` | everything above | `VERSION`, `TAGS`, `oscap-tailoring.xml`, `Containerfile` per row | The artifacts the engine builds from |

Then the driver loops the matrix:

```
ci_hummingbird_matrix   → "distro<TAB>variant<TAB>image_name" rows
ci_hummingbird_configure → CONFIG[] for one row (via `hbgen.py config`)
ci_build_and_push        → shared engine
ci_hummingbird_cleanup_archives → once, after the last row
```

## 3. Module responsibilities

```
ci-hummingbird.sh   bash orchestration only: paths, logging, engine, loop
   │                (no YAML parsing, no Jinja, no matrix logic)
   ▼
hbgen.py            pipeline CLI — one subcommand per stage
   ├── hb_config.py     YAML loading, deep merge, required-key validation
   ├── hb_variant.py    variant decomposition, image naming
   ├── hb_packages.py   package-set resolution (main/build/arch-specific)
   └── generate_jinja2.py  ImageContext: template variables, labels, tags
          └── macros/*.yml.j2, templates/*.j2
aggregate_properties.py   properties → cache (vendored generator)
generate_rpms_in.py       cache → rpms.in.yaml (vendored generator)
get_rpm_versions.sh       repos → .cache/rpm-versions.yml (needs an engine)
```

Rule: **bash orchestrates, Python decides.** Nothing in bash parses YAML; every
`hbgen.py` subcommand can be run standalone.

## 4. Configuration

### 4.1 Files

```
builders/variables.yml          shared defaults for every builder   (base)
builders/<image>/variables.yml  per-image overrides                (overlay)
builders/<image>/properties.yml image definition
```

`base` + `overlay` are deep-merged with **list policy = replace** (an override
`default_distros: [ubi9]` selects ubi9 only). The merged result is written to
`.hbgen/images/variables.yml` and is the single configuration source for every
later stage. At least one of the two files must exist.

Properties are merged on top of variables for the template context with
**list policy = extend** (a per-image `oscap.exclude_rules` adds to the global
ones). Both merges are the same function, `hb_config.deep_merge`, with an
explicit policy argument.

### 4.2 `variables.yml` keys

| Key | Used for |
| --- | --- |
| `default_distros` | distros when `properties.yml` has no `distros:` |
| `default_variants` | variants when `properties.yml` has no `variants:` |
| `registry`, `registries` | push targets (`registries` may be strings or `{name, prefix, push}` maps) |
| `default_user` | uid/name behind `container_user: default` |
| `labels` | `maintainer`, `vendor`, `source_url` |
| `variant_descriptions` | `io.hummingbird-project.variant.description` (keyed by **base** name) |
| `default_rpm_packages` | package groups shared by all builders: `all`, `builder`, `fips`, `<variant>` |
| `default_variant_repos` | distro → repo file names from `yum-repos/` |
| `oscap` | `enabled`, `profiles.{cis,stig}`, `exclude_rules[]`, `datastreams`, `crypto_policy`, `crypto_policy_variants` |
| `platforms` | multi-arch (`linux/amd64,linux/arm64`) |
| `skip_push` | build without pushing |

### 4.3 `properties.yml` keys

Required: `description`, `summary`, `url`, `stream`, `tags`.
Common: `main_package`, `version_package`, `rpm_packages`, `variants`,
`additional_variants`, `distros`, `user`, `registries`, `repository`,
`support_level`, `tag_suffix_aliases`, `additional_repos`, `build_from_source`,
`variant_descriptions`, `oscap`, `remove_rpms_from_newroot`.

`tags` is itself a Jinja list, rendered before use:

```yaml
tags:
  - value: "{{ package_version(package_name_for_version) }}"
    label: org.opencontainers.image.version
  - value: "{{ package_major_minor_version(package_name_for_version) }}"
    label: io.hummingbird-project.major-minor-version
  - value: latest
```

### 4.4 Environment knobs

| Variable | Effect |
| --- | --- |
| `HB_DISTROS` | Override distro selection (`"ubi9"`, `"hummingbird ubi9"`) |
| `HB_VARIANTS` | Select variants; validated against the aggregated list |
| `HB_VERSION` | Override the resolved package version |
| `HB_TAGS` | Override the generated tag list (space separated) |
| `HB_REGISTRIES` | Comma-separated registries (with `IMAGE_PREFIX`) |
| `HB_SKIP_RPM_VERSIONS` | `true` skips stage 4 (no engine needed) |
| `HB_RPM_VERSIONS_TTL` | Reuse `.cache/rpm-versions.yml` younger than N seconds |
| `HB_PYTHON` | Interpreter for all generators (venv/pinned python) |
| `HUMMINGBIRD_DIR` | Vendored machinery location (default `build/lib/hummingbird`) |
| `SKIP_PUSH`, `PLATFORMS`, `REGISTRY`, `IMAGE_PREFIX`, `SOURCE_DATE_EPOCH`, `DEBUG` | Shared engine overrides |

Precedence for every build value is implemented once, in `hbgen.py:cmd_config`
— its docstring is the reference table.

## 5. Macros and templates

`macros/*.yml.j2` are concatenated in filename order and prepended to every
template, so any macro can call any other. Rendered with
`jinja2.StrictUndefined`: an unknown variable is a hard error, never an empty
string.

| Macro | Emits |
| --- | --- |
| `setup_newroot()` | builder stage `FROM`, `ARG NEWROOT/DNF_CACHE/DNF_FLAGS`, distro repo `COPY`, package `ARG`s, `filesystem` bootstrap |
| `main_packages_arg()` / `build_packages_arg()` | `ARG MAIN_PACKAGES`, `ARG ARCH_PACKAGES_<arch>`, `ARG BUILD_PACKAGES` |
| `install_newroot()` | `dnf-installroot` of `${MAIN_PACKAGES}`, arch-specific `case "${TARGETARCH}"`, crypto-policy pinning, `verify_compliance()` |
| `cleanup_newroot()` | licence/locale removal (**non-builder only**), sqlite journal-off, cache/machine-id purge |
| `verify_compliance()` | `verify-compliance` with the right datastream, profiles, tailoring file |
| `final_stage()` | `chunkah build > /run/src/out.ociarchive`, `FROM oci-archive:`, labels, default-user env |
| `set_user()` | `USER` |
| `is_builder_variant()` | `"true"`/`"false"` string (kept for existing templates; prefer `is_builder`) |
| `package_version()`, `package_major_version()`, `package_major_minor_version()`, `git_submodule_hash()` | version strings from `rpm_versions` or submodule labels |
| `image_metadata_labels()`, `inject_source_info_labels()` | `LABEL` lines |

Template variables available to `Containerfile.j2` (built by
`generate_jinja2.ImageContext`): everything in the merged variables and
properties, plus `variant`, `variant_base`, `is_builder`, `is_fips`,
`image_name`, `image_repo_name`, `distro`, `container_user`, `package_name_for_version`,
`main_packages`, `build_packages`, `arch_specific_packages`, `rpm_versions`,
`gitmodules`, `tags`, `tag_values`, `registries`, `canonical_name`, `cpe`,
`inject_labels`, `oscap` (always defined, with `enabled`, `active_profiles`,
`profile_exclude_rules`, `has_tailoring`, `datastreams`, `crypto_policy`,
`crypto_policy_variants`).

## 6. Invariants (do not break)

1. The matrix honours `additional_variants[].distros` restrictions.
2. Package versions are resolved **per distro**; `.cache/rpm-versions.yml` is
   nested under `distros:`.
3. `is_builder` / `is_fips` / variant base come from `hb_variant` only.
4. `rpms.in.yaml` and `ARG MAIN_PACKAGES` are produced by the same resolver.
5. The `name=` label equals `registry/<published repository>`.
6. `oscap` is always defined in the template context.
7. `out.ociarchive` lives until the last matrix row is built.
8. Only the SCAP datastreams of the selected distros enter the build context.
9. The build context passed to the engine is `.hbgen/images/<image>` — the
   macros reference context-relative paths (`yum-repos/…`, `oscap/…`) and
   `/run/src/…` (the bind mount of that same directory).

## 7. Deltas from the upstream vendored generators

`aggregate_properties.py`, `generate_rpms_in.py` and `generate_jinja2.py` are
vendored from the upstream hummingbird containers repository and carry local
fixes. Keep this list current when re-vendoring:

| File | Local delta |
| --- | --- |
| `aggregate_properties.py` | exports `variant_distros` + `distros` into the cache; actionable errors for missing/empty `variables.yml` |
| `generate_rpms_in.py` | package set delegated to `hb_packages.resolve_package_set` |
| `generate_jinja2.py` | `oscap` always defined; required-property validation; gitmodules resolved from the image dir and via `git submodule status`; per-distro `rpm-versions.yml`; `canonical_name` via `hb_variant`; empty renders skipped; variant/package sets from the shared modules |
| `get_rpm_versions.sh` | per-distro cache format; single scan of `rpms.in.yaml`; one `repoquery` per distro; `HB_PYTHON`/`HB_RPM_VERSIONS_TTL` support |
