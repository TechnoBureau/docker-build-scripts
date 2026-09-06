# Extension guide

Recipes for the changes that are actually requested, in the order they are usually
needed. Each recipe lists the files to touch, the invariant it must respect, and
the test to add.

Start from `AGENTS.md` §2.2 (ownership map) — if a recipe seems to require
editing two owners for one behaviour, the design has drifted; fix the owner
instead.

---

## 1. Add a new distro (e.g. `ubi11`)

```
1. build/lib/hummingbird/yum-repos/ubi11.repo        new repo definition
2. builders/variables.yml                            default_variant_repos.ubi11: [ubi11.repo]
3. builders/variables.yml (or per-image properties)   oscap.datastreams.ubi11: ssg-rhel11-ds.xml
4. build/lib/hummingbird/oscap/ssg-rhel11-ds.xml      vendored datastream (only if scanning)
```

Also register the distro's default repo/release in `hb_config.py` and its FIPS
package baseline in `hb_rootfs.FIPS_PACKAGES`. FIPS is enabled by default; an
unknown distro must not inherit an unverified package set. The package and rootfs
macros then use the shared policy rather than adding another distro-specific
branch. `get_rpm_versions.sh` uses the same repo/release plan, per target arch.
Verify without an engine:

```bash
HB=<repo>/build/lib/hummingbird
python3 $HB/hbgen.py prepare --image-dir <builder> --builders-dir <builders> --distros ubi11
# stage 2 is a vendored generator and must run with cwd = the work tree;
# `matrix` fails without it
( cd <builder>/.hbgen && python3 $HB/aggregate_properties.py )
python3 $HB/hbgen.py matrix  --hbgen <builder>/.hbgen --image <name> --distros ubi11
```

**Test:** add the distro to a fixture builder and assert the repo `COPY`, the
`--disablerepo` flag and the datastream selection (pattern: D13–D15, A8).

---

## 2. Add a variant modifier (e.g. `debug`)

One file owns variant semantics:

```python
# build/lib/hummingbird/hb_variant.py
MODIFIER_SUFFIXES = frozenset({"builder", "fips", "debug"})

@dataclass(frozen=True)
class VariantInfo:
    ...
    is_debug: bool            # add the flag

# decompose_variant(): found → is_debug="debug" in found
```

Then decide, explicitly:

| Question | Where |
| --- | --- |
| Does it change the published repository name? | `IMAGE_NAME_SUFFIXES` in `hb_variant.py` |
| Does it add packages? | `hb_packages.package_keys` already appends every modifier, so a `default_rpm_packages.debug` / `rpm_packages.debug` group is picked up automatically |
| Does it change the Containerfile? | read `is_debug` in a macro (add it to `ImageContext._build_variables` next to `is_builder`/`is_fips`) |
| Does it need a description? | `variant_descriptions` is keyed by **base**, so `debug` alone resolves to base `default` |

Declare the variant in a builder:

```yaml
additional_variants:
  - name: debug
    distros: [hummingbird]      # optional restriction
```

**Invariant:** never test `variant == "debug"` in bash or Jinja — that is exactly
how composite variants (`fips-debug-builder`) broke before. Use the decomposed
flags.

**Test:** mirror the `fips-builder` assertions (B5, D2–D6).

---

## 3. Add a package group

`hb_packages.package_keys` defines the lookup order; adding a *group* usually
needs no code at all:

```yaml
# properties.yml (image) or variables.yml (shared)
rpm_packages:            # default_rpm_packages: …
  all:        [curl]                  # every variant
  hummingbird: [hummingbird-release]  # one distro
  builder:    [curl-devel]            # one modifier
  ubi9/fips:  [openssl-fips-provider] # distro+FIPS modifier (already in baseline)
  build-deps: [cmake]                 # builder stage only, not the newroot
```

Arch-constrained packages:

```yaml
rpm_packages:
  all:
    - name: intel-ipsec-mb
      arches: {only: x86_64}
    - name: some-tool
      arches: {not: [aarch64]}
```

They become `ARG ARCH_PACKAGES_<arch>` plus a `case "${TARGETARCH}"` install step
in `install_newroot.yml.j2`. `build-deps` entries instead use the builder-stage
architecture map; they must never be installed into newroot. OCI arch aliases
are accepted and `arches.only`/`arches.not` are applied together.

**Invariant:** the same resolver feeds `rpms.in.yaml` and `ARG MAIN_PACKAGES` —
do not add a key in one place only.

**Test:** assert both artifacts contain the package (pattern: D2/D3 + the
`rpms.in.yaml` content).

---

## 4. Add a macro or change generated image content

```
build/lib/hummingbird/macros/<name>.yml.j2      macro (auto-loaded, filename order)
build/lib/hummingbird/templates/<NAME>.j2       whole-file render (add to hbgen.VARIANT_TEMPLATES)
```

Rules (see `conventions.md` §4):

- Read only variables that `ImageContext` guarantees. If you need a new one, add
  it in `_build_variables` — do **not** use `| default(...)` to hide an undefined
  name; `StrictUndefined` is there to catch exactly that.
- Emit valid Containerfile syntax; verify by reading the rendered file, not the
  template.
- Keep the explanatory comment inside the macro.

After prepare → aggregate → rpms (see troubleshooting §1), render one row:

```bash
python3 build/lib/hummingbird/hbgen.py render --hbgen <builder>/.hbgen --image <name> \
        --distros hummingbird --variants default
cat <builder>/.hbgen/images/<name>/hummingbird/default/Containerfile
```

**Test:** assert on the rendered Containerfile (that is what the D group does).

---

## 5. Add a build-configuration knob

Engine-facing values belong to `hbgen.py:cmd_config`. Rootfs/FIPS/base-image
policy belongs to `hb_rootfs.py`, and target selection to `hb_platforms.py`.
Do not add a second resolver in the bash driver.

```python
# 1. resolve it (env override > rendered artifact > variables.yml > default)
my_knob = _resolve_my_knob(variables)

# 2. emit it
emitted += [("HBGEN_MY_KNOB", str(my_knob))]
```

```bash
# 3. map it onto CONFIG in ci_hummingbird_configure
[[ -n "${hb[HBGEN_MY_KNOB]}" ]] && CONFIG[MY_KNOB]="${hb[HBGEN_MY_KNOB]}"
```

```
# 4. document it: AGENTS.md §4, context/hummingbird-pipeline.md §4.4
# 5. if the engine must act on it: ci-build.sh reads CONFIG[MY_KNOB]
```

**Do not** add a `python3 - <<PY` heredoc in bash to read a YAML key — that is
the duplication this design removed.

**Test:** one assertion per precedence level (pattern: F20–F25).

---

## 6. Add a registry / change push behaviour

Registries come from `HB_REGISTRIES` (env) → `REGISTRY` (env) →
`variables.yml registries:` → `variables.yml registry:`, resolved in
`hbgen._resolve_registries`, mapped to `CONFIG[DF_REGISTRY_<i>]*` and turned into
the engine's `REGISTRIES` array by `build_registries_array`.

```yaml
registries:
  - name: us.icr.io
    prefix: my-namespace
    push: true
  - ghcr.io/technobureau        # string form, push defaults to true
```

Per-registry credentials are the engine's business (`ci-registry.sh`), not the
flavour's. To add a credential source, extend `ci-registry.sh` only.

**Invariant:** clear stale `DF_REGISTRY_*` keys before filling them
(`ci_hummingbird_reset_config`) — `build_registries_array` stops at the first gap.

---

## 7. Add a compliance profile or tailoring rule

```yaml
oscap:
  enabled: true
  profiles:
    stig: true                       # or {variants: ["*builder*"]} for globs
    cis:
      variants: ["default", "fips"]
  exclude_rules:
    - id: xccdf_org.ssgproject.content_rule_x
      reason: not applicable to a single-purpose container image
      profiles: [stig]               # optional; omit = every active profile
      variants: ["*"]                # optional glob filter
  crypto_policy: FIPS                # or per variant:
  crypto_policy_variants: {builder: FIPS}
  datastreams: {ubi9: ssg-rhel9-ds.xml}
```

A new profile name must be added to `OSCAP_PROFILES` in **both**
`generate_jinja2.py` and `hbgen.py` (the constant is duplicated deliberately:
one is the renderer's activation list, the other is documentation for the
driver) — and `verify-compliance` in the builder image must accept `--<profile>`.

Tailoring XML is generated when a rule survives filtering **or** an active
STIG scan needs its resolved crypto policy pinned. With no active scan, no file
is emitted. Changing the crypto policy does not implicitly opt a variant out
of FIPS; contradictions are rejected by `hb_rootfs.resolve_rootfs`.

**Test:** pattern D16–D18 and E4.

---

## 8. Add a new build flavour (peer of hummingbird)

```
build/lib/ci-<flavour>.sh
    ci_<flavour>_detect_flavor <dir>      → prints the flavour name
    ci_<flavour>_find_image [name]        → resolves the definition directory
    ci_<flavour>_build <dir>              → fills CONFIG, calls ci_build_and_push,
                                            accumulates <FLAVOUR>_BUILT_IMAGES
build/universal-ci.sh                     source it, add a branch in main_build
context/architecture.md                   update the module map
AGENTS.md §2.2                            add the ownership rows
tests/<flavour>/                          offline suite (copy the hummingbird shape)
```

Contract with the engine — the flavour must:

1. Express everything through `CONFIG` (see `architecture.md` §3); never call the
   container engine directly.
2. Reset the `CONFIG` keys it owns before each build.
3. Accumulate built images across builds (`ci_build_and_push` resets
   `CI_BUILT_IMAGES` every call).
4. Return non-zero with `log_error`; never `exit`, never `${1:?}`.
5. Keep its own parsing out of bash — give it a Python CLI like `hbgen.py`.

---

## 9. Re-vendor an upstream generator

`aggregate_properties.py`, `generate_rpms_in.py` and `generate_jinja2.py` come
from the upstream hummingbird containers repository and carry local fixes.

1. Diff against upstream and read
   `context/hummingbird-pipeline.md` §7 (the delta table) first.
2. Re-apply each delta, or upstream the fix.
3. Run `./tests/hummingbird/run-tests.sh` — the B/C/D/E groups exist precisely to
   catch a re-vendor that silently drops a local fix.
4. Update the delta table in the same commit.

---

## 10. Checklist for any extension

- [ ] Behaviour implemented in its single owner (`AGENTS.md` §2.2)
- [ ] No YAML/JSON parsing added to bash; no engine calls added to Python
- [ ] `WHY:` comment wherever the reason is not obvious from the code
- [ ] Deterministic output (sorted/deduplicated) for anything generated
- [ ] Offline assertion added to `tests/hummingbird/run-tests.sh`
- [ ] Docs updated: `context/hummingbird-pipeline.md`, `AGENTS.md` §4 knob table,
      `README.md` if user-visible
- [ ] Backwards compatible, or the change is called out in the commit message
      and the release notes


## 11. Seed a rootfs from a base image

Use `base_image` in properties.yml (literal reference or distro/variant mapping).
No template-specific base-copy logic is necessary when the template calls
`setup_newroot()` and `install_newroot()`.

```yaml
base_image:
  ubi9: registry.access.redhat.com/ubi9/ubi-minimal:latest
platforms: [linux/amd64, linux/arm64]
rpm_packages:
  all: [curl, ca-certificates]
```

The rootfs is reset first, seeded once, checked against the selected distro, then
upgraded and extended. Use a base that supplies every selected platform and pin
its digest for controlled releases. Image metadata is not inherited by a filesystem
COPY; declare final environment/user/entrypoint in the template.

**Tests:** extend `BuildContractTests` and `RootfsHelperTests`; cover both no-base
and base-seeded recipes. Never make newroot a cache mount or copy the tooling
image into it. Prefer portable final-stage COPY; chunkah is an explicit Podman-only
mode with different cache/parallelism requirements.
