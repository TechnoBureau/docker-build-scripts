# AGENTS.md

Operating manual for agents and engineers working in **docker-build-scripts**.
Read this entry point, then load only the relevant documents in
[`context/`](context/README.md). Context describes current code, not one-time
reviews or task-completion reports.

## 1. Repository surfaces

| Surface | Location | Responsibility |
| --- | --- | --- |
| Build engine | `build/universal-ci.sh`, `build/lib/ci-*.sh` | Dockerfile and Hummingbird flavours share config, registry, build and artifact machinery |
| Declarative RPM builder | `build/lib/hummingbird/` | One definition → Hummingbird/UBI distro × variant × platform builds |
| Image provisioning | `docker/` | Scripts copied into images for installation/hardening |
| Runtime libraries | `build/lib/hummingbird/prebuildfs/` | Entrypoint, logging and hook libraries inside built images |

`universal-ci.sh` is a source-and-call library: `source build/universal-ci.sh`,
then `main_build ...`. Running the file directly does not invoke a build.

## 2. Lifecycle hooks

### 2.1 `on_session_start`

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

### 2.2 `before_edit` — find the owner

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
| Artifacts/signing | `ci-artifacts.sh` |

Python filenames above are under `build/lib/hummingbird/`; CI libraries are
under `build/lib/`.

Rules: bash orchestrates, Python resolves structured data, Jinja renders resolved
values. Preserve public function names. Keep useful `WHY:` comments; update them
when behavior changes. Do not commit credentials, `.hbgen/`, `.venv/` or image output.

### 2.3 `after_edit` — fast to slow

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

### 2.4 `before_commit`

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

### 2.5 `on_failure`

1. Start with the real error, not a guess about the failing stage.
2. Reproduce with the smallest stage/test possible.
3. Inspect `.hbgen/images/<image>/<distro>/<variant>/Containerfile`, its RPM
   input, and `hbgen.py config` output rather than only the source template.
4. Add a test before fixing the behavior; rerun the whole suite afterward.

## 3. Required invariants

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

16. **RPM installroot commands run with temporary proc/dev/runtime mounts.**
    Use `hb-rootfs exec`, not bare installroot transactions or disabled scriptlets.
    Cleanup preserves command failures and leaves no runtime mounts in the image.
    Permissions are independent of chunkah; Docker elevation requires explicit
    opt-in. *(RootfsTransactionTests; RootfsMountNamespaceTests; EngineTests)*

Python test classes are in `tests/hummingbird/test_*.py` and
`tests/test_build_engine.py`. A–F identifiers belong to the shell suite.

## 4. Operational entry points

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
