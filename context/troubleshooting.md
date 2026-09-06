# Troubleshooting

## 1. Reproduce the generator pipeline without an engine

From the repository root, with `HB_PYTHON` pointing to a Python containing
PyYAML/Jinja2 (use an absolute venv path):

```bash
REPO="$PWD"
HB="$REPO/build/lib/hummingbird"
PY="${HB_PYTHON:-python3}"
WORK="$(mktemp -d)"
cp -R "$REPO/tests/hummingbird/fixtures/no-oscap/builders" "$WORK/builders"
BUILDER="$WORK/builders/hello"
TREE="$BUILDER/.hbgen"

"$PY" "$HB/hbgen.py" prepare --image-dir "$BUILDER" --builders-dir "$WORK/builders"
( cd "$TREE" && "$PY" "$HB/aggregate_properties.py" )
"$PY" "$HB/hbgen.py" matrix --hbgen "$TREE" --image hello
"$PY" "$HB/hbgen.py" rpms --hbgen "$TREE" --image hello

# With an engine/network, resolve real versions here:
# ( cd "$TREE" && HB_PYTHON="$PY" CONTAINER_ENGINE=podman ci/get_rpm_versions.sh )

"$PY" "$HB/hbgen.py" render --hbgen "$TREE" --image hello
"$PY" "$HB/hbgen.py" config --hbgen "$TREE" --image hello --distro hummingbird --variant default
cat "$TREE/images/hello/hummingbird/default/Containerfile"
# WORK is a temporary copy; remove it when finished inspecting it.
```

Omitting the versions stage makes package-derived tags unresolved. Render still
works; config drops `unknown`/`unknown-*` tags and warns, falling back to usable
tags such as `latest`. It does not prove that packages exist in real repositories.

| Command | Prerequisites |
| --- | --- |
| `matrix` | prepare + aggregate |
| `rpms` | prepare + aggregate |
| `render` | the above + rpms; versions required for real version tags |
| `config` | the row's rendered Containerfile |

For the actual build, **source and call** the library:

```bash
source ./build/universal-ci.sh
DEBUG=true main_build -i curl
```

## 2. Configuration and generation

| Message/symptom | Action |
| --- | --- |
| `no variables.yml` | Provide shared `builders/variables.yml` or a per-image file |
| `variables.yml ... is empty` | Supply a mapping, including `default_distros` |
| `missing required key(s)` | Add the listed image properties; `default_variants` is optional |
| `unknown variant(s)` | Select a declared variant; inspect the aggregate with `hbgen.py variants` |
| `skipping ubi9/debug: restricted ...` | The explicit `additional_variants[].distros` filter excluded the row |
| UBI FIPS row skipped | Remove an obsolete Hummingbird-only restriction in your definition; the FIPS package baseline supports UBI |
| `unsupported architecture/platform` | Hummingbird/UBI supports `linux/amd64` and `linux/arm64`; use canonical values or RPM aliases |
| `fips=... contradicts crypto_policy=...` | Keep policy and FIPS flag consistent; use an explicit opt-out only for a non-FIPS variant |
| `no FIPS package policy for distro` | Extend the distro policy table and test it; do not guess package names in Jinja |
| `base_image must be an image reference` | Use a literal reference/scoped mapping, not shell or Jinja interpolation |
| `no repository files configured` / `repo file not found` | Provide the repo definition in vendored `yum-repos/`; built-in UBI/Hummingbird defaults need no repeated mapping |
| Python dependency errors | Use `HB_PYTHON` with PyYAML/Jinja2 installed in a virtualenv; see `tests/README.md` |

## 3. Versions and platforms

| Message/symptom | Action |
| --- | --- |
| `No version resolved for: ubi9/<package> (architecture aarch64)` | Check the package in that distro/arch repo, not the host's repo; missing FIPS providers are fatal |
| `differs across requested architectures` | Align repository versions or build architectures separately; one manifest tag must not silently describe different versions |
| Cache not reused despite fresh mtime | Check the request fingerprint: packages, repos, builder reference or architectures changed |
| `RPM versions cache lacks ... architectures` | Regenerate RPM inputs and run the versions stage for the new selection |
| Single arm64 build reports `exec format error` | Use an arm64 worker or working QEMU/binfmt; a single foreign target needs emulation too |
| `INSTALL_BINFMT=false` reports missing emulator | Supply emulation outside the build or use a native worker; `false` deliberately performs no privileged install |
| Docker multi-arch requires buildx | Install/configure buildx. The engine uses a docker-container builder or `BUILDX_BUILDER` |

## 4. Rootfs and base images

- `hb-rootfs reset` removes the entire validated newroot, including dotfiles and
  stale RPM databases. It refuses protected paths, symlinked paths and `..`.
- `base image ID=... does not match requested distro` means a seed and repository
  release disagree. Use a compatible seed or select the matching distro.
- `FIPS provider missing` or `FIPS definitions missing` is not a cosmetic warning:
  fix the package/repository inputs. The helper will not write a successful FIPS
  state for a rootfs lacking its provider/definitions.
- Composite policies such as `FIPS:OSPP` need pre-generated definitions in the
  rootfs. The helper does not execute foreign policy-generation binaries.
- `rootfs/` in the build context is **not** an implicit base. Copy custom files
  deliberately in `Containerfile.j2` after `setup_newroot()`.
- Seeding copies filesystem content, not base-image `ENV`, `USER`, `ENTRYPOINT`
  or other image metadata. Define those in the final template.

## 5. Image output

- Default assembly is `FROM scratch` + a normal `COPY --from=builder`. No shared
  OCI archive is needed, and the stage dependency works for each target.
- `chunkah: true` requires Podman. Keep it serialized and uncached: its bind-mount
  output cannot safely be replayed from layer cache. Do not restore the old
  assumption that merely retaining `out.ociarchive` makes cache hits safe.
- With `SKIP_PUSH=true`, Docker multi-arch output is an OCI archive in
  `BUILD_OUTPUT_DIR` (default `<context>/.ci-output/`); Podman returns/logs a local
  manifest. No image tags should be published.
- A failed platform build or manifest push must fail the pipeline. Never turn a
  push error into a warning followed by a success record.

Run `HB_PYTHON=... ./tests/run-tests.sh` after changing any of these paths.
Real image builds, crypto-provider operation and compliance scans still need a
suitable container runner; the offline suite does not emulate those guarantees.
