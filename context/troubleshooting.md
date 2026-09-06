# Troubleshooting

Match the message you see to a row. Everything here was produced by real runs in
this repository.

## 1. First moves (always)

```bash
DEBUG=true ./build/universal-ci.sh -i <image>        # verbose logging + keeps temp files
ls -la <builder>/.hbgen                              # did generation happen at all?
ls -R  <builder>/.hbgen/images/<image>               # which rows exist?
cat    <builder>/.hbgen/images/<image>/<distro>/<variant>/Containerfile   # the truth
cat    <builder>/.hbgen/images/<image>/<distro>/<variant>/VERSION
cat    <builder>/.hbgen/images/<image>/<distro>/<variant>/TAGS
cat    <builder>/.hbgen/.cache/properties.json       # aggregated variants + distros
cat    <builder>/.hbgen/.cache/rpm-versions.yml      # resolved versions per distro
```

Then re-run the failing stage in isolation — every stage is a standalone command:

```bash
cd <builder>
HB=<repo>/build/lib/hummingbird          # adjust to where this repo is mounted

python3 $HB/hbgen.py prepare --image-dir . --builders-dir .. --distros ubi9

# Stage 2 is a vendored generator and must run with cwd = the work tree.
# Skipping it is the most common mistake here: `matrix` then fails with
# ".cache/properties.json not found".
( cd .hbgen && python3 $HB/aggregate_properties.py )

python3 $HB/hbgen.py matrix  --hbgen .hbgen --image <name>
python3 $HB/hbgen.py rpms    --hbgen .hbgen --image <name>    # required before render
python3 $HB/hbgen.py render  --hbgen .hbgen --image <name> --distros ubi9
python3 $HB/hbgen.py config  --hbgen .hbgen --image <name> --distro ubi9 --variant default
```

The stages are cumulative, and each one names its missing prerequisite:

| Command | Requires | Error if you skip ahead |
| --- | --- | --- |
| `matrix` | `prepare` + `aggregate_properties.py` | `.cache/properties.json not found — run aggregate_properties.py … first` |
| `render` | the above + `rpms` | `…/rpms/rpms.in.yaml is missing — run 'hbgen.py rpms' …` |
| `config` | the above + `render` | `no rendered Containerfile for … — run 'hbgen.py render' first` |

`render` also wants `.cache/rpm-versions.yml` (stage 4, needs a container
engine). Without it the render still succeeds, but every version reads
`unknown`; `config` then drops those tags and falls back to `latest` with a
warning — see [finding 30](flaw-report-hummingbird.md).

`hbgen.py config` prints the exact key/value pairs the driver loads into
`CONFIG` — the fastest way to see what the engine was actually told.

## 2. Generation errors

| Message | Cause | Fix |
| --- | --- | --- |
| `error: <dir> is not a hummingbird builder: missing Containerfile.j2` | Wrong directory, or the builder is incomplete | `ci_hummingbird_find_image` searches `BUILDERS_DIR/<name>` then `SOURCE_DIR`; check both |
| `error: variables.yml not found (looked in <builder>/variables.yml and <builders>/variables.yml)` | Neither file exists | Create one; at least one is required |
| `error: variables.yml (shared defaults) is empty: <path>` | File exists but parses to `null` | Add `default_distros:` / `default_variants:` |
| `error: images/variables.yml is missing required key(s): default_variants` | Merged variables lack a key | All missing keys are listed at once |
| `error: properties.yml of image 'x' is missing required key(s): stream` | Incomplete `properties.yml` | Required: `description`, `summary`, `url`, `stream`, `tags` |
| `error: unknown image 'x'; known images: a, b` | Name/typo mismatch | The message lists what exists |
| `error: HB_VARIANTS='x' does not match any variant of image 'y' (available: …)` | Override names a variant that was not declared | Declare it in `variants:`/`additional_variants:` or fix the override |
| `warning: skipping ubi9/fips: restricted to hummingbird by additional_variants` | Working as intended | The variant declared `distros:`; remove the restriction if you want it |
| `jinja2.exceptions.UndefinedError: 'x' is undefined` | A macro read a variable `ImageContext` does not provide | Add it in `_build_variables`; do **not** add `\| default(...)` (see `conventions.md` §4) |
| `KeyError` / traceback from a generator | Unexpected input shape, or a re-vendored file dropped a local fix | Check `hummingbird-pipeline.md` §7; tracebacks are treated as bugs |

## 3. Versions and tags

| Symptom | Cause | Fix |
| --- | --- | --- |
| `VERSION` is `unknown` | Stage 4 was skipped or could not resolve the version package | `HB_SKIP_RPM_VERSIONS=true` intentionally skips it; otherwise check the repoquery output below. Driver falls back to tag `latest` **and warns** |
| Tag is `latest` but you expected a version | Same as above | Run stage 4 with an engine, or set `HB_VERSION=…` |
| ubi9 image tagged with the hummingbird version | Stale **flat** `.cache/rpm-versions.yml` from before the per-distro format | Delete `.cache/rpm-versions.yml` and re-run stage 4 (flat caches are still read for compatibility, but they cannot distinguish distros) |
| `error: rpm versions cache has no entry for distro 'ubi9' (known: hummingbird)` | Stage 4 ran for a different distro set | Re-run with the same `--distros`, or clear the TTL cache |
| Versions resolve to an unexpected build (e.g. `8.21.0-0.dev1`) | `version_package` / `main_package` mismatch, or the repo has a newer build | `rpm_versions` keys come from `properties.yml`'s `version_package`; the driver warns when `main_package` has no resolved version |
| Version not refreshed after a repo update | Cache TTL reuse | `HB_RPM_VERSIONS_TTL=0` forces a re-resolve |
| `epoch` prefix in a tag (`3:8.10.1`) | Old cache format | Fixed: epochs are stripped when the cache is written; regenerate it |

Debug stage 4 by hand (needs an engine and repo access):

```bash
podman run --rm -v "$PWD/.hbgen:/run/src:z" -w /run/src \
  <builder-image> bash -lc \
  'dnf repoquery --repofrompath "tmp,https://…" --repoid=tmp --qf "%{name} %{evr}" curl'
```

## 4. Build-time failures

| Message | Cause | Fix |
| --- | --- | --- |
| `Error: creating build context: … out.ociarchive: file not found` | The chunkah archive was deleted between matrix rows | Do not widen the cleanup glob in `ci-build.sh` (see the `WHY` there); the driver cleans once, after the last row |
| `error: required function 'ci_build_and_push' is not loaded` | The engine libraries were not sourced | Source `build/universal-ci.sh` (it pulls in `ci-core`/`ci-build`/…), not `ci-hummingbird.sh` alone |
| `error: required function 'build_registries_array' is not loaded` | Same | Same |
| `error: image directory is required` followed by a dead CI job | Legacy `${1:?}` in a sourced function | Fixed: the driver returns 1 with a message. If you see a job die silently, you are on an older revision |
| Only some matrix rows were built | A loop reading its row list from stdin | Fixed (`mapfile` + `for`). If it recurs, check any new command in the row loop that reads stdin |
| Images pushed to a registry from a previous row | Stale `DF_REGISTRY_*` keys | Fixed (`ci_hummingbird_reset_config`); any new `CONFIG` key you fill must be reset there too |
| Build works on amd64, fails on arm64 | No QEMU/binfmt in the runner | `ci_setup_buildx` installs binfmt; in a sandbox use `--platform linux/amd64` and skip arm64 |
| Context is huge / build is slow to start | Unexpected files in `.hbgen/images/<image>` | Only repo files + the selected SCAP datastreams belong there; check `du -sh .hbgen/images/<image>` and the distro selection |
| `COPY yum-repos/<distro>.repo` not found | Repo file missing for that distro | Add `yum-repos/<distro>.repo` and `default_variant_repos.<distro>` |

## 5. Environment problems

| Symptom | Cause | Fix |
| --- | --- | --- |
| `ModuleNotFoundError: No module named 'yaml'` / `'jinja2'` | System python lacks the deps | `python3 -m venv /tmp/hbvenv && /tmp/hbvenv/bin/pip install pyyaml jinja2`, then `HB_PYTHON=/tmp/hbvenv/bin/python` |
| Stage 3 fails although stages 1–2 worked | `get_rpm_versions.sh` used a different interpreter than the rest | Set `HB_PYTHON` — it is honoured by every stage including stage 3 |
| `pip install …` refuses with `externally-managed-environment` (PEP 668) | Distro-managed python | Use a venv; do not pass `--break-system-packages` |
| Test suite fails with `unknown` versions everywhere | `HB_PYTHON` not set when running the suite | `HB_PYTHON=/tmp/hbvenv/bin/python ./tests/hummingbird/run-tests.sh` |
| `podman: command not found` | No container engine | Generation and rendering still work; builds and stage 4 do not. The test suite stubs the engine |
| `git submodule status` returns nothing | Not a submodule-configured work tree | Expected; `gitmodules` becomes `{}` and `git_submodule_hash()` returns `unknown` |

## 6. Reading the logs

```
[hbgen] note:      stage progress (stdout, part of the command output)
[hbgen] info:      diagnostic detail (stderr)
[hbgen] warning:   recoverable problem, generation continues
[hbgen] error:     fatal, nothing usable was produced
[hbgen] debug:     only with DEBUG=true
```

The driver prefixes its own lines with `ci-hummingbird:` / `hummingbird:`.
`hbgen` logs go to **stderr** so that `hbgen.py config`'s TSV output on stdout
can be consumed directly — never redirect stderr into the captured output.

## 7. Still stuck?

1. Reduce to one row: `HB_DISTROS=hummingbird HB_VARIANTS=default`.
2. Skip the engine-dependent stage: `HB_SKIP_RPM_VERSIONS=true HB_VERSION=1.2.3`.
3. Inspect the rendered Containerfile — 90% of "the build is wrong" is visible
   there before any container runs.
4. Add the case to `tests/hummingbird/fixtures/` so it stays fixed.
