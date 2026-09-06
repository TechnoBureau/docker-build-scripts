# AGENTS.md

Operating manual for AI agents (and humans) working in **docker-build-scripts**.

This file is the entry point. It tells you what to load, what to run, and what
must never break. Detailed knowledge lives in [`context/`](context/README.md) —
load those on demand, not all at once.

---

## 1. What this repository is

Enterprise DevOps toolkit, three independent surfaces:

| Surface | Path | What it does |
| --- | --- | --- |
| CI/CD build engine | `build/` | Sources bash libraries to build, tag, sign and push container images; runs the hummingbird and Dockerfile flavours |
| Image provisioning | `docker/` | Standalone scripts `COPY`'d into Dockerfiles (tool installs, DISA STIG hardening) |
| Container runtime libs | `build/lib/hummingbird/prebuildfs/` | `lib*` shell libraries baked into images (entrypoint, logging, hooks) |

The **hummingbird builder** (`build/lib/ci-hummingbird.sh` +
`build/lib/hummingbird/`) is the most intricate part: one image definition
(`properties.yml` + `Containerfile.j2`) fans out into a matrix of
distro × variant images. Start with
[`context/hummingbird-pipeline.md`](context/hummingbird-pipeline.md).

---

## 2. Hooks

Hooks are commands, not aspirations. Run them at the stated moment.

### 2.1 `on_session_start` — orient before touching anything

```bash
git status --short && git log --oneline -5      # where am I, what just happened
ls build/lib build/lib/hummingbird              # module inventory
bash --version | head -1; python3 -VV           # toolchain
command -v podman docker shellcheck             # what can I actually run here
```

Then read, in this order, **only what the task needs**:

| Task mentions | Load |
| --- | --- |
| hummingbird, properties.yml, Containerfile.j2, variant, distro, rpms.in.yaml | `context/hummingbird-pipeline.md` |
| any build/push/tag/registry/signing behaviour | `context/architecture.md` |
| writing or reviewing code | `context/conventions.md` |
| "add a …", "support a new …" | `context/extension-guide.md` |
| a build that fails | `context/troubleshooting.md` |
| "why is it like this?", regression hunting | `context/flaw-report-hummingbird.md` |

### 2.2 `before_edit` — locate the owner of the behaviour

Change behaviour in exactly one place. This table is the anti-duplication map:

| Behaviour | Single owner | Never re-implement in |
| --- | --- | --- |
| Variant parsing, `-builder` naming | `build/lib/hummingbird/hb_variant.py` | macros, bash, `generate_jinja2.py` |
| YAML load / deep merge / required keys | `build/lib/hummingbird/hb_config.py` | bash heredocs |
| Which packages a variant installs | `build/lib/hummingbird/hb_packages.py` | `package_args.yml.j2`, `generate_rpms_in.py` |
| Work tree, matrix, per-row config | `build/lib/hummingbird/hbgen.py` | `ci-hummingbird.sh` |
| Jinja rendering, labels, tags | `build/lib/hummingbird/generate_jinja2.py` | bash |
| Tag *strategies*, logging, engine detection | `build/lib/ci-core.sh` | anywhere |
| Registry precedence | `build/lib/ci-config.sh` | flavours |
| Actual build/push/artifacts | `build/lib/ci-build.sh`, `ci-artifacts.sh` | flavours |

Rules of the road:

- **Bash orchestrates, Python decides.** No YAML/JSON parsing in bash — call
  `hbgen.py`. No container-engine calls in Python — return data to bash.
- **Keep `WHY:` comments.** They encode incidents (cache interactions, quoting
  traps, emulation limits). Deleting one re-opens a bug.
- **Preserve the public function names** (`ci_*`, `main_build`, `load_config`):
  consumer repositories source them directly.
- Never write secrets, tokens or `.hbgen/` output into git.

### 2.3 `after_edit` — validate (fast → slow)

```bash
# 1. Syntax and shell correctness (~2s)
python3 -m py_compile build/lib/hummingbird/*.py
shellcheck -x -S warning build/lib/ci-hummingbird.sh build/universal-ci.sh \
                         build/lib/hummingbird/get_rpm_versions.sh

# 2. Hummingbird regression suite, fully offline (~6s, 99 assertions)
#    needs PyYAML + Jinja2; point HB_PYTHON at an interpreter that has them
HB_PYTHON=python3 ./tests/hummingbird/run-tests.sh
#    narrow it while iterating:
./tests/hummingbird/run-tests.sh -k matrix      # one group (prepare|matrix|versions|render|errors|driver)
./tests/hummingbird/run-tests.sh -t fips        # report only assertions whose name matches

# 3. Inspect real generated output (needs PyYAML + Jinja2 only)
#    The stages are cumulative: `matrix` needs stage 2, `render` needs `rpms`.
REPO=/path/to/docker-build-scripts           # this repository
HB="$REPO/build/lib/hummingbird"
python3 "$HB/hbgen.py" prepare --image-dir <builder> --builders-dir <builders>
( cd <builder>/.hbgen && python3 "$HB/aggregate_properties.py" )
python3 "$HB/hbgen.py" matrix --hbgen <builder>/.hbgen --image <name>
```

The suite needs **no** container engine, network, builder image or package repo:
`tests/hummingbird/stubs/podman` answers `dnf repoquery`. A real end-to-end
build (`ci_build_and_push`) cannot run in a sandbox — say so explicitly instead
of implying it was tested.

### 2.4 `before_commit`

```bash
git status --short                    # no .hbgen/, no __pycache__/, no fixtures drift
git diff --stat                       # did I touch more than the task needs?
./tests/hummingbird/run-tests.sh      # green
```

Checklist:

- [ ] Behaviour changed in one owner only (§2.2)
- [ ] Regression test added or updated for every fixed flaw
- [ ] `WHY:` comment added wherever the fix is non-obvious
- [ ] Docs updated: `context/*` **and** `README.md` when behaviour is user-visible
- [ ] No new inline `python3 - <<PY` heredoc in bash
- [ ] Backwards compatible, or the break is listed in the commit message

### 2.5 `on_failure` — when a build breaks

1. Read the error text; match it against `context/troubleshooting.md`.
2. Reproduce at the smallest stage instead of re-running the pipeline:
   every `hbgen.py` subcommand runs standalone (`prepare`, `rpms`, `matrix`,
   `render`, `config`, `vars`, `distros`).
3. Inspect the generated truth, not the template:
   `<builder>/.hbgen/images/<image>/<distro>/<variant>/Containerfile`.
4. Add the failing case to `tests/hummingbird/` before fixing it.

---

## 3. Non-negotiable invariants

Breaking any of these has caused a real incident; each is covered by a test id.

1. **The build matrix honours `additional_variants[].distros`.** A variant
   pinned to `hummingbird` must never be built for `ubi9`. *(tests B2, F12)*
2. **Versions are per distro.** `curl` in ubi9 repos is not `curl` in
   hummingbird repos; a flat version map silently mis-tags images. *(C3–C7, D20)*
3. **`is_builder` comes from `hb_variant`.** Composite variants
   (`fips-builder`) are builders: packages, dnf defaults, licence retention and
   the published repository name all depend on it. *(B5, D2–D6)*
4. **The `name=` label equals the pushed repository.** Scanners resolve images
   through that label. *(D8, D9)*
5. **`rpms.in.yaml` and `ARG MAIN_PACKAGES` describe the same set.** *(D2, D3)*
6. **`oscap` is always defined in the template context**, enabled or not.
   *(E1, E2)*
7. **Matrix iteration never reads the row list from stdin.** Any command in the
   loop body that consumes stdin silently truncates the build. *(F9)*
8. **A library function returns non-zero; it never terminates the caller's
   shell.** No `${1:?}` in sourced functions. *(F7)*
9. **Chunkah `out.ociarchive` survives until the last row is built**, then is
   removed. Deleting it per build breaks layer-cache replays. *(F26)*
10. **The build context stays small.** Only the SCAP datastreams of the
    selected distros are vendored into it. *(A8, A9)*
11. **No tag containing an unresolved version is ever published.** `unknown` and
    `unknown-<variant>` are filtered out of `CONFIG[CUSTOM_TAGS]`, which the
    engine publishes verbatim under `TAG_STRATEGY=custom`. *(F28–F32)*
12. **`TAG_STRATEGY` names are the ones `ci_generate_tag` implements.** There is
    no `version-only`, `latest-only` or `git-sha`; an unrecognised value warns
    and falls back to `latest` rather than tagging silently.

---

## 4. Command reference

```bash
# Full CI pipeline (Dockerfile flavour)
./build/universal-ci.sh -d ./Dockerfile -i myimage --skip-push

# Full CI pipeline (hummingbird flavour, auto-detected)
./build/universal-ci.sh -i curl
HB_DISTROS="hummingbird ubi9" HB_VARIANTS="default,fips" ./build/universal-ci.sh -i curl

# Promotion between registries
./build/promotion.sh -s icr.io/ns -r 123.dkr.ecr.us-east-1.amazonaws.com -l "img:v1"

# Debug anything
DEBUG=true ./build/universal-ci.sh -i curl
```

Hummingbird environment knobs (full list: `context/hummingbird-pipeline.md`):
`HB_DISTROS`, `HB_VARIANTS`, `HB_VERSION`, `HB_TAGS`, `HB_REGISTRIES`,
`HB_SKIP_RPM_VERSIONS`, `HB_RPM_VERSIONS_TTL`, `HB_PYTHON`, `HUMMINGBIRD_DIR`.

Engine knobs (both flavours): `INSTALL_BINFMT` (`auto`|`false`|`force` — set
`false` on runners without `--privileged`), `DIND_IMAGE`, `SOURCE_DATE_EPOCH`,
`DEBUG`, `SKIP_PUSH`, `PLATFORMS`.

---

## 5. Layout

```
build/
├── universal-ci.sh            main_build(): flavour detection + orchestration
├── promotion.sh               registry-to-registry promotion
├── go-dependencies.sh         Go dependency pinning
└── lib/
    ├── ci-core.sh             logging, temps, engine detection, tag strategies
    ├── ci-config.sh           CONFIG/REGISTRIES precedence, git metadata
    ├── ci-dockerfile.sh       Dockerfile comment/ARG/secret parsing
    ├── ci-build.sh            ci_build_and_push(): buildx, tags, push, chunkah
    ├── ci-artifacts.sh        artifact + signing records
    ├── ci-registry.sh         logins, credential lookup
    ├── ci-ecr.sh / ci-secrets.sh / ci-utils.sh / ci-yaml.sh / ci-promote.sh
    ├── ci-hummingbird.sh      hummingbird flavour driver (thin orchestrator)
    └── hummingbird/
        ├── hbgen.py           pipeline CLI: prepare|rpms|matrix|render|config|vars|variants|distros
        ├── hb_variant.py      variant decomposition + image naming
        ├── hb_config.py       YAML loading, deep merge, required keys
        ├── hb_packages.py     package-set resolution
        ├── aggregate_properties.py  stage 1 (vendored)
        ├── generate_rpms_in.py      stage 2 (vendored)
        ├── get_rpm_versions.sh      stage 3 (needs a container engine)
        ├── generate_jinja2.py       stage 4 renderer (vendored)
        ├── macros/ templates/       Jinja building blocks
        ├── yum-repos/ oscap/ prebuildfs/   vendored build inputs
        └── (tests live in /tests/hummingbird)
docker/                        provisioning + hardening scripts
tests/hummingbird/             offline regression suite
context/                       agent knowledge base (start at context/README.md)
```
