# Architecture

How the pieces fit, who calls whom, and where a change belongs.

## 1. Two flavours, one engine

`build/universal-ci.sh` exposes a single entry point, `main_build`, which is
**sourced and called** by consumer repositories (it is a library, not a CLI):

```bash
source "$BUILD_IMG_PATH/../../scripts/build/universal-ci.sh"
main_build -i "$IMAGE_NAME" "$@"
```

```
main_build(-d Dockerfile | -i name) [-r repo -b branch] [-f flavor]
   │
   ├─ load_repository()            optional git clone into SOURCE_DIR
   ├─ ci_hummingbird_find_image()  resolve the builder directory
   ├─ ci_hummingbird_detect_flavor()  →  hummingbird | dockerfile | ""
   │
   ├──[ hummingbird ]──────────────────────────────────────────────────┐
   │    extract_git_info()                                             │
   │    ci_hummingbird_build()                                         │
   │      ├─ ci_hummingbird_generate()   renders the whole matrix      │
   │      ├─ ci_hummingbird_matrix()     distro × variant rows         │
   │      └─ for each row:                                             │
   │           ci_hummingbird_configure()  → CONFIG[]                  │
   │           ci_build_and_push()         → shared engine             │
   │    remove_docker_images(HB_BUILT_IMAGES)                          │
   │                                                                   │
   └──[ dockerfile ]───────────────────────────────────────────────────┘
        find_dockerfile()
        load_config()               Dockerfile comments + YAML + ENV
        extract_git_info()
        get_runner_id()
        ci_build_and_push()
        remove_docker_images(CI_BUILT_IMAGES)
```

Both paths converge on `ci_build_and_push`, which is why flavour-specific code
must express itself through the shared `CONFIG` associative array and never by
calling the container engine itself.

## 2. Module map (`build/lib/`)

| Module | Responsibility | Key entry points |
| --- | --- | --- |
| `ci-core.sh` | Base layer, no dependencies. Logging, temp files, engine detection, tag strategies, OCI labels | `log_info/warn/error/success/debug`, `detect_container_engine`, `ci_generate_tag`, `ci_generate_oci_labels`, `get_runner_id` |
| `ci-dockerfile.sh` | Parses `# KEY: value` comments, `ARG`, `SECRET`, `FROM` images out of a Dockerfile | `parse_dockerfile_comments`, `parse_dockerfile_args`, `find_dockerfile` |
| `ci-yaml.sh` | YAML config parsing (the optional `-c config.yaml` path) | `parse_yaml_registries`, `parse_yaml_scalar` |
| `ci-secrets.sh` | Build secrets: detection, file materialisation, `--secret` args | `ci_resolve_secret_value`, `ci_secret_to_file`, `auto_add_secrets_from_dockerfile` |
| `ci-config.sh` | Precedence merge into `CONFIG`, registry arrays, git metadata | `load_config`, `build_registries_array`, `build_sign_registries_array`, `extract_git_info` |
| `ci-registry.sh` | Logins and credential lookup (env, `dockerconfigjson`, registry-specific keys) | `ci_login_all_registries`, `ci_login_to_registry` |
| `ci-ecr.sh` | Best-effort ECR repository auto-create | `ci_ensure_ecr_repository` |
| `ci-build.sh` | The engine: buildx/binfmt setup, tag generation, build, push, multi-arch, chunkah workarounds | `ci_setup_buildx`, `ci_build_and_push` |
| `ci-artifacts.sh` | Artifact records: digest/size capture, IBM Cloud toolchain store with a local fallback, summary rendering | `ci_collect_image_metadata`, `ci_store_artifact`, `ci_ibmcloud_save_artifact`, `ci_generate_artifact_summary` |
| `ci-utils.sh` | Repo loading, image removal, cosign signing | `load_repository`, `remove_docker_images`, `sign_with_cosign` |
| `ci-promote.sh` | Promotion helpers used by `build/promotion.sh` | `ci_promote_*` |
| `ci-hummingbird.sh` | Hummingbird flavour driver | see [`hummingbird-pipeline.md`](hummingbird-pipeline.md) |

Dependency rule: **`ci-core.sh` depends on nothing; every other library depends
on core; flavours depend on the engine; the engine never depends on a flavour.**
Each file guards its own sourcing with `CI_CORE_LOADED` so a consumer can source
one library and get its dependencies.

## 3. The shared contract: `CONFIG`

`CONFIG` is a process-wide bash associative array. It is the *only* interface
between a flavour and the engine.

| Key | Meaning | Set by |
| --- | --- | --- |
| `IMAGE_NAME` | Repository name (without registry/prefix/tag) | both flavours |
| `VERSION` | Version string used by tag strategies | both flavours |
| `TAG_STRATEGY` | One of the strategies in `ci_generate_tag` | both flavours |
| `CUSTOM_TAGS` | Space-separated tags when strategy is `custom` | both flavours |
| `DF_REGISTRY_<i>` / `_PREFIX` / `_PUSH` | Registry list, positional | `ci-dockerfile.sh`, hummingbird |
| `YAML_REGISTRY_<i>`, `ENV_REGISTRY_*` | Same, lower precedence sources | `ci-yaml.sh`, `ci-config.sh` |
| `PLATFORMS` | `linux/amd64,linux/arm64` | both flavours |
| `CHUNKAH` | `true` enables the oci-archive workarounds | hummingbird |
| `ARG_<name>` | Auto-passed as `--build-arg <name>=$<name>` from env | both flavours |
| `SECRET_<id>` | Auto-materialised as `--secret id=<id>` | `ci-secrets.sh` |
| `GIT_*` | Commit metadata for labels | `extract_git_info` |
| `DISTRO`, `VARIANT` | Hummingbird row identity (informational) | hummingbird |

Registry precedence is resolved by `build_registries_array()` into the global
`REGISTRIES` array as `"name,prefix,push"` strings:

```
DF_REGISTRY_*  >  YAML_REGISTRY_*  >  ENV_REGISTRY / default (docker.io)
```

**Trap:** `build_registries_array` walks indices `0,1,2,…` and stops at the
first gap. Leftover keys from a previous build therefore get pushed to. Any
code that fills `DF_REGISTRY_*` must clear the old keys first — see
`ci_hummingbird_reset_config`.

Tag strategies live in `ci_generate_tag()` (`ci-core.sh`): `version`, `runner`,
`sha`, `latest`, `tag`, `custom`, and the combinations `runner-latest`,
`sha-latest`, `version-latest` (the default), `version-runner`, `version-sha`,
`tag-latest`, `version-runner-latest`, `version-sha-latest`.

There is no `version-only`, `latest-only` or `git-sha`; an unrecognised value
warns and falls back to `latest`.

## 4. Configuration precedence

```
Dockerfile comments  >  YAML config file  >  environment variables  >  defaults
```

For the hummingbird flavour the same idea applies with different sources
(resolved in one place, `hbgen.py:cmd_config`):

```
HB_* environment override  >  rendered artifact (VERSION/TAGS)  >  variables.yml  >  defaults
```

## 5. Runtime surfaces outside `build/`

- `docker/*.sh` — copied into images and executed during `RUN`. They must be
  idempotent, work offline where possible, and never assume bash 5.
- `build/lib/hummingbird/prebuildfs/usr/local/bin/lib*` — sourced *inside* the
  running container by image entrypoints (`libentrypoint`, `liblog`, `libhook`,
  `libjson`, `libwatch`, `libenv`, `libfs`), plus `usr/sbin/run-script` and
  `install_packages_chroot`. POSIX-friendly, no external dependencies.
- `build/lib/hummingbird/oscap/*.xml` — SCAP datastreams (~25 MB each). They are
  vendored for offline compliance scans and copied **selectively** into the
  build context.

## 6. Where a change belongs

| I want to… | Change |
| --- | --- |
| Add a tag strategy | `ci_generate_tag()` in `ci-core.sh` |
| Add a registry credential source | `ci-registry.sh` |
| Change what gets pushed/built | `ci-build.sh` |
| Add a hummingbird config knob | `hbgen.py:cmd_config` (+ `ci_hummingbird_configure` mapping) |
| Change variant naming | `hb_variant.py` |
| Change which packages are installed | `hb_packages.py` |
| Change generated Containerfile content | `macros/*.yml.j2`, `templates/*.j2` |
| Change the work-tree layout | `hbgen.py:cmd_prepare` (+ the path helpers in `ci-hummingbird.sh`) |
| Add a new flavour | new `ci-<flavour>.sh` + a branch in `main_build` |
