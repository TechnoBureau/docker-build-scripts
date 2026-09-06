# Hummingbird builder — flaw report and fixes

Review of the hummingbird builder (`build/lib/ci-hummingbird.sh` +
`build/lib/hummingbird/`) performed against the state at commit `cfad902`.

Every flaw below was **reproduced**, not inferred from reading: the "Evidence"
line is real output from this repository's generators, and the "Regression"
line is an assertion id in [`tests/hummingbird/run-tests.sh`](../tests/hummingbird/run-tests.sh).

Severity: **S1** produces a wrong or broken artifact · **S2** breaks a
supported configuration · **S3** maintainability, performance or robustness.

| # | Sev | Flaw | Status |
| --- | --- | --- | --- |
| 1 | S1 | Package versions collapsed across distros (duplicate YAML keys) | fixed |
| 2 | S1 | Build matrix ignored per-variant distro restrictions | fixed |
| 3 | S1 | Composite builder variants (`fips-builder`) were not builders | fixed |
| 4 | S1 | `name=` label advertised a repository that was never pushed | fixed |
| 5 | S1 | `rpms.in.yaml` and `ARG MAIN_PACKAGES` disagreed | fixed |
| 6 | S2 | Missing `oscap:` key aborted generation | fixed |
| 7 | S2 | `.gitmodules` never found; `git submodule` mis-invoked | fixed |
| 8 | S2 | Configuration errors surfaced as Python tracebacks | fixed |
| 9 | S2 | Matrix loop read its row list from stdin | fixed |
| 10 | S2 | `${1:?}` in a sourced function killed the caller's shell | fixed |
| 11 | S2 | `CONFIG` keys leaked between matrix rows | fixed |
| 12 | S3 | 49 MB of SCAP datastreams copied into every build context | fixed |
| 13 | S3 | Deep merge implemented three times with two semantics | fixed |
| 14 | S3 | Seven inline Python snippets in the bash driver (six `<<'PY'` heredocs + one `python3 -c`) | fixed |
| 15 | S3 | Duplicated variables.yml resolution and distro×variant loops | fixed |
| 16 | S3 | Chunkah archive cleanup pattern never matched the archive | fixed (documented) |
| 17 | S3 | Helper function leaked into the global namespace; dead search branch | fixed |
| 18 | S3 | Dead code: unused function, pointless `chmod +x` on the vendored tree | fixed |
| 19 | S3 | `-i <name>` builds failed to detect a builder in `SOURCE_DIR` | fixed |
| 20 | S3 | `CHUNKAH` hard-coded; empty `oscap-tailoring.xml`; no way to skip stage 4 | fixed |
| 21 | S3 | The whole flavour was undocumented; `ci-ecr.sh` shebang not on line 1 | fixed |
| | | **Outside the hummingbird builder** (found by the audit sweep; repo is now shellcheck-clean at warning level) | |
| 22 | S2 | `INSTALL_BINFMT` was read into a local and never used — the knob did nothing | fixed |
| 23 | S2 | `re-source.sh` used BSD `sed -i ''` (no-op on Linux) and bash-only `read -d` under `#!/bin/sh` | fixed |
| 24 | S2 | `find_dockerfile` leaked two global functions and aborted the caller under `set -u` | fixed |
| 25 | S2 | `go-setup.sh` ran the Go build in the wrong directory when `cd` failed | fixed |
| 26 | S3 | Instana scripts: bare redirection, two write-only associative arrays | fixed |
| 27 | S3 | `venv.sh`: `local x=$(…)` masking failures, dead version decomposition | fixed |
| 28 | S3 | `ci-utils.sh`: three "security" regexes that validated nothing | fixed |
| 29 | S2 | README documented three tag strategies that do not exist; unknown values fell back silently | fixed |
| 30 | S1 | Unresolved versions still published literal `:unknown` tags | fixed |

---

## S1 — wrong or broken artifacts

### 1. Package versions collapsed across distros

**Symptom.** With `HB_DISTROS="hummingbird ubi9"`, the ubi9 image was tagged
with the hummingbird version.

**Cause.** `get_rpm_versions.sh` carefully produced *per-distro* result files —
its own comment says a global file "would mask a ubi miss with a hummingbird
hit for the same package name" — and then merged them into one **flat**
`.cache/rpm-versions.yml`. Duplicate mapping keys are legal YAML: `safe_load`
silently keeps the last, so every distro rendered the same versions.

**Evidence** (before the fix):

```
# .cache/rpm-versions.yml
curl: 8.10.1-2.el9
curl: 8.21.0-1.hum1
>>> yaml.safe_load(...)
{'curl': '8.21.0-1.hum1'}          # the el9 value is gone

images/curl/ubi9/default/VERSION   → 8.21.0   (actual package: 8.10.1)
images/curl/ubi9/default/TAGS      → 8.21.0 / 8.21 / latest
```

**Fix.** The cache is now nested per distro, and the renderer selects its own
distro (flat caches are still accepted for compatibility):

```yaml
distros:
  hummingbird: {curl: 8.21.0-1.hum1}
  ubi9:        {curl: 8.10.1-2.el9}
```

Epochs are stripped while writing (`3:8.10.1-2.el9` → `8.10.1-2.el9`), a
missing distro raises an actionable error instead of rendering `unknown`, and
`HB_RPM_VERSIONS_TTL` allows a re-render without a container engine.

**Regression.** C3–C7 (cache shape, both distros, epoch stripping, no duplicate
keys), D20–D23 (rendered VERSION/TAGS per distro).

---

### 2. Build matrix ignored per-variant distro restrictions

**Symptom.** Variants pinned to one distro were built for every distro.

**Cause.** `aggregate_properties.py` computed the authoritative
`distro_variants` list (cartesian product *filtered* by
`additional_variants[].distros`), but the bash driver ignored it and looped
`distros × variants` itself. The restriction data never left the cache.

**Evidence** (before the fix):

```
cache distro_variants: hummingbird/default hummingbird/builder
                       hummingbird/fips hummingbird/fips-builder
rows the driver built:  ...plus ubi9/fips and ubi9/fips-builder
```

`ubi9/fips` then resolved the FIPS package set against the ubi9 repositories —
a wasted build at best, a failed one at worst.

**Fix.** `aggregate_properties.py` now also exports `variant_distros` (the raw
restriction map) and `distros`; `hbgen.resolve_matrix` applies it to the
*selected* distros, so `HB_DISTROS` overrides still work while restrictions are
honoured. Skipped combinations are logged:

```
[hbgen] warning: skipping ubi9/fips: restricted to hummingbird by additional_variants
```

**Regression.** B2 (excluded), B3 (kept), B7 (row count), F12 (never built).

---

### 3. Composite builder variants were not builders

**Symptom.** A variant named `fips-builder` produced an image with no build
tooling, stripped of licences and locales, published under the wrong name.

**Cause.** Three places tested `variant == "builder"` (bash `CONFIG[IMAGE_NAME]`,
`is_builder_variant.yml.j2`, `final_stage.yml.j2`) while
`generate_jinja2._decompose_variant` already understood composite names — and
used that understanding to emit `variant.builder="true"` labels. The same
Containerfile therefore claimed to be a builder and behaved like a runtime image.

**Evidence** (before the fix, `hummingbird/fips-builder` vs `hummingbird/builder`):

```
fips-builder: ARG MAIN_PACKAGES="curl ca-certificates filesystem"
builder:      ARG MAIN_PACKAGES="curl ca-certificates filesystem gcc make curl-devel"
fips-builder: (no 90-builder-defaults.conf RUN)
fips-builder: RUN rm -rf ${NEWROOT}/usr/share/licenses ${NEWROOT}/usr/share/locale
              ↑ the macro's own comment warns this must not happen for builders
fips-builder: (no ENV CONTAINER_DEFAULT_USER)
both:         LABEL io.hummingbird-project.variant.builder="true"
```

**Fix.** New module `hb_variant.py` owns variant semantics:
`decompose_variant`, `is_builder_variant`, `resolve_image_name`.
`generate_jinja2.py` exposes `is_builder`, `is_fips`, `variant_base` and
`image_repo_name` as template variables; the macros use them; the bash driver
takes the image name from `hbgen.py matrix`/`config`, which use the same
function. One rule, three consumers, no drift.

**Regression.** B5, D2–D6, D11, F11.

---

### 4. `name=` label advertised a repository that was never pushed

**Symptom.** Scanners and vulnerability tooling resolve images through the
`name=` label; for non-builder variants it pointed at a non-existent repository.

**Cause.** `_set_canonical_name` appended **every** non-default variant to the
repository name, while the driver appended `-builder` only for the literal
`builder` variant.

**Evidence** (before the fix):

```
rendered:  LABEL name="ghcr.io/technobureau/curl-fips-builder"
published: ghcr.io/technobureau/curl:<version>-fips-builder     (repo "curl")
rendered:  LABEL name="ghcr.io/technobureau/curl-fips"
published: ghcr.io/technobureau/curl:<version>-fips             (repo "curl")
```

**Fix.** Both sides call `hb_variant.resolve_image_name` (and
`image_repository` for the label). Decision: **only the `builder` modifier
changes the repository name**; every other variant shares the repository and is
distinguished by its tag, which is what `TAGS.j2` already does
(`value + "-" + variant`). The variant remains discoverable through the
`io.hummingbird-project.variant*` labels. This keeps existing published names
stable — no repository is renamed — while making the label truthful.

**Regression.** D8, D9, D10, B4–B6.

---

### 5. `rpms.in.yaml` and `ARG MAIN_PACKAGES` disagreed

**Symptom.** Versions were resolved (and locked) for packages that were never
installed, and some packages that should have been installed were missing from
both.

**Cause.** The package set was computed twice, independently:
`generate_rpms_in.py` (Python key walk) and `package_args.yml.j2` (Jinja key
walk). The rules had drifted:

| Key | rpms.in.yaml | MAIN_PACKAGES |
| --- | --- | --- |
| `rpm_packages.builder` for variant `fips-builder` | no | no |
| `default_rpm_packages.<variant>` (e.g. `fips:`) | yes | **no** |
| `default_rpm_packages.builder` | only `endswith("-builder")` | only via the macro |
| dedup/sorting | yes | no |

**Evidence.** `fips-builder` resolved `curl-devel` in neither artifact (flaw 3),
and any `default_rpm_packages.fips` group had its version resolved but was
never installed into the image.

**Fix.** New module `hb_packages.py` implements the rule once
(`package_keys`, `resolve_package_set` → `main` / `build` / `arch_entries` /
`arch_packages`). `generate_rpms_in.py` and `generate_jinja2.py` both consume
it, and `package_args.yml.j2` shrank from 40 lines of key-walking Jinja to two
`join(' ')` calls. Sets are sorted and deduplicated, so the `ARG` line is
stable across runs (a reordered package list invalidates every downstream layer).

**Regression.** D2, D3, D7, plus the resolver's key matrix exercised through B/D.

---

## S2 — supported configurations that broke

### 6. Missing `oscap:` key aborted generation

**Symptom.** Any image whose merged config had no `oscap` section failed to
generate at all — including plain runtime images that never intended to scan.

**Cause.** `_compute_oscap_config` returned early without defining
`variables["oscap"]`, while `oscap-tailoring.xml.j2` (rendered for every row)
and `install_newroot.yml.j2` read `oscap.enabled` directly. Under
`jinja2.StrictUndefined` an attribute access on an undefined name raises before
the `| default(false)` filter can help.

**Evidence:**

```
$ generate_jinja2.py templates/oscap-tailoring.xml.j2 .../oscap-tailoring.xml
jinja2.exceptions.UndefinedError: 'oscap' is undefined
$ generate_jinja2.py images/curl/Containerfile.j2 .../Containerfile
jinja2.exceptions.UndefinedError: 'oscap' is undefined
```

`install_newroot.yml.j2` guarded one `oscap` use with `oscap is defined` and the
next one without — evidence the failure had been hit before and patched locally.

**Fix.** `_compute_oscap_config` always writes a normalised `oscap` dict
(`enabled`, `profiles`, `exclude_rules`, `datastreams`, `crypto_policy`,
`crypto_policy_variants`, `active_profiles`, `profile_exclude_rules`,
`has_tailoring`), and accepts `enabled: "true"` as well as `enabled: true`.
All defensive `is defined` / `| default(false)` guards were removed from the
macros, which are now readable as plain conditions.

**Regression.** E1–E4 (renders, no traceback, no empty tailoring file).

---

### 7. `.gitmodules` never found; `git submodule` mis-invoked

**Symptom.** Source builds (`build_from_source: true`) could not resolve
submodule versions, and crashed instead of falling back.

**Cause.** Two independent defects:

1. `ci_hummingbird_generate` copied `.gitmodules` to
   `images/<name>/.gitmodules`, but `ImageContext` looked only at
   `base_dir/.gitmodules` (`.hbgen/.gitmodules`) — a path nothing ever wrote.
2. `get_submodule_hashes` ran bare `git submodule` with `check=True`. That
   subcommand prints usage and exits 128 outside a submodule-configured work
   tree.

**Evidence:**

```
base_dir/.gitmodules exists?   False      → parse_gitmodules → {}
image_dir/.gitmodules exists?  True       → never consulted
subprocess.CalledProcessError: Command '['git','submodule']' returned non-zero exit status 128
jinja2.exceptions.UndefinedError: 'gitmodules' is undefined   (build_from_source: true)
```

**Fix.** `_load_gitmodules` searches the image dir then the work-tree root (both
upstream and driver layouts); the git call is `git submodule status`, run
non-fatally with `check=False` and an `OSError` guard, so an unavailable git
degrades to `unknown` instead of aborting; `gitmodules` is **always** defined in
the template context because `package_version.yml.j2` subscripts it.

**Regression.** covered by the render suite (no traceback on the source path);
the git fallback is unit-visible through `get_submodule_hashes(search_dir)`.

---

### 8. Configuration errors surfaced as Python tracebacks

**Symptom.** Operators got `KeyError: 'default_variants'`,
`TypeError: 'NoneType' object is not subscriptable` or `KeyError: 'stream'`
with no indication of which file to fix.

**Evidence:**

```
$ aggregate_properties.py            → KeyError: 'default_variants'
$ aggregate_properties.py (empty yml)→ TypeError: 'NoneType' object is not subscriptable
$ generate_jinja2.py (no stream:)    → KeyError: 'stream'
                                       labels["io.hummingbird-project.stream"] = props["stream"]
```

**Fix.** `hb_config.load_yaml` / `require_keys` / `ConfigError` validate inputs
and report **all** missing keys at once, naming the file and its role; entry
points catch `ConfigError` and print one line. `generate_jinja2` validates the
required property set (`description`, `summary`, `url`, `stream`, `tags`) up
front, and reports an unknown image name with the list of known ones.

```
[hbgen] error: properties.yml of image 'curl' is missing required key(s): stream
[hbgen] error: images/variables.yml is missing required key(s): default_variants
[hbgen] error: variables.yml (shared defaults) is empty: /…/variables.yml
[hbgen] error: /…/curl is not a hummingbird builder: missing Containerfile.j2
```

**Regression.** E6–E13, each paired with a "no traceback" assertion.

---

### 9. Matrix loop read its row list from stdin

**Symptom.** Some matrix rows were silently never built.

**Cause.** `ci_hummingbird_generate` and `ci_hummingbird_build` iterated with
nested `while IFS= read -r … done <<< "${variants}"`. The here-string *is* the
loop's stdin, so any command in the body that reads stdin consumes the remaining
rows. The body calls `ci_build_and_push` → registry logins, engine calls, git,
`ssh`-style helpers — any of which can read stdin.

**Evidence** (minimal reproduction):

```bash
variants="default
builder"
while IFS= read -r v; do count=$((count+1)); head -c 40 >/dev/null; done <<< "$variants"
# variants seen: 1 (expected 2)
```

**Fix.** Rows are read once with `mapfile` and iterated with `for`, and the
nested distro/variant loops were replaced by the single `hbgen.py matrix`
row list. The regression test's stubbed `ci_build_and_push` deliberately reads
stdin to prove the loop survives it.

**Regression.** F9 (7 rows built despite a stdin-reading build step).

---

### 10. `${1:?}` in a sourced function killed the caller's shell

**Symptom.** A driver called with an empty builder directory terminated the CI
job's shell instead of returning an error.

**Cause.** `local dir="${1:?missing image directory}"` — bash writes the message
and **exits the non-interactive shell**. These libraries are sourced into
consumer build scripts, so the consumer's script died mid-run.

**Evidence:**

```bash
f() { local d="${1:?missing image directory}"; }
f            # → "1: missing image directory"
echo never   # → never printed; caller exit=1
```

`universal-ci.sh` can legitimately pass an empty `image_dir` (e.g. `-f
hummingbird` with no resolvable builder), so this was reachable.

**Fix.** `ci_hummingbird_require_builder` validates explicitly and returns 1
with an actionable message; `${1:?}` is gone from the flavour driver.
`universal-ci.sh` initialises `HB_BUILT_IMAGES` before the call so the cleanup
path is safe under `set -u`.

**Regression.** F7 (the caller shell survives and prints `survived`).

---

### 11. `CONFIG` keys leaked between matrix rows

**Symptom.** A row could push to a registry configured for a previous row.

**Cause.** `CONFIG` is process-wide and `ci_hummingbird_configure` only ever
*added* keys. `build_registries_array` walks `DF_REGISTRY_0,1,2,…` until the
first gap, so leftovers beyond the current row's count were picked up. The same
applied to `PLATFORMS`, `CUSTOM_TAGS`, `TAG_STRATEGY` and `CHUNKAH`.

**Evidence:**

```bash
CONFIG[DF_REGISTRY_2]=c                 # row 1 had three registries
# row 2 defines only 0 and 1 →
keys after: DF_REGISTRY_0=x DF_REGISTRY_1=y DF_REGISTRY_2=c   # stale entry pushed to
```

**Fix.** `ci_hummingbird_reset_config` unsets the keys this module owns before
each row (never a blanket `CONFIG=()`, which would drop the `GIT_*` metadata the
engine still needs).

**Regression.** F19.

---

## S3 — maintainability, performance, robustness

### 12. 49 MB of SCAP datastreams in every build context

`ci_hummingbird_generate` copied **all** `oscap/*.xml` (28 MB + 22 MB) into
`.hbgen/images/<image>/oscap/` for every image, although the hummingbird
datastream is baked into the builder image and ubi datastreams are only read by
`verify-compliance` for the distros that declare one. The engine reads the build
context once per matrix row.

```
before: .hbgen/images/curl = 49 MB   (8 rows → context read 8 times)
after:  hummingbird-only build        = 65 KB
        hummingbird + ubi9 build      = 27 MB (rhel9 datastream only)
```

**Fix.** `hbgen.required_oscap_datastreams` selects datastreams from the
*effective* oscap section (`hb_config.effective_section`, so an image that
enables oscap in its own `properties.yml` is handled like one that enables it in
`variables.yml`) restricted to the selected distros, minus `hummingbird`.
A missing vendored datastream warns instead of failing silently at scan time.

**Regression.** A8, A9.

### 13. Deep merge implemented three times with two semantics

`ci_hummingbird_distros` and `ci_hummingbird_generate` each embedded the same
Python `merge()` (lists **replace**), while `ImageContext._deep_merge` used lists
**concatenate** — two different rules for what looks like one operation, with no
documentation of which applies where.

**Fix.** One implementation, `hb_config.deep_merge(base, overlay, list_policy)`,
with named policies (`LIST_POLICY_REPLACE` for `variables.yml` overlays,
`LIST_POLICY_EXTEND` for the properties overlay feeding templates) and a
docstring explaining why they differ.

**Regression.** A3, A4.

### 14. Seven inline Python snippets in the bash driver

Seven inline snippets, verified by counting `<<'PY'` and `python3 -c` at
`cfad902` (lines 151, 204, 281, 488, 514, 561, 610). They covered eight
purposes, because the first snippet both merged `variables.yml` and resolved
distros: variables merge (×2), distro resolution, variant list (×2 — one from
the properties cache via `python3 -c`, one from `properties.yml`), `skip_push`,
registries, platforms. None was testable, all duplicated parsing rules, and any
consumer without `pyyaml` got a raw traceback.

**Fix.** `hbgen.py` — one CLI, one subcommand per stage
(`prepare`, `rpms`, `matrix`, `render`, `config`, `vars`, `variants`,
`distros`). `ci-hummingbird.sh` now contains **no** inline Python; every
interpreter call goes through one wrapper, `ci_hummingbird_python`, which invokes
only `hbgen.py` and `aggregate_properties.py`. (`generate_rpms_in.py` and
`generate_jinja2.py` are called by `hbgen.py`, not by bash.) Each subcommand is
runnable by hand, which is also the debugging workflow.

**Result.** 702 → 585 lines of bash (−17%) with more functionality, and the
behaviour it used to embed is now unit-testable. One inline heredoc remains
elsewhere in the repository — `ci-yaml.sh:41`, in the Dockerfile flavour — and
was left alone as out of scope.

### 15. Duplicated resolution logic and loops

- The `repo_vars` / `builder_vars` / `vars_base` block plus its error message
  appeared twice → `hbgen.resolve_variables_files`.
- The nested `distro × variant` while-read loop appeared three times (rpms,
  render, build) → `_matrix_for` in Python, one `for` loop in bash.
- `ci_hummingbird_distros` was computed twice per run (driver + generate) →
  resolved once per stage from the same inputs.
- The `.hbgen` path was rebuilt by string concatenation in six places →
  `ci_hummingbird_worktree` / `ci_hummingbird_context` / `ci_hummingbird_variant_dir`.
- `get_rpm_versions.sh` scanned every `rpms.in.yaml` twice (once for packages,
  once for repos) → one pass writing both lists.
- Its four-way `if/elif` ladder around one `dnf repoquery` call (32 near-identical
  lines, there to dodge empty-array expansion under `set -u` on bash < 4.4) →
  a single call using `"${arr[@]+"${arr[@]}"}"`.

### 16. Chunkah archive cleanup pattern never matched the archive

`ci-build.sh` cleaned `"$context"/out-*.ociarchive`, but the hummingbird final
stage writes `out.ociarchive` (no `-arch`): the engine's stated intent never ran,
and a full rootfs archive stayed in the work tree.

**Fix — deliberately not a glob change.** Widening the pattern to
`out*.ociarchive` would delete the archive *between* matrix rows. `FROM
oci-archive:out.ociarchive` is resolved from the build context, and when the
engine replays the producing `RUN` from its layer cache the file is not
rewritten — the next row would fail with "archive file not found". So the
per-build pattern is documented with that reasoning, and the hummingbird driver
removes `out*.ociarchive` once, after the last row
(`ci_hummingbird_cleanup_archives`).

**Regression.** F26.

### 17. Helper function leaked globally; dead search branch

`ci_hummingbird_find_image` defined `search_dir()` *inside* itself. Bash
functions defined in a function body become global after the first call, so it
could shadow a consumer's own `search_dir`. Its "Priority 3" branch then looped
`"$BUILDERS_DIR"/*` and compared `basename == name` — the same test as Priority
1 (`$BUILDERS_DIR/$name`), i.e. unreachable.

```
before: declare -F search_dir → not defined
after : declare -F search_dir → DEFINED (leak)
```

**Fix.** No nested function; the search reuses `ci_hummingbird_detect_flavor`
and tries exactly two locations. `[[ -n "$BUILDERS_DIR" ]]` also became
`${BUILDERS_DIR:-}` — the unguarded form aborts under `set -u`, which consumer
scripts commonly enable.

**Regression.** F4–F6.

### 18. Dead code

- `ci_hummingbird_read_variants` — defined, documented, never called (the driver
  reads the authoritative list from the cache after aggregation). Removed;
  `ci_hummingbird_variants` remains as the public accessor.
- `for gen in …; do [[ -x … ]] || chmod +x …; done` — the generators are invoked
  as `python3 <script>`, so the executable bit is irrelevant; worse, it **mutated
  the checked-out source tree** (a `100644 → 100755` git diff) from a read-only
  build step. Removed.
- `ci_hummingbird_generate`'s `case "${template}" in *VERSION.j2)` mapping —
  replaced by the declarative `VARIANT_TEMPLATES` table in `hbgen.py`.

### 19. `-i <name>` builds failed to detect a builder in `SOURCE_DIR`

`main_build` resolved the builder directory with `if [[ -n "$image_name" ]]; then
image_dir=$(ci_hummingbird_find_image …); elif …SOURCE_DIR…`. When `-i` was given
and the name did not resolve under `BUILDERS_DIR`, `image_dir` stayed empty and
the `SOURCE_DIR` branch was skipped — so a hummingbird checkout in `SOURCE_DIR`
was misdetected as the Dockerfile flavour and failed with "Dockerfile not found".

**Fix.** Both lookups always run: `BUILDERS_DIR/<name>` first, then `SOURCE_DIR`;
`ci_hummingbird_detect_flavor` decides.

### 20. Hard-coded `CHUNKAH`, empty artifacts, unavoidable engine stage

- `CONFIG[CHUNKAH]="true"` was set unconditionally. A `Containerfile.j2` that
  never calls `final_stage()` has no oci-archive step, yet still paid for the
  chunkah workarounds (bind mount, serialised platform builds, `--cap-add`).
  Now detected from the rendered Containerfile (`hbgen._detect_chunkah`).
- `oscap-tailoring.xml` was written for every row even when empty (1 byte),
  cluttering the work tree with files that look generated. Empty renders are now
  skipped with an explicit message.
- Stage 4 always needed a container engine and repository access, with no escape
  hatch. `HB_SKIP_RPM_VERSIONS=true` skips it (documented consequence: versions
  fall back to `latest`), and `HB_RPM_VERSIONS_TTL=<seconds>` reuses a fresh
  cache.
- `VERSION` reading `unknown` (no version resolvable) now falls back to `latest`
  **and warns**. The matching fix for the *tag list* was not part of this change
  and was found later — see finding 30.
- `HB_PYTHON` selects the interpreter for every generator, including
  `get_rpm_versions.sh` (which previously hard-coded `python3`, so a venv-based
  toolchain broke only at stage 3).

**Regression.** F17, F27, E4, D20.

### 21. Documentation gaps

- `README.md` and `CLAUDE.md` mentioned hummingbird **zero** times, although it
  is the largest and most intricate subsystem (a 702-line driver, four
  generators, eleven macros, 49 MB of vendored SCAP data).
- `AGENTS.md`, `context/` and `tests/` did not exist.
- `build/lib/ci-ecr.sh` had a stray comment line above its shebang, so the
  shebang was not on line 1 (shellcheck `SC1128`, error level).

**Fix.** This folder, `AGENTS.md` (with runnable hooks and the invariant list),
`tests/hummingbird/` with its own README, a hummingbird section in `README.md`,
and the `ci-ecr.sh` shebang restored to line 1.

---

## Found outside the hummingbird builder

The audit sweep (`shellcheck -x -S warning` across all 26 shell files, plus
reading every file the hummingbird path touches) turned up nine more defects in
the shared engine, the `docker/` scripts and the README itself. They are not hummingbird bugs, but
they are in code this pipeline runs through, so they were fixed here rather than
left for someone else to rediscover.

The repository is now **shellcheck-clean at warning level across all 26 shell
files** (it was 21 warnings before this pass).

### 22. `INSTALL_BINFMT` was a knob that did nothing (S2)

`ci_setup_buildx` read it into a local — `local install_binfmt="${INSTALL_BINFMT:-auto}"` —
and then never referenced it. Multi-platform builds always attempted to install
QEMU emulators, so a runner without `--privileged` (a common CI restriction) had
no way to opt out; it could only watch the build fail.

Fixed by honouring three modes, with `auto` preserving the historic behaviour
exactly. Verified against a stubbed engine by counting install attempts:

| `INSTALL_BINFMT` | install attempts | log |
| --- | --- | --- |
| unset / `auto` | 1 | `Missing emulators: arm64 - attempting installation` |
| `false` | **0** | `INSTALL_BINFMT=false: not installing missing emulators: arm64` |
| `force` | 1 | reinstalls even when already registered |
| anything else | 1 | `Unknown INSTALL_BINFMT='…' (expected auto|false|force) - using auto` |

The same edit removed a shellcheck `SC2178`/`SC2128` pair caused by
`ci_ensure_binfmt_support` reusing the name `required_arches` for a *string*
while `ci_get_required_binfmt_arches` used it for an *array* — a genuine
readability trap even though the two are separate function scopes.

### 23. `re-source.sh` could not work on Linux at all (S2)

Two independent defects in a 21-line script:

- `Replace()` used `sed -i ''` — BSD/macOS syntax. GNU sed reads `''` as a
  filename and exits 2 (`sed: can't read : No such file or directory`), so **every
  replacement silently did nothing on Linux**. Verified: `exit=2` before,
  `exit=0` after switching to the portable `sed -i.bak … && rm -f *.bak`.
- `#!/bin/sh` with `read -d $'\0'` — a bash extension. On any system where
  `/bin/sh` is dash or busybox ash the rename loop fails outright.

Also fixed while rewriting: unquoted `$file`/`$me`, backticks, `echo` for `\t`
(now `printf %b`), and `grep -rl` → `grep -rlI` so binary files are skipped
instead of being corrupted by sed. Behaviour verified end-to-end on a scratch
tree: text rewritten, binary left intact, file renamed, no stray `.bak`, and the
script no longer rewrites its own token list.

### 24. `find_dockerfile` leaked two global functions and aborted under `set -u` (S2/S3)

The same class as flaw 17, in the Dockerfile flavour this time: `search()` and
`try_search()` were defined *inside* `find_dockerfile`, so they became global on
first call and could shadow a consumer's own functions. A third local, `found`,
was assigned and never read.

The `set -u` exposure is narrower than flaw 17's but real: `ci-core.sh` normally
defines `BUILDERS_DIR`/`SOURCE_DIR`, yet a consumer that pre-sets
`CI_CORE_LOADED` (or supplies its own core) skips that sourcing — then the bare
`"$BUILDERS_DIR"` test aborts their job. Measured both ways:

| | exit | output |
| --- | --- | --- |
| original, `CI_CORE_LOADED` preset + `set -u` | 1 | *(nothing — caller died silently)* |
| rewritten | 0 | `REACHED END (find_dockerfile exit=1)` |

Rewritten as a flat, ordered candidate list (`dir|pattern`) with one loop — no
nested functions, no dead variable, `${VAR:-}` throughout. Search priority
verified **byte-identical** to the original across four scenarios (both dirs set
with and without a name, `SOURCE_DIR` only, `BUILDERS_DIR` fallback).

### 25. `go-setup.sh` ran the Go build in the wrong directory on failure (S2)

`cd ${HOME}/go` with no guard: if that directory is missing, `go mod init` and
`go build` execute in whatever directory the image build happens to be in. Fixed
to `cd "${HOME}/go" || exit 1`, with `$PATH` and the `-o` target quoted.

### 26. Instana plugin scripts: bare redirection and write-only bookkeeping (S3)

`> "$CONF_FILE"` with no command (shellcheck `SC2188` — valid, but reads like a
typo and is fragile under `set -e`) → `: > "$CONF_FILE"`. Two associative arrays
(`seen_modules`, `installed_modules`) were assigned per module and never read;
both removed. Note that deleting only the `declare -A` would have changed
semantics — `arr[string]=1` without the declaration creates an *indexed* array
with the key evaluated arithmetically — so the assignment went too.

### 27. `venv.sh`: masked failures and dead version parsing (S3)

Two `local x=$(cmd)` forms (`SC2155`) that always return 0 and hide the command's
status; the `mktemp -d` one mattered, since a failure would leave
`cleanup_python_install` running `rm -rf ""`. Both split into declare + assign.
`min_major`/`min_minor` were parsed out of `MIN_PYTHON_VERSION` and never used —
`version_compare` takes the full `major.minor.micro` strings — so the dead
decomposition was removed.

### 28. `ci-utils.sh`: "security" regexes that validated nothing (S3)

Three `readonly REGEX_*` constants sat under a `# …for Input Validation
(Security)` comment with no caller anywhere in the repository — decoration that
implied a guard that did not exist. They were **not** simply wired in:
`REGEX_IMAGE_NAME` is `^[a-zA-Z0-9/_.-]+$`, which excludes `:`, so applying it to
a real reference like `us.icr.io/ns/curl:8.21.0` would reject every tagged image
and break working builds.

Instead: the constants are kept (they are `readonly` globals a consumer may
already source) with an accurate comment about what each matches, and a new
opt-in `ci_validate_image_ref()` splits `repo[:tag]` and validates each part with
the right pattern. It is deliberately *not* called from
`remove_docker_images`/`sign_with_cosign` — those already quote their arguments,
and rejecting a reference there would turn a warning into a hard failure for
consumers. Verified: accepts `us.icr.io/ns/curl:8.21.0`, `curl`, `curl:latest`,
`ghcr.io/org/img:1.2.3-rc1`; rejects `bad ref!:x`, `img:ta g`, and `""`.

The remaining `SC2034`s in `ci-core.sh` and `ci-artifacts.sh` were annotated
rather than removed, because both are false positives with a reason: the
`ci-core.sh` globals (`CONFIG`, `REGISTRIES`, `CI_BUILT_IMAGES`,
`CI_LAST_BUILT_IMAGES`, `CI_CORE_LOADED`) are the library's public contract read
by other files and by consumers, and the `ci-artifacts.sh` locals are positional
`read` placeholders that must be consumed for the wanted fields to land
correctly. Each now carries a `WHY` saying so, which is also the answer to the
next engineer who wonders whether they are dead.

### 29. Three documented tag strategies did not exist (S2)

`README.md` listed `version-only`, `latest-only` and `git-sha` as tag strategies.
`ci_generate_tag()` implements none of them — the real names are `version`,
`latest` and `sha`. Because the `case` ends in a catch-all that echoes `latest`,
an engineer who copied the documented value got a **silently wrong tag**: the
image published as `:latest` instead of the version-only tag they asked for, with
nothing in the log to explain it.

Verified empirically before the fix:

| `TAG_STRATEGY` | tags produced | log |
| --- | --- | --- |
| `version` | `1.2.3` | — |
| `version-only` | `latest` | *(nothing)* |
| `git-sha` | `latest` | *(nothing)* |
| `latest-only` | `latest` | *(nothing)* |

This is the same class as finding 22: a documented knob whose value is not
actually honoured, made worse by a fallback that hides the mismatch.

**Fix.** Three parts:

1. The catch-all now warns and still returns `latest`, so existing pipelines keep
   working but the mismatch is visible:
   `[WARN] Unknown TAG_STRATEGY='version-only' - falling back to 'latest'. Valid: version, runner, sha, latest, tag, custom, and the -latest/-runner/-sha combinations`.
   An *unset* strategy cannot trigger this — it defaults to `version-latest`
   before the `case`, so only a genuinely misspelled value reaches the branch.
2. `README.md` now carries the full strategy table generated from the actual
   `case` arms, with an explicit note that `version-only`/`latest-only`/`git-sha`
   do not exist.
3. `context/architecture.md` listed the same three phantom names — I had copied
   the README's error into my own document. Corrected to the fourteen real
   strategies.

Worth noting as a process lesson: the audit cross-check that caught this compared
every backticked identifier in the docs against the code. It flagged my own new
document, not just the pre-existing one.

### 30. Unresolved versions still published literal `:unknown` tags (S1)

Found by executing the debug commands this report tells engineers to run, with no
package-version cache present — i.e. the `HB_SKIP_RPM_VERSIONS=true` path that
finding 20 documented as supported.

Finding 20 fixed only half the problem. `_resolve_version` correctly turned an
unresolved `VERSION` into `latest` and warned, but `_resolve_tags` returned the
rendered `TAGS` file **verbatim**. Because those tags are published through
`TAG_STRATEGY=custom`, which makes the engine echo `CONFIG[CUSTOM_TAGS]` as-is,
the image was still pushed under literal `unknown` tags:

```
$ hbgen.py render …            # no version cache
VERSION → unknown
TAGS    → unknown / unknown / latest          (hummingbird/default)
        → unknown-fips / unknown-fips / latest-fips   (hummingbird/fips)

$ hbgen.py config …
HBGEN_VERSION   latest                        # fixed by finding 20
HBGEN_TAGS      unknown unknown latest        # NOT fixed -> two bogus tags pushed
```

`TAGS.j2` appends the variant suffix, so the value is `unknown-<variant>` for
every non-default variant — a filter matching only the exact string `unknown`
would have missed all of them.

**Fix.** `_resolve_tags` now drops any tag that is `unknown` or starts with
`unknown-`, removes duplicates while preserving order (the engine treats the
first entry as the primary tag, so sorting would change behaviour), warns with
the count and the survivors, and falls back to the resolved `VERSION` if every
rendered tag was unresolved:

```
HBGEN_TAGS  latest-fips
[hbgen] warning: …/fips/TAGS: dropped 2 tag(s) with an unresolved version (kept: latest-fips)
```

A new `_dedupe` helper keeps first-seen order, and `_is_unresolved_tag` owns the
`unknown` / `unknown-<variant>` rule in one place.

**Regression.** F28 (no `unknown` tag reaches `CONFIG[CUSTOM_TAGS]`), F29
(`VERSION` fallback), F30 (the drop is reported), and F31/F32 as a guard against
over-reach — a fully resolved list must still pass through intact, deduplicated
and in order.

**Two process notes.** First, writing the test exposed a trap worth recording:
capturing the driver's stderr with `stderr="$(ci_hummingbird_configure …)"` runs
the function in a **subshell**, so its writes to the global `CONFIG` array are
silently discarded and the following assertions read stale values. Stderr is now
redirected to a file. Second, this finding contradicted a "fixed" claim already
published in this report; the claim in finding 20 has been narrowed to what was
actually true at the time.

## Deliberate behaviour changes

Call these out in release notes; they are fixes, but they change output:

1. **`ubi9/fips`-style rows are no longer built** when `additional_variants`
   restricts the variant's distros (flaw 2).
2. **`ARG MAIN_PACKAGES` is sorted and deduplicated**, and now includes modifier
   and base package groups for composite variants (flaws 3, 5). Existing layer
   caches invalidate once.
3. **`.cache/rpm-versions.yml` is nested under `distros:`** (flaw 1). Flat caches
   are still read, so a stale cache does not break a build.
4. **`name=` labels for non-builder variants no longer carry the variant
   suffix** (flaw 4); the variant remains in
   `io.hummingbird-project.variant*` labels and in the tags.
5. **Empty `oscap-tailoring.xml` is not written** (flaw 20).
6. **Composite builder variants publish `<image>-builder`** (flaws 3, 4) — e.g.
   `fips-builder` moves from `<image>` to `<image>-builder`.

## Suggested follow-ups (not done here)

| Idea | Value | Cost |
| --- | --- | --- |
| Fetch SCAP datastreams from a release artifact instead of vendoring 49 MB in git | repository size, clone time | needs a download step + checksum |
| Per-row `out-<distro>-<variant>.ociarchive` + `--no-cache` on the final stage | removes the archive lifetime coupling entirely | slower builds |
| Publish a JSON build report per run (rows, digests, versions, profiles) | auditability, promotion tooling | new artifact contract |
| Parallelise independent matrix rows | wall-clock time | chunkah's shared `/run/src` bind mount must become per-row |
| `hbgen.py lint` for builders (unknown keys, missing descriptions, unused repos) | shift-left config errors | new command |
| Lockfile mode (`rpms.lock.yaml`) as the default once hermetic builds are required | reproducibility | needs lockfile tooling in the builder image |
