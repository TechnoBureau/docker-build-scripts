# tests/

Offline regression tests for the build scripts.

The CI engine itself (`ci-build.sh`, `ci-registry.sh`, …) needs real registries,
a container engine and credentials, so it is not unit-tested here. What **is**
tested is everything that decides *what gets built*: the hummingbird generators,
the work-tree layout, the build matrix, version resolution, rendering semantics
and the contract between the bash driver and the Python pipeline.

## hummingbird/

```
tests/hummingbird/
├── run-tests.sh          99 assertions, 6 groups, offline (~6s)
├── stubs/podman          stub container engine (answers `dnf repoquery`)
└── fixtures/
    ├── builders/
    │   ├── variables.yml         shared defaults (distros, registries, oscap, packages)
    │   └── curl/                 full builder: oscap on, two distros, four variants
    │       ├── properties.yml    incl. additional_variants restricted to hummingbird
    │       ├── variables.yml     per-image overlay (deep-merge coverage)
    │       └── Containerfile.j2  exercises macros, is_builder, oscap, labels
    ├── no-oscap/                 second builders root, for the oscap-absent path
    │   └── builders/
    │       ├── variables.yml     no oscap section at all
    │       └── hello/            minimal builder: no oscap, no variants
    └── rpm-versions.tsv          canned `dnf repoquery` output, per distro
```

### Run

```bash
# PyYAML + Jinja2 must be importable by the interpreter you point at
HB_PYTHON=/tmp/hbvenv/bin/python ./tests/hummingbird/run-tests.sh

# Run one GROUP while iterating (keyword, not group letter)
./tests/hummingbird/run-tests.sh -k prepare    # A
./tests/hummingbird/run-tests.sh -k matrix     # B
./tests/hummingbird/run-tests.sh -k versions   # C
./tests/hummingbird/run-tests.sh -k render     # D
./tests/hummingbird/run-tests.sh -k errors     # E
./tests/hummingbird/run-tests.sh -k driver     # F

# Report only assertions whose NAME matches (every group still executes)
./tests/hummingbird/run-tests.sh -t fips
./tests/hummingbird/run-tests.sh -t "A4 overlay"

./tests/hummingbird/run-tests.sh -h                 # usage
HB_TEST_KEEP=1 ./tests/hummingbird/run-tests.sh     # keep the work dir for inspection
```

`-k` selects a group; `-t` narrows reporting by assertion name. Each group is
**self-sufficient**: the pipeline stages are cumulative
(`prepare → aggregate → rpms → versions → render`), so `ensure_stage` runs any
stage a selected group depends on but did not execute itself, at most once per
run. `-k render` therefore passes on its own.

Exit code is `0` only when every *reported* assertion passes, and the summary
restates any active filter so a green filtered run is never mistaken for a green
full run:

```
Summary
  passed: 14
  failed: 0
  assertion filter (-t): fips  (other assertions ran but were not reported)
```

A failure prints its group, its id, the expectation and the actual value.

### Groups

| Group | Ids | Filter | Covers |
| --- | --- | --- | --- |
| A — work tree | A1–A9 | `prepare` | `hbgen prepare`: `.hbgen` layout, merged `images/variables.yml` (overlay applied, list **replace** policy), `Containerfile.j2` and distro repo files copied into the build context, `ci/get_rpm_versions.sh` linked, **selective** oscap datastream copying |
| B — matrix | B1–B10 | `matrix` | `aggregate_properties` cache + `hbgen matrix`: per-variant distro restrictions honoured, variant decomposition, published image names, row count |
| C — versions | C1–C11 | `versions` | `rpms.in.yaml` generation and `get_rpm_versions.sh` against the stub engine: cache keyed **per distro**, no duplicate keys, epoch stripping |
| D — render semantics | D1–D23 | `render` | The rendered Containerfile/VERSION/TAGS: `ARG MAIN_PACKAGES` per variant and distro, builder dnf defaults, licence/locale retention, `name=` label vs published repository, oscap profiles, crypto policy |
| E — robustness | E1–E13 | `errors` | Error paths: missing `oscap`, empty `variables.yml`, missing required properties, unknown image, bad `HB_VARIANTS`, non-builder directory — each asserted to produce an actionable message **and no traceback** |
| F — driver contract | F1–F32 (+F13b) | `driver` | `ci-hummingbird.sh` with stubbed engine functions: flavour detection, builder search, validation that returns instead of killing the caller, `CONFIG` reset, stdin-safe matrix loop, chunkah detection, archive-cleanup timing, config precedence, and that unresolved `unknown` tags are never published |

### How it stays offline

- **No container engine.** `stubs/podman` is prepended to `PATH`; it answers the
  `dnf repoquery` invocations from `fixtures/rpm-versions.tsv`. The suite
  asserts the *generated artifacts*, never a real image.
- **No network.** Fixtures are self-contained; the vendored tree is symlinked
  into a throwaway work directory.
- **No writes to the checkout.** Fixtures are copied to a temp dir per run
  (`HB_TEST_KEEP=1` preserves it for inspection).
- **Self-maintaining stub tree.** The suite copies every `*.py`/`*.sh` from
  `build/lib/hummingbird/` into the work tree, so adding a module cannot
  silently break it.

### Assertion helpers

Defined at the top of `run-tests.sh`:

| Helper | Signature |
| --- | --- |
| `assert_eq` | `<id+name> <expected> <actual>` |
| `assert_contains` / `assert_not_contains` | `<id+name> <haystack> <needle>` |
| `assert_file` / `assert_no_file` | `<id+name> <path>` |
| `assert_fails_with` | `<id+name> <combined output+status> <needle>` |
| `assert_no_traceback` | `<id+name> <stderr>` |

Support helpers: `hbgen` (runs `hbgen.py` with the suite's interpreter),
`variant_dir <distro> <variant>`, `read_file <path>`, `matches_filter <name>`,
`skip_remaining <reason>`. Group B defines a local `row_for <distro> <variant>`
that matches a matrix row with `awk` field equality — **never** substring-match a
TAB-separated row (`"ubi9\tfips"` is a substring of `"ubi9\tfips-builder"`).

### Adding an assertion

1. Reproduce the behaviour with a fixture (add to `fixtures/builders/`, or to
   `fixtures/no-oscap/` if the point is an absent configuration section).
2. Put the assertion in the group that owns it, with the next free id, and name
   it after the behaviour rather than the implementation.
3. If it locks in a fixed flaw, cross-reference it from
   `context/flaw-report-hummingbird.md` (the "Regression" line) and, if it is a
   hard guarantee, from `AGENTS.md` §3.

### Known limits

- End-to-end builds (`ci_build_and_push`, real `dnf-installroot`, real
  `verify-compliance`) cannot run without an engine and registry credentials;
  the suite stops at the generated Containerfile.
- Arm64 behaviour is asserted only through the generated `case "${TARGETARCH}"`
  branches, not through a real cross-build.
- The shared engine (`ci-build.sh`, `ci-registry.sh`, `ci-artifacts.sh`) has no
  suite of its own; changes there are covered only by shellcheck plus the
  hummingbird driver-contract group, which stubs the engine out.
