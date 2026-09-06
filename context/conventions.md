# Conventions

How code in this repository is written. Follow these so a reviewer can focus on
behaviour instead of style, and so an agent produces diffs that belong here.

## 1. Language boundaries

| Layer | Language | Rule |
| --- | --- | --- |
| Orchestration, logging, container engine | bash | Never parse YAML/JSON in bash |
| Configuration, matrix, rendering | Python 3.10+ | Never invoke the container engine from Python |
| Generated image content | Jinja2 | Never compute package sets or names in Jinja |

The seam between them is narrow and explicit: bash calls `hbgen.py` subcommands
and reads **TAB-separated** or **line-separated** output. No `eval` of generated
text, no shell quoting rules to reason about.

## 2. Bash

### Structure

```bash
#!/usr/bin/env bash
# lib/ci-<area>.sh
#
# Purpose:      one paragraph — what and why, not how
# Usage:        source lib/ci-<area>.sh
# Public functions:  name <args> -> effect
# Environment:  VAR   meaning (default)

if [[ -z "${CI_CORE_LOADED:-}" ]]; then
    LIB_DIR="${LIB_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
    source "${LIB_DIR}/ci-core.sh"
fi

# =====…=====
# function_name
# Purpose / Input / Output / Returns   (WHY: … when non-obvious)
# =====…=====
function_name() { … }
```

### Rules

- **Prefix by subsystem**: `ci_*` for engine functions, `ci_hummingbird_*` for
  the flavour, `hb_*`/`hbgen` for the Python side.
- **Libraries return, they never exit.** No `exit` and no `${1:?}` inside a
  function — these are sourced into consumer scripts, and both terminate the
  caller's shell. Validate and `return 1` with `log_error`.
- **Always default your expansions**: `${VAR:-}`, `${arr[@]+"${arr[@]}"}`.
  Consumers run with `set -euo pipefail`; an unbound variable aborts their job.
- **No nested function definitions.** A function defined inside a function
  becomes global on first call and can shadow the consumer's own functions.
- **Iterate arrays, not stdin.** `mapfile -t rows < <(cmd)` then `for row in
  "${rows[@]}"`. A `while read … done <<< "$list"` loop hands its own row list to
  anything in the body that reads stdin.
- **`local` everything**; declare and assign separately when the return status
  matters (`local x; x="$(cmd)"`).
- **Multi-line commands need continuations.** A bare newline inside `<( … )`
  splits the command (shellcheck `SC2215`) — build an args array instead.
- **Portable file edits**: `sed -i.bak … && rm -f *.bak` (BSD/GNU), or do it in
  Python. Never `sed -i ""`.
- **Log with the core helpers** (`log_info`, `log_warn`, `log_error`,
  `log_success`, `log_debug`). Warnings and errors go to stderr.
- **Guard destructive operations.** Validate the path before `rm -rf`
  (`hbgen._recreate_tree` refuses anything not named `.hbgen`).

### Comments

Comment **why**, never what. The convention in this repository is a `WHY:`
prefix for anything a future reader might "simplify" into a bug:

```bash
# WHY --no-cache for chunkah: its bind-mounted OCI archive is not a layer
# output. Retaining the file does not make a cached RUN safe across target
# architectures; the next worker must recreate its own archive.
```

Keep useful `WHY:` comments, and update obsolete ones when the contract changes.

## 3. Python

- Python 3.10+ typing (`dict[str, Any]`, `X | None`), `from __future__ import
  annotations` where needed.
- **Module docstring states the contract**: what it owns, who calls it, what the
  data shapes are. These modules are the documentation for the pipeline.
- Small pure functions over classes; the one class (`ImageContext`) exists
  because rendering genuinely carries state.
- `dataclass(frozen=True)` for value objects (`VariantInfo`, `PackageSet`, `RootfsConfig`).
- **Errors**: raise `hb_config.ConfigError` with a message that names the file,
  the key and the fix. Entry points catch it and print one line — a traceback is
  a bug, not an error report.
- Constants over literals: `KEY_ALL`, `OSCAP_PROFILES`, `SUPPORTED_ARCHES`,
  `DEFAULT_REGISTRY`.
- No side effects at import time; no global state; no `print` to stdout except
  the documented command output (logs go to stderr — see `hbgen.info`/`note`).
- Subprocesses: `check=False` plus an explicit return-code branch when failure
  is recoverable; `check=True` only when it is not.
- Determinism matters: sort and deduplicate anything that lands in a generated
  artifact (package lists, repo lists, tags). Reordering invalidates image
  layers and breaks reproducibility.

## 4. Jinja2 macros and templates

- Files: `macros/<name>.yml.j2` (macros, concatenated in filename order before
  every template), `templates/<NAME>.j2` (whole-file renders).
- Rendered with `jinja2.StrictUndefined`: an undefined variable is a hard error.
  Therefore every variable a macro reads must be **guaranteed defined** by
  `ImageContext` (that is why `oscap` and `gitmodules` are always present). Do
  not add `| default(...)` to paper over a missing variable — define it in
  Python.
- Whitespace control is deliberate: `{%- … -%}` trims, and the emitted file must
  be a valid Containerfile. Check the rendered output, not the template.
- Macros return strings; `is_builder_variant()` returns `"true"`/`"false"` for
  backwards compatibility, but **new templates should use the `is_builder`
  boolean**.
- Do not compute sets, names or versions in Jinja. Ask for a variable that
  Python already resolved (`main_packages`, `image_repo_name`, `rpm_versions`,
  `oscap.active_profiles`).
- Keep the explanatory comments inside the macro file — they are the only
  documentation a template author will see.

## 5. Generated artifacts and the work tree

- `.hbgen/` is generated, gitignored, and deleted/recreated on every run. Never
  commit it, never hand-edit it, never treat its contents as source.
- The build context is `.hbgen/images/<image>`. Anything the Containerfile
  `COPY`s must live inside it; anything only the generators read may stay at the
  work-tree root (symlinks to the vendored tree).
- Keep the context small: it is read once per matrix row.

## 6. Tests

- `tests/run-tests.sh` runs all offline suites: shell regressions, Python
  rootfs/platform/version contracts, and the real shared engine with recording
  Docker/Podman executables. See `tests/README.md` for their boundaries.
- One assertion per behaviour, id-prefixed (`B5`, `D20`, `F9`) and cross-linked
  from `AGENTS.md` §3.
- Every fixed flaw gets an assertion. Every new knob gets one too.
- Fixtures live in `tests/hummingbird/fixtures/` and are copied to a temp dir
  before use, so the checkout is never written to.
- Prefer asserting on **rendered artifacts** (the Containerfile, VERSION, TAGS)
  over internals: they are what ships.

## 7. Commit and review

- Commit messages: `<area>: <what changed>` — e.g.
  `hummingbird: resolve package versions per distro`.
- One behaviour change per commit where practical; keep refactors separate from
  fixes so a bisect can tell them apart.
- Run the `before_commit` hook in `AGENTS.md` §2.4.
- Reviewer's first question: *which module owns this behaviour, and did the diff
  respect that?* (see `AGENTS.md` §2.2).
