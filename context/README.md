# context/ — agent knowledge base

Purpose: everything an agent (or a new engineer) needs to act correctly in this
repository, split into small files that can be loaded **on demand**.

[`AGENTS.md`](../AGENTS.md) is the entry point and the rulebook. This folder is
the reference material behind it.

## Load on demand

Do not read all of this up front. Match the task to one or two files:

| If the task is about… | Read | Size |
| --- | --- | --- |
| Where anything lives, how the CI engine flows, who calls whom | [`architecture.md`](architecture.md) | ~4 min |
| hummingbird: builders, distros, variants, `.hbgen`, rpms, macros | [`hummingbird-pipeline.md`](hummingbird-pipeline.md) | ~8 min |
| "Why is this code like this?" / regressions / known traps | [`flaw-report-hummingbird.md`](flaw-report-hummingbird.md) | ~10 min |
| Writing or reviewing code (bash, Python, Jinja) | [`conventions.md`](conventions.md) | ~5 min |
| Adding a distro, variant, macro, registry, template, flavour | [`extension-guide.md`](extension-guide.md) | ~6 min |
| A failing build or a confusing error message | [`troubleshooting.md`](troubleshooting.md) | lookup |
| Running or extending the tests | [`../tests/README.md`](../tests/README.md) | ~3 min |

## How these documents are maintained

- **One owner per fact.** If a fact belongs to a module, it is documented next
  to the module (docstring or `WHY:` comment) and only summarised here.
- **Behaviour changes update docs in the same commit.** `AGENTS.md` §2.4 lists
  it in the pre-commit checklist.
- **Incidents become invariants.** When a bug is fixed, it gets: a `WHY:`
  comment at the fix site, a row in `flaw-report-hummingbird.md`, an invariant
  in `AGENTS.md` §3, and a test id in `tests/hummingbird/run-tests.sh`.
- **Nothing here is aspirational.** Every command in these files has been run
  in this repository.

## Quick orientation (30 seconds)

```
build/universal-ci.sh          → main_build(): detects flavour, orchestrates
build/lib/ci-*.sh              → shared engine (config, build, registry, artifacts)
build/lib/ci-hummingbird.sh    → hummingbird flavour driver (bash orchestration)
build/lib/hummingbird/*.py     → hummingbird generators (all YAML/Jinja logic)
docker/*.sh                    → scripts copied into images at build time
tests/hummingbird/             → offline regression suite (no engine needed)
```

Two flavours, one engine:

```
                    ┌── Dockerfile flavour ──→ load_config() ─┐
main_build() ───────┤                                         ├──→ ci_build_and_push()
                    └── hummingbird flavour ─→ .hbgen matrix ─┘
                        (ci-hummingbird.sh)     per distro/variant
```
