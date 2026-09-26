# CLAUDE.md

Repository guide for Claude Code. The canonical operating manual for this
repository is **[AGENTS.md](AGENTS.md)** — it is the single source of truth and
is kept in sync with the code. Do not duplicate its content here; edit
`AGENTS.md` and the [`context/`](context/README.md) documents it references.

@AGENTS.md

## Where to look

| Topic | Document |
| --- | --- |
| Lifecycle hooks, ownership map, invariants | [AGENTS.md](AGENTS.md) |
| Knowledge base index (load on demand) | [context/README.md](context/README.md) |
| Module map, `CONFIG` contract, precedence | [context/architecture.md](context/architecture.md) |
| Hummingbird/UBI/FIPS pipeline | [context/hummingbird-pipeline.md](context/hummingbird-pipeline.md) |
| Bash/Python/Jinja style rules | [context/conventions.md](context/conventions.md) |
| Extension recipes | [context/extension-guide.md](context/extension-guide.md) |
| Failing command diagnosis | [context/troubleshooting.md](context/troubleshooting.md) |
| Offline test suites | [tests/README.md](tests/README.md) |
| User-facing overview | [README.md](README.md) |
