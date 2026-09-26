# context/ — reusable repository knowledge

[`README.md`](../README.md) is the single source of truth — [`AGENTS.md`](../AGENTS.md)
and [`CLAUDE.md`](../CLAUDE.md) are symlinks to it. This folder describes **current
code contracts and reusable workflows**, not one-time audits, task histories or
completion reports. Load only the documents needed for the current task.

| Task | Read |
| --- | --- |
| Where code lives, entry points and shared engine | [architecture.md](architecture.md) |
| Hummingbird/UBI, FIPS, base images, rootfs, platforms, package queries | [hummingbird-pipeline.md](hummingbird-pipeline.md) |
| Style and language boundaries | [conventions.md](conventions.md) |
| Add a distro, variant, package group, macro or setting | [extension-guide.md](extension-guide.md) |
| Diagnose a failing build | [troubleshooting.md](troubleshooting.md) |
| Run or extend offline tests | [../tests/README.md](../tests/README.md) |

## Maintenance rules

- One owner per behavior. Keep detailed rationale in its docstring or `WHY:`
  comment; summarize the contract here rather than duplicating implementation.
- Change current docs and regression tests alongside behavior.
- Add durable guarantees to `README.md` §3 (AI Agent Operating Manual), with a test reference.
- Keep one-time review/audit narratives in the change description, not this folder.
- Execute documented command sequences before publishing changes to them.

## Orientation

```
main_build() ── Dockerfile flavour ── load_config() ───┐
             └─ hummingbird flavour ── .hbgen matrix ─┴─ ci_build_and_push()
                                                          └─ ci-platforms.sh
```

`build/lib/hummingbird/*.py` owns structured data and rendering;
`build/lib/ci-*.sh` owns the engine; `docker/*.sh` and
`build/lib/hummingbird/prebuildfs/` are independent image-provisioning/runtime
libraries.
