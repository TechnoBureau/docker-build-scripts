# Offline tests

## Run everything

Bash 4.4+ and Python 3.10+ with PyYAML/Jinja2 are required. No real container
engine, registry credentials, package repository or network is used by the tests.

```bash
python3 -m venv .venv
.venv/bin/python -m pip install pyyaml jinja2
HB_PYTHON="$PWD/.venv/bin/python" ./tests/run-tests.sh
```

Use an existing interpreter via `HB_PYTHON` if those dependencies are already
installed. The first two commands are dependency setup and need package access;
the test run itself is offline.

## Suites

| Suite | Coverage |
| --- | --- |
| `hummingbird/run-tests.sh` | 100 assertions: work tree, merges, matrix restrictions, naming, per-distro versions, rendering, errors, bash-driver contract |
| `hummingbird/test_build_contract.py` | FIPS-enabled defaults on Hummingbird/UBI9/UBI10; amd64/arm64/both; package-set parity; base selection, seed/upgrade/install order; portable/optional chunkah output; actual rootfs helper operations |
| `hummingbird/test_versions.py` | Distro × target-architecture queries, missing FIPS packages, conflicting versions, cache fingerprint/TTL isolation; real query shell with a stub executable |
| `hummingbird/test_rootfs_transactions.py` | Temporary runtime mounts, preserved seed content, RPM failures/signals, reverse cleanup and locked-submount handling. Also performs real native mount/chroot probes in isolated Linux user/mount namespaces when available |
| `test_build_engine.py` | Real `ci_build_and_push` with recording Docker/Podman executables: single/multi targets, manifests, no-push output, failed builds/pushes, chunkah cache isolation, base registry parsing, Podman mount capabilities and opt-in BuildKit rootfs permissions |

Python suites use `unittest` (no additional test framework). Subtests iterate the
supported distro/platform/engine combinations. Engine stubs are deliberately quiet
on success to catch filters that accidentally turn a successful command into an error.

The curl fixture uses `chunkah: true` to cover the optional legacy path. Its
`fips` variant supports both distros; a separate `debug` variant exercises explicit
distro restrictions. A second fixture has no OSCAP section. Additional small
builders/rootfs trees are generated inside temporary directories by the Python tests.

## Focus a test while editing

```bash
# Legacy shell groups; each runs its own prerequisites.
HB_PYTHON=.venv/bin/python ./tests/hummingbird/run-tests.sh -k matrix
# Groups: prepare, matrix, versions, render, errors, driver
HB_PYTHON=.venv/bin/python ./tests/hummingbird/run-tests.sh -t fips

# Named Python test classes/methods are accepted by unittest.
.venv/bin/python tests/hummingbird/test_build_contract.py RootfsHelperTests
.venv/bin/python tests/hummingbird/test_versions.py
.venv/bin/python tests/test_build_engine.py

# Preserve the shell suite's generated work tree for inspection.
HB_TEST_KEEP=1 HB_PYTHON=.venv/bin/python ./tests/hummingbird/run-tests.sh
```

The shell suite's `-t` filter narrows **reporting**, not execution; a filtered
summary is not proof that the full suite passed. Stable A–F assertion IDs are
cross-referenced from `AGENTS.md`. Add new behavioral tests to the suite owning
the behavior, not to a one-time task report.

## Boundaries

Passing these tests validates resolver behavior, generated recipes, helper
operations and engine command contracts. It does **not** validate:

- actual DNF transactions or RPM scriptlets in a container;
- QEMU/remote workers, base-image manifests or the builder image's availability;
- a registry push, real crypto-provider operation, OSCAP results or FIPS certification.

The native namespace probe tests actual `/proc/self/exe` visibility in a chroot
and cleanup on success/failure. It is skipped where Linux user/mount namespaces
are unavailable; it is **not** a Rosetta, QEMU or RPM transaction test.

Before releasing, run representative real builds on a suitable container runner:
Hummingbird/UBI9/UBI10 × amd64/arm64/both, empty and base-seeded rootfs. Inspect
manifests, installed packages and crypto policy for every platform. The base seed
must be distro-compatible and provide the selected architecture(s).
