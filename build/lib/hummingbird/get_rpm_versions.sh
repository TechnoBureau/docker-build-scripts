#!/usr/bin/env bash
# ci/get_rpm_versions.sh
#
# Purpose:
#   Resolve current package versions from each distro's own repositories and
#   cache them to .cache/rpm-versions.yml. Used instead of lockfiles to compute
#   version tags (e.g. 8.21.0) at Containerfile/TAGS generation time.
#   Non-hermetic by design: versions are resolved from the repositories at
#   generation time, using the single hummingbird-builder image (it carries the
#   required dnf tooling) with each distro's own yum-repos/*.repo files
#   bind-mounted in.
#
# Usage:
#   cd <work-tree-root> && ci/get_rpm_versions.sh
#
# Output (.cache/rpm-versions.yml) — per distro, because the same package name
# resolves to a different version in each distro's repositories:
#   distros:
#     hummingbird:
#       curl: 8.21.0-1.hum1
#     ubi9:
#       curl: 8.10.1-2.el9
#
# Environment:
#   BUILDER_IMAGE      Image carrying dnf/repoquery (default: hummingbird-builder)
#   CONTAINER_ENGINE   podman|docker (default: podman; the CI driver exports the
#                      detected engine)
#   HB_RPM_VERSIONS_TTL  Reuse a cache younger than this many seconds instead of
#                      re-querying (default: 0 = always refresh). Lets a local
#                      re-render run without a container engine.

set -euo pipefail
# inherit_errexit requires bash 4.4+; keep behavior on older bash (e.g. macOS 3.2)
if [[ ${BASH_VERSINFO[0]} -gt 4 ]] || { [[ ${BASH_VERSINFO[0]} -eq 4 && ${BASH_VERSINFO[1]} -ge 4 ]]; }; then
    shopt -s inherit_errexit
fi

cd "$(dirname "${BASH_SOURCE[0]}")/.."

BUILDER_IMAGE=${BUILDER_IMAGE:-quay.io/hummingbird-ci/hummingbird-builder:latest}
# Single builder image for all distros: it carries the required tools
# (dnf, repoquery) plus the hummingbird repos. Non-hummingbird distros
# (ubi9/ubi10) resolve versions from their own .repo files, bind-mounted
# from yum-repos/ into /etc/yum.repos.d/ with hummingbird repos disabled.
CONTAINER_ENGINE=${CONTAINER_ENGINE:-podman}
# Same interpreter as the rest of the pipeline: the CI driver exports HB_PYTHON
# so a venv or a pinned python can be used without editing any script.
PYTHON=${HB_PYTHON:-python3}
CACHE_FILE=".cache/rpm-versions.yml"
HB_RPM_VERSIONS_TTL=${HB_RPM_VERSIONS_TTL:-0}

mkdir -p .cache

# Reuse a fresh cache so repeated renders (or a laptop without a container
# engine) do not re-query every repository.
if [[ ${HB_RPM_VERSIONS_TTL} -gt 0 && -f ${CACHE_FILE} ]]; then
    cache_age=$(( $(date +%s) - $(stat -c %Y "${CACHE_FILE}" 2>/dev/null || stat -f %m "${CACHE_FILE}" 2>/dev/null || echo 0) ))
    if [[ ${cache_age} -lt ${HB_RPM_VERSIONS_TTL} ]]; then
        echo "Reusing ${CACHE_FILE} (age ${cache_age}s < TTL ${HB_RPM_VERSIONS_TTL}s)"
        exit 0
    fi
fi

TMPDIR=$(mktemp -d)
trap 'rm -rf "${TMPDIR}"' EXIT

# -----------------------------------------------------------------------------
# Stage 1 — one pass over every rpms.in.yaml collects BOTH the packages to
# query and the repo files to bind-mount. A single scan (previously two) keeps
# the two lists guaranteed to come from the same set of files.
# Output: $TMPDIR/packages.txt "<distro> <package>"  (sorted, deduplicated)
#         $TMPDIR/repos.txt    "<distro> <abs-repo-path>"
# WHY distro-aware: each distro resolves versions from its own repos. Querying
# ubi packages (e.g. redhat-release) against the builder's baked-in hummingbird
# repos fails or returns wrong (.hum1) versions, so ubi queries bind-mount the
# distro's yum-repos/*.repo files and disable the hummingbird repos.
# -----------------------------------------------------------------------------
WORK_DIR=$(pwd) "${PYTHON}" - "${TMPDIR}" <<'EOF'
import os
import pathlib
import sys

import yaml

out_dir = pathlib.Path(sys.argv[1])
work_dir = pathlib.Path(os.environ["WORK_DIR"])

packages: set[str] = set()
repos: set[str] = set()

# Path layout: images/<image>/<distro>/<variant>/rpms/rpms.in.yaml
for path in sorted(pathlib.Path("images").glob("*/[!.]*/*/rpms/rpms.in.yaml")):
    distro = path.parent.parent.parent.name
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}

    for item in data.get("packages", []):
        # Arch-specific entries are dicts; dnf is queried for the plain names
        # only, which is what the version tags are computed from.
        if isinstance(item, str):
            packages.add(f"{distro} {item}")

    content_origin = data.get("contentOrigin") or {}
    for repofile in content_origin.get("repofiles") or []:
        abs_path = os.path.normpath(os.path.join(str(path.parent), repofile))
        if os.path.isfile(abs_path):
            repos.add(f"{distro} {os.path.abspath(abs_path)}")

(out_dir / "packages.txt").write_text("".join(f"{line}\n" for line in sorted(packages)))
(out_dir / "repos.txt").write_text("".join(f"{line}\n" for line in sorted(repos)))

if not packages:
    print("No packages found in images/*/*/*/rpms/rpms.in.yaml", file=sys.stderr)
    raise SystemExit(1)
EOF

packages_by_distro=$(cat "${TMPDIR}/packages.txt")

# -----------------------------------------------------------------------------
# Stage 2 — one `dnf repoquery` per distro, into a per-distro result file.
# Per-distro files are what make an unresolved package attributable to the
# distro whose repos lack it (a single global file would mask a ubi miss with a
# hummingbird hit for the same package name).
# -----------------------------------------------------------------------------
query_distro() {
    local distro="$1"
    shift
    local repo_path repo_base line
    local -a mount_args=()
    local -a extra_flags=()

    # Bind-mount this distro's repo files so the single builder image can
    # resolve non-hummingbird packages. Hummingbird queries use the baked-in
    # repos unchanged; other distros get their repos mounted and hummingbird
    # repos disabled so e.g. bash resolves to el9/el10, not .hum1.
    while IFS= read -r line; do
        [[ -n "${line:-}" ]] || continue
        [[ "${line%% *}" == "${distro}" ]] || continue
        repo_path="${line#* }"
        repo_base="$(basename "${repo_path}")"
        mount_args+=("-v" "${repo_path}:/etc/yum.repos.d/${repo_base}:ro")
    done < "${TMPDIR}/repos.txt"

    if [[ "${distro}" != "hummingbird" ]]; then
        extra_flags+=("--disablerepo=public-hummingbird*")
    fi

    # WHY "${arr[@]+"${arr[@]}"}": expands to nothing for an empty array under
    # `set -u` on bash < 4.4 (e.g. macOS 3.2) while keeping every element
    # separately quoted on newer bash — one invocation instead of a branch per
    # empty/non-empty array combination.
    # WHY quoting: the quoted/unquoted forms pass the identical --disablerepo
    # glob to dnf. In the Containerfile macros the flag must be UNQUOTED inside
    # ARG DNF_FLAGS (unquoted ${DNF_FLAGS} expansion keeps literal quotes,
    # breaking the match); here in bash the quoted array element is correct and
    # prevents host-shell glob expansion.
    local run_ok
    # shellcheck disable=SC2086  # intentional word splitting for dnf package args
    run_ok="$(
        "${CONTAINER_ENGINE}" run --rm \
            "${mount_args[@]+"${mount_args[@]}"}" \
            "${BUILDER_IMAGE}" \
            dnf repoquery --quiet --latest-limit=1 \
                --queryformat '%{NAME} %{VERSION}-%{RELEASE}\n' \
            "${extra_flags[@]+"${extra_flags[@]}"}" \
            "$@" 2>/dev/null >> "${TMPDIR}/${distro}.versions" && echo yes || echo no
    )"

    if [[ "${run_ok}" != "yes" ]]; then
        echo "dnf repoquery failed for distro '${distro}' (image: ${BUILDER_IMAGE}); is '${CONTAINER_ENGINE}' running and the image pullable? (${CONTAINER_ENGINE} run --rm ${BUILDER_IMAGE} ...)" >&2
        return 1
    fi
}

current_distro=""
current_pkgs=()

flush_distro() {
    if [[ -n "${current_distro}" && ${#current_pkgs[@]} -gt 0 ]]; then
        query_distro "${current_distro}" "${current_pkgs[@]}" || return 1
    fi
}

# packages.txt is sorted, so every package of a distro is contiguous: one
# repoquery call per distro instead of one per package.
while read -r distro pkg; do
    [[ -n "${distro:-}" && -n "${pkg:-}" ]] || continue
    if [[ -n "${current_distro}" && "${distro}" != "${current_distro}" ]]; then
        flush_distro || exit 1
        current_pkgs=()
    fi
    current_distro="${distro}"
    current_pkgs+=("${pkg}")
done <<< "${packages_by_distro}"
flush_distro || exit 1

# -----------------------------------------------------------------------------
# Stage 3 — fail fast when a requested package has no version in its OWN distro
# repos. dnf would otherwise fail ~10 minutes later at install time with a
# vaguer error. Typical cause: shared default_rpm_packages listing packages the
# distro repos don't carry — clear/override them in builders/<image>/variables.yml.
# -----------------------------------------------------------------------------
missing=""
while read -r distro pkg; do
    [[ -n "${distro:-}" && -n "${pkg:-}" ]] || continue
    if ! awk -v p="${pkg}" '$1 == p { found = 1; exit } END { exit !found }' "${TMPDIR}/${distro}.versions" 2>/dev/null; then
        missing+="${missing:+ }${distro}/${pkg}"
    fi
done <<< "${packages_by_distro}"
if [[ -n "${missing}" ]]; then
    echo "No version resolved for: ${missing} (each distro is queried against its own repos)" >&2
    exit 1
fi

# -----------------------------------------------------------------------------
# Stage 4 — write the cache, keyed by distro.
# WHY nested: a flat {package: version} map cannot hold two distros at once.
# Merging per-distro results into one flat file produced duplicate YAML keys
# (curl: 8.10.1-2.el9 and curl: 8.21.0-1.hum1); yaml.safe_load silently keeps
# the last, so every distro rendered the tags of whichever distro sorted last —
# a ubi9 image published as 8.21.0 while actually shipping curl 8.10.1.
# -----------------------------------------------------------------------------
TMPDIR="${TMPDIR}" "${PYTHON}" - "${CACHE_FILE}" <<'EOF'
import os
import pathlib
import sys

tmp_dir = pathlib.Path(os.environ["TMPDIR"])
cache_file = pathlib.Path(sys.argv[1])

distros: dict[str, dict[str, str]] = {}
for result_file in sorted(tmp_dir.glob("*.versions")):
    versions = distros.setdefault(result_file.stem, {})
    for line in result_file.read_text(encoding="utf-8").splitlines():
        line = line.rstrip("\r").strip()
        if not line:
            continue
        name, _, evr = line.partition(" ")
        if not name or not evr:
            continue
        # Strip the epoch prefix (e.g. "3:" from "3:10.11.14-1.fc44"); version
        # tags are computed from these values.
        versions[name] = evr.split(":", 1)[1] if ":" in evr else evr

if not any(distros.values()):
    print("dnf repoquery returned no results; is the builder image available?", file=sys.stderr)
    raise SystemExit(1)

lines = [
    "# Generated by ci/get_rpm_versions.sh - do not edit manually",
    "# Keyed by distro: the same package name resolves differently per distro.",
    "# Epochs are stripped; version tags are computed from these versions.",
    "distros:",
]
for distro in sorted(distros):
    lines.append(f"  {distro}:")
    lines.extend(f"    {name}: {evr}" for name, evr in sorted(distros[distro].items()))

cache_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
print(f"Wrote {cache_file} ({len(distros)} distro(s), "
      f"{sum(len(v) for v in distros.values())} package version(s))")
EOF
