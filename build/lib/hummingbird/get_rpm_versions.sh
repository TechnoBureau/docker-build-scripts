#!/usr/bin/env bash

# Resolve current package versions from the build repositories and cache them
# to .cache/rpm-versions.yml. Used instead of lockfiles to compute version
# tags (e.g. 8.21.0) at Containerfile/TAGS generation time.
# Non-hermetic by design: versions are resolved from the repositories at
# generation time, using the single hummingbird-builder image (it carries the
# required dnf tooling) with each distro's own yum-repos/*.repo files
# bind-mounted in.

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
# Container engine used to run dnf repoquery; the CI driver exports the
# detected engine (podman or docker) at the call site.
CONTAINER_ENGINE=${CONTAINER_ENGINE:-podman}
CACHE_FILE=".cache/rpm-versions.yml"

mkdir -p .cache

# Collect string packages per distro (python3 avoids a yq dependency).
# WHY: Distro-aware (images/<group>/<distro>/<variant>/rpms/rpms.in.yaml):
# each distro resolves versions from its own repos. Querying ubi packages
# (e.g. redhat-release) against the builder's baked-in hummingbird repos
# fails or returns wrong (.hum1) versions, so ubi queries bind-mount the
# distro's yum-repos/*.repo files and disable the hummingbird repos.
# Output format per line: "<distro> <package>" (sorted, deduplicated).
packages_by_distro=$(python3 - <<'EOF'
import pathlib
import yaml

seen = set()
# Path layout: images/<image>/<distro>/<variant>/rpms/rpms.in.yaml
for path in sorted(pathlib.Path("images").glob("*/[!.]*/*/rpms/rpms.in.yaml")):
    distro = path.parent.parent.parent.name
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    for item in data.get("packages", []):
        if isinstance(item, str):
            seen.add(f"{distro} {item}")
for line in sorted(seen):
    print(line)
EOF
)
if [[ -z ${packages_by_distro} ]]; then
    echo "No packages found in images/*/rpms/rpms.in.yaml" >&2
    exit 1
fi

# Collect repofiles per distro from the same rpms.in.yaml files, resolved to
# absolute host paths for bind-mounting into the builder container.
# Output format per line: "<distro> <absolute-repo-path>".
repos_by_distro=$(python3 - <<'EOF'
import os
import pathlib
import yaml

seen = set()
# Path layout: images/<image>/<distro>/<variant>/rpms/rpms.in.yaml
for path in sorted(pathlib.Path("images").glob("*/[!.]*/*/rpms/rpms.in.yaml")):
    distro = path.parent.parent.parent.name
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    content_origin = data.get("contentOrigin", {}) or {}
    for repofile in content_origin.get("repofiles", []) or []:
        abs_path = os.path.normpath(os.path.join(str(path.parent), repofile))
        if os.path.isfile(abs_path):
            seen.add(f"{distro} {os.path.abspath(abs_path)}")
for line in sorted(seen):
    print(line)
EOF
)

# Per-distro result files so unresolved packages can be attributed to the
# distro whose repos lack them (a global file would mask a ubi miss with a
# hummingbird hit for the same package name).
TMPDIR=$(mktemp -d)
trap 'rm -rf "${TMPDIR}"' EXIT

query_distro() {
    local distro="$1"
    shift
    # shellcheck disable=SC2086  # intentional word splitting for dnf package args
    # Bind-mount this distro's repo files so the single builder image can
    # resolve non-hummingbird packages. Hummingbird queries use the baked-in
    # repos unchanged; other distros get their repos mounted and hummingbird
    # repos disabled so e.g. bash resolves to el9/el10, not .hum1.
    local mount_args=()
    local extra_flags=()
    local line repo_path repo_base run_ok
    while IFS= read -r line; do
        [[ -n "${line:-}" ]] || continue
        repo_path="${line#* }"
        [[ "${line%% *}" == "${distro}" && -n "${repo_path}" ]] || continue
        repo_base="$(basename "${repo_path}")"
        mount_args+=("-v" "${repo_path}:/etc/yum.repos.d/${repo_base}:ro")
    done <<< "${repos_by_distro}"
    if [[ "${distro}" != "hummingbird" ]]; then
        extra_flags+=("--disablerepo=public-hummingbird*")
    fi
    # WHY: Branch on empty arrays — "${arr[@]}" on an empty array fails
    # under `set -u` on bash < 4.4 (e.g. macOS 3.2).
    # WHY quoting: the quoted/unquoted branches below pass the identical
    # --disablerepo glob to dnf. In the Containerfile macros the flag must be
    # UNQUOTED inside ARG DNF_FLAGS (unquoted ${DNF_FLAGS} expansion keeps
    # literal quotes, breaking the match); here in bash the quoted array
    # element is correct and prevents host-shell glob expansion.
    if ((${#mount_args[@]})) && ((${#extra_flags[@]})); then
        run_ok="$("${CONTAINER_ENGINE}" run --rm "${mount_args[@]}" "${BUILDER_IMAGE}" \
            dnf repoquery --quiet --latest-limit=1 --queryformat '%{NAME} %{VERSION}-%{RELEASE}\n' "${extra_flags[@]}" "$@" 2>/dev/null >> "${TMPDIR}/${distro}.txt" && echo yes || echo no)"
    elif ((${#mount_args[@]})); then
        run_ok="$("${CONTAINER_ENGINE}" run --rm "${mount_args[@]}" "${BUILDER_IMAGE}" \
            dnf repoquery --quiet --latest-limit=1 --queryformat '%{NAME} %{VERSION}-%{RELEASE}\n' "$@" 2>/dev/null >> "${TMPDIR}/${distro}.txt" && echo yes || echo no)"
    elif ((${#extra_flags[@]})); then
        run_ok="$("${CONTAINER_ENGINE}" run --rm "${BUILDER_IMAGE}" \
            dnf repoquery --quiet --latest-limit=1 --queryformat '%{NAME} %{VERSION}-%{RELEASE}\n' "${extra_flags[@]}" "$@" 2>/dev/null >> "${TMPDIR}/${distro}.txt" && echo yes || echo no)"
    else
        run_ok="$("${CONTAINER_ENGINE}" run --rm "${BUILDER_IMAGE}" \
            dnf repoquery --quiet --latest-limit=1 --queryformat '%{NAME} %{VERSION}-%{RELEASE}\n' "$@" 2>/dev/null >> "${TMPDIR}/${distro}.txt" && echo yes || echo no)"
    fi
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

# Fail fast when a requested package has no version in its OWN distro repos.
# dnf would otherwise fail ~10 minutes later at install time with a vaguer
# error. Typical cause: shared default_rpm_packages listing packages the
# distro repos don't carry — clear/override them in builders/<image>/variables.yml.
missing=""
while read -r distro pkg; do
    [[ -n "${distro:-}" && -n "${pkg:-}" ]] || continue
    if ! awk -v p="${pkg}" '$1 == p { found = 1; exit } END { exit !found }' "${TMPDIR}/${distro}.txt" 2>/dev/null; then
        missing+="${missing:+ }${distro}/${pkg}"
    fi
done <<< "${packages_by_distro}"
if [[ -n "${missing}" ]]; then
    echo "No version resolved for: ${missing} (each distro is queried against its own repos)" >&2
    exit 1
fi

readarray -t versions < <(sort -u "${TMPDIR}"/*.txt)

if [[ ${#versions[@]} -eq 0 ]]; then
    echo "dnf repoquery returned no results; is the builder image available?" >&2
    exit 1
fi

{
    echo "# Generated by ci/get_rpm_versions.sh - do not edit manually"
    echo "# Epochs are stripped; version tags are computed from these versions."
    for line in "${versions[@]}"; do
        line=${line%$'\r'}
        name=${line%% *}
        evr=${line#* }
        if [[ ${evr} == *:* ]]; then
            evr=${evr#*:}
        fi
        if [[ -n ${name} ]]; then
            printf '%s: %s\n' "${name}" "${evr}"
        fi
    done
} > "${CACHE_FILE}"

echo "Wrote ${CACHE_FILE}"
