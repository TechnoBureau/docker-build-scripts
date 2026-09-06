#!/usr/bin/env bash
# Resolve versions from the SAME distro/architecture repos used for installation.
# File/YAML logic lives in hb_versions.py; this file only orchestrates queries.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERSION_TOOL="${SCRIPT_DIR}/hb_versions.py"
[[ -f "$VERSION_TOOL" ]] || VERSION_TOOL="${SCRIPT_DIR}/internal/hb_versions.py"
cd "${SCRIPT_DIR}/.."

BUILDER_IMAGE="${BUILDER_IMAGE:-quay.io/hummingbird-ci/hummingbird-builder:latest}"
CONTAINER_ENGINE="${CONTAINER_ENGINE:-podman}"
PYTHON="${HB_PYTHON:-python3}"
CACHE_FILE=".cache/rpm-versions.yml"
HB_RPM_VERSIONS_TTL="${HB_RPM_VERSIONS_TTL:-0}"
[[ "$HB_RPM_VERSIONS_TTL" =~ ^[0-9]+$ ]] || { echo 'HB_RPM_VERSIONS_TTL must be a non-negative integer' >&2; exit 1; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
"$PYTHON" "$VERSION_TOOL" plan --output "$WORK" --builder-image "$BUILDER_IMAGE"
# WHY fingerprint before TTL: a fresh cache for amd64 must not satisfy a later
# arm64 build, nor mask newly added FIPS packages or changed repository files.
if "$PYTHON" "$VERSION_TOOL" fresh --plan "$WORK/plan.json" --cache "$CACHE_FILE" --ttl "$HB_RPM_VERSIONS_TTL"; then
    echo "Reusing ${CACHE_FILE} (matching package/repository/platform request)"
    exit 0
fi

ci_query_rpm_versions() {
    local distro="$1" arch="$2" releasever="$3" packages="$4" repo_distro repo_arch repo
    local -a mounts=() flags=("--forcearch=$arch" "--arch=$arch,noarch" "--setopt=reposdir=/etc/hb-repos") names=()
    read -r -a names <<< "$packages"
    while IFS=$'\t' read -r repo_distro repo_arch repo; do
        [[ "$repo_distro" == "$distro" && "$repo_arch" == "$arch" ]] || continue
        mounts+=(-v "$repo:/etc/hb-repos/${repo##*/}:ro")
    done < "$WORK/repos.tsv"
    if [[ "$distro" != "hummingbird" ]]; then
        flags+=("--disablerepo=public-hummingbird*")
    fi
    [[ "$releasever" == - ]] || flags+=("--releasever=$releasever")
    # repoquery runs native; --forcearch selects the TARGET repo/solver arch.
    # No emulation is necessary to query arm64 packages on an amd64 runner.
    if ! "$CONTAINER_ENGINE" run --rm "${mounts[@]}" "$BUILDER_IMAGE" \
        dnf repoquery --quiet --latest-limit=1 \
        --queryformat '%{NAME} %{VERSION}-%{RELEASE}\n' \
        "${flags[@]}" "${names[@]}" < /dev/null > "$WORK/$distro--$arch.versions"; then
        echo "dnf repoquery failed for $distro/$arch (image: $BUILDER_IMAGE, engine: $CONTAINER_ENGINE)" >&2
        return 1
    fi
}

while IFS=$'\t' read -r distro arch releasever packages; do
    ci_query_rpm_versions "$distro" "$arch" "$releasever" "$packages"
done < "$WORK/requests.tsv"
"$PYTHON" "$VERSION_TOOL" cache --plan "$WORK/plan.json" --results "$WORK" --cache "$CACHE_FILE"
