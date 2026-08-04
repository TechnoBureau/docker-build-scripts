#!/usr/bin/env bash
# sync-hummingbird.sh
#
# Purpose:
#   Sync the Hummingbird pipeline machinery from the containers repository
#   into the vendored hummingbird/ directory. The containers repo is the
#   source of truth; this tool copies files verbatim (pure copy, no patches).
#
# Usage:
#   tools/sync-hummingbird.sh [--from /path/to/containers]
#
# Options:
#   --from DIR   Path to the containers repo checkout (default: ../containers)
#
# Example:
#   tools/sync-hummingbird.sh
#   tools/sync-hummingbird.sh --from ~/git/containers
#
# Returns:
#   0 on success, non-zero when a source file is missing

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "${SCRIPT_DIR}")"
HB_DIR="${REPO_ROOT}/hummingbird"

SOURCE_DIR="${REPO_ROOT}/../containers"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --from)
            SOURCE_DIR="$2"
            shift 2
            ;;
        *)
            echo "Unknown argument: $1" >&2
            exit 1
            ;;
    esac
done

SOURCE_DIR="$(cd "${SOURCE_DIR}" && pwd)"

if [[ ! -d "${SOURCE_DIR}/images" ]]; then
    echo "Error: ${SOURCE_DIR} does not look like a containers repo checkout (missing images/)" >&2
    exit 1
fi

mkdir -p "${HB_DIR}"

copy_file() {
    local src="$1"
    local dst="$2"
    if [[ ! -f "${src}" ]]; then
        echo "Error: missing source file: ${src}" >&2
        exit 1
    fi
    mkdir -p "$(dirname "${dst}")"
    cp "${src}" "${dst}"
    echo "Synced ${src} → ${dst}"
}

copy_tree() {
    local src_dir="$1"
    local dst_dir="$2"
    local pattern="$3"
    if ! compgen -G "${src_dir}/${pattern}" > /dev/null; then
        echo "Error: no files matching ${src_dir}/${pattern}" >&2
        exit 1
    fi
    mkdir -p "${dst_dir}"
    rm -rf "${dst_dir}"/*
    cp "${src_dir}"/${pattern} "${dst_dir}/"
    echo "Synced ${src_dir}/${pattern} → ${dst_dir}/"
}

# Global variables and label defaults
copy_file "${SOURCE_DIR}/images/variables.yml" "${HB_DIR}/variables.yml"

# Jinja2 macros used at render time
copy_tree "${SOURCE_DIR}/macros" "${HB_DIR}/macros" '*.yml.j2'

# Templates: TAGS/VERSION/oscap-tailoring rendering and grype markdown report
for template in TAGS.j2 VERSION.j2 oscap-tailoring.xml.j2 grype-markdown.tmpl; do
    copy_file "${SOURCE_DIR}/templates/${template}" "${HB_DIR}/templates/${template}"
done

# Generator scripts
for script in aggregate_properties.py generate_jinja2.py generate_rpms_in.py; do
    copy_file "${SOURCE_DIR}/ci/internal/${script}" "${HB_DIR}/${script}"
done

# RPM version resolution (runs inside the reconstructed image tree; requires
# podman and the hummingbird-builder image)
copy_file "${SOURCE_DIR}/ci/get_rpm_versions.sh" "${HB_DIR}/get_rpm_versions.sh"

# Repository files referenced by rpms.in.yaml (contentOrigin.repofiles)
copy_file "${SOURCE_DIR}/yum-repos/hummingbird.repo" "${HB_DIR}/yum-repos/hummingbird.repo"

echo
echo "Sync complete: ${SOURCE_DIR} → ${HB_DIR}"
