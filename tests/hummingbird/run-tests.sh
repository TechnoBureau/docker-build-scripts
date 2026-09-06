#!/usr/bin/env bash
# tests/hummingbird/run-tests.sh
#
# Offline regression suite for the hummingbird builder.
#
# Runs the real generators and the real bash driver against the fixtures in
# tests/hummingbird/fixtures, with a stub container engine (stubs/podman) and a
# stub vendored tree, so no container runtime, builder image, package
# repository or network access is needed.
#
# Usage:
#   ./tests/hummingbird/run-tests.sh            # run everything
#   ./tests/hummingbird/run-tests.sh -k matrix  # run one GROUP by keyword:
#                                               #   prepare|matrix|versions|render|errors|driver
#   ./tests/hummingbird/run-tests.sh -t fips    # report only assertions whose NAME
#                                               #   matches (all groups still execute)
#   HB_TEST_KEEP=1 ./tests/hummingbird/run-tests.sh   # keep the work dir
#
# Requirements:
#   python3 with PyYAML and Jinja2 (the same requirements as the generators):
#     python3 -m pip install --user pyyaml jinja2
#
# Exit code: 0 when every test passed, 1 otherwise.

set -uo pipefail

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${TESTS_DIR}/../.." && pwd)"
HB_DIR="${REPO_ROOT}/build/lib/hummingbird"
LIB_DIR="${REPO_ROOT}/build/lib"
FIXTURES="${TESTS_DIR}/fixtures"
STUBS="${TESTS_DIR}/stubs"

KEEP_WORK_DIR="${HB_TEST_KEEP:-0}"
FILTER=""        # group keyword (-k)
TEST_FILTER=""   # assertion name substring (-t)
while [[ $# -gt 0 ]]; do
    case "$1" in
        -k|--filter) FILTER="${2:-}"; shift 2 ;;
        -t|--test) TEST_FILTER="${2:-}"; shift 2 ;;
        -h|--help) sed -n '2,25p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

# --------------------------------------------------------------------------- #
# Assertions
# --------------------------------------------------------------------------- #
PASSED=0
FAILED=0
CURRENT_GROUP=""

group() {
    CURRENT_GROUP="$1"
    printf '\n\033[1m%s\033[0m\n' "$1"
}

# Every assertion is prefixed with a stable test id so a failure can be traced
# back to the behaviour it guards. Ids are cited from AGENTS.md §3 (the
# invariants) and from the WHY: comment at each fix site.
# WHY -t suppresses counting as well as printing: a filtered run reports only
# the assertions you asked about, so the summary stays meaningful. The scope is
# restated in the summary so a green filtered run is never mistaken for a green
# full run.
wanted() { [[ -z "${TEST_FILTER}" || "$1" == *"${TEST_FILTER}"* ]]; }

ok() {
    wanted "$1" || return 0
    PASSED=$((PASSED + 1))
    printf '  \033[32mPASS\033[0m %s\n' "$1"
}

fail() {
    wanted "$1" || return 0
    FAILED=$((FAILED + 1))
    printf '  \033[31mFAIL\033[0m [%s] %s\n' "${CURRENT_GROUP:-?}" "$1"
    [[ -n "${2:-}" ]] && printf '       %s\n' "${2}"
    return 0
}

assert_eq() { # <id> <expected> <actual>
    if [[ "$2" == "$3" ]]; then ok "$1"; else fail "$1" "expected: [$2]
       actual:   [$3]"; fi
}

assert_contains() { # <id> <haystack> <needle>
    if [[ "$2" == *"$3"* ]]; then ok "$1"; else fail "$1" "expected to contain: [$3]
       in: [$2]"; fi
}

assert_not_contains() { # <id> <haystack> <needle>
    if [[ "$2" != *"$3"* ]]; then ok "$1"; else fail "$1" "expected NOT to contain: [$3]"; fi
}

assert_file() { # <id> <path>
    if [[ -f "$2" ]]; then ok "$1"; else fail "$1" "missing file: $2"; fi
}

assert_no_file() { # <id> <path>
    if [[ ! -e "$2" ]]; then ok "$1"; else fail "$1" "unexpected file: $2"; fi
}

assert_fails_with() { # <id> <output+status text> <needle>
    if [[ "$2" == *"$3"* ]]; then ok "$1"; else fail "$1" "expected error to mention: [$3]
       got: [$2]"; fi
}

assert_no_traceback() { # <id> <stderr>
    if [[ "$2" != *"Traceback (most recent call last)"* ]]; then
        ok "$1"
    else
        fail "$1" "Python traceback leaked to the operator:
$(printf '%s' "$2" | tail -6 | sed 's/^/       /')"
    fi
}

skip_remaining() {
    printf '\n\033[33mSKIPPED\033[0m %s\n' "$1"
}

# --------------------------------------------------------------------------- #
# Environment
# --------------------------------------------------------------------------- #
PYTHON="${HB_PYTHON:-python3}"
if [[ "$PYTHON" == */* && "$PYTHON" != /* ]]; then
    PYTHON="$(cd "$(dirname "$PYTHON")" && pwd)/$(basename "$PYTHON")"
fi
if ! command -v "${PYTHON}" >/dev/null 2>&1; then
    echo "python3 not found; cannot run the hummingbird tests" >&2
    exit 1
fi
if ! "${PYTHON}" -c 'import yaml, jinja2' >/dev/null 2>&1; then
    echo "PyYAML and Jinja2 are required: ${PYTHON} -m pip install --user pyyaml jinja2" >&2
    exit 1
fi

WORK="$(mktemp -d)"
cleanup() {
    if [[ "${KEEP_WORK_DIR}" == "1" ]]; then
        printf '\nwork dir kept: %s\n' "${WORK}"
    else
        rm -rf "${WORK}"
    fi
}
trap cleanup EXIT

# Stub vendored tree: real generators and macros, tiny fake SCAP datastreams.
# Keeps the suite hermetic (the real datastreams are ~25 MB each) and exercises
# the HUMMINGBIRD_DIR override at the same time.
VENDORED="${WORK}/vendored"
mkdir -p "${VENDORED}/oscap"
# Copy every generator/module rather than a hand-kept list: a new hb_*.py module
# must not silently break the suite.
for file in "${HB_DIR}"/*.py "${HB_DIR}"/*.sh; do
    cp "${file}" "${VENDORED}/$(basename "${file}")"
done
for dir in macros templates yum-repos prebuildfs; do
    ln -s "${HB_DIR}/${dir}" "${VENDORED}/${dir}"
done
echo '<fake ssg-rhel9-ds/>' > "${VENDORED}/oscap/ssg-rhel9-ds.xml"
echo '<fake ssg-rhel10-ds/>' > "${VENDORED}/oscap/ssg-rhel10-ds.xml"

export HUMMINGBIRD_DIR="${VENDORED}"
export HB_PYTHON="${PYTHON}"
export HB_STUB_DATA="${FIXTURES}/rpm-versions.tsv"
export PATH="${STUBS}:${PATH}"

# Builder trees are copied so the repository checkout is never written to.
BUILDERS="${WORK}/builders"
cp -R "${FIXTURES}/builders" "${BUILDERS}"
NO_OSCAP_BUILDERS="${WORK}/no-oscap-builders"
cp -R "${FIXTURES}/no-oscap/builders" "${NO_OSCAP_BUILDERS}"

CURL="${BUILDERS}/curl"
HELLO="${NO_OSCAP_BUILDERS}/hello"
CURL_TREE="${CURL}/.hbgen"
CURL_CTX="${CURL_TREE}/images/curl"

hbgen() { "${PYTHON}" "${VENDORED}/hbgen.py" "$@"; }
variant_dir() { printf '%s/%s/%s\n' "${CURL_CTX}" "$1" "$2"; }
read_file() { [[ -f "$1" ]] && cat "$1" || echo "<missing:$1>"; }

matches_filter() { [[ -z "${FILTER}" || "$1" == *"${FILTER}"* ]]; }

# --------------------------------------------------------------------------- #
# Pipeline stages, run at most once each
#
# WHY: the hummingbird stages are cumulative (prepare -> aggregate -> rpms ->
# versions -> render) and groups B/C/D assert on the later ones. Running a single
# group with -k used to fail every assertion that needed an earlier stage,
# because that stage only ran inside group A. ensure_stage makes each group
# self-sufficient without repeating work during a full run.
# --------------------------------------------------------------------------- #
STAGES_DONE=""
ensure_stage() {
    local stage="$1"
    [[ " ${STAGES_DONE} " == *" ${stage} "* ]] && return 0
    case "${stage}" in
        prepare)
            hbgen prepare --image-dir "${CURL}" --builders-dir "${BUILDERS}" >/dev/null 2>&1
            ;;
        aggregate)
            ensure_stage prepare
            ( cd "${CURL_TREE}" && "${PYTHON}" "${VENDORED}/aggregate_properties.py" >/dev/null 2>&1 )
            ;;
        rpms)
            ensure_stage aggregate
            hbgen rpms --hbgen "${CURL_TREE}" --image curl >/dev/null 2>&1
            ;;
        versions)
            ensure_stage rpms
            ( cd "${CURL_TREE}" && HB_STUB_LOG="${WORK}/engine-calls.log" \
                CONTAINER_ENGINE=podman ci/get_rpm_versions.sh >/dev/null 2>&1 )
            ;;
        *)
            echo "ensure_stage: unknown stage '${stage}'" >&2
            return 2
            ;;
    esac
    STAGES_DONE="${STAGES_DONE} ${stage}"
}

# --------------------------------------------------------------------------- #
# Group A — work tree preparation and configuration merge
# --------------------------------------------------------------------------- #
if matches_filter "prepare"; then
    group "A. Work tree preparation and variables.yml merge"

    output="$(hbgen prepare --image-dir "${CURL}" --builders-dir "${BUILDERS}" 2>&1)"
    status=$?
    assert_eq "A1 prepare succeeds" "0" "${status}"
    assert_file "A2 merged variables.yml written" "${CURL_TREE}/images/variables.yml"

    merged="$(read_file "${CURL_TREE}/images/variables.yml")"
    assert_contains "A3 per-image overlay applied" "${merged}" "overlay-applied"
    assert_eq "A4 overlay list replaces (not appends) default_distros" \
        "2" "$(grep -c '^- \(hummingbird\|ubi9\)$' <<< "${merged}")"

    assert_file "A5 Containerfile.j2 copied into the tree" "${CURL_CTX}/Containerfile.j2"
    assert_file "A6 distro repo files copied into the build context" "${CURL_CTX}/yum-repos/ubi9.repo"
    assert_file "A7 get_rpm_versions.sh linked as ci/get_rpm_versions.sh" "${CURL_TREE}/ci/get_rpm_versions.sh"

    # Flaw: every datastream was copied into the build context (~49 MB) even for
    # builds that scan nothing.
    copied_oscap="$(ls "${CURL_CTX}/oscap" 2>/dev/null | tr '\n' ' ')"
    assert_eq "A8 only the datastreams of the selected distros are vendored" \
        "ssg-rhel9-ds.xml " "${copied_oscap}"

    output="$(hbgen prepare --image-dir "${CURL}" --builders-dir "${BUILDERS}" --distros hummingbird 2>&1)"
    assert_no_file "A9 hummingbird-only build vendors no datastream" "${CURL_CTX}/oscap/ssg-rhel9-ds.xml"

    # Restore the two-distro tree for the remaining groups.
    hbgen prepare --image-dir "${CURL}" --builders-dir "${BUILDERS}" >/dev/null 2>&1
    STAGES_DONE="${STAGES_DONE} prepare"
fi

# --------------------------------------------------------------------------- #
# Group B — build matrix resolution
# --------------------------------------------------------------------------- #
if matches_filter "matrix"; then
    group "B. Build matrix (distros x variants x image name)"

    ensure_stage prepare
    ( cd "${CURL_TREE}" && "${PYTHON}" "${VENDORED}/aggregate_properties.py" >/dev/null )
    status=$?
    assert_eq "B1 aggregate_properties succeeds" "0" "${status}"

    matrix="$(hbgen matrix --hbgen "${CURL_TREE}" --image curl 2>/dev/null)"

    # Flaw: the driver built the raw cartesian product and ignored the
    # additional_variants distro restriction, producing an unwanted debug row.
    row_for() { awk -F '\t' -v d="$1" -v v="$2" '$1==d && $2==v {print "present"}' <<< "${matrix}"; }
    assert_eq "B2 distro-restricted variant ubi9/debug is excluded" "" "$(row_for ubi9 debug)"
    assert_eq "B3 unrestricted variant hummingbird/fips is kept" "present" "$(row_for hummingbird fips)"

    image_for() { awk -F '\t' -v d="$1" -v v="$2" '$1==d && $2==v {print $3}' <<< "${matrix}"; }
    assert_eq "B4 builder variant publishes curl-builder" "curl-builder" "$(image_for hummingbird builder)"
    # Flaw: only the literal variant "builder" was recognised, so composite
    # builder variants published the wrong repository name.
    assert_eq "B5 composite fips-builder publishes curl-builder" "curl-builder" "$(image_for hummingbird fips-builder)"
    assert_eq "B6 non-builder variant shares the image repository" "curl" "$(image_for hummingbird fips)"

    assert_eq "B7 matrix has one row per allowed combination" "9" "$(grep -c . <<< "${matrix}")"

    output="$(hbgen matrix --hbgen "${CURL_TREE}" --image curl --variants nosuchvariant 2>&1)"
    assert_fails_with "B8 unknown variant is rejected" "${output}" "unknown variant"
    assert_fails_with "B9 rejection lists the valid variants" "${output}" "fips-builder"
    assert_no_traceback "B10 rejection is a message, not a traceback" "${output}"
    assert_eq "B11 ubi9/fips is supported" "present" "$(row_for ubi9 fips)"
fi

# --------------------------------------------------------------------------- #
# Group C — package version resolution (stub container engine)
# --------------------------------------------------------------------------- #
if matches_filter "versions"; then
    group "C. Package version resolution (get_rpm_versions.sh)"

    ensure_stage aggregate
    hbgen rpms --hbgen "${CURL_TREE}" --image curl >/dev/null 2>&1
    assert_file "C1 rpms.in.yaml written for a matrix row" \
        "$(variant_dir hummingbird default)/rpms/rpms.in.yaml"

    stub_log="${WORK}/engine-calls.log"
    ( cd "${CURL_TREE}" && HB_STUB_LOG="${stub_log}" CONTAINER_ENGINE=podman ci/get_rpm_versions.sh ) \
        > "${WORK}/versions.out" 2>&1
    status=$?
    assert_eq "C2 get_rpm_versions.sh succeeds with the stub engine" "0" "${status}"

    cache="$(read_file "${CURL_TREE}/.cache/rpm-versions.yml")"
    assert_contains "C3 cache is keyed per distro" "${cache}" "distros:"
    assert_contains "C4 hummingbird versions recorded" "${cache}" "8.21.0-1.hum1"
    assert_contains "C5 ubi9 versions recorded" "${cache}" "8.10.1-2.el9"
    assert_not_contains "C6 epoch prefix stripped" "${cache}" "3:8.10.1"

    # Flaw: the per-distro results were merged into one flat file, so duplicate
    # YAML keys silently kept whichever distro sorted last and every distro
    # rendered the same version tags.
    duplicates="$("${PYTHON}" - "${CURL_TREE}/.cache/rpm-versions.yml" <<'PY'
import sys, yaml
data = yaml.safe_load(open(sys.argv[1], encoding="utf-8"))
print("nested" if "distros" in data else "flat")
PY
)"
    assert_eq "C7 cache structure is unambiguous (no duplicate keys)" "nested" "${duplicates}"

    engine_calls="$(grep -c 'dnf repoquery' "${stub_log}" 2>/dev/null || echo 0)"
    assert_eq "C8 one repoquery per distro (not per package)" "2" "${engine_calls}"

    # Fail fast on a package the distro repositories do not carry.
    broken="${WORK}/broken"
    cp -R "${CURL}" "${broken}"
    ( cd "${broken}/.hbgen" && "${PYTHON}" - <<'PY'
import pathlib
pathlib.Path("images/curl/hummingbird/default/rpms/rpms.in.yaml").write_text(
    "arches: [x86_64]\ncontentOrigin:\n  repofiles: []\ncontext:\n  bare: true\n"
    "installWeakDeps: false\npackages:\n  - no-such-package-anywhere\nzchunk: false\n",
    encoding="utf-8")
PY
    )
    output="$(cd "${broken}/.hbgen" && CONTAINER_ENGINE=podman ci/get_rpm_versions.sh 2>&1)"
    status=$?
    assert_eq "C9 unresolved package fails the stage" "1" "${status}"
    assert_fails_with "C10 failure names the distro and package" "${output}" "hummingbird/no-such-package-anywhere"

    # TTL reuse keeps a re-render possible without an engine.
    output="$(cd "${CURL_TREE}" && HB_RPM_VERSIONS_TTL=600 CONTAINER_ENGINE=/nonexistent \
        ci/get_rpm_versions.sh 2>&1)"
    assert_contains "C11 HB_RPM_VERSIONS_TTL reuses a fresh cache" "${output}" "Reusing"
fi

# --------------------------------------------------------------------------- #
# Group D — rendered Containerfile semantics
# --------------------------------------------------------------------------- #
if matches_filter "render"; then
    group "D. Rendered Containerfile semantics"

    ensure_stage versions
    hbgen render --hbgen "${CURL_TREE}" --image curl >/dev/null 2>&1
    status=$?
    assert_eq "D1 render succeeds" "0" "${status}"

    builder_cf="$(read_file "$(variant_dir hummingbird builder)/Containerfile")"
    fips_builder_cf="$(read_file "$(variant_dir hummingbird fips-builder)/Containerfile")"
    fips_cf="$(read_file "$(variant_dir hummingbird fips)/Containerfile")"
    default_cf="$(read_file "$(variant_dir hummingbird default)/Containerfile")"
    ubi9_cf="$(read_file "$(variant_dir ubi9 default)/Containerfile")"

    # Flaw: is_builder_variant() compared variant == "builder", so composite
    # builder variants lost every builder behaviour.
    assert_contains "D2 fips-builder installs the builder default packages" "${fips_builder_cf}" "gcc make"
    assert_contains "D3 fips-builder installs the image builder packages" "${fips_builder_cf}" "curl-devel"
    assert_contains "D4 fips-builder writes the builder dnf defaults" "${fips_builder_cf}" "90-builder-defaults.conf"
    assert_contains "D5 fips-builder exports CONTAINER_DEFAULT_USER" "${fips_builder_cf}" "CONTAINER_DEFAULT_USER"
    assert_not_contains "D6 fips-builder keeps licenses and locales" "${fips_builder_cf}" '${NEWROOT}/usr/share/licenses'
    assert_contains "D7 plain builder variant is unchanged" "${builder_cf}" "gcc make"

    # Flaw: the name label advertised a repository that was never pushed.
    label_of() { sed -n 's/^LABEL name="\(.*\)"$/\1/p' <<< "$1"; }
    assert_eq "D8 fips-builder name label matches the published repository" \
        "ghcr.io/technobureau/curl-builder" "$(label_of "${fips_builder_cf}")"
    assert_eq "D9 fips variant name label matches the published repository" \
        "ghcr.io/technobureau/curl" "$(label_of "${fips_cf}")"
    assert_contains "D10 fips variant still carries its variant label" "${fips_cf}" \
        'io.hummingbird-project.variant="fips"'
    assert_contains "D11 fips-builder is labelled as a builder" "${fips_builder_cf}" \
        'io.hummingbird-project.variant.builder="true"'

    assert_contains "D12 FIPS crypto policy applied for the fips variant" "${fips_cf}" 'hb-rootfs policy "${NEWROOT}" "FIPS"'
    assert_contains "D13 ubi9 build disables the hummingbird repositories" "${ubi9_cf}" "--disablerepo=public-hummingbird*"
    assert_contains "D14 ubi9 build copies its own repo file" "${ubi9_cf}" "COPY yum-repos/ubi9.repo"
    assert_contains "D15 ubi9 compliance uses the ubi9 datastream" "${ubi9_cf}" "/run/src/oscap/ssg-rhel9-ds.xml"
    assert_contains "D16 compliance tailoring is passed when rules are excluded" "${default_cf}" "--tailoring-file"
    assert_file "D17 oscap-tailoring.xml generated" "$(variant_dir hummingbird default)/oscap-tailoring.xml"
    assert_contains "D18 tailoring excludes the configured rule" \
        "$(read_file "$(variant_dir hummingbird default)/oscap-tailoring.xml")" "no_example_rule"

    assert_contains "D19 oci-archive reference rewritten to an absolute path" "${default_cf}" \
        "FROM oci-archive:${CURL_CTX}/out.ociarchive"

    assert_eq "D20 ubi9 version comes from the ubi9 repositories" "8.10.1" \
        "$(read_file "$(variant_dir ubi9 default)/VERSION")"
    assert_eq "D21 hummingbird version comes from the hummingbird repositories" "8.21.0" \
        "$(read_file "$(variant_dir hummingbird default)/VERSION")"
    assert_contains "D22 ubi9 tags carry the ubi9 version" \
        "$(read_file "$(variant_dir ubi9 default)/TAGS")" "8.10.1"
    assert_contains "D23 variant tags are suffixed with the variant" \
        "$(read_file "$(variant_dir hummingbird fips)/TAGS")" "8.21.0-fips"
fi

# --------------------------------------------------------------------------- #
# Group E — configuration errors surface as messages, not tracebacks
# --------------------------------------------------------------------------- #
if matches_filter "errors"; then
    group "E. Robustness: clean errors for missing configuration"

    # Flaw: rendering aborted with "UndefinedError: 'oscap' is undefined" for
    # any image whose merged config had no oscap section.
    hbgen prepare --image-dir "${HELLO}" --builders-dir "${NO_OSCAP_BUILDERS}" >/dev/null 2>&1
    ( cd "${HELLO}/.hbgen" && "${PYTHON}" "${VENDORED}/aggregate_properties.py" >/dev/null 2>&1 )
    hbgen rpms --hbgen "${HELLO}/.hbgen" --image hello >/dev/null 2>&1
    printf 'distros:\n  hummingbird:\n    hello: 1.0.0-1.hum1\n    filesystem: 3.18-1.hum1\n' \
        > "${HELLO}/.hbgen/.cache/rpm-versions.yml"

    output="$(hbgen render --hbgen "${HELLO}/.hbgen" --image hello 2>&1)"
    status=$?
    assert_eq "E1 image without any oscap config renders" "0" "${status}"
    assert_no_traceback "E2 no Jinja UndefinedError traceback" "${output}"
    assert_file "E3 Containerfile rendered" "${HELLO}/.hbgen/images/hello/hummingbird/default/Containerfile"
    assert_no_file "E4 empty oscap-tailoring.xml is not written" \
        "${HELLO}/.hbgen/images/hello/hummingbird/default/oscap-tailoring.xml"
    assert_eq "E5 version resolved from the per-distro cache" "1.0.0" \
        "$(read_file "${HELLO}/.hbgen/images/hello/hummingbird/default/VERSION")"

    broken="${WORK}/broken-props"
    cp -R "${CURL}" "${broken}"
    grep -v '^stream:' "${CURL}/properties.yml" > "${broken}/properties.yml"
    output="$(hbgen prepare --image-dir "${broken}" --builders-dir "${BUILDERS}" 2>&1; \
              cd "${broken}/.hbgen" 2>/dev/null && "${PYTHON}" "${VENDORED}/aggregate_properties.py" 2>&1; \
              "${PYTHON}" "${VENDORED}/generate_jinja2.py" templates/VERSION.j2 \
                "${broken}/.hbgen/images/curl/hummingbird/default/VERSION" 2>&1)"
    assert_fails_with "E6 missing required property names the key" "${output}" "stream"
    assert_no_traceback "E7 missing property is a message, not a traceback" "${output}"

    novars="${WORK}/no-vars"
    mkdir -p "${novars}"
    printf 'summary: s\n' > "${novars}/properties.yml"
    printf 'x\n' > "${novars}/Containerfile.j2"
    output="$(hbgen prepare --image-dir "${novars}" --builders-dir "${BUILDERS}" 2>&1)"
    assert_fails_with "E8 missing variables.yml explains both locations" "${output}" "variables.yml"
    assert_no_traceback "E9 missing variables.yml is a message, not a traceback" "${output}"

    badvars="${WORK}/bad-vars"
    cp -R "${NO_OSCAP_BUILDERS}" "${badvars}"
    printf 'default_distros: [hummingbird]\n' > "${badvars}/variables.yml"
    output="$(cd "${badvars}/hello/.hbgen" 2>/dev/null || mkdir -p "${badvars}/hello/.hbgen"; \
              cd "${badvars}/hello" && hbgen prepare --image-dir "${badvars}/hello" --builders-dir "${badvars}" >/dev/null 2>&1; \
              cd "${badvars}/hello/.hbgen" && "${PYTHON}" "${VENDORED}/aggregate_properties.py" 2>&1)"
    assert_contains "E10 omitted default_variants uses the secure default" "${output}" "variants: default"
    assert_no_traceback "E11 default_variants is optional" "${output}"

    emptyvars="${WORK}/empty-vars"
    cp -R "${NO_OSCAP_BUILDERS}" "${emptyvars}"
    : > "${emptyvars}/variables.yml"
    output="$(hbgen prepare --image-dir "${emptyvars}/hello" --builders-dir "${emptyvars}" >/dev/null 2>&1; \
              cd "${emptyvars}/hello/.hbgen" && "${PYTHON}" "${VENDORED}/aggregate_properties.py" 2>&1)"
    assert_fails_with "E12 empty variables.yml is reported" "${output}" "empty"

    notabuilder="${WORK}/plain"
    mkdir -p "${notabuilder}"
    output="$(hbgen prepare --image-dir "${notabuilder}" 2>&1)"
    assert_fails_with "E13 non-builder directory is rejected" "${output}" "not a hummingbird builder"
fi

# --------------------------------------------------------------------------- #
# Group F — bash driver contract
# --------------------------------------------------------------------------- #
if matches_filter "driver"; then
    group "F. Bash driver contract (ci-hummingbird.sh)"

    # shellcheck source=/dev/null
    source "${LIB_DIR}/ci-core.sh"
    # shellcheck source=/dev/null
    source "${LIB_DIR}/ci-config.sh"
    # shellcheck source=/dev/null
    source "${LIB_DIR}/ci-hummingbird.sh"

    export BUILDERS_DIR="${BUILDERS}"
    export SOURCE_DIR="${CURL}"

    assert_eq "F1 detect_flavor recognises a builder" "hummingbird" "$(ci_hummingbird_detect_flavor "${CURL}")"
    assert_eq "F2 detect_flavor recognises a Dockerfile directory" "dockerfile" \
        "$(mkdir -p "${WORK}/dock" && touch "${WORK}/dock/Dockerfile" && ci_hummingbird_detect_flavor "${WORK}/dock")"
    assert_eq "F3 detect_flavor returns empty for an unrelated directory" "" \
        "$(ci_hummingbird_detect_flavor "${WORK}")"

    assert_eq "F4 find_image resolves BUILDERS_DIR/<name>" "${CURL}" "$(ci_hummingbird_find_image curl)"
    assert_eq "F5 find_image falls back to SOURCE_DIR" "${CURL}" \
        "$(BUILDERS_DIR="" ci_hummingbird_find_image "")"

    # Flaw: a helper function defined inside another function leaked into the
    # global namespace of the sourcing script.
    ci_hummingbird_find_image curl >/dev/null 2>&1
    leaked="$(declare -F search_dir >/dev/null 2>&1 && echo yes || echo no)"
    assert_eq "F6 no helper function leaks into the global namespace" "no" "${leaked}"

    # Flaw: ${1:?} inside a sourced function terminated the caller's shell.
    output="$(bash -c "
        source '${LIB_DIR}/ci-core.sh'
        source '${LIB_DIR}/ci-hummingbird.sh'
        ci_hummingbird_build '' >/dev/null 2>&1
        echo survived
    " 2>&1)"
    assert_contains "F7 empty argument returns an error instead of killing the shell" "${output}" "survived"

    # Full pipeline with a stubbed build engine.
    BUILT_ROWS=()
    ci_build_and_push() {
        # Deliberately reads stdin: with `while read` loops this consumed the
        # remaining matrix rows and silently built only part of the matrix.
        head -c 8 >/dev/null 2>&1 || true
        BUILT_ROWS+=("${CONFIG[DISTRO]}/${CONFIG[VARIANT]}:${CONFIG[IMAGE_NAME]}")
        # WHY assigned but not read here: the real ci_build_and_push exports this
        # global and the driver consumes it for image cleanup, so the stub must
        # reproduce the contract even though nothing in the test reads it.
        # shellcheck disable=SC2034
        CI_BUILT_IMAGES=("${CONFIG[IMAGE_NAME]}:probe")
        return 0
    }
    detect_container_engine() { printf 'podman\n'; }

    unset HB_DISTROS HB_VARIANTS HB_VERSION HB_TAGS HB_REGISTRIES REGISTRY PLATFORMS SKIP_PUSH SOURCE_DATE_EPOCH
    ci_hummingbird_build "${CURL}" > "${WORK}/build.log" 2>&1
    status=$?
    assert_eq "F8 full pipeline succeeds" "0" "${status}"
    assert_eq "F9 every matrix row was built (stdin-safe iteration)" "9" "${#BUILT_ROWS[@]}"
    assert_eq "F10 images accumulated for post-build cleanup" "9" "${#HB_BUILT_IMAGES[@]}"
    assert_contains "F11 composite builder variant built as curl-builder" "${BUILT_ROWS[*]}" \
        "hummingbird/fips-builder:curl-builder"
    assert_not_contains "F12 restricted ubi9/debug never built" "${BUILT_ROWS[*]}" "ubi9/debug:"

    # Reproducible builds: the engine passes CONFIG[ARG_*] from the environment,
    # so the epoch has to be exported and stable between rows.
    first_epoch="${SOURCE_DATE_EPOCH:-}"
    ci_hummingbird_configure "${CURL}" hummingbird default > /dev/null 2>&1
    second_epoch="${SOURCE_DATE_EPOCH:-}"
    if [[ "${first_epoch}" =~ ^[0-9]+$ && "${first_epoch}" == "${second_epoch}" ]]; then
        ok "F13 SOURCE_DATE_EPOCH exported and stable across rows"
    else
        fail "F13 SOURCE_DATE_EPOCH exported and stable across rows" \
            "first: [${first_epoch}] second: [${second_epoch}]"
    fi
    assert_eq "F13b engine sees the epoch as a build arg" "present" "${CONFIG[ARG_SOURCE_DATE_EPOCH]:-}"

    # Per-row configuration
    ci_hummingbird_configure "${CURL}" ubi9 default > /dev/null 2>&1
    assert_eq "F14 version resolved for the ubi9 row" "8.10.1" "${CONFIG[VERSION]:-}"
    assert_eq "F15 tags come from the rendered TAGS file" "custom" "${CONFIG[TAG_STRATEGY]:-}"
    assert_contains "F16 custom tags carry the ubi9 version" "${CONFIG[CUSTOM_TAGS]:-}" "8.10.1"
    assert_eq "F17 chunkah detected from the rendered Containerfile" "true" "${CONFIG[CHUNKAH]:-}"
    assert_eq "F18 registry from variables.yml" "ghcr.io/technobureau" "${CONFIG[DF_REGISTRY_0]:-}"

    # Flaw: CONFIG keys leaked from the previous row, so a row with fewer
    # registries inherited (and pushed to) the leftovers.
    CONFIG[DF_REGISTRY_5]="stale.example.com"
    ci_hummingbird_configure "${CURL}" hummingbird builder > /dev/null 2>&1
    assert_eq "F19 stale registry keys are cleared between rows" "" "${CONFIG[DF_REGISTRY_5]:-}"

    HB_VERSION=9.9.9 HB_TAGS="9.9.9 edge" ci_hummingbird_configure "${CURL}" hummingbird default > /dev/null 2>&1
    assert_eq "F20 HB_VERSION overrides the resolved version" "9.9.9" "${CONFIG[VERSION]:-}"
    assert_eq "F21 HB_TAGS overrides the generated tags" "9.9.9 edge" "${CONFIG[CUSTOM_TAGS]:-}"

    HB_REGISTRIES="quay.io/acme,icr.io/ns" IMAGE_PREFIX="team" \
        ci_hummingbird_configure "${CURL}" hummingbird default > /dev/null 2>&1
    assert_eq "F22 HB_REGISTRIES takes precedence" "quay.io/acme" "${CONFIG[DF_REGISTRY_0]:-}"
    assert_eq "F23 second registry parsed" "icr.io/ns" "${CONFIG[DF_REGISTRY_1]:-}"
    assert_eq "F24 IMAGE_PREFIX applied" "team" "${CONFIG[DF_REGISTRY_0_PREFIX]:-}"

    SKIP_PUSH=true ci_hummingbird_configure "${CURL}" hummingbird default > /dev/null 2>&1
    assert_eq "F25 SKIP_PUSH disables pushing" "false" "${CONFIG[DF_REGISTRY_0_PUSH]:-}"

    # Archive cleanup happens at the pipeline boundary, not per build.
    touch "${CURL_CTX}/out.ociarchive" "${CURL_CTX}/out-amd64.ociarchive"
    ci_hummingbird_cleanup_archives "${CURL_CTX}"
    removed=0
    [[ -e "${CURL_CTX}/out.ociarchive" ]] && removed=1
    [[ -e "${CURL_CTX}/out-amd64.ociarchive" ]] && removed=1
    assert_eq "F26 chunkah archives removed from the context" "0" "${removed}"

    HB_SKIP_RPM_VERSIONS=true ci_hummingbird_resolve_rpm_versions "${CURL}" > "${WORK}/skip.log" 2>&1
    assert_contains "F27 HB_SKIP_RPM_VERSIONS skips the engine stage" "$(cat "${WORK}/skip.log")" "skipping"

    # Flaw: TAG_STRATEGY=custom makes the engine publish CONFIG[CUSTOM_TAGS]
    # verbatim, so a row whose package version could not be resolved pushed real
    # ":unknown" / ":unknown-fips" tags to the registry (VERSION fell back to
    # latest, the tag list did not).
    unresolved_dir="$(variant_dir hummingbird fips)"
    printf 'unknown\n' > "${unresolved_dir}/VERSION"
    printf 'unknown-fips\nunknown-fips\nlatest-fips\n' > "${unresolved_dir}/TAGS"
    # WHY stderr goes to a file and not to $(...): a command substitution runs
    # the function in a SUBSHELL, so its writes to the global CONFIG array would
    # be discarded and the next two assertions would see stale values.
    ci_hummingbird_configure "${CURL}" hummingbird fips > /dev/null 2> "${WORK}/f28.err"
    stderr="$(cat "${WORK}/f28.err")"
    assert_eq "F28 unresolved 'unknown' tags are never published" "latest-fips" "${CONFIG[CUSTOM_TAGS]:-}"
    assert_eq "F29 VERSION falls back to latest when unresolved" "latest" "${CONFIG[VERSION]:-}"
    assert_contains "F30 dropping unresolved tags is reported" "${stderr}" "unresolved version"

    # The filter must not over-reach: a resolved tag list passes through intact,
    # in order, with duplicates removed.
    printf '8.21.0\n' > "${unresolved_dir}/VERSION"
    printf '8.21.0-fips\n8.21.0-fips\n8.21-fips\nlatest-fips\n' > "${unresolved_dir}/TAGS"
    ci_hummingbird_configure "${CURL}" hummingbird fips > /dev/null 2>&1
    assert_eq "F31 resolved tags pass through, deduplicated, in order" \
        "8.21.0-fips 8.21-fips latest-fips" "${CONFIG[CUSTOM_TAGS]:-}"
    assert_eq "F32 resolved VERSION is untouched" "8.21.0" "${CONFIG[VERSION]:-}"
fi

# --------------------------------------------------------------------------- #
# Summary
# --------------------------------------------------------------------------- #
printf '\n\033[1mSummary\033[0m\n'
printf '  passed: %d\n  failed: %d\n' "${PASSED}" "${FAILED}"
# WHY: a green run that only covered part of the suite must not look like a
# green full run.
[[ -n "${FILTER}" ]]      && printf '  group filter (-k): %s\n' "${FILTER}"
[[ -n "${TEST_FILTER}" ]] && printf '  assertion filter (-t): %s  (other assertions ran but were not reported)\n' "${TEST_FILTER}"
if ((FAILED > 0)); then
    printf '\n\033[31mFAILED\033[0m\n'
    exit 1
fi
printf '\n\033[32mALL TESTS PASSED\033[0m\n'
