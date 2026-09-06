#!/usr/bin/env python3
"""Package set resolution — one rule for what a distro/variant installs.

Two artifacts must describe the same package set:

``rpms/rpms.in.yaml``
    Consumed by the lockfile tooling and by get_rpm_versions.sh, so it decides
    which package versions are resolved and tagged.

``ARG MAIN_PACKAGES`` in the rendered Containerfile
    What dnf-installroot actually installs into the image.

They used to be computed independently — once in generate_rpms_in.py and once in
package_args.yml.j2 — and the two rules had drifted:

=========================================  =============  =================
Key                                        rpms.in.yaml   MAIN_PACKAGES
=========================================  =============  =================
``rpm_packages.all``                        yes            yes
``rpm_packages.<distro>``                   yes            yes
``rpm_packages.<variant>``                  yes            yes
``rpm_packages.<distro>/<variant>``         yes            yes
``rpm_packages.builder`` for "fips-builder" no             no
``default_rpm_packages.<variant>``          yes            **no**
``default_rpm_packages.builder``            endswith only  macro only
=========================================  =============  =================

So a composite builder variant silently lost the image's own builder packages,
and any ``default_rpm_packages.<variant>`` entry had its version resolved but
was never installed. Both artifacts now come from :func:`resolve_package_set`.

Key rule (applied to the image's ``rpm_packages`` and to the shared
``default_rpm_packages``):

    all, <distro>, <variant>, <distro>/<variant>,
    every modifier of the variant ("builder", "fips"),
    and the variant base when it is a real base name ("fpm" in "fpm-fips-builder")

``build-deps`` is resolved separately: those packages are installed in the
builder stage, not into the newroot, but they still need versions.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from hb_variant import DEFAULT_BASE_VARIANT, decompose_variant

#: Key holding packages installed into the image for every variant.
KEY_ALL = "all"
#: Key holding packages installed only in the builder stage.
KEY_BUILD_DEPS = "build-deps"
#: Architectures the Containerfile case statement can select from.
SUPPORTED_ARCHES = ("aarch64", "x86_64")
#: dnf/OCI architecture names, for the TARGETARCH case statement.
ARCH_TO_TARGETARCH = {"x86_64": "amd64", "aarch64": "arm64"}


@dataclass(frozen=True)
class PackageSet:
    """Resolved packages for one distro/variant."""

    #: Plain package names installed into the newroot (sorted, deduplicated).
    main: list[str] = field(default_factory=list)
    #: Plain package names installed in the builder stage (sorted).
    build: list[str] = field(default_factory=list)
    #: Arch-constrained entries, verbatim, for rpms.in.yaml (sorted by name).
    arch_entries: list[dict[str, Any]] = field(default_factory=list)
    #: Arch-constrained names grouped by architecture, for the Containerfile.
    arch_packages: dict[str, list[str]] = field(default_factory=dict)


def package_keys(distro: str, variant: str) -> list[str]:
    """Ordered rpm_packages/default_rpm_packages keys for a distro/variant.

    Modifier and base keys are what make composite variants work: "fips-builder"
    picks up the "builder" and "fips" package groups as well as its own.
    """
    info = decompose_variant(variant)
    keys = [KEY_ALL, distro, variant, f"{distro}/{variant}"]

    # Only the modifiers this variant actually carries, plus its base name when
    # the base is a real variant ("fpm"), not the implicit "default".
    if info.is_builder:
        keys.append("builder")
    if info.is_fips:
        keys.append("fips")
    if info.base not in (variant, DEFAULT_BASE_VARIANT):
        keys.append(info.base)

    deduplicated: list[str] = []
    for key in keys:
        if key and key not in deduplicated:
            deduplicated.append(key)
    return deduplicated


def resolve_package_set(
    properties: dict[str, Any],
    variables: dict[str, Any],
    distro: str,
    variant: str,
) -> PackageSet:
    """Resolve every package this distro/variant needs.

    Args:
        properties: Image properties (``rpm_packages``).
        variables: Merged variables (``default_rpm_packages``).
        distro: Distro being built.
        variant: Variant being built.
    """
    keys = package_keys(distro, variant)
    sources = (
        properties.get("rpm_packages") or {},
        variables.get("default_rpm_packages") or {},
    )

    plain_main: set[str] = set()
    plain_build: set[str] = set()
    arch_entries: list[dict[str, Any]] = []

    for source in sources:
        if not isinstance(source, dict):
            continue
        for key in keys:
            for entry in source.get(key) or []:
                if isinstance(entry, str):
                    plain_main.add(entry)
                elif isinstance(entry, dict) and entry.get("name"):
                    arch_entries.append(entry)
        for entry in source.get(KEY_BUILD_DEPS) or []:
            if isinstance(entry, str):
                plain_build.add(entry)
            elif isinstance(entry, dict) and entry.get("name"):
                arch_entries.append(entry)

    return PackageSet(
        main=sorted(plain_main),
        build=sorted(plain_build),
        arch_entries=_deduplicate_arch_entries(arch_entries),
        arch_packages=_group_by_arch(arch_entries),
    )


def _deduplicate_arch_entries(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Sort arch-constrained entries by name and drop exact duplicates."""
    import json

    seen: set[str] = set()
    unique: list[dict[str, Any]] = []
    for entry in sorted(entries, key=lambda item: str(item.get("name", ""))):
        fingerprint = json.dumps(entry, sort_keys=True, default=str)
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        unique.append(entry)
    return unique


def _group_by_arch(entries: list[dict[str, Any]]) -> dict[str, list[str]]:
    """Group arch-constrained package names by architecture.

    ``arches.only`` lists the architectures a package is installed on;
    ``arches.not`` lists the ones it is excluded from.
    """
    grouped: dict[str, list[str]] = {}
    for entry in entries:
        name = str(entry.get("name", ""))
        if not name:
            continue
        arches = entry.get("arches") or {}
        only = arches.get("only")
        excluded = arches.get("not")

        if only is not None:
            wanted = [only] if isinstance(only, str) else list(only)
            targets = [arch for arch in wanted if arch in SUPPORTED_ARCHES]
        elif excluded is not None:
            blocked = [excluded] if isinstance(excluded, str) else list(excluded)
            targets = [arch for arch in SUPPORTED_ARCHES if arch not in blocked]
        else:
            continue

        for arch in targets:
            names = grouped.setdefault(arch, [])
            if name not in names:
                names.append(name)

    return {arch: sorted(grouped[arch]) for arch in sorted(grouped)}


def targetarch(arch: str) -> str:
    """Map an rpm architecture to the TARGETARCH value used in a Containerfile."""
    return ARCH_TO_TARGETARCH.get(arch, arch)
