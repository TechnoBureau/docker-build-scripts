#!/usr/bin/env python3
"""One package-set resolver for RPM lock inputs and the rendered Containerfile.

Runtime and builder dependencies remain separate, including arch-specific ones.
Distro/modifier groups extend the mandatory filesystem and FIPS baseline. Both
sources (rpm_packages and default_rpm_packages) follow the same key rules.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import re
from typing import Any

from hb_config import ConfigError, as_list, effective_section
from hb_platforms import ARCH_TO_TARGETARCH, SUPPORTED_ARCHES, entry_arches, targetarch
from hb_rootfs import resolve_rootfs
from hb_variant import DEFAULT_BASE_VARIANT, decompose_variant

KEY_ALL = "all"
KEY_BUILD_DEPS = "build-deps"


@dataclass(frozen=True)
class PackageSet:
    main: list[str] = field(default_factory=list)
    build: list[str] = field(default_factory=list)
    arch_entries: list[dict[str, Any]] = field(default_factory=list)
    arch_packages: dict[str, list[str]] = field(default_factory=dict)
    build_arch_packages: dict[str, list[str]] = field(default_factory=dict)


def package_keys(distro: str, variant: str, *, fips: bool | None = None) -> list[str]:
    """all + distro + variant + distro/variant + base/modifier equivalents."""
    info = decompose_variant(variant)
    keys = [KEY_ALL, distro, variant, f"{distro}/{variant}"]
    modifiers = []
    if info.is_builder:
        modifiers.append("builder")
    if (info.is_fips if fips is None else fips):
        modifiers.append("fips")
    if info.base not in (variant, DEFAULT_BASE_VARIANT):
        modifiers.append(info.base)
    for modifier in modifiers:
        keys.extend((modifier, f"{distro}/{modifier}"))
    return list(dict.fromkeys(keys))


def _add_entries(entries: Any, plain: set[str], by_name: dict[str, set[str]]) -> None:
    for entry in as_list(entries):
        name = entry.get("name") if isinstance(entry, dict) else entry
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.+:-]*", name):
            raise ConfigError(f"invalid RPM package name/entry: {entry!r}")
        if isinstance(entry, str) or not entry.get("arches"):
            plain.add(name)
        else:
            by_name.setdefault(name, set()).update(entry_arches(entry))


def _group_by_arch(by_name: dict[str, set[str]], plain: set[str]) -> dict[str, list[str]]:
    return {
        arch: sorted(name for name, arches in by_name.items() if arch in arches and name not in plain)
        for arch in SUPPORTED_ARCHES
        if any(arch in arches and name not in plain for name, arches in by_name.items())
    }


def resolve_package_set(properties: dict, variables: dict, distro: str, variant: str) -> PackageSet:
    """Return deterministic runtime, build-time and architecture-specific sets.

    WHY resolve the properties overlay here, not in each caller: extending
    default_rpm_packages in properties.yml must affect the lock inputs AND the
    installed packages. Neither the renderer nor rpms generator may merge it
    independently.
    """
    rootfs = resolve_rootfs(variables, properties, distro, variant)
    keys = package_keys(distro, variant, fips=rootfs.fips)
    plain_main = {"filesystem", *rootfs.fips_packages}
    plain_build: set[str] = set()
    main_arch: dict[str, set[str]] = {}
    build_arch: dict[str, set[str]] = {}
    for section in ("rpm_packages", "default_rpm_packages"):
        source = effective_section(variables, properties, section)
        for key in keys:
            _add_entries(source.get(key), plain_main, main_arch)
        _add_entries(source.get(KEY_BUILD_DEPS), plain_build, build_arch)

    locked_arches: dict[str, set[str]] = {}
    for source in (main_arch, build_arch):
        for name, arches in source.items():
            if name not in plain_main | plain_build:
                locked_arches.setdefault(name, set()).update(arches)
    return PackageSet(
        main=sorted(plain_main),
        build=sorted(plain_build),
        arch_entries=[{"name": name, "arches": {"only": sorted(arches)}}
                      for name, arches in sorted(locked_arches.items()) if arches],
        arch_packages=_group_by_arch(main_arch, plain_main),
        build_arch_packages=_group_by_arch(build_arch, plain_build),
    )
