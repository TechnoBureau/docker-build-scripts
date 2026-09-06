#!/usr/bin/env python3
"""Target platforms for Hummingbird and UBI: one selection for every stage.

The common supported set is amd64 + arm64. OCI and RPM aliases are accepted,
then canonicalised before producing lock inputs, repo queries or engine config.
An omitted selection means the runner's native architecture, not both arches.
"""
from __future__ import annotations

import os
import platform
from collections.abc import Mapping, Sequence
from typing import Any

from hb_config import ConfigError

ARCH_TO_TARGETARCH = {"x86_64": "amd64", "aarch64": "arm64"}
SUPPORTED_ARCHES = tuple(ARCH_TO_TARGETARCH)
ALIASES = {**{arch: arch for arch in SUPPORTED_ARCHES},
           **{oci: rpm for rpm, oci in ARCH_TO_TARGETARCH.items()}}


def rpm_arch(value: str) -> str:
    """Canonical RPM architecture, accepting a bare arch or an OCI platform."""
    name = str(value).strip().lower()
    if name.startswith("linux/"):
        name = name.removeprefix("linux/")
    if name == "arm64/v8":
        name = "arm64"
    if name not in ALIASES:
        raise ConfigError(
            f"unsupported architecture/platform '{value}': Hummingbird/UBI builds "
            "support linux/amd64 (x86_64) and linux/arm64 (aarch64)"
        )
    return ALIASES[name]


def targetarch(arch: str) -> str:
    return ARCH_TO_TARGETARCH[rpm_arch(arch)]


def rpm_arches(platforms: Sequence[str]) -> list[str]:
    return list(dict.fromkeys(rpm_arch(item) for item in platforms))


def _items(value: Any) -> list[str]:
    if isinstance(value, str):
        return value.replace(",", " ").split()
    if isinstance(value, (list, tuple)) and all(isinstance(item, str) for item in value):
        return list(value)
    raise ConfigError("platforms must be a list or a comma/space-separated string")


def resolve_platforms(
    variables: Mapping[str, Any],
    properties: Mapping[str, Any],
    *,
    native_arch: str | None = None,
) -> list[str]:
    """PLATFORMS > properties.platforms > variables.platforms > runner native.

    An explicit empty list or a typo is an error; it must not silently turn a
    requested multi-arch build into an unrelated native build.
    """
    env = os.environ.get("PLATFORMS", "").strip()
    if env:
        configured = env
    elif "platforms" in properties:
        configured = properties["platforms"]
    elif "platforms" in variables:
        configured = variables["platforms"]
    else:
        configured = native_arch or platform.machine()
    values = _items(configured)
    if not values:
        raise ConfigError("platforms is empty; omit it for native, or select linux/amd64 and/or linux/arm64")
    return list(dict.fromkeys(f"linux/{targetarch(item)}" for item in values))


def entry_arches(entry: Mapping[str, Any]) -> list[str]:
    """Architectures selected by a package's arches.only AND arches.not."""
    constraints = entry.get("arches") or {}
    if not isinstance(constraints, dict) or set(constraints) - {"only", "not"}:
        raise ConfigError(f"invalid arches for package '{entry.get('name')}': use only/not")
    only = rpm_arches(_items(constraints["only"])) if "only" in constraints else list(SUPPORTED_ARCHES)
    excluded = rpm_arches(_items(constraints["not"])) if "not" in constraints else []
    return [arch for arch in only if arch not in excluded]
