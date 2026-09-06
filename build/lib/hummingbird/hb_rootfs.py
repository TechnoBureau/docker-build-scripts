#!/usr/bin/env python3
"""Rootfs policy shared by package resolution and Containerfile rendering.

`default` keeps its unsuffixed tags, but is FIPS-enabled. FIPS is independent of
OSCAP (which only controls scanning). No builder filesystem is implicitly used
as a base: base_image must be explicitly configured.
"""
from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any

from hb_config import ConfigError, as_bool, as_list, effective_section
from hb_variant import decompose_variant

# Current public Hummingbird/UBI repositories provide the provider and its .so
# separately. These are required packages, not weak deps (weak deps are off).
# Hummingbird additionally ships openssl-config-fips; UBI does not. Do not put
# that distro-specific package in a shared `all` group.
FIPS_COMMON = (
    "crypto-policies", "crypto-policies-scripts", "openssl", "openssl-libs",
    "openssl-fips-provider", "openssl-fips-provider-so",
)
FIPS_PACKAGES = {
    "hummingbird": (*FIPS_COMMON, "openssl-config-fips"),
    "ubi9": FIPS_COMMON,
    "ubi10": FIPS_COMMON,
}


@dataclass(frozen=True)
class RootfsConfig:
    base_image: str
    fips: bool
    crypto_policy: str
    fips_packages: tuple[str, ...]
    chunkah: bool


def _scoped(value: Any, distro: str, variant: str, default: Any = None) -> Any:
    """Scalar or distro/variant > distro > variant > default mapping."""
    if not isinstance(value, dict):
        return value
    for key in (f"{distro}/{variant}", distro, variant, "default"):
        if key in value:
            return value[key]
    return default


def _boolean(value: Any, key: str, default: bool) -> bool:
    if value is None:
        return default
    if str(value).lower() not in ("true", "false", "yes", "no", "on", "off", "1", "0"):
        raise ConfigError(f"{key} must be a boolean, got {value!r}")
    return as_bool(value)


def resolve_rootfs(variables: dict, properties: dict, distro: str, variant: str) -> RootfsConfig:
    """Resolve the security, seed and assembly contract for one build row.

    Image properties override shared variables (including an explicit `scratch`
    seed). base_image and fips may also be scoped mappings. A FIPS-named variant
    cannot opt out, and its crypto policy cannot claim DEFAULT while it is
    labelled FIPS. Unsupported distro packages fail early rather than guessing.
    """
    values = {**variables, **properties}
    fips = _boolean(_scoped(values.get("fips"), distro, variant, True), "fips", True)
    if decompose_variant(variant).is_fips and not fips:
        raise ConfigError(f"fips cannot be disabled for a FIPS-named variant '{variant}'")
    if fips and distro not in FIPS_PACKAGES:
        raise ConfigError(f"no FIPS package policy for distro '{distro}'; add it to hb_rootfs.FIPS_PACKAGES")

    oscap = effective_section(variables, properties, "oscap")
    policies = oscap.get("crypto_policy_variants") or {}
    if not isinstance(policies, dict):
        raise ConfigError("oscap.crypto_policy_variants must be a mapping")
    policy = policies.get(variant, oscap.get("crypto_policy")) or ("FIPS" if fips else "DEFAULT")
    if not isinstance(policy, str) or not re.fullmatch(r"[A-Z][A-Z0-9_-]*(?::[A-Z0-9_-]+)*", policy):
        raise ConfigError(f"invalid oscap.crypto_policy: {policy!r}")
    if (policy.split(":")[0] == "FIPS") != fips:
        raise ConfigError(
            f"fips={str(fips).lower()} contradicts crypto_policy={policy!r} for {distro}/{variant}; "
            "use a FIPS policy, or explicitly set fips: false for a non-FIPS variant"
        )

    base = _scoped(values.get("base_image", ""), distro, variant, "")
    if base is None or base == "scratch":
        base = ""
    if not isinstance(base, str) or (base and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/@+-]*", base)):
        raise ConfigError("base_image must be an image reference (optionally a distro mapping), not shell/Jinja text")
    removals = values.get("remove_rpms_from_newroot") or []
    removals = removals.split() if isinstance(removals, str) else as_list(removals)
    if not all(isinstance(name, str) for name in removals):
        raise ConfigError("remove_rpms_from_newroot must contain package names")
    forbidden = sorted(set(removals) & set(FIPS_PACKAGES.get(distro, ()))) if fips else []
    if forbidden:
        raise ConfigError(f"remove_rpms_from_newroot cannot remove required FIPS packages: {', '.join(forbidden)}")
    return RootfsConfig(
        base_image=base,
        fips=fips,
        crypto_policy=policy,
        fips_packages=FIPS_PACKAGES[distro] if fips else (),
        chunkah=_boolean(values.get("chunkah"), "chunkah", False),
    )
