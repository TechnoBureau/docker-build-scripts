#!/usr/bin/env python3
"""Configuration loading and merging for the hummingbird pipeline.

Two YAML sources feed every build:

``variables.yml``
    Build configuration. A shared ``builders/variables.yml`` (defaults for
    every image) optionally overridden by a per-image ``variables.yml``.
    Merged with :func:`merge_variables` — **lists replace**, because an
    override such as ``default_distros: [ubi9]`` is meant to select ubi9
    only, not to add it to the shared list.

``properties.yml``
    Image definition (summary, tags, packages, variants). Merged on top of
    the variables by :func:`deep_merge` with ``list_policy="extend"`` when
    building the template context, so a per-image ``oscap.exclude_rules``
    adds to the global rules instead of silently dropping them.

Both merges are implemented once, here. Keeping them in a single function
with an explicit ``list_policy`` is what prevents the two sources from
drifting apart — they used to be three separate copies with undocumented
differences.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

#: List handling for the variables.yml (shared + per-image) merge.
LIST_POLICY_REPLACE = "replace"
#: List handling for the properties.yml overlay used by the templates.
LIST_POLICY_EXTEND = "extend"


class ConfigError(RuntimeError):
    """Raised for missing/invalid configuration, with an actionable message."""


def load_yaml(path: str | Path, description: str) -> dict[str, Any]:
    """Load a YAML mapping, raising ConfigError with context on any problem.

    Args:
        path: File to read.
        description: Human readable name used in error messages, e.g.
            ``"builders/variables.yml (shared defaults)"``.
    """
    path = Path(path)
    if not path.is_file():
        raise ConfigError(f"{description} not found: {path}")
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ConfigError(f"{description} is not valid YAML: {path}\n  {exc}") from exc
    if data is None:
        raise ConfigError(f"{description} is empty: {path}")
    if not isinstance(data, dict):
        raise ConfigError(
            f"{description} must contain a mapping at the top level, "
            f"got {type(data).__name__}: {path}"
        )
    return data


def require_keys(mapping: dict[str, Any], keys: tuple[str, ...], source: str) -> None:
    """Validate that all keys are present and non-empty in mapping.

    Args:
        mapping: Data to validate.
        keys: Required key names.
        source: File description used in the error message.

    Raises:
        ConfigError: Listing every missing key at once, so the operator fixes
            the file in one pass instead of one error per run.
    """
    missing = [key for key in keys if not mapping.get(key)]
    if missing:
        raise ConfigError(
            f"{source} is missing required key(s): {', '.join(missing)}"
        )


def deep_merge(
    base: dict[str, Any],
    overlay: dict[str, Any],
    list_policy: str = LIST_POLICY_EXTEND,
) -> dict[str, Any]:
    """Deep-merge overlay onto base and return a new dict.

    Dicts are merged recursively. Lists are either replaced or concatenated
    (base first) according to list_policy. Every other value: overlay wins.

    Args:
        base: Values with lower precedence.
        overlay: Values with higher precedence.
        list_policy: LIST_POLICY_REPLACE or LIST_POLICY_EXTEND.
    """
    if list_policy not in (LIST_POLICY_REPLACE, LIST_POLICY_EXTEND):
        raise ValueError(f"unknown list_policy: {list_policy}")

    merged = dict(base)
    for key, value in overlay.items():
        existing = merged.get(key)
        if isinstance(existing, dict) and isinstance(value, dict):
            merged[key] = deep_merge(existing, value, list_policy)
        elif (
            list_policy == LIST_POLICY_EXTEND
            and isinstance(existing, list)
            and isinstance(value, list)
        ):
            merged[key] = [*existing, *value]
        else:
            merged[key] = value
    return merged


def merge_variables(base_path: str | Path, overlay_path: str | Path | None) -> dict[str, Any]:
    """Merge the shared variables.yml with the per-image overlay.

    Args:
        base_path: Shared ``builders/variables.yml``.
        overlay_path: Per-image ``variables.yml``; skipped when it is None or
            the same file as base_path.
    """
    base = load_yaml(base_path, "variables.yml (shared defaults)")
    if overlay_path is None or Path(overlay_path) == Path(base_path):
        return base
    if not Path(overlay_path).is_file():
        return base
    overlay = load_yaml(overlay_path, "variables.yml (per-image overrides)")
    return deep_merge(base, overlay, LIST_POLICY_REPLACE)


def effective_section(
    variables: dict[str, Any], properties: dict[str, Any], section: str
) -> dict[str, Any]:
    """Resolve one configuration section as the templates will see it.

    The renderer merges the aggregated variables.yml with the image's
    properties.yml (properties win, lists accumulate). Anything outside the
    renderer that needs the same view — e.g. deciding which SCAP datastreams to
    vendor into the build context — must use this helper instead of reading one
    of the two files, or the two disagree.

    Args:
        variables: Merged variables.yml content.
        properties: Image properties.yml content.
        section: Section name, e.g. ``"oscap"``.
    """
    base = variables.get(section) or {}
    overlay = properties.get(section) or {}
    if not isinstance(base, dict) or not isinstance(overlay, dict):
        raise ConfigError(
            f"'{section}' must be a mapping in variables.yml and properties.yml"
        )
    return deep_merge(base, overlay, LIST_POLICY_EXTEND)


def as_list(value: Any) -> list[Any]:
    """Normalise a config value that may be a scalar, a list or missing."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def as_bool(value: Any, default: bool = False) -> bool:
    """Normalise the many ways a YAML/env boolean can be spelled."""
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in ("true", "yes", "1", "on"):
        return True
    if text in ("false", "no", "0", "off", ""):
        return False
    return default


# Built-in distro repos take precedence over a generic `default` entry: a UBI
# build must not query/install from Hummingbird just because its key was omitted.
DISTRO_RELEASEVERS = {"ubi9": "9", "ubi10": "10"}
DEFAULT_DISTRO_REPOS = {
    "hummingbird": ["hummingbird.repo"],
    "ubi9": ["ubi9.repo"],
    "ubi10": ["ubi10.repo"],
}


def resolve_repos(variables: dict, properties: dict, distro: str) -> list[str]:
    """The same selected repo files feed lock inputs, queries and installation."""
    configured = effective_section(variables, properties, "default_variant_repos")
    selected = configured.get(distro, DEFAULT_DISTRO_REPOS.get(distro, configured.get("default", [])))
    additional = properties.get("additional_repos", variables.get("additional_repos", []))
    repos = as_list(selected) + as_list(additional)
    if not repos:
        raise ConfigError(f"no repository files configured for distro '{distro}'")
    for repo in repos:
        if not isinstance(repo, str) or Path(repo).name != repo or not repo.endswith(".repo"):
            raise ConfigError(f"invalid repository filename {repo!r}: use a .repo file in yum-repos/")
    return list(dict.fromkeys(repos))
