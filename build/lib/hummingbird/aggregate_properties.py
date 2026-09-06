#!/usr/bin/python3
"""Aggregate properties.yml files into .cache/properties.json.

Scans images/ directories, merges with images/variables.yml, and
generates
- .cache/properties.json to provide information about all images and their variants
  for use by generation scripts
- .cache/properties.mk to trigger Make to restart when properties updated

The structure of .cache/properties.json:
{
    "variables": { ... },  # from images/variables.yml
    "images": {
        "caddy": {
            "image_directory": "images/caddy",
            "image_group": "caddy",
            "properties": {
                "variants": [ ... ],  # merged from properties.yml and images/variables.yml
                "distro_variants": [ ... ],  # list of distro/variant paths that exist
                ...  # from properties.yml
            }
        }
    }
}

The aggregated JSON properties file removes the need to read a large number of
YAML files to get the information about all images and their variants, and
allows to infer expected variants even if they have never been built before.
"""

import fnmatch
import json
from pathlib import Path
import sys

import yaml

from hb_config import ConfigError, as_list, load_yaml, require_keys

#: Keys variables.yml must define for the variant/distro matrix to resolve.
REQUIRED_VARIABLES = ("default_distros", "default_variants")


def _parse_additional_variants(additional_variants: list) -> tuple[list, dict]:
    """Parse additional_variants which can be strings or objects.

    Supports two formats:
      - Simple string: "fips"
      - Object with distros: {"name": "fips", "distros": ["hummingbird"]}

    Returns:
        Tuple of (variant_names, variant_distros_map)
    """
    variant_names = []
    variant_distros = {}

    for item in additional_variants:
        if isinstance(item, str):
            variant_names.append(item)
        elif isinstance(item, dict):
            name = item["name"]
            variant_names.append(name)
            if "distros" in item:
                variant_distros[name] = item["distros"]

    return variant_names, variant_distros


def _compute_variants(image_props: dict, default_variants: list) -> tuple[list, dict]:
    """Compute final variants from image properties and defaults.

    Returns:
        Tuple of (variants, variant_distros_map)
    """
    base = image_props.get("variants", default_variants)
    additional = image_props.get("additional_variants", [])
    additional_names, variant_distros = _parse_additional_variants(additional)
    return base + additional_names, variant_distros


def _compute_distros(image_props: dict, default_distros: list) -> list:
    """Compute final distros from image properties and defaults."""
    return image_props.get("distros", default_distros)


def _compute_distro_variants(
    distros: list,
    variants: list,
    variant_distros: dict,
) -> list:
    """Compute list of distro/variant combinations.

    Returns the cartesian product of distros x variants, filtered by
    variant_distros restrictions. Does not check directory existence
    since directories are created on-demand by generation scripts.

    Args:
        distros: List of distros to build for
        variants: List of variants to build
        variant_distros: Optional dict mapping variant names to allowed distros.
                        If a variant is in this dict, it will only be built for
                        the specified distros. Supports glob patterns.
    """
    result = []
    for distro in distros:
        for variant in variants:
            # Check if this variant has distro restrictions
            if variant in variant_distros:
                allowed_distros = variant_distros[variant]
                # Check if current distro matches any allowed pattern
                if not any(fnmatch.fnmatch(distro, pattern) for pattern in allowed_distros):
                    continue
            result.append(f"{distro}/{variant}")
    return result


def _load_image_properties(
    properties_file: Path,
    base_dir: Path,
    default_distros: list,
    default_variants: list,
) -> dict:
    """Load and process image properties from a properties.yml file."""
    image_props = load_yaml(properties_file, f"properties.yml of '{properties_file.parent.name}'")
    distros = as_list(_compute_distros(image_props, default_distros))
    variants, variant_distros = _compute_variants(image_props, default_variants)
    variants = as_list(variants)
    distro_variants = _compute_distro_variants(distros, variants, variant_distros)
    # Remove additional_variants from output (consumed into variants)
    image_props.pop("additional_variants", None)
    # WHY: the computed "variants" above must win: image_props still holds the
    # raw properties.yml "variants" key, which would overwrite the computed
    # list (base + additional_variants) in the merge below and silently drop
    # additional variants like "fips".
    image_props.pop("variants", None)
    return {
        "image_directory": str(properties_file.parent.relative_to(base_dir)),
        "image_group": properties_file.parent.name,
        "properties": {
            "variants": variants,
            "distros": distros,
            "distro_variants": distro_variants,
            # WHY exported: the build driver must apply the same per-variant
            # distro restrictions (additional_variants: [{name, distros}]) that
            # produced distro_variants above. Without it the driver builds the
            # full distro x variant product and attempts combinations this file
            # explicitly forbids, e.g. ubi9/fips.
            "variant_distros": variant_distros,
            "repository": properties_file.parent.name,
        }
        | image_props,
    }


def main() -> None:
    """Aggregate properties files."""
    base_dir = Path.cwd()

    # Read variables.yml
    variables_file = base_dir / "images/variables.yml"
    variables = load_yaml(variables_file, "images/variables.yml")
    require_keys(variables, REQUIRED_VARIABLES, str(variables_file))
    default_distros = as_list(variables["default_distros"])
    default_variants = as_list(variables["default_variants"])

    properties_files = sorted(
        (base_dir / "images").glob("*/properties.yml"),
        key=lambda path: str(path.relative_to(base_dir)),
    )
    if not properties_files:
        raise ConfigError(
            f"No images/*/properties.yml found under {base_dir}. "
            f"Run this generator from the work-tree root (the directory that "
            f"holds images/ and .cache/)."
        )

    # Aggregate properties files
    output = {
        "variables": variables,
        "images": {
            properties_file.parent.name: _load_image_properties(
                properties_file,
                base_dir,
                default_distros,
                default_variants,
            )
            for properties_file in properties_files
        },
    }

    # Create .cache directory
    cache_dir = base_dir / ".cache"
    cache_dir.mkdir(exist_ok=True)

    # Write .cache/properties.json
    properties_json = cache_dir / "properties.json"
    properties_json.write_text(json.dumps(output, indent=2, sort_keys=True), encoding="utf-8")

    # Record the exact input set so Make detects added and removed images. Wildcard
    # prerequisites alone cannot detect files which no longer exist.
    properties_mk = cache_dir / "properties.mk"
    relative_properties_files = [str(path.relative_to(base_dir)) for path in properties_files]
    properties_mk.write_text(
        f"CACHED_PROPERTIES_FILES := {' '.join(relative_properties_files)}\n",
        encoding="utf-8",
    )

    print(
        f"Aggregated {len(properties_files)} image(s) into {properties_json} "
        f"(distros: {', '.join(default_distros)}; variants: {', '.join(default_variants)})"
    )


def run() -> int:
    """Entry point that turns configuration problems into a clean message."""
    try:
        main()
    except ConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
