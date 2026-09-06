#!/usr/bin/python3
"""Generate rpms.in.yaml from .cache/properties.json.

Reads image properties and variables from properties cache, and generates
rpms.in.yaml for rpm-lockfile-prototype consumption.

Usage:
    ci/internal/generate_rpms_in.py <path-to-rpms.in.yaml>

Output format:
    arches: [aarch64, x86_64]
    contentOrigin:
      repofiles: [../../../yum-repos/repo.repo]
    context:
      bare: true
    installWeakDeps: false
    packages:
      - pkg1
      - pkg2
      - name: arch-specific-pkg
        arches:
          only: x86_64
"""

import argparse
import json
import os
from pathlib import Path

import yaml

from hb_packages import resolve_package_set


class IndentedListDumper(yaml.SafeDumper):
    """YAML dumper with 2-space indented list items."""

    def increase_indent(self, flow: bool = False, indentless: bool = False) -> None:  # noqa: ARG002, FBT001, FBT002
        """Increase indent for nested blocks, forcing list indentation."""
        return super().increase_indent(flow, False)  # noqa: FBT003


def main() -> None:
    """Generate rpms.in.yaml from properties cache."""
    parser = argparse.ArgumentParser(
        description="Generate rpms.in.yaml from cached properties",
    )
    parser.add_argument(
        "rpms_in_yaml",
        type=Path,
        help="Path to rpms.in.yaml output file",
    )
    args = parser.parse_args()

    # Parse arguments
    # Path structure: images/<group>/<distro>/<variant>/rpms/rpms.in.yaml
    base_dir = Path.cwd()
    rpms_in_path = args.rpms_in_yaml.resolve()
    variant_path = rpms_in_path.parent.parent  # images/caddy/rawhide/default
    distro_path = variant_path.parent  # images/caddy/rawhide
    image_path = distro_path.parent  # images/caddy
    variant = variant_path.name  # default
    distro = distro_path.name  # rawhide

    # Load properties cache
    properties_json = base_dir / ".cache/properties.json"
    cache = json.loads(properties_json.read_text(encoding="utf-8"))

    # Get variables and image data from cache
    variables = cache["variables"]
    image_name = image_path.name
    image_data = cache["images"][image_name]
    properties = image_data["properties"]

    # Determine repositories (keyed by distro)
    default_variant_repos = variables.get("default_variant_repos", {})
    distro_repos = default_variant_repos.get(
        distro,
        default_variant_repos.get("default", []),
    )
    additional_repos = properties.get("additional_repos", [])

    # Determine relative paths from rpms/ directory to yum-repos/
    # (os.path.relpath works with Python < 3.12, unlike Path.relative_to(walk_up=))
    repofiles = [
        os.path.relpath(base_dir / "yum-repos" / repo, rpms_in_path.parent)
        for repo in distro_repos + additional_repos
    ]

    # Packages come from hb_packages.resolve_package_set — the same rule the
    # rendered Containerfile uses for ARG MAIN_PACKAGES, so the versions
    # resolved here are exactly the versions installed there.
    # Entries may be plain strings (all arches) or dicts with "name" and
    # "arches" keys (arch-specific, passed through to rpms.in.yaml).
    package_set = resolve_package_set(properties, variables, distro, variant)

    # Combine: plain strings sorted first, then arch-specific objects by name
    packages: list[str | dict] = [
        *sorted({*package_set.main, *package_set.build}),
        *package_set.arch_entries,
    ]

    # Build complete data structure
    data = {
        "arches": ["aarch64", "x86_64"],
        "contentOrigin": {"repofiles": sorted(repofiles)},
        "context": {"bare": True},
        "installWeakDeps": False,
        "packages": packages,
        "zchunk": False,
    }

    rpms_in_path.parent.mkdir(parents=True, exist_ok=True)
    rpms_in_path.write_text(
        yaml.dump(data, Dumper=IndentedListDumper, explicit_start=True),
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
