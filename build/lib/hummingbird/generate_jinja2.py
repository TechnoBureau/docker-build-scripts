#!/usr/bin/env python3
"""Unified Jinja2 renderer for container image files.

This script provides a generic renderer that can generate any file from a Jinja2
template using container image context (properties, RPM versions, gitmodules, etc.).

Usage:
    ci/internal/generate_jinja2.py <template-file> <output-file>
"""

import argparse
from collections import OrderedDict
import configparser
from fnmatch import fnmatch
import json
from pathlib import Path
import re
import subprocess

import jinja2
import yaml


def get_submodule_hashes() -> dict[str, str]:
    """Get git hashes for all submodules.

    Returns:
        Dictionary mapping submodule paths to their git hashes.
    """
    # Maximum number of splits when parsing git submodule output
    max_splits = 2
    # Minimum number of parts required (hash and path)
    min_parts = 2

    result = subprocess.run(
        ["git", "submodule"],
        capture_output=True,
        text=True,
        check=True,
    )

    hashes = {}
    for line in result.stdout.strip().split("\n"):
        if line.strip():
            # Parse format: " <hash> <path> (<branch_info>)"
            parts = line.strip().split(" ", max_splits)
            if len(parts) >= min_parts:
                hash_value = parts[0]
                # Only keep alphanumeric characters in hash
                hash_value = re.sub(r"[^a-zA-Z0-9]", "", hash_value)
                path = parts[1]
                hashes[path] = hash_value

    return hashes


def parse_gitmodules(gitmodules_path: str | Path) -> dict[str, dict[str, str]]:
    """Parse .gitmodules file and extract submodule information.

    Args:
        gitmodules_path: Path to .gitmodules file

    Returns:
        Dictionary mapping submodule names to their properties (url, label, hash)
    """
    gitmodules_path = Path(gitmodules_path)
    if not gitmodules_path.exists():
        return {}

    config = configparser.ConfigParser()
    config.read(gitmodules_path)

    submodule_hashes = get_submodule_hashes()

    submodules = {}
    for section in config.sections():
        if section.startswith("submodule "):
            # Extract submodule name from section header
            name = section.removeprefix("submodule ").strip('"')

            submodule_data = {}

            # Get URL
            if config.has_option(section, "url"):
                submodule_data["url"] = config.get(section, "url")

            # Get branch as label (for version extraction)
            if config.has_option(section, "branch"):
                submodule_data["label"] = config.get(section, "branch")

            # Get path and corresponding hash
            if config.has_option(section, "path"):
                path = config.get(section, "path")
                submodule_data["path"] = path
                if path in submodule_hashes:
                    submodule_data["hash"] = submodule_hashes[path]

            submodules[name] = submodule_data

    return submodules


class ImageContext:
    """Context for template-based file generation.

    This class encapsulates all the state needed for generating VERSION, TAGS,
    and Containerfile outputs for a container image variant.
    """

    def __init__(self, output_file: Path) -> None:
        """Initialize image context from output file path.

        Args:
            output_file: Path to the output file being generated
        """
        # Parse paths from output file
        # Path structure: images/<group>/<distro>/<variant>/<output_file>
        self.output_file = output_file.resolve()
        self.variant = self.output_file.parent.name
        self.distro = self.output_file.parent.parent.name
        self.image_name = self.output_file.parent.parent.parent.name
        self.variant_dir = self.output_file.parent
        self.distro_dir = self.output_file.parent.parent
        self.image_dir = self.output_file.parent.parent.parent

        # Find base_dir by looking for .cache/properties.json
        current = self.output_file.parent
        while current != current.parent:  # Stop at filesystem root
            if (current / ".cache/properties.json").exists():
                self.base_dir = current
                break
            current = current.parent
        else:
            raise ValueError(f"Base directory not found for {self.output_file}")
        self.macros_dir = self.base_dir / "macros"

        # Load properties
        properties_cache_path = self.base_dir / ".cache/properties.json"
        self.properties = json.loads(properties_cache_path.read_text(encoding="utf-8"))
        self.image_properties = self.properties["images"][self.image_name]["properties"]

        # Build template variables
        self.variables = self._build_variables()

    @staticmethod
    def _deep_merge(base: dict, override: dict) -> dict:
        """Deep-merge override into base, returning a new dict.

        For dict values, recursively merge rather than replace.
        For list values, concatenate (base first, then override).
        For all other types, override wins.
        """
        result = dict(base)
        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = ImageContext._deep_merge(result[key], value)
            elif key in result and isinstance(result[key], list) and isinstance(value, list):
                result[key] = result[key] + value
            else:
                result[key] = value
        return result

    def _build_variables(self) -> dict:
        """Build template variables from properties cache."""
        # Build base variables with defaults, deep-merging dict values
        # so that per-image overrides (e.g. oscap.enabled) don't discard
        # global siblings (e.g. oscap.exclude_rules)
        variables = {
            "variant": self.variant,
            "distro": self.distro,
            "image_name": self.image_name,
            "build_from_source": False,  # Default value
        }
        variables = self._deep_merge(variables, self.properties["variables"])
        variables = self._deep_merge(variables, self.image_properties)

        # Package name for version/tag lookup (e.g. ruby4.0 for ruby-4-0 on Hummingbird)
        # Lookup order: distro/variant, variant, distro, then main_package
        version_pkg_map = self.image_properties.get("version_package") or {}
        distro_variant_key = f"{self.distro}/{self.variant}"
        fallback = self.image_properties.get("main_package", "")
        variables["package_name_for_version"] = (
            version_pkg_map.get(distro_variant_key)
            or version_pkg_map.get(self.variant)
            or version_pkg_map.get(self.distro)
            or fallback
        )

        # Add gitmodules
        gitmodules_path = self.base_dir / ".gitmodules"
        if gitmodules_path.exists():
            variables["gitmodules"] = parse_gitmodules(gitmodules_path)

        # Add RPM versions
        lockfile_path = self.variant_dir / "rpms/rpms.lock.yaml"
        if lockfile_path.exists():
            variables["rpm_versions"] = self._extract_rpm_versions(lockfile_path)
        else:
            rpm_versions_cache = self.base_dir / ".cache/rpm-versions.yml"
            if rpm_versions_cache.exists():
                rpm_versions_data = (
                    yaml.safe_load(rpm_versions_cache.read_text(encoding="utf-8")) or {}
                )
                variables["rpm_versions"] = {
                    name: str(version) for name, version in rpm_versions_data.items()
                }

        # Add tags
        tags = self.image_properties["tags"]
        template_content = yaml.dump(tags, default_flow_style=False, sort_keys=False)
        rendered_tags = yaml.safe_load(
            self.render_jinja2(
                template_content,
                variables,
                self.macros_dir,
            ),
        )
        tag_values = [
            (t["value"] + ("-" + self.variant if self.variant != "default" else ""))
            .lower()
            .replace("~", "-")
            for t in rendered_tags
        ]
        for suffix in self.image_properties.get("tag_suffix_aliases", {}).get(
            self.variant,
            [],
        ):
            tag_values.extend(
                (f"{tag['value']}-{suffix}").lower().replace("~", "-") for tag in rendered_tags
            )
        variables.update(
            {
                "tags": rendered_tags,
                "tag_values": tag_values,
            },
        )

        self._set_canonical_name(variables)

        variables["inject_labels"] = self._build_inject_labels(rendered_tags)

        # Build arch-specific packages map from rpm_packages entries
        variables["arch_specific_packages"] = self._collect_arch_packages(variables)

        # Add 'container_user'; can be per-variant dict or simple value (string/int)
        user_config = self.image_properties.get("user", "default")
        if isinstance(user_config, dict):
            user_value = user_config.get(self.variant, "default")
        else:
            user_value = str(user_config)
        variables["container_user"] = user_value

        self._compute_oscap_config(variables)

        return variables

    @staticmethod
    def _variant_matches(variant: str, patterns: list[str]) -> bool:
        """Check if a variant name matches any of the given glob patterns."""
        return any(fnmatch(variant, p) for p in patterns)

    def _compute_oscap_config(self, variables: dict) -> None:
        """Compute per-variant oscap configuration from merged oscap settings.

        Resolves active profiles and per-profile exclude rules for the current
        variant, adding computed keys to variables["oscap"]:
          - active_profiles: list of profile names active for this variant
          - profile_exclude_rules: dict mapping profile name -> filtered rules
          - has_tailoring: bool, whether a tailoring file is needed
        """
        oscap = variables.get("oscap", {})
        if not oscap.get("enabled", False):
            return

        variant = variables["variant"]

        # Determine active profiles from profiles config (defaults in variables.yml)
        profiles_config = oscap.get("profiles", {})
        active_profiles = []
        for profile_name in ["cis", "stig"]:
            setting = profiles_config.get(profile_name, False)
            if setting is True:
                active_profiles.append(profile_name)
            elif isinstance(setting, dict):
                variant_patterns = setting.get("variants", [])
                if self._variant_matches(variant, variant_patterns):
                    active_profiles.append(profile_name)

        # Filter exclude_rules per profile (variants field supports globs)
        all_rules = oscap.get("exclude_rules", [])
        profile_exclude_rules = {}
        for profile_name in active_profiles:
            profile_exclude_rules[profile_name] = [
                r
                for r in all_rules
                if ("variants" not in r or self._variant_matches(variant, r["variants"]))
                and ("profiles" not in r or profile_name in r["profiles"])
            ]

        oscap["active_profiles"] = active_profiles
        oscap["profile_exclude_rules"] = profile_exclude_rules
        oscap["has_tailoring"] = any(profile_exclude_rules.values())

    def _set_canonical_name(self, variables: dict) -> None:
        """Set canonical_name, registries and cpe in variables.

        The first registry in the per-image registries list (or the global
        default registry) becomes the canonical name, e.g.
        ghcr.io/technobureau/curl-builder. All registries are stored so the
        build can tag and push the image to every registry.
        """
        registries = self.image_properties.get("registries") or []
        if not registries:
            default_registry = self.properties["variables"].get("registry", "ghcr.io/technobureau")
            registries = [default_registry]
        variables["registries"] = registries
        canonical_name = self.image_name
        if self.variant != "default":
            canonical_name = f"{canonical_name}-{self.variant}"
        variables["canonical_name"] = f"{registries[0]}/{canonical_name}"
        variables["cpe"] = ""

    _SUPPORTED_ARCHES = ("aarch64", "x86_64")

    def _collect_arch_packages(self, variables: dict) -> dict[str, list[str]]:
        """Collect arch-specific packages from rpm_packages entries.

        Scans all matching rpm_packages keys for object entries with arch
        constraints (arches.only or arches.not) and groups them by architecture.

        Returns:
            Dictionary mapping arch names to lists of package names.
        """
        rpm_packages = variables.get("rpm_packages", {})
        distro = self.distro
        variant = self.variant
        distro_variant = f"{distro}/{variant}"
        matching_keys = {"all", "build-deps", distro, variant, distro_variant}

        arch_packages: dict[str, list[str]] = {}
        for key, pkg_list in rpm_packages.items():
            if key not in matching_keys:
                continue
            for entry in pkg_list:
                if not isinstance(entry, dict) or "name" not in entry:
                    continue
                arches_spec = entry.get("arches", {})
                if "only" in arches_spec:
                    only = arches_spec["only"]
                    if isinstance(only, str):
                        only = [only]
                    target_arches = [a for a in only if a in self._SUPPORTED_ARCHES]
                elif "not" in arches_spec:
                    excluded = arches_spec["not"]
                    if isinstance(excluded, str):
                        excluded = [excluded]
                    target_arches = [a for a in self._SUPPORTED_ARCHES if a not in excluded]
                else:
                    continue
                for arch in target_arches:
                    arch_packages.setdefault(arch, []).append(entry["name"])

        return arch_packages

    _MODIFIER_SUFFIXES = frozenset({"builder", "fips"})

    @staticmethod
    def _decompose_variant(variant: str) -> tuple[str, bool, bool]:
        """Parse variant name into (base, is_builder, is_fips).

        Strips known modifier suffixes from the right in any order, so
        "fpm-fips-builder" and "fpm-builder-fips" both yield base="fpm".
        A bare modifier (e.g., "builder") yields base="default".
        """
        rest = variant
        found: set[str] = set()
        while True:
            head, sep, tail = rest.rpartition("-")
            if sep and tail in ImageContext._MODIFIER_SUFFIXES:
                found.add(tail)
                rest = head
            elif rest in ImageContext._MODIFIER_SUFFIXES:
                found.add(rest)
                rest = ""
                break
            else:
                break
        base = rest or "default"
        return base, "builder" in found, "fips" in found

    def _build_variant_labels(self) -> dict[str, str]:
        """Build structured variant labels for inject_labels."""
        base, is_builder, is_fips = self._decompose_variant(self.variant)

        base_descs = {
            **self.properties["variables"].get("variant_descriptions", {}),
            **self.image_properties.get("variant_descriptions", {}),
        }
        if base not in base_descs:
            msg = (
                f"Missing variant_descriptions['{base}'] for variant "
                f"'{self.variant}' -- add it to {self.image_dir}/properties.yml "
                f"or images/variables.yml"
            )
            raise ValueError(msg)

        labels: dict[str, str] = {
            "io.hummingbird-project.variant": self.variant,
            "io.hummingbird-project.variant.base": base,
            "io.hummingbird-project.variant.description": base_descs[base],
        }
        if is_builder:
            labels["io.hummingbird-project.variant.builder"] = "true"
        if is_fips:
            labels["io.hummingbird-project.variant.fips"] = "true"
        return labels

    def _build_inject_labels(
        self,
        rendered_tags: list[dict],
    ) -> OrderedDict:
        """Build the inject_labels dict for Containerfile label injection."""
        version_labels = {}
        for tag in rendered_tags:
            if "label" in tag:
                version_labels[tag["label"]] = tag["value"].replace("~", "-").lower()

        version_value = version_labels.get(
            "org.opencontainers.image.version",
            "latest",
        )
        major_version_value = version_labels.get(
            "io.hummingbird-project.major-version",
            "",
        )
        major_minor_version_value = version_labels.get(
            "io.hummingbird-project.major-minor-version",
            "",
        )
        props = self.image_properties
        label_defaults = self.properties["variables"].get("labels", {})

        labels = OrderedDict()
        labels["description"] = props["description"]
        labels["distribution-scope"] = "public"
        labels["io.k8s.description"] = props["description"]
        labels["maintainer"] = label_defaults.get("maintainer", "Technobureau")
        labels["summary"] = props["summary"]
        labels["url"] = props["url"]
        labels["vendor"] = label_defaults.get("vendor", "Technobureau")
        labels["version"] = version_value
        labels["org.opencontainers.image.description"] = props["description"]
        labels["org.opencontainers.image.source"] = label_defaults.get(
            "source_url",
            "",
        )
        labels["org.opencontainers.image.title"] = props.get(
            "repository",
            self.image_name,
        )
        labels["org.opencontainers.image.url"] = props["url"]
        labels["org.opencontainers.image.vendor"] = label_defaults.get(
            "vendor",
            "Technobureau",
        )
        labels["org.opencontainers.image.version"] = version_value
        labels["io.hummingbird-project.containerfile"] = str(
            (self.variant_dir / "Containerfile").relative_to(self.base_dir),
        )
        labels["io.hummingbird-project.major-minor-version"] = major_minor_version_value
        labels["io.hummingbird-project.major-version"] = major_version_value
        labels["io.hummingbird-project.repository"] = props.get(
            "repository",
            self.image_name,
        )
        labels["io.hummingbird-project.stream"] = props["stream"]
        support_level = props.get("support_level", "")
        if support_level:
            labels["io.hummingbird-project.support-level"] = support_level
        labels.update(self._build_variant_labels())
        return labels

    @staticmethod
    def _extract_rpm_versions(lockfile_path: Path) -> dict[str, str]:
        """Extract package versions from RPM lockfile.

        Args:
            lockfile_path: Path to rpms.lock.yaml file

        Returns:
            Dictionary mapping package names to versions (EVR format)
        """
        if not lockfile_path.exists():
            return {}

        lockfile_data = yaml.safe_load(lockfile_path.read_text(encoding="utf-8"))

        # Extract packages from multi-arch format (arches[].packages)
        # Merge packages across all arches (arch-specific packages may differ)
        arches = lockfile_data.get("arches", [])
        if not arches:
            return {}

        packages = [pkg for arch in arches for pkg in arch.get("packages", [])]

        versions = {}
        for package in packages:
            name = package.get("name")
            evr = package.get("evr")  # epoch-version-release
            if name and evr:
                # Strip epoch prefix (e.g., "3:" from "3:10.11.14-1.fc44")
                if ":" in evr:
                    evr = evr.split(":", 1)[1]
                versions[name] = evr

        return versions

    @staticmethod
    def render_jinja2(template: str, variables: dict, macros_dir: Path) -> str:
        """Render Jinja2 template with macros and strict undefined checking."""
        macros = "\n".join(
            m.read_text(encoding="utf-8") for m in sorted(macros_dir.glob("*.yml.j2"))
        )
        full_template = macros + "\n" + template
        return jinja2.Template(full_template, undefined=jinja2.StrictUndefined).render(**variables)

    def write_output_file(self, content: str) -> None:
        """Write content to output file and print success message.

        Args:
            content: Content to write
        """
        self.output_file.write_text(content.strip() + "\n", encoding="utf-8")
        if self.variant:
            print(f"Generated {self.output_file} for {self.image_name}/{self.variant}")
        else:
            print(f"Generated {self.output_file} for {self.image_name}")


def main() -> None:
    """Main function."""
    parser = argparse.ArgumentParser(
        description="Render Jinja2 template for container image",
    )
    parser.add_argument(
        "template_file",
        type=Path,
        help="Path to Jinja2 template file",
    )
    parser.add_argument(
        "output_file",
        type=Path,
        help="Path to output file",
    )
    args = parser.parse_args()

    template_content = args.template_file.read_text(encoding="utf-8")
    context = ImageContext(args.output_file)
    rendered = context.render_jinja2(
        template_content,
        context.variables,
        context.macros_dir,
    )
    context.write_output_file(rendered)


if __name__ == "__main__":
    main()
