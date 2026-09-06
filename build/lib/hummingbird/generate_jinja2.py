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
import sys

import jinja2
import yaml

from hb_packages import resolve_package_set
from hb_config import (
    LIST_POLICY_EXTEND,
    ConfigError,
    as_bool,
    deep_merge,
    load_yaml,
    require_keys,
)
from hb_variant import (
    decompose_variant,
    image_repository,
    is_builder_variant,
    resolve_image_name,
)

#: Registry used for the canonical_name label when neither properties.yml nor
#: variables.yml declares one.
DEFAULT_REGISTRY = "ghcr.io/technobureau"

#: Keys every properties.yml must provide for the labels and tags to render.
#: Validated up front so a typo reports the image and the missing keys instead
#: of a bare KeyError from deep inside label construction.
REQUIRED_PROPERTIES = ("description", "summary", "url", "stream", "tags")

#: Compliance profiles that can be switched on through oscap.profiles.
OSCAP_PROFILES = ("cis", "stig")


def get_submodule_hashes(search_dir: Path) -> dict[str, str]:
    """Get git hashes for all submodules of the repository at search_dir.

    Returns:
        Dictionary mapping submodule paths to their git hashes. Empty when git
        is unavailable or the directory is not inside a git work tree — a
        source build then renders "unknown" instead of aborting generation.
    """
    # Maximum number of splits when parsing git submodule output
    max_splits = 2
    # Minimum number of parts required (hash and path)
    min_parts = 2

    try:
        result = subprocess.run(
            # WHY "status": bare `git submodule` prints usage and exits 128,
            # which aborted rendering for every source-built image.
            ["git", "submodule", "status"],
            cwd=search_dir,
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return {}

    if result.returncode != 0:
        return {}

    hashes = {}
    for line in result.stdout.strip().split("\n"):
        if line.strip():
            # Parse format: " <hash> <path> (<branch_info>)"; a leading "-"
            # marks an uninitialised submodule, "+" a checked-out commit that
            # differs from the recorded one. Both are stripped with the rest.
            parts = line.strip().split(" ", max_splits)
            if len(parts) >= min_parts:
                hash_value = parts[0]
                # Only keep alphanumeric characters in hash
                hash_value = re.sub(r"[^a-zA-Z0-9]", "", hash_value)
                path = parts[1]
                if hash_value:
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

    submodule_hashes = get_submodule_hashes(gitmodules_path.parent)

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
            raise ValueError(
                f"No .cache/properties.json above {self.output_file}. "
                f"Run aggregate_properties.py from the work-tree root first."
            )
        self.macros_dir = self.base_dir / "macros"

        # Load properties
        properties_cache_path = self.base_dir / ".cache/properties.json"
        self.properties = json.loads(properties_cache_path.read_text(encoding="utf-8"))
        image_entry = self.properties["images"].get(self.image_name)
        if image_entry is None:
            raise ValueError(
                f"Image '{self.image_name}' (from path {self.output_file}) is not in "
                f"{properties_cache_path}. Known images: "
                f"{', '.join(sorted(self.properties['images'])) or '<none>'}"
            )
        self.image_properties = image_entry["properties"]
        require_keys(
            self.image_properties,
            REQUIRED_PROPERTIES,
            f"properties.yml of image '{self.image_name}'",
        )

        # Build template variables
        self.variables = self._build_variables()

    @staticmethod
    def _deep_merge(base: dict, override: dict) -> dict:
        """Deep-merge override into base (lists concatenate for templates)."""
        return deep_merge(base, override, LIST_POLICY_EXTEND)

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

        # Variant semantics come from hb_variant so the macros, the labels and
        # the image name the build driver publishes can never disagree.
        variant_info = decompose_variant(self.variant)
        variables["variant_base"] = variant_info.base
        variables["is_builder"] = is_builder_variant(self.image_name, self.variant)
        variables["is_fips"] = variant_info.is_fips
        variables["image_repo_name"] = resolve_image_name(self.image_name, self.variant)

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

        # Add gitmodules. Always defined (empty when there is no submodule
        # metadata) because package_version.yml.j2 subscripts it, and a
        # subscript on an undefined name aborts the render under StrictUndefined.
        variables["gitmodules"] = self._load_gitmodules()

        # Add RPM versions
        variables["rpm_versions"] = self._load_rpm_versions()

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

        self._set_package_sets(variables)

        # Add 'container_user'; can be per-variant dict or simple value (string/int)
        user_config = self.image_properties.get("user", "default")
        if isinstance(user_config, dict):
            user_value = user_config.get(self.variant, "default")
        else:
            user_value = str(user_config)
        variables["container_user"] = user_value
        if user_value == "default" and not variables.get("default_user"):
            raise ConfigError(
                f"Image '{self.image_name}' variant '{self.variant}' runs as the "
                f"default user but variables.yml does not define 'default_user'. "
                f"Set default_user (uid or name) or user: <value> in properties.yml."
            )

        self._compute_oscap_config(variables)

        return variables

    def _load_gitmodules(self) -> dict[str, dict[str, str]]:
        """Load submodule metadata from the image dir, then the work-tree root.

        The build driver copies a builder's .gitmodules next to its
        properties.yml (images/<name>/.gitmodules); upstream layouts keep it at
        the repository root. Both are honoured so source builds resolve
        submodule versions in either tree.
        """
        for candidate in (self.image_dir / ".gitmodules", self.base_dir / ".gitmodules"):
            if candidate.exists():
                return parse_gitmodules(candidate)
        return {}

    def _load_rpm_versions(self) -> dict[str, str]:
        """Resolve package versions for this distro/variant.

        Precedence:
          1. ``rpms/rpms.lock.yaml`` of the variant (hermetic lockfile).
          2. ``.cache/rpm-versions.yml`` written by get_rpm_versions.sh.

        The cache is distro-aware: get_rpm_versions.sh queries each distro
        against its own repositories and records the results per distro, so a
        ubi9 build must not pick up the hummingbird version of the same
        package name. The flat (single-distro) layout is still accepted.
        """
        lockfile_path = self.variant_dir / "rpms/rpms.lock.yaml"
        if lockfile_path.exists():
            return self._extract_rpm_versions(lockfile_path)

        cache_path = self.base_dir / ".cache/rpm-versions.yml"
        if not cache_path.exists():
            return {}

        data = load_yaml(cache_path, ".cache/rpm-versions.yml")
        per_distro = data.get("distros")
        if isinstance(per_distro, dict):
            versions = per_distro.get(self.distro) or {}
            if not versions:
                raise ConfigError(
                    f".cache/rpm-versions.yml has no entry for distro "
                    f"'{self.distro}' (known: {', '.join(sorted(per_distro))}). "
                    f"Re-run get_rpm_versions.sh for this distro."
                )
        else:
            # Flat layout: {package: evr}. Kept for caches produced before the
            # per-distro format existed.
            versions = data

        return {str(name): str(version) for name, version in versions.items()}

    @staticmethod
    def _variant_matches(variant: str, patterns: list[str]) -> bool:
        """Check if a variant name matches any of the given glob patterns."""
        return any(fnmatch(variant, p) for p in patterns)

    def _compute_oscap_config(self, variables: dict) -> None:
        """Normalise and resolve the oscap settings for this variant.

        ``variables["oscap"]`` is ALWAYS defined after this call, with the
        computed keys present:

          - enabled: bool, whether compliance verification runs at all
          - active_profiles: profile names active for this variant
          - profile_exclude_rules: profile name -> filtered exclude rules
          - has_tailoring: bool, whether a tailoring file must be generated

        WHY always defined: the macros and oscap-tailoring.xml.j2 read
        ``oscap.*`` directly, and Jinja's StrictUndefined turns a missing key
        into "oscap is undefined" — which aborted generation for every image
        whose variables.yml simply did not configure oscap.

        Profile activation supports two spellings: a boolean (``stig: true``)
        and a variant-scoped mapping (``stig: {variants: ["*builder*"]}``).
        """
        configured = variables.get("oscap") or {}
        if not isinstance(configured, dict):
            raise ConfigError(
                f"oscap must be a mapping in variables.yml/properties.yml, "
                f"got {type(configured).__name__}"
            )

        oscap = dict(configured)
        oscap.setdefault("profiles", {})
        oscap.setdefault("exclude_rules", [])
        oscap.setdefault("datastreams", {})
        oscap.setdefault("crypto_policy", "")
        oscap.setdefault("crypto_policy_variants", {})
        oscap["enabled"] = as_bool(oscap.get("enabled"), default=False)
        oscap["active_profiles"] = []
        oscap["profile_exclude_rules"] = {}
        oscap["has_tailoring"] = False
        variables["oscap"] = oscap

        if not oscap["enabled"]:
            return

        variant = variables["variant"]
        profiles_config = oscap["profiles"] or {}

        active_profiles = []
        for profile_name in OSCAP_PROFILES:
            setting = profiles_config.get(profile_name, False)
            if isinstance(setting, dict):
                if self._variant_matches(variant, setting.get("variants", [])):
                    active_profiles.append(profile_name)
            elif as_bool(setting):
                active_profiles.append(profile_name)

        # Filter exclude_rules per profile (variants field supports globs)
        all_rules = oscap["exclude_rules"] or []
        profile_exclude_rules = {}
        for profile_name in active_profiles:
            profile_exclude_rules[profile_name] = [
                rule
                for rule in all_rules
                if ("variants" not in rule or self._variant_matches(variant, rule["variants"]))
                and ("profiles" not in rule or profile_name in rule["profiles"])
            ]

        oscap["active_profiles"] = active_profiles
        oscap["profile_exclude_rules"] = profile_exclude_rules
        oscap["has_tailoring"] = any(profile_exclude_rules.values())

    def _set_canonical_name(self, variables: dict) -> None:
        """Set canonical_name, registries and cpe in variables.

        The first registry becomes the canonical name, e.g.
        ghcr.io/technobureau/curl-builder. All registries are stored so the
        build can tag and push the image to every registry.

        WHY hb_variant.resolve_image_name: the ``name`` label is what scanners
        use to resolve the published image, so it must be built with the same
        rule the build driver uses for CONFIG[IMAGE_NAME]. Appending every
        non-default variant (the previous behaviour) advertised references that
        were never pushed — e.g. ".../curl-fips" while the image was published
        as ".../curl:<version>-fips".
        """
        registries = self.image_properties.get("registries") or []
        if not registries:
            default_registry = self.properties["variables"].get("registry", DEFAULT_REGISTRY)
            registries = [default_registry]
        variables["registries"] = registries
        variables["canonical_name"] = image_repository(
            registries[0], self.image_name, self.variant
        )
        variables["cpe"] = ""

    def _set_package_sets(self, variables: dict) -> None:
        """Expose the resolved package sets to the templates.

        Delegates to hb_packages.resolve_package_set so ARG MAIN_PACKAGES and
        rpms.in.yaml can never disagree about what this variant installs.
        """
        shared = dict(self.properties["variables"])
        # An image may extend the shared default packages in its properties.yml.
        if isinstance(self.image_properties.get("default_rpm_packages"), dict):
            shared["default_rpm_packages"] = deep_merge(
                shared.get("default_rpm_packages") or {},
                self.image_properties["default_rpm_packages"],
                LIST_POLICY_EXTEND,
            )

        package_set = resolve_package_set(
            self.image_properties, shared, self.distro, self.variant
        )
        variables["main_packages"] = package_set.main
        variables["build_packages"] = package_set.build
        variables["arch_specific_packages"] = package_set.arch_packages

    def _build_variant_labels(self) -> dict[str, str]:
        """Build structured variant labels for inject_labels."""
        variant_info = decompose_variant(self.variant)
        base = variant_info.base

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
        if variant_info.is_builder:
            labels["io.hummingbird-project.variant.builder"] = "true"
        if variant_info.is_fips:
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

    def write_output_file(self, content: str) -> bool:
        """Write content to the output file; skip empty renders.

        Args:
            content: Content to write

        Returns:
            True when the file was written, False when the render was empty
            and therefore skipped (e.g. oscap-tailoring.xml for an image with
            no exclude rules). Skipping keeps the work tree free of files that
            look generated but carry no information.
        """
        body = content.strip()
        if not body:
            print(f"Skipped {self.output_file} (empty render)")
            return False

        self.output_file.write_text(body + "\n", encoding="utf-8")
        print(f"Generated {self.output_file} for {self.image_name}/{self.variant}")
        return True


def render_template(template_file: Path, output_file: Path) -> bool:
    """Render one template to one output file.

    Args:
        template_file: Jinja2 template to render.
        output_file: Destination; its path also selects the image, distro and
            variant (images/<image>/<distro>/<variant>/<file>).

    Returns:
        True when the output file was written.
    """
    template_content = Path(template_file).read_text(encoding="utf-8")
    context = ImageContext(Path(output_file))
    rendered = context.render_jinja2(
        template_content,
        context.variables,
        context.macros_dir,
    )
    return context.write_output_file(rendered)


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

    try:
        render_template(args.template_file, args.output_file)
    except (ConfigError, ValueError) as exc:
        # WHY: a configuration problem is an operator error, not a crash —
        # print the actionable message instead of a Python traceback.
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
