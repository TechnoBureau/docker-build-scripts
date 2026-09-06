#!/usr/bin/env python3
"""hbgen — hummingbird work-tree generator.

The one Python entry point used by ``build/lib/ci-hummingbird.sh``. Everything
that reads or writes YAML/JSON lives here, so the bash driver stays a thin,
readable orchestrator and no parsing logic is duplicated between the two.

Pipeline (each stage is a subcommand and can be run by hand to debug):

    hbgen.py prepare   build the .hbgen work tree from a builder directory
    hbgen.py rpms      write rpms.in.yaml for every distro/variant
    (get_rpm_versions.sh — needs a container engine; called by the driver)
    hbgen.py render    write VERSION, TAGS, oscap-tailoring.xml, Containerfile
    hbgen.py matrix    list the distro/variant/image-name rows to build
    hbgen.py config    print the build configuration of one row (TAB separated)

Work-tree layout produced by ``prepare`` (a reconstruction of the upstream
hummingbird repository layout, so the vendored generators run unchanged)::

    .hbgen/
    ├── macros/  templates/  yum-repos/     symlinks to the vendored copies
    ├── ci/get_rpm_versions.sh              symlink to the vendored script
    ├── images/
    │   ├── variables.yml                   shared + per-image, deep-merged
    │   └── <image>/
    │       ├── properties.yml  Containerfile.j2  [.gitmodules]
    │       ├── yum-repos/*.repo            inside the build context (COPY)
    │       ├── oscap/*.xml                 only the datastreams in use
    │       ├── [rootfs/ src/ prebuildfs/]  extra build-context files
    │       └── <distro>/<variant>/
    │           ├── rpms/rpms.in.yaml
    │           ├── VERSION  TAGS  [oscap-tailoring.xml]
    │           └── Containerfile
    └── .cache/
        ├── properties.json                 from aggregate_properties.py
        └── rpm-versions.yml                from get_rpm_versions.sh

Environment:
    HUMMINGBIRD_DIR   Vendored machinery location (default: this file's dir).
"""

from __future__ import annotations

import argparse
from collections.abc import Iterable, Sequence
import fnmatch
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

from hb_config import (
    ConfigError,
    as_bool,
    as_list,
    effective_section,
    load_yaml,
    merge_variables,
)
from hb_variant import resolve_image_name

#: Vendored generators/macros/templates, overridable for testing.
HUMMINGBIRD_DIR = Path(os.environ.get("HUMMINGBIRD_DIR", Path(__file__).resolve().parent))

#: Name of the work tree created inside a builder directory.
WORK_TREE_NAME = ".hbgen"

#: Distro used when nothing is configured. Keeps single-distro builders working
#: with no variables.yml distro keys at all.
FALLBACK_DISTRO = "hummingbird"

#: Files copied from the builder directory into the build context when present.
EXTRA_CONTEXT_DIRS = ("rootfs", "src", "prebuildfs")

#: Templates rendered per distro/variant, and the file each one produces.
VARIANT_TEMPLATES: tuple[tuple[str, str], ...] = (
    ("templates/VERSION.j2", "VERSION"),
    ("templates/TAGS.j2", "TAGS"),
    ("templates/oscap-tailoring.xml.j2", "oscap-tailoring.xml"),
)

#: Recognised compliance profiles; mirrors OSCAP_PROFILES in generate_jinja2.py.
OSCAP_PROFILES = ("cis", "stig")

#: The builder image carries its own datastream baked in, so none is copied.
SELF_HOSTED_OSCAP_DISTRO = "hummingbird"


# --------------------------------------------------------------------------- #
# Work tree
# --------------------------------------------------------------------------- #
class WorkTree:
    """Paths and cached metadata of one ``.hbgen`` work tree."""

    def __init__(self, root: str | Path, image: str) -> None:
        self.root = Path(root).resolve()
        self.image = image
        self.images_dir = self.root / "images"
        self.image_dir = self.images_dir / image
        self.cache_dir = self.root / ".cache"

    # -- paths -------------------------------------------------------------
    def variant_dir(self, distro: str, variant: str) -> Path:
        """Directory holding the rendered files of one distro/variant."""
        return self.image_dir / distro / variant

    def containerfile(self, distro: str, variant: str) -> Path:
        return self.variant_dir(distro, variant) / "Containerfile"

    @property
    def merged_variables_file(self) -> Path:
        return self.images_dir / "variables.yml"

    @property
    def properties_cache_file(self) -> Path:
        return self.cache_dir / "properties.json"

    # -- cached data -------------------------------------------------------
    def properties_cache(self) -> dict:
        """Load .cache/properties.json (written by aggregate_properties.py)."""
        if not self.properties_cache_file.is_file():
            raise ConfigError(
                f"{self.properties_cache_file} not found — run "
                f"aggregate_properties.py from {self.root} first"
            )
        return json.loads(self.properties_cache_file.read_text(encoding="utf-8"))

    def image_properties(self) -> dict:
        cache = self.properties_cache()
        entry = cache["images"].get(self.image)
        if entry is None:
            raise ConfigError(
                f"image '{self.image}' is not in {self.properties_cache_file}; "
                f"known: {', '.join(sorted(cache['images'])) or '<none>'}"
            )
        return entry["properties"]

    def merged_variables(self) -> dict:
        """Load the merged images/variables.yml of the work tree."""
        return load_yaml(self.merged_variables_file, "merged images/variables.yml")


# --------------------------------------------------------------------------- #
# Matrix resolution — the single source of truth for "what gets built"
# --------------------------------------------------------------------------- #
def resolve_distros(
    variables: dict, properties: dict, requested: str | Sequence[str] | None
) -> list[str]:
    """Resolve the distro list to build.

    Precedence: explicit request (HB_DISTROS) > properties.yml ``distros`` >
    variables.yml ``default_distros`` > FALLBACK_DISTRO.
    """
    if requested:
        return [str(d).strip() for d in _split(requested) if str(d).strip()]

    configured = as_list(properties.get("distros")) or as_list(variables.get("default_distros"))
    return [str(d) for d in configured] or [FALLBACK_DISTRO]


def resolve_variants(properties: dict, requested: str | Sequence[str] | None) -> list[str]:
    """Resolve the variant list to build.

    The authoritative list is the one aggregated from properties.yml
    (``variants`` plus ``additional_variants``); an explicit request
    (HB_VARIANTS) selects a subset of it and is validated here.
    """
    known = [str(v) for v in as_list(properties.get("variants"))] or ["default"]
    if not requested:
        return known

    wanted = [str(v).strip() for v in _split(requested) if str(v).strip()]
    unknown = [variant for variant in wanted if variant not in known]
    if unknown:
        raise ConfigError(
            f"unknown variant(s) {', '.join(unknown)}; valid: {', '.join(known)}"
        )
    return wanted


def resolve_matrix(
    properties: dict,
    distros: Sequence[str],
    variants: Sequence[str],
) -> list[tuple[str, str]]:
    """Filter the distro x variant product by per-variant distro restrictions.

    ``additional_variants`` entries may pin a variant to specific distros::

        additional_variants:
          - name: fips
            distros: [hummingbird]

    Aggregating those restrictions into ``variant_distros`` is not enough on its
    own: building the raw cartesian product produced ubi9/fips anyway, which
    then resolved FIPS packages against the ubi9 repositories and failed (or
    worse, built an image nobody asked for).
    """
    restrictions: dict[str, list[str]] = {
        str(name): [str(pattern) for pattern in as_list(patterns)]
        for name, patterns in (properties.get("variant_distros") or {}).items()
    }

    matrix: list[tuple[str, str]] = []
    for distro in distros:
        for variant in variants:
            allowed = restrictions.get(variant)
            if allowed and not any(fnmatch.fnmatch(distro, p) for p in allowed):
                note(
                    f"skipping {distro}/{variant}: restricted to "
                    f"{', '.join(allowed)} by additional_variants"
                )
                continue
            matrix.append((distro, variant))

    if not matrix:
        raise ConfigError(
            f"no distro/variant combination left to build "
            f"(distros: {', '.join(distros)}; variants: {', '.join(variants)})"
        )
    return matrix


def _split(value: str | Sequence[str]) -> list[str]:
    """Normalise an env/CLI list given as a list, or a comma/space string."""
    if isinstance(value, str):
        return [part for part in value.replace(",", " ").split() if part]
    return [str(item) for item in value]


def _dedupe(items: Iterable[str]) -> list[str]:
    """Drop duplicates while preserving first-seen order.

    WHY order matters: the tag list becomes CONFIG[CUSTOM_TAGS], and the engine
    treats the first entry as the primary tag (build arg TAG=...). Sorting would
    change which tag is primary, so this keeps the rendered order and only
    removes repeats.
    """
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out


# --------------------------------------------------------------------------- #
# Stage: prepare
# --------------------------------------------------------------------------- #
def resolve_variables_files(builders_dir: Path | None, image_dir: Path) -> tuple[Path, Path | None]:
    """Locate the shared and per-image variables.yml.

    Returns:
        (base, overlay). base is the shared ``builders/variables.yml`` when it
        exists, otherwise the per-image file. overlay is the per-image file when
        it is not already the base.
    """
    shared = (builders_dir / "variables.yml") if builders_dir else None
    per_image = image_dir / "variables.yml"

    if shared and shared.is_file():
        return shared, per_image if per_image.is_file() else None
    if per_image.is_file():
        return per_image, None

    raise ConfigError(
        f"no variables.yml for '{image_dir.name}': create {per_image} "
        f"(per-image overrides) or {shared or '<builders>/variables.yml'} "
        f"(shared defaults)"
    )


def required_oscap_datastreams(
    variables: dict, properties: dict, distros: Sequence[str]
) -> dict[str, str]:
    """Map distro -> datastream filename for the distros actually being built.

    The oscap section is resolved with hb_config.effective_section so an image
    that enables oscap in its own properties.yml is treated exactly like one
    that enables it in the shared variables.yml — the same view the renderer
    uses when it emits the verify-compliance step.

    WHY selective: the vendored datastreams are ~25 MB each and land inside the
    build context, which the container engine reads once per distro/variant.
    Copying all of them for every image added ~49 MB of context to builds that
    never scan anything (the hummingbird datastream is baked into the builder
    image and is never read from the context).
    """
    oscap = effective_section(variables, properties, "oscap")
    if not as_bool(oscap.get("enabled")):
        return {}

    datastreams = oscap.get("datastreams") or {}
    return {
        distro: str(datastreams[distro])
        for distro in distros
        if distro in datastreams and distro != SELF_HOSTED_OSCAP_DISTRO
    }


def cmd_prepare(args: argparse.Namespace) -> int:
    """Create the work tree: merged variables, vendored machinery, context."""
    image_dir = Path(args.image_dir).resolve()
    require_builder_files(image_dir)

    image = args.image or image_dir.name
    builders_dir = Path(args.builders_dir).resolve() if args.builders_dir else None
    hbgen = Path(args.hbgen).resolve() if args.hbgen else image_dir / WORK_TREE_NAME

    base_vars, overlay_vars = resolve_variables_files(builders_dir, image_dir)
    variables = merge_variables(base_vars, overlay_vars)
    properties = load_yaml(image_dir / "properties.yml", f"properties.yml of '{image}'")

    distros = resolve_distros(variables, properties, args.distros)

    _recreate_tree(hbgen)

    # Merged variables.yml — the single configuration source for every stage.
    _dump_yaml(variables, hbgen / "images" / "variables.yml")

    target_image_dir = hbgen / "images" / image
    target_image_dir.mkdir(parents=True, exist_ok=True)

    # Image definition
    for name in ("properties.yml", "Containerfile.j2", ".gitmodules"):
        source = image_dir / name
        if source.is_file():
            shutil.copy2(source, target_image_dir / name)

    # Vendored machinery: symlinked so the work tree never carries a second
    # copy that could drift from the generators that read it.
    for name in ("macros", "templates", "yum-repos"):
        _symlink(HUMMINGBIRD_DIR / name, hbgen / name)
    (hbgen / "ci").mkdir(parents=True, exist_ok=True)
    _symlink(HUMMINGBIRD_DIR / "get_rpm_versions.sh", hbgen / "ci" / "get_rpm_versions.sh")

    # Distro repo files must live INSIDE the build context: non-hummingbird
    # Containerfiles COPY yum-repos/<distro>.repo into the builder stage so
    # dnf-installroot installs from that distro's repositories. The hbgen-level
    # yum-repos symlink serves rpms.in.yaml/get_rpm_versions.sh only.
    _copy_repo_files(HUMMINGBIRD_DIR / "yum-repos", target_image_dir / "yum-repos")

    # SCAP datastreams for the distros being built (see required_oscap_datastreams).
    _copy_oscap_datastreams(
        required_oscap_datastreams(variables, properties, distros), target_image_dir
    )

    # Extra build-context files (rootfs for config/scripts, src for source
    # builds, prebuildfs for the shared runtime libraries).
    _copy_extra_context(image_dir, target_image_dir)

    info(
        f"prepared {hbgen} for '{image}' "
        f"(distros: {', '.join(distros)}; variables: {base_vars}"
        f"{f' + {overlay_vars}' if overlay_vars else ''})"
    )
    print(hbgen)
    return 0


def require_builder_files(image_dir: Path) -> None:
    """Fail early with an actionable message when this is not a builder dir."""
    if not image_dir.is_dir():
        raise ConfigError(f"builder directory not found: {image_dir}")
    missing = [
        name for name in ("properties.yml", "Containerfile.j2")
        if not (image_dir / name).is_file()
    ]
    if missing:
        raise ConfigError(
            f"{image_dir} is not a hummingbird builder: missing {', '.join(missing)}"
        )


def _recreate_tree(hbgen: Path) -> None:
    """Remove and recreate the work tree.

    The path is validated before removal: a driver bug that passed an empty or
    unexpected directory must never turn into a recursive delete of a real tree.
    """
    if hbgen.name != WORK_TREE_NAME:
        raise ConfigError(f"refusing to recreate '{hbgen}': not a {WORK_TREE_NAME} work tree")
    if hbgen.exists():
        if not hbgen.is_dir() or hbgen.is_symlink():
            raise ConfigError(f"refusing to remove '{hbgen}': not a plain directory")
        shutil.rmtree(hbgen)
    (hbgen / "images").mkdir(parents=True)
    (hbgen / "ci").mkdir(parents=True)
    (hbgen / ".cache").mkdir(parents=True)


def _symlink(target: Path, link: Path) -> None:
    if not target.exists():
        raise ConfigError(f"vendored path missing: {target}")
    link.parent.mkdir(parents=True, exist_ok=True)
    link.symlink_to(target)


def _copy_repo_files(source_dir: Path, target_dir: Path) -> None:
    if not source_dir.is_dir():
        return
    repos = sorted(source_dir.glob("*.repo"))
    if not repos:
        return
    target_dir.mkdir(parents=True, exist_ok=True)
    for repo in repos:
        shutil.copy2(repo, target_dir / repo.name)


def _copy_oscap_datastreams(datastreams: dict[str, str], target_image_dir: Path) -> None:
    if not datastreams:
        return
    source_dir = HUMMINGBIRD_DIR / "oscap"
    copied: list[str] = []
    for distro, filename in sorted(datastreams.items()):
        source = source_dir / filename
        if not source.is_file():
            note(
                f"oscap datastream for '{distro}' not vendored: {source} "
                f"(verify-compliance will fail unless the builder image provides it)"
            )
            continue
        target_image_dir.joinpath("oscap").mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target_image_dir / "oscap" / filename)
        copied.append(f"{distro}={filename}")
    if copied:
        info(f"vendored oscap datastream(s): {', '.join(copied)}")


def _copy_extra_context(image_dir: Path, target_image_dir: Path) -> None:
    for name in EXTRA_CONTEXT_DIRS:
        source = image_dir / name
        if source.is_dir():
            shutil.copytree(source, target_image_dir / name, symlinks=True)
            continue
        # prebuildfs is vendored alongside the machinery and shared by every
        # builder that does not carry its own copy.
        if name == "prebuildfs" and (HUMMINGBIRD_DIR / name).is_dir():
            shutil.copytree(
                HUMMINGBIRD_DIR / name, target_image_dir / name, symlinks=True
            )


# --------------------------------------------------------------------------- #
# Stage: rpms
# --------------------------------------------------------------------------- #
def cmd_rpms(args: argparse.Namespace) -> int:
    """Write rpms.in.yaml for every distro/variant of the matrix."""
    tree = WorkTree(args.hbgen, args.image)
    for distro, variant in _matrix_for(tree, args):
        output = tree.variant_dir(distro, variant) / "rpms" / "rpms.in.yaml"
        output.parent.mkdir(parents=True, exist_ok=True)
        relative = output.relative_to(tree.root)
        _run_vendored("generate_rpms_in.py", tree.root, str(relative))
        info(f"rpms.in.yaml: {tree.image}/{distro}/{variant}")
    return 0


def _run_vendored(script: str, cwd: Path, *script_args: str) -> None:
    """Run a vendored generator from the work-tree root, as upstream does."""
    command = [sys.executable, str(HUMMINGBIRD_DIR / script), *script_args]
    result = subprocess.run(command, cwd=cwd, check=False)
    if result.returncode != 0:
        raise ConfigError(f"{script} failed (exit {result.returncode}) in {cwd}")


# --------------------------------------------------------------------------- #
# Stage: matrix
# --------------------------------------------------------------------------- #
def cmd_variants(args: argparse.Namespace) -> int:
    """Print the variant list of an image (one per line).

    The list is the aggregated one: properties.yml ``variants`` plus
    ``additional_variants``, which is why it is only available after
    aggregate_properties.py has run.
    """
    tree = WorkTree(args.hbgen, args.image)
    for variant in resolve_variants(tree.image_properties(), args.variants):
        print(variant)
    return 0


def cmd_matrix(args: argparse.Namespace) -> int:
    """Print one row per build: ``<distro>\\t<variant>\\t<image-name>``.

    The image name is resolved here (hb_variant.resolve_image_name) so the
    driver publishes exactly the name the rendered labels advertise.
    """
    tree = WorkTree(args.hbgen, args.image)
    for distro, variant in _matrix_for(tree, args):
        print(f"{distro}\t{variant}\t{resolve_image_name(tree.image, variant)}")
    return 0


def _matrix_for(tree: WorkTree, args: argparse.Namespace) -> list[tuple[str, str]]:
    """Shared matrix resolution for rpms/matrix/render/config."""
    properties = tree.image_properties()
    distros = resolve_distros(tree.merged_variables(), properties, args.distros)
    variants = resolve_variants(properties, args.variants)
    return resolve_matrix(properties, distros, variants)


# --------------------------------------------------------------------------- #
# Stage: render
# --------------------------------------------------------------------------- #
def cmd_render(args: argparse.Namespace) -> int:
    """Render VERSION, TAGS, oscap-tailoring.xml and Containerfile per variant."""
    # Imported lazily: `prepare`, `matrix` and `config` do not need Jinja.
    from generate_jinja2 import render_template

    tree = WorkTree(args.hbgen, args.image)
    for distro, variant in _matrix_for(tree, args):
        variant_dir = tree.variant_dir(distro, variant)
        if not (variant_dir / "rpms" / "rpms.in.yaml").is_file():
            raise ConfigError(
                f"{variant_dir}/rpms/rpms.in.yaml is missing — run 'hbgen.py rpms' "
                f"and get_rpm_versions.sh before rendering"
            )

        for template, output_name in VARIANT_TEMPLATES:
            render_template(
                tree.root / template,
                variant_dir / output_name,
            )

        containerfile = tree.containerfile(distro, variant)
        render_template(
            tree.image_dir / "Containerfile.j2",
            containerfile,
        )
        _rewrite_oci_archive_path(containerfile, tree.image_dir)
        info(f"rendered {tree.image}/{distro}/{variant}")
    return 0


def _rewrite_oci_archive_path(containerfile: Path, context_dir: Path) -> None:
    """Point ``FROM oci-archive:`` at an absolute path inside the build context.

    chunkah writes /run/src/out.ociarchive, and /run/src is a bind mount of the
    build context (= images/<image>). The driver cannot chdir before invoking
    the engine, and buildah resolves a relative oci-archive against its CWD, so
    the reference has to be absolute.
    """
    archive = context_dir / "out.ociarchive"
    lines = containerfile.read_text(encoding="utf-8").splitlines()
    rewritten = [
        f"FROM oci-archive:{archive}" if line.startswith("FROM oci-archive:") else line
        for line in lines
    ]
    if rewritten != lines:
        containerfile.write_text("\n".join(rewritten) + "\n", encoding="utf-8")


# --------------------------------------------------------------------------- #
# Stage: config
# --------------------------------------------------------------------------- #
def cmd_config(args: argparse.Namespace) -> int:
    """Print the build configuration of one distro/variant as TAB-separated pairs.

    The driver reads these into its CONFIG array. Every
    precedence rule for the hummingbird flavour lives in this one function, so
    "where does this value come from?" has a single answer.

    Precedence (highest first):
        image name   hb_variant.resolve_image_name(image, variant)
        version      HB_VERSION > rendered VERSION > "latest"
        tags         HB_TAGS > rendered TAGS > version-latest strategy
        registries   HB_REGISTRIES > REGISTRY > variables.yml registries/registry
        push         SKIP_PUSH > variables.yml skip_push > per-registry push
        platforms    PLATFORMS > variables.yml platforms
        chunkah      detected from the rendered Containerfile
        source epoch SOURCE_DATE_EPOCH > git commit time > template mtime > now
    """
    tree = WorkTree(args.hbgen, args.image)
    distro, variant = args.distro, args.variant
    variant_dir = tree.variant_dir(distro, variant)
    if not tree.containerfile(distro, variant).is_file():
        raise ConfigError(
            f"no rendered Containerfile for {tree.image}/{distro}/{variant} — "
            f"run 'hbgen.py render' first"
        )

    variables = tree.merged_variables()
    image_name = resolve_image_name(tree.image, variant)

    version = _resolve_version(variant_dir)
    tags, tag_strategy = _resolve_tags(variant_dir, version)
    skip_push = _resolve_skip_push(variables)
    registries = _resolve_registries(variables, skip_push)
    platforms = _resolve_platforms(variables)
    chunkah = _detect_chunkah(tree.containerfile(distro, variant))
    source_date_epoch = _resolve_source_date_epoch(args.image_dir or tree.image_dir)

    emitted: list[tuple[str, str]] = [
        ("HBGEN_IMAGE_NAME", image_name),
        ("HBGEN_DISTRO", distro),
        ("HBGEN_VARIANT", variant),
        ("HBGEN_VERSION", version),
        ("HBGEN_TAG_STRATEGY", tag_strategy),
        ("HBGEN_TAGS", tags),
        ("HBGEN_SKIP_PUSH", "true" if skip_push else "false"),
        ("HBGEN_PLATFORMS", platforms),
        ("HBGEN_CHUNKAH", "true" if chunkah else "false"),
        ("HBGEN_SOURCE_DATE_EPOCH", str(source_date_epoch)),
        ("HBGEN_REGISTRY_COUNT", str(len(registries))),
    ]
    emitted += [
        (f"HBGEN_REGISTRY_{index}", f"{name}|{prefix}|{push}")
        for index, (name, prefix, push) in enumerate(registries)
    ]

    # TAB separated so the driver reads values verbatim: no shell quoting rules
    # to get right and no eval of generated text.
    for key, value in emitted:
        print(f"{key}\t{value}")
    return 0


def _resolve_version(variant_dir: Path) -> str:
    override = os.environ.get("HB_VERSION", "").strip()
    if override:
        return override
    version_file = variant_dir / "VERSION"
    version = version_file.read_text(encoding="utf-8").strip() if version_file.is_file() else ""
    if not version or version == "unknown":
        # "unknown" means no package version could be resolved; publishing an
        # image tagged "unknown" hides that, so fall back and say so.
        if version == "unknown":
            note(
                f"{version_file} resolved to 'unknown' — no version for the "
                f"main package in this distro's repositories; tagging 'latest'"
            )
        return "latest"
    return version


def _is_unresolved_tag(tag: str) -> bool:
    """True when a tag carries an unresolved package version.

    ``package_version()`` renders ``unknown`` when the version could not be
    resolved, and ``TAGS.j2`` appends the variant suffix, so the value reaching
    us is either ``unknown`` or ``unknown-<variant>`` (e.g. ``unknown-fips``).
    """
    return tag == "unknown" or tag.startswith("unknown-")


def _resolve_tags(variant_dir: Path, version: str) -> tuple[str, str]:
    """Return (space separated tags, tag strategy).

    WHY tags are filtered and deduplicated here: ``TAG_STRATEGY=custom`` makes
    the engine publish ``CONFIG[CUSTOM_TAGS]`` verbatim, so a tag list rendered
    from an unresolved version would push real ``:unknown`` / ``:unknown-fips``
    tags to the registry. Dropping them leaves the meaningful tags (``latest``,
    ``latest-<variant>``) and keeps the list stable when a template emits the
    same value twice.
    """
    override = os.environ.get("HB_TAGS", "").strip()
    if override:
        return " ".join(_dedupe(_split(override))), "custom"

    tags_file = variant_dir / "TAGS"
    if tags_file.is_file():
        rendered = [
            line.strip()
            for line in tags_file.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        tags = _dedupe(t for t in rendered if not _is_unresolved_tag(t))
        dropped = len(rendered) - len(tags)
        if dropped:
            note(
                f"{tags_file}: dropped {dropped} tag(s) with an unresolved version "
                f"(kept: {' '.join(tags) or 'none'})"
            )
        if tags:
            return " ".join(tags), "custom"
        # Every rendered tag was unresolved: fall back to the resolved VERSION
        # (which _resolve_version already turned into "latest") rather than
        # publishing nothing at all.
        if version:
            return version, "custom"
    return "", "version-latest"


def _resolve_skip_push(variables: dict) -> bool:
    env_value = os.environ.get("SKIP_PUSH", "").strip()
    if env_value:
        return as_bool(env_value)
    return as_bool(variables.get("skip_push"))


def _resolve_registries(variables: dict, skip_push: bool) -> list[tuple[str, str, str]]:
    """Return (name, prefix, push) triples in declaration order."""
    env_list = os.environ.get("HB_REGISTRIES") or os.environ.get("REGISTRY") or ""
    env_prefix = os.environ.get("IMAGE_PREFIX", "")

    entries: list[tuple[str, str, str]] = []
    if env_list.strip():
        entries = [(name, env_prefix, "") for name in _split(env_list)]
    else:
        for registry in as_list(variables.get("registries")) or []:
            if isinstance(registry, dict):
                entries.append(
                    (
                        str(registry.get("name", "")),
                        str(registry.get("prefix", "") or ""),
                        "" if registry.get("push") is None else str(registry["push"]),
                    )
                )
            else:
                entries.append((str(registry), "", ""))
        if not entries:
            scalar = variables.get("registries") or variables.get("registry")
            if isinstance(scalar, str) and scalar.strip():
                entries.append((scalar.strip(), "", ""))

    resolved: list[tuple[str, str, str]] = []
    for name, prefix, push in entries:
        if not name:
            continue
        enabled = not skip_push
        if push and not as_bool(push, default=True):
            enabled = False
        resolved.append((name, prefix, "true" if enabled else "false"))

    if not resolved:
        note(
            "no registry configured (HB_REGISTRIES / REGISTRY / variables.yml "
            "registries) — the build engine will fall back to its own default"
        )
    return resolved


def _resolve_platforms(variables: dict) -> str:
    env_value = os.environ.get("PLATFORMS", "").strip()
    if env_value:
        return ",".join(_split(env_value))
    configured = variables.get("platforms")
    if isinstance(configured, list):
        return ",".join(str(item) for item in configured)
    return str(configured or "")


def _detect_chunkah(containerfile: Path) -> bool:
    """True when the rendered Containerfile produces its image with chunkah.

    Detected from the artifact instead of being hard-coded: a Containerfile.j2
    that does not call final_stage() has no oci-archive step, and the engine's
    chunkah workarounds (bind mount, serial platform builds, --cap-add) would
    only slow it down.
    """
    return "chunkah build" in containerfile.read_text(encoding="utf-8")


def _resolve_source_date_epoch(image_dir: Path | str) -> int:
    """Deterministic build timestamp for reproducible images.

    The rendered Containerfile declares ARG SOURCE_DATE_EPOCH (upstream
    reproducibility hook) and the engine warns when no value is passed.
    """
    env_value = os.environ.get("SOURCE_DATE_EPOCH", "").strip()
    if env_value.isdigit():
        return int(env_value)

    image_dir = Path(image_dir)
    commit_time = _git_commit_time(image_dir)
    if commit_time:
        return commit_time

    template = image_dir / "Containerfile.j2"
    if template.is_file():
        return int(template.stat().st_mtime)

    note("SOURCE_DATE_EPOCH falling back to the current time (build not reproducible)")
    return int(time.time())


def _git_commit_time(directory: Path) -> int | None:
    try:
        result = subprocess.run(
            ["git", "log", "-1", "--format=%ct"],
            cwd=directory,
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return None
    if result.returncode != 0:
        return None
    value = result.stdout.strip()
    return int(value) if value.isdigit() else None


# --------------------------------------------------------------------------- #
# Stage: vars / distros (small standalone helpers, also used by the driver)
# --------------------------------------------------------------------------- #
def cmd_vars(args: argparse.Namespace) -> int:
    """Print (or write) the deep-merged variables.yml."""
    base = Path(args.base).resolve()
    overlay = Path(args.overlay).resolve() if args.overlay else None
    merged = merge_variables(base, overlay)
    if args.out:
        out = Path(args.out).resolve()
        out.parent.mkdir(parents=True, exist_ok=True)
        _dump_yaml(merged, out)
        print(out)
    else:
        _dump_yaml(merged, sys.stdout)
    return 0


def cmd_distros(args: argparse.Namespace) -> int:
    """Print the resolved distro list, warning about unmapped repositories.

    Works straight from a builder directory (no .hbgen needed), so it can be
    used to answer "which distros would this build?" before generating.
    """
    image_dir = Path(args.image_dir).resolve()
    require_builder_files(image_dir)
    base_vars, overlay_vars = resolve_variables_files(
        Path(args.builders_dir).resolve() if args.builders_dir else None, image_dir
    )
    variables = merge_variables(base_vars, overlay_vars)
    properties = load_yaml(image_dir / "properties.yml", "properties.yml")

    distros = resolve_distros(variables, properties, args.requested)
    _warn_missing_repos(variables, properties, distros)
    print("\n".join(distros))
    return 0


def _warn_missing_repos(variables: dict, properties: dict, distros: Iterable[str]) -> None:
    """Warn when a distro has no repo mapping.

    generate_rpms_in falls back to default_variant_repos.default or the image's
    additional_repos, and the build itself resolves packages from the builder
    image's baked-in repos — so this is a warning, not an error.
    """
    known_repos = variables.get("default_variant_repos") or {}
    if properties.get("additional_repos") or "default" in known_repos:
        return
    for distro in distros:
        if distro not in known_repos:
            note(
                f"no default_variant_repos entry for distro '{distro}' in "
                f"variables.yml; rpms.in.yaml will reference no yum repo files"
            )


def _dump_yaml(data: dict, destination: "Path | object") -> None:
    """Write data as YAML to a path or to an open stream (e.g. sys.stdout)."""
    import yaml

    rendered = yaml.safe_dump(data, sort_keys=False, allow_unicode=True)
    if isinstance(destination, Path):
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(rendered, encoding="utf-8")
    else:
        destination.write(rendered)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def info(message: str) -> None:
    print(f"[hbgen] {message}", file=sys.stderr)


def note(message: str) -> None:
    print(f"[hbgen] warning: {message}", file=sys.stderr)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hbgen.py",
        description="Hummingbird work-tree generator (see module docstring).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    def add_matrix_options(command: argparse.ArgumentParser) -> None:
        command.add_argument("--distros", help="comma/space separated distro selection")
        command.add_argument("--variants", help="comma/space separated variant selection")

    prepare = sub.add_parser("prepare", help="create the .hbgen work tree")
    prepare.add_argument("--image-dir", required=True, help="builder directory")
    prepare.add_argument("--hbgen", help=f"work tree (default: <image-dir>/{WORK_TREE_NAME})")
    prepare.add_argument("--image", help="image name (default: builder directory name)")
    prepare.add_argument("--builders-dir", help="directory holding the shared variables.yml")
    prepare.add_argument("--distros", help="comma/space separated distro selection")
    prepare.set_defaults(handler=cmd_prepare)

    rpms = sub.add_parser("rpms", help="write rpms.in.yaml for every matrix entry")
    rpms.add_argument("--hbgen", required=True)
    rpms.add_argument("--image", required=True)
    add_matrix_options(rpms)
    rpms.set_defaults(handler=cmd_rpms)

    matrix = sub.add_parser("matrix", help="list distro/variant/image-name rows")
    matrix.add_argument("--hbgen", required=True)
    matrix.add_argument("--image", required=True)
    add_matrix_options(matrix)
    matrix.set_defaults(handler=cmd_matrix)

    render = sub.add_parser("render", help="render the per-variant files")
    render.add_argument("--hbgen", required=True)
    render.add_argument("--image", required=True)
    add_matrix_options(render)
    render.set_defaults(handler=cmd_render)

    config = sub.add_parser("config", help="print one row's build config as shell vars")
    config.add_argument("--hbgen", required=True)
    config.add_argument("--image", required=True)
    config.add_argument("--distro", required=True)
    config.add_argument("--variant", required=True)
    config.add_argument("--image-dir", help="builder directory (for SOURCE_DATE_EPOCH)")
    config.set_defaults(handler=cmd_config)

    variables = sub.add_parser("vars", help="print/write the merged variables.yml")
    variables.add_argument("--base", required=True, help="shared variables.yml")
    variables.add_argument("--overlay", help="per-image variables.yml")
    variables.add_argument("--out", help="write here instead of stdout")
    variables.set_defaults(handler=cmd_vars)

    variants = sub.add_parser("variants", help="print the aggregated variant list")
    variants.add_argument("--hbgen", required=True)
    variants.add_argument("--image", required=True)
    variants.add_argument("--variants", help="explicit variant selection (HB_VARIANTS)")
    variants.set_defaults(handler=cmd_variants)

    distros = sub.add_parser("distros", help="print the resolved distro list")
    distros.add_argument("--image-dir", required=True, help="builder directory")
    distros.add_argument("--builders-dir", help="directory holding the shared variables.yml")
    distros.add_argument("--requested", help="explicit distro selection (HB_DISTROS)")
    distros.set_defaults(handler=cmd_distros)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.handler(args) or 0)
    except ConfigError as exc:
        # WHY: configuration problems are operator errors; a traceback hides
        # the one line that says which file and which key to fix.
        print(f"[hbgen] error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
