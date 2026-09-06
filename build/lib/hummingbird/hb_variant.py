#!/usr/bin/env python3
"""Variant naming semantics — the single source of truth.

A hummingbird *variant* is a build flavour of one image definition. Variant
names are composed of an optional base name plus modifier suffixes, in any
order::

    default            -> base "default", no modifiers
    builder            -> base "default", builder
    fips               -> base "default", fips
    fpm                -> base "fpm",     no modifiers
    fpm-fips-builder   -> base "fpm",     builder + fips
    fpm-builder-fips   -> base "fpm",     builder + fips  (order independent)

Three consumers need these semantics and they MUST agree, otherwise the
published image, its labels and its package set drift apart:

===========================  =========================================
Consumer                     Uses
===========================  =========================================
Jinja macros (*.yml.j2)      is_builder / is_fips template variables
generate_jinja2.py           canonical_name label, variant labels
hbgen.py                     image name handed to the build engine
===========================  =========================================

Everything lives here so a new modifier (e.g. "debug") is added in exactly
one place: extend MODIFIER_SUFFIXES and, if it changes the published
repository name, IMAGE_NAME_SUFFIXES.
"""

from __future__ import annotations

from dataclasses import dataclass

#: Modifier suffixes that can be appended to a base variant name, in any order.
MODIFIER_SUFFIXES: frozenset[str] = frozenset({"builder", "fips"})

#: Repository-name suffix applied per modifier. Only modifiers listed here
#: change the published image name; every other variant shares the image
#: repository and is distinguished by its tag (see TAGS.j2, which appends
#: "-<variant>" to every tag of a non-default variant).
IMAGE_NAME_SUFFIXES: tuple[tuple[str, str], ...] = (("builder", "-builder"),)

#: Variant used when a name carries modifiers only (e.g. "builder").
DEFAULT_BASE_VARIANT = "default"


@dataclass(frozen=True)
class VariantInfo:
    """Decomposed variant name."""

    name: str
    base: str
    is_builder: bool
    is_fips: bool

    @property
    def is_default(self) -> bool:
        """True for the plain "default" variant (no modifiers)."""
        return self.name == DEFAULT_BASE_VARIANT


def decompose_variant(variant: str) -> VariantInfo:
    """Split a variant name into its base name and modifier flags.

    Suffixes are stripped from the right in any order, so "fpm-fips-builder"
    and "fpm-builder-fips" both decompose to base "fpm" with both modifiers.
    A name made only of modifiers (e.g. "builder") has base "default".
    """
    remaining = variant
    found: set[str] = set()

    while remaining:
        head, separator, tail = remaining.rpartition("-")
        candidate = tail if separator else remaining
        if candidate not in MODIFIER_SUFFIXES:
            break
        found.add(candidate)
        remaining = head if separator else ""

    return VariantInfo(
        name=variant,
        base=remaining or DEFAULT_BASE_VARIANT,
        is_builder="builder" in found,
        is_fips="fips" in found,
    )


def is_builder_variant(image_name: str, variant: str) -> bool:
    """True when this build produces a *builder* image.

    The builder image itself is always a builder, whatever its variant.
    """
    return image_name == "hummingbird-builder" or decompose_variant(variant).is_builder


def resolve_image_name(image_name: str, variant: str) -> str:
    """Return the image repository name published for this variant.

    The same rule feeds CONFIG[IMAGE_NAME] in the build driver and the
    ``name``/``canonical_name`` OCI labels, so a scanner reading the label
    always resolves to the repository the image was actually pushed to.
    """
    info = decompose_variant(variant)
    suffix = "".join(
        repo_suffix
        for modifier, repo_suffix in IMAGE_NAME_SUFFIXES
        if getattr(info, f"is_{modifier}", False)
    )
    return f"{image_name}{suffix}"


def image_repository(canonical_registry: str, image_name: str, variant: str) -> str:
    """Fully qualified reference (without tag) for this distro/variant."""
    return f"{canonical_registry.rstrip('/')}/{resolve_image_name(image_name, variant)}"
