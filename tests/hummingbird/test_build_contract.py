#!/usr/bin/env python3
"""Offline contract tests: FIPS defaults, target platforms and rootfs lifecycle.

Run with a Python containing PyYAML and Jinja2. No container engine is used.
Tests exercise the real resolvers/macros and execute the rootfs helper in a
throwaway directory; runtime cryptographic certification is not simulated.
"""
from __future__ import annotations

import os
import re
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import yaml

REPO = Path(__file__).resolve().parents[2]
HB = REPO / "build/lib/hummingbird"
sys.path.insert(0, str(HB))

from generate_jinja2 import ImageContext
from hb_config import ConfigError, resolve_repos
from hb_packages import resolve_package_set
from hb_platforms import resolve_platforms, rpm_arches
from hb_rootfs import resolve_rootfs


class BuildContractTests(unittest.TestCase):
    def test_default_and_builder_are_fips_for_each_distro(self):
        for distro in ("hummingbird", "ubi9", "ubi10"):
            for variant in ("default", "builder", "fips", "fips-builder"):
                with self.subTest(distro=distro, variant=variant):
                    config = resolve_rootfs({}, {}, distro, variant)
                    self.assertTrue(config.fips)
                    self.assertEqual(config.crypto_policy, "FIPS")
                    packages = resolve_package_set({}, {}, distro, variant).main
                    self.assertIn("crypto-policies", packages)
                    self.assertIn("openssl-fips-provider", packages)
                    self.assertIn("openssl-fips-provider-so", packages)
                    self.assertEqual("openssl-config-fips" in packages, distro == "hummingbird")

    def test_explicit_non_fips_is_possible_but_not_under_a_fips_name(self):
        self.assertFalse(resolve_rootfs({}, {"fips": False}, "ubi9", "default").fips)
        self.assertNotIn("openssl-fips-provider", resolve_package_set({"fips": False}, {}, "ubi9", "default").main)
        with self.assertRaisesRegex(ConfigError, "fips.*variant"):
            resolve_rootfs({}, {"fips": False}, "ubi9", "fips-builder")

    def test_fips_and_crypto_policy_cannot_contradict_one_another(self):
        with self.assertRaisesRegex(ConfigError, "crypto_policy"):
            resolve_rootfs({}, {"oscap": {"crypto_policy": "DEFAULT"}}, "ubi9", "default")
        with self.assertRaisesRegex(ConfigError, "fips"):
            resolve_rootfs({}, {"fips": False, "oscap": {"crypto_policy": "FIPS"}}, "ubi9", "default")
        with self.assertRaises(ConfigError):
            resolve_rootfs({}, {"fips": "truue"}, "ubi9", "default")

    def test_default_packages_and_distro_modifier_groups_are_not_lost(self):
        properties = {"default_rpm_packages": {"all": ["prop-default"]},
                      "rpm_packages": {"all": ["curl", "curl"], "ubi9/fips": ["ubi-fips-extra"],
                                       "builder": ["tool"], "fips": ["fips-extra"]}}
        packages = resolve_package_set(properties, {"default_rpm_packages": {"all": ["shared"]}}, "ubi9", "fips-builder")
        self.assertTrue({"prop-default", "shared", "curl", "ubi-fips-extra", "tool", "fips-extra"}.issubset(packages.main))
        self.assertEqual(packages.main, sorted(set(packages.main)))

    def test_arch_build_dependencies_do_not_enter_runtime(self):
        properties = {"rpm_packages": {
            "all": [{"name": "arm-runtime", "arches": {"only": "arm64"}}, {"name": "everywhere"}],
            "build-deps": [{"name": "arm-compiler", "arches": {"only": "aarch64"}}]}}
        packages = resolve_package_set(properties, {}, "ubi10", "default")
        self.assertIn("everywhere", packages.main)
        self.assertEqual(packages.arch_packages, {"aarch64": ["arm-runtime"]})
        self.assertEqual(packages.build_arch_packages, {"aarch64": ["arm-compiler"]})
        self.assertNotIn("arm-compiler", packages.main)

    def test_arch_only_and_not_both_apply_and_aliases_are_normalized(self):
        p = {"rpm_packages": {"all": [{"name": "pkg", "arches": {"only": ["amd64", "arm64"], "not": "aarch64"}}]}}
        self.assertEqual(resolve_package_set(p, {}, "ubi9", "default").arch_packages, {"x86_64": ["pkg"]})
        with self.assertRaisesRegex(ConfigError, "architecture"):
            resolve_package_set({"rpm_packages": {"all": [{"name": "pkg", "arches": {"only": "arm65"}}]}}, {}, "ubi9", "default")

    def test_platform_precedence_and_deduplication(self):
        with patch.dict(os.environ, {"PLATFORMS": "linux/arm64, arm64 aarch64"}):
            self.assertEqual(resolve_platforms({"platforms": ["amd64"]}, {"platforms": "linux/amd64"}), ["linux/arm64"])
        with patch.dict(os.environ, {"PLATFORMS": ""}):
            self.assertEqual(resolve_platforms({"platforms": ["amd64"]}, {"platforms": "aarch64"}), ["linux/arm64"])
            self.assertEqual(resolve_platforms({"platforms": ["amd64", "arm64"]}, {}), ["linux/amd64", "linux/arm64"])
            self.assertEqual(resolve_platforms({}, {}, native_arch="aarch64"), ["linux/arm64"])
            self.assertEqual(rpm_arches(["linux/amd64", "linux/arm64"]), ["x86_64", "aarch64"])

    def test_bad_or_unsupported_platform_fails_before_build(self):
        for value in ("windows/amd64", "linux/arm65", "linux/arm/v7", "linux/amd64/garbage", ",,", []):
            with self.subTest(value=value), patch.dict(os.environ, {"PLATFORMS": ""}):
                with self.assertRaises(ConfigError):
                    resolve_platforms({}, {"platforms": value})

    def test_builtin_distro_repositories_do_not_fall_back_to_hummingbird(self):
        for distro in ("hummingbird", "ubi9", "ubi10"):
            self.assertEqual(resolve_repos({"default_variant_repos": {"default": ["hummingbird.repo"]}}, {}, distro), [f"{distro}.repo"])
        self.assertEqual(resolve_repos({}, {"additional_repos": ["private.repo"]}, "ubi9"), ["ubi9.repo", "private.repo"])

    def test_base_image_is_explicit_and_can_be_selected_per_distro(self):
        self.assertEqual(resolve_rootfs({}, {}, "ubi9", "default").base_image, "")
        p = {"base_image": {"ubi9": "registry.access.redhat.com/ubi9/ubi-minimal:latest", "hummingbird": "quay.io/example/base:latest"}}
        self.assertIn("ubi9", resolve_rootfs({}, p, "ubi9", "default").base_image)
        self.assertIn("quay.io", resolve_rootfs({}, p, "hummingbird", "default").base_image)
        self.assertEqual(resolve_rootfs({}, p, "ubi10", "default").base_image, "")
        self.assertEqual(resolve_rootfs({"base_image": "example/base:1"}, {"base_image": "scratch"}, "ubi9", "default").base_image, "")

    def test_required_fips_packages_cannot_be_removed_after_installation(self):
        with self.assertRaisesRegex(ConfigError, "required FIPS packages"):
            resolve_rootfs({}, {"remove_rpms_from_newroot": ["openssl-fips-provider"]}, "ubi9", "default")

    def test_base_image_and_policy_injection_rejected(self):
        for image in ("base:1\nRUN touch /oops", "bad ref", ["base:1"], "${UNSET}"):
            with self.subTest(image=image), self.assertRaises(ConfigError):
                resolve_rootfs({}, {"base_image": image}, "ubi9", "default")
        with self.assertRaises(ConfigError):
            resolve_rootfs({}, {"oscap": {"crypto_policy": 'FIPS"; echo nope'}}, "ubi9", "default")

    def render(self, properties, distro="ubi9", platforms="linux/amd64,linux/arm64"):
        """Exercise the actual prepare/aggregate/rpms/render/config pipeline."""
        with tempfile.TemporaryDirectory() as tmp:
            builders = Path(tmp) / "builders"
            image = builders / "demo"
            image.mkdir(parents=True)
            variables = {"default_distros": [distro], "variant_descriptions": {"default": "runtime"}, "default_user": "1001"}
            (builders / "variables.yml").write_text(yaml.safe_dump(variables))
            props = {"description": "demo", "summary": "demo", "url": "https://example.com", "stream": "1", "tags": [{"value": "latest"}], **properties}
            (image / "properties.yml").write_text(yaml.safe_dump(props))
            (image / "Containerfile.j2").write_text("{{ setup_newroot() }}\n{{ install_newroot() }}\n{{ cleanup_newroot() }}\n{{ final_stage() }}\n")
            env = {**os.environ, "PLATFORMS": platforms, "HUMMINGBIRD_DIR": str(HB)}
            tree = image / ".hbgen"
            commands = [
                [sys.executable, str(HB / "hbgen.py"), "prepare", "--image-dir", str(image), "--builders-dir", str(builders)],
                [sys.executable, str(HB / "aggregate_properties.py")],
                *[[sys.executable, str(HB / "hbgen.py"), stage, "--hbgen", str(tree), "--image", "demo"] for stage in ("rpms", "render")],
            ]
            for i, command in enumerate(commands):
                result = subprocess.run(command, cwd=tree if i else builders, env=env, text=True, capture_output=True)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            variant = tree / "images/demo" / distro / "default"
            cf = (variant / "Containerfile").read_text()
            # Parse every emitted RUN as shell; successful Jinja rendering alone
            # does not establish that the generated recipe is syntactically valid.
            for line in re.sub(r"\\\n", " ", cf).splitlines():
                if line.startswith("RUN "):
                    command = re.sub(r"^(?:--\S+\s+)+", "", line[4:])
                    syntax = subprocess.run(["bash", "-n"], input=command, text=True, capture_output=True)
                    self.assertEqual(syntax.returncode, 0, command + "\n" + syntax.stderr)
            rpms = yaml.safe_load((variant / "rpms/rpms.in.yaml").read_text())
            with patch.dict(os.environ, env):
                ctx = ImageContext(variant / "Containerfile")
            return cf, rpms, ctx.variables

    def test_rendered_fips_packages_match_rpm_inputs_on_each_platform(self):
        for distro in ("hummingbird", "ubi9", "ubi10"):
            for platforms, arches in (("linux/amd64", ["x86_64"]), ("linux/arm64", ["aarch64"]), ("linux/amd64,linux/arm64", ["x86_64", "aarch64"])):
                with self.subTest(distro=distro, platforms=platforms):
                    cf, rpms, variables = self.render({"rpm_packages": {"all": ["curl"]}}, distro, platforms)
                    self.assertEqual(rpms["arches"], arches)
                    self.assertEqual(set(rpms["packages"]), set(variables["main_packages"]))
                    self.assertIn("openssl-fips-provider", cf)
                    self.assertIn('io.hummingbird-project.variant.fips="true"', cf)
                    self.assertIn('hb-rootfs policy "${NEWROOT}" "FIPS"', cf)
                    self.assertFalse(variables["oscap"]["enabled"])

    def test_blank_rootfs_and_portable_final_stage_are_the_default(self):
        cf, _, _ = self.render({})
        self.assertIn('hb-rootfs reset "${NEWROOT}"', cf)
        self.assertNotIn("AS hb_base", cf)
        self.assertNotIn("dnf-installroot", cf)
        self.assertNotIn("oci-archive:", cf)
        self.assertIn("FROM scratch", cf)
        self.assertIn("COPY --from=builder ${NEWROOT}/ /", cf)

    def test_all_installroot_rpm_transactions_use_the_mount_wrapper(self):
        for distro in ("hummingbird", "ubi9", "ubi10"):
            with self.subTest(distro=distro):
                cf, _, _ = self.render({
                    "base_image": "example.com/base:1",
                    "rpm_packages": {"all": [{"name": "arm-runtime", "arches": {"only": "aarch64"}}]},
                    "remove_rpms_from_newroot": ["example-package"],
                }, distro)
                commands = re.sub(r"\\\n", " ", cf).splitlines()
                transactions = [line for line in commands if line.startswith("RUN ") and
                                ('--installroot="${NEWROOT}"' in line or 'rpm --root "${NEWROOT}"' in line)]
                self.assertEqual(len(transactions), 5)  # bootstrap, upgrade, main, arch, removal
                self.assertTrue(all('hb-rootfs exec "${NEWROOT}"' in line for line in transactions))
                self.assertNotIn("noscripts", cf)
                self.assertNotIn("nopost", cf)

    def test_seed_then_upgrade_then_install_order_is_explicit(self):
        cf, _, _ = self.render({"base_image": "example.com/ubi9/base:1", "rpm_packages": {"all": ["curl"]}})
        self.assertIn("FROM example.com/ubi9/base:1 AS hb_base", cf)
        reset = cf.index('hb-rootfs reset "${NEWROOT}"')
        seed = cf.index("COPY --from=hb_base / ${NEWROOT}/")
        upgrade = cf.index('upgrade')
        install = cf.index('install ${MAIN_PACKAGES}')
        self.assertLess(reset, seed)
        self.assertLess(seed, upgrade)
        self.assertLess(upgrade, install)
        self.assertIn("--releasever=9", cf)
        self.assertIn("COPY yum-repos/ubi9.repo", cf)

    def test_stig_tailoring_and_installed_policy_agree_without_exclusions(self):
        _, _, variables = self.render({"oscap": {"enabled": True, "profiles": {"stig": True}}})
        self.assertTrue(variables["oscap"]["has_tailoring"])
        self.assertEqual(variables["oscap"]["crypto_policy"], "FIPS")

    def test_chunkah_is_an_explicit_opt_in(self):
        cf, _, _ = self.render({"chunkah": True})
        self.assertIn("chunkah build", cf)
        self.assertIn("FROM oci-archive:", cf)


class RootfsHelperTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / "new-root-fs"
        self.root.mkdir()

    def tearDown(self):
        self.tmp.cleanup()

    def run_helper(self, action, *args, root=None):
        return subprocess.run(["bash", str(HB / "rootfs.sh"), action, str(root or self.root), *args], text=True, capture_output=True)

    def test_reset_removes_stale_content_including_dotfiles(self):
        (self.root / "stale").write_text("from a previous build")
        (self.root / ".hidden").write_text("also stale")
        self.assertEqual(self.run_helper("reset").returncode, 0)
        self.assertEqual(list(self.root.iterdir()), [])
        self.assertEqual(self.run_helper("reset").returncode, 0)

    def test_reset_refuses_unsafe_paths_and_symlinks(self):
        for path in ("/", "/etc", str(self.root / ".."), "relative"):
            with self.subTest(path=path):
                self.assertNotEqual(self.run_helper("reset", root=path).returncode, 0)
        alias = Path(self.tmp.name) / "alias"
        alias.symlink_to(self.root, target_is_directory=True)
        self.assertNotEqual(self.run_helper("reset", root=alias).returncode, 0)
        self.assertTrue(self.root.is_dir())

    def test_fips_policy_replaces_relative_links_and_regular_backend_files(self):
        definitions = self.root / "usr/share/crypto-policies/FIPS"
        definitions.mkdir(parents=True)
        for backend in ("opensslcnf", "gnutls"):
            (definitions / f"{backend}.txt").write_text("FIPS policy fixture")
        backends = self.root / "etc/crypto-policies/back-ends"
        backends.mkdir(parents=True)
        (backends / "opensslcnf.config").symlink_to("../../../usr/share/crypto-policies/LEGACY/opensslcnf.txt")
        (backends / "gnutls.config").write_text("old DEFAULT policy")
        module = self.root / "usr/lib64/ossl-modules"
        module.mkdir(parents=True)
        (module / "fips.so").write_text("fixture (not a real crypto module)")
        result = self.run_helper("policy", "FIPS")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.root / "etc/crypto-policies/config").read_text().strip(), "FIPS")
        self.assertEqual((self.root / "etc/crypto-policies/state/current").read_text().strip(), "FIPS")
        for backend in ("opensslcnf", "gnutls"):
            self.assertEqual(os.readlink(backends / f"{backend}.config"), f"/usr/share/crypto-policies/FIPS/{backend}.txt")
        self.assertEqual(self.run_helper("policy", "FIPS").returncode, 0)

    def test_base_check_rejects_cross_distro_upgrades_without_changing_content(self):
        (self.root / "etc").mkdir()
        (self.root / "etc/os-release").write_text('ID="rhel"\nVERSION_ID="9.6"\n')
        (self.root / "from-base").write_text("preserve me")
        self.assertEqual(self.run_helper("check-base", "ubi9").returncode, 0)
        for distro in ("ubi10", "hummingbird"):
            result = self.run_helper("check-base", distro)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("does not match", result.stderr)
        self.assertEqual((self.root / "from-base").read_text(), "preserve me")

    def test_rootfs_policy_cannot_write_through_an_inherited_external_symlink(self):
        outside = Path(self.tmp.name) / "outside"
        outside.mkdir()
        (self.root / "etc").symlink_to(outside, target_is_directory=True)
        result = self.run_helper("policy", "FIPS")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("escapes", result.stderr)
        self.assertEqual(list(outside.iterdir()), [])

    def test_fips_policy_fails_if_packages_are_missing(self):
        result = self.run_helper("policy", "FIPS")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("FIPS", result.stderr)
        self.assertFalse((self.root / "etc/crypto-policies/config").exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
