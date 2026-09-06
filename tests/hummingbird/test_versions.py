#!/usr/bin/env python3
"""RPM requests are distro/architecture scoped; cache reuse is request scoped."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import yaml

REPO = Path(__file__).resolve().parents[2]
HB = REPO / "build/lib/hummingbird"
sys.path.insert(0, str(HB))
from hb_config import ConfigError
from hb_versions import cache_is_fresh, collect_results, make_plan, write_plan


class VersionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.results = self.root / "results"
        self.results.mkdir()
        (self.root / "ci").mkdir()
        (self.root / "ci/get_rpm_versions.sh").symlink_to(HB / "get_rpm_versions.sh")
        (self.root / "ci/internal").symlink_to(HB)
        self.cache = self.root / ".cache/rpm-versions.yml"

    def tearDown(self):
        self.tmp.cleanup()

    def inputs(self, distros=("hummingbird", "ubi9", "ubi10"), arches=("x86_64", "aarch64"), extra=None):
        for distro in distros:
            path = self.root / f"images/demo/{distro}/default/rpms/rpms.in.yaml"
            path.parent.mkdir(parents=True, exist_ok=True)
            data = {"arches": list(arches), "packages": ["curl", "openssl-fips-provider", *(extra or [])],
                    "contentOrigin": {"repofiles": [str(HB / f"yum-repos/{distro}.repo")]}}
            path.write_text(yaml.safe_dump(data))
        return make_plan(self.root, "example/builder:1")

    def answers(self, plan):
        for query in plan["queries"]:
            file = self.results / f"{query['distro']}--{query['arch']}.versions"
            file.write_text("".join(f"{package} 3:1.0-1.{query['distro']}\n" for package in query["packages"]))

    def test_one_query_per_selected_distro_arch_with_correct_package_constraints(self):
        plan = self.inputs(extra=[{"name": "arm-only", "arches": {"only": "arm64"}},
                                  {"name": "amd-only", "arches": {"not": "arm64"}}])
        self.assertEqual(len(plan["queries"]), 6)
        for query in plan["queries"]:
            self.assertEqual("arm-only" in query["packages"], query["arch"] == "aarch64")
            self.assertEqual("amd-only" in query["packages"], query["arch"] == "x86_64")
            self.assertEqual(query["repos"], [str(HB / f"yum-repos/{query['distro']}.repo")])

    def test_single_arm64_selection_does_not_query_amd64(self):
        plan = self.inputs(arches=("aarch64",))
        self.assertEqual(len(plan["queries"]), 3)
        self.assertEqual({query["arch"] for query in plan["queries"]}, {"aarch64"})

    def test_cache_preserves_both_distro_and_architecture_and_strips_epoch(self):
        plan = self.inputs()
        self.answers(plan)
        cache = collect_results(plan, self.results)
        self.assertEqual(cache["distros"]["ubi9"]["curl"], "1.0-1.ubi9")
        self.assertEqual(set(cache["architectures"]["ubi10"]), {"x86_64", "aarch64"})
        self.assertNotEqual(cache["distros"]["hummingbird"]["curl"], cache["distros"]["ubi9"]["curl"])

    def test_missing_provider_on_one_arch_cannot_be_masked_by_the_other(self):
        plan = self.inputs(distros=("ubi9",))
        self.answers(plan)
        (self.results / "ubi9--aarch64.versions").write_text("curl 1.0-1.ubi9\n")
        with self.assertRaisesRegex(ConfigError, "ubi9/openssl-fips-provider.*aarch64"):
            collect_results(plan, self.results)

    def test_conflicting_versions_fail_instead_of_mistagging_a_manifest(self):
        plan = self.inputs(distros=("ubi9",))
        self.answers(plan)
        (self.results / "ubi9--aarch64.versions").write_text("curl 2.0-1.ubi9\nopenssl-fips-provider 1.0-1.ubi9\n")
        with self.assertRaisesRegex(ConfigError, "differs across requested architectures"):
            collect_results(plan, self.results)

    def test_fresh_cache_for_other_architectures_or_packages_is_not_reused(self):
        plan = self.inputs(distros=("ubi9",), arches=("x86_64",))
        self.answers(plan)
        self.cache.parent.mkdir()
        self.cache.write_text(yaml.safe_dump(collect_results(plan, self.results)))
        self.assertTrue(cache_is_fresh(plan, self.cache, 600))
        arm_plan = self.inputs(distros=("ubi9",), arches=("aarch64",))
        self.assertFalse(cache_is_fresh(arm_plan, self.cache, 600))
        pkg_plan = self.inputs(distros=("ubi9",), arches=("x86_64",), extra=["new-package"])
        self.assertFalse(cache_is_fresh(pkg_plan, self.cache, 600))
        self.assertFalse(cache_is_fresh(plan, self.cache, 0))

    def test_shell_queries_target_architecture_without_running_foreign_binaries(self):
        self.inputs(distros=("hummingbird", "ubi9"))
        log = self.root / "queries.log"
        env = {**os.environ, "PATH": f"{REPO / 'tests/hummingbird/stubs'}:{os.environ['PATH']}",
               "CONTAINER_ENGINE": "podman", "HB_PYTHON": sys.executable,
               "HB_STUB_DATA": str(REPO / "tests/hummingbird/fixtures/rpm-versions.tsv"),
               "HB_STUB_LOG": str(log)}
        result = subprocess.run(["bash", "ci/get_rpm_versions.sh"], cwd=self.root, env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        calls = log.read_text().splitlines()
        self.assertEqual(len(calls), 4)
        self.assertEqual(sum("--forcearch=aarch64" in call for call in calls), 2)
        self.assertEqual(sum("--forcearch=x86_64" in call for call in calls), 2)
        self.assertTrue(all("--platform" not in call for call in calls))
        self.assertTrue(all("--setopt=reposdir=/etc/hb-repos" in call for call in calls))
        cache = yaml.safe_load(self.cache.read_text())
        self.assertEqual(len(cache["architectures"]["ubi9"]), 2)
        self.assertIn("8.10.1", cache["distros"]["ubi9"]["curl"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
