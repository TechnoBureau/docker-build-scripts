#!/usr/bin/env python3
"""Exercise the real build engine with recording Docker/Podman executables.

These tests verify commands, manifest assembly, selection and failure propagation.
They do not pretend that a recording stub can build or validate a real image.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[1]

STUB = r'''#!/usr/bin/env python3
import json, os, pathlib, sys
args = sys.argv[1:]
with open(os.environ["ENGINE_LOG"], "a") as f:
    f.write(json.dumps([pathlib.Path(sys.argv[0]).name, *args]) + "\n")
failure = os.environ.get("ENGINE_FAIL", "").split()
if failure and args[:len(failure)] == failure:
    print("deliberate engine failure", file=sys.stderr)
    sys.exit(7)
if "--iidfile" in args:
    platform = args[args.index("--platform") + 1]
    pathlib.Path(args[args.index("--iidfile") + 1]).write_text("id-" + platform.replace("/", "-") + "\n")
if "--output" in args:
    output = args[args.index("--output") + 1]
    if "dest=" in output:
        pathlib.Path(output.split("dest=", 1)[1]).write_text("OCI output fixture, not a real image")
if "--file" in args:
    pathlib.Path(os.environ["RECIPE_LOG"]).write_text(pathlib.Path(args[args.index("--file") + 1]).read_text())
# Deliberately quiet success: output filters must not turn exit 0 into failure.
'''

HARNESS = r'''
set -uo pipefail
source "$REPO/build/lib/ci-core.sh"
source "$REPO/build/lib/ci-build.sh"
detect_container_engine() { printf '%s\n' "$TEST_ENGINE"; }
ci_login_all_registries() { :; }
ci_prepull_from_images() { :; }
ci_cleanup_pulled_images() { :; }
ci_ensure_ecr_repository() { :; }
ci_generate_oci_labels() { :; }
ci_ibmcloud_save_artifact() { :; }
CONFIG=([IMAGE_NAME]=demo [VERSION]=1 [TAG_STRATEGY]=custom [CUSTOM_TAGS]="1 latest"
        [PLATFORMS]="$TEST_PLATFORMS" [DISTRO]="$TEST_DISTRO" [CHUNKAH]="$TEST_CHUNKAH")
REGISTRIES=("registry.example.com,team,$TEST_PUSH" "other.example.com,team,$TEST_PUSH" "disabled.example.com,team,false")
ci_build_and_push "$TEST_CONTEXT/Containerfile" "$TEST_CONTEXT"
status=$?
printf 'RESULT=%s ARCHES=%s PARALLEL=%s ARCHIVE=%s MANIFEST=%s\n' "$status" "${CI_BUILD_ARCHES[*]}" "${PARALLEL_PLATFORMS:-unset}" "${CI_IMAGE_ARCHIVE:-}" "${CI_LOCAL_MANIFEST:-}"
exit "$status"
'''


class EngineTests(unittest.TestCase):
    def run_engine(self, engine, platforms, *, distro="ubi9", push=True, fail="", chunkah=False, parallel=True, global_skip=False, rootfs=False, allow_insecure=False):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            for name in ("podman", "docker"):
                script = work / name
                script.write_text(STUB)
                script.chmod(0o755)
            recipe = ('# syntax=docker/dockerfile:1\nFROM scratch\nARG NEWROOT=/new-root-fs\n'
                      'RUN echo sandboxed\nRUN --mount=type=cache,target=/tmp/cache \\\n'
                      '    hb-rootfs exec "${NEWROOT}" dnf --installroot="${NEWROOT}" install filesystem\n'
                      'RUN echo still-sandboxed\n') if rootfs else "FROM scratch\n"
            (work / "Containerfile").write_text(recipe)
            log = work / "commands.jsonl"
            env = {**os.environ, "PATH": f"{tmp}:{os.environ['PATH']}", "ENGINE_LOG": str(log),
                   "ENGINE_FAIL": fail, "REPO": str(REPO), "TEST_CONTEXT": tmp,
                   "RECIPE_LOG": str(work / "built.recipe"), "ALLOW_INSECURE_ROOTFS": str(allow_insecure).lower(),
                   "TEST_ENGINE": engine, "TEST_PLATFORMS": platforms, "TEST_DISTRO": distro,
                   "TEST_PUSH": str(push).lower(), "TEST_CHUNKAH": str(chunkah).lower(),
                   "PARALLEL_PLATFORMS": str(parallel).lower(), "INSTALL_BINFMT": "false",
                   "SKIP_PUSH": str(global_skip).lower()}
            result = subprocess.run(["bash", "-c", HARNESS], env=env, text=True, capture_output=True)
            calls = [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
            self.last_recipe = (work / "built.recipe").read_text() if (work / "built.recipe").exists() else ""
            self.assertEqual((work / "Containerfile").read_text(), recipe)
            self.prepared_recipe_exists = [Path(cmd[cmd.index("--file") + 1]).exists() for cmd in calls
                                          if "--file" in cmd and cmd[cmd.index("--file") + 1] != str(work / "Containerfile")]
            return result, calls

    def test_single_arch_builds_for_each_distro_and_engine(self):
        for engine in ("docker", "podman"):
            for distro in ("hummingbird", "ubi9", "ubi10"):
                for platform in ("linux/amd64", "linux/arm64"):
                    with self.subTest(engine=engine, distro=distro, platform=platform):
                        result, calls = self.run_engine(engine, platform, distro=distro)
                        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                        builds = [cmd for cmd in calls if cmd[1] == "build"]
                        self.assertEqual(len(builds), 1)
                        self.assertEqual(builds[0][builds[0].index("--platform") + 1], platform)
                        self.assertEqual(len([cmd for cmd in calls if cmd[1] == "push"]), 4)
                        self.assertFalse(any("--privileged" in cmd for cmd in calls))
                        if engine == "podman":
                            self.assertIn(f"TARGETARCH={platform.split('/')[1]}", builds[0])

    def test_podman_rootfs_mount_capability_does_not_depend_on_chunkah(self):
        for chunkah in (False, True):
            for platforms in ("amd64", "amd64,arm64"):
                with self.subTest(chunkah=chunkah, platforms=platforms):
                    result, calls = self.run_engine("podman", platforms, rootfs=True, chunkah=chunkah)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    builds = [cmd for cmd in calls if cmd[1] == "build"]
                    self.assertTrue(builds)
                    self.assertTrue(all(cmd.count("--cap-add=SYS_ADMIN") == 1 for cmd in builds))
                    self.assertFalse(any("--privileged" in cmd for cmd in builds))

    def test_docker_rootfs_mounts_require_an_explicit_security_opt_in(self):
        result, calls = self.run_engine("docker", "amd64", rootfs=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("ALLOW_INSECURE_ROOTFS", result.stderr)
        self.assertFalse(any(cmd[1] == "build" or cmd[1:3] == ["buildx", "build"] for cmd in calls))

    def test_opted_in_docker_limits_insecure_run_flags_to_rootfs_transactions(self):
        for platforms in ("amd64", "amd64,arm64"):
            result, calls = self.run_engine("docker", platforms, rootfs=True, allow_insecure=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            builds = [cmd for cmd in calls if cmd[1:3] == ["buildx", "build"]]
            self.assertEqual(len(builds), 1)
            self.assertIn("--allow=security.insecure", builds[0])
            self.assertIn("--load" if platforms == "amd64" else "--push", builds[0])
            self.assertTrue(self.last_recipe.startswith("# syntax=docker/dockerfile:1-labs\n"))
            self.assertIn("RUN --security=insecure --mount=type=cache", self.last_recipe)
            self.assertIn("RUN echo sandboxed", self.last_recipe)
            self.assertIn("RUN echo still-sandboxed", self.last_recipe)
            self.assertEqual(self.last_recipe.count("--security=insecure"), 1)
            self.assertEqual(self.prepared_recipe_exists, [False])
            creates = [cmd for cmd in calls if cmd[1:3] == ["buildx", "create"]]
            # The stub reports a builder already present; custom builders must
            # be provisioned with the entitlement by their operator.
            self.assertFalse(creates)

    def test_rootfs_buildkit_builder_creation_enables_the_required_daemon_entitlement(self):
        result, calls = self.run_engine("docker", "amd64", rootfs=True, allow_insecure=True, fail="buildx inspect")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        creates = [cmd for cmd in calls if cmd[1:3] == ["buildx", "create"]]
        self.assertEqual(len(creates), 1)
        self.assertIn("docker-build-scripts-rootfs", creates[0])
        self.assertIn("--allow-insecure-entitlement security.insecure", creates[0])

    def test_rootfs_docker_failure_cleans_the_temporary_recipe_without_pushing(self):
        result, calls = self.run_engine("docker", "amd64", rootfs=True, allow_insecure=True, fail="buildx build")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.prepared_recipe_exists, [False])
        self.assertFalse(any(cmd[1] == "push" for cmd in calls))

    def test_rootfs_detection_is_not_broken_by_pipefail_on_large_recipes(self):
        with tempfile.TemporaryDirectory() as tmp:
            recipe = Path(tmp) / "Containerfile"
            recipe.write_text('RUN hb-rootfs exec /new-root-fs dnf install glibc\n' + 'RUN echo ordinary\n' * 10000)
            script = 'set -eo pipefail; source "$REPO/build/lib/ci-platforms.sh"; ci_requires_rootfs_mounts "$RECIPE"'
            result = subprocess.run(["bash", "-c", script], env={**os.environ, "REPO": str(REPO), "RECIPE": str(recipe)}, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_docker_multiarch_publishes_one_index_not_overwriting_tags(self):
        result, calls = self.run_engine("docker", "linux/amd64, linux/arm64 linux/amd64")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        builds = [cmd for cmd in calls if cmd[1:3] == ["buildx", "build"]]
        self.assertEqual(len(builds), 1)
        self.assertIn("linux/amd64,linux/arm64", builds[0])
        self.assertIn("--push", builds[0])
        self.assertEqual(builds[0].count("--tag"), 4)
        self.assertFalse(any(cmd[1] in ("push", "build") for cmd in calls))
        self.assertFalse(any("disabled.example.com" in " ".join(cmd) for cmd in calls))

    def test_podman_multiarch_assembles_after_all_workers(self):
        for parallel in (True, False):
            with self.subTest(parallel=parallel):
                result, calls = self.run_engine("podman", "amd64,arm64", parallel=parallel)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                builds = [cmd for cmd in calls if cmd[1] == "build"]
                self.assertEqual(len(builds), 2)
                self.assertTrue(all("--tag" not in cmd and "--manifest" not in cmd for cmd in builds))
                self.assertEqual({cmd[cmd.index("--platform") + 1] for cmd in builds}, {"linux/amd64", "linux/arm64"})
                self.assertEqual(len({cmd[cmd.index("--iidfile") + 1] for cmd in builds}), 2)
                creates = [i for i, cmd in enumerate(calls) if cmd[1:3] == ["manifest", "create"]]
                self.assertEqual(len(creates), 1)
                self.assertTrue(all(i < creates[0] for i, cmd in enumerate(calls) if cmd[1] == "build"))
                additions = [cmd for cmd in calls if cmd[1:3] == ["manifest", "add"]]
                self.assertEqual(len(additions), 2)
                self.assertTrue(all(cmd[-1].startswith("containers-storage:localhost/demo:ci-") for cmd in additions))
                self.assertEqual(len([cmd for cmd in calls if cmd[1] == "tag"]), 2)
                pushes = [cmd for cmd in calls if cmd[1:3] == ["manifest", "push"]]
                self.assertEqual(len(pushes), 4)
                self.assertTrue(all("--all" in cmd for cmd in pushes))

    def test_skipping_push_keeps_all_architectures_locally(self):
        for engine in ("docker", "podman"):
            with self.subTest(engine=engine):
                result, calls = self.run_engine(engine, "amd64,arm64", push=False)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertFalse(any("push" in cmd or "--push" in cmd for cmd in calls))
                if engine == "docker":
                    build = next(cmd for cmd in calls if cmd[1:3] == ["buildx", "build"])
                    self.assertIn("--output", build)
                    self.assertIn("type=oci,dest=", build[build.index("--output") + 1])
                    self.assertNotIn("--load", build)
                else:
                    self.assertIn("MANIFEST=localhost/demo:ci-", result.stdout)

    def test_global_skip_push_overrides_push_enabled_registries(self):
        for engine in ("docker", "podman"):
            result, calls = self.run_engine(engine, "amd64,arm64", global_skip=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertFalse(any("push" in cmd or "--push" in cmd for cmd in calls))

    def test_hummingbird_helpers_return_errors_without_exiting_the_caller(self):
        script = r'''
source "$REPO/build/lib/ci-core.sh"
source "$REPO/build/lib/ci-hummingbird.sh"
for fn in ci_hummingbird_worktree ci_hummingbird_context ci_hummingbird_variant_dir ci_hummingbird_python; do
    "$fn" >/dev/null 2>&1
    [[ $? -ne 0 ]] || exit 2
    printf 'survived %s\n' "$fn"
done
'''
        result = subprocess.run(["bash", "-uc", script], env={**os.environ, "REPO": str(REPO)}, text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout.count("survived"), 4)

    def test_build_failure_cannot_publish_a_partial_manifest(self):
        for engine in ("docker", "podman"):
            with self.subTest(engine=engine):
                result, calls = self.run_engine(engine, "amd64,arm64", fail="buildx build" if engine == "docker" else "build")
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(any(cmd[1] == "push" or cmd[1:3] in (["manifest", "create"], ["manifest", "push"]) for cmd in calls))

    def test_push_and_manifest_errors_are_fatal(self):
        for engine, platforms, failure in (("podman", "amd64,arm64", "tag"), ("podman", "amd64,arm64", "manifest push"),
                                            ("podman", "amd64,arm64", "manifest add"),
                                            ("podman", "amd64,arm64", "manifest create"),
                                            ("podman", "amd64", "push"), ("docker", "amd64", "push")):
            with self.subTest(engine=engine, failure=failure):
                result, _ = self.run_engine(engine, platforms, fail=failure)
                self.assertNotEqual(result.returncode, 0)

    def test_chunkah_is_serial_uncached_and_does_not_change_global_parallelism(self):
        result, calls = self.run_engine("podman", "amd64,arm64", chunkah=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        builds = [cmd for cmd in calls if cmd[1] == "build"]
        self.assertEqual(len(builds), 2)
        self.assertTrue(all("--no-cache" in cmd for cmd in builds))
        self.assertTrue(all(not any(arg.startswith("--jobs") for arg in cmd) for cmd in builds))
        self.assertIn("PARALLEL=true", result.stdout)
        result, calls = self.run_engine("docker", "amd64", chunkah=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("chunkah", result.stderr)
        self.assertFalse(any(cmd[1] == "build" for cmd in calls))

    def test_bad_platform_is_rejected_before_engine_calls(self):
        result, calls = self.run_engine("podman", "linux/arm65")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(calls)

    def test_base_registry_scan_ignores_paths_and_stages_and_preserves_ports(self):
        with tempfile.TemporaryDirectory() as tmp:
            file = Path(tmp) / "Containerfile"
            file.write_text("ARG NEWROOT=/new-root-fs\nARG BASE=localhost:5000/team/base:1\n"
                            "FROM ${BASE} AS hb_base\nFROM hb_base AS intermediate\n"
                            "FROM --platform=$TARGETPLATFORM quay.io/hummingbird-ci/builder:latest AS builder\n"
                            "FROM scratch\n")
            script = r'''
source "$REPO/build/lib/ci-core.sh"
source "$REPO/build/lib/ci-dockerfile.sh"
CONFIG[FROM_REGISTRY_9]=stale.example.com
parse_dockerfile_from_images "$FILE" >/dev/null
printf '%s\n' "${CONFIG[FROM_REGISTRY_0]:-}" "${CONFIG[FROM_REGISTRY_1]:-}"
[[ -z "${CONFIG[FROM_REGISTRY_2]:-}${CONFIG[FROM_REGISTRY_9]:-}" ]]
'''
            result = subprocess.run(["bash", "-uc", script], env={**os.environ, "REPO": str(REPO), "FILE": str(file)}, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(result.stdout.splitlines(), ["localhost:5000", "quay.io"])

    def test_explicit_foreign_single_arch_requests_emulation(self):
        script = r'''
source "$REPO/build/lib/ci-core.sh"
source "$REPO/build/lib/ci-build.sh"
CONFIG[PLATFORMS]=linux/arm64
INSTALL_BINFMT=false
uname() { echo x86_64; }
ci_setup_buildx
ci_get_required_binfmt_arches "${CONFIG[PLATFORMS]}"
'''
        result = subprocess.run(["bash", "-c", script], env={**os.environ, "REPO": str(REPO)}, text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout.strip().splitlines()[-1], "arm64")
        self.assertIn("arm64", result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
