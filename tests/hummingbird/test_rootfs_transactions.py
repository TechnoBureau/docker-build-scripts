#!/usr/bin/env python3
"""Transaction-private mount lifetimes for RPM installroot scriptlets.

Recording tools model namespace entry/exit, faults and RPM's /proc requirement.
Separate Linux tests use real mounts and native processes, including a runner
that refuses proc/sys unmounts. They do not emulate Rosetta or execute RPM.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[2]
HELPER = REPO / "build/lib/hummingbird/rootfs.sh"
MOUNT_PATHS = ("proc", "sys", "dev", "run", "tmp", "var/tmp")

COMMAND_STUB = r'''#!/usr/bin/env python3
import json, os, pathlib, signal, subprocess, sys
command = pathlib.Path(sys.argv[0]).name
args = sys.argv[1:]
root = pathlib.Path(os.environ["TEST_ROOTFS"])
state_file = pathlib.Path(os.environ["TEST_MOUNTS"])
state = json.loads(state_file.read_text())
with open(os.environ["TEST_EVENTS"], "a") as out:
    out.write(json.dumps([command, *args]) + "\n")
if command == "readlink":
    if args == ["/proc/self/ns/mnt"]:
        print("mnt:[101]" if os.environ.get("TEST_PRIVATE_NAMESPACE") == "1" else "mnt:[100]")
        sys.exit(0)
    os.execv(os.environ["TEST_REAL_READLINK"], ["readlink", *args])
if command == "unshare":
    if os.environ.get("TEST_UNSHARE_DENIED"):
        print("unshare: unshare failed: Operation not permitted", file=sys.stderr)
        sys.exit(1)
    if os.environ.get("TEST_FAIL_PRIVATE"):
        print("unshare: failed to set mount propagation: Operation not permitted", file=sys.stderr)
        sys.exit(1)
    if args[:3] != ["--mount", "--propagation", "private"]:
        sys.exit(98)
    process = None
    interrupted = 0
    def on_signal(signum, frame):
        global interrupted
        interrupted = signum
        if process is not None:
            try:
                process.send_signal(signum)
            except ProcessLookupError:
                pass
    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(signum, on_signal)
    env = {**os.environ, "TEST_PRIVATE_NAMESPACE": "0" if os.environ.get("TEST_UNSHARE_NOOP") else "1"}
    try:
        process = subprocess.Popen(args[3:], env=env)
        status = process.wait()
    finally:
        # Model kernel-owned namespace lifetime, not explicit umount commands.
        # File writes remain; only the worker's fake runtime views disappear.
        if not os.environ.get("TEST_NAMESPACE_LEAK"):
            if str(root / "proc") not in state and (root / "proc/self/exe").exists():
                (root / "proc/self/exe").unlink()
                (root / "proc/self").rmdir()
            state_file.write_text(json.dumps(state))
    sys.exit(128 + interrupted if interrupted else (128 - status if status < 0 else status))
if command == "mountpoint":
    sys.exit(0 if args[-1] in state else 1)
if command == "mount":
    target = pathlib.Path(args[-1])
    relative = str(target.relative_to(root))
    if os.environ.get("TEST_FAIL_MOUNT") == relative:
        print("mount: permission denied", file=sys.stderr)
        sys.exit(22)
    state[str(target)] = args
    if relative == "proc":
        (target / "self").mkdir(exist_ok=True)
        (target / "self/exe").write_bytes(b"\x7fELF")
    state_file.write_text(json.dumps(state))
    sys.exit(0)
if command == "umount":
    # A correct private-namespace implementation never needs this operation.
    print("umount: Operation not permitted", file=sys.stderr)
    sys.exit(32)
if command in ("dnf", "rpm"):
    if not (root / "proc/self/exe").is_file():
        print("rosetta error: Unable to open /proc/self/exe: 2", file=sys.stderr)
        sys.exit(95)
    required = {str(root / path) for path in ("proc", "sys", "dev", "run", "tmp", "var/tmp")}
    if not required.issubset(state):
        print("RPM runtime mounts missing", file=sys.stderr)
        sys.exit(96)
    if os.environ.get("TEST_SIGNAL"):
        os.kill(os.getppid(), int(os.environ["TEST_SIGNAL"]))
    status = int(os.environ.get("TEST_RPM_STATUS", "0"))
    if not status:
        (root / "installed-package").write_text("transaction output")
    sys.exit(status)
sys.exit(99)
'''


class RootfsTransactionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.work = Path(self.tmp.name)
        self.root = self.work / "new-root-fs"
        self.root.mkdir()
        self.bin = self.work / "bin"
        self.bin.mkdir()
        self.state = self.work / "mounts.json"
        self.state.write_text("{}")
        self.events = self.work / "events.jsonl"
        for command in ("unshare", "readlink", "mount", "umount", "mountpoint", "dnf", "rpm"):
            file = self.bin / command
            file.write_text(COMMAND_STUB)
            file.chmod(0o755)
        self.env = {**os.environ, "PATH": f"{self.bin}:{os.environ['PATH']}",
                    "TEST_ROOTFS": str(self.root), "TEST_MOUNTS": str(self.state),
                    "TEST_EVENTS": str(self.events), "TEST_REAL_READLINK": shutil.which("readlink")}

    def tearDown(self):
        self.tmp.cleanup()

    def run_transaction(self, command="dnf", **overrides):
        args = (["-y", "--releasever=9", f"--installroot={self.root}", "install", "glibc", "crypto-policies-scripts"]
                if command == "dnf" else ["--root", str(self.root), "-e", "example-package"])
        return subprocess.run(["bash", str(HELPER), "exec", str(self.root), command, *args],
                              env={**self.env, **overrides}, text=True, capture_output=True, timeout=10)

    def calls(self, command=None):
        calls = [json.loads(line) for line in self.events.read_text().splitlines()] if self.events.exists() else []
        return [call for call in calls if command is None or call[0] == command]

    def assert_unmounted(self):
        self.assertEqual(json.loads(self.state.read_text()), {})
        self.assertFalse((self.root / "proc/self/exe").exists())
        self.assertFalse(self.calls("umount"), "namespace teardown must not depend on umount permission")

    def test_transaction_supplies_proc_to_scriptlets_without_resetting_seed(self):
        bare = subprocess.run([str(self.bin / "dnf"), f"--installroot={self.root}", "install", "glibc"],
                              env=self.env, text=True, capture_output=True)
        self.assertEqual(bare.returncode, 95)
        self.assertIn("Unable to open /proc/self/exe", bare.stderr)
        (self.root / "base-content").write_text("preserve me")
        result = self.run_transaction()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual((self.root / "base-content").read_text(), "preserve me")
        self.assertTrue((self.root / "installed-package").exists())
        self.assert_unmounted()
        self.assertEqual([call[-1] for call in self.calls("mount")], [str(self.root / p) for p in MOUNT_PATHS])
        namespace = self.calls("unshare")[0]
        self.assertEqual(namespace[1:4], ["--mount", "--propagation", "private"])
        self.assertNotIn("--pid", namespace)
        self.assertNotIn("--user", namespace)
        transaction = self.calls("dnf")[-1]
        self.assertIn("--releasever=9", transaction)
        self.assertIn(f"--installroot={self.root}", transaction)
        self.assertFalse(any("noscripts" in arg or "nopost" in arg for arg in transaction))

    def test_rpm_failure_status_survives_namespace_teardown(self):
        result = self.run_transaction(TEST_RPM_STATUS="17")
        self.assertEqual(result.returncode, 17, result.stdout + result.stderr)
        self.assert_unmounted()
        self.assertEqual(len(self.calls("dnf")), 1, "never retry failed transactions outside the namespace")

    def test_removal_scriptlets_get_the_same_mount_environment(self):
        result = self.run_transaction(command="rpm")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.calls("rpm")[0][1:], ["--root", str(self.root), "-e", "example-package"])
        self.assert_unmounted()

    def test_partial_mount_failure_is_scoped_to_the_worker_and_never_runs_dnf(self):
        result = self.run_transaction(TEST_FAIL_MOUNT="dev")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("SYS_ADMIN", result.stderr)
        self.assertFalse(self.calls("dnf"))
        self.assert_unmounted()

    def test_mount_propagation_failure_does_not_start_the_worker(self):
        result = self.run_transaction(TEST_FAIL_PRIVATE="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("propagation", result.stderr)
        self.assertFalse(self.calls("mount"))
        self.assertFalse(self.calls("dnf"))
        self.assert_unmounted()

    def test_namespace_creation_failure_is_not_retried_in_the_caller(self):
        result = self.run_transaction(TEST_UNSHARE_DENIED="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unshare failed: Operation not permitted", result.stderr)
        self.assertEqual(len(self.calls("unshare")), 1)
        self.assertFalse(self.calls("mount"))
        self.assertFalse(self.calls("dnf"))
        self.assert_unmounted()

    def test_worker_rejects_a_noop_unshare(self):
        result = self.run_transaction(TEST_UNSHARE_NOOP="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("distinct private mount namespace", result.stderr)
        self.assertFalse(self.calls("mount"))
        self.assertFalse(self.calls("dnf"))
        self.assert_unmounted()

    def test_mounts_visible_in_the_caller_cannot_produce_a_successful_layer(self):
        result = self.run_transaction(TEST_NAMESPACE_LEAK="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("after private transaction", result.stderr)
        self.assertFalse(self.calls("umount"), "do not modify unexpected caller mounts")

    def test_caller_mount_check_does_not_mask_original_rpm_failure(self):
        result = self.run_transaction(TEST_RPM_STATUS="19", TEST_NAMESPACE_LEAK="1")
        self.assertEqual(result.returncode, 19)
        self.assertIn("after private transaction", result.stderr)

    def test_term_interrupt_preserves_signal_status(self):
        result = self.run_transaction(TEST_SIGNAL="15")
        self.assertEqual(result.returncode, 143, result.stdout + result.stderr)
        self.assert_unmounted()

    def test_preexisting_mounts_and_symlink_targets_are_not_modified(self):
        (self.root / "proc").mkdir()
        self.state.write_text(json.dumps({str(self.root / "proc"): ["existing"]}))
        result = self.run_transaction()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.calls("dnf"))
        self.assertFalse(self.calls("umount"))
        self.assertFalse(self.calls("mount"))
        self.assertFalse(self.calls("unshare"))
        self.state.write_text("{}")
        (self.root / "proc").rmdir()
        (self.root / "proc").symlink_to(self.work)
        result = self.run_transaction()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.calls("mount"))


class RootfsMountNamespaceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if sys.platform != "linux" or not shutil.which("unshare"):
            raise unittest.SkipTest("real mount probe needs Linux unshare")
        cls.namespace = ["unshare", "--user", "--map-root-user", "--mount", "--fork", "--propagation", "private"]
        available = subprocess.run([*cls.namespace, "true"], capture_output=True, text=True, timeout=10)
        if available.returncode:
            raise unittest.SkipTest("runner forbids unprivileged user/mount namespaces")

    def test_private_transaction_does_not_depend_on_proc_sys_umount_permission(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            root = work / "new-root-fs"
            root.mkdir()
            binaries = work / "bin"
            binaries.mkdir()
            # Model a runner that permits mounting but refuses both recursive
            # and lazy unmount of proc/sys. Other mounts use the real kernel.
            shim = binaries / "umount"
            shim.write_text("""#!/usr/bin/env bash
printf '%s\\n' "$*" >> "$UMOUNT_EVENTS"
case "${!#}" in
    */proc|*/sys) echo 'umount: Operation not permitted' >&2; exit 32 ;;
    *) exec "$REAL_UMOUNT" "$@" ;;
esac
""")
            shim.chmod(0o755)
            events = work / "umount.events"
            script = r'''
set -eu
bash "$HELPER" exec "$ROOTFS" sh -c 'test -r "$1/proc/self/exe"; printf installed > "$1/payload"' sh "$ROOTFS"
for directory in proc sys dev run tmp var/tmp; do
    if mountpoint -q "$ROOTFS/$directory"; then exit 97; fi
done
mountpoint -q /proc
mountpoint -q /sys
'''
            env = {**os.environ, "PATH": f"{binaries}:{os.environ['PATH']}", "ROOTFS": str(root),
                   "HELPER": str(HELPER), "UMOUNT_EVENTS": str(events), "REAL_UMOUNT": shutil.which("umount")}
            result = subprocess.run([*self.namespace, "bash", "-c", script], env=env, capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual((root / "payload").read_text(), "installed")
            self.assertFalse(events.exists(), "private namespace teardown must not depend on umount")

    def test_real_chroot_can_open_proc_self_exe_only_during_transaction(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "new-root-fs"
            root.mkdir()
            probe = Path(tmp) / "probe.py"
            probe.write_text('''import os, signal, sys
os.chroot(sys.argv[1])
os.chdir("/")
try:
    with open("/proc/self/exe", "rb") as file:
        assert file.read(4) == b"\\x7fELF"
    with open("/dev/null", "wb") as file:
        file.write(b"probe")
    assert os.readlink("/proc/self/ns/mnt") != os.environ["PARENT_MNT_NS"]
    assert os.readlink("/proc/self/ns/pid") == os.environ["PARENT_PID_NS"]
    assert os.readlink("/proc/self/ns/user") == os.environ["PARENT_USER_NS"]
except FileNotFoundError:
    sys.exit(95)
if len(sys.argv) > 2 and sys.argv[2] == "143":
    os.kill(os.getpid(), signal.SIGTERM)
sys.exit(int(sys.argv[2]) if len(sys.argv) > 2 else 0)
''')
            script = r'''
set -eu
# The worker must change ONLY the mount namespace, not user/PID namespaces.
export PARENT_MNT_NS="$(readlink /proc/self/ns/mnt)"
export PARENT_PID_NS="$(readlink /proc/self/ns/pid)"
export PARENT_USER_NS="$(readlink /proc/self/ns/user)"
# Before mount setup, this native process sees the same missing proc path.
status=0
"$PYTHON" "$PROBE" "$ROOTFS" || status=$?
[ "$status" -eq 95 ]
for expected in 0 17 143; do
    status=0
    bash "$HELPER" exec "$ROOTFS" "$PYTHON" "$PROBE" "$ROOTFS" "$expected" || status=$?
    [ "$status" -eq "$expected" ]
    for directory in proc sys dev run tmp var/tmp; do
        if mountpoint -q "$ROOTFS/$directory"; then exit 97; fi
    done
done
# Cleanup must not unmount the namespace's source filesystems.
mountpoint -q /proc
mountpoint -q /dev
'''
            env = {**os.environ, "ROOTFS": str(root), "HELPER": str(HELPER), "PYTHON": sys.executable, "PROBE": str(probe)}
            result = subprocess.run([*self.namespace, "bash", "-c", script], env=env, capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(list((root / "proc").iterdir()), [])
            self.assertEqual(list((root / "dev").iterdir()), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
