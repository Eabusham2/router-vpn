#!/usr/bin/env python3
"""Check the exact privilege, isolation, joined-runner and verdict boundaries."""
from pathlib import Path
import importlib.util
import io
import stat
import subprocess
import sys
import tempfile
import types
import unittest
from contextlib import contextmanager, redirect_stdout
from unittest.mock import Mock, patch

SPEC = importlib.util.spec_from_file_location("desktop_network_cohort_gate", Path(__file__).with_name("test_desktop_network_cohort.py"))
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)


def verdict():
    parent = "TestLinuxNativeNetworkCohortEvents"
    return "\n".join("--- PASS: " + name + " (0.01s)" for name in
                     [parent, *(parent + "/" + leaf for leaf in RUNNER.NATIVE_CASES)])


class RoutingRetirementVerdicts(unittest.TestCase):
    def test_exact_observation_caller_and_failure_cases(self):
        for platform in ("linux", "darwin", "win32"):
            names = []
            for parent, leaves in RUNNER.OBSERVATION_CONTEXT_CASES.items():
                if parent == "TestNetworkNativeObservationHeldMutex":
                    leaves = ("snapshot",) if platform == "win32" else ("barrier",)
                names.extend((parent, *(parent + "/" + leaf for leaf in leaves)))
            output = "\n".join("--- PASS: " + name + " (0.01s)" for name in names)
            RUNNER.check_observation_context_verdict(output, platform)
            for line in output.splitlines():
                for mutation in (output.replace(line, "", 1), output + "\n" + line,
                                 output.replace(line, line.replace("PASS", "SKIP"), 1),
                                 output.replace(line, line.replace("PASS", "FAIL"), 1)):
                    with self.assertRaises(ValueError):
                        RUNNER.check_observation_context_verdict(mutation, platform)

    def test_exact_original_and_foreign_retirement_cases(self):
        parent="TestLinuxRoutingRetirementRequiresOriginalJoinedInventory"
        output="\n".join("--- PASS: "+name+" (0.01s)" for name in (parent,*(parent+"/"+leaf for leaf in RUNNER.ROUTING_RETIREMENT_CASES)))
        RUNNER.check_routing_retirement_verdict(output)
        for line in output.splitlines():
            for mutation in (output.replace(line,"",1),output+"\n"+line,output.replace(line,line.replace("PASS","SKIP"),1),output.replace(line,line.replace("PASS","FAIL"),1)):
                with self.assertRaises(ValueError):RUNNER.check_routing_retirement_verdict(mutation)


class NetworkNamespaceLauncher(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="network-private-source-")
        self.addCleanup(self.temporary.cleanup)
        self.work = Path(self.temporary.name)
        self.binary = self.work / "network-native.test"
        self.binary.write_bytes(b"exact compiled network fixture")
        self.binary.chmod(0o755)
        self.staged = []
        self.env = {"EXACT_COMPILER_ENV": "captured"}
        self.native = Mock()
        self.native.run.return_value = verdict()
        self.native.privilege_tool.return_value = "/usr/bin/sudo"

        def observe(command, **options):
            offset = 3 if options["sudo"] is not None else 0
            image = Path(command[offset + 8])
            self.staged.append(image)
            self.assertNotEqual(image, self.binary)
            self.assertEqual(image.read_bytes(), self.binary.read_bytes())
            self.assertEqual(stat.S_IMODE(image.stat().st_mode), 0o555)
            self.assertEqual(stat.S_IMODE(image.parent.stat().st_mode), 0o711)
            self.assertEqual(stat.S_IMODE(self.work.stat().st_mode), 0o700)
            return self.native.run.return_value

        self.native.run.side_effect = observe
        self.platform = patch.object(RUNNER, "sys", types.SimpleNamespace(platform="linux"))
        self.identity = patch.object(RUNNER.os, "readlink", return_value="net:[987654]")
        self.loader = patch.object(RUNNER, "namespace_runner", return_value=self.native)
        self.platform.start()
        self.identity.start()
        self.loader.start()
        self.addCleanup(self.loader.stop)
        self.addCleanup(self.identity.stop)
        self.addCleanup(self.platform.stop)

    def test_only_exact_namespace_binary_uses_available_sudo_and_join_owner(self):
        self.assertEqual(RUNNER.linux_namespace_test(self.binary, self.env), verdict())
        self.native.privilege_tool.assert_called_once_with()
        self.native.run.assert_called_once_with(
            ["/usr/bin/sudo", "-n", "--", "/usr/bin/env", "ROUTERVPN_NATIVE_NETWORK_EVENTS=1",
             "ROUTERVPN_NETWORK_PARENT_NAMESPACE=net:[987654]", "/usr/bin/unshare", "--user",
             "--map-root-user", "--net", "--fork", str(self.staged[0]), "-test.v", "-test.timeout=45s",
             "-test.run=^TestLinuxNativeNetworkCohortEvents$"],
            cwd=RUNNER.ROOT, env=self.env, timeout=60, sudo="/usr/bin/sudo")
        self.assertFalse(self.staged[0].parent.exists())
        self.assertTrue(self.binary.exists())

    def test_actual_root_does_not_add_sudo(self):
        self.native.privilege_tool.return_value = None
        RUNNER.linux_namespace_test(self.binary, self.env)
        args, options = self.native.run.call_args
        self.assertEqual(args[0][0], "/usr/bin/env")
        self.assertNotIn("sudo", " ".join(args[0]))
        self.assertIsNone(options["sudo"])
        self.assertEqual(args[0][8], str(self.staged[0]))
        self.assertFalse(self.staged[0].parent.exists())

    def test_missing_trusted_privilege_fails_before_execution(self):
        self.native.privilege_tool.side_effect = ValueError("no trusted native privilege")
        with self.assertRaisesRegex(ValueError, "trusted native privilege"):
            RUNNER.linux_namespace_test(self.binary, self.env)
        self.native.run.assert_not_called()

    def test_unavailable_namespace_is_reported_and_never_retried_unisolated(self):
        self.native.run.side_effect = subprocess.CalledProcessError(1, ["unshare"], b"uid_map denied\n")
        output = io.StringIO()
        with redirect_stdout(output), self.assertRaisesRegex(RuntimeError, "isolated native network fixture failed"):
            RUNNER.linux_namespace_test(self.binary, self.env)
        self.assertEqual(output.getvalue(), "uid_map denied\n")
        self.native.run.assert_called_once()

    def test_timeout_join_failure_is_not_converted_to_a_verdict_or_retried(self):
        self.native.run.side_effect = RuntimeError("owned group could not be joined")
        with self.assertRaisesRegex(RuntimeError, "could not be joined"):
            RUNNER.linux_namespace_test(self.binary, self.env)
        self.native.run.assert_called_once()

    def test_each_parent_and_native_case_must_actually_pass(self):
        lines = verdict().splitlines()
        for index in range(len(lines)):
            with self.subTest(missing=lines[index]):
                self.native.run.return_value = "\n".join(lines[:index] + lines[index + 1:])
                with self.assertRaisesRegex(RuntimeError, "omitted its executed case"):
                    RUNNER.linux_namespace_test(self.binary, self.env)

    def test_failed_and_skipped_output_remains_failed(self):
        for marker in ("--- FAIL:", "--- SKIP:"):
            with self.subTest(marker=marker):
                self.native.run.return_value = verdict() + "\n" + marker + " original fixture (0.01s)"
                with self.assertRaisesRegex(RuntimeError, "failed or skipped"):
                    RUNNER.linux_namespace_test(self.binary, self.env)

    def test_other_hosts_cannot_launch_linux_mutation_case(self):
        with patch.object(RUNNER.sys, "platform", "win32"), self.assertRaisesRegex(RuntimeError, "native Linux"):
            RUNNER.linux_namespace_test(self.binary, self.env)
        self.native.privilege_tool.assert_not_called()
        self.native.run.assert_not_called()

    def test_changed_staged_image_cannot_turn_native_pass_into_success(self):
        def replace_bytes(command, **options):
            offset = 3 if options["sudo"] is not None else 0
            staged = Path(command[offset + 8])
            self.staged.append(staged)
            staged.chmod(0o755)
            staged.write_bytes(b"different executable returned fabricated PASS records")
            staged.chmod(0o555)
            return verdict()

        self.native.run.side_effect = replace_bytes
        with self.assertRaisesRegex(ValueError, "staged image"):
            RUNNER.linux_namespace_test(self.binary, self.env)
        self.native.run.assert_called_once()
        self.assertFalse(self.staged[0].parent.exists())
        self.assertEqual(stat.S_IMODE(self.work.stat().st_mode), 0o700)

    def test_linked_or_non_executable_input_is_rejected_before_namespace(self):
        original = self.binary.with_name("original.test")
        self.binary.rename(original)
        self.binary.symlink_to(original)
        with self.assertRaisesRegex(ValueError, "owned regular"):
            RUNNER.linux_namespace_test(self.binary, self.env)
        self.binary.unlink()
        original.rename(self.binary)
        self.binary.chmod(0o600)
        with self.assertRaisesRegex(ValueError, "owned executable"):
            RUNNER.linux_namespace_test(self.binary, self.env)
        self.native.run.assert_not_called()


class PortableNetworkNamespaceDispatch(unittest.TestCase):
    """Exercise launcher composition without pretending this host has Linux DAC.

    The retained executable's real inode/UID/mode and mutation controls remain
    in NetworkNamespaceLauncher, executed on native Linux below. This boundary
    double represents only that independently tested context manager; no
    privilege, namespace or native network operation is performed here.
    """

    def setUp(self):
        self.original = Path("original-network.test")
        self.staged = Path("retained-network.test")
        self.env = {"EXACT_COMPILER_ENV": "captured"}
        self.native = Mock()
        self.native.privilege_tool.return_value = "/usr/bin/sudo"
        self.native.run.return_value = verdict()
        self.entered = self.retired = 0
        self.retirement_error = None

        @contextmanager
        def image(binary):
            self.assertEqual(binary, self.original)
            self.entered += 1
            try:
                yield self.staged
            finally:
                self.retired += 1
                if self.retirement_error is not None:
                    raise self.retirement_error

        for replacement in (
            patch.object(RUNNER, "sys", types.SimpleNamespace(platform="linux")),
            patch.object(RUNNER.os, "readlink", return_value="net:[987654]"),
            patch.object(RUNNER, "namespace_runner", return_value=self.native),
            patch.object(RUNNER, "namespace_fixture_image", side_effect=image),
        ):
            replacement.start()
            self.addCleanup(replacement.stop)

    def invoke(self):
        return RUNNER.linux_namespace_test(self.original, self.env)

    def test_exact_captured_image_and_environment_reach_only_the_owned_runner(self):
        for sudo in ("/usr/bin/sudo", None):
            with self.subTest(sudo=sudo):
                self.native.reset_mock()
                self.native.privilege_tool.return_value = sudo
                self.assertEqual(self.invoke(), verdict())
                command = ["/usr/bin/env", "ROUTERVPN_NATIVE_NETWORK_EVENTS=1",
                           "ROUTERVPN_NETWORK_PARENT_NAMESPACE=net:[987654]", "/usr/bin/unshare",
                           "--user", "--map-root-user", "--net", "--fork", str(self.staged),
                           "-test.v", "-test.timeout=45s", "-test.run=^TestLinuxNativeNetworkCohortEvents$"]
                if sudo is not None:
                    command = [sudo, "-n", "--", *command]
                self.native.run.assert_called_once_with(command, cwd=RUNNER.ROOT,
                    env=self.env, timeout=60, sudo=sudo)
                self.assertEqual(self.entered, self.retired)

    def test_native_host_guard_precedes_privilege_or_image_access(self):
        for host in ("win32", "darwin", "freebsd"):
            with self.subTest(host=host), patch.object(RUNNER, "sys", types.SimpleNamespace(platform=host)), \
                 self.assertRaisesRegex(RuntimeError, "native Linux"):
                self.invoke()
        self.native.privilege_tool.assert_not_called()
        self.native.run.assert_not_called()
        self.assertEqual(self.entered, 0)

    def test_privilege_and_image_failures_precede_native_execution(self):
        self.native.privilege_tool.side_effect = ValueError("untrusted privilege")
        with self.assertRaisesRegex(ValueError, "untrusted privilege"):
            self.invoke()
        self.assertEqual(self.entered, 0)
        self.native.privilege_tool.side_effect = None
        with patch.object(RUNNER, "namespace_fixture_image", side_effect=ValueError("original image changed")), \
             self.assertRaisesRegex(ValueError, "original image changed"):
            self.invoke()
        self.native.run.assert_not_called()

    def test_run_failure_timeout_and_image_retirement_failure_remain_failures(self):
        for error, message in ((subprocess.CalledProcessError(7, ["unshare"], b"namespace denied"),
                                "isolated native network fixture failed"),
                               (RuntimeError("owned group did not join"), "did not join")):
            with self.subTest(error=type(error).__name__):
                self.native.run.reset_mock(side_effect=True)
                self.native.run.side_effect = error
                with redirect_stdout(io.StringIO()), self.assertRaisesRegex(RuntimeError, message):
                    self.invoke()
                self.native.run.assert_called_once()
                self.assertEqual(self.entered, self.retired)
        self.native.run.reset_mock(side_effect=True)
        self.retirement_error = ValueError("staged image changed after execution")
        with self.assertRaisesRegex(ValueError, "staged image changed"):
            self.invoke()
        self.native.run.assert_called_once()
        self.assertEqual(self.entered, self.retired)

    def test_missing_failed_or_skipped_native_verdict_never_passes(self):
        lines = verdict().splitlines()
        for index in range(len(lines)):
            with self.subTest(missing=lines[index]):
                self.native.run.return_value = "\n".join(lines[:index] + lines[index + 1:])
                with self.assertRaisesRegex(RuntimeError, "omitted its executed case"):
                    self.invoke()
        for marker in ("--- FAIL:", "--- SKIP:"):
            with self.subTest(marker=marker):
                self.native.run.return_value = verdict() + "\n" + marker + " native case (0.01s)"
                with self.assertRaisesRegex(RuntimeError, "failed or skipped"):
                    self.invoke()
        self.assertEqual(self.entered, self.retired)


def load_tests(loader, _standard_tests, _pattern):
    suite = loader.loadTestsFromTestCase(PortableNetworkNamespaceDispatch)
    suite.addTests(loader.loadTestsFromTestCase(RoutingRetirementVerdicts))
    # Linux ownership/mode tests require real Linux filesystem semantics. A
    # mocked sys.platform must not run POSIX geteuid/chmod checks on Windows or
    # replace its native retained-handle/creation-time identity semantics.
    if sys.platform == "linux":
        suite.addTests(loader.loadTestsFromTestCase(NetworkNamespaceLauncher))
    return suite


if __name__ == "__main__":
    unittest.main(verbosity=2)
