#!/usr/bin/env python3
"""Check the exact privilege, isolation, joined-runner and verdict boundaries."""
from pathlib import Path
import importlib.util
import io
import subprocess
import unittest
from contextlib import redirect_stdout
from unittest.mock import Mock, patch

SPEC = importlib.util.spec_from_file_location("desktop_network_cohort_gate", Path(__file__).with_name("test_desktop_network_cohort.py"))
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)


def verdict():
    parent = "TestLinuxNativeNetworkCohortEvents"
    return "\n".join("--- PASS: " + name + " (0.01s)" for name in
                     [parent, *(parent + "/" + leaf for leaf in RUNNER.NATIVE_CASES)])


class NetworkNamespaceLauncher(unittest.TestCase):
    def setUp(self):
        self.binary = Path("/original-private-work/network-native.test")
        self.env = {"EXACT_COMPILER_ENV": "captured"}
        self.native = Mock()
        self.native.run.return_value = verdict()
        self.native.privilege_tool.return_value = "/usr/bin/sudo"
        self.platform = patch.object(RUNNER.sys, "platform", "linux")
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
             "--map-root-user", "--net", "--fork", str(self.binary), "-test.v", "-test.timeout=45s",
             "-test.run=^TestLinuxNativeNetworkCohortEvents$"],
            cwd=RUNNER.ROOT, env=self.env, timeout=60, sudo="/usr/bin/sudo")

    def test_actual_root_does_not_add_sudo(self):
        self.native.privilege_tool.return_value = None
        RUNNER.linux_namespace_test(self.binary, self.env)
        args, options = self.native.run.call_args
        self.assertEqual(args[0][0], "/usr/bin/env")
        self.assertNotIn("sudo", " ".join(args[0]))
        self.assertIsNone(options["sudo"])
        self.assertEqual(args[0][8], str(self.binary))

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


if __name__ == "__main__":
    unittest.main()
