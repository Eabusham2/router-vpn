#!/usr/bin/env python3
"""Check privileged routing execution retains its exact native fixture owner."""
from pathlib import Path
import contextlib
import hashlib
import importlib.util
import io
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("desktop_node_routing_gate", ROOT / "deploy/test_desktop_node_physical.py")
NODE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(NODE)


class RoutingNamespaceLauncher(unittest.TestCase):
    def setUp(self):
        self.binary = Path("/private-owned-work/routing.test")
        self.source = Path("/original-source")
        self.env = {"GOOS": "linux", "EXACT_COMPILER_ENV": "captured",
                    "ROUTERVPN_NATIVE_ROUTING_RECEIPT_CHILD": "1",
                    "ROUTERVPN_ROUTING_PARENT_NET": "foreign-network",
                    "ROUTERVPN_ROUTING_PARENT_USER": "foreign-user"}
        self.native = Mock()
        self.native.privilege_tool.return_value = "/usr/bin/sudo"
        self.native.run.return_value = "actual native fixture output\n"
        self.system = patch.object(NODE.platform, "system", return_value="Linux")
        self.loader = patch.object(NODE, "namespace_runner", return_value=self.native)
        self.system.start()
        self.loader.start()
        self.addCleanup(self.loader.stop)
        self.addCleanup(self.system.stop)

    def invoke(self):
        return NODE.linux_routing_receipt_test(self.binary, cwd=self.source, env=self.env, duration=90)

    def test_only_exact_compiled_fixture_uses_trusted_privilege_and_join_owner(self):
        original = dict(self.env)
        self.assertEqual(self.invoke(), (0, "actual native fixture output\n"))
        self.native.privilege_tool.assert_called_once_with()
        self.native.run.assert_called_once_with(
            ["/usr/bin/sudo", "-n", "--", str(self.binary),
             "-test.run=^TestRouterVPNNativeLinuxRouting", "-test.count=1", "-test.timeout=90s", "-test.v"],
            cwd=self.source, env={"GOOS": "linux", "EXACT_COMPILER_ENV": "captured"}, timeout=105, sudo="/usr/bin/sudo")
        self.assertEqual(self.env, original)

    def test_root_keeps_the_same_fixture_and_owned_timeout_without_sudo(self):
        self.native.privilege_tool.return_value = None
        self.invoke()
        args, options = self.native.run.call_args
        self.assertEqual(args[0][0], str(self.binary))
        self.assertIsNone(options["sudo"])
        self.assertEqual(options["timeout"], 105)

    def test_missing_trusted_privilege_fails_before_execution(self):
        self.native.privilege_tool.side_effect = ValueError("no trusted native privilege")
        with self.assertRaisesRegex(ValueError, "trusted native privilege"):
            self.invoke()
        self.native.run.assert_not_called()

    def test_unavailable_namespace_keeps_failure_and_never_runs_unisolated(self):
        for output in (b"unshare: uid_map denied\n", "unshare: uid_map denied\n", None):
            with self.subTest(output=output):
                self.native.run.reset_mock()
                self.native.run.side_effect = subprocess.CalledProcessError(7, ["unshare"], output=output)
                self.assertEqual(self.invoke(), (7, "" if output is None else "unshare: uid_map denied\n"))
                self.native.run.assert_called_once()

    def test_timeout_join_failure_never_becomes_a_verdict_or_retry(self):
        self.native.run.side_effect = RuntimeError("owned group could not be joined")
        with self.assertRaisesRegex(RuntimeError, "could not be joined"):
            self.invoke()
        self.native.run.assert_called_once()

    def test_other_hosts_or_cross_targets_cannot_launch_the_linux_fixture(self):
        for system, target in (("Windows", "linux"), ("Darwin", "linux"), ("Linux", "windows"), ("Linux", None)):
            with self.subTest(system=system, target=target), patch.object(NODE.platform, "system", return_value=system):
                self.env["GOOS"] = target
                with self.assertRaisesRegex(ValueError, "native Linux"):
                    self.invoke()
        self.native.privilege_tool.assert_not_called()
        self.native.run.assert_not_called()


class BaselineRoutingDispatch(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="node-routing-runner-")
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name)
        self.source = self.work / "source"
        self.source.mkdir()
        self.binary = self.work / "original.test"
        self.binary.write_bytes(b"original compiled image")
        self.package = "github.com/sagernet/sing-tun"
        self.env = {"GOOS": "linux"}
        self.baselines = NODE.BaselineBinaries(self.source, self.work, ["captured-go", "test", "-c"], self.env, {})
        self.baselines.binaries[self.package] = self.binary, NODE.retained_binary(self.binary)
        self.quiet = contextlib.redirect_stdout(io.StringIO())
        self.quiet.__enter__()
        self.addCleanup(self.quiet.__exit__, None, None, None)

    def test_original_named_suite_uses_namespace_runner_and_preserves_receipt(self):
        with patch.object(NODE, "linux_routing_receipt_test", return_value=(0, "native pass")) as native, \
             patch.object(NODE, "run", return_value=(0, "native pass")) as ordinary:
            self.assertEqual(self.baselines.execute("native-routing-receipt", self.package,
                             "^TestRouterVPNNativeLinuxRouting", 90), (0, "native pass"))
        native.assert_called_once_with(self.binary, cwd=self.source, env=self.env, duration=90)
        ordinary.assert_not_called()

    def test_unrelated_suites_keep_ordinary_execution(self):
        with patch.object(NODE, "linux_routing_receipt_test") as native, \
             patch.object(NODE, "run", return_value=(0, "ordinary pass")) as ordinary:
            self.assertEqual(self.baselines.execute("unrelated", self.package, "^OtherCase$", 12), (0, "ordinary pass"))
        native.assert_not_called()
        ordinary.assert_called_once_with([self.binary, "-test.run=^OtherCase$", "-test.count=1", "-test.timeout=12s", "-test.v"],
                                         cwd=self.source, env=self.env, timeout=27)

    def test_changed_package_or_selector_cannot_gain_routing_privilege(self):
        for package, selector in (("./unrelated", "^TestRouterVPNNativeLinuxRouting"),
                                  (self.package, ".*"), (self.package, "^TestRouterVPNNativeLinuxRouting|OtherCase")):
            with self.subTest(package=package, selector=selector), \
                 patch.object(self.baselines, "binary") as compile_image, \
                 patch.object(NODE, "linux_routing_receipt_test") as native:
                with self.assertRaisesRegex(ValueError, "another package or selector"):
                    self.baselines.execute("native-routing-receipt", package, selector, 90)
                compile_image.assert_not_called()
                native.assert_not_called()

    def test_privileged_execution_cannot_replace_its_original_compiled_image(self):
        def replacement(*args, **kwargs):
            self.binary.write_bytes(b"replaced compiled image")
            return 0, "native pass"
        with patch.object(NODE, "linux_routing_receipt_test", side_effect=replacement), \
             self.assertRaisesRegex(ValueError, "original compiled image"):
            self.baselines.execute("native-routing-receipt", self.package, "^TestRouterVPNNativeLinuxRouting", 90)

    def test_namespace_runner_and_its_checks_remain_captured_source_inputs(self):
        deploy = self.work / "deploy"
        deploy.mkdir()
        for key, name in (("namespace-launcher", "test_desktop_socket_uid.py"),
                          ("routing-runner", "test_desktop_node_routing_runner.py")):
            with self.subTest(key=key), patch.object(NODE, "ROOT", self.work):
                path = deploy / name
                path.write_bytes(b"original owned runner")
                self.baselines.records = {key: hashlib.sha256(path.read_bytes()).hexdigest()}
                self.baselines.check_inputs()
                path.write_bytes(b"different runner")
                with self.assertRaisesRegex(ValueError, "captured source input"):
                    self.baselines.check_inputs()


if __name__ == "__main__":
    unittest.main()
