#!/usr/bin/env python3
"""Check privileged routing execution retains its exact native fixture owner."""
from pathlib import Path
import contextlib
import hashlib
import importlib.util
import io
import os
import stat
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
        self.temporary = tempfile.TemporaryDirectory(prefix="node-routing-private-")
        self.addCleanup(self.temporary.cleanup)
        self.work = Path(self.temporary.name)
        self.binary = self.work / "original.test"
        self.binary.write_bytes(b"exact compiled routing fixture")
        self.binary.chmod(0o755)
        self.staged = []
        self.source = Path("/original-source")
        self.env = {"GOOS": "linux", "EXACT_COMPILER_ENV": "captured",
                    "ROUTERVPN_NATIVE_ROUTING_RECEIPT_CHILD": "1",
                    "ROUTERVPN_ROUTING_PARENT_NET": "foreign-network",
                    "ROUTERVPN_ROUTING_PARENT_USER": "foreign-user"}
        self.native = Mock()
        self.native.privilege_tool.return_value = "/usr/bin/sudo"
        self.native.run.return_value = "actual native fixture output\n"

        def observe(command, **options):
            offset = 3 if options["sudo"] is not None else 0
            image = Path(command[offset])
            self.staged.append(image)
            self.assertNotEqual(image, self.binary)
            self.assertEqual(image.read_bytes(), self.binary.read_bytes())
            self.assertEqual(stat.S_IMODE(image.stat().st_mode), 0o555)
            self.assertEqual(stat.S_IMODE(image.parent.stat().st_mode), 0o711)
            self.assertEqual(stat.S_IMODE(self.work.stat().st_mode), 0o700)
            return self.native.run.return_value

        self.native.run.side_effect = observe
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
            ["/usr/bin/sudo", "-n", "--", str(self.staged[0]),
             "-test.run=^TestRouterVPNNativeLinuxRouting", "-test.count=1", "-test.timeout=90s", "-test.v"],
            cwd=self.source, env={"GOOS": "linux", "EXACT_COMPILER_ENV": "captured"}, timeout=105, sudo="/usr/bin/sudo")
        self.assertEqual(self.env, original)
        self.assertFalse(self.staged[0].parent.exists())
        self.assertTrue(self.binary.exists())

    def test_root_keeps_the_same_fixture_and_owned_timeout_without_sudo(self):
        self.native.privilege_tool.return_value = None
        self.invoke()
        args, options = self.native.run.call_args
        self.assertEqual(args[0][0], str(self.staged[0]))
        self.assertFalse(self.staged[0].parent.exists())
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


class RoutingFixtureImage(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="node-routing-source-")
        self.addCleanup(self.temporary.cleanup)
        self.work = Path(self.temporary.name)
        self.image = self.work / "original.test"
        self.image.write_bytes(b"exact compiled native fixture")
        self.image.chmod(0o755)

    def test_stages_only_the_exact_read_execute_image_and_preserves_private_source(self):
        original = NODE.retained_binary(self.image)
        with NODE.routing_fixture_image(self.image) as staged:
            self.assertEqual(staged.parent.parent, Path("/tmp"))
            self.assertNotEqual(staged.parent, self.work)
            self.assertEqual(list(staged.parent.iterdir()), [staged])
            self.assertEqual(staged.read_bytes(), self.image.read_bytes())
            self.assertNotEqual(staged.stat().st_ino, self.image.stat().st_ino)
            self.assertEqual(staged.stat().st_uid, os.geteuid())
            self.assertEqual(stat.S_IMODE(staged.stat().st_mode), 0o555)
            self.assertEqual(stat.S_IMODE(staged.parent.stat().st_mode), 0o711)
            self.assertEqual(stat.S_IMODE(self.work.stat().st_mode), 0o700)
        self.assertFalse(staged.parent.exists())
        self.assertEqual(NODE.retained_binary(self.image), original)
        self.assertEqual(stat.S_IMODE(self.work.stat().st_mode), 0o700)

    def test_execution_failure_and_cancellation_remove_only_owned_staging(self):
        for error in (subprocess.CalledProcessError(7, ["owned fixture"]), RuntimeError("joined timeout")):
            with self.subTest(error=type(error).__name__):
                with self.assertRaises(type(error)):
                    with NODE.routing_fixture_image(self.image) as staged:
                        raise error
                self.assertFalse(staged.parent.exists())
                self.assertTrue(self.image.exists())

    def test_changed_staged_image_identity_bytes_or_permissions_cannot_pass(self):
        for change in ("replacement", "contents", "permissions", "symlink"):
            with self.subTest(change=change):
                with self.assertRaisesRegex(ValueError, "staged image|owned regular"):
                    with NODE.routing_fixture_image(self.image) as staged:
                        if change == "replacement":
                            other = staged.with_name("replacement.test")
                            other.write_bytes(staged.read_bytes())
                            other.chmod(0o555)
                            other.replace(staged)
                        elif change == "contents":
                            staged.chmod(0o755)
                            staged.write_bytes(b"changed compiled fixture")
                            staged.chmod(0o555)
                        elif change == "permissions":
                            staged.chmod(0o777)
                        else:
                            staged.unlink()
                            staged.symlink_to(self.image)
                self.assertFalse(staged.parent.exists())
                self.assertTrue(self.image.exists())

    def test_changed_original_image_cannot_pass_and_keeps_private_directory(self):
        with self.assertRaisesRegex(ValueError, "source image changed"):
            with NODE.routing_fixture_image(self.image) as staged:
                self.image.write_bytes(b"replacement source fixture")
        self.assertFalse(staged.parent.exists())
        self.assertEqual(stat.S_IMODE(self.work.stat().st_mode), 0o700)

    def test_corrupted_copy_never_reaches_execution(self):
        def corrupt(source, target):
            target.write(b"different compiled fixture")
        entered = False
        with patch.object(NODE.shutil, "copyfileobj", side_effect=corrupt), \
             self.assertRaisesRegex(ValueError, "staged image"):
            with NODE.routing_fixture_image(self.image):
                entered = True
        self.assertFalse(entered)

    def test_symlink_hardlink_foreign_owner_and_writable_source_are_rejected(self):
        self.image.chmod(0o777)
        with self.assertRaisesRegex(ValueError, "owned executable"):
            with NODE.routing_fixture_image(self.image):
                self.fail("unsafe source executed")
        self.image.chmod(0o755)
        alias = self.work / "symlink.test"
        alias.symlink_to(self.image)
        with self.assertRaisesRegex(ValueError, "owned regular"):
            with NODE.routing_fixture_image(alias):
                self.fail("symlink source executed")
        alias.unlink()
        os.link(self.image, alias)
        with self.assertRaisesRegex(ValueError, "owned regular"):
            with NODE.routing_fixture_image(self.image):
                self.fail("hardlink source executed")
        alias.unlink()
        with patch.object(NODE.os, "geteuid", return_value=self.image.stat().st_uid + 1), \
             self.assertRaisesRegex(ValueError, "owned executable"):
            with NODE.routing_fixture_image(self.image):
                self.fail("foreign source executed")

    def test_staging_directory_permissions_are_part_of_retained_identity(self):
        with self.assertRaisesRegex(ValueError, "staging directory"):
            with NODE.routing_fixture_image(self.image) as staged:
                staged.parent.chmod(0o777)
        self.assertFalse(staged.parent.exists())


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
