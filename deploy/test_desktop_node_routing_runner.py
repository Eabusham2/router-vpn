#!/usr/bin/env python3
"""Check privileged routing execution retains its exact native fixture owner."""
from pathlib import Path
import contextlib
import hashlib
import importlib.util
import io
import os
import re
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


class HysteriaPhaseDispatch(unittest.TestCase):
    """Exercise the ordinary cached-image dispatch and its required verdicts.

    Only compiler/process outputs are modeled here. The real six encrypted
    peer groups remain mandatory in the native gate and use the same helper.
    """

    ROOTS = {
        "hysteria2-credentials": ("WrongCredential", "WrongWhitening"),
        "hysteria2-identity": ("LayerTLSIdentity", "ReferenceCapture"),
        "hysteria2-cover": ("LayerCover", "OuterCannotBypassFinal"),
    }
    LEAVES = {
        "WrongCredential": (
            "off/hysteria-password", "off/hysteria-trust", "off/hysteria-salamander",
            "aes-256-gcm/hysteria-password", "aes-256-gcm+xor-whitening/hysteria-password",
            "aes-256-gcm/aes-key", "aes-256-gcm+xor-whitening/aes-key",
            "aes-256-gcm/hysteria-trust", "aes-256-gcm+xor-whitening/hysteria-trust",
            "aes-256-gcm/hysteria-salamander", "aes-256-gcm+xor-whitening/hysteria-salamander"),
        "LayerTLSIdentity": tuple(layer + "/" + identity for layer in
                                  ("off", "aes-256-gcm", "aes-256-gcm+xor-whitening")
                                  for identity in ("ip-absent", "ip-empty", "ip-wrong-certificate")),
        "ReferenceCapture": ("unchanged", "ip-absent", "ip-empty", "wrong-ip", "unknown-identity",
                             "other-mode", "whitening", "wrong-layer", "wrong-mode"),
        "LayerCover": tuple(layer + "/" + fault for layer in ("aes-256-gcm", "aes-256-gcm+xor-whitening")
                            for fault in ("owned", "wrong-node", "drop-cover")),
        "OuterCannotBypassFinal": ("aes-256-gcm", "aes-256-gcm+xor-whitening"),
    }
    PREFIX = "TestRouterVPNDesktopNodeHysteria2"

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="node-hysteria-phases-")
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name)
        self.source = self.work / "source"
        self.source.mkdir()
        self.input = self.source / "captured.go"
        self.input.write_bytes(b"original shipping source")
        records = {"captured.go": hashlib.sha256(self.input.read_bytes()).hexdigest()}
        self.env = {"GOOS": "linux", "CGO_ENABLED": "1", "EXACT_COMPILER_ENV": "captured"}
        self.build = ["captured-go", "test", "-c", "-mod=readonly", "-race"]
        self.baselines = NODE.BaselineBinaries(self.source, self.work, self.build, self.env, records)
        self.compiles, self.invocations = [], []
        self.outputs = {}
        self.status = 0
        self.mutation = None
        for suite in NODE.HYSTERIA2_SUITES:
            names = self.ROOTS[suite[0]]
            required = [self.PREFIX + name for name in names]
            leaves = [self.PREFIX + name + "/" + leaf for name in names for leaf in self.LEAVES.get(name, ())]
            self.outputs[suite[2]] = "".join("--- PASS: " + name + " (0.01s)\n" for name in (*required, *leaves))
        self.quiet = contextlib.redirect_stdout(io.StringIO())
        self.quiet.__enter__()
        self.addCleanup(self.quiet.__exit__, None, None, None)
        runner = patch.object(NODE, "run", side_effect=self.observe_run)
        runner.start()
        self.addCleanup(runner.stop)

    def observe_run(self, command, *, cwd, env, timeout):
        self.assertEqual(cwd, self.source)
        self.assertEqual(env, self.env)
        if command[0] == "captured-go":
            self.assertEqual(command[:-3], self.build)
            self.assertEqual(command[-3], "-o")
            self.assertEqual(command[-1], "./protocol/routervpnamnezia")
            self.assertEqual(timeout, 600)
            self.compiles.append(command)
            Path(command[-2]).write_bytes(b"one captured encrypted peer test image")
            return 0, "compiled fixture boundary\n"
        self.assertEqual(command[2:], ["-test.count=1", "-test.timeout=90s", "-test.v"])
        self.assertEqual(timeout, 105)
        selector = command[1].removeprefix("-test.run=")
        self.assertIn(selector, self.outputs)
        self.invocations.append((tuple(command), timeout))
        if self.mutation is not None:
            self.mutation(Path(command[0]))
        return self.status, self.outputs[selector]

    def test_three_disjoint_phases_execute_the_original_six_roots_on_one_cached_image(self):
        all_roots = {self.PREFIX + root for roots in self.ROOTS.values() for root in roots}
        self.assertEqual(len(NODE.HYSTERIA2_SUITES), 3)
        admitted = []
        for suite in NODE.HYSTERIA2_SUITES:
            name, package, selector, required = suite
            self.assertEqual(package, "./protocol/routervpnamnezia")
            self.assertEqual(tuple(self.PREFIX + root for root in self.ROOTS[name]), required)
            self.assertTrue(selector.startswith("^") and selector.endswith("$"))
            selected = {root for root in all_roots if re.search(selector, root)}
            self.assertEqual(selected, set(required))
            self.assertFalse(any(re.search(selector, root + "Unselected") for root in all_roots))
            admitted.extend(selected)
            NODE.execute_baseline_suite(self.baselines, suite)
        self.assertCountEqual(admitted, all_roots)
        self.assertEqual(len(self.compiles), 1)
        self.assertEqual(len(self.invocations), 3)
        self.assertEqual(len({command[0] for command, _ in self.invocations}), 1)
        self.assertEqual([command[1] for command, _ in self.invocations],
                         ["-test.run=" + suite[2] for suite in NODE.HYSTERIA2_SUITES])

    def test_each_original_root_and_required_leaf_must_pass_in_its_own_phase(self):
        for suite in NODE.HYSTERIA2_SUITES:
            selector = suite[2]
            original = self.outputs[selector]
            for line in original.splitlines(keepends=True):
                with self.subTest(phase=suite[0], missing=line.strip()):
                    self.outputs[selector] = original.replace(line, "", 1)
                    with self.assertRaisesRegex(ValueError, "omitted"):
                        NODE.execute_baseline_suite(self.baselines, suite)
            self.outputs[selector] = original
        self.assertEqual(len(self.compiles), 1)

    def test_successful_text_cannot_hide_failed_process_skip_or_race(self):
        for suite in NODE.HYSTERIA2_SUITES:
            original = self.outputs[suite[2]]
            for status, trailer in ((1, ""), (0, "--- SKIP: hidden boundary\n"), (0, "WARNING: DATA RACE\n")):
                with self.subTest(phase=suite[0], status=status, trailer=trailer):
                    self.status = status
                    self.outputs[suite[2]] = original + trailer
                    with self.assertRaisesRegex(ValueError, "required native boundary"):
                        NODE.execute_baseline_suite(self.baselines, suite)
            self.status = 0
            self.outputs[suite[2]] = original

    def test_timeout_is_propagated_without_recompilation_or_another_phase(self):
        suite = NODE.HYSTERIA2_SUITES[0]
        def timeout(_):
            raise subprocess.TimeoutExpired("captured test image", 105)
        self.mutation = timeout
        with self.assertRaises(subprocess.TimeoutExpired):
            NODE.execute_baseline_suite(self.baselines, suite)
        self.assertEqual(len(self.compiles), 1)
        self.assertEqual(len(self.invocations), 1)

    def test_source_change_between_phases_prevents_cached_execution(self):
        NODE.execute_baseline_suite(self.baselines, NODE.HYSTERIA2_SUITES[0])
        self.input.write_bytes(b"replacement source")
        with self.assertRaisesRegex(ValueError, "captured source input"):
            NODE.execute_baseline_suite(self.baselines, NODE.HYSTERIA2_SUITES[1])
        self.assertEqual(len(self.compiles), 1)
        self.assertEqual(len(self.invocations), 1)

    def test_replaced_image_cannot_supply_a_phase_verdict(self):
        self.mutation = lambda binary: binary.write_bytes(b"replacement executable")
        with self.assertRaisesRegex(ValueError, "original compiled image"):
            NODE.execute_baseline_suite(self.baselines, NODE.HYSTERIA2_SUITES[0])
        self.assertEqual(len(self.compiles), 1)
        self.assertEqual(len(self.invocations), 1)


if __name__ == "__main__":
    unittest.main()
