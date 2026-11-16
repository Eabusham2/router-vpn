#!/usr/bin/env python3
"""Python/process controls for the exact-source macOS profile gate."""
from pathlib import Path
import contextlib
import hashlib
import importlib.util
import io
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

PATH = Path(__file__).resolve().with_name("validate-macos-profile-source.py")
spec = importlib.util.spec_from_file_location("routervpn_focused_macos_profiles", PATH)
if spec is None or spec.loader is None:
    raise RuntimeError("macOS profile validator is missing")
D = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = D
spec.loader.exec_module(D)


def complete(controls=None, positive=None, summary=None):
    controls = D.CONTROL_NAMES if controls is None else controls
    positive = "Actual AppKit profiles, deferred catalogs and Settings Add/Load/Update callbacks: 123 checks PASS" if positive is None else positive
    summary = f"AppKit capture, refresh ownership, relink and post-response idle negatives: {len(D.CONTROL_NAMES)} rejected" if summary is None else summary
    return ("\n".join([positive, *("PASS causal AppKit " + name for name in controls), summary]) + "\n").encode()


class MacProfileGateTests(unittest.TestCase):
    def test_exact_original_and_new_control_order_is_required(self):
        self.assertEqual(len(D.CONTROL_NAMES), 75)
        self.assertEqual(len(set(D.CONTROL_NAMES)), 75)
        self.assertEqual(D.CONTROL_NAMES[19], "ordered-locked-source-preconditions")
        self.assertEqual(D.CONTROL_NAMES[20:22], ("ordered-execution-capture", "ordered-execution-connect"))
        self.assertEqual(D.CONTROL_NAMES[22:30], (
            "ordered-final-draft", "ordered-final-snapshot", "ordered-final-apply", "ordered-final-widget",
            "ordered-final-layer", "ordered-imported-final", "ordered-imported-choice", "ordered-loaded-final"))
        self.assertEqual(D.CONTROL_NAMES[30], "setup-source-preconditions")
        self.assertEqual(D.CONTROL_NAMES[38], "setup-stale-body")
        self.assertEqual(D.CONTROL_NAMES[39:43], (
            "ordered-socks-protocol", "ordered-socks-draft-mode",
            "ordered-socks-capability", "ordered-socks-final"))
        self.assertEqual(D.CONTROL_NAMES[43:45], ("ordered-connect-protocol", "ordered-connect-draft-mode"))
        self.assertEqual(D.CONTROL_NAMES[45:56], (
            "imported-execution-old-trio", "imported-execution-later-prefix-layer",
            "imported-execution-later-prefix-kind", "imported-execution-layer",
            "imported-execution-layers-disabled", "imported-execution-entry-layer",
            "imported-execution-final-layer", "imported-execution-boolean",
            "imported-execution-live-capability", "imported-execution-draft", "imported-execution-body"))
        self.assertEqual(D.CONTROL_NAMES[56:61], (
            "connect-execution-prefix-layer", "connect-execution-old-trio",
            "connect-execution-final-layer", "connect-execution-boolean", "connect-execution-capability"))
        self.assertEqual(D.CONTROL_NAMES[61:70], (
            "socks-execution-old-trio", "socks-execution-final-layer",
            "socks-execution-capability", "socks-execution-boolean", "socks-execution-layer",
            "socks-execution-entry-layer", "socks-execution-protocol", "socks-execution-draft",
            "socks-execution-body"))
        self.assertEqual(D.CONTROL_NAMES[70:], ("hostname-execution-minimum", "hostname-execution-boolean", "hostname-execution-conflict", "socks-execution-final-layer-required", "connect-execution-final-layer-required"))
        self.assertTrue(D.verdict(complete(), 0, False, True)["accepted"])

    def test_inventory_matches_actual_prepared_swift_programs_without_execution(self):
        # Run the original source/variant preparation, with both compiler and
        # program calls intercepted. These are synthetic inventory observations,
        # never Swift execution or native acceptance evidence.
        source = PATH.resolve().parents[1] / D.SCRIPT
        spec = importlib.util.spec_from_file_location("mac_profile_source_inventory", source)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        fixture = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(fixture)
        compiled, executed = {}, []

        def capture(command, **options):
            command = [str(value) for value in command]
            if command[0] == "swiftc":
                self.assertEqual(command[1:3], ["-swift-version", "6"])
                self.assertEqual(command[-2], "-o")
                original, binary = Path(command[-3]), Path(command[-1])
                self.assertEqual(original.parent, workspace)
                self.assertEqual(binary.parent, workspace)
                self.assertEqual(original.name, binary.name + ".swift")
                self.assertNotIn(binary.name, compiled)
                self.assertFalse(options)
                compiled[binary.name] = hashlib.sha256(original.read_bytes()).hexdigest()
            else:
                self.assertEqual(len(command), 1)
                name = Path(command[0]).name
                self.assertIn(name, compiled)
                self.assertIs(options["negative"], name != "shipping")
                executed.append(name)

        with tempfile.TemporaryDirectory(prefix="mac-profile-source-inventory-") as directory:
            workspace = Path(directory).resolve()
            blocked = AssertionError("source inventory must not compile or execute native programs")
            with contextlib.redirect_stdout(io.StringIO()), patch.object(fixture, "run", side_effect=capture), \
                    patch.object(fixture.subprocess, "run", side_effect=blocked), \
                    patch.object(fixture.subprocess, "Popen", side_effect=blocked):
                fixture.macos(workspace)
        self.assertEqual(tuple(executed), ("shipping",) + D.CONTROL_NAMES)
        self.assertEqual(tuple(compiled), tuple(executed))
        self.assertEqual(len(compiled), 76)
        for name in D.CONTROL_NAMES:
            self.assertNotEqual(compiled[name], compiled["shipping"], name)

    def test_each_missing_original_or_new_control_is_refused(self):
        for index, name in enumerate(D.CONTROL_NAMES):
            with self.subTest(control=name):
                rows = D.CONTROL_NAMES[:index] + D.CONTROL_NAMES[index+1:]
                self.assertFalse(D.verdict(complete(rows), 0, False, True)["accepted"])

    def test_duplicate_foreign_and_out_of_order_controls_are_refused(self):
        cases = (D.CONTROL_NAMES + D.CONTROL_NAMES[:1],
                 D.CONTROL_NAMES[:-1] + ("unrelated",), tuple(reversed(D.CONTROL_NAMES)))
        for rows in cases:
            with self.subTest(rows=rows):
                self.assertFalse(D.verdict(complete(rows), 0, False, True)["accepted"])

    def test_positive_and_complete_summary_must_each_occur_once(self):
        valid = complete()
        for data in (valid + valid.splitlines()[0] + b"\n", valid + valid.splitlines()[-1] + b"\n",
                     complete(positive=""), complete(summary=""),
                     complete(positive="Actual AppKit profiles, deferred catalogs and Settings Add/Load/Update callbacks: 0 checks PASS"),
                     complete(summary="AppKit capture, refresh ownership, relink and post-response idle negatives: 29 rejected"),
                     complete(D.CONTROL_NAMES[:20] + D.CONTROL_NAMES[22:43], summary="AppKit capture, refresh ownership, relink and post-response idle negatives: 41 rejected"),
                     complete(D.CONTROL_NAMES[:37], summary="AppKit capture, refresh ownership, relink and post-response idle negatives: 37 rejected")):
            with self.subTest(data=data[:80]):
                self.assertFalse(D.verdict(data, 0, False, True)["accepted"])

    def test_failed_timeout_signal_and_unjoined_children_are_not_accepted(self):
        for code, timeout, joined in ((1, False, True), (-9, False, True), (0, True, True), (0, False, False)):
            with self.subTest(code=code, timeout=timeout, joined=joined):
                self.assertFalse(D.verdict(complete(), code, timeout, joined)["accepted"])

    def test_prefixed_or_suffixed_markers_and_invalid_encoding_are_refused(self):
        for raw in (b"prefix " + complete(), complete().replace(b" checks PASS\n", b" checks PASS suffix\n", 1)):
            self.assertFalse(D.verdict(raw, 0, False, True)["accepted"])
        with self.assertRaises(UnicodeDecodeError):
            D.verdict(complete() + b"\xff", 0, False, True)

    def test_original_process_executor_and_original_source_contract_are_reused(self):
        self.assertEqual(D.SCRIPT, "deploy/test_desktop_connection_profile_modes.py")
        self.assertEqual(D.SOURCE_PATH, "client/macos/RouterVPNConnectionProfiles.swift")
        self.assertEqual(D.OUTER_SECONDS, 1800)
        self.assertEqual(D.CORE_PATH.name, "test_focused_multihop_clocks.py")
        with tempfile.TemporaryDirectory(prefix="mac-profile-process-control-") as directory:
            root = Path(directory)
            command = [sys.executable, "-c", "import sys;sys.stdout.buffer.write(" + repr(complete()) + ")"]
            code, timed_out, joined = D.CORE.execute(command, root, dict(os.environ), root/"positive.log", 10)
            self.assertTrue(D.verdict((root/"positive.log").read_bytes(), code, timed_out, joined)["accepted"])
            command[-1] += ";sys.exit(4)"
            code, timed_out, joined = D.CORE.execute(command, root, dict(os.environ), root/"failed.log", 10)
            self.assertFalse(D.verdict((root/"failed.log").read_bytes(), code, timed_out, joined)["accepted"])
            self.assertEqual(code, 4)
            self.assertTrue(joined)


if __name__ == "__main__":
    unittest.main(verbosity=2)
