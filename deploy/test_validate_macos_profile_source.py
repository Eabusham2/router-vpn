#!/usr/bin/env python3
"""Python/process controls for the exact-source macOS profile gate."""
from pathlib import Path
import importlib.util
import os
import sys
import tempfile
import unittest

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
    summary = "AppKit capture, refresh ownership, relink and post-response idle negatives: 41 rejected" if summary is None else summary
    return ("\n".join([positive, *("PASS causal AppKit " + name for name in controls), summary]) + "\n").encode()


class MacProfileGateTests(unittest.TestCase):
    def test_exact_original_and_new_control_order_is_required(self):
        self.assertEqual(len(D.CONTROL_NAMES), 41)
        self.assertEqual(len(set(D.CONTROL_NAMES)), 41)
        self.assertEqual(D.CONTROL_NAMES[19], "ordered-locked-source-preconditions")
        self.assertEqual(D.CONTROL_NAMES[20:28], (
            "ordered-final-draft", "ordered-final-snapshot", "ordered-final-apply", "ordered-final-widget",
            "ordered-final-layer", "ordered-imported-final", "ordered-imported-choice", "ordered-loaded-final"))
        self.assertEqual(D.CONTROL_NAMES[28], "setup-source-preconditions")
        self.assertEqual(D.CONTROL_NAMES[36], "setup-stale-body")
        self.assertEqual(D.CONTROL_NAMES[37:], (
            "ordered-socks-protocol", "ordered-socks-draft-mode",
            "ordered-socks-capability", "ordered-socks-final"))
        self.assertTrue(D.verdict(complete(), 0, False, True)["accepted"])

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
