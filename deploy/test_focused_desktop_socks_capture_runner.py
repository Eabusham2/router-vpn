#!/usr/bin/env python3
"""Strict receipts for the desktop typed SOCKS source gate, without Go execution."""
from __future__ import annotations
import importlib.util
import json
from pathlib import Path
import sys
import unittest

PATH = Path(__file__).resolve().with_name("test_focused_desktop_socks_capture.py")
spec = importlib.util.spec_from_file_location("desktop_socks_capture_gate", PATH)
assert spec and spec.loader
G = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = G
spec.loader.exec_module(G)


def encoded(case, *, omission=None, wrong_witness=None):
    rows = []
    action = "fail" if case.mutation else "pass"
    for name in sorted(case.expected):
        if name == omission:
            continue
        rows.append({"Action": "run", "Package": G.CORE.PACKAGE, "Test": name})
        if case.mutation and name in case.witness_tests:
            rows.append({"Action": "output", "Package": G.CORE.PACKAGE, "Test": name,
                         "Output": ("unrelated failure" if name == wrong_witness else case.witness) + "\n"})
        rows.append({"Action": action, "Package": G.CORE.PACKAGE, "Test": name})
    rows.append({"Action": action, "Package": G.CORE.PACKAGE})
    return b"".join(json.dumps(row).encode() + b"\n" for row in rows)


class DesktopSOCKSCaptureGateTests(unittest.TestCase):
    def test_exact_inventory(self):
        cases = G.cases()
        self.assertEqual([len(case.expected) for case in cases], [54, 8, 9, 3, 1])
        self.assertEqual(len(cases[0].expected), len(set(cases[0].expected)))
        self.assertEqual(G.CORE.PACKAGE, "router-vpn/cmd/client")
        for case in cases:
            result = G.CORE.verdict(encoded(case), case, 1 if case.mutation else 0)
            self.assertTrue(result["accepted"], result)

    def test_missing_original_or_new_leaf_is_rejected(self):
        for case in G.cases():
            for name in sorted(case.expected):
                result = G.CORE.verdict(encoded(case, omission=name), case, 1 if case.mutation else 0)
                self.assertFalse(result["accepted"], (case.name, name))

    def test_every_control_requires_its_original_leaf_witness(self):
        for case in G.cases()[2:]:
            for name in case.witness_tests:
                result = G.CORE.verdict(encoded(case, wrong_witness=name), case, 1)
                self.assertFalse(result["accepted"], name)

    def test_failed_build_panic_race_skip_foreign_and_duplicate_are_refused(self):
        case = G.cases()[0]
        raw = encoded(case)
        name = sorted(case.expected)[0]
        for extra in (b"panic: unrelated\n", b"fatal error: unrelated\n", b"WARNING: DATA RACE\n",
                      b"[build failed]\n",
                      json.dumps({"Action": "build-fail"}).encode() + b"\n",
                      json.dumps({"Action": "skip", "Package": G.CORE.PACKAGE, "Test": name}).encode() + b"\n",
                      json.dumps({"Action": "pass", "Package": G.CORE.PACKAGE, "Test": name}).encode() + b"\n"):
            self.assertFalse(G.CORE.verdict(raw + extra, case, 0)["accepted"], extra)
        self.assertFalse(G.CORE.verdict(raw.replace(G.CORE.PACKAGE.encode(), b"foreign/package", 1), case, 0)["accepted"])

    def test_late_and_missing_starts_are_refused(self):
        for case in G.cases():
            rows = encoded(case).splitlines()
            start, terminal = rows[0], rows[-1]
            code = 1 if case.mutation else 0
            for changed in (rows[1:], [terminal] + rows[:-1], rows + [start]):
                self.assertFalse(G.CORE.verdict(b"\n".join(changed), case, code)["accepted"])

    def test_signal_timeout_unjoined_and_wrong_exit_are_refused(self):
        for case in G.cases():
            code = 1 if case.mutation else 0
            raw = encoded(case)
            self.assertFalse(G.CORE.verdict(raw, case, code, True, True)["accepted"])
            self.assertFalse(G.CORE.verdict(raw, case, code, False, False)["accepted"])
            self.assertFalse(G.CORE.verdict(raw, case, -9)["accepted"])
            self.assertFalse(G.CORE.verdict(raw, case, 1-code)["accepted"])

    def test_original_commands_and_compiled_overlay_are_bounded(self):
        for case in G.cases():
            overlay = Path("/original/mutant.json") if case.mutation else None
            command = G.command_for("/pinned/go", case, overlay)
            self.assertEqual(command[-1], "./cmd/client")
            self.assertIn("-race", command)
            self.assertIn("-mod=readonly", command)
            self.assertIn("-timeout=120s", command)
            self.assertEqual(case.outer_seconds, 600)
            self.assertEqual("-overlay" in command, bool(case.mutation))
            if case.mutation:
                with self.assertRaises(ValueError):
                    G.command_for("/pinned/go", case)

    def test_catalog_and_asset_controls_need_exact_original_guards(self):
        source = "capture.seal != capture.digest() ||\n\t\t!original.profilesCurrent(control, profiles)\n"
        source += "if err != nil || !original.profilesCurrent(control, profiles) {\n"
        source += "\t\tif !matches {\n"
        source += "\t\tif err := mobilemtu.LockContext(ctx, &a.mu); err != nil {\n"
        source += "\t\t\treturn common.RouterProfile{}, nil, err\n\t\t}\n"
        for case in G.cases()[2:]:
            changed = G.mutation_source(case, source)
            self.assertNotEqual(source, changed)
            for wrong in ("", source + source):
                with self.assertRaises(ValueError):
                    G.mutation_source(case, wrong)


if __name__ == "__main__":
    unittest.main()
