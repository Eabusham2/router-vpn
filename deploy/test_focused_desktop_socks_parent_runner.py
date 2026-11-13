#!/usr/bin/env python3
"""Strict typed desktop parent receipts and read-only tooling; no Go execution."""
from __future__ import annotations
import importlib.util
import json
from pathlib import Path
import sys
import unittest
from unittest import mock
import tempfile

PATH = Path(__file__).resolve().with_name("test_focused_desktop_socks_parent.py")
spec = importlib.util.spec_from_file_location("desktop_socks_parent_gate", PATH)
assert spec and spec.loader
G = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = G
spec.loader.exec_module(G)


def encoded(case, *, omission=None, wrong_witness=None):
    G.CORE.PACKAGE = "router-vpn/" + G.package_for(case)
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


class DesktopSOCKSParentGateTests(unittest.TestCase):
    def test_exact_inventory(self):
        cases = G.cases()
        self.assertEqual([len(case.expected) for case in cases], [14, 42, 38, 26, 54, 8, 54, 34, 43, 36, 9, 2, 2, 29, 2, 9])
        self.assertEqual(len(cases[0].expected), len(set(cases[0].expected)))
        self.assertEqual(sum(len(c.expected) for c in cases if not c.mutation), 387)
        self.assertEqual(len([c for c in cases if c.mutation]), 4)
        for case in cases:
            result = G.verdict(encoded(case), case, 1 if case.mutation else 0)
            self.assertTrue(result["accepted"], result)

    def test_missing_original_or_new_leaf_is_rejected(self):
        for case in G.cases():
            for name in sorted(case.expected):
                result = G.verdict(encoded(case, omission=name), case, 1 if case.mutation else 0)
                self.assertFalse(result["accepted"], (case.name, name))

    def test_every_control_requires_its_original_leaf_witness(self):
        for case in (c for c in G.cases() if c.mutation):
            for name in case.witness_tests:
                result = G.verdict(encoded(case, wrong_witness=name), case, 1)
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
            self.assertFalse(G.verdict(raw + extra, case, 0)["accepted"], extra)
        self.assertFalse(G.verdict(raw.replace(G.CORE.PACKAGE.encode(), b"foreign/package", 1), case, 0)["accepted"])

    def test_late_and_missing_starts_are_refused(self):
        for case in G.cases():
            rows = encoded(case).splitlines()
            start, terminal = rows[0], rows[-1]
            code = 1 if case.mutation else 0
            for changed in (rows[1:], [terminal] + rows[:-1], rows + [start]):
                self.assertFalse(G.verdict(b"\n".join(changed), case, code)["accepted"])

    def test_signal_timeout_unjoined_and_wrong_exit_are_refused(self):
        for case in G.cases():
            code = 1 if case.mutation else 0
            raw = encoded(case)
            self.assertFalse(G.verdict(raw, case, code, True, True)["accepted"])
            self.assertFalse(G.verdict(raw, case, code, False, False)["accepted"])
            self.assertFalse(G.verdict(raw, case, -9)["accepted"])
            self.assertFalse(G.verdict(raw, case, 1-code)["accepted"])

    def test_original_commands_and_compiled_overlay_are_bounded(self):
        for case in G.cases():
            overlay = Path("/original/mutant.json") if case.mutation else None
            command = G.command_for("/pinned/go", case, overlay)
            self.assertEqual(command[-1], "./" + G.package_for(case))
            self.assertIn("-race", command)
            self.assertIn("-mod=readonly", command)
            self.assertIn("-timeout=120s", command)
            self.assertEqual(case.outer_seconds, 600)
            self.assertEqual("-overlay" in command, bool(case.mutation))
            if case.mutation:
                with self.assertRaises(ValueError):
                    G.command_for("/pinned/go", case)

    def test_controls_require_exact_original_guard(self):
        anchors = {
            "foreign-source-pointer": "return err == nil && original == c.socks.source",
            "generic-ready-kind": 'r.Schema != 1 || r.Kind != "routervpn-node-chain-socks-ready-v1" ||',
            "completed-auto-contention": G.MTU_CONTRACT["control"]["before"],
            "omitted-catalog-retirement": ("capture.seal != capture.digest() ||\n"
                "\t\t!original.profilesCurrent(control, profiles)\n"
                "if err != nil || !original.profilesCurrent(control, profiles) {"),
        }
        for case in (c for c in G.cases() if c.mutation):
            source = "// preserved prefix\n" + anchors[case.mutation] + "\n// preserved suffix\n"
            changed = G.mutation_source(case, source)
            self.assertNotEqual(changed, source)
            self.assertTrue(changed.startswith("// preserved prefix\n"))
            self.assertTrue(changed.endswith("// preserved suffix\n"))
            for wrong in ("", source + source):
                with self.assertRaises(ValueError):
                    G.mutation_source(case, wrong)

    def test_distinct_package_receipts_cannot_cross_satisfy_cases(self):
        for case in G.cases():
            raw = encoded(case)
            foreign = raw.replace(("router-vpn/" + G.package_for(case)).encode(), b"router-vpn/foreign")
            self.assertFalse(G.verdict(foreign, case, 1 if case.mutation else 0)["accepted"])

    def test_original_capture_cases_and_mutation_are_reused(self):
        current, original = G.cases(), G.CAPTURE.cases()
        self.assertEqual(current[4:6], original[:2])
        self.assertEqual(current[-1], original[2])
        self.assertEqual(G.MUTATION_PATHS["omitted-catalog-retirement"], G.CAPTURE.SOURCE)
        self.assertEqual(G.package_for(current[3]), "internal/mobilemultihop")
        self.assertEqual(G.package_for(current[9]), "internal/macosprocess")

    def test_readonly_format_patch_does_not_mutate_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, output = root/"source", root/"output"
            source.mkdir()
            output.mkdir()
            path = source/"original.go"
            path.write_text("package p\n")
            before = path.read_bytes()
            calls = []
            def execute(command, cwd, env, log, timeout):
                calls.append((command, cwd, timeout))
                log.write_text("diff original.go.orig original.go\n")
                return 0, False, True
            with mock.patch.object(G.CORE, "execute", side_effect=execute):
                receipt = G.formatting_report(root/"go", source, output,
                    {"changes": [{"path": "original.go"}, {"path": "readme.md"}]},
                    {"original.go": {}}, {})
            self.assertEqual(path.read_bytes(), before)
            self.assertEqual(calls, [([str(root/"go"/"bin"/"gofmt"), "-d", str(path)], source, 60)])
            self.assertTrue(receipt["has_diff"])
            self.assertFalse(receipt["candidate_mutated"])
            self.assertEqual(receipt["exit"], 0)
            self.assertNotIn("-w", calls[0][0])

    def test_formatter_failure_and_unjoined_receipts_are_not_forged(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for result in ((2, False, True), (-9, True, True), (0, False, False)):
                def execute(command, cwd, env, log, timeout):
                    log.write_text("original formatter diagnostic")
                    return result
                with mock.patch.object(G.CORE, "execute", side_effect=execute):
                    receipt = G.formatting_report(root/"go", root, root,
                        {"changes": [{"path": "original.go"}]}, {"original.go": {}}, {})
                self.assertEqual((receipt["exit"], receipt["timed_out"], receipt["process_group_joined"]), result)
            with self.assertRaises(ValueError):
                G.formatting_report(root, root, root, {"changes": []}, {}, {})

    def test_unknown_suite_and_unpaired_control_overlay_are_refused(self):
        with self.assertRaises(ValueError):
            G.cases("desktop-socks-capture")
        for case in G.cases():
            wrong = None if case.mutation else Path("/foreign/overlay.json")
            with self.assertRaises(ValueError):
                G.command_for("/pinned/go", case, wrong)


if __name__ == "__main__":
    unittest.main()
