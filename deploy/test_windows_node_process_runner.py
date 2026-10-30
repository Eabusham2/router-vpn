#!/usr/bin/env python3
"""Reject missing source and false native-process gate acknowledgments."""
from pathlib import Path
import importlib.util
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "windows_node_process_runner_gate", ROOT / "deploy/test_windows_node_process.py")
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)


class NodeProcessRunner(unittest.TestCase):
    def test_complete_source_closure_includes_actual_adapter_and_embedded_command(self):
        records = GATE.sources()
        self.assertTrue(set(GATE.REQUIRED_SOURCES).issubset(records))
        self.assertIn("cmd/client/ui.html", records)
        self.assertIn("cmd/client/logical_ui.js", records)

    def test_missing_or_linked_native_adapter_cannot_reuse_a_source_receipt(self):
        with tempfile.TemporaryDirectory(prefix="node-process-source-") as directory:
            root = Path(directory)
            for relative in GATE.REQUIRED_SOURCES:
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(b"captured source\n")
            missing = root / "cmd/client/desktop_node_process_windows_native_test.go"
            with patch.object(GATE, "ROOT", root):
                GATE.sources()
                missing.unlink()
                with self.assertRaisesRegex(ValueError, "actual regular source"):
                    GATE.sources()
                missing.symlink_to(root / "cmd/client/desktop_node_process_test.go")
                with self.assertRaisesRegex(ValueError, "actual regular source"):
                    GATE.sources()

    def test_baseline_requires_every_native_shared_and_command_case(self):
        output = "\n".join("--- PASS: " + name + " (0.01s)" for name in GATE.EXPECTED)
        GATE.check_baseline(0, output)
        for name in GATE.EXPECTED:
            with self.subTest(missing=name):
                with self.assertRaisesRegex(ValueError, "every required ownership case"):
                    GATE.check_baseline(0, output.replace("--- PASS: " + name + " (", "--- PASS: omitted ("))
        for status, suffix in ((1, ""), (0, "\n--- SKIP: hidden (0.00s)"),
                               (0, "\nWARNING: DATA RACE"), (0, "\npanic: test timed out"),
                               (0, "\n--- FAIL: actual (0.01s)")):
            with self.subTest(status=status, suffix=suffix):
                with self.assertRaisesRegex(ValueError, "every required ownership case"):
                    GATE.check_baseline(status, output + suffix)

    def test_negative_requires_its_actual_failure_and_specific_witness(self):
        for _, name, test, witness, _ in GATE.mutants():
            output = "--- FAIL: " + test + " (0.01s)\n    source_test.go:1: " + witness + "\n"
            with self.subTest(name=name):
                GATE.check_rejection(name, test, witness, 1, output)
                for status, wrong in ((0, output), (1, output.replace(witness, "another error")),
                                      (1, output.replace(test, "AnotherTest")),
                                      (1, output + "panic: test timed out"),
                                      (1, output + "WARNING: DATA RACE"),
                                      (1, output + "--- SKIP: other (0.00s)"),
                                      (1, output + "[build failed]")):
                    with self.assertRaisesRegex(ValueError, "intended boundary"):
                        GATE.check_rejection(name, test, witness, status, wrong)

    def test_mutations_are_exact_production_changes_and_leave_the_source_unchanged(self):
        originals = {name: (ROOT / name).read_bytes() for name in
                     ("cmd/client/desktop_node_process.go", "cmd/client/desktop_node_journal.go", "cmd/client/desktop_node_journal_release.go", "cmd/client/private_store_replace_windows.go",
                      "cmd/client/desktop_node_journal_off.go", "cmd/client/desktop_node_protection_off.go", "cmd/client/profile_protection_owned.go")}
        changes = GATE.mutants()
        self.assertEqual(len(changes), 14)
        self.assertEqual(len({change[1] for change in changes}), 14)
        for filename, _, test, witness, replacement in changes:
            self.assertIn(filename, originals)
            self.assertNotEqual(replacement.encode(), originals[filename])
            self.assertTrue(test.split("/")[0] in GATE.REQUIRED)
            self.assertTrue(witness)
        for filename, original in originals.items():
            self.assertEqual((ROOT / filename).read_bytes(), original)

    def test_other_host_cannot_report_native_windows_execution(self):
        with patch.object(GATE.platform, "system", return_value="Linux"):
            with self.assertRaisesRegex(ValueError, "actual Windows execution"):
                GATE.execute()


if __name__ == "__main__":
    unittest.main()
