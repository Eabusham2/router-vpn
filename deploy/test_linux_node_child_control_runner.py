#!/usr/bin/env python3
"""Require every generated Linux child verdict and the original image digest."""
from pathlib import Path
import importlib.util
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("linux_child_verdict", Path(__file__).with_name("test_linux_node_child_control.py"))
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)


def completed():
    prefix = "--- PASS: TestDesktopLinuxGuardianKernelNodeChildControl"
    return [prefix + " (1.00s)", *(prefix + "/" + name + " (0.10s)" for name in RUNNER.CASES)]


class LinuxNodeChildControlRunner(unittest.TestCase):
    def test_complete_actual_verdict_is_accepted(self):
        self.assertEqual(len(RUNNER.CASES), 22)
        self.assertEqual(sum(case.startswith("imported/") for case in RUNNER.CASES), 11)
        RUNNER.check_verdict("\n".join(completed()))

    def test_every_original_boundary_is_required(self):
        rows = completed()
        for missing in range(len(rows)):
            with self.subTest(missing=rows[missing]), self.assertRaises(ValueError):
                RUNNER.check_verdict("\n".join(rows[:missing] + rows[missing + 1:]))

    def test_failed_skipped_and_empty_results_fail(self):
        for output in ("", "\n".join(completed()) + "\n--- SKIP: actual source (0.10s)",
                       "\n".join(completed()) + "\n--- FAIL: original child (0.10s)"):
            with self.subTest(output=output[-80:]), self.assertRaises(ValueError):
                RUNNER.check_verdict(output)

    def test_only_original_digest_enters_namespace(self):
        binary, digest = Path("/captured/native-child.test"), "b" * 64
        with patch.object(RUNNER.GUARD, "namespace_test", return_value=23) as native:
            self.assertEqual(RUNNER.namespace_test(binary, digest), 23)
        native.assert_called_once_with(binary, "NodeChildControl", digest)


if __name__ == "__main__":
    unittest.main()
