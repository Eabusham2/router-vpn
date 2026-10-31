#!/usr/bin/env python3
"""Keep every original native transaction verdict and image identity mandatory."""
from pathlib import Path
import importlib.util
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("linux_transaction_runner", Path(__file__).with_name("test_linux_node_transaction.py"))
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)


def completed():
    prefix = "--- PASS: TestDesktopLinuxGuardianKernelNodeTransaction"
    return [prefix + " (1.00s)", *(prefix + "/" + name + " (0.10s)" for name in RUNNER.CASES)]


class LinuxNodeTransactionRunner(unittest.TestCase):
    def test_complete_actual_verdict_is_accepted(self):
        RUNNER.check_verdict("\n".join(completed()))

    def test_every_actual_boundary_is_required(self):
        rows = completed()
        for missing in range(len(rows)):
            with self.subTest(missing=rows[missing]), self.assertRaises(ValueError):
                RUNNER.check_verdict("\n".join(rows[:missing] + rows[missing + 1:]))

    def test_skipped_failed_and_empty_results_fail(self):
        for result in ("", "\n".join(completed()) + "\n--- SKIP: missing native dependency (0.10s)",
                       "\n".join(completed()) + "\n--- FAIL: actual child (0.10s)"):
            with self.subTest(result=result[-80:]), self.assertRaises(ValueError):
                RUNNER.check_verdict(result)

    def test_only_captured_image_digest_enters_namespace(self):
        path = Path("/captured/native-transaction.test")
        digest = "c" * 64
        with patch.object(RUNNER.GUARD, "namespace_test", return_value=17) as native:
            self.assertEqual(RUNNER.namespace_test(path, digest), 17)
        native.assert_called_once_with(path, "NodeTransaction", digest)


if __name__ == "__main__":
    unittest.main()
