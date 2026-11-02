#!/usr/bin/env python3
"""Require executed typed Linux native lifecycle verdicts and exact binary."""
from pathlib import Path
import importlib.util
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("linux_external_lifecycle_verdict", Path(__file__).with_name("test_linux_external_lifecycle.py"))
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)


def completed():
    prefix = "--- PASS: TestDesktopLinuxGuardianKernelExternalLifecycle"
    return [prefix + " (1.00s)", *(prefix + "/" + name + " (0.10s)" for name in RUNNER.CASES)]


class LinuxExternalLifecycleRunner(unittest.TestCase):
    def test_complete_actual_verdict_is_accepted(self):
        RUNNER.check_verdict("\n".join(completed()))

    def test_each_actual_boundary_is_required_once(self):
        rows = completed()
        for index in range(len(rows)):
            for changed in (rows[:index] + rows[index + 1:], rows + [rows[index]],
                            rows[:index] + ["test log: " + rows[index]] + rows[index + 1:]):
                with self.subTest(index=index, changed=changed), self.assertRaises(ValueError):
                    RUNNER.check_verdict("\n".join(changed))

    def test_failed_skipped_raced_and_empty_results_fail(self):
        for suffix in ("--- FAIL: exact owner (0.10s)", "--- SKIP: exact owner (0.10s)", "DATA RACE"):
            with self.subTest(suffix=suffix), self.assertRaises(ValueError):
                RUNNER.check_verdict("\n".join(completed()) + "\n" + suffix)
        with self.assertRaises(ValueError):
            RUNNER.check_verdict("")

    def test_only_original_digest_enters_namespace(self):
        binary, digest = Path("/captured/external-lifecycle.test"), "b" * 64
        with patch.object(RUNNER.GUARD, "namespace_test", return_value=23) as native:
            self.assertEqual(RUNNER.namespace_test(binary, digest), 23)
        native.assert_called_once_with(binary, "ExternalLifecycle", digest)


if __name__ == "__main__":
    unittest.main()
