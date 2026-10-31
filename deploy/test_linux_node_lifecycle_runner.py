#!/usr/bin/env python3
"""Keep native Linux Node evidence mandatory and namespace capture scoped."""
from pathlib import Path
import importlib.util
import os
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("linux_node_runner", Path(__file__).with_name("test_linux_node_lifecycle.py"))
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)


def completed():
    lines = []
    for name in RUNNER.CASES:
        lines.append("--- PASS: TestDesktopLinuxGuardianKernel" + name + " (1.00s)")
    for name, children in RUNNER.SUBCASES.items():
        lines.extend("    --- PASS: TestDesktopLinuxGuardianKernel" + name + "/" + child + " (0.10s)" for child in children)
    return lines


class LinuxNodeRunner(unittest.TestCase):
    def test_complete_native_result_is_accepted(self):
        RUNNER.check_verdict("\n".join(completed()))

    def test_each_native_case_and_negative_is_required(self):
        rows = completed()
        for missing in range(len(rows)):
            with self.subTest(missing=rows[missing]), self.assertRaises(ValueError):
                RUNNER.check_verdict("\n".join(rows[:missing] + rows[missing + 1:]))

    def test_failed_skipped_and_empty_results_are_rejected(self):
        for output in ("", "\n".join(completed()) + "\n--- FAIL: actual child (0.10s)",
                       "\n".join(completed()) + "\n--- SKIP: native dependency (0.10s)"):
            with self.subTest(output=output[-80:]), self.assertRaises(ValueError):
                RUNNER.check_verdict(output)

    def test_outer_namespace_capture_is_exact_and_restored_on_failure(self):
        namespace = os.stat("/proc/self/ns/net")
        key = "ROUTERVPN_NODE_OUTER_NETNS_ID"
        expected = str(namespace.st_dev) + ":" + str(namespace.st_ino)
        for previous in (None, "previous-captured-value"):
            with self.subTest(previous=previous), patch.dict(os.environ):
                if previous is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = previous
                def enter(binary, case):
                    self.assertEqual(os.environ[key], expected)
                    self.assertEqual(binary, Path("/captured-test-binary"))
                    self.assertEqual(case, "NodeLifecycle")
                    raise RuntimeError("original namespace refusal")
                with patch.object(RUNNER.GUARD, "namespace_test", side_effect=enter):
                    with self.assertRaisesRegex(RuntimeError, "original namespace refusal"):
                        RUNNER.namespace_test(Path("/captured-test-binary"), "NodeLifecycle")
                self.assertEqual(os.environ.get(key), previous)


if __name__ == "__main__":
    unittest.main()
