#!/usr/bin/env python3
"""Keep native Linux Node evidence mandatory and namespace capture scoped."""
from pathlib import Path
from contextlib import redirect_stderr
import io
import importlib.util
import os
import subprocess
import sys
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

    def test_failed_original_child_retains_status_and_bounded_native_output(self):
        for noisy in (False, True):
            with self.subTest(noisy=noisy):
                command = [sys.executable, "-c",
                           "import os; " + ("os.write(1, b'old-prefix\\n' + b'x' * 60000 + b'\\xff'); "
                           "os.write(2, b'original native failure\\n'); " if noisy else "") + "raise SystemExit(37)"]
                failures = []
                def failed(source, go):
                    self.assertEqual(source, Path("/captured-source"))
                    self.assertEqual(go, "/captured-go")
                    try:
                        RUNNER.GUARD.UID.run(command, timeout=5)
                    except subprocess.CalledProcessError as error:
                        failures.append(error)
                        raise
                diagnostic = io.StringIO()
                with patch.object(RUNNER, "execute", side_effect=failed), redirect_stderr(diagnostic):
                    with self.assertRaises(subprocess.CalledProcessError) as caught:
                        RUNNER.main(["/captured-source", "--go", "/captured-go"])
                self.assertEqual(len(failures), 1)
                self.assertIs(caught.exception, failures[0])
                self.assertEqual(caught.exception.returncode, 37)
                self.assertEqual(caught.exception.cmd, command)
                original = caught.exception.output
                self.assertEqual(diagnostic.getvalue(), original[-32768:].decode("utf-8", errors="replace"))
                if noisy:
                    self.assertNotIn("old-prefix", diagnostic.getvalue())
                    self.assertIn("\uFFFDoriginal native failure", diagnostic.getvalue())
                    self.assertLessEqual(len(diagnostic.getvalue()), 32768)
                else:
                    self.assertEqual(diagnostic.getvalue(), "")

    def test_cli_preserves_success_and_namespace_exit(self):
        diagnostic = io.StringIO()
        with patch.object(RUNNER, "execute") as execute, redirect_stderr(diagnostic):
            RUNNER.main(["/captured-source", "--go", "/captured-go"])
        execute.assert_called_once_with(Path("/captured-source"), "/captured-go")
        self.assertEqual(diagnostic.getvalue(), "")
        with patch.object(RUNNER, "namespace_test", return_value=23) as enter, patch.object(RUNNER, "execute") as execute:
            with self.assertRaises(SystemExit) as caught:
                RUNNER.main(["--namespace-test-binary", "/captured-binary", "--namespace-test-sha256", "a" * 64,
                             "--kernel-case", "NodeLifecycle"])
        self.assertEqual(caught.exception.code, 23)
        enter.assert_called_once_with(Path("/captured-binary"), "NodeLifecycle", "a" * 64)
        execute.assert_not_called()

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
                digest = "a" * 64
                def enter(binary, case, actual_digest):
                    self.assertEqual(os.environ[key], expected)
                    self.assertEqual(binary, Path("/captured-test-binary"))
                    self.assertEqual(case, "NodeLifecycle")
                    self.assertEqual(actual_digest, digest)
                    raise RuntimeError("original namespace refusal")
                with patch.object(RUNNER.GUARD, "namespace_test", side_effect=enter):
                    with self.assertRaisesRegex(RuntimeError, "original namespace refusal"):
                        RUNNER.namespace_test(Path("/captured-test-binary"), "NodeLifecycle", digest)
                self.assertEqual(os.environ.get(key), previous)


if __name__ == "__main__":
    unittest.main()
