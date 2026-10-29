#!/usr/bin/env python3
"""Exercise actual subprocess success/failure reporting without native privilege."""
from pathlib import Path
import contextlib
import importlib.util
import io
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('darwin_guardian_runner_fixture', ROOT/'deploy/test_desktop_darwin_guardian.py')
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)


class DarwinNativeDiagnostics(unittest.TestCase):
    def test_actual_failed_command_exposes_bounded_tail_and_remains_failure(self):
        diagnostic = 'actual compiler fixture: missing required declaration'
        command = [sys.executable, '-c',
                   "import os,sys; os.write(2, b'x'*60000+b'\\xff\\n'+"+repr(diagnostic.encode())+"); sys.exit(42)"]
        shown = io.StringIO()
        with contextlib.redirect_stderr(shown), self.assertRaises(subprocess.CalledProcessError) as failed:
            GATE.reported_run(command, timeout=5)
        self.assertEqual(failed.exception.returncode, 42)
        self.assertIn(diagnostic, shown.getvalue())
        self.assertIn('Darwin native command failure output (bounded tail):', shown.getvalue())
        self.assertIn('\ufffd', shown.getvalue())
        self.assertLessEqual(len(shown.getvalue()), 24*1024+128)
        self.assertGreater(len(failed.exception.output), 60000, 'the original failure evidence was discarded')

    def test_actual_success_returns_evidence_without_fabricating_failure_output(self):
        shown = io.StringIO()
        with contextlib.redirect_stderr(shown):
            output = GATE.reported_run([sys.executable, '-c', "print('actual successful command')"], timeout=5)
        self.assertEqual(output, 'actual successful command\n')
        self.assertEqual(shown.getvalue(), '')


if __name__ == '__main__':
    unittest.main(verbosity=2)
