#!/usr/bin/env python3
"""Parent verdict validation rejects a missing, duplicated or substituted control."""
from pathlib import Path
from contextlib import redirect_stdout
import importlib.util
import io
import unittest
from unittest.mock import Mock
ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('socks_parent_gate', ROOT/'deploy/test_desktop_socks_parent.py')
G = importlib.util.module_from_spec(spec)
spec.loader.exec_module(G)

class ParentGate(unittest.TestCase):
    def completed(self, target):
        return ''.join('=== RUN   '+name+'\n--- PASS: '+name+' (0.01s)\n' for name in G.inventory(target)[1])+'PASS\n'
    def test_complete_windows_and_linux_inventory(self):
        self.assertEqual(len(G.inventory('windows')[1]), 15)
        self.assertEqual(len(G.inventory('linux')[1]), 32)
        for target in ('windows', 'linux'):
            good = self.completed(target)
            G.require_verdicts(good, target)
            for line in good.splitlines(True):
                for bad in (good.replace(line, '', 1), good+line, good.replace(line, 'foreign '+line, 1)):
                    with self.subTest(target=target, line=line), self.assertRaises(ValueError):
                        G.require_verdicts(bad, target)
    def test_failure_skip_race_rejected(self):
        for fault in ('--- FAIL:', '--- SKIP:', 'WARNING: DATA RACE', 'panic:', 'fatal error:'):
            with self.assertRaises(ValueError):
                G.require_verdicts(self.completed('linux')+fault, 'linux')
    def test_compiled_process_and_evidence_boundary(self):
        run = Mock(return_value=(0, self.completed('windows')))
        captured = {'GOTOOLCHAIN': 'local'}
        with redirect_stdout(io.StringIO()):
            receipt = G.execute(Path('/captured/controller'), 'windows', run, ROOT, captured)
        self.assertFalse(receipt['native_kernel_acceptance'])
        self.assertEqual(receipt['cases'], list(G.inventory('windows')[1]))
        self.assertEqual(run.call_args.kwargs, dict(cwd=ROOT, env=captured, timeout=70))
        self.assertIn('-test.count=1', run.call_args.args[0])
        for status, output in ((1,self.completed('windows')), (0,'PASS\n'), (0,self.completed('linux'))):
            with self.assertRaises(ValueError):
                G.execute(Path('/captured/controller'), 'windows', Mock(return_value=(status,output)), ROOT, captured)

if __name__ == '__main__': unittest.main()
