#!/usr/bin/env python3
"""Reject incomplete public CONNECT controls without fabricating native acceptance."""
from contextlib import redirect_stdout
from pathlib import Path
import importlib.util
import io
import unittest
from unittest.mock import Mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('connect_public_gate', ROOT/'deploy/test_desktop_connect_admission.py')
G = importlib.util.module_from_spec(spec)
spec.loader.exec_module(G)


def completed():
    return ''.join('=== RUN   '+name+'\n--- PASS: '+name+' (0.01s)\n' for name in G.REQUIRED)+'PASS\n'


class PublicCONNECTSourceGate(unittest.TestCase):
    def test_every_protocol_source_and_public_transaction_is_required(self):
        self.assertEqual(len(G.REQUIRED), 72)
        self.assertEqual(len(set(G.REQUIRED)), 72)
        G.require_verdicts(completed())
        for line in completed().splitlines(True):
            for broken in (completed().replace(line, '', 1), completed()+line,
                           completed().replace(line, 'foreign '+line, 1)):
                with self.subTest(line=line), self.assertRaises(ValueError):
                    G.require_verdicts(broken)

    def test_failure_skip_race_and_false_process_success_are_refused(self):
        for fault in ('--- FAIL:', '--- SKIP:', 'WARNING: DATA RACE', 'panic:', 'fatal error:'):
            with self.subTest(fault=fault), self.assertRaises(ValueError):
                G.require_verdicts(completed()+fault)
        for status, output in ((1, completed()), (0, 'PASS\n')):
            with self.assertRaises(ValueError):
                G.execute('/captured/controller', 'linux', Mock(return_value=(status, output)), ROOT, {})

    def test_original_process_bound_and_source_only_scope(self):
        for target in ('windows', 'linux'):
            run = Mock(return_value=(0, completed()))
            env = {'GOTOOLCHAIN': 'local'}
            with redirect_stdout(io.StringIO()):
                receipt = G.execute('/captured/controller', target, run, ROOT, env)
            self.assertEqual(receipt['scope'], 'registered-public-connect-source-controls')
            self.assertIs(receipt['native_kernel_acceptance'], False)
            self.assertEqual(receipt['target'], target)
            self.assertEqual(receipt['cases'], list(G.REQUIRED))
            self.assertEqual(run.call_args.kwargs, dict(cwd=ROOT, env=env, timeout=100))
            self.assertIn('-test.timeout=90s', run.call_args.args[0])
        for target in ('darwin', 'linux/amd64', '', None):
            run = Mock()
            with self.assertRaises(ValueError):
                G.execute('/captured/controller', target, run, ROOT, {})
            run.assert_not_called()


if __name__ == '__main__':
    unittest.main()
