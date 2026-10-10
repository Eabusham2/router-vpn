#!/usr/bin/env python3
"""Check fixture plumbing; real Swift/native graphs run in the separate gate."""
from pathlib import Path
import importlib.util
import json
import subprocess
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('xray_exit_runner', ROOT/'deploy/test_ios_xray_exits.py')
RUNNER = importlib.util.module_from_spec(spec)
spec.loader.exec_module(RUNNER)


class NativeExitFixtureInputs(unittest.TestCase):
    def fixture(self, role):
        return {mode: {'fixture_role': role} for mode in RUNNER.EXPECTED_NATIVE_MODES}

    def test_both_roles_are_generated_by_the_real_production_generator(self):
        calls = []
        def execute(command, **kwargs):
            self.assertEqual(command[:3], ['go', 'run', './deploy/testfixtures/xray-entry'])
            self.assertEqual(kwargs['cwd'], ROOT)
            self.assertTrue(kwargs['check'])
            self.assertEqual(kwargs['timeout'], 90)
            role = 'exits' if command[3:] == ['--exits'] else 'entries'
            self.assertIn(command[3:], ([], ['--exits']))
            json.dump(self.fixture(role), kwargs['stdout'])
            calls.append(role)
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(RUNNER.subprocess, 'run', side_effect=execute):
            entry, exit = RUNNER.prepare_fixture_inputs(Path(tmp))
            self.assertNotEqual(entry, exit)
            self.assertEqual(calls, ['entries', 'exits'])
            self.assertEqual(json.loads(entry.read_text()), self.fixture('entries'))
            self.assertEqual(json.loads(exit.read_text()), self.fixture('exits'))

    def test_preexported_inputs_remain_offline_and_unmodified(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(RUNNER.subprocess, 'run') as run:
            directory = Path(tmp)
            entry, exit = directory/'provided-entry.json', directory/'provided-exit.json'
            entry.write_text(json.dumps(self.fixture('entries')))
            exit.write_text(json.dumps(self.fixture('exits')))
            before = (entry.read_bytes(), exit.read_bytes())
            self.assertEqual(RUNNER.prepare_fixture_inputs(directory, entry, exit), (entry.resolve(), exit.resolve()))
            run.assert_not_called()
            self.assertEqual((entry.read_bytes(), exit.read_bytes()), before)

    def test_generation_failure_or_missing_mode_cannot_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            with mock.patch.object(RUNNER.subprocess, 'run', side_effect=subprocess.CalledProcessError(1, ['go'])):
                with self.assertRaises(subprocess.CalledProcessError):
                    RUNNER.prepare_fixture_inputs(directory)
            entry, exit = directory/'entry.json', directory/'exit.json'
            for broken in ({}, [], self.fixture('exits') | {'other': {}}, {key: None for key in RUNNER.EXPECTED_NATIVE_MODES}):
                entry.write_text(json.dumps(self.fixture('entries')))
                exit.write_text(json.dumps(broken))
                with mock.patch.object(RUNNER.subprocess, 'run') as run, self.assertRaises(RuntimeError):
                    RUNNER.prepare_fixture_inputs(directory, entry, exit)
                run.assert_not_called()

    def test_every_shared_harness_environment_input_is_supplied(self):
        source = (ROOT/'deploy/test_ios_xray_exits.py').read_text()
        self.assertIn('ROUTERVPN_XRAY_ENTRY_FIXTURES=str(entries)', source)
        self.assertIn('ROUTERVPN_XRAY_EXIT_FIXTURES=str(exits)', source)
        self.assertIn('ROUTERVPN_XRAY_EXIT_POLICY=str(helper)', source)
        self.assertIn('subprocess.run([str(exe)],env=env,check=True,timeout=90)', source)
        self.assertIn('prefix+TEST', source)


if __name__ == '__main__':
    unittest.main()
