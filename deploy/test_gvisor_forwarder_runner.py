#!/usr/bin/env python3
"""Exercise native forwarder gate admission, inventory and failure propagation."""
from pathlib import Path
import contextlib
import importlib.util
import io
import json
import os
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('forwarder_runner_controls', ROOT / 'deploy/test_gvisor_forwarder_pinned.py')
GATE = importlib.util.module_from_spec(spec)
spec.loader.exec_module(GATE)


def verdicts():
    rows = [{'Package': GATE.PACKAGE, 'Action': 'start'}]
    for name in sorted(GATE.REQUIRED):
        rows += [{'Package': GATE.PACKAGE, 'Test': name, 'Action': action} for action in ('run', 'pass')]
    rows.append({'Package': GATE.PACKAGE, 'Action': 'pass'})
    return rows


def encoded(rows):
    return '\n'.join(json.dumps(row) for row in rows) + '\n'


class VerdictControls(unittest.TestCase):
    def test_complete_eight_roots_and_thirteen_children_are_required(self):
        self.assertEqual(len(GATE.GROUPS), 8)
        self.assertEqual(len(GATE.SUBCASES), 13)
        self.assertEqual(len(GATE.REQUIRED), 21)
        GATE.check_verdicts(encoded(verdicts()))
        for name in GATE.REQUIRED:
            for action in ('run', 'pass'):
                rows = [row for row in verdicts() if (row.get('Test'), row['Action']) != (name, action)]
                with self.subTest(name=name, action=action), self.assertRaises(ValueError):
                    GATE.check_verdicts(encoded(rows))

    def test_failed_skipped_raced_unknown_foreign_and_duplicate_verdicts_are_rejected(self):
        faults = [
            {'Package': GATE.PACKAGE, 'Action': action} for action in ('fail', 'skip', 'build-fail')
        ] + [
            {'Package': GATE.PACKAGE, 'Action': 'output', 'Output': 'WARNING: DATA RACE\n'},
            {'Package': 'foreign/package', 'Action': 'pass'},
            {'Package': GATE.PACKAGE, 'Test': 'TestRouterVPNForwarderOmitted', 'Action': 'run'},
            {'Package': GATE.PACKAGE, 'Test': GATE.GROUPS[0], 'Action': 'run'},
            {'Package': GATE.PACKAGE, 'Test': GATE.GROUPS[0], 'Action': 'pass'},
            {'Package': GATE.PACKAGE, 'Action': 'pass'},
        ]
        for fault in faults:
            with self.subTest(fault=fault), self.assertRaises(ValueError):
                GATE.check_verdicts(encoded(verdicts() + [fault]))

    def test_missing_package_completion_and_invalid_json_cannot_pass(self):
        for value in (encoded(verdicts()[:-1]), '', encoded(verdicts()) + 'compiler failed\n'):
            with self.subTest(value=value[-50:]), self.assertRaises((ValueError, json.JSONDecodeError)):
                GATE.check_verdicts(value)

    def test_pass_without_actual_run_is_rejected_even_if_run_appears_later(self):
        rows = verdicts()
        rows[1], rows[2] = rows[2], rows[1]
        with self.assertRaises(ValueError):
            GATE.check_verdicts(encoded(rows))


class ExecutionControls(unittest.TestCase):
    def setUp(self):
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.vendor = Path(self.stack.enter_context(tempfile.TemporaryDirectory())).resolve()
        self.verify = self.stack.enter_context(patch.object(GATE.POLICY, 'verify'))
        self.inputs = self.stack.enter_context(patch.object(GATE, 'source_inputs', return_value={'source': 'captured'}))
        self.goenv = self.stack.enter_context(patch.object(GATE.subprocess, 'check_output', return_value='linux\namd64\n'))
        self.process = self.stack.enter_context(patch.object(GATE.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, encoded(verdicts()).encode())))
        self.system = self.stack.enter_context(patch.object(GATE.platform, 'system', return_value='Linux'))
        self.machine = self.stack.enter_context(patch.object(GATE.platform, 'machine', return_value='x86_64'))
        self.stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
        self.environment = {'GOWORK': '/unrelated/workspace', 'CAPTURED': 'unchanged'}

    def run_gate(self):
        GATE.run(self.vendor, 'owned-go', self.environment)

    def test_all_six_actual_hosts_execute_the_exact_inventory_with_supported_race_mode(self):
        for system, goos in (('Linux', 'linux'), ('Darwin', 'darwin'), ('Windows', 'windows')):
            for machine, goarch in (('x86_64', 'amd64'), ('arm64', 'arm64')):
                with self.subTest(system=system, arch=goarch):
                    self.verify.reset_mock()
                    self.process.reset_mock()
                    self.inputs.reset_mock()
                    self.system.return_value, self.machine.return_value = system, machine
                    self.goenv.return_value = goos + '\n' + goarch + '\n'
                    self.run_gate()
                    self.assertEqual(self.verify.call_count, 2)
                    self.assertEqual(self.inputs.call_count, 2)
                    command = self.process.call_args.args[0]
                    self.assertEqual(command[:3], ['owned-go', 'test', '-json'])
                    self.assertEqual('-race' in command, (goos, goarch) != ('windows', 'arm64'))
                    self.assertIn('-mod=readonly', command)
                    self.assertIn(GATE.PACKAGE, command)
                    self.assertIn('-count=1', command)
                    self.assertIn('-timeout=45s', command)
                    self.assertEqual(command[command.index('-run') + 1], '^TestRouterVPNForwarder')
                    options = self.process.call_args.kwargs
                    self.assertEqual(options['cwd'], self.vendor)
                    self.assertEqual(options['env'], {'GOWORK': 'off', 'CAPTURED': 'unchanged'})
                    self.assertEqual(options['timeout'], 180)
                    self.assertEqual(self.verify.call_args.kwargs['env'], options['env'])
                    self.assertEqual(self.environment['GOWORK'], '/unrelated/workspace')

    def test_mismatched_cross_compile_or_unsupported_host_cannot_start_a_test(self):
        for result in ('linux\narm64\n', 'windows\namd64\n', 'freebsd\namd64\n', ''):
            with self.subTest(result=result):
                self.goenv.return_value = result
                with self.assertRaises(ValueError):
                    self.run_gate()
                self.process.assert_not_called()

    def test_unverified_source_fails_before_any_native_process(self):
        self.verify.side_effect = ValueError('changed pinned dependency')
        with self.assertRaisesRegex(ValueError, 'changed pinned dependency'):
            self.run_gate()
        self.goenv.assert_not_called()
        self.process.assert_not_called()

    def test_process_failure_timeout_and_incomplete_verdict_never_verify_success(self):
        for fault in ('exit', 'timeout', 'missing'):
            with self.subTest(fault=fault):
                self.verify.reset_mock()
                self.process.side_effect = None
                self.process.return_value = subprocess.CompletedProcess([], 1 if fault == 'exit' else 0,
                                                                        encoded(verdicts()[:-1]).encode())
                if fault == 'timeout':
                    self.process.side_effect = subprocess.TimeoutExpired('actual forwarder gate', 180)
                with self.assertRaises((ValueError, subprocess.CalledProcessError, subprocess.TimeoutExpired)):
                    self.run_gate()
                self.assertEqual(self.verify.call_count, 1)

    def test_post_execution_dependency_drift_and_source_drift_cannot_pass(self):
        self.verify.side_effect = [None, ValueError('dependency changed during execution')]
        with self.assertRaisesRegex(ValueError, 'dependency changed during execution'):
            self.run_gate()
        self.verify.side_effect = None
        self.inputs.side_effect = [{'source': 'captured'}, {'source': 'replaced'}]
        with self.assertRaisesRegex(ValueError, 'source changed'):
            self.run_gate()


class SourceOwnershipControls(unittest.TestCase):
    def test_exact_source_hashes_reject_missing_linked_or_shared_inputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            owned, other = root / 'owned.py', root / 'other.py'
            owned.write_bytes(b'captured source\n')
            other.write_bytes(b'foreign source\n')
            with patch.object(GATE, 'ROOT', root), patch.object(GATE.POLICY, 'inputs', return_value=[owned]):
                before = GATE.source_inputs()
                owned.write_bytes(b'changed source\n')
                self.assertNotEqual(GATE.source_inputs(), before)
                owned.unlink()
                with self.assertRaises(ValueError):
                    GATE.source_inputs()
                os.link(other, owned)
                with self.assertRaises(ValueError):
                    GATE.source_inputs()
                owned.unlink()
                if os.name != 'nt':
                    owned.symlink_to(other)
                    with self.assertRaises(ValueError):
                        GATE.source_inputs()
                self.assertEqual(other.read_bytes(), b'foreign source\n')


if __name__ == '__main__':
    unittest.main()
