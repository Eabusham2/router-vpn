#!/usr/bin/env python3
"""Exercise actual subprocess success/failure reporting without native privilege."""
from pathlib import Path
import ast
import contextlib
import importlib.util
import io
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
GATES = []
for name in ('test_desktop_darwin_guardian', 'test_macos_controller_privilege'):
    spec = importlib.util.spec_from_file_location(name+'_diagnostic_fixture', ROOT/'deploy'/f'{name}.py')
    gate = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gate)
    GATES.append(gate)


class DarwinNativeDiagnostics(unittest.TestCase):
    def test_actual_failed_command_exposes_bounded_tail_and_remains_failure(self):
        diagnostic = 'actual compiler fixture: missing required declaration'
        command = [sys.executable, '-c',
                   "import os,sys; os.write(2, b'x'*60000+b'\\xff\\n'+"+repr(diagnostic.encode())+"); sys.exit(42)"]
        for gate in GATES:
            with self.subTest(runner=gate.__name__):
                shown = io.StringIO()
                with contextlib.redirect_stderr(shown), self.assertRaises(subprocess.CalledProcessError) as failed:
                    gate.reported_run(command, timeout=5)
                self.assertEqual(failed.exception.returncode, 42)
                self.assertIn(diagnostic, shown.getvalue())
                self.assertIn('Darwin native command failure output (bounded', shown.getvalue())
                self.assertIn('\ufffd', shown.getvalue())
                self.assertLessEqual(len(shown.getvalue()), 24*1024+128)
                self.assertGreater(len(failed.exception.output), 60000, 'the original failure evidence was discarded')

    def test_actual_success_returns_evidence_without_fabricating_failure_output(self):
        for gate in GATES:
            with self.subTest(runner=gate.__name__):
                shown = io.StringIO()
                with contextlib.redirect_stderr(shown):
                    output = gate.reported_run([sys.executable, '-c', "print('actual successful command')"], timeout=5)
                self.assertEqual(output, 'actual successful command\n')
                self.assertEqual(shown.getvalue(), '')

    def test_controller_failed_original_leaf_survives_later_successful_inventory(self):
        gate = GATES[1]
        original = ('=== RUN   TestOriginal/retirement\n'
                    '    original_test.go:42: original captured child did not join\n'
                    '    --- FAIL: TestOriginal/retirement (0.01s)\n'
                    '--- FAIL: TestOriginal (0.01s)\n')
        tail = '=== RUN   TestLater\n--- PASS: TestLater (0.01s)\n'*2000+'FAIL\n'
        raw = (original+tail).encode()
        command = [sys.executable, '-c', 'import os,sys; os.write(1,'+repr(raw)+'); sys.exit(42)']
        shown = io.StringIO()
        with contextlib.redirect_stderr(shown), self.assertRaises(subprocess.CalledProcessError) as failed:
            gate.reported_run(command, timeout=5)
        self.assertEqual(failed.exception.returncode, 42)
        self.assertEqual(failed.exception.output, raw)
        self.assertIn('original_test.go:42: original captured child did not join', shown.getvalue())
        self.assertIn('--- FAIL: TestOriginal/retirement', shown.getvalue())
        self.assertIn('--- PASS: TestLater', shown.getvalue())
        self.assertTrue(shown.getvalue().rstrip().endswith('FAIL'))
        self.assertLessEqual(len(shown.getvalue()), 24*1024+128)

    def test_controller_multiple_failure_excerpts_remain_bounded_and_original(self):
        gate = GATES[1]
        raw = ''.join('=== RUN   TestOriginal'+str(index)+'\n'+
                      'x'*6000+'\n    original_test.go:42: assertion '+str(index)+'\n'+
                      '--- FAIL: TestOriginal'+str(index)+' (0.01s)\n' for index in range(8))
        raw += 'later successful output\n'*3000+'FAIL\n'
        shown = gate.native_failure_excerpt(raw)
        for index in range(4):
            self.assertIn('original_test.go:42: assertion '+str(index), shown)
        self.assertLessEqual(len(shown), 24*1024)
        self.assertTrue(shown.endswith('FAIL\n'))
        self.assertEqual(gate.native_failure_excerpt('short original failure\n'), 'short original failure\n')


class DarwinNativeTimeoutDiagnostics(unittest.TestCase):
    def setUp(self):
        self.gate = GATES[0]
        self.process = mock.Mock(pid=431, returncode=0)
        self.expired = subprocess.TimeoutExpired(['original-captured-native-test'], 730,
            output=b'old-prefix:' + b'x' * 10000 + b'\xff\noriginal native case entered\n')

    def test_timeout_excerpt_retains_initial_failure_and_final_stack_with_a_bound(self):
        raw = b'actual selected-private UDP association: original owner failure\n' + b'x'*40000 + b'final joined stack\n'
        shown = self.gate.native_timeout_excerpt(raw)
        self.assertIn('actual selected-private UDP association: original owner failure', shown)
        self.assertIn('final joined stack', shown)
        self.assertIn('bounded middle omitted', shown)
        self.assertLess(len(shown), 12400)
        self.assertEqual(self.gate.native_timeout_excerpt(b'complete short output'), 'complete short output')

    def test_success_retains_original_output_without_signalling(self):
        self.process.communicate.return_value = (b'original native result\n', None)
        with mock.patch.object(self.gate.os, 'killpg') as kill:
            self.assertEqual(self.gate.native_test_output(self.process), b'original native result\n')
        self.process.communicate.assert_called_once_with(timeout=730)
        kill.assert_not_called()

    def test_timeout_progress_precedes_denied_termination_and_both_failures_survive(self):
        self.process.communicate.side_effect = self.expired
        shown = io.StringIO()
        denied = PermissionError(1, 'original group denied')
        def kill(pid, signal):
            self.assertEqual((pid, signal), (431, self.gate.signal.SIGKILL))
            self.assertIn('original native case entered', shown.getvalue())
            self.assertIn('\ufffd', shown.getvalue())
            self.assertIn('old-prefix:', shown.getvalue())
            self.assertLess(len(shown.getvalue()), 12500)
            raise denied
        with contextlib.redirect_stderr(shown), mock.patch.object(self.gate.os, 'killpg', side_effect=kill), \
             self.assertRaisesRegex(RuntimeError, 'bounded lifetime; original process-group termination failed: PermissionError') as failed:
            self.gate.native_test_output(self.process)
        self.assertIs(failed.exception.__cause__, self.expired)
        self.assertIn('original group denied', str(failed.exception))
        self.process.communicate.assert_called_once_with(timeout=730)

    def test_timeout_remains_failure_after_original_group_joins_with_successful_exit(self):
        self.process.communicate.side_effect = [self.expired, (b'late original output\n', None)]
        with contextlib.redirect_stderr(io.StringIO()), mock.patch.object(self.gate.os, 'killpg') as kill, \
             self.assertRaisesRegex(RuntimeError, 'bounded lifetime after its original process group joined: late original output') as failed:
            self.gate.native_test_output(self.process)
        kill.assert_called_once_with(431, self.gate.signal.SIGKILL)
        self.assertEqual(self.process.communicate.call_args_list, [mock.call(timeout=730), mock.call(timeout=10)])
        self.assertIs(failed.exception.__cause__, self.expired)

    def test_unjoined_output_keeps_original_timeout_and_latest_partial_progress(self):
        for cleanup in (subprocess.TimeoutExpired(['original-captured-native-test'], 10, output=b'later retained descendant progress'),
                        OSError('original pipe read failed')):
            with self.subTest(cleanup=type(cleanup).__name__):
                self.process.communicate.reset_mock(side_effect=True)
                self.process.communicate.side_effect = [self.expired, cleanup]
                shown = io.StringIO()
                with contextlib.redirect_stderr(shown), mock.patch.object(self.gate.os, 'killpg') as kill, \
                     self.assertRaisesRegex(RuntimeError, 'bounded lifetime; original process-group output did not join') as failed:
                    self.gate.native_test_output(self.process)
                self.assertIn('original native case entered', shown.getvalue())
                if isinstance(cleanup, subprocess.TimeoutExpired):
                    self.assertIn('later retained descendant progress', shown.getvalue())
                self.assertIs(failed.exception.__cause__, self.expired)
                kill.assert_called_once_with(431, self.gate.signal.SIGKILL)
                self.assertEqual(self.process.communicate.call_args_list, [mock.call(timeout=730), mock.call(timeout=10)])

    def test_privileged_fixture_uses_original_session_and_timeout_helper(self):
        tree = ast.parse(Path(self.gate.__file__).read_text())
        root = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'root_fixture')
        launches = [node for node in ast.walk(root) if isinstance(node, ast.Call) and
                    isinstance(node.func, ast.Attribute) and node.func.attr == 'Popen']
        self.assertEqual(len(launches), 1)
        self.assertTrue(next(keyword.value.value for keyword in launches[0].keywords if keyword.arg == 'start_new_session'))
        calls = [node for node in ast.walk(root) if isinstance(node, ast.Call) and
                 isinstance(node.func, ast.Name) and node.func.id == 'native_test_output']
        self.assertEqual(len(calls), 1)
        self.assertEqual(ast.unparse(calls[0].args[0]), 'process')
        self.assertEqual(ast.unparse(calls[0].args[1]), 'binary')

    def test_exited_main_and_exact_helper_identity_precede_denied_kill(self):
        self.process.communicate.side_effect = self.expired
        binary = Path('/opt/routervpn-darwin-guardian-original/darwin-guardian.test')
        shown = io.StringIO()
        def kill(*_args):
            self.assertIn('"cached_returncode": 0', shown.getvalue())
            self.assertIn('"pid": 712', shown.getvalue())
            self.assertIn('"pgid": 710', shown.getvalue())
            self.assertIn('"sid": 431', shown.getvalue())
            raise PermissionError(1, 'original group denied')
        with contextlib.redirect_stderr(shown), \
             mock.patch.object(self.gate.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, b'431 400 431 Z\n')) as observe, \
             mock.patch.object(self.gate, 'owned_children', return_value=[712]) as children, \
             mock.patch.object(self.gate.os, 'getpgid', return_value=710) as pgid, \
             mock.patch.object(self.gate.os, 'getsid', return_value=431), \
             mock.patch.object(self.gate.os, 'killpg', side_effect=kill), \
             self.assertRaises(RuntimeError) as failed:
            self.gate.native_test_output(self.process, binary)
        self.assertIs(failed.exception.__cause__, self.expired)
        children.assert_called_once_with(binary)
        pgid.assert_called_once_with(712)
        self.process.poll.assert_not_called()
        self.process.wait.assert_not_called()
        observe.assert_called_once_with(['/bin/ps', '-p', '431', '-o', 'pid=,ppid=,pgid=,state='],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            timeout=2, check=False, env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})
        self.assertIn('"state": "Z"', shown.getvalue())

    def test_failed_identity_observation_never_masks_original_timeout_or_kill(self):
        self.process.communicate.side_effect = self.expired
        shown = io.StringIO()
        with contextlib.redirect_stderr(shown), \
             mock.patch.object(self.gate.subprocess, 'run', side_effect=OSError('read failure with private text')), \
             mock.patch.object(self.gate, 'owned_children', side_effect=ValueError('private inventory text')), \
             mock.patch.object(self.gate.os, 'killpg', side_effect=PermissionError(1, 'original denied')), \
             self.assertRaisesRegex(RuntimeError, 'original denied') as failed:
            self.gate.native_test_output(self.process, Path('/captured/original'))
        self.assertIs(failed.exception.__cause__, self.expired)
        self.assertIn('"nonreaping_observation_error": "OSError"', shown.getvalue())
        self.assertIn('"type": "ValueError"', shown.getvalue())
        self.assertNotIn('private', shown.getvalue())

    def test_identity_inventory_bounds_native_reads_and_keeps_running_state(self):
        self.process.returncode = None
        shown = io.StringIO()
        with contextlib.redirect_stderr(shown), \
             mock.patch.object(self.gate, 'owned_children', return_value=list(range(100, 200))), \
             mock.patch.object(self.gate.os, 'getpgid', side_effect=ProcessLookupError(3, 'gone')) as pgid, \
             mock.patch.object(self.gate.os, 'getsid', return_value=431) as sid, \
             mock.patch.object(self.gate.os, 'kill') as kill, mock.patch.object(self.gate.os, 'killpg') as killpg:
            self.gate.native_timeout_identity(self.process, Path('/captured/original'))
        self.assertEqual(pgid.call_count, 32)
        self.assertEqual(sid.call_count, 32)
        self.assertIn('"cached_returncode": null', shown.getvalue())
        self.assertIn('"count": 100, "reported": 32', shown.getvalue())
        self.assertIn('"pgid_errno": 3', shown.getvalue())
        self.assertLess(len(shown.getvalue()), 7000)
        kill.assert_not_called()
        killpg.assert_not_called()

    def test_native_inventory_matches_only_exact_captured_executable(self):
        binary = Path('/opt/routervpn-darwin-guardian-original/darwin-guardian.test')
        proc = mock.Mock()
        def pids(values, size):
            if values is None:
                return 3
            values[0], values[1], values[2] = 401, 402, 403
            return 3
        def path(pid, buffer, size):
            value = str(binary) if pid == 402 else '/other/darwin-guardian.test'
            buffer.value = os.fsencode(value)
            return len(buffer.value)
        proc.proc_listallpids.side_effect = pids
        proc.proc_pidpath.side_effect = path
        with mock.patch.object(self.gate.ctypes, 'CDLL', return_value=proc), \
             mock.patch.object(self.gate.os, 'kill') as kill:
            self.assertEqual(self.gate.owned_children(binary), [402])
        self.assertEqual(proc.proc_pidpath.call_count, 3)
        kill.assert_not_called()

    def test_original_child_observation_rejects_foreign_duplicate_and_unbounded_rows(self):
        for raw in (b'432 400 431 Z\n', b'431 400 431 Z\n431 400 431 Z\n',
                    b'431 400 431 '+b'Z'*300, b'431 400 431 Z private-command-data\n'):
            with self.subTest(raw=raw[:30]), contextlib.redirect_stderr(io.StringIO()) as shown, \
                 mock.patch.object(self.gate.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, raw)):
                self.gate.native_timeout_identity(self.process, None)
                self.assertIn('"nonreaping_observation_error": "ValueError"', shown.getvalue())
                self.assertNotIn('private-command-data', shown.getvalue())
        self.process.poll.assert_not_called()
        self.process.wait.assert_not_called()
        self.process.communicate.assert_not_called()

    def test_actual_exited_child_remains_waitable_after_nonreaping_ps_diagnostic(self):
        process = subprocess.Popen([sys.executable, '-c', 'import sys; sys.exit(37)'],
                                   stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        try:
            process.stdout.read()  # EOF observes exit without consuming wait status.
            shown = io.StringIO()
            with contextlib.redirect_stderr(shown), \
                 mock.patch.object(process, 'poll', side_effect=AssertionError('diagnostic reaped original child')), \
                 mock.patch.object(process, 'wait', side_effect=AssertionError('diagnostic waited original child')), \
                 mock.patch.object(process, 'communicate', side_effect=AssertionError('diagnostic consumed original output')):
                self.gate.native_timeout_identity(process, None)
            self.assertIsNone(process.returncode)
            self.assertIn('"cached_returncode": null', shown.getvalue())
            # A sandbox may expose a different process namespace to ps. An
            # unavailable readback still must not consume the original status.
            self.assertIn('"pid": '+str(process.pid), shown.getvalue())
            self.assertEqual(process.wait(timeout=5), 37)
        finally:
            process.stdout.close()
            process.wait(timeout=5)


class MacOSNativeVerdicts(unittest.TestCase):
    def setUp(self):
        self.gate = GATES[1]
        names = ['TestMacOSOwnedControllerNative'+name for name in self.gate.CASES]
        names += ['TestDesktopMacOS'+name for name in self.gate.PARENT_CASES]
        names += ['TestDesktopMacOS'+name for name in self.gate.EXECUTION_PARENT_CASES]
        self.lines = ['--- PASS: '+name+' (0.01s)' for name in names]
        self.output = '\n'.join(self.lines+['PASS', ''])

    def test_exact_complete_native_and_parent_cases_pass_once(self):
        self.gate.require_native_verdicts(self.output)

    def test_missing_duplicate_prefixed_subcase_and_incomplete_verdicts_fail(self):
        first = self.lines[0]
        for changed in ('', first+'\n'+first, 'diagnostic '+first,
                        first+' diagnostic', first.replace(' (', '/subcase ('),
                        first.replace('0.01s', 'unknown')):
            with self.subTest(verdict=changed), self.assertRaises(RuntimeError):
                self.gate.require_native_verdicts(self.output.replace(first, changed, 1))
        for ending in ('', 'PASS\nPASS\n', 'PASS\nextra\n'):
            with self.subTest(ending=ending), self.assertRaises(RuntimeError):
                self.gate.require_native_verdicts('\n'.join(self.lines)+'\n'+ending)

    def test_fixture_events_metadata_requires_its_unique_native_verdict(self):
        name = 'TestMacOSOwnedControllerNativeFixtureEventsPreserveCapturedDirectoryMetadata'
        line = '--- PASS: '+name+' (0.01s)'
        self.assertIn(line, self.lines)
        for changed in ('', line+'\n'+line, 'diagnostic '+line):
            with self.subTest(verdict=changed), self.assertRaises(RuntimeError):
                self.gate.require_native_verdicts(self.output.replace(line, changed, 1))

    def test_fail_skip_race_panic_fatal_or_build_failure_never_becomes_pass(self):
        for failure in ('--- FAIL: SomeOtherCase (0.01s)', '    --- SKIP: SomeCase/child (0.00s)',
                        'FAIL', 'SKIP', 'WARNING: DATA RACE', 'panic: broken',
                        'fatal error: concurrent map writes', 'FAIL package [build failed]'):
            with self.subTest(failure=failure), self.assertRaises(RuntimeError):
                self.gate.require_native_verdicts(failure+'\n'+self.output)

    def test_execution_parent_requires_all_five_exact_native_roots(self):
        expected = ('ExecutionReaderKeepsPreparationAndAdoptionDistinct',
                    'ExecutionReaderCancellationDoesNotWaitForOwnerMutex',
                    'ExecutionReaderRequiresPhysicalRetirement',
                    'ExecutionReplacementJoinsBeforeHoldingOriginalProtection',
                    'ExecutionReplacementRefusesForeignPreparation')
        self.assertEqual(self.gate.EXECUTION_PARENT_CASES, expected)
        self.assertEqual(len(self.gate.CASES)+len(self.gate.PARENT_CASES), 26)
        for suffix in expected:
            line = '--- PASS: TestDesktopMacOS'+suffix+' (0.01s)'
            self.assertIn(line, self.lines)
            for changed in ('', line+'\n'+line, 'diagnostic '+line,
                            line.replace(' (', '/subcase ('),
                            line.replace('--- PASS:', '--- SKIP:'),
                            line.replace('--- PASS:', '--- FAIL:')):
                with self.subTest(case=suffix, verdict=changed), self.assertRaises(RuntimeError):
                    self.gate.require_native_verdicts(self.output.replace(line, changed, 1))

    def test_actual_native_command_selects_execution_roots_without_changing_bounds(self):
        arguments = self.gate.native_test_arguments()
        self.assertEqual(arguments[1:], ['-test.v', '-test.timeout=180s'])
        self.assertTrue(arguments[0].startswith('-test.run='))
        pattern = arguments[0].removeprefix('-test.run=')
        for line in self.lines:
            name = line.removeprefix('--- PASS: ').split(' ', 1)[0]
            with self.subTest(case=name):
                self.assertIsNotNone(re.search(pattern, name))
        for suffix in self.gate.EXECUTION_PARENT_CASES:
            self.assertIsNone(re.search(pattern, 'TestDesktopMacOS'+suffix+'Unrelated'))
        for name in ('TestDesktopMacOSExecutionBaselineRetainsExactFamily',
                     'TestDesktopMacOSExecutionUnrelated'):
            self.assertIsNone(re.search(pattern, name))
        tree = ast.parse(Path(self.gate.__file__).read_text())
        main = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'main')
        commands = [node.value for node in ast.walk(main) if isinstance(node, ast.Assign)
                    and any(isinstance(target, ast.Name) and target.id == 'command' for target in node.targets)]
        # The original second assignment adds sudo around this same command.
        self.assertEqual(len(commands), 2)
        selected = [node for node in ast.walk(commands[0]) if isinstance(node, ast.Starred)
                    and isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Name)
                    and node.value.func.id == 'native_test_arguments']
        self.assertEqual(len(selected), 1, 'actual native invocation omitted the required execution roots')


class DarwinMutationOverlays(unittest.TestCase):
    def setUp(self):
        self.gate = GATES[0]
        tree = ast.parse(Path(self.gate.__file__).read_text())
        function = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
                        and node.name == 'execute_mutations')
        assignment = next(node for node in function.body if isinstance(node, ast.Assign)
                          and any(isinstance(name, ast.Name) and name.id == 'mutations' for name in node.targets))
        self.mutations = ast.literal_eval(assignment.value)
        self.quick = next(value for value in self.mutations if value[0] == 'quick deny before foreign pass')
        self.directory = tempfile.TemporaryDirectory(prefix='routervpn-darwin-mutation-')
        self.addCleanup(self.directory.cleanup)
        self.output = Path(self.directory.name)
        self.target = ROOT/'internal/mobiletor'

    def test_all_current_mutations_capture_their_actual_source_without_editing_it(self):
        for index, (label, case, witness, names, replacements) in enumerate(self.mutations):
            with self.subTest(label=label):
                paths = (names,) if isinstance(names, str) else names
                original = {str(self.target/name): (self.target/name).read_text() for name in paths}
                overlay = self.gate.write_mutation_overlay(self.output, index, self.target, names, replacements, label)
                actual = json.loads(overlay.read_text())['Replace']
                self.assertEqual(set(actual), set(original))
                for source, changed in actual.items():
                    self.assertEqual(Path(source).read_text(), original[source])
                    self.assertNotEqual(Path(changed).read_text(), original[source])
                    self.assertEqual(Path(changed).parent, self.output)
                self.assertTrue(case and witness)
        revoke = [entry for entry in self.mutations if entry[0] == 'authenticated revoke channel retirement']
        self.assertEqual(len(revoke), 1, 'the original native revoke lifetime control is mandatory')
        self.assertEqual(revoke[0][1], 'StaleCaptureAndReplacement')
        self.assertIn(revoke[0][1], self.gate.CASES)
        self.assertEqual(revoke[0][3], 'desktop_socket_darwin_policy.go')

    def test_descriptor_retirement_requires_the_first_original_tuple_and_joined_cleanup(self):
        controls = [entry for entry in self.mutations if entry[0] == 'per-socket descriptor retirement']
        self.assertEqual(len(controls), 1)
        _, case, witness, name, _ = controls[0]
        self.assertEqual(case, 'SocketRetirementReusesCapacity')
        self.assertEqual(name, 'desktop_socket_broker.go')
        self.assertEqual(witness, 'joined original socket retained its source port at iteration 0:')
        verdict = '--- FAIL: '+self.gate.native_case_name(case)+' (0.01s)'
        output = '    fixture.go:1: '+witness+' address already in use\n'+verdict+'\nFAIL\n'
        self.gate.require_mutation_failure(output, case, witness)
        for unrelated in ('sequential owned socket 128:', 'sequential owned socket 35 did not retire within the fixture drain bound',
                          witness.replace('iteration 0:', 'iteration 1:'),
                          'retained descriptor fixture could not recover its original creation',
                          'retained descriptor fixture did not prove original tuple recovery'):
            with self.subTest(unrelated=unrelated), self.assertRaises(ValueError):
                self.gate.require_mutation_failure(output.replace(witness, unrelated), case, witness)
        for cleanup in ('Darwin native broker did not drain context deadline exceeded',
                        'actual Darwin guardian close context deadline exceeded',
                        'Native fixture cleanup retained its recovery record',
                        'Darwin kernel test exceeded its bounded lifetime', 'WARNING: DATA RACE'):
            with self.subTest(cleanup=cleanup), self.assertRaises(ValueError):
                self.gate.require_mutation_failure(output+cleanup, case, witness)

    def test_quick_deny_control_reaches_both_baselines_without_changing_another_field(self):
        label, case, witness, names, replacements = self.quick
        self.assertEqual(case, 'ForeignBlockAndLaterPass')
        self.assertEqual(witness, 'later foreign pass bypassed nested quick deny')
        self.assertEqual(names, ('desktop_socket_darwin_pf.go', 'desktop_socket_pf_baseline.go'))
        overlay = self.gate.write_mutation_overlay(self.output, 0, self.target, names, replacements, label)
        changes = json.loads(overlay.read_text())['Replace']
        altered = []
        for source, changed in changes.items():
            before, after = Path(source).read_text(), Path(changed).read_text()
            self.assertEqual(len(before.splitlines()), len(after.splitlines()))
            for old, new in zip(before.splitlines(), after.splitlines()):
                if old != new:
                    self.assertIn('block drop out quick ', old)
                    self.assertEqual(new, old.replace('block drop out quick ', 'block drop out ', 1))
                    altered.append((Path(source).name, old))
        self.assertEqual([name for name, _ in altered], [names[0], names[1], names[1]])
        self.assertIn('desktopDarwinPFTestScope', altered[0][1])
        self.assertIn('scope, allowed, label', altered[1][1])
        self.assertIn('quick all ! tagged', altered[2][1])
        # Reproduce the obsolete single-file overlay's masking: the shared
        # production and scoped baseline guards remain quick in that version.
        old = self.gate.write_mutation_overlay(self.output, 1, self.target, names[0],
                                               (('block drop out quick ', 'block drop out '),), label)
        self.assertEqual(len(json.loads(old.read_text())['Replace']), 1)
        baseline = (self.target/names[1]).read_text()
        self.assertIn('block drop out quick %s ! tagged', baseline)
        self.assertIn('block drop out quick all ! tagged', baseline)

    def test_paired_control_rejects_missing_duplicate_or_repeated_targets_before_writing(self):
        label, _, _, names, replacements = self.quick
        for fault in ('missing', 'duplicate', 'repeated-target'):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory(prefix='routervpn-mutation-seam-') as temporary:
                root = Path(temporary)
                target, output = root/'source', root/'overlay'
                target.mkdir(); output.mkdir()
                for name in names:
                    (target/name).write_bytes((self.target/name).read_bytes())
                seam = replacements[1][0][0]
                baseline = target/names[1]
                if fault == 'missing':
                    baseline.write_text(baseline.read_text().replace(seam, '// changed captured guard', 1))
                elif fault == 'duplicate':
                    baseline.write_text(baseline.read_text()+'\n'+seam+'\n')
                selected = (names[0], names[0]) if fault == 'repeated-target' else names
                with self.assertRaises(ValueError):
                    self.gate.write_mutation_overlay(output, 0, target, selected, replacements, label)
                self.assertEqual(list(output.iterdir()), [], 'partial mutation files escaped an unproved second source')


class DarwinSOCKSBoundaries(unittest.TestCase):
    def setUp(self):
        self.gate = GATES[0]
        self.address = '10.254.77.10'
        self.before = {'destination': 'default', 'gateway': '192.0.2.1', 'interface': 'en0',
                       'flags': '<UP,GATEWAY,DONE,STATIC>'}
        self.owned = {'destination': self.address, 'gateway': self.address, 'interface': 'lo0',
                      'flags': '<UP,HOST,DONE,LLINFO,STATIC,IFSCOPE,IFREF>'}
        self.present = 'lo0: flags=8049<UP,LOOPBACK,RUNNING> mtu 16384\n\tinet '+self.address+' netmask 0xffffffff\n'
        self.absent = 'lo0: flags=8049<UP,LOOPBACK,RUNNING> mtu 16384\n\tinet 127.0.0.1 netmask 0xff000000\n'

    def route(self, values):
        return '\n'.join('   '+key+': '+value for key, value in values.items())+'\n'

    def test_original_route_must_be_unambiguous_default(self):
        self.gate.require_default_route(self.gate.native_route(self.route(self.before)))
        for changed in (dict(self.before, destination=self.address), dict(self.before, mask='255.0.0.0'),
                        dict(self.before, flags='<UP,HOST>')):
            with self.subTest(route=changed), self.assertRaises(ValueError):
                self.gate.require_default_route(self.gate.native_route(self.route(changed)))
        for raw in ('destination: default\n', self.route(self.before)+'interface: lo0\n'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                self.gate.native_route(raw)

    def test_exact_private_alias_rejects_changed_interface_mask_and_duplicate(self):
        self.assertTrue(self.gate.private_alias_present(self.present, self.address))
        self.assertFalse(self.gate.private_alias_present(self.absent, self.address))
        for changed in (self.present.replace('lo0:', 'en0:'), self.present.replace('0xffffffff', '0xffffff00'),
                        self.present+self.present):
            with self.subTest(alias=changed), self.assertRaises(ValueError):
                self.gate.private_alias_present(changed, self.address)

    def test_native_route_requires_exact_host_on_owned_interface(self):
        for changed in (dict(self.owned, destination='10.254.77'), dict(self.owned, interface='en0'),
                        dict(self.owned, flags='<UP,DONE>'), dict(self.owned, mask='255.255.255.0')):
            with self.subTest(route=changed), mock.patch.object(self.gate, 'system', return_value=(self.route(changed), '')), self.assertRaises(ValueError):
                self.gate.private_alias_route(self.address)
        with mock.patch.object(self.gate, 'system', return_value=(self.route(self.owned), '')):
            self.assertEqual(self.gate.private_alias_route(self.address), self.owned)

    def test_joined_alias_retirement_deletes_only_original_address_and_reads_absence(self):
        replies = [(self.present, ''), (self.route(self.owned), ''), ('', ''),
                   (self.absent, ''), (self.route(self.before), '')]
        with mock.patch.object(self.gate, 'system', side_effect=replies) as call:
            self.gate.retire_private_alias(self.address, self.before, self.owned)
        self.assertEqual([item.args[0] for item in call.call_args_list], [
            ['/sbin/ifconfig', '-a'], ['/sbin/route', '-n', 'get', self.address],
            ['/sbin/ifconfig', 'lo0', 'inet', self.address, '-alias'],
            ['/sbin/ifconfig', '-a'], ['/sbin/route', '-n', 'get', self.address]])

    def test_partial_creation_is_joined_but_changed_route_never_deleted(self):
        with mock.patch.object(self.gate, 'system', side_effect=[(self.present, ''), (self.route(self.owned), ''), ('', ''), (self.absent, ''), (self.route(self.before), '')]):
            self.gate.retire_private_alias(self.address, self.before, None)
        with mock.patch.object(self.gate, 'system', side_effect=[(self.present, ''), (self.route(dict(self.owned, gateway='10.254.77.11')), '')]) as call, self.assertRaises(ValueError):
            self.gate.retire_private_alias(self.address, self.before, self.owned)
        self.assertFalse(any('-alias' in item.args[0] for item in call.call_args_list))
        with mock.patch.object(self.gate, 'system', side_effect=[(self.absent, ''), (self.absent, ''), (self.route(dict(self.before, gateway='192.0.2.2')), '')]), self.assertRaises(ValueError):
            self.gate.retire_private_alias(self.address, self.before, self.owned)

    def test_nondefault_post_removal_route_preserves_exact_evidence_without_delete(self):
        observed = dict(self.owned, gateway='10.254.77.11', flags='<UP,HOST,DONE,WASCLONED>')
        shown = io.StringIO()
        replies = [(self.absent, ''), (self.absent, ''), (self.route(observed), '')]
        with contextlib.redirect_stderr(shown), mock.patch.object(self.gate, 'system', side_effect=replies) as call, \
             self.assertRaisesRegex(ValueError, 'nondefault route'):
            self.gate.retire_private_alias(self.address, self.before, self.owned)
        evidence = json.loads(shown.getvalue().split(': ', 1)[1])
        self.assertEqual(evidence, {'address': self.address, 'phase': 'after-removal',
                         'original': self.before, 'captured': self.owned, 'observed': observed})
        self.assertEqual(call.call_count, 3)
        self.assertFalse(any('-alias' in item.args[0] or 'delete' in item.args[0] for item in call.call_args_list))

    def test_default_derived_host_cache_requires_unchanged_parent_without_route_delete(self):
        clone = dict(self.before, destination=self.address,
                     flags='<UP,GATEWAY,HOST,DONE,WASCLONED,IFSCOPE,IFREF,GLOBAL>')
        for fault in ('none', 'gateway', 'interface', 'destination', 'flags', 'parent'):
            with self.subTest(fault=fault):
                observed, parent = dict(clone), dict(self.before)
                if fault == 'gateway': observed['gateway'] = '192.0.2.2'
                if fault == 'interface': observed['interface'] = 'en1'
                if fault == 'destination': observed['destination'] = '10.254.77.11'
                if fault == 'flags': observed['flags'] = observed['flags'][:-1] + ',REJECT>'
                if fault == 'parent': parent['gateway'] = '192.0.2.2'
                replies = [(self.absent, ''), (self.absent, ''), (self.route(observed), ''),
                           (self.route(parent), '')]
                with mock.patch.object(self.gate, 'system', side_effect=replies) as call:
                    if fault == 'none':
                        self.gate.retire_private_alias(self.address, self.before, self.owned)
                    else:
                        with self.assertRaises(ValueError):
                            self.gate.retire_private_alias(self.address, self.before, self.owned)
                commands = [item.args[0] for item in call.call_args_list]
                self.assertFalse(any('delete' in cmd or '-alias' in cmd for cmd in commands))
                if fault in ('none', 'parent'):
                    self.assertEqual(commands[-1], ['/sbin/route', '-n', 'get', 'default'])

    def test_changed_pre_removal_route_is_bounded_and_diagnostic_failure_preserves_refusal(self):
        observed = dict(self.owned, gateway='x'*1000)
        for broken in (False, True):
            with self.subTest(broken=broken):
                shown = io.StringIO()
                sink = mock.Mock(write=mock.Mock(side_effect=OSError('closed diagnostic'))) if broken else shown
                with contextlib.redirect_stderr(sink), \
                     mock.patch.object(self.gate, 'system', side_effect=[(self.present, ''), (self.route(observed), '')]) as call, \
                     self.assertRaisesRegex(ValueError, 'changed before retirement'):
                    self.gate.retire_private_alias(self.address, self.before, self.owned)
                self.assertEqual(call.call_count, 2)
                if not broken:
                    evidence = json.loads(shown.getvalue().split(': ', 1)[1])
                    self.assertEqual(evidence['phase'], 'before-removal')
                    self.assertEqual(evidence['observed']['gateway'], 'x'*128)
                    self.assertLess(len(shown.getvalue()), 1200)

    def verdicts(self, case='SOCKSAssociations'):
        root = self.gate.native_case_name(case)
        names = [root]+[root+'/ipv'+family for family in ('4', '6')]
        if case == 'SOCKSAssociations':
            names += [root+'/ipv'+family+'/'+leaf for family in ('4', '6') for leaf in self.gate.SOCKS_LEAVES]
        return ['--- PASS: '+name+' (0.01s)' for name in names]

    def test_all_twenty_three_actual_socks_verdicts_are_required_once(self):
        lines = self.verdicts()
        self.assertEqual(len(lines), 23)
        self.gate.require_socks_verdicts('\n'.join(lines))
        for line in lines:
            for change in ('', line+'\n'+line, 'diagnostic '+line, line.replace('PASS', 'FAIL'), line.replace('PASS', 'SKIP')):
                with self.subTest(line=line, change=change), self.assertRaises(ValueError):
                    self.gate.require_socks_verdicts('\n'.join(lines).replace(line, change, 1))
        for failure in ('WARNING: DATA RACE', 'panic: fixture', 'fatal error: fixture', 'FAIL package [build failed]'):
            with self.subTest(failure=failure), self.assertRaises(ValueError):
                self.gate.require_socks_verdicts('\n'.join(lines+[failure]))

    def test_independent_expiry_requires_exact_parent_root_and_both_families(self):
        case = 'SOCKSDerivedExpiry'
        lines = self.verdicts(case)
        self.assertEqual(len(lines), 3)
        output = '\n'.join(lines)
        self.gate.require_socks_verdicts(output, case)
        for line in lines:
            for change in ('', line+'\n'+line, 'diagnostic '+line,
                           line.replace('PASS', 'FAIL'), line.replace('PASS', 'SKIP')):
                with self.subTest(line=line, change=change), self.assertRaises(ValueError):
                    self.gate.require_socks_verdicts(output.replace(line, change, 1), case)
        for changed in ('\n'.join(self.verdicts()), output.replace('/ipv6', '/ipv4'),
                        output+'\n--- PASS: '+self.gate.native_case_name(case)+'/unexpected (0.01s)',
                        output+'\nWARNING: DATA RACE', output+'\npanic: fixture'):
            with self.subTest(output=changed), self.assertRaises(ValueError):
                self.gate.require_socks_verdicts(changed, case)
        with self.assertRaises(ValueError):
            self.gate.require_socks_verdicts(output, 'TCPAndUDP')

    def test_manual_renewal_capture_requires_every_original_ownership_case(self):
        gate = self.gate
        names = [gate.RENEWAL_CAPTURE_ROOT]+[gate.RENEWAL_CAPTURE_ROOT+'/'+leaf for leaf in gate.RENEWAL_CAPTURE_CASES]
        lines = ['--- PASS: '+name+' (0.01s)' for name in names]
        gate.require_renewal_capture_verdicts('\n'.join(lines))
        for index in range(len(lines)):
            for changed in (lines[:index]+lines[index+1:], lines+[lines[index]],
                            lines[:index]+[lines[index].replace('PASS', 'SKIP')]+lines[index+1:]):
                with self.assertRaises(ValueError):
                    gate.require_renewal_capture_verdicts('\n'.join(changed))
        selector = next(arg.removeprefix('-test.run=') for arg in gate.native_test_arguments() if arg.startswith('-test.run='))
        self.assertRegex(gate.RENEWAL_CAPTURE_ROOT, selector)

    def test_every_required_case_has_one_bounded_fixture_selection(self):
        gate = self.gate
        cases = gate.CASES+gate.READBACK_CASES+gate.SOCKS_CASES
        selected = []
        for case in (None,)+gate.SEPARATE_CASES:
            arguments = gate.native_test_arguments(case)
            self.assertIn('-test.timeout=12m', arguments)
            self.assertIn('-test.count=1', arguments)
            run = next(argument.removeprefix('-test.run=') for argument in arguments if argument.startswith('-test.run='))
            skip = next((argument.removeprefix('-test.skip=') for argument in arguments if argument.startswith('-test.skip=')), None)
            selected += [name for name in cases if re.search(run, gate.native_case_name(name)) and
                         (skip is None or not re.search(skip, gate.native_case_name(name)))]
            self.assertRegex('TestDesktopPFABIRejectsUnprovedKernel', run)
        self.assertCountEqual(selected, cases)
        self.assertEqual(len(selected), len(set(selected)))
        with self.assertRaises(ValueError):
            gate.native_test_arguments('unregistered-case')

    def test_default_gate_runs_separate_owned_fixtures_and_requires_every_verdict(self):
        gate = self.gate
        original = ['--- PASS: '+gate.native_case_name(name)+' (0.01s)' for name in gate.CASES+gate.READBACK_CASES
                    if name not in gate.SEPARATE_CASES]
        original += ['--- PASS: TestDesktopPFABIRejectsUnprovedKernel (0.01s)']
        original += ['--- PASS: '+name+' (0.01s)' for name in (gate.RENEWAL_CAPTURE_ROOT,)+tuple(gate.RENEWAL_CAPTURE_ROOT+'/'+leaf for leaf in gate.RENEWAL_CAPTURE_CASES)]
        original += ['--- PASS: TestDesktopDarwinGuardian'+name+' (0.01s)' for name in
                     ('ChannelFragmentsAndDescriptorClosure', 'CurrentFreshnessAndStateScope', 'UIDAbsenceWait', 'UIDObserverProtocol')]
        original += ['--- PASS: TestDesktopDarwinGuardianKernelTCPAndUDP/'+network+' (0.01s)' for network in ('tcp4', 'udp4', 'tcp6', 'udp6')]
        for missing in (None,)+gate.SEPARATE_CASES:
            calls = []
            def run(command, **kwargs):
                calls.append(command)
                if 'test' in command:
                    Path(command[command.index('-o')+1]).write_bytes(b'runner invocation fixture only')
                    return ''
                if '--case' in command:
                    self.assertEqual(kwargs['timeout'], 850)
                    case = command[-1]
                    self.assertIn(case, gate.SEPARATE_CASES)
                    verdicts = self.verdicts(case) if case in gate.SOCKS_CASES else ['--- PASS: '+gate.native_case_name(case)+' (0.01s)']
                    return '\n'.join(verdicts[1:] if missing == case else verdicts)+'\n'
                return '\n'.join(original)+'\n'
            with self.subTest(missing=missing), mock.patch.object(gate.platform, 'system', return_value='Darwin'), mock.patch.dict(os.environ, {'GOOS': 'darwin'}), mock.patch.object(gate.UID, 'compiler_toolchain', side_effect=lambda source, go, env: ('fixture-go', env)), mock.patch.object(gate.UID, 'privilege_tool', return_value=None), mock.patch.object(gate, 'reported_run', side_effect=run), contextlib.redirect_stdout(io.StringIO()):
                if missing:
                    with self.assertRaises(ValueError):
                        gate.execute(ROOT)
                else:
                    gate.execute(ROOT)
            expected = gate.SEPARATE_CASES
            if missing in gate.SOCKS_CASES:
                expected = expected[:expected.index(missing)+1]
            self.assertEqual(len(calls), 2+len(expected))
            self.assertNotIn('--case', calls[1])
            for command, case in zip(calls[2:], expected):
                self.assertEqual(command, calls[1]+['--case', case])

    def test_mutation_requires_exact_assertion_and_join_without_timeout_or_race(self):
        witness = 'SOCKS control retired before its original UDP descriptor'
        line = '--- FAIL: TestDesktopDarwinGuardianKernelSOCKSAssociations (0.01s)'
        output = '    fixture.go:1: '+witness+'\n'+line+'\nFAIL\n'
        self.gate.require_mutation_failure(output, 'SOCKSAssociations', witness)
        for changed in ('diagnostic '+line, line+'\n'+line, line.replace('FAIL', 'PASS'), ''):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                self.gate.require_mutation_failure(output.replace(line, changed), 'SOCKSAssociations', witness)
        for failure in ('panic: test timed out', 'WARNING: DATA RACE', 'fatal error: fixture',
                        'Native fixture cleanup retained its recovery record', 'Darwin kernel test exceeded its bounded lifetime',
                        '--- SKIP: MissingBoundary (0.00s)', 'FAIL package [build failed]'):
            with self.subTest(failure=failure), self.assertRaises(ValueError):
                self.gate.require_mutation_failure(output+failure, 'SOCKSAssociations', witness)

    def test_six_controls_are_shipping_source_mutations_with_exact_required_witnesses(self):
        tree = ast.parse(Path(self.gate.__file__).read_text())
        function = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'execute_mutations')
        assignment = next(node for node in function.body if isinstance(node, ast.Assign) and any(isinstance(name, ast.Name) and name.id == 'mutations' for name in node.targets))
        mutations = [value for value in ast.literal_eval(assignment.value) if value[1] in self.gate.SOCKS_CASES]
        self.assertEqual(len(mutations), 6)
        self.assertEqual(len({value[0] for value in mutations}), 6)
        self.assertEqual(sum(value[1] == 'SOCKSAssociations' for value in mutations), 5)
        test = (ROOT/'internal/mobiletor/desktop_socket_darwin_guardian_test.go').read_text()
        for label, _, witness, name, replacements in mutations:
            self.assertIn(witness, test)
            names, changes = ((name,), (replacements,)) if isinstance(name, str) else (name, replacements)
            for path, edits in zip(names, changes):
                raw = (ROOT/'internal/mobiletor'/path).read_text()
                for old, new in edits:
                    self.assertEqual(raw.count(old), 1, label)
                    self.assertNotEqual(old, new)

    def test_expiry_mutation_changes_only_cap_and_requires_its_own_assertion(self):
        tree = ast.parse(Path(self.gate.__file__).read_text())
        function = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'execute_mutations')
        assignment = next(node for node in function.body if isinstance(node, ast.Assign) and any(isinstance(name, ast.Name) and name.id == 'mutations' for name in node.targets))
        controls = [value for value in ast.literal_eval(assignment.value) if value[0] == 'SOCKS derived expiry cap']
        self.assertEqual(len(controls), 1)
        label, case, witness, name, changes = controls[0]
        self.assertEqual(case, 'SOCKSDerivedExpiry')
        self.assertIn(case, self.gate.SOCKS_CASES)
        self.assertIn(case, self.gate.SEPARATE_CASES)
        self.assertEqual(name, 'desktop_socket_darwin_socks_pf.go')
        self.assertEqual(changes, (('if until.Before(expires) {', 'if false && until.Before(expires) {'),))
        with tempfile.TemporaryDirectory(prefix='routervpn-expiry-mutation-') as directory:
            overlay = self.gate.write_mutation_overlay(Path(directory), 0, ROOT/'internal/mobiletor', name, changes, label)
            self.assertEqual(set(json.loads(overlay.read_text())['Replace']), {str(ROOT/'internal/mobiletor'/name)})
        verdict = '--- FAIL: '+self.gate.native_case_name(case)+' (0.01s)'
        output = '    fixture.go:1: '+witness+'\n'+verdict+'\nFAIL\n'
        self.gate.require_mutation_failure(output, case, witness)
        for replaced in ('Darwin renewed relay outlived its retained original control',
                         'actual selected-private UDP association: context canceled'):
            with self.subTest(witness=replaced), self.assertRaises(ValueError):
                self.gate.require_mutation_failure(output.replace(witness, replaced), case, witness)
        for failure in ('Darwin native broker did not drain', 'actual Darwin guardian close',
                        'Native fixture cleanup retained its recovery record', 'test timed out', 'WARNING: DATA RACE'):
            with self.subTest(failure=failure), self.assertRaises(ValueError):
                self.gate.require_mutation_failure(output+failure, case, witness)


class MacOSPythonDiscovery(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='routervpn-python-discovery-')
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        source = (ROOT / 'client/install-macos-native.sh').read_text()
        start = source.index('routervpn_discover_install_python() {\n')
        self.function = source[start:source.index('\n}\n', start) + 3]

    def candidate(self, name, code=0, executable=True):
        path = self.root / name
        path.write_text('#!/bin/sh\n'
                        '[ "$1" = -EsS ] && [ "$2" = -c ] && [ "$#" -eq 3 ] || exit 91\n'
                        'printf ran >> ' + shlex.quote(str(self.root / (name + '.ran'))) + '\n'
                        'printf suppressed-output\n'
                        'exit ' + str(code) + '\n')
        path.chmod(0o700 if executable else 0o600)
        return path

    def discover(self, *candidates, env=None):
        return subprocess.run(['/bin/bash', '-c', self.function + '\nroutervpn_discover_install_python "$@"',
                               'discovery-fixture', *map(str, candidates)], cwd=self.root,
                              env=env, text=True, capture_output=True, timeout=5)

    def test_actual_shipping_selector_preserves_priority_and_hides_probe_output(self):
        first, second = self.candidate('first'), self.candidate('second')
        result = self.discover(first, second)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, str(first) + '\n')
        self.assertFalse((self.root / 'second.ran').exists())

    def test_actual_shipping_selector_skips_missing_nonexecuting_and_unsupported_candidates(self):
        blocked, old, selected = self.candidate('blocked', executable=False), self.candidate('old', code=1), self.candidate('selected')
        result = self.discover(self.root / 'missing', blocked, old, selected)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, str(selected) + '\n')
        self.assertFalse((self.root / 'blocked.ran').exists())
        self.assertTrue((self.root / 'old.ran').exists())

    def test_actual_shipping_selector_never_substitutes_ambient_path_python(self):
        self.candidate('python3')
        result = self.discover(self.root / 'missing', env=dict(os.environ, PATH=str(self.root)))
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, '')
        self.assertIn('Install Python 3.9 or newer', result.stderr)
        self.assertFalse((self.root / 'python3.ran').exists())

    def test_native_wrapper_captures_ordinary_user_before_any_discovery_execution(self):
        gate = GATES[1]
        account = type('Account', (), {'pw_gid': 41, 'pw_dir': '/Users/fixture'})()
        reply = subprocess.CompletedProcess([], 0, '/Library/Developer/CommandLineTools/usr/bin/python3\n', '')
        with mock.patch.object(gate.os, 'geteuid', return_value=0), mock.patch.object(gate.pwd, 'getpwuid', return_value=account), mock.patch.object(gate.subprocess, 'run', return_value=reply) as run:
            self.assertEqual(gate.discover_python(501), reply.stdout.rstrip('\n'))
            arguments, options = run.call_args
            self.assertEqual(arguments[0], ['/bin/bash', str(ROOT / 'client/install-macos-native.sh'), '--discover-python'])
            self.assertEqual((options['user'], options['group'], options['extra_groups']), (501, 41, []))
            self.assertEqual(options['env'], {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'HOME': '/Users/fixture', 'LC_ALL': 'C'})
        with mock.patch.object(gate.os, 'geteuid', return_value=0), mock.patch.object(gate.subprocess, 'run') as run:
            with self.assertRaises(ValueError):
                gate.discover_python(0)
            run.assert_not_called()


class DarwinOriginalControlLifetime(unittest.TestCase):
    def test_actual_control_method_joins_rejected_grant_and_revoke_and_preserves_other_operations(self):
        spec = importlib.util.spec_from_file_location('darwin_control_lifetime', ROOT/'deploy/test_desktop_darwin_control_lifetime.py')
        regression = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(regression)
        regression.execute(ROOT)


class DarwinOriginalReadbackObservation(unittest.TestCase):
    def test_actual_command_retains_original_owner_while_native_boundary_is_pending(self):
        spec = importlib.util.spec_from_file_location('darwin_original_observation', ROOT/'deploy/test_desktop_darwin_observation.py')
        regression = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(regression)
        regression.execute(ROOT)


class DarwinSOCKSCleanupOwnership(unittest.TestCase):
    def test_actual_registration_reaches_bounded_owner_before_blocked_connection_close(self):
        source = (ROOT/'internal/mobiletor/desktop_socket_darwin_guardian_test.go').read_text()
        start = source.index('func desktopDarwinKernelBroker(')
        helper = source[start:source.index('\nfunc desktopDarwinKernelTrace(', start)]
        case = source[source.index('func TestDesktopDarwinGuardianKernelSOCKSAssociations('):]
        snippets = []
        for name, collection in (('control', 'controls'), ('relay', 'relays')):
            begin = f'{collection} = append({collection}, {name})'
            end = f'desktopDarwinExchange(t, {name})'
            self.assertEqual(case.count(begin), 1)
            self.assertEqual(case.count(end), 1)
            snippets.append(case[case.index(begin):case.index(end)])
        variants = {'baseline': '\n'.join(snippets)}
        for selected in ('control', 'relay', 'both'):
            parts = list(snippets)
            for index, name in enumerate(('control', 'relay')):
                if selected in (name, 'both'):
                    parts[index] += f'\nt.Cleanup(func() {{ _ = {name}.Close() }})\n'
            variants[selected] = '\n'.join(parts)
        header = r'''package cleanup
import("context";"io";"os";"sync";"syscall";"testing";"time")
type processBoundary struct{}
func(*processBoundary)Signal(os.Signal)error{return nil}
type commandBoundary struct{Process *processBoundary}
type DesktopDarwinSocketPolicy struct{capture int;command commandBoundary}
type DesktopSocketBroker struct{events chan string;release chan struct{};once sync.Once}
var original *DesktopSocketBroker
func NewDesktopSocketBroker(context.Context,int,*DesktopDarwinSocketPolicy,func()bool)(*DesktopSocketBroker,error){return original,nil}
func(b *DesktopSocketBroker)Close(context.Context)error{b.events<-"bounded-owner-cleanup";b.once.Do(func(){close(b.release)});return nil}
func desktopDarwinKernelTrace(*testing.T,*DesktopDarwinSocketPolicy,*DesktopSocketBroker){}
func desktopDarwinKernelReadbackTrace(*testing.T,*DesktopDarwinSocketPolicy,string){}
type heldConnection struct{name string;owner *DesktopSocketBroker}
func(c *heldConnection)Close()error{c.owner.events<-"direct-"+c.name+"-close";<-c.owner.release;return nil}
'''
        registrations = ''
        for name, snippet in variants.items():
            registrations += ('\nfunc register_'+name+'(t *testing.T,control,relay io.Closer){\n'
                              'var controls,relays []io.Closer\n'+snippet+'\n_ = controls;_ = relays\n}\n')
        test = r'''
func TestShippingSOCKSCleanupRegistration(t *testing.T){
 original=&DesktopSocketBroker{events:make(chan string,8),release:make(chan struct{})}
 policy:=&DesktopDarwinSocketPolicy{command:commandBoundary{Process:&processBoundary{}}}
 control:=&heldConnection{"control",original};relay:=&heldConnection{"relay",original}
 joined:=make(chan struct{})
 go func(){defer close(joined);t.Run("actual-cleanup-stack",func(t *testing.T){
  broker:=desktopDarwinKernelBroker(t,policy);if broker!=original{t.Fatal("cleanup replaced original owner")}
  switch os.Getenv("ROUTERVPN_CLEANUP_VARIANT"){
   case "baseline":register_baseline(t,control,relay)
   case "control":register_control(t,control,relay)
   case "relay":register_relay(t,control,relay)
   case "both":register_both(t,control,relay)
   default:t.Fatal("unknown cleanup variant")
  }
 })}()
 var first string
 select{case first=<-original.events:case <-time.After(2*time.Second):t.Fatal("cleanup made no observable progress")}
 // Join even the historical bad ordering: a rejection is the wrong first
 // retirement event, never a timeout or a deliberately leaked goroutine.
 original.once.Do(func(){close(original.release)})
 select{case <-joined:case <-time.After(2*time.Second):t.Fatal("cleanup did not join after captured release")}
 if first!="bounded-owner-cleanup"{t.Fatal("direct connection cleanup blocked the original bounded broker owner",first)}
}
'''
        compiler = shutil.which('go')
        self.assertIsNotNone(compiler, 'Go is required for actual cleanup registration regression')
        with tempfile.TemporaryDirectory(prefix='darwin-socks-cleanup-') as directory:
            folder = Path(directory)
            implementation, regression = folder/'cleanup.go', folder/'cleanup_test.go'
            implementation.write_text(header+helper+registrations)
            regression.write_text('package cleanup\nimport("os";"testing";"time")\n'+test)
            # Actual testing.T drives the extracted registration sequence.
            # Native policy/socket boundaries model only ownership ordering.
            binary = folder/('cleanup.test.exe' if os.name == 'nt' else 'cleanup.test')
            built = subprocess.run([compiler,'test','-race','-c','-o',str(binary),str(implementation),str(regression)],
                                   capture_output=True,text=True,timeout=120,
                                   env=dict(os.environ,GOTOOLCHAIN='local'))
            self.assertEqual(built.returncode,0,built.stdout+built.stderr)
            for variant in variants:
                result = subprocess.run([str(binary),'-test.run=^TestShippingSOCKSCleanupRegistration$','-test.v','-test.timeout=10s'],
                                        capture_output=True,text=True,timeout=15,
                                        env=dict(os.environ,ROUTERVPN_CLEANUP_VARIANT=variant))
                output=result.stdout+result.stderr
                if variant=='baseline':
                    self.assertEqual(result.returncode,0,output)
                    self.assertIn('--- PASS: TestShippingSOCKSCleanupRegistration (',output)
                else:
                    self.assertNotEqual(result.returncode,0,output)
                    self.assertIn('direct connection cleanup blocked the original bounded broker owner',output)
                    self.assertIn('--- FAIL: TestShippingSOCKSCleanupRegistration (',output)
                    for invalid in ('panic:','fatal error:','WARNING: DATA RACE','[build failed]','cleanup did not join','cleanup made no observable progress'):
                        self.assertNotIn(invalid,output)
                print('Darwin SOCKS cleanup: '+variant+' verified',flush=True)


class DarwinCreatorAdmission(unittest.TestCase):
    def test_actual_admission_rejects_expired_completion_and_cancellation_during_identity(self):
        # Execute the shipping method with actual owned file descriptors.
        # Only Darwin's libproc identity read is modeled; the native suite
        # separately checks this same method with real kernel socket identity.
        source = (ROOT/'internal/mobiletor/desktop_socket_darwin_helper.go').read_text()
        start = 'func (g *desktopDarwinGuardian) adoptCreatedSocket('
        end = '\nfunc (g *desktopDarwinGuardian) bind('
        self.assertEqual(source.count(start), 1)
        self.assertEqual(source.count(end), 1)
        method = source[source.index(start):source.index(end)]
        header = r'''package creator
import("context";"errors";"os")
type DesktopSocketCreation struct{SocketID,Network string}
type DesktopSocketGrant struct{}
type desktopDarwinKernelSocket struct{uid uint32;network string}
type desktopDarwinOwnedSocket struct{creation DesktopSocketCreation;file *os.File;identity desktopDarwinKernelSocket;grants map[string]DesktopSocketGrant}
type desktopDarwinGuardian struct{uid uint32;sockets map[string]*desktopDarwinOwnedSocket}
var inspect func(*os.File)(desktopDarwinKernelSocket,error)
func desktopDarwinSocketIdentity(f *os.File)(desktopDarwinKernelSocket,error){return inspect(f)}
'''
        test = r'''package creator
import("context";"errors";"os";"testing";"time")
func TestShippingCreatorAdmission(t *testing.T){
 for _,mode:=range []string{"live","cancelled","expired","during-identity","identity-error"}{t.Run(mode,func(t *testing.T){
  f,err:=os.CreateTemp(t.TempDir(),"original");if err!=nil{t.Fatal(err)};defer f.Close()
  retained:=&desktopDarwinOwnedSocket{};g:=&desktopDarwinGuardian{uid:41,sockets:map[string]*desktopDarwinOwnedSocket{"retained":retained}}
  c:=DesktopSocketCreation{"original","udp"};ctx,cancel:=context.WithCancel(context.Background());defer cancel()
  var want error
  switch mode{case "cancelled":cancel();want=context.Canceled
  case "expired":var stop context.CancelFunc;ctx,stop=context.WithDeadline(context.Background(),time.Now().Add(-time.Second));defer stop();want=context.DeadlineExceeded
  case "during-identity","identity-error":want=context.Canceled}
  calls:=0;identity:=desktopDarwinKernelSocket{41,"udp"}
  inspect=func(actual *os.File)(desktopDarwinKernelSocket,error){calls++;if actual!=f{t.Fatal("replaced original descriptor")};if mode=="during-identity"||mode=="identity-error"{cancel()};if mode=="identity-error"{return identity,os.ErrClosed};return identity,nil}
  got,err:=g.adoptCreatedSocket(ctx,c,f)
  if g.sockets["retained"]!=retained{t.Fatal("changed retained owner")}
  if want!=nil{
   if got!=nil||!errors.Is(err,want)||len(g.sockets)!=1{t.Fatal("late creator completion acquired socket authority",got,err)}
   if _,err:=f.Stat();!errors.Is(err,os.ErrClosed){t.Fatal("late descriptor was not closed",err)}
   if (mode=="cancelled"||mode=="expired")&&calls!=0{t.Fatal("expired creator completion entered kernel inspection")}
   if mode=="identity-error"&&!errors.Is(err,os.ErrClosed){t.Fatal("identity error was discarded",err)}
  }else{owned:=g.sockets[c.SocketID];if err!=nil||got!=f||len(g.sockets)!=2||owned==nil||owned.creation!=c||owned.file!=f||owned.identity!=identity{t.Fatal("live completion lost original authority",err)};if _,err:=f.Stat();err!=nil{t.Fatal("live descriptor was closed",err)}}
 })}
}
'''
        guard = '\tif err := ctx.Err(); err != nil {\n\t\tfile.Close()\n\t\treturn nil, err\n\t}\n'
        self.assertEqual(method.count(guard), 2)
        variants = [('baseline', method, None),
                    ('expired-inspection', method.replace(guard, '', 1), 'expired creator completion entered kernel inspection'),
                    ('late-adoption', method[:method.rindex(guard)]+method[method.rindex(guard)+len(guard):],
                     'late creator completion acquired socket authority')]
        compiler = shutil.which('go')
        self.assertIsNotNone(compiler, 'Go is required for shipping creator admission regression')
        with tempfile.TemporaryDirectory(prefix='darwin-creator-admission-') as directory:
            folder = Path(directory)
            implementation, regression = folder/'creator.go', folder/'creator_test.go'
            regression.write_text(test)
            for label, selected, witness in variants:
                implementation.write_text(header+selected)
                result = subprocess.run([compiler, 'test', '-race', '-v', '-timeout=20s', str(implementation), str(regression)],
                                        capture_output=True, text=True, timeout=120,
                                        env=dict(os.environ, GOTOOLCHAIN='local'))
                output = result.stdout+result.stderr
                if witness is None:
                    self.assertEqual(result.returncode, 0, output)
                    self.assertEqual(output.count('--- PASS: TestShippingCreatorAdmission/'), 5, output)
                else:
                    self.assertNotEqual(result.returncode, 0, output)
                    self.assertIn(witness, output)
                    for invalid in ('panic:', 'fatal error:', 'WARNING: DATA RACE', '[build failed]'):
                        self.assertNotIn(invalid, output)
                print('Darwin creator admission: '+label+' verified', flush=True)


if __name__ == '__main__':
    unittest.main(verbosity=2)
