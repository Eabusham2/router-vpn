#!/usr/bin/env python3
"""Check the real fixture writer's test-clock/Apple-SDK source boundary.

Only compiler/process execution is substituted here. Native Swift execution and
the real iOS SDK acceptance remain mandatory in test_ios_via_entry_candidates.py.
"""
from pathlib import Path
import ast
import contextlib
import errno
import importlib.util
import io
import select
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    'via_entry_fixture', ROOT / 'deploy/test_ios_via_entry_candidates.py')
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)


class ViaEntrySourceBoundary(unittest.TestCase):
    def run_gate(self, negative_result=None, *, phase=None, actor_result=None, require_overlap=False, fail_mutant_compile=False):
        original = (GATE.APP / 'IOSViaEntryTCP.swift').read_text()
        sdk_sources = []
        executable_sources = []
        executions = []
        compiled_paths = []
        baseline_sources = {}
        baseline_running = threading.Event()
        mutant_compiled = threading.Event()
        witnesses = (
            'actual routed comparison has fifty samples',
            'actual summary removes five samples at each end',
            'receipt selects robust fifty-sample winner',
            'a network change during teardown cannot adopt old results onto the new path',
            'Cancel is not fabricated socket drain: cancel',
            'direct measurements require captured physical interface',
        )

        def run(command, **options):
            if '-emit-module' in command:
                self.assertEqual(options, dict(check=True, timeout=120))
                return subprocess.CompletedProcess(command, 0)
            if '-sdk' in command:
                self.assertEqual(options['timeout'], 120)
                self.assertNotIn('-I', command)
                self.assertNotIn('-lNetwork', command)
                helper = next(Path(value) for value in command if str(value).endswith('/ActualTCP.swift'))
                source = helper.read_text()
                sdk_sources.append(source)
                self.assertNotIn('NWTest', source)
                self.assertEqual(source.count('DispatchTime.now().uptimeNanoseconds'), 2)
                if phase != 'sdk-actor' and len(sdk_sources) == 1:
                    self.assertEqual(source, original)
                    return subprocess.CompletedProcess(command, 0)
                self.assertIn('static func measure(_ target: RouterProfile,', source)
                if actor_result is not None:
                    return subprocess.CompletedProcess(command, *actor_result)
                return subprocess.CompletedProcess(command, 1, '', "sending 'candidate' risks causing data races")
            if '-parse-as-library' in command:
                self.assertEqual(options['timeout'], 150)
                helper = next(Path(value) for value in command if str(value).endswith('/IOSViaEntryTCP.swift'))
                source = helper.read_text()
                output = Path(command[command.index('-o') + 1])
                if not executable_sources:
                    baseline_sources.update({Path(value): Path(value).read_text()
                                             for value in command if str(value).endswith('.swift')})
                elif 'static func measure(_ target: RouterProfile,' not in source:
                    self.assertNotIn(output, compiled_paths, 'mutant overwrote another compiled executable')
                    self.assertNotIn(helper, baseline_sources, 'mutant reused a running baseline source path')
                    for path, captured in baseline_sources.items():
                        self.assertEqual(path.read_text(), captured, 'mutant changed a baseline compiler input')
                    if require_overlap:
                        self.assertTrue(baseline_running.wait(2), 'mutant compiler did not overlap baseline execution')
                    if fail_mutant_compile:
                        raise subprocess.CalledProcessError(1, command)
                    mutant_compiled.set()
                compiled_paths.append(output)
                executable_sources.append(source)
                self.assertEqual(source.count('NWTest.shared.measurementNow()'), 2)
                self.assertNotIn('DispatchTime.now().uptimeNanoseconds', source)
                if 'static func measure(_ target: RouterProfile,' in source:
                    if actor_result is not None:
                        return subprocess.CompletedProcess(command, *actor_result)
                    return subprocess.CompletedProcess(command, 1, '', "IOSViaEntryLatency.swift: sending 'candidate' risks causing data races")
                return subprocess.CompletedProcess(command, 0)
            target = (None, 'statistics', 'statistics', 'statistics', 'retirement-network', 'socket-drain', 'physical-binding')[len(executions)]
            self.assertEqual(command[1:], [] if target is None else [target])
            self.assertEqual(Path(command[0]).name, 'tests')
            self.assertEqual(options['timeout'], 120)
            executions.append(command)
            if len(executions) == 1:
                baseline_running.set()
                if require_overlap:
                    self.assertTrue(mutant_compiled.wait(2), 'baseline waited for sequential mutant compilation')
                return subprocess.CompletedProcess(command, 0, 'substituted executable', '')
            if negative_result is not None:
                return subprocess.CompletedProcess(command, *negative_result)
            return subprocess.CompletedProcess(command, 1, '', 'FAIL: ' + witnesses[len(executions) - 2])

        with patch.object(GATE.shutil, 'which', return_value='/fixture/swiftc'), \
             patch('platform.system', return_value='Darwin'), \
             patch.object(GATE.subprocess, 'check_output', return_value='/fixture/iphoneos-sdk\n'), \
             patch.object(GATE.subprocess, 'run', side_effect=run), \
             patch.object(GATE.OwnedCandidateCompiler, 'run', side_effect=run), \
             contextlib.redirect_stdout(io.StringIO()) as output:
            GATE.main(phase)
        expected = {None: (7, 8, 2), 'runtime': (7, 7, 0), 'actor': (0, 1, 0), 'sdk': (0, 0, 1), 'sdk-actor': (0, 0, 1)}[phase]
        self.assertEqual((len(executions), len(executable_sources), len(sdk_sources)), expected)
        self.assertEqual(len(set(compiled_paths)), expected[1])
        receipts = [line for line in output.getvalue().splitlines() if line.startswith(GATE.PHASE_RECEIPT)]
        self.assertEqual(receipts, [GATE.PHASE_RECEIPT + name for name in (GATE.PHASES if phase is None else (phase,))])
        self.assertEqual((GATE.APP / 'IOSViaEntryTCP.swift').read_text(), original)

    def test_exact_targeted_mutations_preserve_the_full_baseline_and_real_sdk_clock(self):
        self.run_gate()

    def test_independent_phases_keep_the_exact_complete_native_inventory(self):
        for phase in GATE.PHASES:
            with self.subTest(phase=phase):
                self.run_gate(phase=phase)

    def test_real_sdk_phase_cannot_be_substituted_with_a_portable_host(self):
        for phase in ('sdk', 'sdk-actor'):
            with self.subTest(phase=phase), patch('platform.system', return_value='Linux'), \
                 patch.object(GATE.subprocess, 'run') as compiler, \
                 self.assertRaisesRegex(RuntimeError, 'native Darwin host'):
                GATE.main(phase)
            compiler.assert_not_called()

    def test_targeted_negative_must_fail_at_its_own_assertion(self):
        for result, message in [((0, 'unexpected pass', ''), 'Negative control escaped'),
                                ((1, '', 'FAIL: unrelated witness'), 'failed at an unrelated witness'),
                                ((1, '', 'compiler/runtime crashed'), 'Negative control escaped')]:
            with self.subTest(result=result), self.assertRaisesRegex(AssertionError, message):
                self.run_gate(result)

    def test_both_actor_phases_require_the_original_swift_diagnostic(self):
        for phase in ('actor', 'sdk-actor'):
            for result in ((0, 'unsafe source accepted', ''), (1, '', 'unrelated compiler error')):
                with self.subTest(phase=phase, result=result), self.assertRaisesRegex(AssertionError, 'actor crossing'):
                    self.run_gate(phase=phase, actor_result=result)

    def test_mutant_compilation_overlaps_full_baseline_with_isolated_sources(self):
        self.run_gate(require_overlap=True)

    def test_background_mutant_compiler_failure_cannot_become_acceptance(self):
        with self.assertRaises(subprocess.CalledProcessError):
            self.run_gate(fail_mutant_compile=True)


class ShippingCandidatePhases(unittest.TestCase):
    def execute_shipping_loop(self, receipt=None, fail_phase=None):
        # Execute the shipping contract's actual loop, substituting only its
        # child processes. This catches omission, reordering, receipt replay,
        # swallowed compiler failure and an accidental aggregate timeout.
        path = ROOT / 'ios/RouterVPN/test_runtime_selection_contract.py'
        tree = ast.parse(path.read_text())
        loops = [node for node in ast.walk(tree) if isinstance(node, ast.For)
                 and isinstance(node.target, ast.Name) and node.target.id == 'candidate_phase']
        self.assertEqual(len(loops), 1)
        self.assertEqual(ast.literal_eval(loops[0].iter), GATE.PHASES)
        calls = []
        def run(command, **options):
            phase = GATE.PHASES[len(calls)]
            self.assertEqual(command, [sys.executable, str(ROOT / 'deploy/test_ios_via_entry_candidates.py'), '--phase', phase])
            self.assertEqual(options, dict(check=False, timeout=150, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT))
            calls.append(phase)
            output = GATE.PHASE_RECEIPT + phase + '\n' if receipt is None else receipt(phase)
            return subprocess.CompletedProcess(command, 1 if phase == fail_phase else 0, output)
        with patch.object(subprocess, 'run', side_effect=run), contextlib.redirect_stdout(io.StringIO()):
            exec(compile(ast.Module(body=loops, type_ignores=[]), str(path), 'exec'),
                 dict(root=ROOT, sys=sys, subprocess=subprocess))
        self.assertEqual(calls, list(GATE.PHASES))

    def test_shipping_contract_requires_each_exact_phase_with_its_original_bound(self):
        self.execute_shipping_loop()

    def test_missing_wrong_duplicate_or_foreign_receipts_cannot_complete_the_suite(self):
        receipts = {
            'missing': lambda phase: '',
            'wrong': lambda phase: GATE.PHASE_RECEIPT + 'sdk-actor\n',
            'duplicate': lambda phase: (GATE.PHASE_RECEIPT + phase + '\n') * 2,
            'foreign': lambda phase: GATE.PHASE_RECEIPT + phase + '\n' + GATE.PHASE_RECEIPT + 'sdk-actor\n',
        }
        for fault, receipt in receipts.items():
            with self.subTest(fault=fault), self.assertRaises(AssertionError):
                self.execute_shipping_loop(receipt)

    def test_every_phase_failure_prevents_shipping_acceptance(self):
        for phase in GATE.PHASES:
            with self.subTest(phase=phase), self.assertRaises(subprocess.CalledProcessError):
                self.execute_shipping_loop(fail_phase=phase)


class OriginalCompilerLifetime(unittest.TestCase):
    def test_completed_compiler_keeps_a_live_original_group_and_its_exact_exit_status(self):
        # Darwin rejects killpg when the retained group has only zombies. Make
        # that kernel behavior explicit on Linux too, without reaping the
        # original handle before the production cleanup has signalled it.
        spawn, signal_group = subprocess.Popen, GATE.os.killpg
        for exit_status in (0, 7):
            with self.subTest(exit_status=exit_status):
                compiler = GATE.OwnedCandidateCompiler(time.monotonic() + 5)
                handles, acknowledged = [], []
                def capture_original(*arguments, **options):
                    original = spawn(*arguments, **options)
                    handles.append(original)
                    return original
                def signal_live_original(group, sig):
                    self.assertEqual(group, handles[0].pid)
                    self.assertIsNone(handles[0].returncode)
                    if sys.platform.startswith('linux'):
                        exited = GATE.os.waitid(GATE.os.P_PID, group,
                                               GATE.os.WEXITED | GATE.os.WNOHANG | GATE.os.WNOWAIT)
                        if exited is not None and exited.si_pid == group:
                            raise PermissionError(errno.EPERM, 'Darwin refuses a zombie-only process group')
                    signal_group(group, sig)
                    acknowledged.append(group)
                command = [sys.executable, '-c', f'raise SystemExit({exit_status})']
                try:
                    with patch.object(GATE.subprocess, 'Popen', side_effect=capture_original), \
                         patch.object(GATE.os, 'killpg', side_effect=signal_live_original):
                        if exit_status:
                            with self.assertRaises(subprocess.CalledProcessError) as rejected:
                                compiler.run(command, check=True, timeout=5)
                            self.assertEqual(rejected.exception.returncode, exit_status)
                            self.assertEqual(rejected.exception.cmd, command)
                        else:
                            compiler.run(command, check=True, timeout=5)
                    self.assertEqual(len(handles), 1)
                    self.assertEqual(acknowledged, [handles[0].pid])
                    self.assertIsNotNone(handles[0].returncode, 'original group leader was not joined')
                    self.assertIsNone(compiler.process)
                finally:
                    # The causal old-driver regression leaves its already
                    # exited original child unreaped. Join only that handle.
                    for original in handles:
                        original.wait(timeout=2)

    def test_cancellation_drains_original_compiler_descendants_without_signalling_foreign_child(self):
        compiler = GATE.OwnedCandidateCompiler(time.monotonic() + 10)
        result = []
        with tempfile.TemporaryDirectory(prefix='candidate-compiler-') as temporary:
            ready = Path(temporary) / 'ready'
            descendant = 'import pathlib,sys,time;pathlib.Path(sys.argv[1]).write_text("ready");time.sleep(10)'
            command = [sys.executable, '-c',
                       'import subprocess,sys;child=subprocess.Popen([sys.executable,"-c",sys.argv[1],sys.argv[2]]);child.wait()',
                       descendant, str(ready)]
            spawn = subprocess.Popen
            original_handles = []
            def spawn_compiler(*arguments, **options):
                self.assertTrue(options['start_new_session'])
                process = spawn(*arguments, stdout=subprocess.PIPE, **options)
                original_handles.append(process)
                return process
            def compile_original():
                try:
                    compiler.run(command, check=True, timeout=10)
                except BaseException as error:
                    result.append(error)
            worker = threading.Thread(target=compile_original)
            foreign = subprocess.Popen([sys.executable, '-c', 'import time;time.sleep(10)'])
            interception = patch.object(GATE.subprocess, 'Popen', side_effect=spawn_compiler)
            interception.start()
            worker.start()
            try:
                deadline = time.monotonic() + 3
                while not ready.exists() and time.monotonic() < deadline:
                    time.sleep(.005)
                self.assertTrue(ready.exists(), 'original compiler did not start')
                with compiler.lock:
                    original = compiler.process
                self.assertIsNotNone(original)
                compiler.cancel()
                worker.join(2)
                self.assertFalse(worker.is_alive(), 'cancelled compiler was not joined')
                self.assertIsNotNone(original.returncode, f'compiler handle was cleared before its child joined: {result!r}')
                self.assertTrue(select.select([original.stdout], [], [], 2)[0], 'original compiler descendant retained its inherited pipe')
                self.assertEqual(original.stdout.read(), b'', 'original compiler descendant was not drained')
                self.assertIsNone(foreign.poll(), 'compiler cancellation signalled another child')
                self.assertIsNone(compiler.process)
                self.assertEqual(len(result), 1)
                self.assertIsInstance(result[0], subprocess.CalledProcessError)
                with self.assertRaisesRegex(RuntimeError, 'cancelled'):
                    compiler.run(command, check=True, timeout=10)
            finally:
                compiler.cancel()
                worker.join(2)
                interception.stop()
                for handle in original_handles:
                    handle.stdout.close()
                foreign.terminate()
                foreign.wait(timeout=2)

    def test_remaining_aggregate_budget_bounds_and_joins_the_original_compiler(self):
        compiler = GATE.OwnedCandidateCompiler(time.monotonic() + .15)
        command = [sys.executable, '-c', 'import time;time.sleep(10)']
        with self.assertRaises(subprocess.TimeoutExpired):
            compiler.run(command, check=True, timeout=150)
        self.assertIsNone(compiler.process)
        with patch.object(GATE.subprocess, 'Popen') as spawn:
            with self.assertRaises(subprocess.TimeoutExpired):
                compiler.run(command, check=True, timeout=150)
            spawn.assert_not_called()


if __name__ == '__main__':
    unittest.main()
