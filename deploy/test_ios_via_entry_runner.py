#!/usr/bin/env python3
"""Check the real fixture writer's test-clock/Apple-SDK source boundary.

Only compiler/process execution is substituted here. Native Swift execution and
the real iOS SDK acceptance remain mandatory in test_ios_via_entry_candidates.py.
"""
from pathlib import Path
import contextlib
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
    def run_gate(self, negative_result=None, *, require_overlap=False, fail_mutant_compile=False):
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
                return subprocess.CompletedProcess(command, 0)
            if '-sdk' in command:
                self.assertNotIn('-I', command)
                self.assertNotIn('-lNetwork', command)
                helper = next(Path(value) for value in command if str(value).endswith('/ActualTCP.swift'))
                source = helper.read_text()
                sdk_sources.append(source)
                self.assertNotIn('NWTest', source)
                self.assertEqual(source.count('DispatchTime.now().uptimeNanoseconds'), 2)
                if len(sdk_sources) == 1:
                    self.assertEqual(source, original)
                    return subprocess.CompletedProcess(command, 0)
                self.assertIn('static func measure(_ target: RouterProfile,', source)
                return subprocess.CompletedProcess(command, 1, '', "sending 'candidate' risks causing data races")
            if '-parse-as-library' in command:
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
             contextlib.redirect_stdout(io.StringIO()):
            GATE.main()
        self.assertEqual(len(executions), 7)
        self.assertEqual(len(executable_sources), 8)
        self.assertEqual(len(sdk_sources), 2)
        self.assertEqual(len(set(compiled_paths)), 8)
        self.assertEqual((GATE.APP / 'IOSViaEntryTCP.swift').read_text(), original)

    def test_exact_targeted_mutations_preserve_the_full_baseline_and_real_sdk_clock(self):
        self.run_gate()

    def test_targeted_negative_must_fail_at_its_own_assertion(self):
        for result, message in [((0, 'unexpected pass', ''), 'Negative control escaped'),
                                ((1, '', 'FAIL: unrelated witness'), 'failed at an unrelated witness'),
                                ((1, '', 'compiler/runtime crashed'), 'Negative control escaped')]:
            with self.subTest(result=result), self.assertRaisesRegex(AssertionError, message):
                self.run_gate(result)

    def test_mutant_compilation_overlaps_full_baseline_with_isolated_sources(self):
        self.run_gate(require_overlap=True)

    def test_background_mutant_compiler_failure_cannot_become_acceptance(self):
        with self.assertRaises(subprocess.CalledProcessError):
            self.run_gate(fail_mutant_compile=True)


class OriginalCompilerLifetime(unittest.TestCase):
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
                self.assertIsNotNone(original.returncode, 'compiler handle was cleared before its child joined')
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
