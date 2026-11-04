#!/usr/bin/env python3
"""Check the real fixture writer's test-clock/Apple-SDK source boundary.

Only compiler/process execution is substituted here. Native Swift execution and
the real iOS SDK acceptance remain mandatory in test_ios_via_entry_candidates.py.
"""
from pathlib import Path
import contextlib
import importlib.util
import io
import subprocess
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    'via_entry_fixture', ROOT / 'deploy/test_ios_via_entry_candidates.py')
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)


class ViaEntrySourceBoundary(unittest.TestCase):
    def test_real_sdk_never_receives_the_synthetic_network_clock(self):
        original = (GATE.APP / 'IOSViaEntryTCP.swift').read_text()
        sdk_sources = []
        executable_sources = []
        executions = []
        witnesses = (
            'only valid responses can win',
            'actual summary removes five samples at each end',
            'receipt selects robust fifty-sample winner',
            'network changed during native retirement',
            'cancel substituted for acknowledged socket drain',
            'direct probe lost its required physical interface',
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
                executable_sources.append(source)
                self.assertEqual(source.count('NWTest.shared.measurementNow()'), 2)
                self.assertNotIn('DispatchTime.now().uptimeNanoseconds', source)
                if 'static func measure(_ target: RouterProfile,' in source:
                    return subprocess.CompletedProcess(command, 1, '', "IOSViaEntryLatency.swift: sending 'candidate' risks causing data races")
                return subprocess.CompletedProcess(command, 0)
            self.assertEqual(len(command), 1)
            self.assertEqual(Path(command[0]).name, 'tests')
            self.assertEqual(options['timeout'], 120)
            executions.append(command)
            if len(executions) == 1:
                return subprocess.CompletedProcess(command, 0, 'substituted executable', '')
            return subprocess.CompletedProcess(command, 1, '', 'FAIL: ' + witnesses[len(executions) - 2])

        with patch.object(GATE.shutil, 'which', return_value='/fixture/swiftc'), \
             patch('platform.system', return_value='Darwin'), \
             patch.object(GATE.subprocess, 'check_output', return_value='/fixture/iphoneos-sdk\n'), \
             patch.object(GATE.subprocess, 'run', side_effect=run), \
             contextlib.redirect_stdout(io.StringIO()):
            GATE.main()
        self.assertEqual(len(executions), 7)
        self.assertEqual(len(executable_sources), 8)
        self.assertEqual(len(sdk_sources), 2)
        self.assertEqual((GATE.APP / 'IOSViaEntryTCP.swift').read_text(), original)


if __name__ == '__main__':
    unittest.main()
