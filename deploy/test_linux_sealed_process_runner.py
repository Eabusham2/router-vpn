#!/usr/bin/env python3
"""Exact verdict inventory for actual sealed-image/process capability tests."""
import re
import unittest
from pathlib import Path
import test_linux_controller_privilege as GATE


class SealedProcessGateTests(unittest.TestCase):
    def verdict(self):
        names = []
        for group, leaves in GATE.PROCESS_SEALED_GROUPS.items():
            names.extend('TestLinuxProcessNamespace'+suffix for suffix in (group, *(group+'/'+leaf for leaf in leaves)))
        return names, '\n'.join('--- PASS: '+name+' (0.01s)' for name in names)+'\n'

    def test_complete_exact_native_inventory(self):
        names, output = self.verdict()
        GATE.check_sealed_process_verdict(output)
        source = (Path(__file__).resolve().parents[1]/'internal/linuxprocess/sealed_image_linux_native_test.go').read_text()
        for group, leaves in GATE.PROCESS_SEALED_GROUPS.items():
            self.assertIn(group, GATE.PROCESS_CASES)
            self.assertIn('func TestLinuxProcessNamespace'+group+'(', source)
            for leaf in leaves:
                self.assertIn('"'+leaf+'"', source)
        runner = Path(GATE.__file__).read_text()
        self.assertIn('check_sealed_process_verdict(process_output)', runner)
        self.assertIn('test_linux_sealed_process_runner.py', runner)

    def test_missing_renamed_duplicate_and_failure_are_rejected(self):
        names, output = self.verdict()
        for name in names:
            line = '--- PASS: '+name+' (0.01s)\n'
            for invalid in (output.replace(line, ''), output.replace(line, line.replace(name, name+'-renamed')),
                            output+line, output+line.replace('PASS', 'SKIP'), output+line.replace('PASS', 'FAIL')):
                with self.subTest(name=name, invalid=invalid[-120:]), self.assertRaises(ValueError):
                    GATE.check_sealed_process_verdict(invalid)


if __name__ == '__main__':
    unittest.main()
