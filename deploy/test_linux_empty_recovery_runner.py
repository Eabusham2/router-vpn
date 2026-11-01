#!/usr/bin/env python3
"""Require the actual empty-checkpoint restart cases in the shipping gate."""
from pathlib import Path
import importlib.util
import unittest

SPEC = importlib.util.spec_from_file_location('linux_empty_recovery_runner', Path(__file__).with_name('test_linux_controller_privilege.py'))
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)


def markers(native):
    groups = {'TestLinuxOwnedControllerNamespaceEmptyJournalRecovery': RUNNER.EMPTY_RECOVERY_CASES} if native else RUNNER.EMPTY_RECOVERY_UNITS
    return ['--- PASS: '+name+' (0.01s)' for group, leaves in groups.items()
            for name in (group, *(group+'/'+leaf for leaf in leaves))]


class LinuxEmptyRecoveryRunner(unittest.TestCase):
    def test_requires_each_actual_boundary(self):
        for native in (False, True):
            rows = markers(native)
            RUNNER.check_empty_recovery_verdict('\n'.join(rows), native=native)
            for index, marker in enumerate(rows):
                with self.subTest(marker=marker), self.assertRaises(ValueError):
                    RUNNER.check_empty_recovery_verdict('\n'.join(rows[:index]+rows[index+1:]), native=native)

    def test_rejects_failed_skipped_logged_or_duplicated_cases(self):
        for native in (False, True):
            rows = markers(native)
            for output in ('', '\n'.join(rows)+'\n--- SKIP: original-owner (0.01s)',
                           '\n'.join(rows)+'\n--- FAIL: original-owner (0.01s)'):
                with self.subTest(native=native), self.assertRaises(ValueError):
                    RUNNER.check_empty_recovery_verdict(output, native=native)
            for marker in rows:
                for replacement in ('fixture.go:42: '+marker, marker+'\n'+marker):
                    with self.subTest(marker=marker), self.assertRaises(ValueError):
                        RUNNER.check_empty_recovery_verdict('\n'.join(rows).replace(marker, replacement), native=native)

    def test_source_and_native_case_are_in_shipping_controller_gate(self):
        self.assertIn('EmptyJournalRecovery', RUNNER.CASES)
        for name in ('cmd/client/desktop_node_recovery_linux.go', 'cmd/client/desktop_node_recovery_linux_test.go',
                     'cmd/client/desktop_node_recovery_linux_native_test.go'):
            self.assertIn(name, RUNNER.source_identity())


if __name__ == '__main__':
    unittest.main()
