#!/usr/bin/env python3
"""Require complete native ownership verdicts and causal execution witnesses."""
import importlib.util
import json
import re
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('execution_owner_runner_checks', ROOT/'deploy/test_node_chain_execution_owner.py')
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)


def events():
    rows = []
    for package in RUNNER.ROOTS:
        rows.append(dict(Package=package, Action='start'))
        for root in RUNNER.ROOTS[package]:
            name = RUNNER.PREFIX+root
            rows.append(dict(Package=package, Action='run', Test=name))
            for child in RUNNER.CHILDREN.get(root, ()):
                rows.append(dict(Package=package, Action='run', Test=name+'/'+child))
                rows.append(dict(Package=package, Action='pass', Test=name+'/'+child))
            rows.append(dict(Package=package, Action='pass', Test=name))
        rows.append(dict(Package=package, Action='pass'))
    return rows


def encoded(rows):
    return '\n'.join(json.dumps(row) for row in rows)


class Verdict(unittest.TestCase):
    def test_exact_complete_three_package_inventory(self):
        result = RUNNER.verdict(encoded(events()), 0)
        self.assertEqual(result, {'roots': 35, 'test_records': 114})
        self.assertEqual(len(RUNNER.CONTROLS), 25)

    def test_selection_keeps_only_exact_owner_inventory(self):
        pattern = re.compile(RUNNER.selection())
        for roots in RUNNER.ROOTS.values():
            for root in roots:
                self.assertIsNotNone(pattern.fullmatch(RUNNER.PREFIX+root))
        self.assertIsNone(pattern.fullmatch(RUNNER.PREFIX+'TUNDNSAddressCannotBypass'))
        self.assertIsNone(pattern.fullmatch(RUNNER.PREFIX+'NativeCloseReceiptForeign'))

    def test_omitted_root_child_or_package_cannot_pass(self):
        rows = events()
        for index, row in enumerate(rows):
            if row['Action'] in ('run', 'pass'):
                with self.subTest(index=index), self.assertRaises(ValueError):
                    RUNNER.verdict(encoded(rows[:index]+rows[index+1:]), 0)

    def test_failed_skipped_racing_or_nonzero_cannot_pass(self):
        for action, output in (('fail', ''), ('skip', ''), ('output', 'WARNING: DATA RACE')):
            rows = events()
            rows.insert(1, dict(Package=RUNNER.PACKAGE, Action=action, Output=output))
            with self.subTest(action=action), self.assertRaises(ValueError):
                RUNNER.verdict(encoded(rows), 0)
        with self.assertRaises(ValueError):
            RUNNER.verdict(encoded(events()), 1)

    def test_foreign_duplicate_late_and_unrun_pass_refused(self):
        rows = events()
        for extra in (dict(Package='foreign', Action='pass'), rows[1], rows[2],
                      dict(Package=RUNNER.PACKAGE, Action='pass', Test='TestForeign')):
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                RUNNER.verdict(encoded(rows[:2]+[extra]+rows[2:]), 0)
        with self.assertRaises(ValueError):
            RUNNER.verdict(encoded(rows+[dict(Package=RUNNER.PACKAGE, Action='output', Output='late')]), 0)

    def test_incomplete_child_before_parent_pass_refused(self):
        rows = events()
        child = next(i for i, r in enumerate(rows) if '/' in r.get('Test', '') and r['Action'] == 'pass')
        row = rows.pop(child)
        parent = next(i for i, r in enumerate(rows) if r.get('Test') == row['Test'].split('/')[0] and r['Action'] == 'pass')
        rows.insert(parent+1, row)
        with self.assertRaises(ValueError):
            RUNNER.verdict(encoded(rows), 0)

    def test_compiled_control_requires_exact_reached_failure_and_witness(self):
        selected, witness = 'NativeOpenCannotFinishAfterRevoke', 'older pending native open completed after revoke'
        name = RUNNER.PREFIX+selected
        rows = [dict(Package=RUNNER.PACKAGE, Action='run', Test=name),
                dict(Package=RUNNER.PACKAGE, Action='output', Test=name, Output=witness),
                dict(Package=RUNNER.PACKAGE, Action='fail', Test=name)]
        self.assertTrue(RUNNER.rejected(encoded(rows), 1, selected, witness))
        self.assertFalse(RUNNER.rejected(encoded(rows), 0, selected, witness))
        for index in range(3):
            self.assertFalse(RUNNER.rejected(encoded(rows[:index]+rows[index+1:]), 1, selected, witness))
        self.assertFalse(RUNNER.rejected('build failed', 1, selected, witness))
        self.assertFalse(RUNNER.rejected(encoded(rows+[dict(Output='WARNING: DATA RACE')]), 1, selected, witness))


if __name__ == '__main__':
    unittest.main()
