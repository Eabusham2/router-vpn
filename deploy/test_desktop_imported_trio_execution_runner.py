#!/usr/bin/env python3
"""Pin the complete actual imported-trio native test verdict inventory."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('imported_execution', Path(__file__).with_name('test_desktop_imported_trio_execution.py'))
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


def events():
    rows = [{'Action': 'start', 'Package': gate.PACKAGE}]
    for suffix, children in gate.CASES.items():
        root = gate.PREFIX+suffix
        rows.append({'Action':'run','Package':gate.PACKAGE,'Test':root})
        for child in children:
            rows.extend({'Action':action,'Package':gate.PACKAGE,'Test':root+'/'+child} for action in ('run','pass'))
        rows.append({'Action':'pass','Package':gate.PACKAGE,'Test':root})
    rows.append({'Action': 'pass', 'Package': gate.PACKAGE})
    return rows


def verdict(rows, code=0):
    return gate.verdict('\n'.join(json.dumps(row) for row in rows), code)


class ImportedExecutionRunner(unittest.TestCase):
    def test_complete_original_inventory(self):
        self.assertEqual(verdict(events())['tests'], 38)
        self.assertEqual(set(gate.CASES), {'TrioExecutionNativeAdoptionAndRestore', 'TrioExecutionPhysicalPolicy', 'TrioExecutionRejectsChangedNativeGraph', 'PrefixExecutionNativeAdoption', 'PrefixExecutionRejectsChangedNativeGraph'})
        self.assertEqual(len(gate.CASES['TrioExecutionNativeAdoptionAndRestore']), 6)
        self.assertEqual(len(gate.CASES['TrioExecutionPhysicalPolicy']), 4)
        self.assertEqual(len(gate.CASES['TrioExecutionRejectsChangedNativeGraph']), 5)
        self.assertEqual(gate.CASES['PrefixExecutionNativeAdoption'], tuple(mode+'/'+str(count)+'/'+requested for mode in ('wg','awg2-fast','awg2-strong') for count in (2,6) for requested in ('server','auto')))
        self.assertEqual(gate.CASES['PrefixExecutionRejectsChangedNativeGraph'], ('middle-key','middle-endpoint','earlier-key','earlier-detour','selected-dns','cancel'))

    def test_each_original_leaf_required(self):
        for missing in gate.expected():
            with self.subTest(missing=missing), self.assertRaises(ValueError):
                verdict([row for row in events() if row.get('Test') != missing])

    def test_failure_skip_foreign_or_runless_pass_rejected(self):
        for change in ({'Action': 'fail'}, {'Action': 'skip'}, {'Package': 'foreign'}, {'Test': gate.PREFIX+'Foreign'}, {'Action': 'pass'}):
            rows = events()
            rows[1].update(change)
            with self.subTest(change=change), self.assertRaises(ValueError):
                verdict(rows)

    def test_duplicate_original_run_or_pass_rejected(self):
        for index in (1, 2, -1):
            rows = events()
            rows.insert(index, copy.deepcopy(rows[index]))
            with self.subTest(index=index), self.assertRaises(ValueError):
                verdict(rows)

    def test_nonzero_exit_or_non_json_rejected(self):
        with self.assertRaises(ValueError):
            verdict(events(), 1)
        with self.assertRaises(ValueError):
            gate.verdict('PASS', 0)

    def test_missing_package_start_and_late_data_race_refused(self):
        rows = events()
        with self.assertRaises(ValueError):
            verdict(rows[1:])
        rows.append({'Action':'output','Package':gate.PACKAGE,'Output':'WARNING: DATA RACE\n'})
        with self.assertRaises(ValueError):
            verdict(rows)

    def test_duplicate_json_keys_refused(self):
        raw = '\n'.join(json.dumps(row) for row in events())
        raw = raw.replace('"Action": "start"', '"Action": "run", "Action": "start"', 1)
        with self.assertRaises(ValueError):
            gate.verdict(raw, 0)

    def test_package_cannot_precede_original_children(self):
        rows = events()
        rows.insert(0, rows.pop())
        with self.assertRaises(ValueError):
            verdict(rows)


if __name__ == '__main__':
    unittest.main()
