#!/usr/bin/env python3
"""Refuse incomplete native prefix verdicts and disconnected shipping gates."""
import copy
import importlib.util
import json
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('prefix_gate', ROOT/'deploy/test_node_chain_candidate_preparation.py')
GATE = importlib.util.module_from_spec(spec)
spec.loader.exec_module(GATE)


def receipt():
    result = []
    for package, roots in GATE.ROOTS.items():
        result.append(dict(Package=package, Action='start'))
        for root, children in roots.items():
            result.append(dict(Package=package, Action='run', Test=root))
            for child in children:
                result.extend([dict(Package=package, Action='run', Test=root+'/'+child), dict(Package=package, Action='pass', Test=root+'/'+child)])
            result.append(dict(Package=package, Action='pass', Test=root))
        result.append(dict(Package=package, Action='pass'))
    return result


def raw(rows):
    return '\n'.join(json.dumps(row) for row in rows)


class PrefixGate(unittest.TestCase):
    def test_complete_inventory(self):
        self.assertEqual(GATE.verdict(raw(receipt()), 0), 41)

    def test_actual_templates_and_all_causal_controls_are_required(self):
        for package, template in ((GATE.PACKAGE, 'candidate_preparation_box_test.go.tmpl'), (GATE.PACKAGE+'/experimental/libbox', 'candidate_preparation_test.go.tmpl')):
            source = (ROOT/'mobile/chain'/template).read_text()
            names = re.findall(r'^func (Test\w+)\(t \*testing.T\)', source, re.M)
            self.assertEqual(set(names), set(GATE.ROOTS[package]))
            self.assertEqual(len(names), len(set(names)))
        self.assertEqual(len(GATE.CONTROLS), 13)
        for label, relative, before, after, package, selected, witness in GATE.CONTROLS:
            template = 'candidate_preparation.go.tmpl' if package == './experimental/libbox' else 'candidate_preparation_box.go.tmpl'
            self.assertEqual((ROOT/'mobile/chain'/template).read_text().count(before), 1, label)
            self.assertNotEqual(before, after)
            self.assertTrue(witness)
            self.assertIn(selected, GATE.expected(GATE.PACKAGE+('/experimental/libbox' if package == './experimental/libbox' else '')))

    def test_rejects_missing_original_leaf(self):
        rows = [row for row in receipt() if row.get('Test') != 'TestRouterVPNNodeChainCandidatePreparationNativeClosedPrefixAndFifty/awg2-strong']
        with self.assertRaises(ValueError): GATE.verdict(raw(rows), 0)

    def test_rejects_empty_package(self):
        rows = [dict(Package=package, Action=action) for package in GATE.ROOTS for action in ('start','pass')]
        with self.assertRaises(ValueError): GATE.verdict(raw(rows), 0)

    def test_rejects_skipped_or_failed_or_duplicate_leaf(self):
        for action in ('skip','fail','duplicate'):
            rows = receipt()
            index = next(i for i,row in enumerate(rows) if '/' in row.get('Test','') and row['Action']=='pass')
            if action == 'duplicate': rows.insert(index,copy.deepcopy(rows[index]))
            else: rows[index]['Action']=action
            with self.subTest(action=action), self.assertRaises(ValueError): GATE.verdict(raw(rows),0)

    def test_rejects_parent_before_child_completion(self):
        rows = receipt()
        first = next(i for i,row in enumerate(rows) if row.get('Test') and '/' not in row['Test'] and row['Action']=='pass')
        rows.insert(2,rows.pop(first))
        with self.assertRaises(ValueError): GATE.verdict(raw(rows),0)

    def test_rejects_late_foreign_or_racing_receipt(self):
        for extra in (dict(Package=GATE.PACKAGE,Action='output',Output='late'),dict(Package='foreign',Action='start'),dict(Package=GATE.PACKAGE,Action='output',Output='DATA RACE')):
            rows=receipt(); rows.insert(1,extra) if 'DATA RACE' in extra.get('Output','') else rows.append(extra)
            with self.subTest(extra=extra), self.assertRaises(ValueError): GATE.verdict(raw(rows),0)

    def test_shipping_native_gate_and_export_are_mandatory(self):
        source=(ROOT/'android/build-sing-box-libbox.sh').read_text()
        line='python3 "$ROOT/../deploy/test_node_chain_candidate_preparation.py" --vendor "$VENDOR" --go "$(command -v go)"'
        self.assertEqual(source.count(line),1)
        self.assertEqual(source.count('python3 "$ROOT/../deploy/test_node_chain_candidate_preparation_runner.py"'),1)
        self.assertLess(source.index(line),source.index('go_retry test ./experimental/libbox/routervpn/...'))
        self.assertIn('RouterNodeChainCandidatePreparation newRouterNodeChainCandidatePreparation(java.lang.String, int, java.lang.String) throws java.lang.Exception;',source)
        self.assertIn('io.nekohasekai.libbox.RouterNodeChainCandidateCatalog) throws java.lang.Exception;',source)


if __name__ == '__main__':
    unittest.main()
