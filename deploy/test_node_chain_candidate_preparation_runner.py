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


    def build_output(self, package=GATE.PACKAGE, output=None):
        # Exact Go 1.26 Darwin linker shape observed before Box/libbox start.
        return dict(ImportPath=package+'.test', Action='build-output',
                    Output=output if output is not None else
                    '# '+package+'.test\nld: warning: ignoring duplicate libraries: \'-lobjc\'\n')

    def test_actual_darwin_linker_records_preserve_exact_inventory(self):
        rows = receipt()
        augmented = []
        for row in rows:
            if row['Action'] == 'start':
                augmented.append(self.build_output(row['Package']))
            augmented.append(row)
        self.assertEqual(GATE.verdict(raw(augmented), 0), 41)
        split = [self.build_output(output='first linker fragment\n'),
                 self.build_output()] + rows
        self.assertEqual(GATE.verdict(raw(split), 0), GATE.verdict(raw(rows), 0))

    def test_build_output_cannot_replace_runtime_acceptance(self):
        rows = receipt()
        for changed in ([self.build_output()], [self.build_output()]+rows[:-1],
                        [self.build_output()]+[row for row in rows if row['Action'] != 'run']):
            with self.assertRaises(ValueError): GATE.verdict(raw(changed), 0)

    def test_foreign_late_named_or_malformed_build_output_is_refused(self):
        base = self.build_output()
        for changed in (dict(base, ImportPath='github.com/foreign/native.test'),
                        dict(base, ImportPath=GATE.PACKAGE),
                        dict(base, Package=GATE.PACKAGE),
                        dict(base, Test='TestOtherOwner'),
                        dict(base, Output=None), dict(base, Output=''),
                        dict(base, Output='WARNING: DATA RACE')):
            with self.subTest(record=changed), self.assertRaises(ValueError):
                GATE.verdict(raw([changed]+receipt()), 0)
        rows = receipt()
        for position in (1, len(rows)):
            changed = copy.deepcopy(rows); changed.insert(position, base)
            with self.assertRaises(ValueError): GATE.verdict(raw(changed), 0)

    def test_build_output_bound_counts_every_utf8_fragment(self):
        exact = 'é'*(GATE.MAX_BUILD_OUTPUT_BYTES//2)
        self.assertEqual(GATE.verdict(raw([self.build_output(output=exact)]+receipt()), 0), 41)
        for rows in ([self.build_output(output=exact+'x')],
                     [self.build_output(output=exact), self.build_output(output='x')]):
            with self.assertRaises(ValueError): GATE.verdict(raw(rows+receipt()), 0)

    def test_build_failure_unknown_events_and_nonzero_exit_still_refused(self):
        for action in ('build-fail', 'build-unknown', 'timeout'):
            with self.assertRaises(ValueError):
                GATE.verdict(raw([dict(self.build_output(), Action=action)]+receipt()), 0)
        for action in ('fail', 'skip', 'unknown'):
            rows = receipt(); rows[2]['Action'] = action
            with self.assertRaises(ValueError):
                GATE.verdict(raw([self.build_output()]+rows), 0)
        for code in (1, 124, -9):
            with self.assertRaises(ValueError):
                GATE.verdict(raw([self.build_output()]+receipt()), code)
        with self.assertRaises(ValueError): GATE.verdict('[]', 0)

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
