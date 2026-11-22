#!/usr/bin/env python3
"""Refuse incomplete native prefix verdicts and disconnected shipping gates."""
import copy
import importlib.util
import json
from pathlib import Path
import re
import unittest
from unittest import mock
import subprocess

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
        self.assertEqual(GATE.verdict(raw(receipt()), 0), 69)


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
        self.assertEqual(GATE.verdict(raw(augmented), 0), 69)
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
        self.assertEqual(GATE.verdict(raw([self.build_output(output=exact)]+receipt()), 0), 69)
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
        for package, templates in ((GATE.PACKAGE, ('candidate_preparation_box_test.go.tmpl', 'candidate_preparation_typed_box_test.go.tmpl')), (GATE.PACKAGE+'/experimental/libbox', ('candidate_preparation_test.go.tmpl', 'candidate_preparation_typed_test.go.tmpl'))):
            source = '\n'.join((ROOT/'mobile/chain'/template).read_text() for template in templates)
            names = re.findall(r'^func (Test\w+)\(t \*testing.T\)', source, re.M)
            self.assertEqual(set(names), set(GATE.ROOTS[package]))
            self.assertEqual(len(names), len(set(names)))
        self.assertEqual(len(GATE.CONTROLS), 14)
        for label, relative, before, after, package, selected, witness in GATE.CONTROLS:
            template = 'candidate_preparation.go.tmpl' if package == './experimental/libbox' else 'candidate_preparation_box.go.tmpl'
            self.assertEqual((ROOT/'mobile/chain'/template).read_text().count(before), 1, label)
            self.assertNotEqual(before, after)
            self.assertTrue(witness)
            self.assertIn(selected, GATE.expected(GATE.PACKAGE+('/experimental/libbox' if package == './experimental/libbox' else '')))

    def test_rejects_missing_original_leaf(self):
        rows = [row for row in receipt() if row.get('Test') != 'TestRouterVPNNodeChainCandidatePreparationNativeClosedPrefixAndFifty/awg2-strong']
        with self.assertRaises(ValueError): GATE.verdict(raw(rows), 0)

    def test_requires_saved_openvpn_prefix_cases(self):
        root = 'TestRouterVPNNodeChainCandidatePreparationNativeOpenVPNSavedSuffix'
        self.assertEqual(GATE.ROOTS[GATE.PACKAGE][root], ('3', '4', '8'))
        for child in ('3', '4', '8'):
            rows = [row for row in receipt() if row.get('Test') != root+'/'+child]
            with self.subTest(child=child), self.assertRaises(ValueError):
                GATE.verdict(raw(rows), 0)

    def test_requires_saved_imported_ss_prefix_cases(self):
        root = GATE.IMPORTED_SS_ROOT
        self.assertEqual(GATE.ROOTS[GATE.PACKAGE][root], ('3', '4', '8'))
        for child in ('3', '4', '8'):
            rows = [row for row in receipt() if row.get('Test') != root+'/'+child]
            with self.subTest(child=child), self.assertRaises(ValueError):
                GATE.verdict(raw(rows), 0)

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
        self.assertLess(source.index(line),source.index('python3 "$ROOT/../deploy/test_mobile_go_groups.py" shared "$VENDOR"'))
        self.assertIn('RouterNodeChainCandidatePreparation newRouterNodeChainCandidatePreparation(java.lang.String, int, java.lang.String) throws java.lang.Exception;',source)
        self.assertIn('io.nekohasekai.libbox.RouterNodeChainCandidateCatalog) throws java.lang.Exception;',source)


    def partition_rows(self, inventory):
        return [row for row in receipt() if row['Package'] in inventory and
                (not row.get('Test') or row['Test'] in inventory[row['Package']])]

    def partition_results(self):
        return [(label, raw(self.partition_rows(inventory)), 0)
                for label, _, _, inventory in GATE.positive_phases()]

    def test_partitions_preserve_exact_union_and_original_selection(self):
        phases = GATE.positive_phases()
        self.assertEqual([p[0] for p in phases], ['original', 'openvpn-3', 'openvpn-4', 'openvpn-8', 'imported-ss-3', 'imported-ss-4', 'imported-ss-8', *('typed-'+family+'-'+str(count) for family in ('socks', 'http', 'https') for count in (3, 4, 8))])
        self.assertEqual(phases[0][1], ['.', './experimental/libbox'])
        self.assertNotIn(GATE.OPENVPN_ROOT, phases[0][2])
        self.assertNotIn(GATE.IMPORTED_SS_ROOT, phases[0][2])
        self.assertNotIn(GATE.TYPED_ROOT, phases[0][2])
        self.assertEqual(sum(len(n) for p in phases for n in p[3].values()), 81)
        self.assertEqual(GATE.partition_verdict(self.partition_results()), 69)
        for offset, root in ((1, GATE.OPENVPN_ROOT), (4, GATE.IMPORTED_SS_ROOT)):
            for child, phase in zip(('3', '4', '8'), phases[offset:offset+3]):
                self.assertEqual(phase[2], '^'+root+'$/^'+child+'$')
                self.assertEqual(phase[3], {GATE.PACKAGE: {root, root+'/'+child}})
        for child, phase in zip(GATE.ROOTS[GATE.PACKAGE][GATE.TYPED_ROOT], phases[7:]):
            self.assertEqual(phase[2], '^'+GATE.TYPED_ROOT+'$/'+'/'.join('^'+part+'$' for part in child.split('/')))
            self.assertEqual(phase[3], {GATE.PACKAGE: {GATE.TYPED_ROOT, GATE.TYPED_ROOT+'/'+child}})
        for _, packages, selection, _ in phases:
            self.assertIn('-timeout=150s', GATE.command('go', packages, selection))

    def test_missing_duplicate_foreign_or_reordered_partition_refused(self):
        results = self.partition_results()
        for index in range(len(results)):
            with self.subTest(omitted=index), self.assertRaises(ValueError):
                GATE.partition_verdict(results[:index]+results[index+1:])
        for changed in (results[:-1], results+[results[-1]], results[::-1],
                        [('foreign', results[0][1], 0)]+results[1:]):
            with self.assertRaises(ValueError): GATE.partition_verdict(changed)

    def test_partition_scope_missing_duplicate_failed_and_foreign_events_refused(self):
        results = self.partition_results()
        rows = self.partition_rows(GATE.positive_phases()[1][3])
        leaf = GATE.OPENVPN_ROOT+'/3'
        for changed, code in (([r for r in rows if r.get('Test') != leaf], 0),
                              (rows+[rows[-1]], 0), (rows, 1),
                              (receipt(), 0),
                              ([dict(r, Action='fail') if r.get('Test') == leaf and r['Action']=='pass' else r for r in rows], 0)):
            bad = list(results); bad[1] = (bad[1][0], raw(changed), code)
            with self.assertRaises(ValueError): GATE.partition_verdict(bad)
        # Swapping a valid other leaf's transcript cannot fill this phase.
        bad = list(results); bad[1] = (bad[1][0], results[2][1], 0)
        with self.assertRaises(ValueError): GATE.partition_verdict(bad)
        for index in (4, 5, 6):
            # Neither the other family nor a different valid SS child may fill
            # this exact imported phase's compiled inventory.
            for other in (index-3, 4+(index-3)%3):
                bad = list(results); bad[index] = (bad[index][0], results[other][1], 0)
                with self.subTest(phase=index, substitute=other), self.assertRaises(ValueError):
                    GATE.partition_verdict(bad)

    def test_total_budget_is_shared_and_failed_phase_stops_next_launch(self):
        results = self.partition_results()
        completed = [subprocess.CompletedProcess([], 0, stdout=r[1]) for r in results]
        clock = [0, *(value for index in range(len(results)) for value in (index*40, (index+1)*40))]
        with mock.patch.object(GATE.time, 'monotonic', side_effect=clock), mock.patch.object(GATE.subprocess, 'run', side_effect=completed) as run:
            self.assertEqual(GATE.positive_baseline(Path('/unused'), 'go', {}), 69)
            self.assertEqual([c.kwargs['timeout'] for c in run.call_args_list], [900-index*40 for index in range(len(results))])
        with mock.patch.object(GATE.time, 'monotonic', side_effect=[0, 0, 901]), mock.patch.object(GATE.subprocess, 'run', return_value=completed[0]) as run:
            with self.assertRaises(ValueError): GATE.positive_baseline(Path('/unused'), 'go', {})
            self.assertEqual(run.call_count, 1)
        with mock.patch.object(GATE.time, 'monotonic', return_value=0), mock.patch.object(GATE.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1, stdout='')) as run:
            with self.assertRaises(ValueError): GATE.positive_baseline(Path('/unused'), 'go', {})
            self.assertEqual(run.call_count, 1)
        with mock.patch.object(GATE.time, 'monotonic', return_value=0), mock.patch.object(GATE.subprocess, 'run', side_effect=subprocess.TimeoutExpired('go', 900)) as run:
            with self.assertRaises(subprocess.TimeoutExpired): GATE.positive_baseline(Path('/unused'), 'go', {})
            self.assertEqual(run.call_count, 1)


if __name__ == '__main__':
    unittest.main()
