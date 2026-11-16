#!/usr/bin/env python3
"""Strict ordinary reservation inventories; these checks are not native acceptance."""
import importlib.util
import json
from pathlib import Path
import unittest
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('ordinary_reservation_gate',ROOT/'deploy/test_node_chain_ordinary_candidate_reservation.py')
V=importlib.util.module_from_spec(spec);spec.loader.exec_module(V)

def encode(rows):return '\n'.join(json.dumps(row) for row in rows)
def events():
    rows=[dict(Action='start',Package=V.PACKAGE)]
    for root,children in V.ROOTS.items():
        rows.append(dict(Action='run',Package=V.PACKAGE,Test=root))
        for child in children:
            for action in ('run','pass'):rows.append(dict(Action=action,Package=V.PACKAGE,Test=root+'/'+child))
        rows.append(dict(Action='pass',Package=V.PACKAGE,Test=root))
    rows.append(dict(Action='pass',Package=V.PACKAGE));return rows

def failed(fault,witness):
    leaf=V.RESERVATION+'/'+fault
    return [dict(Action='start',Package=V.PACKAGE),dict(Action='run',Package=V.PACKAGE,Test=V.RESERVATION),dict(Action='run',Package=V.PACKAGE,Test=leaf),dict(Action='output',Package=V.PACKAGE,Test=leaf,Output=witness),dict(Action='fail',Package=V.PACKAGE,Test=leaf),dict(Action='fail',Package=V.PACKAGE,Test=V.RESERVATION),dict(Action='fail',Package=V.PACKAGE)]

class OrdinaryReservationVerdict(unittest.TestCase):
    def test_exact_baseline(self):self.assertEqual(V.verdict(encode(events()),0),13)
    def test_every_record_required(self):
        rows=events()
        for index in range(len(rows)):
            with self.subTest(index=index),self.assertRaises(ValueError):V.verdict(encode(rows[:index]+rows[index+1:]),0)
    def test_duplicate_foreign_skip_failed(self):
        for fault in ('duplicate','foreign','skip','fail','wrong-package'):
            rows=events()
            if fault=='duplicate':rows.insert(2,dict(rows[1]))
            elif fault=='foreign':rows[1]['Test']+='Foreign'
            elif fault=='wrong-package':rows[1]['Package']='foreign'
            else:rows[2]['Action']=fault
            with self.subTest(fault=fault),self.assertRaises(ValueError):V.verdict(encode(rows),0)
    def test_bad_exit_is_not_positive(self):
        for code in (1,2,124,-9):
            with self.assertRaises(ValueError):V.verdict(encode(events()),code)
    def test_all_causal_controls(self):
        self.assertEqual([c[0] for c in V.CONTROLS],['duplicate','stale-same-inventory','copied-owner'])
        for fault,relative,changes,witness in V.CONTROLS:
            V.negative(encode(failed(fault,witness)),1,fault,witness)
            name='lifecycle.go.tmpl' if relative==V.LIFECYCLE else 'candidates.go.tmpl'
            source=(ROOT/'mobile/chain'/name).read_text()
            self.assertNotEqual(V.mutation(source,changes),source)
            for before,_ in changes:self.assertEqual(source.count(before),1)
    def test_omission_abort_is_not_refusal(self):
        fault,_,_,witness=V.CONTROLS[0];rows=failed(fault,witness)
        for code in (0,2,124,-9):
            with self.assertRaises(ValueError):V.negative(encode(rows),code,fault,witness)
        for output in ('panic: bad','WARNING: DATA RACE','test timed out','signal: killed','build failed','missing witness'):
            changed=failed(fault,output)
            with self.assertRaises(ValueError):V.negative(encode(changed),1,fault,witness)
    def test_omission_each_event_required(self):
        fault,_,_,witness=V.CONTROLS[0];rows=failed(fault,witness)
        for i in range(len(rows)):
            with self.subTest(i=i),self.assertRaises(ValueError):V.negative(encode(rows[:i]+rows[i+1:]),1,fault,witness)
    def test_omission_duplicate_foreign_skip(self):
        fault,_,_,witness=V.CONTROLS[0]
        for change in ('duplicate','foreign','skip','foreign-package','pass'):
            rows=failed(fault,witness)
            if change=='duplicate':rows.insert(2,dict(rows[1]))
            elif change=='foreign':rows[2]['Test']+='foreign'
            elif change=='foreign-package':rows[3]['Package']='foreign'
            else:rows[4]['Action']=change
            with self.subTest(change=change),self.assertRaises(ValueError):V.negative(encode(rows),1,fault,witness)
    def test_canonical_build_output_only(self):
        fault,_,_,witness=V.CONTROLS[0];rows=failed(fault,witness)
        build=dict(Action='build-output',ImportPath=V.PACKAGE+'.test',Output='link warning\n')
        V.negative(encode([build,*rows]),1,fault,witness)
        for changed in (dict(build,ImportPath='foreign'),dict(build,Package=V.PACKAGE),dict(build,Output='x'*65537)):
            with self.assertRaises(ValueError):V.negative(encode([changed,*rows]),1,fault,witness)
        with self.assertRaises(ValueError):V.negative(encode([rows[0],build,*rows[1:]]),1,fault,witness)
    def test_original_clocks_and_compile_flags(self):
        cmd=V.command('go')
        for flag in ('-race','-json','-count=1','-p=1','-mod=readonly','-timeout=150s'):self.assertIn(flag,cmd)
        self.assertFalse(any(flag.startswith('-vet=') for flag in cmd))
        source=(ROOT/'deploy/test_node_chain_ordinary_candidate_reservation.py').read_text()
        self.assertIn('timeout=600',source);self.assertIn('timeout=300',source)
        self.assertIn("choices=('baselines','controls')",source)
    def test_returned_reservation_before_callback(self):
        source=(ROOT/'mobile/chain/candidates.go.tmpl').read_text()
        factory=source[source.index('func (m *RouterNodeChain) newCandidateMeasurementContext'):source.index('func (m *RouterNodeChainCandidateMeasurement) Prepare')]
        self.assertNotIn('NewMeasurementContext',factory)
        tail=factory[factory.index('m.candidate.Store(candidate)'):]
        self.assertEqual(tail.count('return '),1);self.assertIn('return candidate, nil',tail)
        self.assertNotIn('RouterNodeChainCloseCandidateMeasurement',source)
        self.assertIn('context.WithDeadline(ctx, m.prepareDeadline)',source)
    def test_actual_ownership_fixture_and_cleared_slot(self):
        source=(ROOT/'mobile/chain/candidates_test.go.tmpl').read_text()
        for root in V.ROOTS:self.assertIn('func '+root+'(',source)
        for leaf in V.ROOTS[V.RESERVATION]:self.assertIn('"'+leaf+'"',source)
        self.assertIn('[]bool{false, true}',source.replace('false,true','false, true'))
        self.assertIn('copy.state.Store(m.state.Load())',source)
        self.assertIn('copy.NetworkChanged()',source);self.assertIn('err := copy.Close()',source)
    def test_changed_anchors_fail_closed(self):
        for _,relative,changes,_ in V.CONTROLS:
            name='lifecycle.go.tmpl' if relative==V.LIFECYCLE else 'candidates.go.tmpl'
            source=(ROOT/'mobile/chain'/name).read_text()
            with self.assertRaises(ValueError):V.mutation(source.replace(changes[0][0],'',1),changes)
            with self.assertRaises(ValueError):V.mutation(source+changes[0][0],changes)

if __name__=='__main__':unittest.main()
