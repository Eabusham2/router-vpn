#!/usr/bin/env python3
"""Strict event and source wiring controls; never native traffic evidence."""
import importlib.util
import json
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('typed_native_gate',ROOT/'deploy/test_node_chain_typed_connected_candidates.py');V=importlib.util.module_from_spec(spec);spec.loader.exec_module(V)
def events():
    rows=[dict(Action='start',Package=V.PACKAGE)]
    for root,children in V.ROOTS.items():
        rows.append(dict(Action='run',Package=V.PACKAGE,Test=root))
        for child in children:
            for action in ('run','pass'):rows.append(dict(Action=action,Package=V.PACKAGE,Test=root+'/'+child))
        rows.append(dict(Action='pass',Package=V.PACKAGE,Test=root))
    rows.append(dict(Action='pass',Package=V.PACKAGE));return rows
def encode(rows):return '\n'.join(json.dumps(row) for row in rows)
def failed(family='SOCKS',fault='engine',witness='replacement native engine accepted'):
    root=f'TestRouterNodeChain{family}ConnectedCandidateNativeOwnership';leaf=root+'/'+fault
    return [dict(Action='start',Package=V.PACKAGE),dict(Action='run',Package=V.PACKAGE,Test=root),dict(Action='run',Package=V.PACKAGE,Test=leaf),dict(Action='output',Package=V.PACKAGE,Test=leaf,Output=witness),dict(Action='fail',Package=V.PACKAGE,Test=leaf),dict(Action='fail',Package=V.PACKAGE,Test=root),dict(Action='fail',Package=V.PACKAGE)]
class NativeConnectedVerdict(unittest.TestCase):
    def test_complete_inventory(self):self.assertEqual(V.verdict(encode(events()),0),38)
    def test_every_original_record_required(self):
        rows=events()
        for index in range(len(rows)):
            with self.subTest(index=index),self.assertRaises(ValueError):V.verdict(encode(rows[:index]+rows[index+1:]),0)
    def test_duplicate_foreign_and_skip(self):
        for change in ('duplicate','foreign','skip','failure'):
            rows=events()
            if change=='duplicate':rows.insert(2,dict(rows[1]))
            elif change=='foreign':rows[2]['Test']+='-foreign'
            else:rows[3]['Action']='skip' if change=='skip' else 'fail'
            with self.subTest(change=change),self.assertRaises(ValueError):V.verdict(encode(rows),0)
    def test_nonzero_and_foreign_partition(self):
        for code in (1,124,-9):
            with self.assertRaises(ValueError):V.verdict(encode(events()),code)
        with self.assertRaises(ValueError):V.verdict(encode(events()),0,{'foreign':()})
    def test_exact_causal_terminal(self):
        for family,fault,_,_,witness in (*V.CONTROLS,*V.OWNERSHIP_CONTROLS):V.negative(encode(failed(family,fault,witness)),1,family,fault,witness)
    def test_causal_abort_not_refusal(self):
        for code in (0,2,124,-9):
            with self.assertRaises(ValueError):V.negative(encode(failed()),code,'SOCKS','engine','replacement native engine accepted')
        for output in ('panic: test','WARNING: DATA RACE','test timed out','signal: killed','build failed','wrong witness'):
            with self.assertRaises(ValueError):V.negative(encode(failed(witness=output)),1,'SOCKS','engine','replacement native engine accepted')
    def test_causal_missing_duplicate_foreign(self):
        for change in ('drop','duplicate','foreign','skip'):
            rows=failed()
            if change=='drop':rows.pop()
            elif change=='duplicate':rows.insert(2,dict(rows[1]))
            elif change=='foreign':rows[2]['Test']+='-foreign'
            else:rows[4]['Action']='skip'
            with self.subTest(change=change),self.assertRaises(ValueError):V.negative(encode(rows),1,'SOCKS','engine','replacement native engine accepted')
    def test_canonical_build_output_only(self):
        row=dict(Action='build-output',ImportPath=V.PACKAGE+'.test',Output='link warning\n')
        V.negative(encode([row,*failed()]),1,'SOCKS','engine','replacement native engine accepted')
        for changed in (dict(row,ImportPath='foreign'),dict(row,Package=V.PACKAGE),dict(row,Output='x'*65537)):
            with self.assertRaises(ValueError):V.negative(encode([changed,*failed()]),1,'SOCKS','engine','replacement native engine accepted')
        with self.assertRaises(ValueError):V.negative(encode([failed()[0],row,*failed()[1:]]),1,'SOCKS','engine','replacement native engine accepted')
    def test_original_retirement_boundaries_are_required(self):
        self.assertEqual(len(V.CONTROLS),8)
        self.assertEqual(len(V.OWNERSHIP_CONTROLS),4)
        for family,fault,relative,before,witness in V.OWNERSHIP_CONTROLS:
            self.assertIn(fault,('copied-owner','copied-owner-cleared'))
            source=(ROOT/'mobile/chain'/(family.lower()+'_lifecycle.go.tmpl')).read_text()
            self.assertEqual(source.count(before),2)
            for method in ('networkChangedContext','closeContext'):
                body=source[source.index('func (m *RouterNodeChain'+family+') '+method+'('):]
                self.assertLess(body.index(before),body.index('m.retireProof()'))
            for child in ('copied-owner','copied-owner-cleared','foreign-slot'):
                self.assertIn(child,V.ROOTS['TestRouterNodeChain'+family+'ConnectedCandidateNativeOwnership'])

    def test_reservation_precedes_foreign_prepare_and_has_no_key_cleanup(self):
        source=(ROOT/'mobile/chain/typed_candidates.go.tmpl').read_text()
        for family in ('SOCKS','CONNECT'):
            self.assertNotIn('RouterNodeChain'+family+'CloseCandidateMeasurement',source)
            start=source.index('func (m *RouterNodeChain'+family+') newConnectedCandidateMeasurementContext(')
            stop=source.index('func (m *RouterNodeChain'+family+'CandidateMeasurement) Prepare()',start)
            factory=source[start:stop]
            tail=factory[factory.index('m.candidate.Store(candidate)'):]
            self.assertNotIn('NewMeasurementContext',factory)
            self.assertEqual(tail.count('return '),1)
            self.assertIn('return candidate, nil',tail)
            prepare=source[stop:source.index('func (m *RouterNodeChain'+family+'CandidateMeasurement) current(',stop)]
            self.assertIn('context.WithDeadline(ctx, m.prepareDeadline)',prepare)
            self.assertNotIn('context.WithTimeout',prepare)
            self.assertIn('m.prepareStarted = true',prepare)
            self.assertIn('defer close(done)',prepare)
            self.assertIn('m.plan.NewMeasurementContext(ctx, m)',prepare)

    def test_actual_additive_shipping_wiring(self):
        driver=(ROOT/'deploy/test_node_chain_candidate_preparation.py').read_text()
        self.assertIn('connected.execute(core, go)',driver)
        self.assertLess(driver.index('for label, relative, before, after, package, name, witness in CONTROLS:'),driver.index('connected.execute(core, go)'))
        gate=V.parser();self.assertEqual(len(gate.CONTROLS),14);self.assertEqual(gate.BASELINE_BUDGET,900)
        self.assertIn('-timeout=150s',gate.command('go',['.'],'test'))
        prep=(ROOT/'deploy/prepare-mobile-node-chain.py').read_text()
        for filename in ('typed_candidates.go.tmpl','typed_candidates_test.go.tmpl','typed_candidates_run_test.go.tmpl','test_node_chain_typed_connected_candidates.py','test_node_chain_typed_connected_candidates_runner.py'):self.assertIn(filename,prep)
if __name__=='__main__':unittest.main()
