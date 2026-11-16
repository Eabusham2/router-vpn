#!/usr/bin/env python3
"""Fail-closed process and inventory checks; no native execution credit."""
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import unittest

P = Path(__file__).with_name('test_desktop_hysteria_execution_controller.py')
spec = importlib.util.spec_from_file_location('hysteria_parent_gate', P)
G = importlib.util.module_from_spec(spec)
spec.loader.exec_module(G)


def causal(root='Original', case='Original/linux/3/server', witness='original failure'):
    events = [{'Action':'start','Package':G.PACKAGE}, {'Action':'run','Package':G.PACKAGE,'Test':root}]
    if case != root:
        events.append({'Action':'run','Package':G.PACKAGE,'Test':case})
    events.append({'Action':'output','Package':G.PACKAGE,'Test':case,'Output':witness+'\n'})
    if case != root:
        events.append({'Action':'fail','Package':G.PACKAGE,'Test':case})
    events.extend([{'Action':'fail','Package':G.PACKAGE,'Test':root},{'Action':'fail','Package':G.PACKAGE}])
    return events


def result(events, code=1, stderr=''):
    return SimpleNamespace(stdout='\n'.join(json.dumps(e) for e in events)+'\n',stderr=stderr,returncode=code)


class HysteriaControllerRunner(unittest.TestCase):
    def test_inventory_retains_every_original_source_and_public_root(self):
        self.assertEqual(len(G.SOURCE),7)
        self.assertEqual(len(G.PUBLIC),19)
        for target in ('linux/amd64','linux/arm64','windows/amd64','windows/arm64','darwin/amd64','darwin/arm64'):
            self.assertEqual(G.inventory(target,'source'),{**G.SOURCE, **(G.LINUX if target.startswith('linux/') else G.DARWIN if target.startswith('darwin/') else {})})
            if target.startswith('darwin/'):
                with self.assertRaises(ValueError):G.inventory(target,'public')
            else:self.assertEqual(G.inventory(target,'public'),G.PUBLIC)
        for target in ('freebsd/amd64','linux/386','windows/arm','android/arm64'):
            with self.assertRaises(ValueError):G.inventory(target,'source')
        for phase in ('unknown','prefix',''):
            with self.assertRaises(ValueError):G.inventory('linux/amd64',phase)
        source='\n'.join(p.read_text() for p in (G.ROOT/'cmd/client').glob('*hysteria*test.go'))
        for root in (*G.SOURCE,*G.PUBLIC,*G.LINUX,*G.DARWIN):self.assertEqual(source.count('func '+root+'('),1,root)

    def test_exact_selected_assertion_failure(self):
        G.verify_causal(result(causal()),'Original','Original/linux/3/server','original failure')
        G.verify_causal(result(causal(case='Original')),'Original','Original','original failure')

    def test_wrong_leaf_cannot_lend_same_witness(self):
        for mutation in ('wrong-leaf','extra-leaf','skip','pass','empty','no-start','race','panic','late-output','wrong-package','duplicate-fail'):
            events=causal()
            if mutation=='wrong-leaf':
                for e in events:
                    if e.get('Test')=='Original/linux/3/server':e['Test']='Original/linux/4/server'
            elif mutation=='extra-leaf':events.insert(-1,{'Action':'run','Test':'Foreign','Package':G.PACKAGE})
            elif mutation in ('skip','pass'):events[-2]['Action']=mutation
            elif mutation=='empty':events=[]
            elif mutation=='no-start':events.pop(0)
            elif mutation in ('race','panic'):events[3]['Output']+='WARNING: DATA RACE' if mutation=='race' else 'panic: bad'
            elif mutation=='late-output':events.append({'Action':'output','Package':G.PACKAGE,'Output':'late'})
            elif mutation=='wrong-package':events[0]['Package']='other'
            elif mutation=='duplicate-fail':events.insert(-1,dict(events[-2]))
            with self.subTest(mutation=mutation),self.assertRaises((ValueError,json.JSONDecodeError)):
                G.verify_causal(result(events),'Original','Original/linux/3/server','original failure')

    def test_process_failure_is_not_causal_acceptance(self):
        for code in (0,2,124,-9,-11):
            with self.subTest(code=code),self.assertRaises(ValueError):G.verify_causal(result(causal(),code),'Original','Original/linux/3/server','original failure')
        with self.assertRaises(ValueError):G.verify_causal(result(causal(),stderr='compiler killed'),'Original','Original/linux/3/server','original failure')
        duplicate=result(causal());duplicate.stdout=duplicate.stdout.replace('"Action": "run"','"Action": "run", "Action": "run"',1)
        with self.assertRaises(ValueError):G.verify_causal(duplicate,'Original','Original/linux/3/server','original failure')

    def test_original_bounds_and_pinned_driver_are_retained(self):
        source=P.read_text()
        self.assertIn('BASE.native_environment(go, without_race)',source)
        self.assertIn('BASE.compile_image(executable, environment, image, without_race)',source)
        self.assertEqual(source.count("'-test.timeout=120s'"),2)
        self.assertIn('verify_imported_native_verdicts',source)
        for path,before,after,root,child,witness in G.CONTROLS:
            self.assertEqual((G.ROOT/path).read_text().count(before),1)
            self.assertNotEqual(before,after)
            self.assertTrue(witness)
            self.assertIn(root,{**G.SOURCE,**G.PUBLIC})
            if child:self.assertIn(child,{**G.SOURCE,**G.PUBLIC}[root])

if __name__=='__main__':unittest.main()
