#!/usr/bin/env python3
"""Coverage/verdict controls for the bounded mobile execution component gate."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('mobile_execution_gate',ROOT/'deploy/test_mobile_node_chain_execution.py')
G=importlib.util.module_from_spec(spec);spec.loader.exec_module(G)


class Runner(unittest.TestCase):
    def events(self):
        result=[]
        for package,names in G.inventory().items():
            def event(action,name=None):
                value={'Package':G.PREFIX+package,'Action':action}
                if name:value['Test']=name
                return value
            result.append(event('start'))
            for name in sorted(names):
                result.extend([event('run',name),event('run',name+'/original'),event('pass',name+'/original'),event('pass',name)])
            result.append(event('pass'))
        return result

    def check(self,events,code=0):
        return G.verdict('\n'.join(map(json.dumps,events)),code,G.inventory())

    def test_complete_exact_two_packages(self):
        self.assertEqual(len(self.check(self.events())),2*sum(map(len,G.inventory().values())))

    def test_missing_root_or_terminal_package_refused(self):
        events=self.events()
        for changed in (events[:-1], [e for e in events if e.get('Test')!=next(iter(G.inventory()['daemon']))]):
            with self.assertRaises(ValueError):self.check(changed)

    def test_skip_race_nonzero_refused(self):
        for fault in ('skip','race','code'):
            events=self.events()
            if fault=='skip':events[2]['Action']='skip'
            if fault=='race':events.insert(3,dict(events[2],Action='output',Output='DATA RACE'))
            with self.assertRaises(ValueError):self.check(events,1 if fault=='code' else 0)

    def test_duplicate_and_late_child_refused(self):
        events=self.events()
        for position,event in ((2,events[1]),(5,dict(events[1],Test=events[1]['Test']+'/late'))):
            changed=copy.deepcopy(events);changed.insert(position,event)
            with self.assertRaises(ValueError):self.check(changed)

    def test_foreign_package_and_test_refused(self):
        for field,value in (('Package','github.com/foreign/native'),('Test','TestOtherOwner')):
            events=self.events();events[1][field]=value
            with self.assertRaises(ValueError):self.check(events)

    def test_parent_before_unjoined_child_refused(self):
        events=self.events();events[3],events[4]=events[4],events[3]
        with self.assertRaises(ValueError):self.check(events)

    def test_bounded_ordinary_race_only(self):
        command=G.command('go',G.inventory(),'^original$')
        self.assertIn('-race',command);self.assertIn('-timeout=180s',command)
        self.assertIn('./experimental/libbox',command);self.assertIn('./daemon',command)
        self.assertNotIn('routervpn_native_pq',G.TAGS)
        self.assertNotIn('routervpn_pq_traffic_test',G.TAGS)

    def test_causal_controls_touch_actual_unique_generated_functions(self):
        inverse={target:source for source,target in G.PREP.TEMPLATES.items()}
        for label,target,before,after,package,test,witness in G.CONTROLS:
            with self.subTest(label=label):
                if target=='daemon/instance.go':
                    raw=G.PREP.instance_source(G.PREP.FIELD_BEFORE+'}\n'+G.PREP.CLOSE_BEFORE+'\n'+G.PREP.CONSTRUCT_BEFORE+G.PREP.BOX_BEFORE+G.PREP.ACQUIRE_BEFORE+'}\n').decode()
                else:
                    raw=(ROOT/'mobile/chain_execution'/inverse[target]).read_text()
                self.assertEqual(raw.count(before),1)
                self.assertNotEqual(before,after)
                self.assertIn(test.split('/')[0],G.inventory()[package])
                self.assertTrue(witness)


if __name__=='__main__':unittest.main()
