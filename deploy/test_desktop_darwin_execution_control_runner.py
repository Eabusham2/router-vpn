#!/usr/bin/env python3
"""Require complete portable execution receipts, including literal slash names."""
from pathlib import Path
import importlib.util
import json
import unittest
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('execution_control',ROOT/'deploy/test_desktop_darwin_execution_control.py');G=importlib.util.module_from_spec(spec);spec.loader.exec_module(G)
class ExecutionControlReceiptTests(unittest.TestCase):
    def setUp(self):
        self.validator=G.load('test_desktop_darwin_retirement.py');self.validator.PACKAGE=G.PACKAGE
        self.cases={'TestOriginal':('linux/server','auto')}
        self.rows=[{'Action':'start'},{'Action':'run','Test':'TestOriginal'}]
        for leaf in self.cases['TestOriginal']:
            self.rows.extend({'Action':action,'Test':'TestOriginal/'+leaf} for action in ('run','pass'))
        self.rows.extend(({'Action':'pass','Test':'TestOriginal'},{'Action':'pass'}))
    def wire(self,rows):return '\n'.join(json.dumps(dict(Package=G.PACKAGE,**r))for r in rows)
    def test_actual_slash_name_has_no_fabricated_parent(self):
        self.assertEqual(G.require_pass(self.wire(self.rows),self.validator,self.cases),3)
        self.assertEqual(sum(1+len(v)for v in G.CASES.values()),75)
    def test_omitted_duplicate_foreign_and_unjoined_events_refuse(self):
        for position in range(len(self.rows)):
            with self.subTest(missing=position),self.assertRaises(ValueError):G.require_pass(self.wire(self.rows[:position]+self.rows[position+1:]),self.validator,self.cases)
            with self.subTest(duplicate=position),self.assertRaises(ValueError):G.require_pass(self.wire(self.rows[:position]+[self.rows[position]]+self.rows[position:]),self.validator,self.cases)
        for action in ('fail','skip','pause'):
            rows=[dict(r,Action=action)if r.get('Test')=='TestOriginal/auto'and r['Action']=='pass' else r for r in self.rows]
            with self.assertRaises(ValueError):G.require_pass(self.wire(rows),self.validator,self.cases)
        rows=[dict(r,Test='TestForeign')if r.get('Test')=='TestOriginal/auto' else r for r in self.rows]
        with self.assertRaises(ValueError):G.require_pass(self.wire(rows),self.validator,self.cases)
    def test_every_causal_boundary_is_exact_shipping_source(self):
        paths={'control.go':'node_chain_execution_control_darwin','command.go':'node_chain_execution_command','native.go':'node_chain_retirement_darwin','dispatch.go':'node_chain_execution_dispatch'}
        for label,name,before,after,witness,message in G.CONTROLS:
            raw=(ROOT/'mobile/desktop'/(paths[name]+'.go.tmpl')).read_text()
            self.assertEqual(raw.count(before),1,label);self.assertNotEqual(before,after)
            root,leaf=witness.split('/',1);self.assertIn(leaf,G.CASES[root]);self.assertTrue(message)
if __name__=='__main__':unittest.main()
