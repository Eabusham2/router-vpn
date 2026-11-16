#!/usr/bin/env python3
import importlib.util
import json
from pathlib import Path
import unittest
spec=importlib.util.spec_from_file_location('candidate_worker',Path(__file__).with_name('test_server_node_chain_candidate_worker.py'));RUN=importlib.util.module_from_spec(spec);spec.loader.exec_module(RUN)
def row(action,name=None,**extra):
 out={'Action':action,'Package':RUN.PACKAGE,**extra}
 if name:out['Test']=name
 return out
def text(rows):return '\n'.join(json.dumps(r) for r in rows)+'\n'
def success():return [row('start')]+[r for name in sorted(RUN.EXPECTED) for r in (row('run',name),row('pass',name))]+[row('pass')]
class CandidateWorker(unittest.TestCase):
 def test_exact_inventory(self):self.assertEqual(RUN.verdict(text(success()),0),{'roots':11,'records':43,'legacy_records':23})
 def test_every_original_and_new_record_required(self):
  for name in RUN.EXPECTED:
   with self.subTest(name=name),self.assertRaises(ValueError):RUN.verdict(text([r for r in success() if r.get('Test')!=name]),0)
 def test_failure_skip_duplicate_and_foreign(self):
  for extra in (row('fail'),row('skip',RUN.ROOTS[0]),row('pass',RUN.ROOTS[0]),row('run','TestForeign')):
   with self.assertRaises(ValueError):RUN.verdict(text(success()+[extra]),0)
 def test_causal_exact_witness(self):
  rows=[row('run',RUN.ROOTS[10]),row('run',RUN.CONTROL),row('output',RUN.CONTROL,Output=RUN.WITNESS),row('fail',RUN.CONTROL),row('fail',RUN.ROOTS[10]),row('fail')]
  self.assertTrue(RUN.rejected(text(rows),1));self.assertFalse(RUN.rejected(text(rows),0))
  for marker in RUN.FORBIDDEN:
   with self.assertRaises(ValueError):RUN.rejected(text(rows+[row('output',Output=marker)]),1)
   with self.assertRaises(ValueError):RUN.rejected(text(rows),1,marker)
if __name__=='__main__':unittest.main()
