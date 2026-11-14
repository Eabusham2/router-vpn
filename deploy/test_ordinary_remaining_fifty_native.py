#!/usr/bin/env python3
"""Strict parser/projection tests; synthetic events are not native acceptance."""
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[1]
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);sys.modules[name]=m;spec.loader.exec_module(m);return m
V=load('ordinary_remaining_unit',ROOT/'deploy/ordinary_remaining_fifty_native.py')
B=load('ordinary_remaining_base',ROOT/'deploy/test_focused_connect_run.py').BASE
def rows(case,control=None):
 action='fail' if control else 'pass'
 return [dict(Action='start',Package=B.LIBBOX),dict(Action='run',Package=B.LIBBOX,Test=V.ROOT),dict(Action='output',Package=B.LIBBOX,Test=V.ROOT,Output=(control['witness'] if control else V.witness(case))+'\n'),dict(Action=action,Package=B.LIBBOX,Test=V.ROOT),dict(Action=action,Package=B.LIBBOX)]
def encoded(value):return ('\n'.join(json.dumps(row) for row in value)+'\n').encode()
class RemainingFiftyNative(unittest.TestCase):
 def test_exact_eight_case_graph_cipher_and_boundary_inventory(self):
  self.assertEqual(len(V.CASES),8);self.assertEqual(len({V.name(c) for c in V.CASES}),8)
  self.assertEqual({c[3] for c in V.CASES if c[:2]==('ss-middle','wg')},{0,1,2})
  self.assertEqual({c[4] for c in V.CASES if c[0]=='ss-middle'},{'2022-blake3-aes-128-gcm','2022-blake3-aes-256-gcm','2022-blake3-chacha20-poly1305'})
  self.assertEqual({(c[1],c[2],c[3]) for c in V.CASES if c[0]=='hysteria2-final'},{('wg',2,1),('awg2-fast',3,2),('awg2-strong',8,7)})
  for case in V.CASES:
   with self.subTest(case=case):
    self.assertTrue(V.events(B,encoded(rows(case)),0,case)['accepted'])
    env=V.environment({'original':'retained'},case,Path('/original/peer'));self.assertEqual(env['original'],'retained');self.assertEqual(env['ROUTERVPN_ORDINARY_FIFTY_PEER'],'/original/peer');self.assertEqual(env['GODEBUG'],'x509usefallbackroots=1')
 def test_wrong_graph_position_count_cipher_or_sample_cannot_pass(self):
  for case in V.CASES:
   for old,new in [('samples=50','samples=49'),('graph='+case[0],'graph=foreign'),('count='+str(case[2]),'count=9'),('position='+str(case[3]),'position=9'),('method='+case[4]+' samples','method=foreign samples')]:
    with self.subTest(case=case,field=old):
     raw=encoded(rows(case));self.assertIn(old.encode(),raw)
     with self.assertRaises(ValueError):V.events(B,raw.replace(old.encode(),new.encode()),0,case)
 def test_missing_duplicate_foreign_or_skipped_verdict_is_refused(self):
  case=V.CASES[1]
  for fault in ('no-marker','duplicate','no-terminal','skip','foreign-package'):
   value=rows(case)
   if fault=='no-marker':value.pop(2)
   elif fault=='duplicate':value.insert(3,dict(value[2]))
   elif fault=='no-terminal':value.pop()
   elif fault=='skip':value[-2]['Action']='skip'
   else:value[-2]['Package']='foreign'
   with self.subTest(fault=fault),self.assertRaises(ValueError):V.events(B,encoded(value),0,case)
 def test_old_adapter_control_requires_original_unique_failure(self):
  case=V.CASES[1];self.assertTrue(V.events(B,encoded(rows(case,V.CONTROL)),1,case,V.CONTROL)['accepted'])
  for value,status in [(rows(case),0),(rows(case,V.CONTROL),0),(rows(case,V.CONTROL)[:-1],1)]:
   with self.assertRaises(ValueError):V.events(B,encoded(value),status,case,V.CONTROL)
  value=rows(case,V.CONTROL);value[2]['Output']='unrelated failure\n'
  with self.assertRaises(ValueError):V.events(B,encoded(value),1,case,V.CONTROL)
 def test_source_and_native_peer_must_match_exact_projection(self):
  with tempfile.TemporaryDirectory() as directory:
   base=Path(directory);source=base/'source';mobile=base/'mobile';owner=base/'owner';table=dict(V.PROJECTIONS);peer_table=dict([V.PEER_PROJECTION]);paths=[]
   for template,relative in (*V.PROJECTIONS,V.PEER_PROJECTION):
    peer=template==V.PEER_PROJECTION[0];a=source/('mobile/desktop' if peer else 'mobile/chain')/template;b=(owner if peer else mobile)/relative
    a.parent.mkdir(parents=True,exist_ok=True);b.parent.mkdir(parents=True,exist_ok=True);a.write_bytes(template.encode());b.write_bytes(a.read_bytes());paths.append(b)
   V.checked_projection(source,mobile,owner,table,peer_table)
   for p in paths:
    original=p.read_bytes();p.write_bytes(original+b' changed')
    with self.assertRaises(ValueError):V.checked_projection(source,mobile,owner,table,peer_table)
    p.write_bytes(original)
 def test_causal_seam_restores_literal_adapter_without_source_mutation(self):
  source=(ROOT/'mobile/chain/box.go.tmpl').read_text();self.assertEqual(source.count(V.CONTROL['before']),1);changed=B.mutate(V.CONTROL,source)
  self.assertIn('return e.observation.Dial(ctx, tag, address) // causal restore',changed);self.assertNotEqual(changed,source);self.assertEqual((ROOT/'mobile/chain/box.go.tmpl').read_text(),source)
if __name__=='__main__':unittest.main()
