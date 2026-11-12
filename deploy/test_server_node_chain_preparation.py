#!/usr/bin/env python3
"""Verify exact ordered Server generated-source ownership, not native routing."""
from pathlib import Path
import hashlib
import importlib.util
import json
import tempfile
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('server_chain_preparation',ROOT/'deploy/prepare-server-node-chain.py')
PREP=importlib.util.module_from_spec(spec)
spec.loader.exec_module(PREP)

class ServerNodeChainPreparation(unittest.TestCase):
 def checkout(self,directory):
  root=Path(directory)/'core';root.mkdir();(root/'go.mod').write_text('module github.com/sagernet/sing-box\n');return root
 def prepare(self,root):
  with mock.patch.object(PREP.subprocess,'check_output',return_value=PREP.CORE+'\n'):
   PREP.prepare(root)
 def test_complete_original_source_inventory(self):
  inputs=set(PREP.inputs());content=PREP.copies()
  expected={}
  for source in (ROOT/'mobile/server_chain').glob('*.tmpl'):
   self.assertIn(source,inputs)
   name=source.name.removesuffix('.tmpl');prefix='routervpn_server_chain_' if name.startswith('box') else 'cmd/sing-box/routervpn_server_chain_';expected[prefix+name]=source.read_bytes()
  self.assertEqual(content,expected)
  for package in ('mobilemultihop','multihoprelay'):
   for source in (ROOT/'internal'/package).glob('node_chain_server*.go' if package=='mobilemultihop' else 'node_chain_*.go'):
    self.assertIn(source,inputs)
  self.assertIn('SERVER_CHAIN.prepare(vendor)',(ROOT/'deploy/prepare-relay-core.py').read_text())
  self.assertIn('SERVER_CHAIN.inputs()',(ROOT/'deploy/prepare-relay-core.py').read_text())
 def test_idempotent_exact_seal(self):
  with tempfile.TemporaryDirectory() as d:
   root=self.checkout(d);self.prepare(root);before=(root/PREP.OWNER).read_bytes();self.prepare(root);self.assertEqual((root/PREP.OWNER).read_bytes(),before)
   seal=json.loads(before);self.assertEqual(seal['source_sha256'],PREP.digest());self.assertEqual(seal['files'],{name:hashlib.sha256(raw).hexdigest() for name,raw in PREP.copies().items()})
   for name,raw in PREP.copies().items():self.assertEqual((root/name).read_bytes(),raw)
 def test_changed_generated_source_cannot_be_overwritten(self):
  with tempfile.TemporaryDirectory() as d:
   root=self.checkout(d);self.prepare(root);name=next(iter(PREP.copies()));p=root/name;p.write_bytes(p.read_bytes()+b'\n// replacement\n');before=p.read_bytes()
   with self.assertRaisesRegex(ValueError,'Changed ordered Server generated source'):self.prepare(root)
   self.assertEqual(p.read_bytes(),before)
 def test_foreign_owner_path_is_not_authority(self):
  with tempfile.TemporaryDirectory() as d:
   root=self.checkout(d);self.prepare(root);record=json.loads((root/PREP.OWNER).read_text());p=root/'foreign.go';p.write_text('package main\n');record['files']['foreign.go']=hashlib.sha256(p.read_bytes()).hexdigest();(root/PREP.OWNER).write_text(json.dumps(record))
   with self.assertRaisesRegex(ValueError,'Foreign ordered Server ownership path'):self.prepare(root)
   self.assertEqual(p.read_text(),'package main\n')
 def test_unowned_existing_source_is_not_replaced(self):
  with tempfile.TemporaryDirectory() as d:
   root=self.checkout(d);name=next(iter(PREP.copies()));p=root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text('foreign source\n')
   with self.assertRaisesRegex(ValueError,'Unowned ordered Server generated source'):self.prepare(root)
   self.assertEqual(p.read_text(),'foreign source\n')
 def test_linked_owner_and_generated_target_are_refused(self):
  for owner in (False,True):
   with self.subTest(owner=owner),tempfile.TemporaryDirectory() as d:
    root=self.checkout(d);outside=Path(d)/'outside';outside.write_text('foreign source\n');name=PREP.OWNER if owner else next(iter(PREP.copies()));p=root/name;p.parent.mkdir(parents=True,exist_ok=True);p.symlink_to(outside)
    with self.assertRaisesRegex(ValueError,'Linked ordered Server'):self.prepare(root)
    self.assertEqual(outside.read_text(),'foreign source\n')
 def test_wrong_core_refuses_before_any_write(self):
  with tempfile.TemporaryDirectory() as d:
   root=self.checkout(d)
   with mock.patch.object(PREP.subprocess,'check_output',return_value='0'*40+'\n'):
    with self.assertRaisesRegex(ValueError,'exact pinned native core'):PREP.prepare(root)
   self.assertEqual({p.name for p in root.iterdir()},{'go.mod'})
 def test_missing_owner_template_cannot_make_partial_worker(self):
  original=PREP.ROOT
  with tempfile.TemporaryDirectory() as d:
   replacement=Path(d);(replacement/'mobile/server_chain').mkdir(parents=True)
   for source in (ROOT/'mobile/server_chain').glob('*.tmpl'):
    if source.name!='front.go.tmpl':(replacement/'mobile/server_chain'/source.name).write_bytes(source.read_bytes())
   with mock.patch.object(PREP,'ROOT',replacement):
    with self.assertRaisesRegex(ValueError,'Incomplete ordered Server native owner'):PREP.copies()

if __name__=='__main__':unittest.main()
