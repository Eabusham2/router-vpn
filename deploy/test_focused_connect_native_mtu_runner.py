#!/usr/bin/env python3
"""Check CONNECT MTU gate composition and strict causal controls; no native verdict."""
from pathlib import Path
import importlib.util
import tempfile
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
def module(name,path):
 spec=importlib.util.spec_from_file_location(name,path);v=importlib.util.module_from_spec(spec);spec.loader.exec_module(v);return v
V=module('connect_mtu_validator_test',ROOT/'deploy/test_focused_connect_native_mtu.py')
F=module('connect_mtu_original_runner',ROOT/'deploy/test_focused_socks_bridge_runner.py')
P=module('connect_mtu_projection_test',ROOT/'deploy/prepare-mobile-connect.py')
class NativeCONNECTMTUValidator(unittest.TestCase):
 def test_exact_inventory_preserves_original_mtu(self):
  self.assertEqual((len(V.NATIVE_ROOTS),len(V.NATIVE_CASES),len(V.WRAPPER_ROOTS),len(V.WRAPPER_CASES)),(9,21,7,13))
  self.assertEqual((len(V.PRESERVED_TYPED),len(V.PRESERVED_BOX),len(V.PRESERVED_CONTROLS)),(64,45,19))
  self.assertEqual((len(V.BASE.VERDICTS),len(V.BASE.ORIGINAL_BOX),len(V.BASE.CONTROLS)),(77,66,34))
  self.assertIn("TestRouterNodeChainSOCKSExportedFactoryRetainsTypedOwner", V.PRESERVED_TYPED)
  for names in (V.BASE.VERDICTS,V.BASE.ORIGINAL_BOX,[c['name'] for c in V.BASE.CONTROLS]):self.assertEqual(len(names),len(set(names)))
 def test_all_phases_keep_original_bounds_and_scope(self):
  with patch.object(F,'V',V.BASE),tempfile.TemporaryDirectory() as directory:
   f=F.Composition(Path(directory));f.validator=V.validate;r=f.run()
   self.assertEqual(len(f.calls),49);self.assertEqual(len(r['controls']),34);self.assertEqual(len(r['owner_controls']),4)
   self.assertTrue(r['native_connect_mtu_component_accepted'])
   for key in ('encrypted_connect_run_accepted','public_mtu_constructor_accepted','physical_mtu_accepted','generated_sdk_accepted','installed_native_accepted','public_native_admission','successful_run_accepted'):self.assertFalse(r[key],key)
   for name,cmd,bound in f.calls:
    if name in {c['name'] for c in V.BASE.CONTROLS}:self.assertEqual(bound,600);self.assertIn('-timeout=90s',cmd);self.assertIn('-race',cmd)
    if name in ('typed-native','original-libbox','original-box'):self.assertEqual(bound,100);self.assertIn('-test.timeout=90s',cmd)
 def test_added_controls_have_exact_unique_actual_source_seams(self):
  inverse={v:ROOT/'mobile/chain'/k for k,v in P.TEMPLATES.items()}
  for c in V.CONTROLS:
   original=inverse[c['path']].read_text();self.assertEqual(original.count(c['before']),1,c['name']);self.assertNotEqual(V.BASE.mutate(c,original),original)
   for bad in ('missing',original+c['before']):
    with self.assertRaises(ValueError):V.BASE.mutate(c,bad)
 def test_controls_require_failing_exact_witness(self):
  with patch.object(F,'V',V.BASE):
   for c in V.CONTROLS:
    package,_=V.BASE.control_target(c);raw=F.encoded(F.events(package,c['cases'],c))
    self.assertTrue(V.BASE.require_events(raw,1,package,c['cases'],c)['accepted'])
    for status,bad in [(0,raw),(-9,raw),(1,raw.replace(c['witness'].encode(),b'unrelated')),(1,raw+b'panic: unrelated\n')]:
     with self.assertRaises(ValueError):V.BASE.require_events(bad,status,package,c['cases'],c)
 def test_missing_or_duplicate_cases_refused(self):
  with patch.object(F,'V',V.BASE):
   for package,names in ((V.BASE.BOX,V.NATIVE_CASES),(V.BASE.LIBBOX,V.WRAPPER_CASES)):
    rows=F.events(package,names);V.BASE.require_events(F.encoded(rows),0,package,names)
    for name in names:
     missing=[r for r in rows if not(r.get('Test')==name and r.get('Action')=='pass')]
     with self.assertRaises(ValueError):V.BASE.require_events(F.encoded(missing),0,package,names)
    with self.assertRaises(ValueError):V.BASE.require_events(F.encoded(rows+rows[-1:]),0,package,names)
 def test_failures_withhold_component_admission(self):
  with patch.object(F,'V',V.BASE):
   for fault in ('compile-fail','native-missing','old-box-missing','native-control-pass','native-control-signal','timeout','unjoined','source-change','native-change','image-change','selection-change'):
    with self.subTest(fault=fault),tempfile.TemporaryDirectory() as directory:
     f=F.Composition(Path(directory),fault);f.validator=V.validate
     with self.assertRaises((ValueError,RuntimeError)):f.run()
if __name__=='__main__':unittest.main(verbosity=2)
