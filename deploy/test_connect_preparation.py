#!/usr/bin/env python3
"""Check CONNECT projection ownership; this fixture grants no native traffic proof."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('connect_preparer',ROOT/'deploy/prepare-mobile-connect.py')
P=importlib.util.module_from_spec(spec);spec.loader.exec_module(P)
ANCHOR='\tif err := routerVPNNodeSOCKSOptions(options.Context, options.Options); err != nil {\n\t\treturn nil, err\n\t}\n'

class Projection(unittest.TestCase):
 def fixture(self):
  directory=tempfile.TemporaryDirectory();self.addCleanup(directory.cleanup)
  root=Path(directory.name)
  (root/'box.go').write_text('package box\nfunc New(options Options) (*Box, error) {\n'+ANCHOR+'\treturn &Box{\n\t\tctx: options.Context,\n\t}, nil\n}\n')
  return root
 def snapshot(self,root):
  return {str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() for p in root.rglob('*') if p.is_file()}
 def test_mobile_and_desktop_source_closures(self):
  for mobile in (False,True):
   with self.subTest(mobile=mobile):
    root=self.fixture()
    with patch.object(P.subprocess,'check_output',return_value=P.PIN+'\n'):
     P.prepare(root,mobile=mobile)
     before=self.snapshot(root)
     P.prepare(root,mobile=mobile)
     self.assertEqual(before,self.snapshot(root))
     record=json.loads((root/P.OWNER).read_bytes())
     expected={relative for name,relative in P.TEMPLATES.items() if (not mobile or name not in P.DESKTOP_ONLY) and (mobile or not relative.startswith('experimental/libbox/'))}
     self.assertEqual(expected,set(record['files']))
     for name,relative in P.TEMPLATES.items():
      if relative in expected:
       self.assertEqual((ROOT/'mobile/chain'/name).read_bytes(),(root/relative).read_bytes())
       self.assertEqual(record['files'][relative],hashlib.sha256((root/relative).read_bytes()).hexdigest())
     self.assertEqual(1,(root/'box.go').read_text().count('routerVPNNodeCONNECTOptions'))
 def test_foreign_and_changed_sources_refused(self):
  for phase in ('foreign','changed','wrong-core','moved-guard','duplicate-guard','linked','foreign-owner'):
   with self.subTest(phase=phase):
    root=self.fixture()
    with patch.object(P.subprocess,'check_output',return_value=P.PIN+'\n'):
     if phase not in ('foreign','linked','wrong-core'):P.prepare(root)
     relative=P.TEMPLATES['connect_owner.go.tmpl'];target=root/relative
     if phase in ('foreign','changed'):
      target.parent.mkdir(parents=True,exist_ok=True);target.write_text('foreign source\n')
     elif phase=='linked':
      target.parent.mkdir(parents=True,exist_ok=True);target.symlink_to(root/'box.go')
     elif phase in ('moved-guard','duplicate-guard'):
      source=(root/'box.go').read_text()
      guard='\tif err := routerVPNNodeCONNECTOptions(options.Context, options.Options); err != nil {\n\t\treturn nil, err\n\t}\n'
      source=source.replace(ANCHOR+guard,guard+ANCHOR) if phase=='moved-guard' else source+guard
      (root/'box.go').write_text(source)
     elif phase=='foreign-owner':
      record=json.loads((root/P.OWNER).read_bytes());record['files']['foreign.go']='0'*64
      (root/P.OWNER).write_text(json.dumps(record))
     before=self.snapshot(root)
     if phase=='wrong-core':
      with patch.object(P.subprocess,'check_output',return_value='f'*40+'\n'):
       with self.assertRaises(ValueError):P.prepare(root)
     else:
      with self.assertRaises(ValueError):P.prepare(root)
     self.assertEqual(before,self.snapshot(root))
 def test_original_return_binding_composes_exact_socks_owner(self):
  plain=(self.fixture()/'box.go').read_text()
  socks=plain.replace('\treturn &Box{\n','\treturn routerVPNNodeSOCKSBind(&Box{\n').replace('\n\t}, nil\n}','\n\t}), nil\n}')
  for original in (plain,socks):
   bound=P.CONNECT_BINDING.bind(original)
   self.assertEqual(bound,P.CONNECT_BINDING.bind(bound))
   self.assertEqual((original,True),P.CONNECT_BINDING.strip(bound))
   self.assertEqual(original.count('routerVPNNodeSOCKSBind'),bound.count('routerVPNNodeSOCKSBind'))
   for broken in (bound+"routerVPNNodeCONNECTBind",bound.replace('routerVPNNodeCONNECTBind(', 'routerVPNNodeCONNECTBind(foreign('),bound.replace('), nil',', nil',1),bound.replace('return routerVPNNodeCONNECTBind','return foreign + routerVPNNodeCONNECTBind')):
    with self.assertRaises(ValueError):P.CONNECT_BINDING.strip(broken)
 def test_every_projected_template_is_an_input(self):
  paths=set(P.inputs())
  self.assertTrue({ROOT/'mobile/chain'/name for name in P.TEMPLATES}<=paths)
  for script in ('prepare-mobile-multihop.py','prepare-desktop-external.py'):
   source=(ROOT/'deploy'/script).read_text()
   self.assertIn('CONNECT.inputs()',source)
   self.assertIn('CONNECT.prepare(vendor',source)

if __name__=='__main__':unittest.main()
