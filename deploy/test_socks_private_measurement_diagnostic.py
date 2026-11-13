#!/usr/bin/env python3
from pathlib import Path
import importlib.util
import json
import re
import sys
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location("socks_private_diag",ROOT/"deploy/socks_private_measurement_diagnostic.py")
D=importlib.util.module_from_spec(spec);spec.loader.exec_module(D)
class PrivateDiagnostic(unittest.TestCase):
 def setUp(self):self.original=(ROOT/"internal/hopmeasure/measure.go").read_text()
 def test_lossless_roundtrip_and_original_results(self):
  changed=D.apply(self.original)
  self.assertEqual(D.restore(changed),self.original)
  body=changed[:-len(D.RECORDER)]
  self.assertEqual([line.strip() for line in self.original.splitlines() if line.lstrip().startswith("return ")],[line.strip() for line in body.splitlines() if line.lstrip().startswith("return ")])
  self.assertEqual(body.count("context.WithTimeout(parent, 2*time.Second)"),self.original.count("context.WithTimeout(parent, 2*time.Second)"))
  self.assertIn("const RequestTimeout = 90 * time.Second",body)
 def test_missing_or_duplicated_source_seam_refused(self):
  old,_=D.REPLACEMENTS[6]
  for broken in (self.original.replace(old,"",1),self.original+"\n"+old):
   with self.subTest(broken=len(broken)),self.assertRaisesRegex(ValueError,"seam moved"):D.apply(broken)
 def test_omitted_recorder_and_changed_return_refused(self):
  changed=D.apply(self.original)
  with self.assertRaisesRegex(ValueError,"recorder"):D.restore(changed[:-1])
  omitted=changed.replace('if diagnosticError != nil { socksPrivateDiagnostic("prove"','if false { socksPrivateDiagnostic("prove"')
  with self.assertRaisesRegex(ValueError,"annotation"):D.restore(omitted)
  before='return nil, start, client, errors.New("routed measurement request failed")'
  tampered=changed.replace(before,'return nil, start, client, nil')
  self.assertNotEqual(D.restore(tampered),self.original)
 def test_duplicate_annotation_refused(self):
  changed=D.apply(self.original);_,annotation=D.REPLACEMENTS[6]
  with self.assertRaisesRegex(ValueError,"annotation"):D.restore(changed.replace(annotation,annotation+annotation))
 def test_nil_caller_keeps_original_rejection_path(self):
  changed=D.apply(self.original)
  self.assertIn("if ctx == nil { return nil }",D.RECORDER)
  self.assertEqual(changed.count("socksPrivateDiagnosticCaller(ctx), time.Since(diagnosticStarted)"),2)
  for line in changed.splitlines():
   if "defer func()" in line and "socksPrivateDiagnostic(" in line:self.assertNotIn("ctx.Err()",line)
  self.assertEqual(D.restore(changed),self.original)
 def test_fixed_failure_only_redacted_categories(self):
  self.assertIn("if result == nil { return }",D.RECORDER)
  self.assertIn('if diagnosticError != nil',D.apply(self.original))
  self.assertNotIn(".Error()",D.RECORDER)
  self.assertNotIn("h.API",D.RECORDER)
  self.assertNotIn("h.Token",D.RECORDER)
  self.assertNotIn("h.Proof",D.RECORDER)
  self.assertNotIn("%v",D.RECORDER)
  for value in ("deadline","cancelled","closed","timeout","rejected","none"):self.assertIn('"'+value+'"',D.RECORDER)
 def test_overlay_preserves_source_and_records_exact_identity(self):
  with tempfile.TemporaryDirectory() as temporary:
   root=Path(temporary);core=root/"core";source=core/D.PROJECTION;source.parent.mkdir(parents=True);source.write_text(self.original)
   receipt=D.prepare(core,root/"diagnostic")
   self.assertEqual(source.read_text(),self.original)
   self.assertEqual(D.restore(Path(receipt["replacement"]).read_text()),self.original)
   self.assertEqual(json.loads(Path(receipt["overlay"]).read_text())["Replace"],{str(source):receipt["replacement"]})
   self.assertFalse(receipt["acceptance_changed"])
   with self.assertRaises(ValueError):D.prepare(core,root/"diagnostic")
 def test_original_source_and_inside_output_refused(self):
  with tempfile.TemporaryDirectory() as temporary:
   root=Path(temporary);source=root/D.PROJECTION;source.parent.mkdir(parents=True);source.write_text(self.original)
   with self.assertRaises(ValueError):D.prepare(root,root/"diagnostic")
   source.unlink();source.symlink_to(ROOT/"internal/hopmeasure/measure.go")
   with self.assertRaises(ValueError):D.prepare(root,root.parent/(root.name+"-diagnostic"))
if __name__=="__main__":unittest.main()
