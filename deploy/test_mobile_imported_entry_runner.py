#!/usr/bin/env python3
"""Negative controls for the mandatory imported-entry native verdict gate."""
import importlib.util
import json
from pathlib import Path
import unittest
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('imported_gate',ROOT/'deploy/test_mobile_imported_entry.py');gate=importlib.util.module_from_spec(spec);spec.loader.exec_module(gate)
class ImportedEntryVerdicts(unittest.TestCase):
 def sample(self):
  expected=gate.names(gate.CORE)
  return expected,[{'Action':a,'Test':n} for n in sorted(expected) for a in ('run','pass')]
 def test_complete(self):
  expected,events=self.sample();gate.require_verdicts('\n'.join(map(json.dumps,events)),expected)
 def test_missing(self):
  expected,events=self.sample()
  with self.assertRaises(ValueError):gate.require_verdicts('\n'.join(map(json.dumps,events[:-1])),expected)
 def test_duplicate(self):
  expected,events=self.sample()
  with self.assertRaises(ValueError):gate.require_verdicts('\n'.join(map(json.dumps,events+[events[-1]])),expected)
 def test_foreign(self):
  expected,events=self.sample();events.append({'Action':'pass','Test':'TestUnselected'})
  with self.assertRaises(ValueError):gate.require_verdicts('\n'.join(map(json.dumps,events)),expected)
 def test_skip(self):
  expected,events=self.sample();events[-1]['Action']='skip'
  with self.assertRaises(ValueError):gate.require_verdicts('\n'.join(map(json.dumps,events)),expected)
 def test_shipping_invocations(self):
  self.assertIn("test_mobile_imported_entry.py'),str(vendor),'--android'",(ROOT/'deploy/test_android_multihop_pinned.py').read_text())
  self.assertIn('"deploy/test_mobile_imported_entry.py", source, "--native-peers"',(ROOT/'deploy/test_desktop_node_physical.py').read_text())
  self.assertIn('node_imported_router_entry_test.go.tmpl',(ROOT/'deploy/prepare-desktop-external.py').read_text())
  self.assertIn('routervpn_imported_entry_native_test.go.tmpl',(ROOT/'deploy/prepare-mobile-multihop.py').read_text())
if __name__=='__main__':unittest.main()
