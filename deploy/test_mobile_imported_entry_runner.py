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
 def test_connect_inventory(self):
  self.assertEqual(len(gate.CONNECT_FILES),12)
  expected=gate.names({'TestRouterVPNImportedCONNECTNativeTraffic':gate.CONNECT_PEERS})
  self.assertEqual(len(expected),51)
  events=[{'Action':a,'Test':n} for n in sorted(expected) for a in ('run','pass')]
  gate.require_verdicts('\n'.join(map(json.dumps,events)),expected)
  for mutation in (events[:-1],events+[events[-1]],events[:-1]+[dict(events[-1],Action='skip')]):
   with self.assertRaises(ValueError):gate.require_verdicts('\n'.join(map(json.dumps,mutation)),expected)
 def test_configured_connect_parser_is_separate_and_complete(self):
  self.assertEqual(len(gate.CONNECT_SERVICE_FILES),24)
  self.assertEqual(len(gate.FILES),337)
  self.assertEqual(len(gate.names({'TestRouterVPNImportedCONNECTNativeTraffic':gate.CONNECT_PEERS})),51)
  self.assertEqual(len(gate.CORE['TestImportedEntryCONNECTServiceConfiguredGraphs']),24)
  expected=gate.names({'TestRouterImportedCONNECTConfiguredServiceGraphs':sorted(gate.CONNECT_SERVICE_FILES)})
  self.assertEqual(len(expected),25)
  events=[{'Action':a,'Test':n} for n in sorted(expected) for a in ('run','pass')]
  gate.require_verdicts('\n'.join(map(json.dumps,events)),expected)
  for mutation in (events[:-1],events+[events[-1]],events[:-1]+[dict(events[-1],Action='skip')]):
   with self.assertRaises(ValueError):gate.require_verdicts('\n'.join(map(json.dumps,mutation)),expected)
 def test_packet_layer_verdicts(self):
  expected=gate.names({'TestRouterVPNImportedSOCKSPacketLayersNativeTraffic':gate.SOCKS_PACKET_LAYER_PEERS})
  self.assertEqual(len(expected),94)
  events=[{'Action':a,'Test':n} for n in sorted(expected) for a in ('run','pass')]
  gate.require_verdicts('\n'.join(map(json.dumps,events)),expected)
  for mutation in (events[:-1],events+[events[-1]],events[:-1]+[dict(events[-1],Action='skip')]):
   with self.assertRaises(ValueError):gate.require_verdicts('\n'.join(map(json.dumps,mutation)),expected)
 def test_entry_layer_verdicts(self):
  expected=gate.names({'TestRouterVPNImportedSOCKSEntryLayersProxyNativeTraffic':gate.SOCKS_ENTRY_PROXY_PEERS,'TestRouterVPNImportedSOCKSEntryLayersPacketNativeTraffic':gate.SOCKS_ENTRY_PACKET_PEERS})
  self.assertEqual(len(expected),155)
  events=[{'Action':a,'Test':n} for n in sorted(expected) for a in ('run','pass')]
  gate.require_verdicts('\n'.join(map(json.dumps,events)),expected)
  for mutation in (events[:-1],events+[events[-1]],events[:-1]+[dict(events[-1],Action='skip')]):
   with self.assertRaises(ValueError):gate.require_verdicts('\n'.join(map(json.dumps,mutation)),expected)
 def test_layered_fixture_inventory(self):
  self.assertEqual(len(gate.FILES),337)
  self.assertEqual(len(gate.SOCKS_FILES),45)
  for mode in ('shadowsocks','hysteria2','wg','awg2-fast','awg2-strong'):
   for layer in gate.LAYERS[1:]:
    self.assertIn('socks5--final-'+mode+'--'+layer+'.json',gate.FILES)
    self.assertNotIn('socks5--final-'+mode+'--off--'+layer+'.json',gate.FILES)
    self.assertIn('socks5--final-'+mode+'--entry-'+layer+'.json',gate.FILES)
    self.assertNotIn('socks5--final-'+mode+'--'+layer+'--off.json',gate.FILES)
 def test_missing_independent_layer_verdict(self):
  expected=gate.names({'TestRouterVPNImportedSOCKSPairedFinalNativeTraffic':gate.SOCKS_PEERS,'TestRouterVPNImportedSOCKSPacketFinalNativeTraffic':gate.SOCKS_PACKET_PEERS})
  for suffix in ('/entry-layer-key','/entry-layer-whitening','/final-layer-key','/final-layer-whitening'):
   omitted=next(n for n in sorted(expected) if n.endswith(suffix))
   events=[{'Action':a,'Test':n} for n in sorted(expected-{omitted}) for a in ('run','pass')]
   with self.assertRaises(ValueError):gate.require_verdicts('\n'.join(map(json.dumps,events)),expected)
 def test_retirement_cases_are_required(self):
  source=(ROOT/'deploy/test_mobile_imported_entry.py').read_text()
  for case in ('TestRouterVPNImportedSOCKSLayerRelayRetirement','retiring-worker-root-close','replacement-owner','foreign-and-closed'):
   self.assertIn(case,source)
 def test_both_layer_verdicts(self):
  self.assertEqual(len(gate.FILES),337)
  expected=gate.names(gate.SOCKS_BOTH_GROUPS)
  self.assertEqual(len(expected),271)
  events=[{'Action':a,'Test':n} for n in sorted(expected) for a in ('run','pass')]
  gate.require_verdicts('\n'.join(map(json.dumps,events)),expected)
  for mutation in (events[:-1],events+[events[-1]],events[:-1]+[dict(events[-1],Action='skip')]):
   with self.assertRaises(ValueError):gate.require_verdicts('\n'.join(map(json.dumps,mutation)),expected)
 def test_first_response_retirement_is_mandatory(self):
  source=(ROOT/'deploy/test_mobile_imported_entry.py').read_text()
  self.assertIn("'TestRouterVPNDesktopLayerFirstResponseRetirement':['eof','cancel']",source)
 def test_openvpn_exact_inventory(self):
  self.assertEqual(len(gate.OPENVPN.FILES),90)
  self.assertEqual(len(gate.OPENVPN.REFUSALS),14)
  self.assertEqual(len(gate.names(gate.OPENVPN.PEERS)),111)
  expected=gate.names(gate.OPENVPN.PEERS)
  events=[{'Action':a,'Test':n} for n in sorted(expected) for a in ('run','pass')]
  gate.require_verdicts('\n'.join(map(json.dumps,events)),expected)
  for mutation in (events[:-1],events+[events[-1]],events[:-1]+[dict(events[-1],Action='skip')]):
   with self.assertRaises(ValueError):gate.require_verdicts('\n'.join(map(json.dumps,mutation)),expected)
 def test_context_owner_verdicts_are_required(self):
  self.assertEqual(len(gate.names(gate.CONTEXT_CORE)),13)
  expected=gate.names(gate.CONTEXT_NATIVE)
  self.assertEqual(len(expected),15)
  events=[{'Action':a,'Test':n} for n in sorted(expected) for a in ('run','pass')]
  gate.require_verdicts('\n'.join(map(json.dumps,events)),expected)
  with self.assertRaises(ValueError):gate.require_verdicts('\n'.join(map(json.dumps,events[:-1])),expected)
 def test_selected_connect_dns_inventory(self):
  self.assertEqual(len(gate.CONNECT_DNS_FILES),44)
  self.assertEqual(len(gate.FILES),337)
  self.assertEqual(len(gate.CONNECT_SERVICE_FILES),24)
  expected=gate.names({'TestRouterImportedCONNECTSelectedDNSGraphs':sorted(gate.CONNECT_DNS_FILES)})
  self.assertEqual(len(expected),45)
  events=[{'Action':a,'Test':n} for n in sorted(expected) for a in ('run','pass')]
  gate.require_verdicts('\n'.join(map(json.dumps,events)),expected)
  for mutation in (events[:-1],events+[events[-1]],events[:-1]+[dict(events[-1],Action='skip')],events+[{'Action':'pass','Test':'foreign'}]):
   with self.assertRaises(ValueError):gate.require_verdicts('\n'.join(map(json.dumps,mutation)),expected)
 def test_shipping_invocations(self):
  self.assertIn("test_mobile_imported_entry.py'),str(vendor),'--android'",(ROOT/'deploy/test_android_multihop_pinned.py').read_text())
  self.assertIn('"deploy/test_mobile_imported_entry.py", source, "--native-peers"',(ROOT/'deploy/test_desktop_node_physical.py').read_text())
  self.assertIn('node_imported_router_entry_test.go.tmpl',(ROOT/'deploy/prepare-desktop-external.py').read_text())
  self.assertIn('routervpn_imported_entry_native_test.go.tmpl',(ROOT/'deploy/prepare-mobile-multihop.py').read_text())
if __name__=='__main__':unittest.main()
