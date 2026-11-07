#!/usr/bin/env python3
"""Negative controls for the mandatory imported-entry native verdict gate."""
import importlib.util
import json
import contextlib
import io
import tempfile
from pathlib import Path
import unittest
from unittest import mock
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
  self.assertEqual(len(gate.FILES),346)
  self.assertEqual(len(gate.names({'TestRouterVPNImportedCONNECTNativeTraffic':gate.CONNECT_PEERS})),51)
  self.assertEqual(len(gate.CORE['TestImportedEntryCONNECTServiceConfiguredGraphs']),24)
  expected=gate.names({'TestRouterImportedCONNECTConfiguredServiceGraphs':sorted(gate.CONNECT_SERVICE_FILES)})
  self.assertEqual(len(expected),25)
  events=[{'Action':a,'Test':n} for n in sorted(expected) for a in ('run','pass')]
  gate.require_verdicts('\n'.join(map(json.dumps,events)),expected)
  for mutation in (events[:-1],events+[events[-1]],events[:-1]+[dict(events[-1],Action='skip')]):
   with self.assertRaises(ValueError):gate.require_verdicts('\n'.join(map(json.dumps,mutation)),expected)
 def test_independent_connect_inventory(self):
  self.assertEqual(len(gate.CONNECT_LAYER_FILES),32)
  self.assertFalse(gate.CONNECT_LAYER_FILES & (gate.FILES | gate.CONNECT_SERVICE_FILES | gate.CONNECT_DNS_FILES))
  core={p:v for p,v in gate.CORE.items() if p in ('TestImportedEntryCONNECTIndependentLayers','TestImportedEntryCONNECTIndependentLayerRefusals')}
  self.assertEqual(len(gate.names(core)),44)
  for parent,count in (('TestRouterVPNImportedHTTPLayersNativeTraffic',62),('TestRouterVPNImportedHTTPSLayersNativeTraffic',66)):
   expected=gate.names({parent:gate.CONNECT_LAYER_PEERS[parent]})
   self.assertEqual(len(expected),count)
   self.assertEqual(len([n for n in expected if n.endswith('/success')]),16)
   events=[{'Action':a,'Test':n} for n in sorted(expected) for a in ('run','pass')]
   gate.require_verdicts('\n'.join(map(json.dumps,events)),expected)
   for suffix in ('/entry-layer-key','/entry-whitening','/final-key','/final-whitening','/dns-route','/final-identity','/cancel','/close-owner'):
    missing=next(n for n in sorted(expected) if n.endswith(suffix))
    with self.subTest(parent=parent,missing=missing),self.assertRaises(ValueError):
     gate.require_verdicts('\n'.join(map(json.dumps,[e for e in events if e['Test']!=missing])),expected)
   for mutation in (events+[events[-1]],events[:-1]+[dict(events[-1],Action='skip')],events[:-1]+[dict(events[-1],Action='fail')],events+[{'Action':'pass','Test':'foreign'}]):
    with self.assertRaises(ValueError):gate.require_verdicts('\n'.join(map(json.dumps,mutation)),expected)
 def test_independent_connect_parser_is_mandatory(self):
  groups=gate.native_parser_groups(False)
  self.assertEqual(groups['TestRouterImportedCONNECTLayerGraphs'],sorted(gate.CONNECT_LAYER_FILES))
  expected=gate.names({'TestRouterImportedCONNECTLayerGraphs':groups['TestRouterImportedCONNECTLayerGraphs']})
  self.assertEqual(len(expected),33)
  events=[{'Action':a,'Test':n} for n in sorted(expected) for a in ('run','pass')]
  gate.require_verdicts('\n'.join(map(json.dumps,events)),expected)
  for mutation in (events[:-1],events+[events[-1]],events[:-1]+[dict(events[-1],Action='skip')],events+[{'Action':'pass','Test':'foreign'}]):
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
  self.assertEqual(len(gate.FILES),346)
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
  self.assertEqual(len(gate.FILES),346)
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
  self.assertEqual(len(gate.names(gate.CONTEXT_CORE)),124)
  self.assertEqual(len(gate.names(gate.CONTEXT_DNS)),23)
  self.assertEqual(len(gate.names(gate.CONTEXT_NATIVE)),104)
  self.assertEqual(len(gate.names(gate.CONTEXT_DNS_BOX)),13)
  self.assertEqual(len(gate.names(gate.CONTEXT_SELECTION_BOX)),27)
  for group in (gate.CONTEXT_CORE,gate.CONTEXT_DNS,gate.CONTEXT_NATIVE,gate.CONTEXT_DNS_BOX,gate.CONTEXT_SELECTION_BOX):
   expected=gate.names(group)
   events=[{'Action':a,'Test':n} for n in sorted(expected) for a in ('run','pass')]
   gate.require_verdicts('\n'.join(map(json.dumps,events)),expected)
   for name in expected:
    with self.subTest(missing=name),self.assertRaises(ValueError):gate.require_verdicts('\n'.join(map(json.dumps,[e for e in events if e['Test']!=name])),expected)
   for mutation in (events+[events[-1]],events[:-1]+[dict(events[-1],Action='skip')],events+[{'Action':'pass','Test':'foreign'}]):
    with self.assertRaises(ValueError):gate.require_verdicts('\n'.join(map(json.dumps,mutation)),expected)
 def test_selected_connect_dns_inventory(self):
  self.assertEqual(len(gate.CONNECT_DNS_FILES),44)
  self.assertEqual(len(gate.FILES),346)
  self.assertEqual(len(gate.CONNECT_SERVICE_FILES),24)
  expected=gate.names({'TestRouterImportedCONNECTSelectedDNSGraphs':sorted(gate.CONNECT_DNS_FILES)})
  self.assertEqual(len(expected),45)
  events=[{'Action':a,'Test':n} for n in sorted(expected) for a in ('run','pass')]
  gate.require_verdicts('\n'.join(map(json.dumps,events)),expected)
  for mutation in (events[:-1],events+[events[-1]],events[:-1]+[dict(events[-1],Action='skip')],events+[{'Action':'pass','Test':'foreign'}]):
   with self.assertRaises(ValueError):gate.require_verdicts('\n'.join(map(json.dumps,mutation)),expected)
 def test_selector_native_execution_is_mandatory(self):
  source=(ROOT/'deploy/test_mobile_imported_entry.py').read_text()
  self.assertIn("names(CONTEXT_SELECTION_BOX),timeout=90)",source)
  self.assertIn("m.EXTERNAL_POLICY.check_selection_sources(vendor)",source)
 def test_selector_commit_source_cannot_be_partially_projected(self):
  spec=importlib.util.spec_from_file_location('selection_projection',ROOT/'deploy/prepare-mobile-external-policy.py')
  projection=importlib.util.module_from_spec(spec);spec.loader.exec_module(projection)
  expected=b'captured cache write\nexact interruption\noriginal history\n'
  with tempfile.TemporaryDirectory() as temporary:
   vendor=Path(temporary);path=vendor/'selector.go';path.write_bytes(expected)
   with mock.patch.object(projection,'selection_sources',return_value={'selector.go':(b'pinned original',expected)}):
    projection.check_selection_sources(vendor)
    for body in (b'pinned original',expected.replace(b'exact interruption\n',b''),expected+b'foreign mutation\n'):
     path.write_bytes(body)
     with self.assertRaisesRegex(ValueError,'changed native selection commit'):projection.check_selection_sources(vendor)
    path.unlink();target=vendor/'foreign.go';target.write_bytes(expected);path.symlink_to(target)
    with self.assertRaisesRegex(ValueError,'changed native selection commit'):projection.check_selection_sources(vendor)
 def test_socks_reality_scope_and_inventory(self):
  self.assertEqual(gate.SOCKS_XRAY_FILES,{'socks5--final-'+gate.socks_label('reality-vision',a,b)+'.json' for a in gate.LAYERS for b in gate.LAYERS})
  self.assertEqual(len(gate.FILES),346)
  self.assertEqual(len(gate.SOCKS_FILES),45)
  groups={p:v for p,v in gate.CORE.items() if p.startswith('TestImportedEntrySOCKSRealityVision')}
  self.assertEqual(len(groups),9)
  expected=gate.names(groups)
  self.assertEqual(len(expected),88)
  events=[{'Action':a,'Test':n} for n in sorted(expected) for a in ('run','pass')]
  gate.require_verdicts('\n'.join(map(json.dumps,events)),expected)
  for name in sorted(expected):
   missing=[e for e in events if e['Test']!=name]
   with self.assertRaises(ValueError):gate.require_verdicts('\n'.join(map(json.dumps,missing)),expected)
  for final in ('reality-pq-vision','reality-xhttp','split','max'):
   self.assertNotIn('socks5--final-'+final+'.json',gate.FILES)
  for layer in gate.LAYERS[1:]:
   self.assertIn('socks5--final-reality-vision--'+layer+'.json',gate.FILES)
 def test_socks_reality_causal_receipts(self):
  controls=gate.socks_xray_controls()
  self.assertEqual(len(controls),3)
  for name,source,before,after,parent,leaf,witness in controls:
   with self.subTest(control=name):
    self.assertEqual((ROOT/source).read_text().count(before),1)
    self.assertNotEqual(before,after)
    case=parent+'/'+leaf
    events=[{'Action':'run','Test':parent},{'Action':'run','Test':case},{'Action':'output','Test':case,'Output':witness},{'Action':'fail','Test':case},{'Action':'fail','Test':parent}]
    raw='\n'.join(map(json.dumps,events))
    gate.require_socks_xray_control(raw,1,parent,leaf,witness)
    for mutation in (events[:-1],events+[events[-1]],events[:2]+events[3:],events+[{'Action':'skip','Test':case}],events+[{'Action':'fail','Test':'foreign'}],events[:2]+[dict(events[2],Test=parent)]+events[3:]):
     with self.assertRaises(ValueError):gate.require_socks_xray_control('\n'.join(map(json.dumps,mutation)),1,parent,leaf,witness)
    for marker in ('panic:','WARNING: DATA RACE','original SOCKS REALITY proof worker did not join','original SOCKS REALITY controller did not close'):
     with self.assertRaises(ValueError):gate.require_socks_xray_control(raw+'\n'+marker,1,parent,leaf,witness)
    with self.assertRaises(ValueError):gate.require_socks_xray_control(raw,0,parent,leaf,witness)
 def test_socks_reality_mobile_parser_is_mandatory(self):
  groups=gate.native_parser_groups(False)
  self.assertEqual(groups[gate.SOCKS_XRAY_PARSER],[])
  self.assertEqual(groups['TestRouterImportedEntryPairedFinalNativeGraphs'],sorted(gate.FILES))
  self.assertEqual(len(gate.FILES),346)
  expected=gate.names(groups)
  self.assertEqual(len(expected),len(gate.FILES)+105)
  events=[{'Action':a,'Test':n} for n in sorted(expected) for a in ('run','pass')]
  gate.require_verdicts('\n'.join(map(json.dumps,events)),expected)
  missing=[e for e in events if e['Test']!=gate.SOCKS_XRAY_PARSER]
  with self.assertRaises(ValueError):gate.require_verdicts('\n'.join(map(json.dumps,missing)),expected)
  duplicate=events+[{'Action':'pass','Test':gate.SOCKS_XRAY_PARSER}]
  with self.assertRaises(ValueError):gate.require_verdicts('\n'.join(map(json.dumps,duplicate)),expected)
  self.assertNotIn(gate.SOCKS_XRAY_PARSER,gate.native_parser_groups(True))
 def android_host(self):
  spec=importlib.util.spec_from_file_location('android_imported_cli',ROOT/'android/test_android_imported_router.py');host=importlib.util.module_from_spec(spec);spec.loader.exec_module(host)
  return host
 def test_android_group_union_retains_every_phase_and_file(self):
  host=self.android_host();groups=gate.android_group_inventory()
  phases=[p for group,_,_ in groups for p in group]
  self.assertEqual(len(host.PRIMARY_PHASES),33)
  self.assertEqual(len(host.CONNECT_LAYER_PHASES),4)
  self.assertEqual(len(phases),len(set(phases)))
  self.assertEqual(set(phases),set(host.PRIMARY_PHASES+host.CONNECT_LAYER_PHASES))
  self.assertEqual(set().union(*(a for _,a,_ in groups)),{'android-'+name for name in gate.FILES})
  self.assertEqual(set().union(*(b for _,_,b in groups)),{'android-'+name for name in gate.CONNECT_LAYER_FILES})
  self.assertEqual(sum(len(a) for _,a,_ in groups),len(gate.FILES))
  self.assertEqual(sum(len(b) for _,_,b in groups),32)
  for changed in (gate.ANDROID_PHASE_GROUPS[:-1],gate.ANDROID_PHASE_GROUPS[:1]+gate.ANDROID_PHASE_GROUPS[1:5]+(gate.ANDROID_PHASE_GROUPS[0][:4],),gate.ANDROID_PHASE_GROUPS[:-1]+(('foreign',*gate.ANDROID_PHASE_GROUPS[-1][1:]),)):
   with self.assertRaises(ValueError):gate.android_group_inventory(changed)
  with mock.patch.object(gate,'FILES',gate.FILES|{'foreign.json'}),self.assertRaises(ValueError):gate.android_group_inventory()
 def test_android_group_exports_reject_missing_foreign_link_and_duplicate(self):
  for fault in ('missing','foreign','link','duplicate','empty','oversized'):
   with self.subTest(fault=fault),tempfile.TemporaryDirectory() as temporary:
    root=Path(temporary);source=root/'source';source.mkdir();target=root/'joined';target.mkdir()
    for name in ('a.json','b.json'):(source/name).write_text('original captured bytes')
    if fault=='missing':(source/'a.json').unlink()
    elif fault=='foreign':(source/'foreign.json').write_text('{}')
    elif fault=='link':(source/'a.json').unlink();(source/'a.json').symlink_to(source/'b.json')
    elif fault=='duplicate':(target/'a.json').write_text('earlier owner')
    elif fault=='empty':(source/'a.json').write_text('')
    else:
     with (source/'a.json').open('wb') as stream:stream.truncate(8*1024*1024+1)
    with self.assertRaises(ValueError):gate.merge_android_exports(source,target,{'a.json','b.json'})
    self.assertFalse((target/'b.json').exists())
 def test_android_groups_keep_process_bounds_and_exact_union(self):
  with tempfile.TemporaryDirectory() as temporary:
   root=Path(temporary);env={'retained':'original'}
   def producer(command,**kwargs):
    self.assertEqual(kwargs['timeout'],240);self.assertTrue(kwargs['check'])
    self.assertEqual(kwargs['cwd'],gate.ROOT)
    self.assertEqual(kwargs['env']['retained'],'original')
    self.assertTrue(all(command[i]=='--phase' for i in range(2,len(command),2)))
    phases=tuple(command[3::2]);self.assertIn(phases,gate.ANDROID_PHASE_GROUPS)
    original=set();layers=set()
    for phase in phases:
     a,b=gate.android_phase_files(phase);original.update(a);layers.update(b)
    for name in original:(Path(kwargs['env']['ROUTERVPN_ANDROID_IMPORTED_ENTRY_FIXTURES'])/name).write_text('owned fixture bytes')
    for name in layers:(Path(kwargs['env']['ROUTERVPN_ANDROID_CONNECT_LAYER_FIXTURES'])/name).write_text('owned fixture bytes')
   with mock.patch.object(gate.subprocess,'run',side_effect=producer) as run,contextlib.redirect_stdout(io.StringIO()):
    primary,layers=gate.run_android_sources(root,env)
   self.assertEqual(run.call_count,6)
   self.assertEqual({p.name for p in primary.iterdir()},{'android-'+n for n in gate.FILES})
   self.assertEqual({p.name for p in layers.iterdir()},{'android-'+n for n in gate.CONNECT_LAYER_FILES})
   self.assertEqual(env['ROUTERVPN_ANDROID_IMPORTED_ENTRY_FIXTURES'],str(primary))
   self.assertEqual(env['ROUTERVPN_ANDROID_CONNECT_LAYER_FIXTURES'],str(layers))
 def test_android_group_failure_or_timeout_cannot_be_a_completed_union(self):
  for failure in (gate.subprocess.CalledProcessError(1,['fixture']),gate.subprocess.TimeoutExpired(['fixture'],240)):
   with tempfile.TemporaryDirectory() as temporary,mock.patch.object(gate.subprocess,'run',side_effect=failure) as run:
    with self.assertRaises(type(failure)):gate.run_android_sources(Path(temporary),{})
    self.assertEqual(run.call_count,1)
 def test_android_cli_preserves_defaults_and_refuses_changed_selection(self):
  host=self.android_host()
  self.assertEqual(host.selected_phases(),host.PRIMARY_PHASES+host.CONNECT_LAYER_PHASES+host.PROXY_XRAY_PHASES+host.CONNECT_XRAY_PHASES)
  self.assertEqual(host.PROXY_XRAY_PHASES,('proxy-reality--shadowsocks','proxy-reality--hysteria2'))
  self.assertEqual(host.CONNECT_XRAY_PHASES,('connect-reality--http-connect','connect-reality--https-connect'))
  for phases in ((),('foreign',),(host.PRIMARY_PHASES[0],)*2):
   with self.assertRaises(ValueError):host.selected_phases(phases)
  selected=(host.PRIMARY_PHASES[1],host.CONNECT_LAYER_PHASES[-1])
  with mock.patch.object(host,'main') as run:
   host.cli(['--phase',selected[0],'--phase',selected[1]])
   self.assertEqual(run.call_args.kwargs.get('phases',run.call_args.args[0] if run.call_args.args else None),selected)
  for args in (['--phase','foreign'],['--phase',selected[0],'--phase',selected[0]],['--phase']):
   with mock.patch.object(host,'main') as run,contextlib.redirect_stderr(io.StringIO()),self.assertRaises((ValueError,SystemExit)):
    host.cli(args)
   run.assert_not_called()
 def test_shipping_invocations(self):
  self.assertIn("test_mobile_imported_entry.py'),str(vendor),'--android'",(ROOT/'deploy/test_android_multihop_pinned.py').read_text())
  self.assertIn('"deploy/test_mobile_imported_entry.py", source, "--native-peers"',(ROOT/'deploy/test_desktop_node_physical.py').read_text())
  self.assertIn('node_imported_router_entry_test.go.tmpl',(ROOT/'deploy/prepare-desktop-external.py').read_text())
  self.assertIn('routervpn_imported_entry_native_test.go.tmpl',(ROOT/'deploy/prepare-mobile-multihop.py').read_text())
if __name__=='__main__':unittest.main()
