#!/usr/bin/env python3
"""Exact OpenVPN Server component inventory, source projection and causal guards."""
import ast
import importlib.util
import json
from pathlib import Path
import unittest
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('openvpn_server_components',ROOT/'deploy/test_server_node_chain_openvpn_native.py')
RUN=importlib.util.module_from_spec(spec);spec.loader.exec_module(RUN)

def transcript(case,failed=False,witness=''):
 child=RUN.TEST+'/'+case.replace('/','_')
 def row(action,test=None,**fields):return dict(Action=action,Package=RUN.PACKAGE,**({'Test':test} if test else {}),**fields)
 rows=[row('start'),row('run',RUN.TEST),row('run',child)]
 if witness:rows.append(row('output',child,Output=witness))
 rows += [row('fail' if failed else 'pass',child),row('fail' if failed else 'pass',RUN.TEST),row('fail' if failed else 'pass')]
 return rows

def output(rows):return '\n'.join(json.dumps(row) for row in rows)+'\n'

def required_wiring(text):
 tree=ast.parse(text);parents={child:parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}
 expected=ast.parse("openvpn_server.execute(source, target, ','.join(tags(target)), env, run)").body[0].value
 calls=[n for n in ast.walk(tree) if isinstance(n,ast.Call) and ast.dump(n,include_attributes=False)==ast.dump(expected,include_attributes=False)]
 if len(calls)!=1:raise ValueError('required native OpenVPN invocation changed')
 parent=parents.get(calls[0]);guard=False
 while parent is not None:
  if isinstance(parent,ast.If) and ast.dump(parent.test,include_attributes=False)==ast.dump(ast.parse("target.startswith('linux/')",mode='eval').body,include_attributes=False):guard=True
  parent=parents.get(parent)
 if not guard:raise ValueError('required native OpenVPN invocation lost Linux guard')

class OpenVPNServerNativeRunner(unittest.TestCase):
 def test_complete_original_matrix(self):
  self.assertEqual(len(RUN.CASES),17);self.assertEqual(len(set(RUN.CASES)),17)
  for network in ('tcp','udp'):
   for layer in ('off','aes-256-gcm','aes-256-gcm+xor-whitening'):self.assertIn(f'wg/{network}/1/{layer}/original',RUN.CASES)
   for fault in ('reconnect','wrong-server-password'):self.assertIn(f'wg/{network}/1/off/{fault}',RUN.CASES)
   self.assertIn(f'wg/{network}/5/off/original',RUN.CASES)
  for case in RUN.CASES:self.assertEqual(RUN.verdict(output(transcript(case)),case),2)
 def test_omission_duplicate_reordered_and_false_terminal(self):
  case=RUN.CASES[0];original=transcript(case)
  changed=[original[:i]+original[i+1:] for i in range(len(original))]
  changed += [original[:i]+[original[i]]+original[i:] for i in range(len(original))]
  changed += [original+[original[-1]],original[:-1]+[dict(original[-1],Action='output',Output='PASS')],original[:2]+[original[3],original[2]]+original[4:]]
  for rows in changed:
   with self.subTest(rows=rows),self.assertRaises(ValueError):RUN.verdict(output(rows),case)
 def test_skip_race_foreign_case_package_and_unknown_case(self):
  case=RUN.CASES[0]
  for mode in ('skip','race','foreign-case','foreign-package','fail'):
   rows=transcript(case)
   if mode=='skip':rows[3]['Action']='skip'
   if mode=='race':rows.insert(3,dict(Action='output',Package=RUN.PACKAGE,Test=RUN.TEST+'/'+case.replace('/','_'),Output='WARNING: DATA RACE'))
   if mode=='foreign-case':rows=transcript(RUN.CASES[1])
   if mode=='foreign-package':rows[0]['Package']='foreign'
   if mode=='fail':rows=transcript(case,True)
   with self.subTest(mode=mode),self.assertRaises(ValueError):RUN.verdict(output(rows),case)
  with self.assertRaises(ValueError):RUN.verdict(output(transcript(case)),'foreign')
 def test_success_cannot_conceal_fatal_output(self):
  case=RUN.CASES[0]
  for marker in ('panic:', 'fatal error:', 'test timed out'):
   rows=transcript(case,False,marker)
   with self.subTest(marker=marker),self.assertRaises(ValueError):RUN.verdict(output(rows),case)
 def test_actual_negative_requires_exact_leaf_and_witness(self):
  for _,case,_,_,witness in RUN.CONTROLS:
   self.assertTrue(RUN.rejected(output(transcript(case,True,witness)),case,witness))
   self.assertFalse(RUN.rejected(output(transcript(case,True,'unrelated failure')),case,witness))
   self.assertFalse(RUN.rejected(output(transcript(case,False,witness)),case,witness))
   for marker in ('panic:', 'fatal error:', 'test timed out', 'failed joined retirement', 'reference source did not join', 'failed retirement'):
    self.assertFalse(RUN.rejected(output(transcript(case,True,witness+'\n'+marker)),case,witness))
  with self.assertRaises(ValueError):RUN.rejected('build failed',RUN.CASES[0],'witness')
 def test_helper_is_original_bytes_and_lifetime_is_exact(self):
  copies=RUN.sources();helper=(ROOT/'mobile/server_chain/openvpn.go.tmpl').read_bytes()
  self.assertEqual(copies['server_openvpn_component_helper.go'],helper.replace(b'package main\n',b'package routervpnamnezia\n',1))
  for name in RUN.ENDPOINT_TEMPLATES:
   raw=(ROOT/'mobile/server_chain'/name).read_bytes()
   self.assertEqual(copies['server_'+name.removesuffix('.tmpl')],raw.replace(b'\npackage main\n',b'\npackage routervpnamnezia\n',1))
  native=(ROOT/'mobile/server_chain/native.go.tmpl').read_text()
  for signature in ('func (n *routerVPNServerChain) initializeLifetime(', 'func (n *routerVPNServerChain) closeTransportContext('):
   self.assertIn(RUN.function(native,signature).encode(),copies['server_openvpn_component_owner.go'])
  self.assertEqual(copies['server_openvpn_component_test.go'],(ROOT/RUN.TEMPLATES[1]).read_bytes())
  self.assertIn(b'const routerVPNServerChainDrainBudget = 8 * time.Second',copies['server_openvpn_component_owner.go'])
 def test_actual_owner_control_anchors_unique(self):
  helper=(ROOT/'mobile/server_chain/openvpn.go.tmpl').read_text()
  for _,case,before,after,witness in RUN.CONTROLS:
   self.assertEqual(helper.count(before),1);self.assertNotEqual(before,after);self.assertIn(case,RUN.CASES)
   self.assertIn(witness,(ROOT/RUN.TEMPLATES[1]).read_text())
 def test_native_tag_cannot_silently_select_stub(self):
  with self.assertRaisesRegex(ValueError,'actual implementation'):
   RUN.execute(ROOT,'linux/amd64','with_wireguard',{'GOOS':'linux','GOARCH':'amd64'},lambda *a,**k:self.fail('stub component ran'))

 def test_native_target_guard_cannot_cross_compile(self):
  for target,env in [('windows/amd64',{'GOOS':'windows','GOARCH':'amd64'}),('linux/amd64',{'GOOS':'linux','GOARCH':'arm64'}),('linux/amd64',{'GOOS':'linux','GOARCH':'amd64','CGO_ENABLED':'0'})]:
   with self.subTest(target=target,env=env),self.assertRaises(ValueError):RUN.execute(ROOT,target,'with_openvpn',env,lambda *a,**k:self.fail('cross-host gate ran'))
 def test_required_release_and_source_closure(self):
  builder=RUN.load('build-native-runtime.py');inputs=set(builder.inputs())
  required=('deploy/test_server_node_chain_openvpn_native.py','deploy/test_server_node_chain_openvpn_native_runner.py',*RUN.TEMPLATES)
  for path in required:self.assertIn(ROOT/path,inputs)
  source=(ROOT/'deploy/build-native-runtime.py').read_text()
  required_wiring(source)
  prep=RUN.load('prepare-server-node-chain.py')
  for path in required:self.assertIn(ROOT/path,prep.inputs())

 def test_required_native_call_cannot_be_removed_commented_or_replaced(self):
  source=(ROOT/'deploy/build-native-runtime.py').read_text()
  anchor="openvpn_server.execute(source, target, ','.join(tags(target)), env, run)"
  for replacement in ('pass','# '+anchor,anchor.replace('target,','"windows/amd64",',1)):
   with self.subTest(replacement=replacement),self.assertRaises(ValueError):required_wiring(source.replace(anchor,replacement,1))

if __name__=='__main__':unittest.main()
