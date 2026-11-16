#!/usr/bin/env python3
"""Actual no-TUN Server Box/OpenVPN components; no installed-carrier claim.

Every case retains its actual concrete endpoint, connected packet receipt,
private/public proof and selected DNS. Only the command-container fields and
first physical UDP tuple are component fixtures. The owner helper and lifetime
methods are copied byte-for-byte from the shipping worker, apart from package.
"""
from pathlib import Path
import hashlib
import importlib.util
import json
import tempfile

ROOT=Path(__file__).resolve().parents[1]
PACKAGE='github.com/sagernet/sing-box/protocol/routervpnamnezia'
TEST='TestNativeOpenVPNServerOriginalEndpoint'
TEMPLATES=('mobile/server_chain_component/openvpn_owner.go.tmpl','mobile/server_chain_component/openvpn_test.go.tmpl')
CASES=tuple(f'wg/{network}/1/{layer}/original' for network in ('tcp','udp') for layer in ('off','aes-256-gcm','aes-256-gcm+xor-whitening'))+(
 'wg/tcp/5/off/original','wg/udp/5/off/original',
 'awg2-fast/tcp/1/off/original','awg2-fast/udp/1/off/original','awg2-strong/udp/5/off/original',
 'wg/tcp/1/off/wrong-server-password','wg/udp/1/off/wrong-server-password',
 'wg/tcp/1/off/reconnect','wg/udp/1/off/reconnect',
 'wg/tcp/1/aes-256-gcm/final-layer-key','wg/udp/1/aes-256-gcm+xor-whitening/final-layer-key')
CONTROLS=(
 ('map-owner','wg/tcp/1/off/original','n.outputs[r.capture.Middle.Tag] != r.endpoint || ', '', 'foreign native outbound retained Server authority'),
 ('original-owner','wg/tcp/1/off/original','r.original != r || ', '', 'copied original owner retained Server authority'),
 ('connected-receipt','wg/tcp/1/off/reconnect','r.state == nil || *r.state != state','r.state == nil','reconnected native packet owner replaced original pinned receipt'))

def load(name):
 spec=importlib.util.spec_from_file_location('openvpn_server_'+name,ROOT/'deploy'/name)
 module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module

def function(source,signature):
 if source.count(signature)!=1:raise ValueError('Original Server lifetime signature changed')
 begin=source.index(signature)
 return source[begin:source.index('\n}\n',begin)+3]

def sources():
 native=(ROOT/'mobile/server_chain/native.go.tmpl').read_text()
 helper=(ROOT/'mobile/server_chain/openvpn.go.tmpl').read_bytes()
 if not helper.startswith(b'package main\n'):raise ValueError('Original OpenVPN helper package changed')
 owner=(ROOT/TEMPLATES[0]).read_text()
 if owner.count('// ORIGINAL_LIFETIME_METHODS')!=1 or owner.count('// ORIGINAL_DRAIN_BUDGET')!=1:raise ValueError('Original lifetime projection markers changed')
 methods='\n'.join(function(native,signature) for signature in (
 'func (n *routerVPNServerChain) initializeLifetime(', 'func (n *routerVPNServerChain) closeTransportContext('))
 command=(ROOT/'mobile/server_chain/command.go.tmpl').read_text()
 budget=[line for line in command.splitlines() if line.startswith('const routerVPNServerChainDrainBudget = ')]
 if len(budget)!=1:raise ValueError('Original bounded transport lifetime absent')
 owner=owner.replace('// ORIGINAL_LIFETIME_METHODS',methods).replace('// ORIGINAL_DRAIN_BUDGET',budget[0])
 return {'server_openvpn_component_owner.go':owner.encode(),
         'server_openvpn_component_helper.go':helper.replace(b'package main\n',b'package routervpnamnezia\n',1),
         'server_openvpn_component_test.go':(ROOT/TEMPLATES[1]).read_bytes()}

def expected(case):
 if case not in CASES:raise ValueError("Uncaptured OpenVPN Server case")
 return {TEST:1,TEST+"/"+case.replace("/","_"):1}

def verdict(output,case):
 helper=load('test_desktop_native_root_phases.py');helper.PACKAGE=PACKAGE
 rows,runs,passes,failures,ended=helper.load_receipt().complete_receipt(output)
 if any(any(marker in row.get('Output','') for marker in ('panic:', 'fatal error:', 'test timed out')) for row in rows):raise ValueError('OpenVPN Server component contains fatal native output')
 if ended!='pass' or failures or runs!=expected(case) or passes!=expected(case):
  raise ValueError('OpenVPN Server component omitted, duplicated or failed its original native root')
 return 2

def rejected(output,case,witness):
 helper=load('test_desktop_native_root_phases.py');helper.PACKAGE=PACKAGE
 rows,runs,passes,failures,ended=helper.load_receipt().complete_receipt(output)
 return not any(any(marker in row.get('Output','') for marker in ('panic:', 'fatal error:', 'test timed out', 'failed joined retirement', 'reference source did not join', 'failed retirement')) for row in rows) and case in CASES and ended=='fail' and runs==expected(case) and not passes and failures==expected(case) and any(witness in row.get('Output','') for row in rows)

def execute(core,target,tags,env,runner):
 if target not in ('linux/amd64','linux/arm64') or (env.get('GOOS'),env.get('GOARCH'))!=tuple(target.split('/')) or env.get('CGO_ENABLED','1')!='1':raise ValueError('OpenVPN Server components require original native Linux race target')
 core=Path(core).resolve();captured=dict(env)
 worker=load('test_server_node_chain_native.py');worker.verify_sources(core)
 peer=load('prepare-desktop-external.py')
 def verify_peers():
  for name,target in peer.PEER_TEMPLATES.items():
   actual=core/target
   if actual.is_symlink() or not actual.is_file() or actual.read_bytes()!=(ROOT/'mobile/desktop'/name).read_bytes():raise ValueError('OpenVPN Server component changed its original native peer source')
 verify_peers()
 helpers=load('test_desktop_native_root_phases.py');original=helpers.source_digest(core);content=sources()
 source_hash=hashlib.sha256(b''.join(name.encode()+b'\0'+raw for name,raw in sorted(content.items()))).hexdigest()
 with tempfile.TemporaryDirectory(prefix='routervpn-openvpn-server-components-') as directory:
  workspace=Path(directory);overlay={}
  for name,raw in content.items():
   p=workspace/name;p.write_bytes(raw);overlay[str(core/'protocol/routervpnamnezia'/name)]=str(p)
  overlay_file=workspace/'original.json';overlay_file.write_text(json.dumps({'Replace':overlay}))
  image=workspace/'original.test'
  base=['go','test','-c','-race','-p=1','-mod=readonly','-tags='+tags,'-ldflags=-checklinkname=0']
  runner([*base,'-overlay='+str(overlay_file),'-o',image,'./protocol/routervpnamnezia'],cwd=core,env=captured,timeout=300)
  identity=helpers.image_identity(image)
  def unchanged():
   if env!=captured or sources()!=content or helpers.source_digest(core)!=original or helpers.image_identity(image)!=identity or any(Path(overlay[str(core/'protocol/routervpnamnezia'/name)]).read_bytes()!=raw for name,raw in content.items()):raise ValueError('OpenVPN Server component changed original source, lifetime, environment or image')
   worker.verify_sources(core);verify_peers()
  unchanged()
  listing=runner([image,'-test.list=^'+TEST+'$'],cwd=core,env=captured,timeout=60).strip().splitlines()
  if listing!=[TEST]:raise ValueError('OpenVPN Server compiled root discovery changed')
  receipts={}
  for case in CASES:
   unchanged();case_env=dict(captured,ROUTERVPN_SERVER_OPENVPN_COMPONENT=case)
   output=runner(['go','tool','test2json','-p',PACKAGE,'-t',image,'-test.v','-test.count=1','-test.timeout=60s','-test.run=^'+TEST+'$'],cwd=core,env=case_env,timeout=75)
   receipts[case]=verdict(output,case);unchanged()
  # Actual compiled causals keep the same concrete provider/Box/root and
  # require its precise failed assertion; compilation errors cannot qualify.
  import subprocess
  for label,case,before,after,witness in CONTROLS:
   unchanged();raw=content['server_openvpn_component_helper.go'].decode()
   if raw.count(before)!=1:raise ValueError('OpenVPN Server causal source anchor changed: '+label)
   mutant=workspace/(label+'.go');mutant.write_text(raw.replace(before,after,1))
   changed=dict(overlay);changed[str(core/'protocol/routervpnamnezia/server_openvpn_component_helper.go')]=str(mutant)
   control=workspace/(label+'.json');control.write_text(json.dumps({'Replace':changed}));control_image=workspace/(label+'.test')
   runner([*base,'-overlay='+str(control),'-o',control_image,'./protocol/routervpnamnezia'],cwd=core,env=captured,timeout=300)
   control_identity=helpers.image_identity(control_image)
   result=subprocess.run(['go','tool','test2json','-p',PACKAGE,'-t',str(control_image),'-test.v','-test.count=1','-test.timeout=60s','-test.run=^'+TEST+'$'],cwd=core,env=dict(captured,ROUTERVPN_SERVER_OPENVPN_COMPONENT=case),text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=75)
   if result.returncode!=1 or result.stderr or not rejected(result.stdout,case,witness) or helpers.image_identity(control_image)!=control_identity:raise ValueError('OpenVPN Server causal control lacked its actual original failure: '+label+'\n'+result.stdout+result.stderr)
   print('Original OpenVPN Server compiled causal: '+label,flush=True)
   print(result.stdout,end='',flush=True)
   unchanged()
  result={'kind':'native-openvpn-server-components-v1','target':target,'source_sha256':original,'projection_sha256':source_hash,'image_sha256':identity[1],'race':True,'cases':receipts,'controls':[row[0] for row in CONTROLS],'installed_carrier_acceptance':False}
  print('Original OpenVPN Server native components: '+json.dumps(result,sort_keys=True),flush=True);return result
