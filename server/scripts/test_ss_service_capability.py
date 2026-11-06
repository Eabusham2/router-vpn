#!/usr/bin/env python3
"""Actual private bundle capability capture and transactional refusal controls."""
import base64
import importlib.util
import json
import subprocess
import sys
import shlex
import shutil
from pathlib import Path
import tempfile
import unittest

HERE=Path(__file__).resolve().parent
def load(name):
 s=importlib.util.spec_from_file_location(name,HERE/(name+'.py'));m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
CAP=load('ss_service_capability')
BUNDLE=load('test_create_bundle_transaction')

class SSServiceCapability(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory(prefix='routervpn-ss-service-');self.addCleanup(self.temp.cleanup)
  self.base=Path(self.temp.name)/'state';BUNDLE.seed(self.base)
  self.out={'type':'shadowsocks','tag':'proxy','server':'vpn.example','server_port':8388,'method':'2022-blake3-aes-256-gcm','password':base64.b64encode(b's'*32).decode()}
  self.server=CAP.encoded({'inbounds':[{'type':'shadowsocks','tag':'ss-in','listen':'::','listen_port':8388,'method':self.out['method'],'password':self.out['password']} ]})
  self.client=CAP.encoded({'outbounds':[self.out]})
  self.claim=CAP.declaration(self.server,self.client,CAP.IMAGE,CAP.IMAGE)
  self.write('config/transports/server.json',self.server)
  self.write('client-bundle/generated/shadowsocks/sing-box.json',self.client)
  self.write('config/transports/ss-service.json',CAP.encoded(self.claim))
 def write(self,path,body):BUNDLE.private_write(self.base/path,body.decode())
 def run_bundle(self):
  result=BUNDLE.run(self.base)
  self.assertEqual(result.returncode,0,result.stderr)
  return json.loads((self.base/'client-bundle/router-vpn-bundle.json').read_bytes())
 def test_actual_bundle_preserves_source_and_captures_private_binding(self):
  bundle=self.run_bundle();files=bundle['profiles']['shadowsocks'];claim=json.loads(base64.b64decode(files[CAP.ASSET]))
  self.assertEqual(base64.b64decode(files['sing-box.json']),self.client)
  self.assertNotIn('udp_over_tcp',json.loads(self.client)['outbounds'][0])
  self.assertEqual(claim['node_id'],bundle['nodeProofId'])
  self.assertEqual(claim['endpoint'],bundle['endpoint'])
  self.assertEqual(claim['key_sha256'],CAP.digest(self.out['password'].encode()))
  self.assertEqual(claim['source_sha256'],CAP.digest(self.client))
  self.assertEqual(claim['uot_version'],2)
  self.assertNotIn(self.out['password'],json.dumps(claim))
  BUNDLE.assert_private_outputs(self.base)
 def test_absent_and_unsupported_declarations_do_not_advertise(self):
  path=self.base/'config/transports/ss-service.json';path.unlink()
  self.assertNotIn(CAP.ASSET,self.run_bundle()['profiles']['shadowsocks'])
  for image in ('ghcr.io/sagernet/sing-box:v1.12.0','foreign.example/ss:v1.13.12'):
   with self.subTest(image=image):
    claim=CAP.declaration(self.server,self.client,image,CAP.IMAGE);self.write('config/transports/ss-service.json',CAP.encoded(claim))
    self.assertNotIn(CAP.ASSET,self.run_bundle()['profiles']['shadowsocks'])
 def test_malformed_and_stale_sources_leave_canonical_bundle_unchanged(self):
  self.run_bundle();before=BUNDLE.canonical(self.base)
  faults=('empty','extra','schema-bool','source-hash','server-hash','source-key','source-port','source-endpoint','server-key','server-port','server-mode','unverified-sidecar')
  for fault in faults:
   with self.subTest(fault=fault):
    claim=dict(self.claim);server=json.loads(self.server);client=json.loads(self.client)
    if fault=='empty':claim={}
    elif fault=='extra':claim['ready']=True
    elif fault=='schema-bool':claim['schema']=True
    elif fault=='source-hash':claim['source_sha256']='0'*64
    elif fault=='server-hash':claim['server_sha256']='0'*64
    elif fault.startswith('source-'):client['outbounds'][0][{'source-key':'password','source-port':'server_port','source-endpoint':'server'}[fault]]='foreign'
    elif fault.startswith('server-'):server['inbounds'][0][{'server-key':'password','server-port':'listen_port','server-mode':'type'}[fault]]='foreign'
    elif fault=='unverified-sidecar':self.write('client-bundle/generated/shadowsocks/'+CAP.ASSET,b'{}')
    self.write('config/transports/ss-service.json',CAP.encoded(claim));self.write('config/transports/server.json',CAP.encoded(server));self.write('client-bundle/generated/shadowsocks/sing-box.json',CAP.encoded(client))
    result=BUNDLE.run(self.base);self.assertNotEqual(result.returncode,0,fault);self.assertEqual(BUNDLE.canonical(self.base),before,fault)
    extra=self.base/'client-bundle/generated/shadowsocks'/CAP.ASSET
    if extra.exists():extra.unlink()
  self.write('config/transports/ss-service.json',CAP.encoded(self.claim));self.write('config/transports/server.json',self.server);self.write('client-bundle/generated/shadowsocks/sing-box.json',self.client)
  self.run_bundle();self.assertEqual(BUNDLE.canonical(self.base),before)
 def test_foreign_node_or_endpoint_cannot_create_sidecar(self):
  for node,endpoint in [('wrong','vpn.example'),('a'*64,'foreign.example')]:
   with self.assertRaises(ValueError):CAP.capture(self.claim,self.server,self.client,node,endpoint)
 def test_actual_generator_preserves_all_original_transport_bytes(self):
  root=HERE.parents[1]
  docker=(root/'deploy/setup-methods-interoperability.Dockerfile').read_text()
  stage=docker.split(' AS method-base\n',1)[1].split('\nFROM ',1)[0]
  copied=Path(self.temp.name)/'image-source'
  for line in stage.splitlines():
   if not line.startswith('COPY '):continue
   fields=shlex.split(line)
   if not fields or fields[0]!='COPY' or fields[1].startswith('--from='):continue
   target=fields[-1]
   if not target.startswith('/src/'):continue
   for name in fields[1:-1]:
    destination=copied/target.removeprefix('/src/')
    if target.endswith('/'):destination/=Path(name).name
    destination.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(root/name,destination)
  self.assertTrue((copied/'server/scripts/ss_service_capability.py').is_file())
  self.assertTrue((copied/'server/portainer-current.yaml').is_file())
  source=(copied/'server/scripts/generate-transports.sh').read_text()
  body=source[source.index('python3 - "$GEN_TMP"'):].split("<<'PY'\n",1)[1].split('\nPY\n',1)[0]
  boundary='"/src/server/scripts/ss_service_capability.py"'
  self.assertEqual(body.count(boundary),1)
  body=body.replace(boundary,repr(str(copied/'server/scripts/ss_service_capability.py')))
  body=body.replace('"/src/server/portainer-current.yaml"',repr(str(copied/'server/portainer-current.yaml')))
  expected={'generated-secrets.json':'a132a0672a594244ebe5b9a11674b39f0984ffc4d5fbd0f97d09b571f12ac36c','hysteria2.json':'52516784fccab0f9ba361c59426fa76481ea28248f056767ea3dbf4cacff2544','server.json':'b3ef69eeea80787ee8b433285f056b92ca7e1e69d0a3e4f81ef9f8a94ed7eca0','shadowsocks.json':'79a60163717fcbdbdb322f88d5b4a997f1d3a1447782480e0208d915e3e7a721'}
  # Exact old shipping generator bytes at c70778ea for the same public fixture.
  for image in (CAP.IMAGE,'foreign.example/ss:old'):
   with self.subTest(image=image),tempfile.TemporaryDirectory() as directory:
    args=[directory,'192.0.2.44','10.77.0.1','8443','8388','c3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3M=','fixture-hysteria-password','router-vpn.home',image]
    subprocess.run([sys.executable,'-c',body,*args],check=True,timeout=15)
    output=Path(directory)
    self.assertEqual({name:CAP.digest((output/name).read_bytes()) for name in expected},expected)
    declaration=json.loads((output/'ss-service.json').read_bytes())
    self.assertEqual(declaration['configured_image'],CAP.IMAGE)
    self.assertEqual(declaration['generator_image'],image)
    claim=CAP.capture(declaration,(output/'server.json').read_bytes(),(output/'shadowsocks.json').read_bytes(),'a'*64,'192.0.2.44')
    self.assertEqual(claim is not None,image==CAP.IMAGE)
  self.assertIn('"$BASE/config/transports/ss-service.json=$GEN_TMP/ss-service.json"',source)
 def test_configured_identity_follows_actual_production_materialization(self):
  path=HERE.parents[1]/'deploy/materialize-production-compose.py'
  spec=importlib.util.spec_from_file_location('capability_production_compose',path);prod=importlib.util.module_from_spec(spec);spec.loader.exec_module(prod)
  source=(HERE.parent/'portainer-current.yaml').read_text()
  for body in (source,prod.materialize(source,'a'*40)):
   self.assertEqual(CAP.configured_service_image(body.encode()),CAP.IMAGE)
   altered=body.replace('  transports:\n    image: '+CAP.IMAGE,'  transports:\n    image: foreign.example/ss:old')
   self.assertNotEqual(altered,body)
   image=CAP.configured_service_image(altered.encode())
   claim=CAP.declaration(self.server,self.client,CAP.IMAGE,image)
   self.assertIsNone(CAP.capture(claim,self.server,self.client,'a'*64,'vpn.example'))
  for body in ('services:\n','services:\n  transports:\n    image: ${SING_BOX_IMAGE}\n',source+source):
   with self.assertRaises(ValueError):CAP.configured_service_image(body.encode())
 def test_unconfigured_setup_placeholder_grants_nothing(self):
  source=dict(self.out,server='router.invalid');client=CAP.encoded({'outbounds':[source]});claim=CAP.declaration(self.server,client,CAP.IMAGE,CAP.IMAGE)
  self.assertIsNone(CAP.capture(claim,self.server,client,'a'*64,''))

if __name__=='__main__':unittest.main()
