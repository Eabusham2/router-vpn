#!/usr/bin/env python3
from pathlib import Path
import importlib.util, json, base64, copy, subprocess, tempfile, unittest
from unittest import mock
ROOT=Path(__file__).resolve().parents[1]
def module(name,path):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
PAIR=module('paired_layer',ROOT/'server/scripts/provision-multihop-relays.py')
class PairedLayer(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.temp=tempfile.TemporaryDirectory();cls.agent=Path(cls.temp.name)/'agent'
  subprocess.run(['go','build','-buildvcs=false','-o',str(cls.agent),'./cmd/router-agent'],cwd=ROOT,check=True,timeout=90)
 @classmethod
 def tearDownClass(cls):cls.temp.cleanup()
 def source(self,mode):
  transport={'type':'shadowsocks','tag':'proxy','server':'192.0.2.2','server_port':8388,'method':'2022-blake3-aes-256-gcm','password':base64.b64encode(b'x'*32).decode()}
  graph={'inbounds':[{'type':'tun','auto_route':True,'strict_route':True}], 'outbounds':[transport],'route':{'final':'proxy'}}
  profile={'id':'exit','node_kind':'router-vpn','node_proof_id':'b'*64,'endpoint':'192.0.2.2','router_api':'http://10.88.0.1:8787','adguard_ipv4':'10.88.0.1','start_layer':mode}
  return {'selectedRouterID':'exit','routerProfiles':[profile],'profiles':{'shadowsocks':{'sing-box.json':base64.b64encode(json.dumps(graph).encode()).decode()}}}
 def pair(self,value):
  run=subprocess.run
  def compile(command,**kwargs):
   self.assertEqual(command[:2],['/usr/local/bin/router-vpn-agent','compile-relay-start-layer'])
   self.assertEqual(kwargs['stderr'],subprocess.DEVNULL)
   return run([str(self.agent),*command[1:]],**kwargs)
  with mock.patch.object(PAIR.subprocess,'run',side_effect=compile):return PAIR.pair(value,'owned-exit')
 def test_exact_selected_layer_and_credentials_are_paired(self):
  for alias,mode in [('aes','aes-256-gcm'),('aes+xor','aes-256-gcm+xor-whitening')]:
   value=self.source(alias);snapshot=copy.deepcopy(value);out=self.pair(value)
   self.assertEqual(value,snapshot);self.assertEqual(len(out),1)
   self.assertEqual(out[0]['start_layer']['mode'],mode)
   self.assertEqual(out[0]['start_layer']['api'],value['routerProfiles'][0]['router_api'])
   self.assertEqual(out[0]['start_layer']['transport']['password'],out[0]['transport']['password'])
   out[0]['start_layer']['transport']['password']='changed-output'
   self.assertEqual(value,snapshot)
 def test_off_never_calls_an_unrequested_compiler(self):
  for mode in ['', 'off','disabled','none']:
   value=self.source(mode)
   with mock.patch.object(PAIR.subprocess,'run',side_effect=AssertionError('off must not invoke compiler')):
    out=PAIR.pair(value,'exit')
   self.assertNotIn('start_layer',out[0])
 def test_bad_input_or_pairing_never_downgrades_to_bare_exit(self):
  for bad in ['xor',True,None,17]:
   with self.assertRaises(ValueError):self.pair(self.source(bad))
  for fault in ['host','api','extra','key']:
   value=self.source('aes');assets=value['profiles']['shadowsocks'];graph=json.loads(base64.b64decode(assets['sing-box.json']))
   if fault=='host':graph['outbounds'][0]['server']='192.0.2.99'
   if fault=='api':value['routerProfiles'][0]['router_api']='http://127.0.0.1:8787'
   if fault=='extra':assets['helper']='e30='
   if fault=='key':graph['outbounds'][0]['password']='private-never-echo'
   assets['sing-box.json']=base64.b64encode(json.dumps(graph).encode()).decode();snapshot=copy.deepcopy(value)
   with self.assertRaises(ValueError) as err:self.pair(value)
   self.assertNotIn('private-never-echo',str(err.exception));self.assertEqual(value,snapshot)
if __name__=='__main__':unittest.main()
