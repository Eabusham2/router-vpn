#!/usr/bin/env python3
"""Execute the shipping advanced-profile generator without network or real keys."""
from pathlib import Path
from unittest import mock
import json
import runpy
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
SCRIPT=ROOT/'server/scripts/generate-advanced-profiles.sh'
PREFIX='mlkem768x25519plus.native.600s.'
CLIENT=PREFIX+'client-fixture-not-a-real-secret'
SERVER=PREFIX+'server-fixture-not-a-real-secret'

class Generation(unittest.TestCase):
    def prepare(self,base,kind='normal'):
        config=base/'config/xray';config.mkdir(parents=True)
        root=base/'client-bundle/generated'
        entries=[{'tag':'reality-in','settings':{'decryption':'none'}},
                 {'tag':'pq-reality-in','settings':{'decryption':SERVER}},
                 {'tag':'max-xhttp-in','settings':{'decryption':'stale'}}]
        if kind=='reordered':entries.reverse()
        if kind=='missing-pq':entries=[x for x in entries if x['tag']!='pq-reality-in']
        if kind=='duplicate-pq':entries.append(entries[1])
        if kind=='plain-pq':entries[1]['settings']['decryption']='none'
        (config/'server.json').write_text(json.dumps({'inbounds':entries,'outbounds':[{'protocol':'freedom','tag':'direct'}]}))
        enc=None if kind=='missing-client' else ('none' if kind=='plain-client' else CLIENT)
        (config/'generated-secrets.json').write_text(json.dumps({'vless_encryption':enc}))
        for raw,asset in [('wg','wg.conf'),('wg','wg-socks.conf'),('awg2-strong','awg.conf'),('awg2-strong','awg-socks.conf')]:
            folder=root/raw;folder.mkdir(parents=True,exist_ok=True)
            (folder/asset).write_text('[Interface]\nPrivateKey = fixture\n[Peer]\nEndpoint = 192.0.2.1:51820\n')
        for mode,out in [('shadowsocks',{'type':'shadowsocks','tag':'proxy','server':'192.0.2.1','server_port':8388,'method':'2022-blake3-aes-128-gcm','password':'fixture'}),('hysteria2',{'type':'hysteria2','tag':'proxy','server':'192.0.2.1','server_port':443,'password':'fixture'})]:
            folder=root/mode;folder.mkdir(parents=True)
            (folder/'sing-box.json').write_text(json.dumps({'outbounds':[out]}))
        (root/'hysteria2/cert.pem').write_text('fixture certificate, not used for network')
        return config,root
    def execute(self,base,stage,program=None):
        body=(program or SCRIPT.read_text()).split(" <<'PY'\n",1)[1].split('\nPY\n',1)[0]
        args=['generator',str(base),str(stage),'192.0.2.1','10.77.0.1','51820','51822','8388','443','10444','www.example.com','443','11111111-1111-1111-1111-111111111111','private-fixture','public-fixture','0123456789abcdef','1098','/xhttp-fixture']
        with mock.patch.object(sys,'argv',args):exec(compile(body,str(SCRIPT),'exec'),{'__name__':'__main__'})
    def test_same_pq_identity_independent_of_order(self):
        for kind in ('normal','reordered'):
            with self.subTest(kind=kind),tempfile.TemporaryDirectory() as tmp:
                base=Path(tmp)/'base';stage=Path(tmp)/'stage';stage.mkdir()
                config,_=self.prepare(base,kind);before=(config/'server.json').read_bytes()
                self.execute(base,stage)
                server=json.loads((stage/'server.json').read_text())
                target=[x for x in server['inbounds'] if x['tag']=='max-xhttp-in'];self.assertEqual(len(target),1)
                self.assertEqual(target[0]['settings']['decryption'],SERVER)
                self.assertEqual(next(x for x in server['inbounds'] if x['tag']=='reality-in')['settings']['decryption'],'none')
                for raw,asset in [('reality-xhttp','xray.json'),('max-tls-wg','outer-xray.json'),('max-tls-awg','outer-xray.json')]:
                    client=json.loads((stage/'generated'/raw/asset).read_text())
                    self.assertEqual(client['outbounds'][0]['settings']['vnext'][0]['users'][0]['encryption'],CLIENT)
                self.assertEqual((config/'server.json').read_bytes(),before,'staging mutated authoritative identity')
    def test_malformed_pair_refuses_downgrade(self):
        for kind in ('missing-pq','duplicate-pq','plain-pq','missing-client','plain-client'):
            with self.subTest(kind=kind),tempfile.TemporaryDirectory() as tmp:
                base=Path(tmp)/'base';stage=Path(tmp)/'stage';stage.mkdir()
                config,_=self.prepare(base,kind);before=(config/'server.json').read_bytes()
                with self.assertRaises(RuntimeError):self.execute(base,stage)
                self.assertFalse((stage/'server.json').exists());self.assertEqual((config/'server.json').read_bytes(),before)
    def test_old_first_nonempty_selection_is_a_negative_control(self):
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp)/'base';stage=Path(tmp)/'stage';stage.mkdir();self.prepare(base)
            source=SCRIPT.read_text();start=source.index('# The ordinary REALITY inbound');end=source.index("server['inbounds']=",start)
            old="client_enc=secrets['vless_encryption']\nserver_dec=next(x['settings']['decryption'] for x in server['inbounds'] if x['settings'].get('decryption'))\n"
            self.execute(base,stage,source[:start]+old+source[end:])
            out=json.loads((stage/'server.json').read_text());value=next(x for x in out['inbounds'] if x['tag']=='max-xhttp-in')['settings']['decryption']
            self.assertEqual(value,'none');self.assertNotEqual(value,SERVER)

if __name__=='__main__':unittest.main()
