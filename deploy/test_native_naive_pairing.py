#!/usr/bin/env python3
"""Exercise the real administrator pairer and Go compiler with disposable assets.
No VPN or external node is started. Native encrypted traffic is a separate gate.
"""
from pathlib import Path
from unittest import mock
import base64
import copy
import importlib.util
import json
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('naive_pairing',ROOT/'server/scripts/provision-multihop-relays.py')
PAIR=importlib.util.module_from_spec(spec);spec.loader.exec_module(PAIR)

def encoded(value):
    if isinstance(value,dict):value=json.dumps(value)
    return base64.b64encode(value.encode()).decode()

class NaivePairing(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.work=tempfile.TemporaryDirectory(prefix='native-naive-pairing-');cls.root=Path(cls.work.name)
        cls.agent=cls.root/'agent'
        subprocess.run(['go','build','-buildvcs=false','-o',str(cls.agent),'./cmd/router-agent'],cwd=ROOT,check=True,timeout=90)
        # This certificate only proves asset ownership/inline preservation. It
        # is not installed in a system trust store or used with any live node.
        subprocess.run(['openssl','req','-x509','-newkey','ed25519','-nodes','-keyout',str(cls.root/'fixture.key'),
                        '-out',str(cls.root/'fixture.pem'),'-days','2','-subj','/CN=naive.fixture.test'],
                       check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=10)
        cls.certificate=(cls.root/'fixture.pem').read_text()
        cls.real_run=staticmethod(subprocess.run)
    @classmethod
    def tearDownClass(cls):cls.work.cleanup()

    def source(self,mode,layer='off',certificate=False):
        out={'type':'naive','tag':'proxy','server':'192.0.2.4','server_port':13443,
             'username':'private-test-user','password':'private-test-password','quic':mode=='naive-h3',
             'udp_over_tcp':{'enabled':True,'version':2},'tls':{'enabled':True,'server_name':'naive.fixture.test'}}
        if certificate:out['tls']['certificate_path']='cert.pem'
        graph={'inbounds':[{'type':'tun','auto_route':True,'strict_route':True}],
               'outbounds':[out],'route':{'final':'proxy'}}
        assets={'sing-box.json':encoded(graph)}
        if certificate:assets['cert.pem']=encoded(self.certificate)
        p={'id':'exit','node_kind':'router-vpn','node_proof_id':'b'*64,'endpoint':'192.0.2.4',
           'adguard_ipv4':'192.168.50.133','router_api':'http://10.88.0.1:8787','start_layer':layer}
        source={'selectedRouterID':'exit','routerProfiles':[p],'profiles':{mode:assets}}
        if layer!='off':
            aes={'type':'shadowsocks','tag':'proxy','server':'192.0.2.4','server_port':8388,
                 'method':'2022-blake3-aes-256-gcm','password':encoded('a'*32)}
            source['profiles']['shadowsocks']={'sing-box.json':encoded(dict(graph,outbounds=[aes]))}
        return source

    def execute(self,command,**kwargs):
        self.assertEqual(command[0],'/usr/local/bin/router-vpn-agent')
        self.assertIn(command[1],('compile-native-relay-profile','compile-relay-start-layer'))
        self.assertIs(kwargs['stderr'],subprocess.DEVNULL);self.assertTrue(kwargs['check'])
        self.assertEqual(kwargs['timeout'],20);self.assertNotIn('shell',kwargs)
        return self.real_run([str(self.agent),*command[1:]],**kwargs)

    def pair(self,source):
        with mock.patch.object(PAIR.subprocess,'run',side_effect=self.execute):
            return PAIR.pair(source,'owned-exit')

    def test_h2_h3_trust_credentials_dns_and_both_layers_are_retained(self):
        for mode in ('naive-h2','naive-h3'):
            for layer in ('off','aes-256-gcm','aes-256-gcm+xor-whitening'):
                for cert in (False,True):
                    with self.subTest(mode=mode,layer=layer,certificate=cert):
                        source=self.source(mode,layer,cert);before=copy.deepcopy(source)
                        output=[x for x in self.pair(source) if x['mode']==mode]
                        self.assertEqual(len(output),1);item=output[0]
                        self.assertEqual(item['id'],'owned-exit');self.assertEqual(item['node_id'],'b'*64)
                        self.assertEqual(item['dns_server'],'192.168.50.133')
                        expected=json.loads(base64.b64decode(source['profiles'][mode]['sing-box.json']))['outbounds'][0]
                        expected['tag']='exit'
                        if cert:
                            del expected['tls']['certificate_path'];expected['tls']['certificate']=[self.certificate]
                        self.assertEqual(item['transport'],expected)
                        if layer=='off':self.assertNotIn('start_layer',item)
                        else:self.assertEqual(item['start_layer']['mode'],layer)
                        self.assertEqual(source,before)

    def test_invalid_present_profile_cannot_be_ignored_or_downgraded(self):
        for mode in ('naive-h2','naive-h3'):
            for fault in ('quic','udp','password','insecure','certificate','helper','route','detour','peer','selection','duplicate'):
                with self.subTest(mode=mode,fault=fault):
                    source=self.source(mode,'aes-256-gcm',True);assets=source['profiles'][mode]
                    g=json.loads(base64.b64decode(assets['sing-box.json']));out=g['outbounds'][0]
                    if fault=='quic':out['quic']=not out['quic']
                    if fault=='udp':out['udp_over_tcp']=False
                    if fault=='password':del out['password']
                    if fault=='insecure':out['tls']['insecure']=True
                    if fault=='certificate':del assets['cert.pem']
                    if fault=='helper':assets['run.sh']=encoded('private-not-executed-sentinel')
                    if fault=='route':g['route']['rules']=[{'outbound':'direct','network':'tcp'}]
                    if fault=='detour':out['detour']='direct'
                    if fault=='peer':source['routerProfiles'][0]['endpoint']='192.0.2.99'
                    if fault=='selection':source['selectedRouterID']='absent'
                    if fault=='duplicate':source['routerProfiles'].append(copy.deepcopy(source['routerProfiles'][0]))
                    assets['sing-box.json']=encoded(g);before=copy.deepcopy(source)
                    with self.assertRaises(ValueError) as raised:self.pair(source)
                    self.assertNotIn('private-test-password',str(raised.exception))
                    self.assertNotIn('private-not-executed-sentinel',str(raised.exception))
                    self.assertEqual(before,source)

    def test_failed_or_changed_compiler_output_never_becomes_paired(self):
        source=self.source('naive-h3',certificate=True)
        valid=self.pair(source)[0]['transport'];valid['tag']='routervpn-hop-entry'
        for field in ('username','password','server','quic','tls','udp_over_tcp','detour','tag'):
            changed=copy.deepcopy(valid);changed[field]='unowned-substitution'
            with self.subTest(field=field),mock.patch.object(PAIR.subprocess,'run',return_value=subprocess.CompletedProcess([],0,json.dumps(changed).encode())):
                with self.assertRaises(ValueError):PAIR.pair(source,'owned-exit')
        for failure in (OSError('private-sentinel'),subprocess.TimeoutExpired('compiler',20),subprocess.CalledProcessError(2,'compiler')):
            with mock.patch.object(PAIR.subprocess,'run',side_effect=failure):
                with self.assertRaisesRegex(ValueError,'offline validation') as raised:PAIR.pair(source,'owned-exit')
                self.assertNotIn('private-sentinel',str(raised.exception))

if __name__=='__main__':unittest.main()
