#!/usr/bin/env python3
"""Exercise the real pairing utility and offline Go compilers on owned assets."""
from pathlib import Path
import base64
import copy
import importlib.util
import json
import subprocess
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('paired_composite',ROOT/'server/scripts/provision-multihop-relays.py')
PAIR = importlib.util.module_from_spec(spec)
spec.loader.exec_module(PAIR)

class CompositePairing(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.agent = Path(cls.temp.name)/'agent'
        cls.generator = Path(cls.temp.name)/'composite-assets'
        subprocess.run(['go','build','-buildvcs=false','-o',str(cls.agent),'./cmd/router-agent'],cwd=ROOT,check=True,timeout=90)
        subprocess.run(['go','build','-buildvcs=false','-o',str(cls.generator),'./deploy/testfixtures/composite'],cwd=ROOT,check=True,timeout=90)
        cls.bundle = json.loads(subprocess.check_output([str(cls.generator),'--exits'],timeout=20))

    @classmethod
    def tearDownClass(cls): cls.temp.cleanup()

    def pair(self, value):
        execute = subprocess.run
        self.calls = []
        def compiler(command,**kwargs):
            self.assertEqual(command[0],'/usr/local/bin/router-vpn-agent')
            self.assertIn(command[1],('compile-composite-relay-profile','compile-relay-start-layer'))
            self.assertEqual(kwargs['stderr'],subprocess.DEVNULL)
            self.assertEqual(kwargs['stdout'],subprocess.PIPE)
            self.assertTrue(kwargs['check'])
            self.assertLessEqual(kwargs['timeout'],20)
            self.calls.append(command[1])
            return execute([str(self.agent),*command[1:]],**kwargs)
        with mock.patch.object(PAIR.subprocess,'run',side_effect=compiler):
            return PAIR.pair(value,'paired-exit')

    def test_complete_raw_or_layered_pairings_preserve_both_nodes_and_credentials(self):
        for selected, expected in [('off',''),('aes','aes-256-gcm'),('aes+xor','aes-256-gcm+xor-whitening')]:
            with self.subTest(layer=selected):
                bundle = copy.deepcopy(self.bundle)
                bundle['routerProfiles'][0]['start_layer'] = selected
                snapshot = copy.deepcopy(bundle)
                results = self.pair(bundle)
                self.assertEqual(bundle,snapshot)
                self.assertEqual(self.calls.count('compile-composite-relay-profile'),3)
                self.assertEqual(self.calls.count('compile-relay-start-layer'),int(bool(expected)))
                self.assertEqual({item['mode'] for item in results},{'shadowsocks','ss-v2ray','split','max'})
                for item in results:
                    self.assertEqual(item['node_id'],bundle['nodeProofId'])
                    if expected:
                        self.assertEqual(item['start_layer']['mode'],expected)
                        self.assertEqual(item['start_layer']['api'],bundle['routerProfiles'][0]['router_api'])
                    else: self.assertNotIn('start_layer',item)
                    if item['mode']=='shadowsocks': continue
                    plan = item['transport']
                    self.assertEqual(set(plan),{'type','mode','node_id','start_layer','tcp','udp'})
                    self.assertEqual(plan['type'],'routervpn-composite-plan')
                    self.assertEqual(plan['mode'],item['mode'])
                    self.assertEqual(plan['start_layer'],'')
                    udp = plan['udp']
                    self.assertEqual(udp['type'],'hysteria2')
                    self.assertEqual(udp['server'],bundle['routerProfiles'][0]['endpoint'])
                    self.assertEqual(udp['password'],'exit-hysteria-secret')
                    self.assertEqual(udp['obfs']['password'],'exit-mask')
                    self.assertNotIn('certificate_path',udp['tls'])
                    self.assertIn('BEGIN CERTIFICATE',udp['tls']['certificate'])
                    self.assertNotIn('detour',udp)
                    self.assertNotIn('detour',plan['tcp'])
                    if item['mode']=='max': self.assertIn('mlkem768x25519plus',plan['tcp']['config_json'])
                    plan['udp']['password'] = 'changed returned object'
                self.assertEqual(bundle,snapshot)

    def test_invalid_complete_source_cannot_pair_only_its_remaining_lane(self):
        for mode in ('ss-v2ray','split','max'):
            for fault in ('missing-UDP','foreign-UDP','weak-TLS','extra-helper','wrong-endpoint','wrong-API','wrong-layer'):
                with self.subTest(mode=mode,fault=fault):
                    bundle = copy.deepcopy(self.bundle)
                    bundle['profiles'] = {mode:bundle['profiles'][mode]}
                    assets = bundle['profiles'][mode]
                    graph = json.loads(base64.b64decode(assets['sing-box.json']))
                    if fault=='missing-UDP': graph['outbounds'] = graph['outbounds'][:1]
                    if fault=='foreign-UDP': graph['outbounds'][1]['server'] = '192.0.2.99'
                    if fault=='weak-TLS': graph['outbounds'][1]['tls']['insecure'] = True
                    if fault=='extra-helper': assets['run.sh'] = base64.b64encode(b'private-must-not-echo').decode()
                    if fault=='wrong-endpoint': bundle['routerProfiles'][0]['endpoint'] = '192.0.2.99'
                    if fault=='wrong-API': bundle['routerProfiles'][0]['router_api'] = 'http://127.0.0.1:8787'
                    if fault=='wrong-layer': bundle['routerProfiles'][0]['start_layer'] = 'aes'
                    assets['sing-box.json'] = base64.b64encode(json.dumps(graph).encode()).decode()
                    snapshot = copy.deepcopy(bundle)
                    with self.assertRaises(ValueError) as failure: self.pair(bundle)
                    self.assertNotIn('private-must-not-echo',str(failure.exception))
                    self.assertEqual(bundle,snapshot)

    def test_bounded_compiler_failures_cannot_forge_runtime_owner(self):
        bundle = copy.deepcopy(self.bundle)
        node = bundle['routerProfiles'][0]
        for output in (b'',b'{}',json.dumps({'type':'selector','mode':'max'}).encode(),b'x'*((4<<20)+2)):
            with mock.patch.object(PAIR.subprocess,'run',return_value=subprocess.CompletedProcess([],0,output,b'')):
                with self.assertRaises(ValueError): PAIR.native_composite(bundle['profiles']['max'],'max',bundle['nodeProofId'],node['endpoint'],node['router_api'])
        for failure in (OSError('private-must-not-echo'),subprocess.CalledProcessError(1,[]),subprocess.TimeoutExpired([],20)):
            with mock.patch.object(PAIR.subprocess,'run',side_effect=failure):
                with self.assertRaises(ValueError) as result: PAIR.native_composite(bundle['profiles']['max'],'max',bundle['nodeProofId'],node['endpoint'],node['router_api'])
                self.assertNotIn('private-must-not-echo',str(result.exception))

if __name__=='__main__': unittest.main()
