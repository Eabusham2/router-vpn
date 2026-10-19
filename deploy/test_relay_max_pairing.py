#!/usr/bin/env python3
"""Run complete MAX pairing through the real administrator and Go compilers.

Captured fixture keys exercise graph ownership here. The native encrypted
protocol gates use independently generated cryptographic keys and traffic.
"""
from pathlib import Path
from unittest import mock
import base64
import copy
import importlib.util
import json
import os
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('paired_max', ROOT/'server/scripts/provision-multihop-relays.py')
PAIR = importlib.util.module_from_spec(spec)
spec.loader.exec_module(PAIR)


def encoded(value):
    return base64.b64encode(json.dumps(value).encode()).decode()


class MAXPairing(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='router-max-pairing-')
        root = Path(cls.temp.name)
        cls.agent = root/'agent'
        fixture = root/'captured-max.json'
        subprocess.run(['go', 'build', '-buildvcs=false', '-o', str(cls.agent), './cmd/router-agent'], cwd=ROOT, check=True, timeout=90)
        subprocess.run(['go', 'test', '-run', '^TestExportMAXMobileProfiles$', '-count=1', './internal/mobilemultihop'], cwd=ROOT,
                       env=dict(os.environ, ROUTERVPN_MAX_PROFILE_FIXTURES=str(fixture)), check=True, timeout=90)
        cls.fixtures = json.loads(fixture.read_text())
        cls.execute = staticmethod(subprocess.run)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def bundle(self, mode, layer='off'):
        source = self.fixtures[mode]
        policy = source['policy']
        profile = dict(id='exit', node_kind='router-vpn', node_proof_id=policy['node_id'], endpoint=policy['endpoint'],
                       router_api=policy['router_api'], adguard_ipv4='10.88.0.1', start_layer=layer)
        aes = next(item for item in source['graph']['outbounds'] if item['tag']=='routervpn-max-ss')
        outer = dict(type='shadowsocks', tag='proxy', server=policy['endpoint'], server_port=aes['server_port'],
                     method=aes['method'], password=aes['password'])
        graph = dict(inbounds=[dict(type='tun', auto_route=True, strict_route=True)], outbounds=[outer], route=dict(final='proxy'))
        return dict(selectedRouterID='exit', routerProfiles=[profile], profiles={mode:copy.deepcopy(source['files']), 'shadowsocks':{'sing-box.json':encoded(graph)}})

    def pair(self, bundle):
        self.calls = []
        def compiler(command, **kwargs):
            self.assertEqual(command[0], '/usr/local/bin/router-vpn-agent')
            self.assertIn(command[1], ('compile-max-relay-profile', 'compile-relay-start-layer'))
            self.assertIs(kwargs['stdout'], subprocess.PIPE)
            self.assertIs(kwargs['stderr'], subprocess.DEVNULL)
            self.assertTrue(kwargs['check'])
            self.assertEqual(kwargs['timeout'], 20)
            self.assertNotIn('shell', kwargs)
            self.calls.append(command[1])
            return self.execute([str(self.agent), *command[1:]], **kwargs)
        with mock.patch.object(PAIR.subprocess, 'run', side_effect=compiler):
            return PAIR.pair(bundle, 'paired-max')

    def test_all_complete_chains_and_selected_layers_preserve_captured_material(self):
        for mode in self.fixtures:
            for layer, expected in [('off', ''), ('aes', 'aes-256-gcm'), ('aes+xor', 'aes-256-gcm+xor-whitening')]:
                with self.subTest(mode=mode, layer=layer):
                    bundle = self.bundle(mode, layer)
                    before = copy.deepcopy(bundle)
                    results = self.pair(bundle)
                    self.assertEqual({item['mode'] for item in results}, {'shadowsocks', mode})
                    self.assertEqual(self.calls.count('compile-max-relay-profile'), 1)
                    self.assertEqual(self.calls.count('compile-relay-start-layer'), int(bool(expected)))
                    item = next(item for item in results if item['mode']==mode)
                    self.assertEqual(item['id'], 'paired-max')
                    self.assertEqual(item['node_id'], bundle['routerProfiles'][0]['node_proof_id'])
                    plan = item['transport']
                    self.assertEqual(set(plan), {'endpoint', 'outbounds'})
                    base = plan['endpoint']
                    original = self.fixtures[mode]['graph']['endpoints'][0]
                    for field in ('type', 'mode', 'node_id', 'private_key', 'pq', 'peers', 'address', 'mtu', 'amnezia'):
                        self.assertEqual(base.get(field), original.get(field), field)
                    self.assertEqual(base['tag'], 'exit')
                    self.assertEqual(base['detour'], 'routervpn-relay-max-ss')
                    self.assertEqual(len(plan['outbounds']), 2)
                    middle, outer = plan['outbounds']
                    self.assertEqual(middle['tag'], 'routervpn-relay-max-ss')
                    self.assertEqual(middle['detour'], 'routervpn-relay-max-outer')
                    self.assertEqual(outer['tag'], 'routervpn-relay-max-outer')
                    self.assertNotIn('detour', outer)
                    if mode.startswith('max-tls-'):
                        self.assertEqual(outer['type'], 'routervpn-xray')
                        self.assertEqual(outer['config_json'], base64.b64decode(bundle['profiles'][mode]['outer-xray.json']).decode())
                    else:
                        self.assertEqual(outer['type'], 'hysteria2')
                        self.assertEqual(outer['password'], 'exact-quic-credential')
                        self.assertEqual(outer['tls']['certificate'], [base64.b64decode(bundle['profiles'][mode]['cert.pem']).decode()])
                    if expected:
                        self.assertEqual(item['start_layer']['mode'], expected)
                        self.assertEqual(item['start_layer']['api'], bundle['routerProfiles'][0]['router_api'])
                        self.assertEqual(item['start_layer']['transport']['password'], middle['password'])
                    else:
                        self.assertNotIn('start_layer', item)
                    plan['endpoint']['private_key'] = 'changed returned object'
                    self.assertEqual(bundle, before)

    def test_present_incomplete_chain_cannot_pair_only_a_weaker_remaining_profile(self):
        for mode in self.fixtures:
            for fault in ('missing-PQ', 'missing-middle', 'missing-outer', 'helper', 'weaker-chain', 'same-PQ-peer', 'wrong-node', 'wrong-server', 'wrong-private-API', 'missing-selected-AES'):
                with self.subTest(mode=mode, fault=fault):
                    bundle = self.bundle(mode, 'aes')
                    assets = bundle['profiles'][mode]
                    if fault=='missing-PQ': del assets['rosenpass-client-secret']
                    if fault=='missing-middle': del assets['middle-sing-box.json']
                    if fault=='missing-outer': assets.pop('outer-xray.json' if mode.startswith('max-tls-') else 'cert.pem')
                    if fault=='helper': assets['run.sh'] = base64.b64encode(b'private-must-not-echo').decode()
                    if fault=='weaker-chain': assets['chain.env'] = base64.b64encode(base64.b64decode(assets['chain.env']).replace(b'PQ_BASE=1', b'PQ_BASE=0')).decode()
                    if fault=='same-PQ-peer': assets['rosenpass-server-public'] = assets['rosenpass-client-public']
                    if fault=='wrong-node': bundle['routerProfiles'][0]['node_proof_id'] = 'invalid'
                    if fault=='wrong-server': bundle['routerProfiles'][0]['endpoint'] = '192.0.2.99'
                    if fault=='wrong-private-API': bundle['routerProfiles'][0]['router_api'] = 'http://127.0.0.1:8787'
                    if fault=='missing-selected-AES': del bundle['profiles']['shadowsocks']
                    before = copy.deepcopy(bundle)
                    with self.assertRaises(ValueError) as raised:
                        self.pair(bundle)
                    self.assertNotIn('private-must-not-echo', str(raised.exception))
                    self.assertEqual(bundle, before)

    def test_compiler_failures_or_partial_outputs_never_publish_a_chain(self):
        for mode in self.fixtures:
            bundle = self.bundle(mode)
            expected = next(item['transport'] for item in self.pair(bundle) if item['mode']==mode)
            for fault in ('empty', 'oversize', 'node', 'mode', 'secret', 'detour', 'missing-outer', 'direct-outer', 'unexpected-field'):
                value = copy.deepcopy(expected)
                if fault=='node': value['endpoint']['node_id'] = 'f'*64
                if fault=='mode': value['endpoint']['mode'] = 'wg'
                if fault=='secret': value['endpoint']['pq']['secret'] = base64.b64encode(b'x'*64).decode()
                if fault=='detour': value['endpoint']['detour'] = 'direct'
                if fault=='missing-outer': value['outbounds'] = value['outbounds'][:1]
                if fault=='direct-outer': value['outbounds'][1]['type'] = 'direct'
                if fault=='unexpected-field': value['route'] = {'final':'direct'}
                output = b'' if fault=='empty' else b'x'*((4<<20)+2) if fault=='oversize' else json.dumps(value).encode()
                with self.subTest(mode=mode, fault=fault), mock.patch.object(PAIR.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, output, b'')):
                    with self.assertRaises(ValueError):
                        PAIR.pair(bundle, 'paired-max')
            for failure in (OSError('private-must-not-echo'), subprocess.CalledProcessError(1, []), subprocess.TimeoutExpired([], 20)):
                with mock.patch.object(PAIR.subprocess, 'run', side_effect=failure):
                    with self.assertRaises(ValueError) as raised:
                        PAIR.pair(bundle, 'paired-max')
                    self.assertNotIn('private-must-not-echo', str(raised.exception))


if __name__=='__main__':
    unittest.main()
