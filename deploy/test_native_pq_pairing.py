#!/usr/bin/env python3
"""Execute server pairing with the actual offline Go PQ compiler.

Keys here are structural fixtures; cryptographic exchange is independently
required by test_server_pq_real.py. No VPN or external node is contacted.
"""
from pathlib import Path
from unittest import mock
import base64
import copy
import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('pq_pairing', ROOT/'server/scripts/provision-multihop-relays.py')
PAIR = importlib.util.module_from_spec(spec)
spec.loader.exec_module(PAIR)


def b64(value):
    return base64.b64encode(value.encode() if isinstance(value, str) else value).decode()


def bundle(mode, layer='off', large=False):
    key = lambda n: b64(bytes([n])*32)
    node = hashlib.sha256(('router-vpn-node-proof-v1\n'+key(2)).encode()).hexdigest()
    tool, name = ('wg', 'wg.conf') if mode == 'wg-pq' else ('awg', 'awg.conf')
    raw = ('[Interface]\nAddress=10.88.0.2/32,fd88:88::2/128\nPrivateKey='+key(3)+'\nDNS=10.77.0.1\nMTU=1400\n'
           '[Peer]\nPublicKey='+key(2)+'\nPresharedKey='+key(4)+'\nEndpoint=198.51.100.2:51820\n'
           'AllowedIPs=0.0.0.0/0,::/0\nPersistentKeepalive=25\n')
    if mode == 'awg2-pq':
        params = 'Jc=3\nJmin=40\nJmax=900\nS1=56\nS2=48\nS3=24\nS4=32\nH1=10000000-19999999\nH2=20000000-29999999\nH3=30000000-39999999\nH4=40000000-49999999\n'
        raw = raw.replace('[Peer]', params+'[Peer]')
    assets = {name: b64(raw), 'rosenpass-client-secret': b64(bytes([7])*64),
              'rosenpass-client-public': b64(bytes([8])*(512*1024 if large else 128)),
              'rosenpass-server-public': b64(bytes([9])*(512*1024 if large else 128)),
              'rosenpass.env': b64('ROSENPASS_TOOL='+tool+'\nROSENPASS_INTERFACE='+tool+'\nROSENPASS_WG_PEER='+key(2)+'\nROSENPASS_KEY_OUT=rosenpass.psk\nROSENPASS_PORT=51822\n'),
              'rosenpass.toml': b64('public_key = "rosenpass-client-public"\nsecret_key = "rosenpass-client-secret"\nlisten = []\nverbosity = "Quiet"\n[[peers]]\npublic_key = "rosenpass-server-public"\nendpoint = "fixture.example.test:51822"\nkey_out = "rosenpass.psk"\n')}
    profile = {'id': 'exit', 'node_kind': 'router-vpn', 'node_proof_id': node, 'endpoint': '198.51.100.2',
               'router_api': 'http://10.88.0.1:8787', 'adguard_ipv4': '192.168.50.133', 'start_layer': layer}
    source = {'selectedRouterID': 'exit', 'routerProfiles': [profile], 'profiles': {mode: assets}}
    if layer != 'off':
        outer = {'type': 'shadowsocks', 'tag': 'proxy', 'server': '198.51.100.2', 'server_port': 8388,
                 'method': '2022-blake3-aes-256-gcm', 'password': key(12)}
        source['profiles']['shadowsocks'] = {'sing-box.json': b64(json.dumps({'inbounds': [{'type': 'tun', 'auto_route': True, 'strict_route': True}], 'outbounds': [outer], 'route': {'final': 'proxy'}}))}
    return source


class PQPairing(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='router-pq-pairing-')
        cls.agent = Path(cls.temp.name)/'agent'
        subprocess.run(['go', 'build', '-buildvcs=false', '-o', str(cls.agent), './cmd/router-agent'], cwd=ROOT, check=True, timeout=90)
        cls.real_run = staticmethod(subprocess.run)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def execute(self, command, **kwargs):
        self.assertEqual(command[0], '/usr/local/bin/router-vpn-agent')
        self.assertIn(command[1], ('compile-pq-relay-profile', 'compile-relay-start-layer'))
        self.assertIs(kwargs['stderr'], subprocess.DEVNULL)
        self.assertTrue(kwargs['check'])
        self.assertEqual(kwargs['timeout'], 20)
        self.assertNotIn('shell', kwargs)
        return self.real_run([str(self.agent), *command[1:]], **kwargs)

    def pair(self, source):
        with mock.patch.object(PAIR.subprocess, 'run', side_effect=self.execute):
            return PAIR.pair(source, 'paired-exit')

    def test_both_protocols_and_both_layers_retain_exact_assets(self):
        for mode in ('wg-pq', 'awg2-pq'):
            for layer in ('off', 'aes-256-gcm', 'aes-256-gcm+xor-whitening'):
                with self.subTest(mode=mode, layer=layer):
                    source = bundle(mode, layer)
                    before = copy.deepcopy(source)
                    result = self.pair(source)
                    found = [x for x in result if x['mode'] == mode]
                    self.assertEqual(len(found), 1)
                    item = found[0]
                    self.assertEqual(item['node_id'], source['routerProfiles'][0]['node_proof_id'])
                    self.assertEqual(item['dns_server'], '192.168.50.133')
                    self.assertEqual(item['id'], 'paired-exit')
                    value = item['transport']
                    self.assertEqual(value['type'], 'routervpn-pq')
                    self.assertEqual(value['mode'], mode)
                    self.assertEqual(value['tag'], 'exit')
                    self.assertNotIn('system', value)
                    self.assertNotIn('listen_port', value)
                    self.assertNotIn('detour', value)
                    self.assertEqual(value['pq']['endpoint'], '198.51.100.2:51822')
                    for field, asset in (('secret', 'rosenpass-client-secret'), ('public', 'rosenpass-client-public'), ('peer', 'rosenpass-server-public')):
                        self.assertEqual(value['pq'][field], source['profiles'][mode][asset])
                    self.assertEqual(value['private_key'], b64(bytes([3])*32))
                    self.assertEqual(value['peers'][0]['public_key'], b64(bytes([2])*32))
                    self.assertEqual(value['mtu'], 1400)
                    if mode == 'awg2-pq':
                        self.assertEqual(len(value['amnezia']), 11)
                    if layer == 'off':
                        self.assertNotIn('start_layer', item)
                    else:
                        self.assertEqual(item['start_layer']['mode'], layer)
                        self.assertEqual(item['start_layer']['api'], 'http://10.88.0.1:8787')
                        self.assertEqual(item['start_layer']['transport']['password'], b64(bytes([12])*32))
                    self.assertEqual(source, before)

    def test_present_but_invalid_pq_cannot_fall_back_to_another_mode(self):
        for mode in ('wg-pq', 'awg2-pq'):
            for fault in ('missing-key', 'empty-mode', 'bad-type', 'same-peer', 'helper', 'command', 'server', 'identity', 'selection', 'duplicate-profile'):
                with self.subTest(mode=mode, fault=fault):
                    source = bundle(mode, 'aes-256-gcm')
                    assets = source['profiles'][mode]
                    if fault == 'missing-key': del assets['rosenpass-client-secret']
                    if fault == 'empty-mode': source['profiles'][mode] = {}
                    if fault == 'bad-type': source['profiles'][mode] = None
                    if fault == 'same-peer': assets['rosenpass-server-public'] = assets['rosenpass-client-public']
                    if fault == 'helper': assets['run.sh'] = b64('do-not-run-private-sentinel')
                    if fault == 'command': assets['rosenpass.env'] = b64(base64.b64decode(assets['rosenpass.env'])+b'COMMAND=private-sentinel\n')
                    if fault == 'server': source['routerProfiles'][0]['endpoint'] = '192.0.2.99'
                    if fault == 'identity': source['routerProfiles'][0]['node_proof_id'] = 'f'*64 if mode == 'wg-pq' else 'invalid'
                    if fault == 'selection': source['selectedRouterID'] = 'missing'
                    if fault == 'duplicate-profile': source['routerProfiles'].append(copy.deepcopy(source['routerProfiles'][0]))
                    before = copy.deepcopy(source)
                    with self.assertRaises((ValueError, TypeError)) as raised:
                        self.pair(source)
                    self.assertNotIn('private-sentinel', str(raised.exception))
                    self.assertEqual(source, before)

    def test_compiler_failure_and_misowned_output_rejected(self):
        source = bundle('wg-pq')
        reference = self.pair(source)[0]['transport']
        for fault in ('mode', 'node', 'tag', 'detour', 'secret', 'handshake', 'peer', 'empty', 'too-large'):
            value = copy.deepcopy(reference)
            if fault == 'mode': value['mode'] = 'wg'
            if fault == 'node': value['node_id'] = 'a'*64
            if fault == 'tag': value['tag'] = 'direct'
            if fault == 'detour': value['detour'] = 'direct'
            if fault == 'secret': value['pq']['secret'] = b64(b'x'*64)
            if fault == 'handshake': value['pq']['endpoint'] = '192.0.2.99:51822'
            if fault == 'peer': value['peers'][0]['address'] = '192.0.2.99'
            raw = b'' if fault == 'empty' else b' '*(12*1024*1024+1) if fault == 'too-large' else json.dumps(value).encode()
            with self.subTest(fault=fault), mock.patch.object(PAIR.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, raw)):
                with self.assertRaises(ValueError): PAIR.pair(source, 'paired-exit')
        for error in (OSError('private-sentinel'), subprocess.TimeoutExpired('offline compiler', 20), subprocess.CalledProcessError(2, 'offline compiler')):
            with mock.patch.object(PAIR.subprocess, 'run', side_effect=error):
                with self.assertRaisesRegex(ValueError, 'offline validation') as raised: PAIR.pair(source, 'paired-exit')
                self.assertNotIn('private-sentinel', str(raised.exception))

    def test_large_key_material_and_atomic_publication_boundary(self):
        source = bundle('awg2-pq', large=True)
        paired = self.pair(source)
        self.assertGreater(len(PAIR.registry_bytes({'exits': paired})), 1<<20)
        with tempfile.TemporaryDirectory() as tmp:
            # macOS temporary paths may pass through /var -> /private/var.
            # Canonicalize only this freshly created test directory; production
            # private-file readers must continue rejecting symlink ancestors.
            root = Path(tmp).resolve()
            read, write, _ = PAIR.helpers()
            alias = root/'untrusted-alias'
            owned = root/'owned'; owned.mkdir()
            alias.symlink_to(owned, target_is_directory=True)
            with self.assertRaises(RuntimeError):
                write(alias/'must-not-exist.json', b'{}')
            self.assertFalse((owned/'must-not-exist.json').exists())
            files = {name: root/(name+'.json') for name in ('bundle', 'agent', 'registry')}
            write(files['bundle'], json.dumps(source).encode())
            write(files['agent'], json.dumps({'node_id': 'a'*64, 'tunnel_cidrs': ['10.77.0.0/24']}).encode())
            foreign = dict(id='unrelated-exit', mode='shadowsocks', node_id='b'*64)
            existing = {'listen_ip': '10.77.0.1', 'first_port': 26240, 'last_port': 26271, 'ttl_seconds': 90, 'exits': [foreign]}
            write(files['registry'], PAIR.registry_bytes(existing))
            initial = files['registry'].read_bytes()
            argv = ['pair', '--bundle', str(files['bundle']), '--exit-id', 'paired-exit', '--agent-config', str(files['agent']), '--registry', str(files['registry']), '--listen-ip', '10.77.0.1']
            for reject in (True, False):
                checks = []
                def command(args, **kwargs):
                    if args[1] != 'check-multihop-registry': return self.execute(args, **kwargs)
                    checks.append(args)
                    self.assertEqual(args[0], '/usr/local/bin/router-vpn-agent')
                    self.assertEqual(kwargs['timeout'], 60)
                    staged = PAIR.decode(read(Path(args[2]), PAIR.MAX_REGISTRY_BYTES))
                    self.assertEqual(staged['exits'][0], foreign)
                    self.assertEqual(staged['exits'][1], paired[0])
                    self.assertEqual(files['registry'].read_bytes(), initial)
                    if reject: raise subprocess.CalledProcessError(2, args)
                    # This double verifies transaction order only. Actual native
                    # parser checks happen in the image's six-PQ-fixture gate.
                    return subprocess.CompletedProcess(args, 0)
                with mock.patch.object(sys, 'argv', argv), mock.patch.object(PAIR.subprocess, 'run', side_effect=command):
                    if reject:
                        with self.assertRaises(subprocess.CalledProcessError): PAIR.main()
                        self.assertEqual(files['registry'].read_bytes(), initial)
                    else: PAIR.main()
                self.assertEqual(len(checks), 1)
                self.assertFalse(list(root.glob('.relay-pair-*')))
            updated = PAIR.decode(read(files['registry'], PAIR.MAX_REGISTRY_BYTES))
            self.assertEqual(updated['exits'], [foreign, *paired])
            self.assertEqual(files['registry'].stat().st_mode & 0o777, 0o600)


if __name__ == '__main__': unittest.main()
