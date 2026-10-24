#!/usr/bin/env python3
"""Run WG/AWG pairing through the real administrator and offline Go compiler."""
from pathlib import Path
from unittest import mock
import copy
import importlib.util
import json
import os
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('packet_pairer', ROOT/'server/scripts/provision-multihop-relays.py')
PAIR = importlib.util.module_from_spec(spec)
spec.loader.exec_module(PAIR)


class PacketPairing(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='router-packet-pairing-')
        cls.agent = Path(cls.temp.name)/'agent'
        fixture = Path(cls.temp.name)/'packet-fixtures.json'
        subprocess.run(['go', 'build', '-buildvcs=false', '-o', str(cls.agent), './cmd/router-agent'], cwd=ROOT, check=True, timeout=90)
        subprocess.run(['go', 'test', '-count=1', '-run', '^TestExportExternalPacketPairingFixtures$', './internal/multihoprelay'],
                       cwd=ROOT, env=dict(os.environ, ROUTERVPN_EXTERNAL_PACKET_PAIR_FIXTURES=str(fixture)), check=True, timeout=90)
        cls.fixtures = json.loads(fixture.read_text())
        cls.real_run = staticmethod(subprocess.run)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def compile(self, command, **kwargs):
        self.assertEqual(command, ['/usr/local/bin/router-vpn-agent', 'compile-external-packet-pair'])
        self.assertIs(kwargs['stderr'], subprocess.DEVNULL)
        self.assertIs(kwargs['stdout'], subprocess.PIPE)
        self.assertEqual(kwargs['timeout'], 20)
        self.assertTrue(kwargs['check'])
        self.assertNotIn('shell', kwargs)
        self.assertIn('server_peer_profile', json.loads(kwargs['input']))
        return self.real_run([str(self.agent), *command[1:]], **kwargs)

    def pair(self, bundle, server):
        with mock.patch.object(PAIR.subprocess, 'run', side_effect=self.compile):
            return PAIR.pair(bundle, 'external-exit', server_peer_profile=server)

    def test_both_protocols_and_layers_use_the_exact_separate_server_credential(self):
        for name, fixture in self.fixtures.items():
            with self.subTest(name=name):
                bundle, server = copy.deepcopy(fixture['bundle']), copy.deepcopy(fixture['server'])
                original = copy.deepcopy((bundle, server))
                protocol, layer = name.split('/', 1)
                source = bundle['routerProfiles'][0]['external']
                result, = self.pair(bundle, server)
                self.assertEqual((bundle, server), original)
                self.assertEqual(result['mode'], protocol)
                self.assertEqual(result['node_id'], '')
                self.assertEqual(result['dns_server'], '')
                self.assertEqual(result['transport']['private_key'], server[protocol]['private_key'])
                self.assertEqual(result['transport']['peers'][0]['pre_shared_key'], server[protocol]['preshared_key'])
                self.assertEqual(result['transport']['address'], source['server_peer']['addresses'])
                self.assertEqual(result['transport']['mtu'], source['server_peer']['mtu'])
                self.assertEqual(result['transport']['peers'][0]['persistent_keepalive_interval'], source['server_peer']['persistent_keepalive_interval'])
                self.assertEqual(result['external']['packet']['owner'], 'server')
                public = json.dumps(result['external']['packet'])
                for secret in (source[protocol]['private_key'], source[protocol]['preshared_key'], server[protocol]['private_key'], server[protocol]['preshared_key']):
                    self.assertNotIn(secret, public)
                self.assertNotIn(source[protocol]['private_key'], json.dumps(result))
                self.assertNotIn(source[protocol]['preshared_key'], json.dumps(result))
                if layer:
                    self.assertEqual(result['start_layer'], source['start_layer'])
                else:
                    self.assertNotIn('start_layer', result)
                if protocol == 'amneziawg':
                    self.assertEqual(result['transport']['amnezia'], source[protocol]['parameters'])

    def test_public_descriptor_command_never_exports_private_server_material(self):
        for name, fixture in self.fixtures.items():
            protocol = name.split('/', 1)[0]
            result = self.real_run([str(self.agent), 'describe-external-packet-peer'],
                                   input=json.dumps(fixture['server']).encode(), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   check=True, timeout=20)
            public = json.loads(result.stdout)
            self.assertEqual(public, fixture['bundle']['routerProfiles'][0]['external']['server_peer'])
            self.assertNotIn(fixture['server'][protocol]['private_key'], result.stdout.decode())
            self.assertNotIn(fixture['server'][protocol]['preshared_key'], result.stdout.decode())
            self.assertEqual(result.stderr, b'')

    def test_pairing_never_uses_local_keys_or_silently_drops_an_incompatible_server_file(self):
        for protocol in ('wireguard', 'amneziawg'):
            fixture = self.fixtures[protocol+'/']
            for fault in ('missing-file', 'local-key', 'secret-in-descriptor', 'changed-remote', 'changed-address', 'changed-mtu', 'changed-keepalive', 'wrong-protocol', 'extra-private-field'):
                with self.subTest(protocol=protocol, fault=fault):
                    bundle, server = copy.deepcopy(fixture['bundle']), copy.deepcopy(fixture['server'])
                    ext = bundle['routerProfiles'][0]['external']
                    if fault == 'missing-file': server = None
                    if fault == 'local-key': server[protocol]['private_key'] = ext[protocol]['private_key']
                    if fault == 'secret-in-descriptor': ext['server_peer']['private_key'] = server[protocol]['private_key']
                    if fault == 'changed-remote': server[protocol]['endpoint'] = '203.0.113.21:51820'
                    if fault == 'changed-address': server[protocol]['addresses'][0] = '10.93.0.99/32'
                    if fault == 'changed-mtu': server[protocol]['mtu'] += 16
                    if fault == 'changed-keepalive': server[protocol]['persistent_keepalive_interval'] += 1
                    if fault == 'wrong-protocol': server['protocol'] = 'shadowsocks'
                    if fault == 'extra-private-field': server['helper'] = 'private-sentinel'
                    before = copy.deepcopy((bundle, server))
                    with self.assertRaises(ValueError) as raised:
                        self.pair(bundle, server)
                    self.assertNotIn('private-sentinel', str(raised.exception))
                    self.assertEqual((bundle, server), before)

    def test_private_server_profile_duplicate_fields_rejected_before_compilation(self):
        with self.assertRaises(ValueError):
            PAIR.decode(b'{"protocol":"wireguard","protocol":"amneziawg"}')


if __name__ == '__main__':
    unittest.main()
