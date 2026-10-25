#!/usr/bin/env python3
"""Use the real administrator pairing path and bounded Go OpenVPN commands."""
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
spec = importlib.util.spec_from_file_location('openvpn_pairer', ROOT/'server/scripts/provision-multihop-relays.py')
PAIR = importlib.util.module_from_spec(spec)
spec.loader.exec_module(PAIR)


class OpenVPNPairing(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='router-openvpn-pairing-')
        cls.agent = Path(cls.temp.name)/'agent'
        fixture = Path(cls.temp.name)/'fixtures'
        subprocess.run(['go', 'build', '-buildvcs=false', '-o', str(cls.agent), './cmd/router-agent'], cwd=ROOT, check=True, timeout=120)
        subprocess.run(['go', 'test', '-count=1', '-run', '^TestExportExternalOpenVPNPairingFixtures$', './internal/multihoprelay'],
                       cwd=ROOT, env=dict(os.environ, ROUTER_VPN_OPENVPN_PAIR_FIXTURES_DIR=str(fixture)), check=True, timeout=90)
        cls.fixtures = {path.stem: json.loads(path.read_text()) for path in fixture.glob('*.json')}
        cls.real_run = staticmethod(subprocess.run)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def compile(self, command, **kwargs):
        self.assertEqual(command, ['/usr/local/bin/router-vpn-agent', 'compile-external-openvpn-pair'])
        self.assertIs(kwargs['stderr'], subprocess.DEVNULL)
        self.assertIs(kwargs['stdout'], subprocess.PIPE)
        self.assertTrue(kwargs['check'])
        self.assertEqual(kwargs['timeout'], 20)
        self.assertNotIn('shell', kwargs)
        return self.real_run([str(self.agent), *command[1:]], **kwargs)

    def pair(self, external, server, layer):
        profile = dict(id='selected', node_kind='external', external=external, start_layer=layer)
        bundle = dict(selectedRouterID='selected', routerProfiles=[profile])
        with mock.patch.object(PAIR.subprocess, 'run', side_effect=self.compile):
            return PAIR.pair(bundle, 'exit', server_peer_profile=server)

    def test_actual_pairer_preserves_each_layer_and_only_server_owned_provider_credentials(self):
        self.assertEqual(set(self.fixtures), {'off', 'aes-256-gcm', 'aes-256-gcm+xor-whitening', 'mapped'})
        for name, fixture in self.fixtures.items():
            with self.subTest(layer=name):
                external, server = copy.deepcopy(fixture['external']), copy.deepcopy(fixture['server_peer_profile'])
                before = copy.deepcopy((external, server))
                paired, = self.pair(external, server, fixture['selected_layer'])
                self.assertEqual((external, server), before)
                self.assertEqual(paired, fixture['paired'])
                owned = paired['external']['openvpn']
                self.assertEqual(owned['owner'], 'server')
                self.assertEqual(owned['profile'], server['openvpn'])
                self.assertEqual(owned['private_key'], server['pairing_private_key'])
                self.assertEqual(paired['transport']['username'], server['openvpn']['username'])
                for secret in (external['openvpn']['password'], external['openvpn_pairing']['private_key']):
                    self.assertNotIn(secret, json.dumps(paired))
                self.assertEqual(len(paired['transport']['servers']), 2)
                self.assertNotIn('server', paired['transport'])
                self.assertFalse(paired['transport']['system'])

    def test_actual_mapped_pairer_preserves_all_hosts_and_rejects_partial_or_unbound_proof(self):
        fixture = self.fixtures['mapped']
        paired, = self.pair(copy.deepcopy(fixture['external']), copy.deepcopy(fixture['server_peer_profile']), '')
        self.assertEqual(paired['external']['openvpn_response_probes'], fixture['external']['openvpn_response_probes'])
        self.assertEqual({remote['server'] for remote in paired['transport']['servers']}, {'203.0.113.20', '203.0.113.21'})
        for fault in ('missing-host', 'foreign-host', 'wrong-proof-host', 'legacy-probe', 'exit-layer', 'changed-original', 'private-descriptor'):
            with self.subTest(fault=fault):
                external, server = copy.deepcopy(fixture['external']), copy.deepcopy(fixture['server_peer_profile'])
                if fault == 'missing-host': del external['openvpn_response_probes']['203.0.113.21']
                if fault == 'foreign-host': external['openvpn_response_probes']['203.0.113.22'] = dict(url='https://203.0.113.22/response')
                if fault == 'wrong-proof-host': external['openvpn_response_probes']['203.0.113.21']['url'] = 'https://203.0.113.20/response'
                if fault == 'legacy-probe': external['response_probe'] = dict(url='https://203.0.113.20/response')
                if fault == 'exit-layer': external['start_layer'] = copy.deepcopy(self.fixtures['aes-256-gcm']['external']['start_layer'])
                if fault == 'changed-original': server['openvpn']['config'] = server['openvpn']['config'].replace('203.0.113.21 443', '203.0.113.21 8443')
                if fault == 'private-descriptor': external['openvpn_pairing']['server']['password'] = 'private-sentinel'
                with self.assertRaises(ValueError) as raised:
                    self.pair(external, server, '')
                self.assertNotIn('private-sentinel', str(raised.exception))

    def test_actual_descriptor_export_contains_no_provider_or_pairing_secrets(self):
        for fixture in self.fixtures.values():
            server = fixture['server_peer_profile']
            completed = self.real_run([str(self.agent), 'describe-external-openvpn-peer'],
                                      input=json.dumps(server).encode(), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                      check=True, timeout=20)
            self.assertEqual(json.loads(completed.stdout), fixture['descriptor'])
            self.assertEqual(completed.stderr, b'')
            for secret in (server['openvpn']['password'], server['pairing_private_key'], 'client_key', 'client_certificate', 'control_wrap_key'):
                self.assertNotIn(secret, completed.stdout.decode())

    def test_actual_compiler_rejects_missing_reused_substituted_and_secret_bearing_counterparts(self):
        for fault in ('missing-file', 'local-profile', 'same-username', 'wrong-auth-key', 'changed-remote', 'changed-mtu', 'missing-pairing', 'hidden-key', 'extra-profile-field', 'extra-server-field', 'wrong-layer'):
            with self.subTest(fault=fault):
                fixture = copy.deepcopy(self.fixtures['aes-256-gcm'])
                external, server, layer = fixture['external'], fixture['server_peer_profile'], fixture['selected_layer']
                if fault == 'missing-file': server = None
                if fault == 'local-profile': server['openvpn'] = copy.deepcopy(external['openvpn'])
                if fault == 'same-username': server['openvpn']['username'] = external['openvpn']['username'].upper()
                if fault == 'wrong-auth-key': server['pairing_private_key'] = external['openvpn_pairing']['private_key']
                if fault == 'changed-remote': server['openvpn']['config'] = server['openvpn']['config'].replace('203.0.113.20', '203.0.113.21')
                if fault == 'changed-mtu': external['openvpn_pairing']['server']['transport']['mtu'] = 9000
                if fault == 'missing-pairing': del external['openvpn_pairing']
                if fault == 'hidden-key': external['openvpn_pairing']['server']['private_key'] = 'private-sentinel'
                if fault == 'extra-profile-field': server['openvpn']['path'] = '/private-sentinel'
                if fault == 'extra-server-field': server['helper'] = 'private-sentinel'
                if fault == 'wrong-layer': layer = 'off'
                before = copy.deepcopy((external, server))
                with self.assertRaises(ValueError) as raised:
                    self.pair(external, server, layer)
                self.assertNotIn('private-sentinel', str(raised.exception))
                self.assertEqual((external, server), before)

    def test_raw_duplicate_unknown_and_trailing_stdin_never_emit_partial_private_output(self):
        fixture = self.fixtures['off']
        body = json.dumps(dict(alias='exit', external=fixture['external'], server_peer_profile=fixture['server_peer_profile'], selected_layer='off'))
        invalid = (body+'{}', body.replace('"alias":', '"alias":"duplicate","alias":', 1),
                   body.replace('"openvpn_pairing": {', '"openvpn_pairing": {"private_key":"duplicate",', 1),
                   body.replace('"server": {', '"server": {"private_key":"private-sentinel",', 1),
                   body[:-1]+',"unexpected":"private-sentinel"}')
        for raw in invalid:
            completed = self.real_run([str(self.agent), 'compile-external-openvpn-pair'], input=raw.encode(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
            self.assertNotEqual(completed.returncode, 0)
            self.assertEqual(completed.stdout, b'')
            self.assertNotIn('private-sentinel', completed.stderr.decode())
        for raw in ('null', json.dumps(fixture['server_peer_profile'])+'{}', '{"protocol":"openvpn","protocol":"openvpn"}'):
            completed = self.real_run([str(self.agent), 'describe-external-openvpn-peer'], input=raw.encode(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
            self.assertNotEqual(completed.returncode, 0)
            self.assertEqual(completed.stdout, b'')


if __name__ == '__main__':
    unittest.main()
