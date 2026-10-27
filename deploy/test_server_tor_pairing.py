#!/usr/bin/env python3
"""Exercise private Tor pairing through the actual bounded native compiler.

Set ROUTERVPN_SERVER_TOR_PACKAGE and ROUTERVPN_SERVER_TOR_NATIVE_CLI to also
run every successful staged transaction through the actual installed-package
verifier and native graph parser. --installed uses the shipped agent command
inside its built image and needs no compiler there. Neither starts a circuit.
"""
from pathlib import Path
from unittest import mock
import base64
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('private_tor_pairer', ROOT/'server/scripts/provision-multihop-relays.py')
PAIR = importlib.util.module_from_spec(spec)
spec.loader.exec_module(PAIR)
NODE = 'a' * 64
BRIDGE = 'obfs4 198.51.100.9:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=' + base64.b64encode(b'\x01' * 52).decode().rstrip('=') + ' iat-mode=0'
INSTALLED = '--installed' in sys.argv
if INSTALLED:
    sys.argv.remove('--installed')


def source(identity='operator-tor', mode='tor-bridge'):
    value = dict(schema=1, id=identity, entry_node_id=NODE, mode=mode,
                 dns=dict(mode='home'), adguard_ipv4='192.168.50.133')
    if mode == 'tor-bridge':
        value['tor_bridge'] = dict(transport='obfs4', bridges=['Bridge ' + BRIDGE])
    return value


class ServerTorPairing(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='server-tor-pairing-tools-')
        cls.real_run = staticmethod(subprocess.run)
        cls.native_checker = None
        if INSTALLED:
            cls.agent = Path('/usr/local/bin/router-vpn-agent')
            if not cls.agent.is_file():
                raise AssertionError('installed pairing gate requires the built agent image')
            return
        cls.agent = Path(cls.temporary.name)/'router-vpn-agent'
        subprocess.run(['go', 'build', '-buildvcs=false', '-o', str(cls.agent), './cmd/router-agent'], cwd=ROOT, check=True, timeout=120)
        package, core = os.environ.get('ROUTERVPN_SERVER_TOR_PACKAGE'), os.environ.get('ROUTERVPN_SERVER_TOR_NATIVE_CLI')
        if bool(package) != bool(core):
            raise AssertionError('native pairing gate requires both actual package and core')
        if package:
            cls.native_checker = Path(cls.temporary.name)/'registry-check.test'
            subprocess.run(['go', 'test', '-c', '-o', str(cls.native_checker), './cmd/router-agent'], cwd=ROOT, check=True, timeout=120)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def compile(self, value):
        result = self.real_run([str(self.agent), 'compile-server-tor-source'],
                               input=json.dumps(dict(entry_node_id=NODE, source=value)).encode(),
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, timeout=20)
        return json.loads(result.stdout)

    def setUp(self):
        self.temporary_case = tempfile.TemporaryDirectory(prefix='private-tor-pairing-')
        self.root = Path(self.temporary_case.name)
        self.registry, self.agent_config, self.input = (self.root/name for name in ('registry.json', 'agent.json', 'source.json'))
        self.sources = self.root/'tor-sources'
        self.sources.mkdir(mode=0o700)
        self.read, self.write, _ = PAIR.helpers()
        self.write(self.agent_config, json.dumps(dict(node_id=NODE, tunnel_cidrs=['10.77.0.0/24'])).encode())
        self.write(self.input, json.dumps(source()).encode())
        self.previous = self.compile(source('preserved-tor', 'tor'))
        self.previous_path = self.sources/(self.previous['reference']['source_sha256'] + '.json')
        self.write(self.previous_path, self.previous['source_json'].encode())
        self.foreign = dict(id='preserved-proxy', mode='shadowsocks', node_id='b'*64, dns_server='10.88.0.1',
                            transport=dict(type='shadowsocks', tag='exit', server='198.51.100.2', server_port=8388,
                                           method='aes-256-gcm', password='private-preserved-proxy-key'))
        self.original = dict(listen_ip='10.77.0.1', first_port=26240, last_port=26271, ttl_seconds=90,
                             exits=[self.foreign], tor_exits=[self.previous['reference']])
        self.write(self.registry, PAIR.registry_bytes(self.original))
        self.unrelated = self.sources/'operator-unreferenced.json'
        self.write(self.unrelated, b'{"private":"preserve-unrelated-source"}')
        self.before = self.registry.read_bytes()
        self.before_source = self.previous_path.read_bytes()
        self.before_inode = self.previous_path.stat().st_ino
        self.on_check = None
        self.checks = 0
        self.output = io.StringIO()

    def tearDown(self):
        self.temporary_case.cleanup()

    def execute(self, command, **kwargs):
        self.assertEqual(command[0], '/usr/local/bin/router-vpn-agent')
        self.assertIs(kwargs['stderr'], subprocess.DEVNULL)
        self.assertTrue(kwargs['check'])
        self.assertNotIn('shell', kwargs)
        if command[1] == 'compile-server-tor-source':
            self.assertEqual(len(command), 2)
            self.assertEqual(kwargs['timeout'], 20)
            self.assertIs(kwargs['stdout'], subprocess.PIPE)
            return self.real_run([str(self.agent), *command[1:]], **kwargs)
        self.assertEqual(command[1], 'check-multihop-registry')
        self.assertEqual(len(command), 5)
        self.assertEqual(kwargs['timeout'], 60)
        self.assertIs(kwargs['stdout'], subprocess.DEVNULL)
        self.checks += 1
        stage, sources = Path(command[2]), Path(command[4])
        self.assertEqual(stage.stat().st_mode & 0o777, 0o600)
        self.assertEqual(sources.stat().st_mode & 0o777, 0o700)
        registry = json.loads(stage.read_bytes())
        for reference in registry['tor_exits']:
            path = sources/(reference['source_sha256'] + '.json')
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            raw = path.read_bytes()
            self.assertEqual(hashlib.sha256(raw).hexdigest(), reference['source_sha256'])
            compiled = self.compile(json.loads(raw))
            self.assertEqual(compiled['reference'], reference)
            self.assertEqual(compiled['source_json'].encode(), raw)
        if INSTALLED:
            self.real_run([str(self.agent), *command[1:]], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, timeout=30)
        elif self.native_checker is not None:
            environment = dict(os.environ, ROUTERVPN_TEST_TOR_REGISTRY=str(stage),
                               ROUTERVPN_TEST_TOR_AGENT=command[3], ROUTERVPN_TEST_TOR_SOURCES=str(sources))
            self.real_run([str(self.native_checker), '-test.run=^TestRunOperatorStagedTorRegistryCheck$'],
                          env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, timeout=30)
        if self.on_check is not None:
            self.on_check()
        return subprocess.CompletedProcess(command, 0)

    def run_pair(self, extra=(), bundle=None):
        selection = ['--bundle', str(bundle)] if bundle is not None else ['--tor-source', str(self.input)]
        argv = ['pair', *selection, '--exit-id', 'operator-tor', '--registry', str(self.registry),
                '--agent-config', str(self.agent_config), '--listen-ip', '10.77.0.1', *map(str, extra)]
        with mock.patch.object(sys, 'argv', argv), mock.patch.object(PAIR.subprocess, 'run', side_effect=self.execute), contextlib.redirect_stdout(self.output):
            PAIR.main()
        self.assertNotIn(BRIDGE, self.output.getvalue())
        self.assertNotIn('private-preserved-proxy-key', self.output.getvalue())

    def assert_preserved(self):
        self.assertEqual(self.registry.read_bytes(), self.before)
        self.assertEqual(self.previous_path.read_bytes(), self.before_source)
        self.assertEqual(self.previous_path.stat().st_ino, self.before_inode)
        self.assertEqual(self.unrelated.read_bytes(), b'{"private":"preserve-unrelated-source"}')
        self.assertFalse(list(self.root.glob('.relay-pair-*')))

    def test_actual_compiler_publishes_immutable_source_and_preserves_other_exits(self):
        compiled = self.compile(source())
        path = self.sources/(compiled['reference']['source_sha256'] + '.json')
        self.run_pair()
        registry = json.loads(self.registry.read_bytes())
        self.assertEqual(registry['exits'], [self.foreign])
        self.assertEqual(registry['tor_exits'], [self.previous['reference'], compiled['reference']])
        self.assertEqual(path.read_bytes(), compiled['source_json'].encode())
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(path.stat().st_nlink, 1)
        self.assertEqual(self.previous_path.stat().st_ino, self.before_inode)
        inode = path.stat().st_ino
        self.run_pair()
        self.assertEqual(path.stat().st_ino, inode)
        self.assertEqual(self.checks, 2)

    def test_selected_policy_update_preserves_previous_owned_and_unrelated_sources(self):
        self.run_pair()
        prior = json.loads(self.registry.read_bytes())['tor_exits'][-1]
        old_path = self.sources/(prior['source_sha256'] + '.json')
        old_bytes, old_inode = old_path.read_bytes(), old_path.stat().st_ino
        replacement = source()
        replacement['dns']['transport'] = 'tcp'
        self.write(self.input, json.dumps(replacement).encode())
        self.run_pair()
        current = json.loads(self.registry.read_bytes())['tor_exits'][-1]
        self.assertNotEqual(current['source_sha256'], prior['source_sha256'])
        self.assertNotEqual(current['dns_policy_sha256'], prior['dns_policy_sha256'])
        self.assertEqual(old_path.read_bytes(), old_bytes)
        self.assertEqual(old_path.stat().st_ino, old_inode)
        self.assertEqual(json.loads(self.registry.read_bytes())['exits'], [self.foreign])
        self.assertEqual(self.unrelated.read_bytes(), b'{"private":"preserve-unrelated-source"}')

    def test_padding_roundtrips_actual_compiler_dry_run_and_owned_publication(self):
        baseline = self.compile(source())
        retained = {}
        for index, (enabled, rate) in enumerate(((True, 0), (True, 32), (True, 192), (False, 0), (False, 192))):
            with self.subTest(enabled=enabled, rate=rate):
                selected = source()
                selected['padding'] = dict(enabled=enabled, rate_kbps=rate)
                self.write(self.input, json.dumps(selected).encode())
                before = self.registry.read_bytes()
                plan = self.root/('padding-review-'+str(index)+'.json')
                self.run_pair(['--dry-run', plan])
                self.assertEqual(self.registry.read_bytes(), before)
                self.assertEqual(plan.stat().st_mode & 0o777, 0o600)
                review = json.loads(plan.read_bytes())
                reference = review['registry']['tor_exits'][-1]
                canonical = review['tor_sources'][reference['source_sha256']]
                expected = dict(enabled=enabled, rate_kbps=192 if enabled and rate == 0 else rate)
                self.assertEqual(json.loads(canonical)['padding'], expected)
                self.assertNotEqual(reference['source_sha256'], baseline['reference']['source_sha256'])
                self.assertEqual(reference['dns_policy_sha256'], baseline['reference']['dns_policy_sha256'])
                self.run_pair()
                path = self.sources/(reference['source_sha256']+'.json')
                self.assertEqual(path.read_bytes(), canonical.encode())
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                if path in retained:
                    self.assertEqual((path.read_bytes(), path.stat().st_ino), retained[path])
                retained[path] = path.read_bytes(), path.stat().st_ino
                for previous, capture in retained.items():
                    self.assertEqual((previous.read_bytes(), previous.stat().st_ino), capture)
                registry = json.loads(self.registry.read_bytes())
                self.assertEqual(registry['exits'], [self.foreign])
                self.assertEqual(registry['tor_exits'], [self.previous['reference'], reference])
                self.assertEqual(self.previous_path.stat().st_ino, self.before_inode)
                self.assertEqual(self.unrelated.read_bytes(), b'{"private":"preserve-unrelated-source"}')

    def test_malformed_padding_cannot_publish_or_leak_private_source(self):
        for padding in (dict(enabled='true'), dict(enabled=True, rate_kbps=193),
                        dict(enabled=False, rate_kbps=None),
                        dict(enabled=True, password='private-padding-secret')):
            selected = source()
            selected['padding'] = padding
            self.write(self.input, json.dumps(selected).encode())
            with self.assertRaises(ValueError) as failure:
                self.run_pair()
            self.assertNotIn('private-padding-secret', str(failure.exception))
            self.assert_preserved()
        self.assertEqual(self.checks, 0)

    def test_dry_run_writes_only_explicit_private_plan(self):
        plan = self.root/'review'/'pairing-plan.json'
        self.run_pair(['--dry-run', plan])
        self.assert_preserved()
        self.assertFalse((self.root/'.registry.json.lock').exists())
        self.assertEqual(plan.stat().st_mode & 0o777, 0o600)
        value = json.loads(plan.read_bytes())
        self.assertEqual(value['kind'], 'routervpn-relay-pairing-plan')
        self.assertEqual(value['entry_node_id'], NODE)
        self.assertEqual(value['registry']['exits'], [self.foreign])
        for reference in value['registry']['tor_exits']:
            raw = value['tor_sources'][reference['source_sha256']]
            self.assertEqual(self.compile(json.loads(raw))['reference'], reference)
        selected = value['registry']['tor_exits'][-1]['source_sha256']
        self.assertFalse((self.sources/(selected + '.json')).exists())

    def test_tor_only_registry_accepts_absent_or_null_ordinary_exits(self):
        for absent in (True, False):
            value = copy.deepcopy(self.original)
            if absent:
                value.pop('exits')
            else:
                value['exits'] = None
            self.write(self.registry, PAIR.registry_bytes(value))
            self.run_pair()
            registry = json.loads(self.registry.read_bytes())
            self.assertIsNone(registry.get('exits'))
            self.assertEqual(len(registry['tor_exits']), 2)

    def test_dry_run_cannot_replace_inputs_or_live_sources(self):
        for output in (self.input, self.agent_config, self.registry, self.sources/'plan.json'):
            with self.subTest(output=output.name), self.assertRaisesRegex(ValueError, 'separate'):
                self.run_pair(['--dry-run', output])
        self.assert_preserved()
        self.assertEqual(self.checks, 0)

    def test_shared_compiler_rejects_borrowed_entry_id_and_dns_without_publication(self):
        for mutate in (lambda value: value.update(entry_node_id='c'*64), lambda value: value.update(id='foreign-id'),
                       lambda value: value['dns'].update(address='192.168.1.53'),
                       lambda value: value.update(torrc='private-secret-must-not-echo')):
            selected = source()
            mutate(selected)
            self.write(self.input, json.dumps(selected).encode())
            with self.assertRaises(ValueError) as failure:
                self.run_pair()
            self.assertNotIn('private-secret-must-not-echo', str(failure.exception))
            self.assert_preserved()
        self.assertEqual(self.checks, 0)

    def test_private_source_permissions_and_links_are_required(self):
        for fault in ('input-public', 'source-public', 'source-linked', 'parent-linked', 'directory-public'):
            with self.subTest(fault=fault):
                if fault == 'input-public': self.input.chmod(0o644)
                if fault == 'source-public': self.previous_path.chmod(0o644)
                if fault == 'source-linked':
                    self.previous_path.rename(self.previous_path.with_suffix('.owned'))
                    self.previous_path.symlink_to(self.previous_path.with_suffix('.owned'))
                if fault == 'parent-linked':
                    self.sources.rename(self.root/'owned-sources')
                    self.sources.symlink_to(self.root/'owned-sources', target_is_directory=True)
                if fault == 'directory-public': self.sources.chmod(0o755)
                with self.assertRaises((ValueError, RuntimeError, OSError)):
                    self.run_pair()
                self.assertEqual(self.registry.read_bytes(), self.before)
                if fault == 'input-public': self.input.chmod(0o600)
                if fault == 'source-public': self.previous_path.chmod(0o600)
                if fault == 'source-linked':
                    self.previous_path.unlink()
                    self.previous_path.with_suffix('.owned').rename(self.previous_path)
                if fault == 'parent-linked':
                    self.sources.unlink()
                    (self.root/'owned-sources').rename(self.sources)
                if fault == 'directory-public': self.sources.chmod(0o700)
        self.assertEqual(self.checks, 0)

    def test_missing_existing_tor_source_does_not_replace_registry(self):
        self.previous_path.unlink()
        with self.assertRaises(FileNotFoundError): self.run_pair()
        self.assertEqual(self.registry.read_bytes(), self.before)
        self.assertEqual(self.checks, 0)

    def test_combined_exit_capacity_is_checked_before_native_execution(self):
        value = copy.deepcopy(self.original)
        value['tor_exits'] *= 64
        self.write(self.registry, PAIR.registry_bytes(value))
        before = self.registry.read_bytes()
        with self.assertRaisesRegex(ValueError, 'count exceeds bound'): self.run_pair()
        self.assertEqual(self.registry.read_bytes(), before)
        self.assertEqual(self.checks, 0)

    def test_native_rejection_has_no_published_source_or_registry(self):
        def reject(): raise RuntimeError('native rejection sentinel')
        self.on_check = reject
        with self.assertRaisesRegex(RuntimeError, 'native rejection'): self.run_pair()
        self.assert_preserved()
        self.assertEqual(sorted(path.name for path in self.sources.iterdir()), sorted([self.previous_path.name, self.unrelated.name]))

    def test_stale_input_and_equal_byte_replacements_cannot_publish(self):
        for path, replacement in ((self.input, json.dumps(source()).encode()), (self.agent_config, self.agent_config.read_bytes()),
                                  (self.previous_path, self.before_source), (self.registry, self.before)):
            with self.subTest(path=path.name):
                self.on_check = lambda path=path, replacement=replacement: self.write(path, replacement)
                with self.assertRaisesRegex(ValueError, 'changed'): self.run_pair()
                self.assertEqual(self.registry.read_bytes(), self.before)
        selected = self.compile(source())['reference']['source_sha256']
        self.assertFalse((self.sources/(selected+'.json')).exists())

    def test_immutable_source_collision_preserves_the_foreign_file(self):
        selected = self.compile(source())['reference']['source_sha256']
        target = self.sources/(selected+'.json')
        self.write(target, b'{"foreign":"must-preserve"}')
        with self.assertRaisesRegex(ValueError, 'immutable Tor source'): self.run_pair()
        self.assertEqual(target.read_bytes(), b'{"foreign":"must-preserve"}')
        self.assert_preserved()

    def test_replaced_source_directory_is_not_adopted(self):
        # No retained source is needed to detect replacement of an initially
        # empty directory during a first pairing.
        value = copy.deepcopy(self.original)
        value['tor_exits'] = []
        self.write(self.registry, PAIR.registry_bytes(value))
        before = self.registry.read_bytes()
        def replace():
            self.sources.rename(self.root/'previous-source-owner')
            self.sources.mkdir(mode=0o700)
            self.write(self.sources/'replacement.json', b'{"owner":"preserve"}')
        self.on_check = replace
        with self.assertRaisesRegex(ValueError, 'source directory changed'):
            self.run_pair()
        self.assertEqual(self.registry.read_bytes(), before)
        self.assertEqual((self.sources/'replacement.json').read_bytes(), b'{"owner":"preserve"}')
        self.assertEqual(list(path.name for path in self.sources.iterdir()), ['replacement.json'])

    def failure_writer(self, callback):
        original = PAIR.helpers
        def helpers():
            read, write, parent = original()
            def guarded(path, body):
                if Path(path) == self.registry:
                    callback(write, body)
                else:
                    write(path, body)
            return read, guarded, parent
        return mock.patch.object(PAIR, 'helpers', side_effect=helpers)

    def test_registry_failure_rolls_back_only_the_new_owned_source(self):
        def fail(write, body): raise RuntimeError('registry publication rejected')
        with self.failure_writer(fail), self.assertRaisesRegex(RuntimeError, 'publication rejected'):
            self.run_pair()
        self.assert_preserved()
        selected = self.compile(source())['reference']['source_sha256']
        self.assertFalse((self.sources/(selected+'.json')).exists())

    def test_post_commit_failure_keeps_the_referenced_source(self):
        def fail(write, body):
            write(self.registry, body)
            raise RuntimeError('post-commit verification rejected')
        with self.failure_writer(fail), self.assertRaisesRegex(RuntimeError, 'post-commit'):
            self.run_pair()
        reference = json.loads(self.registry.read_bytes())['tor_exits'][-1]
        self.assertEqual((self.sources/(reference['source_sha256']+'.json')).read_bytes(), self.compile(source())['source_json'].encode())
        self.assertEqual(self.previous_path.read_bytes(), self.before_source)

    def test_failed_registry_write_cannot_delete_replacement_source_owner(self):
        selected = self.compile(source())['reference']['source_sha256']
        target = self.sources/(selected+'.json')
        def fail(write, body):
            write(target, b'{"replacement":"must-preserve"}')
            raise RuntimeError('registry rejected after replacement')
        with self.failure_writer(fail), self.assertRaisesRegex(RuntimeError, 'after replacement'):
            self.run_pair()
        self.assertEqual(target.read_bytes(), b'{"replacement":"must-preserve"}')
        self.assert_preserved()

    def test_adoption_race_never_overwrites_new_foreign_source(self):
        link = os.link
        def replace(source_path, target, **kwargs):
            self.write(target, b'{"new-owner":"must-preserve"}')
            return link(source_path, target, **kwargs)
        with mock.patch.object(PAIR.os, 'link', side_effect=replace), self.assertRaises(FileExistsError):
            self.run_pair()
        selected = self.compile(source())['reference']['source_sha256']
        self.assertEqual((self.sources/(selected+'.json')).read_bytes(), b'{"new-owner":"must-preserve"}')
        self.assertFalse(list(self.sources.glob('.tor-source-*')))
        self.assert_preserved()

    def test_ordinary_exit_pairing_preserves_and_validates_saved_tor_sources(self):
        bundle = self.root/'bundle.json'
        transport = dict(type='shadowsocks', tag='proxy', server='198.51.100.2', server_port=8388,
                         method='aes-256-gcm', password='private-new-proxy-key')
        value = dict(selectedRouterID='ordinary', routerProfiles=[dict(id='ordinary', node_kind='router-vpn',
                     endpoint='198.51.100.2', adguard_ipv4='10.88.0.1', node_proof_id='c'*64)],
                     profiles={'shadowsocks': {'sing-box.json': base64.b64encode(json.dumps(dict(outbounds=[transport])).encode()).decode()}})
        self.write(bundle, json.dumps(value).encode())
        self.run_pair(bundle=bundle)
        registry = json.loads(self.registry.read_bytes())
        self.assertEqual(registry['tor_exits'], [self.previous['reference']])
        self.assertEqual(registry['exits'][0], self.foreign)
        self.assertEqual(registry['exits'][1]['id'], 'operator-tor')
        self.assertEqual(self.previous_path.stat().st_ino, self.before_inode)


if __name__ == '__main__':
    unittest.main()
