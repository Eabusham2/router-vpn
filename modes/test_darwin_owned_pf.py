#!/usr/bin/env python3
"""Exercise the shipping Darwin dispatcher without touching the host PF table."""
from pathlib import Path
import contextlib
import fcntl
import hashlib
import importlib.util
import io
import json
import os
import stat
import subprocess
import sys
import tempfile
import time
import types
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('darwin_owned_dispatch_test', HERE/'kill-switch-platform.py')
D = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(D)
P = D._darwin
NATIVE_OWNED_INFO = P._baseline._owned_info
SPAWN_WATCHER = D._spawn_watcher
RUN_PF = P.run_pf
POPEN = subprocess.Popen


class OwnedDarwinPF(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='darwin-owned-policy-')
        self.addCleanup(self.temporary.cleanup)
        # macOS temporary paths can retain /var -> /private/var. Capture the
        # physical fixture root before the real no-follow private traversal.
        # Caller-supplied symlinks remain rejected by the production helper.
        self.root = Path(self.temporary.name).resolve(strict=True)
        (self.root/'run').mkdir(mode=0o700)
        self.selected = {'id': 'direct-tor', 'node_kind': 'external', 'endpoint': '198.51.100.44',
                         'external': {'protocol': 'tor'}, 'kill_switch_policy': 'always',
                         'kill_switch': True, 'home_lan_access': False, 'multihop_enabled': False}
        self.store = {'selected_id': 'direct-tor', 'profiles': [self.selected]}
        self.private_json(self.root/'routers.json', self.store)
        self.env = {'HOMEVPN_ROOT': str(self.root), 'HOMEVPN_PROFILE_ID': 'direct-tor',
                    'HOMEVPN_POLICY_PROFILE_ID': 'direct-tor', 'HOMEVPN_STANDARD_ENGINE': 'native',
                    'HOMEVPN_TOR_SESSION': 'a'*32, 'HOMEVPN_TOR_SOURCE_SHA256': 'b'*64,
                    'HOMEVPN_TOR_PHYSICAL_BROKER': '1', 'HOMEVPN_ENDPOINT': '',
                    'HOMEVPN_NATIVE_ENDPOINTS_JSON': '', 'HOMEVPN_NATIVE_EGRESS_JSON': '',
                    'HOMEVPN_EXTERNAL_SESSION': '', 'HOMEVPN_KILLSWITCH_DRY_RUN': '0'}
        self.commands, self.rules, self.saved_before_load = [], {}, []
        self.references, self.next_reference = {'999'}, 417
        self.reference_reads, self.native_calls = [], []
        self.fail_after_load = False
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.dict(os.environ, self.env))
        self.stack.enter_context(patch.object(D.sys, 'platform', 'darwin'))
        self.stack.enter_context(patch.object(P, 'run_pf', side_effect=self.pf))
        self.stack.enter_context(patch.object(P._baseline, '_invoke', side_effect=self.native))
        self.stack.enter_context(patch.object(P._baseline, 'reference', side_effect=self.reference))
        uid, gid = os.getuid(), os.getgid()
        # This portable backend owns only its temporary current-user files.
        # Translate that captured owner at the same explicit fixture boundary
        # as BaselinePrivateJournal; retain the real native mode/type/link
        # predicate and all actual open, inode, readback, lock and fsync checks.
        # The installed native gate separately executes the root-only predicate.
        def fixture_owner(info, *, directory=False):
            if info.st_uid != uid or info.st_gid != gid:
                return False
            scoped = types.SimpleNamespace(st_mode=info.st_mode, st_nlink=info.st_nlink, st_uid=0, st_gid=0)
            return NATIVE_OWNED_INFO(scoped, directory=directory)
        self.stack.enter_context(patch.object(P._baseline, '_owned_info', side_effect=fixture_owner))
        self.stack.enter_context(patch.object(P, 'owned_pf_preflight'))
        self.stack.enter_context(patch.object(P, 'physical_state_interfaces', return_value={'en0': ['192.0.2.1', '2001:db8::1']}))
        self.retire = self.stack.enter_context(patch.object(P, 'retire_physical_states'))
        self.watcher = self.stack.enter_context(patch.object(D, '_spawn_watcher'))
        self.resolver = self.stack.enter_context(patch('socket.getaddrinfo', side_effect=AssertionError('pre-tunnel DNS')))

    def paired_node_capture(self, policy='always', mode='wg', layer='off'):
        self.selected.update(node_kind='router-vpn', node_proof_id='f'*64, start_layer=layer,
                             kill_switch_policy=policy, kill_switch=policy != 'off')
        self.selected.pop('external', None)
        self.private_json(self.root/'routers.json', self.store)
        self.stack.enter_context(patch.dict(os.environ, {'HOMEVPN_TOR_PHYSICAL_BROKER': '',
            'HOMEVPN_TOR_SESSION': '', 'HOMEVPN_TOR_SOURCE_SHA256': '', 'HOMEVPN_ENDPOINT': ''}))
        return dict(schema=1, family='paired-node-v1', profile_id=self.selected['id'], node_id='f'*64,
                    mode=mode, start_layer=layer, session_id='c'*32, source_sha256='d'*64,
                    config_sha256='e'*64, home_lan_access=False, policy=policy)

    def test_paired_node_original_baseline_all_modes_layers_policies(self):
        for mode in D._NODE_MODES:
            for layer in D._NODE_LAYERS:
                for policy in ('off', 'on-connect', 'always'):
                    with self.subTest(mode=mode, layer=layer, policy=policy):
                        capture = self.paired_node_capture(policy, mode, layer)
                        active = D.darwin_node('apply', dict(capture=capture, expected=None))
                        self.assertEqual(active['capture'], capture)
                        self.assertEqual(D.darwin_node('current', dict(capture=capture, expected=active)), active)
                        state = self.saved()
                        self.assertEqual(state['native_socket_family'], 'paired-node-v1')
                        self.assertEqual(state['native_node_capture'], capture)
                        self.assertEqual(state['endpoint_ips'], [])
                        self.assertNotIn('native_egress', state)
                        held = D.darwin_node('retire', dict(capture=capture, expected=active))
                        self.assertEqual(held['baseline']['present'], policy != 'off')
                        retired = D.darwin_node('release', dict(capture=capture, expected=held))
                        self.assertEqual(retired['baseline']['present'], policy == 'always')
                        if policy == 'always': D.darwin_release(True)
                        self.assertEqual(self.references, {'999'})

    def test_paired_node_capture_cannot_borrow_family_or_saved_profile(self):
        original = self.paired_node_capture('off')
        for fault in [dict(family='ordered-node-chain-v1'), dict(mode='max'), dict(start_layer='xor'),
                      dict(node_id='1'*64), dict(profile_id='another'), dict(policy='always'),
                      dict(home_lan_access=True), dict(schema=True), dict(extra='foreign')]:
            before, commands = D._linux.read_state(self.root), list(self.commands)
            with self.assertRaises(RuntimeError):
                D.darwin_node('apply', dict(capture={**original, **fault}, expected=None))
            self.assertEqual(D._linux.read_state(self.root), before)
            self.assertEqual(self.commands, commands)
        self.selected['node_kind'] = 'external'
        self.private_json(self.root/'routers.json', self.store)
        with self.assertRaises(RuntimeError):
            D.darwin_node('apply', dict(capture=original, expected=None))

    def test_paired_node_failed_retirement_and_replacement_keep_exact_owner(self):
        original = self.paired_node_capture('on-connect')
        active = D.darwin_node('apply', dict(capture=original, expected=None))
        def failed_clear(phase, request):
            if request['action'] == 'clear':
                raise RuntimeError('original native reference remains')
            return self.native(phase, request)
        with patch.object(P._baseline, '_invoke', side_effect=failed_clear):
            with self.assertRaisesRegex(RuntimeError, 'reference remains'):
                D.darwin_node('release', dict(capture=original, expected=active))
        self.assertEqual(self.saved()['native_node_capture'], original)
        self.assertIn(active['pf_token'], self.references)
        held = D.darwin_node('retire', dict(capture=original, expected=active))
        successor = self.paired_node_capture('off')
        successor.update(session_id='1'*32, source_sha256='2'*64)
        actual = D.darwin_node('apply', dict(capture=successor, expected=None))
        before, commands = D._linux.read_state(self.root), list(self.commands)
        with self.assertRaisesRegex(RuntimeError, 'another retained owner'):
            D.darwin_node('release', dict(capture=original, expected=held))
        self.assertEqual(D._linux.read_state(self.root), before)
        self.assertEqual(self.commands, commands)
        self.assertEqual(D.darwin_node('current', dict(capture=successor, expected=actual)), actual)
        D.darwin_node('release', dict(capture=successor, expected=actual))

    def external_capture(self, policy='always'):
        self.selected['external'] = {'protocol': 'shadowsocks'}
        self.selected['kill_switch_policy'] = policy
        self.private_json(self.root/'routers.json', self.store)
        self.stack.enter_context(patch.dict(os.environ, {
            'HOMEVPN_TOR_PHYSICAL_BROKER': '', 'HOMEVPN_TOR_SESSION': '',
            'HOMEVPN_TOR_SOURCE_SHA256': '', 'HOMEVPN_ENDPOINT': ''}))
        return dict(schema=2, profile_id='direct-tor', entry_profile_id='', final_policy=policy,
                    entry_policy='', protocol='shadowsocks',
                    session_id='c'*32, source_sha256='d'*64, config_sha256='e'*64,
                    home_lan_access=False, policy=policy)

    def test_off_native_families_keep_host_states_and_exact_retirement_capture(self):
        families = [('external', self.external_capture, D.darwin_external),
                    ('candidate-prefix', self.candidate_prefix_capture, D.darwin_candidate_prefix)]
        for family in D._NODE_CHAIN_FAMILIES:
            families.append((family, lambda policy, family=family: self.node_chain_capture(policy, family), D.darwin_node_chain))
        for label, capture_for, action in families:
            with self.subTest(family=label):
                capture = capture_for('off')
                active = action('apply', dict(capture=capture, expected=None))
                self.assertTrue(active['baseline']['present'])
                self.assertEqual(self.rules[P.OWNED_PF_ANCHOR], 'anchor "p'+capture['session_id']+'" out\n')
                self.assertIs(self.saved()[P._baseline.STATE_KEY]['request']['isolated_only'], True)
                self.assertEqual(action('current', dict(capture=capture, expected=active)), active)
                self.retire.assert_not_called()
                before = self.saved()
                journal = before[P._baseline.STATE_KEY]
                journal['request'].pop('isolated_only')
                self.private_json(self.root/'run/kill-switch.json', before)
                with self.assertRaisesRegex(RuntimeError, 'persistent kill-switch state contains an invalid policy'):
                    action('current', dict(capture=capture, expected=active))
                journal['request']['isolated_only'] = True
                self.private_json(self.root/'run/kill-switch.json', before)
                held = action('retire', dict(capture=capture, expected=active))
                self.assertEqual(held['phase'], 'held')
                self.assertFalse(held['baseline']['present'])
                self.assertEqual(held['pf_token'], active['pf_token'])
                self.assertFalse((self.root/'run/kill-switch.json').exists())
                self.assertEqual(self.references, {'999'})
                self.assertEqual(action('retire', dict(capture=capture, expected=active)), held)
                retired = action('release', dict(capture=capture, expected=held))
                self.assertEqual(retired['phase'], 'retired')
                self.assertFalse(retired['baseline']['present'])
                self.assertEqual(action('release', dict(capture=capture, expected=retired)), retired)
                with self.assertRaisesRegex(RuntimeError, 'retired reference proof'):
                    action('release', dict(capture=capture, expected=None))
                self.references.add(active['pf_token'])
                with self.assertRaisesRegex(RuntimeError, 'retired reference proof'):
                    action('release', dict(capture=capture, expected=retired))
                self.references.remove(active['pf_token'])
        self.watcher.assert_not_called()
        self.resolver.assert_not_called()

    def test_external_native_protocols_reach_original_plan_without_relaxing_unknown_rejection(self):
        protocols = ('socks5', 'shadowsocks', 'http-connect', 'https-connect',
                     'hysteria2', 'wireguard', 'amneziawg', 'openvpn')
        for protocol in protocols:
            with self.subTest(protocol=protocol):
                fixture = OwnedDarwinPF()
                fixture.setUp()
                try:
                    capture = fixture.external_capture('on-connect')
                    capture['protocol'] = protocol
                    fixture.selected['external'] = {'protocol': protocol}
                    fixture.private_json(fixture.root/'routers.json', fixture.store)
                    sentinel = RuntimeError('original external native plan refuses execution')
                    with patch.object(P._baseline, '_invoke', side_effect=sentinel) as native:
                        with self.assertRaises(RuntimeError) as raised:
                            D.darwin_external('apply', dict(capture=capture, expected=None))
                        self.assertIs(raised.exception, sentinel)
                        self.assertEqual(native.call_count, 1)
                    for invalid in ('tor', 'unknown', protocol.upper(), protocol+' '):
                        changed = dict(capture, protocol=invalid)
                        with patch.object(P._baseline, '_invoke', side_effect=sentinel) as native:
                            with self.assertRaisesRegex(RuntimeError, 'exact ordinary policy capture'):
                                D.darwin_external('apply', dict(capture=changed, expected=None))
                            native.assert_not_called()
                    fixture.resolver.assert_not_called()
                finally:
                    fixture.doCleanups()

    def test_external_aggregate_applies_original_members_and_preserves_final_lan(self):
        cases = (('off', 'always', 'always'), ('on-connect', 'always', 'always'),
                 ('always', 'off', 'always'), ('always', 'on-connect', 'always'),
                 ('off', 'on-connect', 'on-connect'), ('on-connect', 'off', 'on-connect'))
        for final, entry_policy, aggregate in cases:
            with self.subTest(final=final, entry=entry_policy):
                fixture = OwnedDarwinPF()
                fixture.setUp()
                try:
                    capture = fixture.external_capture(final)
                    entry = dict(fixture.selected, id='original-entry', external={'protocol': 'openvpn'},
                                 kill_switch_policy=entry_policy, home_lan_access=True)
                    fixture.store['profiles'].append(entry)
                    fixture.private_json(fixture.root/'routers.json', fixture.store)
                    capture.update(entry_profile_id=entry['id'], entry_policy=entry_policy, policy=aggregate)
                    try:
                        active = D.darwin_external('apply', dict(capture=capture, expected=None))
                    except RuntimeError as error:
                        self.fail('external aggregate did not reach its applied strongest policy: '+str(error))
                    state = fixture.saved()
                    self.assertEqual(state['policy'], aggregate, 'external aggregate lost its applied strongest policy')
                    self.assertFalse(state['home_lan_access'])
                    self.assertEqual(state['native_external_capture'], capture)
                    self.assertEqual(D.darwin_external('current', dict(capture=capture, expected=active)), active)
                    if aggregate == 'always':
                        self.assertEqual(D.darwin_reassert(), 0)
                        self.assertEqual(fixture.saved()['policy'], 'always')
                        self.assertEqual(fixture.saved()['native_external_capture'], capture)
                    fixture.resolver.assert_not_called()
                finally:
                    fixture.doCleanups()

    def test_external_changed_member_with_same_aggregate_refuses_before_native_plan(self):
        capture = self.external_capture('always')
        entry = dict(self.selected, id='original-entry', external={'protocol': 'wireguard'},
                     kill_switch_policy='off', home_lan_access=True)
        self.store['profiles'].append(entry)
        self.private_json(self.root/'routers.json', self.store)
        capture.update(entry_profile_id=entry['id'], entry_policy='on-connect')
        sentinel = RuntimeError('original native plan refuses execution')
        with patch.object(P._baseline, '_invoke', side_effect=sentinel) as native:
            try:
                D.darwin_external('apply', dict(capture=capture, expected=None))
            except RuntimeError as error:
                self.assertIn('captured saved protection policy', str(error),
                              'changed original member reached native mutation')
                native.assert_not_called()
            else:
                self.fail('changed original member reached native mutation')

    def test_external_original_member_legacy_boolean_matches_sealed_policy(self):
        for role in ('final', 'entry'):
            for enabled, policy in ((False, 'off'), (True, 'on-connect')):
                for empty_policy in (False, True):
                    with self.subTest(role=role, enabled=enabled, empty_policy=empty_policy):
                        fixture = OwnedDarwinPF()
                        fixture.setUp()
                        try:
                            capture = fixture.external_capture(policy if role == 'final' else 'always')
                            member = fixture.selected
                            if role == 'entry':
                                member = dict(fixture.selected, id='original-entry', external={'protocol': 'openvpn'})
                                fixture.store['profiles'].append(member)
                                capture.update(entry_profile_id=member['id'], entry_policy=policy)
                            member['kill_switch'] = enabled
                            if empty_policy:
                                member['kill_switch_policy'] = ''
                            else:
                                member.pop('kill_switch_policy')
                            fixture.private_json(fixture.root/'routers.json', fixture.store)
                            sentinel = RuntimeError('original member native plan refusal')
                            with patch.object(P._baseline, '_invoke', side_effect=sentinel) as native:
                                with self.assertRaises(RuntimeError) as raised:
                                    D.darwin_external('apply', dict(capture=capture, expected=None))
                                self.assertIs(raised.exception, sentinel,
                                              'legacy member changed its sealed effective policy')
                                self.assertEqual(native.call_count, 1)
                        finally:
                            fixture.doCleanups()

    def test_external_original_member_rejects_noncanonical_policy_before_native_plan(self):
        for role in ('final', 'entry'):
            fixture = OwnedDarwinPF()
            fixture.setUp()
            try:
                capture = fixture.external_capture('on-connect' if role == 'final' else 'always')
                member = fixture.selected
                if role == 'entry':
                    member = dict(fixture.selected, id='original-entry', external={'protocol': 'wireguard'},
                                  kill_switch_policy='on-connect')
                    fixture.store['profiles'].append(member)
                    capture.update(entry_profile_id=member['id'], entry_policy='on-connect')
                for field, value in (('kill_switch', 'true'), ('kill_switch', None), ('kill_switch', 1),
                                     ('kill_switch_policy', 'ON-CONNECT'), ('kill_switch_policy', ' on-connect '),
                                     ('kill_switch_policy', None), ('kill_switch_policy', 1)):
                    with self.subTest(role=role, field=field, value=value):
                        original = member[field]
                        member[field] = value
                        fixture.private_json(fixture.root/'routers.json', fixture.store)
                        with patch.object(P._baseline, '_invoke', side_effect=RuntimeError('native plan should remain closed')) as native:
                            with self.assertRaises(RuntimeError):
                                D.darwin_external('apply', dict(capture=capture, expected=None))
                            native.assert_not_called()
                        member[field] = original
            finally:
                fixture.doCleanups()

    def test_external_legacy_capture_cannot_acquire_a_fresh_native_baseline(self):
        capture = self.external_capture()
        legacy = {key: capture[key] for key in D._EXTERNAL_LEGACY_CAPTURE_FIELDS}
        legacy['schema'] = 1
        with patch.object(P._baseline, '_invoke', side_effect=RuntimeError('native plan should remain closed')) as native:
            try:
                D.darwin_external('apply', dict(capture=legacy, expected=None))
            except RuntimeError as error:
                self.assertIn('legacy macOS external capture', str(error),
                              'legacy unbound capture acquired native admission')
                native.assert_not_called()
            else:
                self.fail('legacy unbound capture acquired native admission')
        self.assertFalse((self.root/'run/kill-switch.json').exists())

    def test_external_legacy_original_state_remains_readable_and_retirable(self):
        capture = self.external_capture('on-connect')
        active = D.darwin_external('apply', dict(capture=capture, expected=None))
        legacy = {key: capture[key] for key in D._EXTERNAL_LEGACY_CAPTURE_FIELDS}
        legacy['schema'] = 1
        state = self.saved()
        state['native_external_capture'] = legacy
        self.private_json(self.root/'run/kill-switch.json', state)
        receipt = dict(active, capture=legacy)
        self.assertEqual(D.darwin_external('current', dict(capture=legacy, expected=receipt)), receipt)
        self.assertEqual(D.darwin_external('apply', dict(capture=legacy, expected=None)), receipt)
        held = D.darwin_external('retire', dict(capture=legacy, expected=receipt))
        self.assertTrue(held['baseline']['present'])
        retired = D.darwin_external('release', dict(capture=legacy, expected=held))
        self.assertFalse(retired['baseline']['present'])
        self.assertFalse((self.root/'run/kill-switch.json').exists())

    def test_external_legacy_always_reassert_preserves_its_exact_original_deny(self):
        capture = self.external_capture('always')
        active = D.darwin_external('apply', dict(capture=capture, expected=None))
        legacy = {key: capture[key] for key in D._EXTERNAL_LEGACY_CAPTURE_FIELDS}
        legacy['schema'] = 1
        state = self.saved()
        state['native_external_capture'] = legacy
        self.private_json(self.root/'run/kill-switch.json', state)
        self.assertEqual(D.darwin_reassert(), 0)
        self.assertEqual(self.saved()['native_external_capture'], legacy)
        self.assertEqual(self.saved()['policy'], 'always')
        receipt = dict(active, capture=legacy)
        held = D.darwin_external('retire', dict(capture=legacy, expected=receipt))
        self.assertTrue(held['baseline']['present'])
        self.assertTrue(D.darwin_external('release', dict(capture=legacy, expected=held))['baseline']['present'])

    def test_external_family_uses_exact_existing_native_journal_and_always_retirement(self):
        capture = self.external_capture()
        request = dict(capture=capture, expected=None)
        with D._darwin_action_guard(self.root):
            active = D.darwin_external('apply', request)
        self.assertEqual(active['phase'], 'active')
        state = self.saved()
        self.assertEqual(state['native_socket_family'], 'external-v1')
        self.assertEqual(state['native_external_capture'], capture)
        self.assertEqual(state[P._baseline.STATE_KEY]['request']['session_id'], capture['session_id'])
        self.assertEqual(state[P._baseline.STATE_KEY]['request']['source_sha256'], capture['source_sha256'])
        self.assertEqual(state['endpoint_ips'], [])
        self.assertNotIn('pass out quick', self.rules[P.OWNED_PF_ANCHOR])
        self.assertEqual(D.darwin_external('current', dict(capture=capture, expected=active)), active)
        self.assertEqual(D.darwin_external('apply', request), active)
        self.assertEqual(self.commands.count(['-E']), 1)
        with D._darwin_action_guard(self.root):
            retired = D.darwin_external('release', dict(capture=capture, expected=active))
        self.assertEqual(retired['phase'], 'retired')
        self.assertTrue(retired['baseline']['present'])
        self.assertEqual(retired['pf_token'], active['pf_token'])
        self.assertEqual(self.saved()[P._baseline.STATE_KEY]['request']['session_id'], '')
        self.assertNotIn('anchor ', self.rules[P.OWNED_PF_ANCHOR])
        self.assertEqual(self.references, {'417', '999'})
        self.watcher.assert_not_called()
        self.resolver.assert_not_called()

    def test_external_on_connect_release_proves_original_reference_and_absence(self):
        capture = self.external_capture('on-connect')
        active = D.darwin_external('apply', dict(capture=capture, expected=None))
        retired = D.darwin_external('release', dict(capture=capture, expected=active))
        self.assertFalse(retired['baseline']['present'])
        self.assertFalse((self.root/'run/kill-switch.json').exists())
        self.assertEqual(self.references, {'999'})
        self.assertEqual(D.darwin_external('release', dict(capture=capture, expected=active)), retired)
        with self.assertRaisesRegex(RuntimeError, 'retired reference proof'):
            D.darwin_external('release', dict(capture=capture, expected=None))
        self.references.add(active['pf_token'])
        with self.assertRaisesRegex(RuntimeError, 'retired reference proof'):
            D.darwin_external('release', dict(capture=capture, expected=active))

    def test_external_stale_scope_or_reference_cannot_retire_replacement(self):
        capture = self.external_capture()
        active = D.darwin_external('apply', dict(capture=capture, expected=None))
        before, commands = self.saved(), list(self.commands)
        for field, other in (('session_id', 'f'*32), ('source_sha256', 'f'*64),
                             ('config_sha256', 'f'*64), ('protocol', 'http-connect'),
                             ('home_lan_access', True), ('profile_id', 'foreign-profile')):
            changed = {**capture, field: other}
            with self.subTest(field=field), self.assertRaises(RuntimeError, msg='stale external capture retired another native owner'):
                D.darwin_external('release', dict(capture=changed, expected=None))
            self.assertEqual(self.saved(), before)
            self.assertEqual(self.commands, commands)
        with self.assertRaisesRegex(RuntimeError, 'original PF reference', msg='external cleanup released a different captured PF reference'):
            D.darwin_external('release', dict(capture=capture, expected={**active, 'pf_token': '999'}))
        self.assertEqual(self.saved(), before)

    def test_external_on_connect_switch_holds_deny_until_exact_disconnect(self):
        capture = self.external_capture('on-connect')
        active = D.darwin_external('apply', dict(capture=capture, expected=None))
        try:
            held = D.darwin_external('retire', dict(capture=capture, expected=active))
        except RuntimeError as error:
            self.fail('native switch released its deny baseline: '+str(error))
        self.assertEqual(held['phase'], 'held')
        self.assertTrue(held['baseline']['present'], 'native switch released its deny baseline')
        self.assertEqual(self.references, {'417', '999'})
        self.assertEqual(self.saved()['policy'], 'on-connect')
        self.assertEqual(self.saved()[P._baseline.STATE_KEY]['request']['session_id'], '')
        self.assertNotIn('anchor ', self.rules[P.OWNED_PF_ANCHOR])
        self.assertEqual(D.darwin_external('retire', dict(capture=capture, expected=held)), held)
        retired = D.darwin_external('release', dict(capture=capture, expected=held))
        self.assertFalse(retired['baseline']['present'])
        self.assertEqual(self.references, {'999'})

    def test_external_successor_replaces_only_joined_deny_and_old_owner_cannot_release(self):
        capture = self.external_capture('on-connect')
        active = D.darwin_external('apply', dict(capture=capture, expected=None))
        held = D.darwin_external('retire', dict(capture=capture, expected=active))
        successor = {**capture, 'session_id': 'a'*32, 'source_sha256': 'b'*64}
        replacement = D.darwin_external('apply', dict(capture=successor, expected=None))
        before, commands = self.saved(), list(self.commands)
        with self.assertRaisesRegex(RuntimeError, 'another retained owner'):
            D.darwin_external('release', dict(capture=capture, expected=held))
        self.assertEqual(self.saved(), before)
        self.assertEqual(self.commands, commands)
        self.assertEqual(D.darwin_external('current', dict(capture=successor, expected=replacement)), replacement)

    def test_external_changed_saved_policy_fails_before_any_off_removal(self):
        capture = self.external_capture()
        self.legacy_state()
        before, commands = self.saved(), list(self.commands)
        for field, value in (('kill_switch_policy', 'off'), ('home_lan_access', True),
                             ('external', {'protocol': 'tor'})):
            original = self.selected[field]
            self.selected[field] = value
            self.private_json(self.root/'routers.json', self.store)
            with self.subTest(field=field), self.assertRaisesRegex(RuntimeError, 'captured saved protection policy'):
                D.darwin_external('apply', dict(capture=capture, expected=None))
            self.selected[field] = original
            self.assertEqual(self.saved(), before)
            self.assertEqual(self.commands, commands)

    def test_external_ambiguous_native_apply_retains_original_cleanup_owner(self):
        capture = self.external_capture('on-connect')
        self.fail_after_load = True
        with self.assertRaisesRegex(RuntimeError, 'ambiguous applied'):
            D.darwin_external('apply', dict(capture=capture, expected=None))
        state = self.saved()
        self.assertEqual(state['native_external_capture'], capture)
        self.assertTrue(state['darwin_transition_pending'])
        self.assertFalse(state[P._baseline.STATE_KEY]['complete'])
        self.assertNotIn(['-X', '417'], self.commands)
        self.fail_after_load = False
        retired = D.darwin_external('release', dict(capture=capture, expected=None))
        self.assertFalse(retired['baseline']['present'])
        self.assertEqual(self.references, {'999'})

    def test_external_retained_reassert_keeps_ordinary_family_without_live_session(self):
        capture = self.external_capture()
        D.darwin_external('apply', dict(capture=capture, expected=None))
        self.assertEqual(D.darwin_reassert(), 0)
        state = self.saved()
        self.assertEqual(state['native_socket_family'], 'external-v1')
        self.assertEqual(state['native_external_capture'], capture)
        self.assertEqual(state[P._baseline.STATE_KEY]['request']['session_id'], '')
        self.assertEqual(state[P._baseline.STATE_KEY]['request']['source_sha256'], '')
        self.assertNotIn('anchor ', self.rules[P.OWNED_PF_ANCHOR])
        with self.assertRaisesRegex(RuntimeError, 'current native session proof'):
            D.darwin_external('apply', dict(capture=capture, expected=None))

    def node_chain_capture(self, policy='always', family='ordered-node-chain-v1'):
        self.selected['node_kind'] = 'router-vpn'
        self.selected.pop('external', None)
        self.selected['kill_switch_policy'] = policy
        entry = dict(id='ordered-entry', node_kind='router-vpn', kill_switch_policy=policy,
                     ipv6_mode='on', home_lan_access=False)
        self.store['profiles'] = [p for p in self.store['profiles'] if p.get('id') != 'ordered-entry'] + [entry]
        self.private_json(self.root/'routers.json', self.store)
        self.stack.enter_context(patch.dict(os.environ, {
            'HOMEVPN_TOR_PHYSICAL_BROKER': '', 'HOMEVPN_TOR_SESSION': '',
            'HOMEVPN_TOR_SOURCE_SHA256': '', 'HOMEVPN_ENDPOINT': ''}))
        rows = [['ordered-entry', 'wg', 'router-vpn', policy, 'on', False],
                ['direct-tor', 'shadowsocks', 'router-vpn', policy, 'on', False]]
        raw = json.dumps(rows, separators=(',', ':'), ensure_ascii=True)
        digest = hashlib.sha256(('routervpn-ordered-protection-members-v1\n'+raw).encode()).hexdigest()
        return dict(schema=3, family=family, profile_id='direct-tor',
                    session_id='c'*32, source_sha256='d'*64, config_sha256='e'*64,
                    home_lan_access=False, policy=policy, members_json=raw, members_sha256=digest)


    def test_socks_node_chain_uses_exact_family_through_native_retirement(self):
        for policy in ('on-connect', 'always'):
            with self.subTest(policy=policy):
                capture = self.node_chain_capture(policy, 'ordered-node-chain-socks-v1')
                active = D.darwin_node_chain('apply', dict(capture=capture, expected=None))
                self.assertEqual(active['capture'], capture)
                state = self.saved()
                self.assertEqual(state['native_socket_family'], capture['family'])
                self.assertEqual(state['native_node_chain_capture'], capture)
                self.assertEqual(state['endpoint_ips'], [])
                self.assertNotIn('native_external_capture', state)
                self.assertNotIn('native_candidate_prefix_capture', state)
                self.assertNotIn('pass out quick', self.rules[P.OWNED_PF_ANCHOR])
                self.assertEqual(D.darwin_node_chain('current', dict(capture=capture, expected=active)), active)
                held = D.darwin_node_chain('retire', dict(capture=capture, expected=active))
                self.assertEqual(held['capture'], capture)
                self.assertTrue(held['baseline']['present'])
                self.assertEqual(held['pf_token'], active['pf_token'])
                self.assertEqual(self.saved()['native_socket_family'], capture['family'])
                retired = D.darwin_node_chain('release', dict(capture=capture, expected=held))
                self.assertEqual(retired['capture'], capture)
                self.assertEqual(retired['baseline']['present'], policy == 'always')
                self.assertEqual(D.darwin_node_chain('release', dict(capture=capture, expected=retired)), retired)
        self.watcher.assert_not_called()
        self.resolver.assert_not_called()

    def test_socks_node_chain_cross_family_receipts_never_adopt_original_owner(self):
        for family, other in (('ordered-node-chain-v1', 'ordered-node-chain-socks-v1'),
                              ('ordered-node-chain-socks-v1', 'ordered-node-chain-v1')):
            with self.subTest(family=family):
                capture = self.node_chain_capture('on-connect', family)
                active = D.darwin_node_chain('apply', dict(capture=capture, expected=None))
                foreign = dict(capture, family=other)
                before, commands = self.saved(), list(self.commands)
                for action in ('apply', 'current', 'retire', 'release'):
                    with self.subTest(action=action), self.assertRaises(RuntimeError):
                        D.darwin_node_chain(action, dict(capture=foreign, expected=active))
                    self.assertEqual(self.saved(), before)
                    self.assertEqual(self.commands, commands)
                for action in ('current', 'retire', 'release'):
                    with self.subTest(action=action), self.assertRaises(RuntimeError):
                        D.darwin_node_chain(action, dict(capture=foreign, expected=None))
                    self.assertEqual(self.saved(), before)
                    self.assertEqual(self.commands, commands)
                D.darwin_node_chain('release', dict(capture=capture, expected=active))

    def test_socks_node_chain_journal_family_drift_refuses_reassert_and_cleanup(self):
        capture = self.node_chain_capture('always', 'ordered-node-chain-socks-v1')
        active = D.darwin_node_chain('apply', dict(capture=capture, expected=None))
        state, commands = self.saved(), list(self.commands)
        for changed in (dict(state, native_socket_family='ordered-node-chain-v1'),
                        dict(state, native_node_chain_capture=dict(capture, family='ordered-node-chain-v1')),
                        dict(state, native_candidate_prefix_capture=capture)):
            self.private_json(self.root/'run/kill-switch.json', changed)
            for action in ('current', 'retire', 'release'):
                with self.subTest(action=action), self.assertRaises(RuntimeError):
                    D.darwin_node_chain(action, dict(capture=capture, expected=active))
                self.assertEqual(self.saved(), changed)
                self.assertEqual(self.commands, commands)
            with self.assertRaises(RuntimeError):
                D.darwin_reassert()
            self.assertEqual(self.saved(), changed)
            self.assertEqual(self.commands, commands)
        self.private_json(self.root/'run/kill-switch.json', state)
        self.assertEqual(D.darwin_reassert(), 0)
        self.assertEqual(self.saved()['native_socket_family'], capture['family'])
        self.assertEqual(self.saved()['native_node_chain_capture'], capture)
        self.assertEqual(self.saved()[P._baseline.STATE_KEY]['request']['session_id'], '')

    def test_socks_node_chain_failed_apply_retains_exact_family_cleanup(self):
        capture = self.node_chain_capture('on-connect', 'ordered-node-chain-socks-v1')
        self.fail_after_load = True
        with self.assertRaisesRegex(RuntimeError, 'ambiguous applied'):
            D.darwin_node_chain('apply', dict(capture=capture, expected=None))
        state = self.saved()
        self.assertEqual(state['native_socket_family'], capture['family'])
        self.assertEqual(state['native_node_chain_capture'], capture)
        self.assertTrue(state['darwin_transition_pending'])
        self.assertFalse(state[P._baseline.STATE_KEY]['complete'])
        self.assertNotIn(['-X', '417'], self.commands)
        self.fail_after_load = False
        with self.assertRaises(RuntimeError):
            D.darwin_node_chain('release', dict(capture=dict(capture, family='ordered-node-chain-v1'), expected=None))
        retired = D.darwin_node_chain('release', dict(capture=capture, expected=None))
        self.assertFalse(retired['baseline']['present'])
        self.assertEqual(self.references, {'999'})

    def test_connect_node_chain_uses_exact_family_through_native_retirement(self):
        for policy in ('on-connect', 'always'):
            with self.subTest(policy=policy):
                capture = self.node_chain_capture(policy, 'ordered-node-chain-connect-v1')
                active = D.darwin_node_chain('apply', dict(capture=capture, expected=None))
                self.assertEqual(active['capture'], capture)
                state = self.saved()
                self.assertEqual(state['native_socket_family'], capture['family'])
                self.assertEqual(state['native_node_chain_capture'], capture)
                self.assertEqual(state['endpoint_ips'], [])
                self.assertNotIn('native_external_capture', state)
                self.assertNotIn('native_candidate_prefix_capture', state)
                self.assertNotIn('pass out quick', self.rules[P.OWNED_PF_ANCHOR])
                self.assertEqual(D.darwin_node_chain('current', dict(capture=capture, expected=active)), active)
                held = D.darwin_node_chain('retire', dict(capture=capture, expected=active))
                self.assertEqual(held['capture'], capture)
                self.assertTrue(held['baseline']['present'])
                self.assertEqual(held['pf_token'], active['pf_token'])
                self.assertEqual(self.saved()['native_socket_family'], capture['family'])
                retired = D.darwin_node_chain('release', dict(capture=capture, expected=held))
                self.assertEqual(retired['capture'], capture)
                self.assertEqual(retired['baseline']['present'], policy == 'always')
                self.assertEqual(D.darwin_node_chain('release', dict(capture=capture, expected=retired)), retired)
        self.watcher.assert_not_called()
        self.resolver.assert_not_called()

    def test_connect_node_chain_cross_family_receipts_never_adopt_original_owner(self):
        for family, other in (('ordered-node-chain-v1', 'ordered-node-chain-connect-v1'),
                              ('ordered-node-chain-connect-v1', 'ordered-node-chain-v1'),
                              ('ordered-node-chain-socks-v1', 'ordered-node-chain-connect-v1'),
                              ('ordered-node-chain-connect-v1', 'ordered-node-chain-socks-v1')):
            with self.subTest(family=family):
                capture = self.node_chain_capture('on-connect', family)
                active = D.darwin_node_chain('apply', dict(capture=capture, expected=None))
                foreign = dict(capture, family=other)
                before, commands = self.saved(), list(self.commands)
                for action in ('apply', 'current', 'retire', 'release'):
                    with self.subTest(action=action), self.assertRaises(RuntimeError):
                        D.darwin_node_chain(action, dict(capture=foreign, expected=active))
                    self.assertEqual(self.saved(), before)
                    self.assertEqual(self.commands, commands)
                for action in ('current', 'retire', 'release'):
                    with self.subTest(action=action), self.assertRaises(RuntimeError):
                        D.darwin_node_chain(action, dict(capture=foreign, expected=None))
                    self.assertEqual(self.saved(), before)
                    self.assertEqual(self.commands, commands)
                D.darwin_node_chain('release', dict(capture=capture, expected=active))

    def test_connect_node_chain_journal_family_drift_refuses_reassert_and_cleanup(self):
        capture = self.node_chain_capture('always', 'ordered-node-chain-connect-v1')
        active = D.darwin_node_chain('apply', dict(capture=capture, expected=None))
        state, commands = self.saved(), list(self.commands)
        for changed in (dict(state, native_socket_family='ordered-node-chain-v1'),
                        dict(state, native_node_chain_capture=dict(capture, family='ordered-node-chain-v1')),
                        dict(state, native_candidate_prefix_capture=capture)):
            self.private_json(self.root/'run/kill-switch.json', changed)
            for action in ('current', 'retire', 'release'):
                with self.subTest(action=action), self.assertRaises(RuntimeError):
                    D.darwin_node_chain(action, dict(capture=capture, expected=active))
                self.assertEqual(self.saved(), changed)
                self.assertEqual(self.commands, commands)
            with self.assertRaises(RuntimeError):
                D.darwin_reassert()
            self.assertEqual(self.saved(), changed)
            self.assertEqual(self.commands, commands)
        self.private_json(self.root/'run/kill-switch.json', state)
        self.assertEqual(D.darwin_reassert(), 0)
        self.assertEqual(self.saved()['native_socket_family'], capture['family'])
        self.assertEqual(self.saved()['native_node_chain_capture'], capture)
        self.assertEqual(self.saved()[P._baseline.STATE_KEY]['request']['session_id'], '')

    def test_connect_node_chain_failed_apply_retains_exact_family_cleanup(self):
        capture = self.node_chain_capture('on-connect', 'ordered-node-chain-connect-v1')
        self.fail_after_load = True
        with self.assertRaisesRegex(RuntimeError, 'ambiguous applied'):
            D.darwin_node_chain('apply', dict(capture=capture, expected=None))
        state = self.saved()
        self.assertEqual(state['native_socket_family'], capture['family'])
        self.assertEqual(state['native_node_chain_capture'], capture)
        self.assertTrue(state['darwin_transition_pending'])
        self.assertFalse(state[P._baseline.STATE_KEY]['complete'])
        self.assertNotIn(['-X', '417'], self.commands)
        self.fail_after_load = False
        with self.assertRaises(RuntimeError):
            D.darwin_node_chain('release', dict(capture=dict(capture, family='ordered-node-chain-v1'), expected=None))
        retired = D.darwin_node_chain('release', dict(capture=capture, expected=None))
        self.assertFalse(retired['baseline']['present'])
        self.assertEqual(self.references, {'999'})

    def test_execution_node_chain_uses_exact_family_through_native_retirement(self):
        for policy in ('on-connect', 'always'):
            with self.subTest(policy=policy):
                capture = self.node_chain_capture(policy, 'ordered-node-chain-execution-v1')
                active = D.darwin_node_chain('apply', dict(capture=capture, expected=None))
                self.assertEqual(active['capture'], capture)
                state = self.saved()
                self.assertEqual(state['native_socket_family'], capture['family'])
                self.assertEqual(state['native_node_chain_capture'], capture)
                self.assertEqual(state['endpoint_ips'], [])
                self.assertNotIn('native_external_capture', state)
                self.assertNotIn('native_candidate_prefix_capture', state)
                self.assertNotIn('pass out quick', self.rules[P.OWNED_PF_ANCHOR])
                self.assertEqual(D.darwin_node_chain('current', dict(capture=capture, expected=active)), active)
                held = D.darwin_node_chain('retire', dict(capture=capture, expected=active))
                self.assertEqual(held['capture'], capture)
                self.assertTrue(held['baseline']['present'])
                self.assertEqual(held['pf_token'], active['pf_token'])
                self.assertEqual(self.saved()['native_socket_family'], capture['family'])
                retired = D.darwin_node_chain('release', dict(capture=capture, expected=held))
                self.assertEqual(retired['capture'], capture)
                self.assertEqual(retired['baseline']['present'], policy == 'always')
                self.assertEqual(D.darwin_node_chain('release', dict(capture=capture, expected=retired)), retired)
        self.watcher.assert_not_called()
        self.resolver.assert_not_called()

    def test_execution_node_chain_cross_family_receipts_never_adopt_original_owner(self):
        for family, other in (('ordered-node-chain-v1', 'ordered-node-chain-execution-v1'),
                              ('ordered-node-chain-execution-v1', 'ordered-node-chain-v1'),
                              ('ordered-node-chain-socks-v1', 'ordered-node-chain-execution-v1'),
                              ('ordered-node-chain-execution-v1', 'ordered-node-chain-socks-v1'),
                              ('ordered-node-chain-connect-v1', 'ordered-node-chain-execution-v1'),
                              ('ordered-node-chain-execution-v1', 'ordered-node-chain-connect-v1')):
            with self.subTest(family=family):
                capture = self.node_chain_capture('on-connect', family)
                active = D.darwin_node_chain('apply', dict(capture=capture, expected=None))
                foreign = dict(capture, family=other)
                before, commands = self.saved(), list(self.commands)
                for action in ('apply', 'current', 'retire', 'release'):
                    with self.subTest(action=action), self.assertRaises(RuntimeError):
                        D.darwin_node_chain(action, dict(capture=foreign, expected=active))
                    self.assertEqual(self.saved(), before)
                    self.assertEqual(self.commands, commands)
                for action in ('current', 'retire', 'release'):
                    with self.subTest(action=action), self.assertRaises(RuntimeError):
                        D.darwin_node_chain(action, dict(capture=foreign, expected=None))
                    self.assertEqual(self.saved(), before)
                    self.assertEqual(self.commands, commands)
                D.darwin_node_chain('release', dict(capture=capture, expected=active))

    def test_execution_node_chain_journal_family_drift_refuses_reassert_and_cleanup(self):
        capture = self.node_chain_capture('always', 'ordered-node-chain-execution-v1')
        active = D.darwin_node_chain('apply', dict(capture=capture, expected=None))
        state, commands = self.saved(), list(self.commands)
        for changed in (dict(state, native_socket_family='ordered-node-chain-v1'),
                        dict(state, native_node_chain_capture=dict(capture, family='ordered-node-chain-v1')),
                        dict(state, native_candidate_prefix_capture=capture)):
            self.private_json(self.root/'run/kill-switch.json', changed)
            for action in ('current', 'retire', 'release'):
                with self.subTest(action=action), self.assertRaises(RuntimeError):
                    D.darwin_node_chain(action, dict(capture=capture, expected=active))
                self.assertEqual(self.saved(), changed)
                self.assertEqual(self.commands, commands)
            with self.assertRaises(RuntimeError):
                D.darwin_reassert()
            self.assertEqual(self.saved(), changed)
            self.assertEqual(self.commands, commands)
        self.private_json(self.root/'run/kill-switch.json', state)
        self.assertEqual(D.darwin_reassert(), 0)
        self.assertEqual(self.saved()['native_socket_family'], capture['family'])
        self.assertEqual(self.saved()['native_node_chain_capture'], capture)
        self.assertEqual(self.saved()[P._baseline.STATE_KEY]['request']['session_id'], '')

    def test_execution_node_chain_failed_apply_retains_exact_family_cleanup(self):
        capture = self.node_chain_capture('on-connect', 'ordered-node-chain-execution-v1')
        self.fail_after_load = True
        with self.assertRaisesRegex(RuntimeError, 'ambiguous applied'):
            D.darwin_node_chain('apply', dict(capture=capture, expected=None))
        state = self.saved()
        self.assertEqual(state['native_socket_family'], capture['family'])
        self.assertEqual(state['native_node_chain_capture'], capture)
        self.assertTrue(state['darwin_transition_pending'])
        self.assertFalse(state[P._baseline.STATE_KEY]['complete'])
        self.assertNotIn(['-X', '417'], self.commands)
        self.fail_after_load = False
        with self.assertRaises(RuntimeError):
            D.darwin_node_chain('release', dict(capture=dict(capture, family='ordered-node-chain-v1'), expected=None))
        retired = D.darwin_node_chain('release', dict(capture=capture, expected=None))
        self.assertFalse(retired['baseline']['present'])
        self.assertEqual(self.references, {'999'})

    def test_execution_node_chain_held_baseline_passes_only_to_fresh_capture(self):
        original = self.node_chain_capture('on-connect', 'ordered-node-chain-execution-v1')
        active = D.darwin_node_chain('apply', dict(capture=original, expected=None))
        transition_start = len(self.native_calls)
        held = D.darwin_node_chain('retire', dict(capture=original, expected=active))
        self.assertTrue(held['baseline']['present'])
        self.assertNotIn(['-X', held['pf_token']], self.commands)
        successor = dict(original, session_id='d'*32, config_sha256='e'*64)
        fresh = D.darwin_node_chain('apply', dict(capture=successor, expected=None))
        self.assertEqual(fresh['capture'], successor)
        self.assertEqual(D.darwin_node_chain('current', dict(capture=successor, expected=fresh)), fresh)
        self.assertTrue(fresh['baseline']['present'])
        transitions = self.native_calls[transition_start:]
        self.assertTrue(transitions)
        self.assertTrue(all(request['action'] == 'replace' for _, request in transitions))
        self.assertNotIn(['-a', P.OWNED_PF_ANCHOR, '-F', 'rules'], self.commands)
        self.assertNotIn('pass out quick', self.rules[P.OWNED_PF_ANCHOR])
        before, commands = self.saved(), list(self.commands)
        for action in ('current', 'retire', 'release'):
            with self.subTest(action=action), self.assertRaises(RuntimeError):
                D.darwin_node_chain(action, dict(capture=original, expected=held))
            self.assertEqual(self.saved(), before)
            self.assertEqual(self.commands, commands)
        retired = D.darwin_node_chain('release', dict(capture=successor, expected=fresh))
        self.assertFalse(retired['baseline']['present'])
        self.assertEqual(self.references, {'999'})

    def test_connect_node_chain_aliases_refuse_before_native_mutation(self):
        capture = self.node_chain_capture('on-connect', 'ordered-node-chain-connect-v1')
        for family in ('ordered-node-chain-connect', 'ordered-node-chain-connect-v2',
                       'Ordered-node-chain-connect-v1', ' ordered-node-chain-connect-v1',
                       'ordered-node-chain-connect-v1 ', 'ordered-node-chain-connect-v1\0',
                       'node-candidate-prefix-v1', 'ordered-node-chain-execution-v2', ''):
            with self.subTest(family=family), self.assertRaises(RuntimeError):
                D.darwin_node_chain('apply', dict(capture=dict(capture, family=family), expected=None))
            self.assertEqual(self.commands, [])
            self.assertEqual(D._linux.read_state(self.root), {})

    def test_node_chain_openvpn_middle_keeps_original_policy_rows(self):
        import copy
        capture = self.node_chain_capture('off')
        middle = dict(id='ordered-openvpn', node_kind='external', endpoint='203.0.113.20',
                      external={'protocol': 'openvpn'}, kill_switch_policy='always',
                      ipv6_mode='on', home_lan_access=False)
        self.store['profiles'].append(middle)
        self.private_json(self.root/'routers.json', self.store)
        rows = json.loads(capture['members_json'])
        rows.insert(1, ['ordered-openvpn', 'openvpn', 'external', 'always', 'on', False])
        raw = json.dumps(rows, separators=(',', ':'), ensure_ascii=True)
        capture.update(policy='always', members_json=raw,
                       members_sha256=hashlib.sha256(('routervpn-ordered-protection-members-v1\n'+raw).encode()).hexdigest())
        try:
            active = D.darwin_node_chain('apply', dict(capture=capture, expected=None))
        except RuntimeError as error:
            self.fail('ordered OpenVPN middle lost original policy binding: '+str(error))
        self.assertEqual(self.saved()['policy'], 'always')
        self.assertEqual(active['capture'], capture)
        held = D.darwin_node_chain('retire', dict(capture=capture, expected=active))
        self.assertTrue(held['baseline']['present'])
        D.darwin_node_chain('release', dict(capture=capture, expected=held))
        for fault in ('first', 'final', 'four-members', 'paired', 'protocol', 'policy'):
            changed = copy.deepcopy(capture)
            mutated = copy.deepcopy(rows)
            if fault == 'first': mutated[0], mutated[1] = mutated[1], mutated[0]
            elif fault == 'final': mutated[1], mutated[2] = mutated[2], mutated[1]
            elif fault == 'four-members': mutated.insert(2, ['extra', 'wg', 'router-vpn', 'off', 'on', False])
            elif fault == 'paired': mutated[1][2] = 'router-vpn'
            elif fault == 'protocol': middle['external']['protocol'] = 'shadowsocks'
            elif fault == 'policy': middle['kill_switch_policy'] = 'off'
            self.private_json(self.root/'routers.json', self.store)
            changed['members_json'] = json.dumps(mutated, separators=(',', ':'), ensure_ascii=True)
            changed['members_sha256'] = hashlib.sha256(('routervpn-ordered-protection-members-v1\n'+changed['members_json']).encode()).hexdigest()
            before = list(self.commands)
            with self.subTest(fault=fault), self.assertRaises(RuntimeError):
                D.darwin_node_chain('apply', dict(capture=changed, expected=None))
            self.assertEqual(self.commands, before)
            middle['external']['protocol'], middle['kill_switch_policy'] = 'openvpn', 'always'

    def connect_prefix_capture(self, count, protocol='https-connect'):
        capture = self.node_chain_capture('off', 'ordered-node-chain-connect-v1')
        members, rows = [], []
        for position in range(count):
            member = dict(id='connect-prefix-'+str(position), node_kind='router-vpn',
                          kill_switch_policy='on-connect' if position == count-1 else 'off',
                          ipv6_mode='off' if position % 2 else 'on', home_lan_access=position % 2 == 0)
            members.append(member)
            rows.append([member['id'], ('wg', 'awg2-fast', 'awg2-strong')[position % 3],
                         'router-vpn', member['kill_switch_policy'], member['ipv6_mode'], member['home_lan_access']])
        middle = dict(id='captured-connect', node_kind='external', external={'protocol': protocol},
                      kill_switch_policy='off', ipv6_mode='on', home_lan_access=False)
        rows.extend([[middle['id'], protocol, 'external', 'off', 'on', False],
                     [self.selected['id'], 'shadowsocks', 'router-vpn', 'off', 'on', False]])
        self.store['profiles'] = [self.selected, *members, middle]
        self.private_json(self.root/'routers.json', self.store)
        raw = json.dumps(rows, separators=(',', ':'), ensure_ascii=True)
        capture.update(policy='on-connect', members_json=raw,
                       members_sha256=hashlib.sha256(('routervpn-ordered-protection-members-v1\n'+raw).encode()).hexdigest())
        return capture, rows

    def test_connect_complete_prefix_keeps_original_member_baseline(self):
        # This exercises the actual dispatcher and saved-store reconstruction.
        # Only the PF/kernel backend is the explicit fixture used by this suite.
        for count in range(1, 7):
            for protocol in ('http-connect', 'https-connect'):
                with self.subTest(prefixes=count, protocol=protocol):
                    capture, rows = self.connect_prefix_capture(count, protocol)
                    try:
                        active = D.darwin_node_chain('apply', dict(capture=capture, expected=None))
                    except RuntimeError as error:
                        self.fail('CONNECT prefix lost its original saved member baseline: '+str(error))
                    self.assertEqual(D._darwin_node_chain_rows(capture), rows)
                    self.assertEqual(active['capture'], capture)
                    state = self.saved()
                    self.assertEqual(state['native_node_chain_capture'], capture)
                    self.assertEqual(state['policy'], 'on-connect')
                    self.assertFalse(state['home_lan_access'])
                    self.assertEqual(state['endpoint_ips'], [])
                    self.assertNotIn('pass out quick', self.rules[P.OWNED_PF_ANCHOR])
                    self.assertEqual(D.darwin_node_chain('current', dict(capture=capture, expected=active)), active)
                    held = D.darwin_node_chain('retire', dict(capture=capture, expected=active))
                    self.assertTrue(held['baseline']['present'])
                    retired = D.darwin_node_chain('release', dict(capture=capture, expected=held))
                    self.assertFalse(retired['baseline']['present'])
                    self.assertEqual(self.references, {'999'})

    def execution_imported_capture(self, protocol, mode='wg', count=3):
        capture, rows = self.connect_prefix_capture(count-2, protocol)
        capture['family'] = 'ordered-node-chain-execution-v1'
        for row in rows[:-2]:
            row[1] = mode
        # A strongest middle policy must survive a final profile set to Off.
        middle = next(profile for profile in self.store['profiles'] if profile['id'] == rows[-2][0])
        middle['kill_switch_policy'] = rows[-2][3] = 'always'
        self.private_json(self.root/'routers.json', self.store)
        raw = json.dumps(rows, separators=(',', ':'), ensure_ascii=True)
        capture.update(policy='always', members_json=raw,
                       members_sha256=hashlib.sha256(('routervpn-ordered-protection-members-v1\n'+raw).encode()).hexdigest())
        return capture, rows

    def test_execution_imported_paths_keep_original_saved_member_baseline(self):
        # Actual capture, saved-profile reconstruction and journal lifecycle;
        # the existing PF/kernel double is not installed native acceptance.
        for protocol, count in ((protocol, count)
                                for protocol in ('shadowsocks', 'http-connect', 'https-connect')
                                for count in (3, 4, 8)):
            for mode in ('wg', 'awg2-fast', 'awg2-strong'):
                with self.subTest(protocol=protocol, mode=mode, count=count):
                    capture, rows = self.execution_imported_capture(protocol, mode, count)
                    try:
                        active = D.darwin_node_chain('apply', dict(capture=capture, expected=None))
                    except RuntimeError as error:
                        self.fail('execution imported path lost original saved member baseline: '+str(error))
                    self.assertEqual(D._darwin_node_chain_capture(capture), capture)
                    self.assertEqual(D._darwin_node_chain_rows(capture), rows)
                    self.assertEqual(active['capture'], capture)
                    state = self.saved()
                    self.assertEqual(state['native_node_chain_capture'], capture)
                    self.assertEqual(state['policy'], 'always')
                    self.assertFalse(state['home_lan_access'])
                    self.assertEqual(state['endpoint_ips'], [])
                    self.assertNotIn('pass out quick', self.rules[P.OWNED_PF_ANCHOR])
                    self.assertEqual(D.darwin_node_chain('current', dict(capture=capture, expected=active)), active)
                    held = D.darwin_node_chain('retire', dict(capture=capture, expected=active))
                    self.assertTrue(held['baseline']['present'])
                    retired = D.darwin_node_chain('release', dict(capture=capture, expected=held))
                    self.assertTrue(retired['baseline']['present'])
                    self.assertEqual(retired['capture'], capture)
                    self.assertEqual(self.references, {'999', '417'})
                    self.assertEqual(D.darwin_node_chain('release', dict(capture=capture, expected=retired)), retired)
                    self.assertNotIn('pass out quick', self.rules[P.OWNED_PF_ANCHOR])

    def test_execution_connect_complete_prefix_cannot_borrow_local_receipt(self):
        import copy
        for protocol in ('http-connect', 'https-connect'):
            for count in (4, 8):
                with self.subTest(protocol=protocol, count=count):
                    capture, _ = self.execution_imported_capture(protocol, count=count)
                    active = D.darwin_node_chain('apply', dict(capture=capture, expected=None))
                    local = dict(capture, family='ordered-node-chain-connect-v1')
                    # Both families now have valid complete-prefix shapes. Their
                    # retained journal and receipt authority remain distinct.
                    self.assertEqual(D._darwin_node_chain_capture(local), local)
                    before_commands, before_state = list(self.commands), copy.deepcopy(self.saved())
                    for action in ('current', 'retire', 'release'):
                        for expected in (None, active):
                            with self.subTest(action=action, receipt=expected is not None), self.assertRaises(RuntimeError):
                                D.darwin_node_chain(action, dict(capture=local, expected=expected))
                            self.assertEqual(self.commands, before_commands)
                            self.assertEqual(self.saved(), before_state)
                    held = D.darwin_node_chain('retire', dict(capture=capture, expected=active))
                    retired = D.darwin_node_chain('release', dict(capture=capture, expected=held))
                    self.assertTrue(retired['baseline']['present'])
                    self.assertEqual(retired['capture'], capture)
                    self.assertNotIn('pass out quick', self.rules[P.OWNED_PF_ANCHOR])

    def test_execution_imported_rows_keep_original_family_and_capture(self):
        import copy
        for protocol in ('shadowsocks', 'http-connect', 'https-connect'):
            capture, rows = self.execution_imported_capture(protocol)
            for fault in ('two', 'four', 'eight', 'middle-first', 'middle-final', 'second-external',
                          'wrong-prefix', 'wrong-final', 'paired-middle', 'socks', 'openvpn',
                          'duplicate-id', 'digest', 'canonical', 'control', 'aggregate-policy', 'aggregate-lan'):
                changed, modified = copy.deepcopy(capture), copy.deepcopy(rows)
                if fault == 'two': modified.pop(0)
                elif fault in ('four', 'eight'):
                    for index in range(1 if fault == 'four' else 5):
                        extra = list(modified[0]); extra[0] = 'extra-'+str(index); modified.insert(0, extra)
                elif fault == 'middle-first': modified[0], modified[1] = modified[1], modified[0]
                elif fault == 'middle-final': modified[1], modified[2] = modified[2], modified[1]
                elif fault == 'second-external': modified[0][1:3] = [protocol, 'external']
                elif fault == 'wrong-prefix': modified[0][1] = 'hysteria2'
                elif fault == 'wrong-final': modified[-1][1] = 'hysteria2'
                elif fault == 'paired-middle': modified[1][2] = 'router-vpn'
                elif fault in ('socks', 'openvpn'): modified[1][1] = 'socks5' if fault == 'socks' else 'openvpn'
                elif fault == 'duplicate-id': modified[1][0] = modified[0][0]
                elif fault == 'control': changed['profile_id'] = 'foreign-control'
                elif fault == 'aggregate-policy': changed['policy'] = 'off'
                elif fault == 'aggregate-lan': changed['home_lan_access'] = True
                raw = json.dumps(modified, separators=(',', ':'), ensure_ascii=True)
                if fault == 'canonical': raw += ' '
                changed.update(members_json=raw,
                               members_sha256=hashlib.sha256(('routervpn-ordered-protection-members-v1\n'+raw).encode()).hexdigest())
                if fault == 'digest': changed['members_sha256'] = 'f'*64
                before = list(self.commands)
                with self.subTest(protocol=protocol, fault=fault), self.assertRaises(RuntimeError):
                    if fault in ('socks', 'four', 'eight'):
                        # The shape is supported, but a changed transport or
                        # invented prefix has no original saved-member authority.
                        D.darwin_node_chain('apply', dict(capture=changed, expected=None))
                    else:
                        D._darwin_node_chain_capture(changed)
                self.assertEqual(self.commands, before)

    def test_execution_imported_paths_check_every_original_saved_member(self):
        import copy
        for protocol, count in ((protocol, count)
                                for protocol in ('shadowsocks', 'http-connect', 'https-connect')
                                for count in (3, 4, 8)):
            capture, rows = self.execution_imported_capture(protocol, count=count)
            original = copy.deepcopy(self.store)
            for row in rows:
                faults = ('missing', 'duplicate', 'policy', 'lan', 'ipv6', 'kind')
                if row[2] == 'external': faults += ('protocol',)
                for fault in faults:
                    changed = copy.deepcopy(original)
                    member = next(value for value in changed['profiles'] if value['id'] == row[0])
                    if fault == 'missing': changed['profiles'].remove(member)
                    elif fault == 'duplicate': changed['profiles'].append(copy.deepcopy(member))
                    elif fault == 'policy': member['kill_switch_policy'] = 'off' if row[3] == 'always' else 'always'
                    elif fault == 'lan': member['home_lan_access'] = not row[5]
                    elif fault == 'ipv6': member['ipv6_mode'] = 'off' if row[4] == 'on' else 'on'
                    elif fault == 'kind': member['node_kind'] = 'router-vpn' if row[2] == 'external' else 'external'
                    elif fault == 'protocol': member['external']['protocol'] = 'socks5'
                    self.private_json(self.root/'routers.json', changed)
                    before = list(self.commands)
                    with self.subTest(protocol=protocol, count=count, member=row[0], fault=fault), self.assertRaises(RuntimeError):
                        D.darwin_node_chain('apply', dict(capture=capture, expected=None))
                    self.assertEqual(self.commands, before)
                    self.assertEqual(D._linux.read_state(self.root), {})
            self.private_json(self.root/'routers.json', original)

    def test_execution_socks_keeps_original_saved_member_baseline(self):
        # Actual capture, saved-profile reconstruction and journal lifecycle;
        # the existing PF/kernel double is not installed native acceptance.
        for protocol, count in (('socks5', count) for count in range(3, 9)):
            for mode in ('wg', 'awg2-fast', 'awg2-strong'):
                with self.subTest(protocol=protocol, mode=mode, count=count):
                    capture, rows = self.execution_imported_capture(protocol, mode, count)
                    try:
                        active = D.darwin_node_chain('apply', dict(capture=capture, expected=None))
                    except RuntimeError as error:
                        self.fail('SOCKS execution lost original saved member baseline: '+str(error))
                    self.assertEqual(D._darwin_node_chain_capture(capture), capture)
                    self.assertEqual(D._darwin_node_chain_rows(capture), rows)
                    self.assertEqual(active['capture'], capture)
                    state = self.saved()
                    self.assertEqual(state['native_node_chain_capture'], capture)
                    self.assertEqual(state['policy'], 'always')
                    self.assertFalse(state['home_lan_access'])
                    self.assertEqual(state['endpoint_ips'], [])
                    self.assertNotIn('pass out quick', self.rules[P.OWNED_PF_ANCHOR])
                    self.assertEqual(D.darwin_node_chain('current', dict(capture=capture, expected=active)), active)
                    held = D.darwin_node_chain('retire', dict(capture=capture, expected=active))
                    self.assertTrue(held['baseline']['present'])
                    retired = D.darwin_node_chain('release', dict(capture=capture, expected=held))
                    self.assertTrue(retired['baseline']['present'])
                    self.assertEqual(retired['capture'], capture)
                    self.assertEqual(self.references, {'999', '417'})
                    self.assertEqual(D.darwin_node_chain('release', dict(capture=capture, expected=retired)), retired)
                    self.assertNotIn('pass out quick', self.rules[P.OWNED_PF_ANCHOR])

    def test_execution_socks_complete_prefix_cannot_borrow_local_receipt(self):
        import copy
        for count in (4, 8):
            with self.subTest(count=count):
                capture, _ = self.execution_imported_capture('socks5', count=count)
                active = D.darwin_node_chain('apply', dict(capture=capture, expected=None))
                local = dict(capture, family='ordered-node-chain-socks-v1')
                self.assertEqual(D._darwin_node_chain_capture(local), local)
                before_commands, before_state = list(self.commands), copy.deepcopy(self.saved())
                for action in ('current', 'retire', 'release'):
                    for expected in (None, active):
                        with self.subTest(action=action, receipt=expected is not None), self.assertRaises(RuntimeError):
                            D.darwin_node_chain(action, dict(capture=local, expected=expected))
                        self.assertEqual(self.commands, before_commands)
                        self.assertEqual(self.saved(), before_state)
                held = D.darwin_node_chain('retire', dict(capture=capture, expected=active))
                retired = D.darwin_node_chain('release', dict(capture=capture, expected=held))
                self.assertTrue(retired['baseline']['present'])
                self.assertEqual(retired['capture'], capture)
                self.assertNotIn('pass out quick', self.rules[P.OWNED_PF_ANCHOR])

    def test_execution_socks_keeps_complete_prefix_and_original_rows(self):
        import copy
        capture, rows = self.execution_imported_capture('socks5')
        for fault in ('two', 'four', 'eight', 'nine', 'middle-first', 'middle-final', 'second-external',
                      'wrong-prefix', 'wrong-final', 'paired-middle', 'openvpn', 'duplicate-id',
                      'digest', 'canonical', 'control', 'aggregate-policy', 'aggregate-lan'):
            changed, modified = copy.deepcopy(capture), copy.deepcopy(rows)
            if fault == 'two': modified.pop(0)
            elif fault in ('four', 'eight', 'nine'):
                for index in range({'four': 1, 'eight': 5, 'nine': 6}[fault]):
                    extra = list(modified[0]); extra[0] = 'extra-'+str(index); modified.insert(0, extra)
            elif fault == 'middle-first': modified[0], modified[1] = modified[1], modified[0]
            elif fault == 'middle-final': modified[1], modified[2] = modified[2], modified[1]
            elif fault == 'second-external': modified[0][1:3] = ['socks5', 'external']
            elif fault == 'wrong-prefix': modified[0][1] = 'hysteria2'
            elif fault == 'wrong-final': modified[-1][1] = 'hysteria2'
            elif fault == 'paired-middle': modified[1][2] = 'router-vpn'
            elif fault == 'openvpn': modified[1][1] = 'openvpn'
            elif fault == 'duplicate-id': modified[1][0] = modified[0][0]
            elif fault == 'control': changed['profile_id'] = 'foreign-control'
            elif fault == 'aggregate-policy': changed['policy'] = 'off'
            elif fault == 'aggregate-lan': changed['home_lan_access'] = True
            raw = json.dumps(modified, separators=(',', ':'), ensure_ascii=True)
            if fault == 'canonical': raw += ' '
            changed.update(members_json=raw,
                           members_sha256=hashlib.sha256(('routervpn-ordered-protection-members-v1\n'+raw).encode()).hexdigest())
            if fault == 'digest': changed['members_sha256'] = 'f'*64
            before = list(self.commands)
            with self.subTest(fault=fault), self.assertRaises(RuntimeError, msg='SOCKS execution borrowed an unsupported shape or member capture'):
                if fault in ('four', 'eight'):
                    # A valid shape cannot invent saved paired-member authority.
                    D.darwin_node_chain('apply', dict(capture=changed, expected=None))
                else:
                    D._darwin_node_chain_capture(changed)
            self.assertEqual(self.commands, before)

    def test_execution_socks_checks_every_original_saved_member(self):
        import copy
        for protocol, count in (('socks5', count) for count in (3, 4, 8)):
            capture, rows = self.execution_imported_capture(protocol, count=count)
            original = copy.deepcopy(self.store)
            for row in rows:
                faults = ('missing', 'duplicate', 'policy', 'lan', 'ipv6', 'kind')
                if row[2] == 'external': faults += ('protocol',)
                for fault in faults:
                    changed = copy.deepcopy(original)
                    member = next(value for value in changed['profiles'] if value['id'] == row[0])
                    if fault == 'missing': changed['profiles'].remove(member)
                    elif fault == 'duplicate': changed['profiles'].append(copy.deepcopy(member))
                    elif fault == 'policy': member['kill_switch_policy'] = 'off' if row[3] == 'always' else 'always'
                    elif fault == 'lan': member['home_lan_access'] = not row[5]
                    elif fault == 'ipv6': member['ipv6_mode'] = 'off' if row[4] == 'on' else 'on'
                    elif fault == 'kind': member['node_kind'] = 'router-vpn' if row[2] == 'external' else 'external'
                    elif fault == 'protocol': member['external']['protocol'] = 'http-connect'
                    self.private_json(self.root/'routers.json', changed)
                    before = list(self.commands)
                    with self.subTest(protocol=protocol, count=count, member=row[0], fault=fault), self.assertRaises(RuntimeError, msg='SOCKS execution borrowed changed saved-member authority'):
                        D.darwin_node_chain('apply', dict(capture=capture, expected=None))
                    self.assertEqual(self.commands, before)
                    self.assertEqual(D._linux.read_state(self.root), {})
            self.private_json(self.root/'routers.json', original)

    def imported_prefix_capture(self, count, protocol):
        capture, rows = self.connect_prefix_capture(count-2, protocol)
        capture['family'] = ('ordered-node-chain-socks-v1' if protocol == 'socks5'
                             else 'ordered-node-chain-v1')
        return capture, rows

    def test_imported_complete_prefix_keeps_original_member_baseline(self):
        # Exercise the actual saved-store dispatcher and journal lifecycle.
        # The existing explicit PF backend remains the only native double.
        for protocol in ('socks5', 'openvpn', 'shadowsocks'):
            for count in (3, 4, 8):
                with self.subTest(protocol=protocol, count=count):
                    capture, rows = self.imported_prefix_capture(count, protocol)
                    try:
                        active = D.darwin_node_chain('apply', dict(capture=capture, expected=None))
                    except RuntimeError as error:
                        self.fail('imported prefix lost its original saved member baseline: '+str(error))
                    self.assertEqual(D._darwin_node_chain_rows(capture), rows)
                    self.assertEqual(active['capture'], capture)
                    state = self.saved()
                    self.assertEqual(state['native_node_chain_capture'], capture)
                    self.assertEqual(state['policy'], 'on-connect')
                    self.assertFalse(state['home_lan_access'])
                    self.assertEqual(state['endpoint_ips'], [])
                    self.assertNotIn('pass out quick', self.rules[P.OWNED_PF_ANCHOR])
                    self.assertEqual(D.darwin_node_chain('current', dict(capture=capture, expected=active)), active)
                    held = D.darwin_node_chain('retire', dict(capture=capture, expected=active))
                    self.assertTrue(held['baseline']['present'])
                    retired = D.darwin_node_chain('release', dict(capture=capture, expected=held))
                    self.assertFalse(retired['baseline']['present'])
                    self.assertEqual(self.references, {'999'})

    def test_imported_prefix_rows_preserve_exact_family_and_position(self):
        import copy
        for protocol in ('socks5', 'openvpn', 'shadowsocks'):
            capture, rows = self.imported_prefix_capture(8, protocol)
            for fault in ('too-short', 'too-long', 'wrong-position', 'second-external', 'wrong-prefix',
                          'wrong-final', 'wrong-family', 'unsupported-imported', 'duplicate-prefix',
                          'digest', 'canonical', 'control', 'aggregate-policy', 'aggregate-lan'):
                changed, modified = copy.deepcopy(capture), copy.deepcopy(rows)
                if fault == 'too-short': modified = modified[-2:]
                elif fault == 'too-long':
                    extra = list(modified[0]); extra[0] = 'another-prefix'; modified.insert(0, extra)
                elif fault == 'wrong-position': modified[0], modified[-2] = modified[-2], modified[0]
                elif fault == 'second-external':
                    modified[1] = list(modified[-2]); modified[1][0] = 'another-external'
                elif fault == 'wrong-prefix': modified[0][1] = 'hysteria2'
                elif fault == 'wrong-final': modified[-1][1] = 'hysteria2'
                elif fault == 'wrong-family':
                    changed['family'] = 'ordered-node-chain-connect-v1'
                elif fault == 'unsupported-imported':
                    changed['family'] = 'ordered-node-chain-v1'; modified[-2][1] = 'naive-h2'
                elif fault == 'duplicate-prefix': modified[1][0] = modified[0][0]
                elif fault == 'control': changed['profile_id'] = 'another-control'
                elif fault == 'aggregate-policy': changed['policy'] = 'always'
                elif fault == 'aggregate-lan': changed['home_lan_access'] = True
                raw = json.dumps(modified, separators=(',', ':'), ensure_ascii=True)
                if fault == 'canonical': raw += ' '
                changed.update(members_json=raw,
                               members_sha256=hashlib.sha256(('routervpn-ordered-protection-members-v1\n'+raw).encode()).hexdigest())
                if fault == 'digest': changed['members_sha256'] = 'f'*64
                added_local_member = protocol == 'shadowsocks' and fault in ('second-external', 'too-long')
                if added_local_member:
                    # Both shapes can describe a Local route. The added
                    # row has no matching captured member in the store.
                    self.assertEqual(D._darwin_node_chain_rows(changed), modified)
                with self.subTest(protocol=protocol, fault=fault), self.assertRaises(RuntimeError, msg='imported prefix borrowed another family, position or member capture'):
                    if added_local_member:
                        D.darwin_node_chain('apply', dict(capture=changed, expected=None))
                    else:
                        D._darwin_node_chain_capture(changed)
            self.assertEqual(self.commands, [])

    def test_extended_original_chain_baseline_and_source_bound_input(self):
        import copy
        for family, layout in (('ordered-node-chain-v1', 'paired'), ('ordered-node-chain-v1', 'import'), ('ordered-node-chain-v1', 'mixed'), ('ordered-node-chain-execution-v1', 'import')):
            for count in (9, 16, 96):
                with self.subTest(family=family, count=count):
                    capture = self.node_chain_capture('off', family)
                    rows = [['ordered-entry', 'wg', 'router-vpn', 'off', 'on', False]]
                    for position in range(1, count-1):
                        identifier = 'original-'+str(position)+'-'+'x'*40
                        member = dict(id=identifier, node_kind='external', external={'protocol':'shadowsocks'},
                                      start_layer='off', kill_switch_policy='off', ipv6_mode='on', home_lan_access=False)
                        self.store['profiles'] = [p for p in self.store['profiles'] if p.get('id') != identifier] + [member]
                        paired = layout == 'paired' or layout == 'mixed' and position < count//2
                        if paired:
                            member.update(node_kind='router-vpn')
                            del member['external']
                        mode = ('awg2-fast' if position % 2 else 'awg2-strong') if layout == 'mixed' and paired else 'wg' if paired else 'shadowsocks'
                        rows.append([identifier, mode, member['node_kind'], 'off', 'on', False])
                    rows.append(['direct-tor', 'shadowsocks', 'router-vpn', 'off', 'on', False])
                    raw = json.dumps(rows, separators=(',', ':'), ensure_ascii=True)
                    capture.update(members_json=raw, members_sha256=hashlib.sha256(('routervpn-ordered-protection-members-v1\n'+raw).encode()).hexdigest())
                    self.private_json(self.root/'routers.json', self.store)
                    self.assertEqual(D._darwin_node_chain_rows(capture), rows)
                    if count == 96:
                        extra = list(rows[-2]); extra[0] = 'beyond-traversal'
                        enlarged = json.dumps(rows[:-1] + [extra, rows[-1]], separators=(',', ':'), ensure_ascii=True)
                        foreign = dict(capture, members_json=enlarged, members_sha256=hashlib.sha256(('routervpn-ordered-protection-members-v1\n'+enlarged).encode()).hexdigest())
                        with self.assertRaises(RuntimeError, msg='97-member PF capture escaped the physical traversal limit'):
                            D._darwin_node_chain_capture(foreign)
                    active = D.darwin_node_chain('apply', dict(capture=capture, expected=None))
                    self.assertEqual(active['capture'], capture)
                    self.assertTrue(D._linux._darwin_isolated_native_state(self.saved()))
                    request = dict(capture=capture, expected=active)
                    encoded = json.dumps(request, separators=(',', ':')).encode('ascii')
                    with patch.object(D.sys, 'stdin', types.SimpleNamespace(buffer=io.BytesIO(encoded))):
                        self.assertEqual(D.darwin_external_input(), request)
                    self.assertEqual(D.darwin_node_chain('current', request), active)
                    held = D.darwin_node_chain('retire', request)
                    self.assertFalse(held['baseline']['present'])
                    retired = D.darwin_node_chain('release', dict(capture=capture, expected=held))
                    self.assertFalse(retired['baseline']['present'])
                    self.assertEqual(self.references, {'999'})
                    for position in (0, count//2, count-1):
                        changed = copy.deepcopy(capture)
                        changed_rows = copy.deepcopy(rows)
                        changed_rows[position][1] = 'hysteria2'
                        changed_raw = json.dumps(changed_rows, separators=(',', ':'), ensure_ascii=True)
                        changed.update(members_json=changed_raw, members_sha256=hashlib.sha256(('routervpn-ordered-protection-members-v1\n'+changed_raw).encode()).hexdigest())
                        with self.assertRaises(RuntimeError, msg='extended original boundary changed its qualified transport'):
                            D._darwin_node_chain_capture(changed)
                    if layout != 'import':
                        with self.assertRaises(RuntimeError):
                            D._darwin_node_chain_rows(dict(capture, family='ordered-node-chain-execution-v1'))
                    for position in (0, count//2, count-1):
                        changed = copy.deepcopy(self.store)
                        member = next(p for p in changed['profiles'] if p['id'] == rows[position][0])
                        member['start_layer'] = 'aes-256-gcm'
                        self.private_json(self.root/'routers.json', changed)
                        before = list(self.commands)
                        with self.assertRaises(RuntimeError, msg='extended original member borrowed an unsupported Start Layer'):
                            D.darwin_node_chain('apply', dict(capture=capture, expected=None))
                        self.assertEqual(self.commands, before)
                    self.private_json(self.root/'routers.json', self.store)

    def test_imported_prefix_checks_every_original_saved_member(self):
        import copy
        for protocol in ('socks5', 'openvpn', 'shadowsocks'):
            capture, rows = self.imported_prefix_capture(8, protocol)
            original = copy.deepcopy(self.store)
            for row in rows:
                for fault in ('missing', 'duplicate', 'policy', 'lan', 'ipv6', 'kind'):
                    changed = copy.deepcopy(original)
                    member = next(value for value in changed['profiles'] if value['id'] == row[0])
                    if fault == 'missing': changed['profiles'].remove(member)
                    elif fault == 'duplicate': changed['profiles'].append(copy.deepcopy(member))
                    elif fault == 'policy': member['kill_switch_policy'] = 'always'
                    elif fault == 'lan': member['home_lan_access'] = not row[5]
                    elif fault == 'ipv6': member['ipv6_mode'] = 'off' if row[4] == 'on' else 'on'
                    elif fault == 'kind': member['node_kind'] = 'router-vpn' if row[2] == 'external' else 'external'
                    self.private_json(self.root/'routers.json', changed)
                    before = list(self.commands)
                    with self.subTest(protocol=protocol, member=row[0], fault=fault), self.assertRaises(RuntimeError, msg='changed imported prefix member reached native mutation'):
                        D.darwin_node_chain('apply', dict(capture=capture, expected=None))
                    self.assertEqual(self.commands, before)
                    self.assertEqual(D._linux.read_state(self.root), {})
            self.private_json(self.root/'routers.json', original)

    def test_connect_prefix_rows_preserve_family_and_position_bounds(self):
        import copy
        capture, rows = self.connect_prefix_capture(6)
        for fault in ('too-short', 'too-long', 'wrong-position', 'second-external', 'wrong-prefix',
                      'wrong-final', 'ordinary-family', 'socks-family', 'unknown-execution-family',
                      'duplicate-prefix', 'digest', 'control'):
            changed, modified = copy.deepcopy(capture), copy.deepcopy(rows)
            if fault == 'too-short': modified = modified[-2:]
            elif fault == 'too-long':
                extra = list(modified[0]); extra[0] = 'another-prefix'; modified.insert(0, extra)
            elif fault == 'wrong-position': modified[0], modified[-2] = modified[-2], modified[0]
            elif fault == 'second-external':
                modified[1] = list(modified[-2]); modified[1][0] = 'another-external'
            elif fault == 'wrong-prefix': modified[0][1] = 'hysteria2'
            elif fault == 'wrong-final': modified[-1][1] = 'hysteria2'
            elif fault == 'ordinary-family':
                changed['family'] = 'ordered-node-chain-v1'  # Keep the original CONNECT transport.
            elif fault == 'socks-family':
                changed['family'] = 'ordered-node-chain-socks-v1'
            elif fault == 'unknown-execution-family': changed['family'] = 'ordered-node-chain-execution-copy-v1'
            elif fault == 'duplicate-prefix': modified[1][0] = modified[0][0]
            elif fault == 'control': changed['profile_id'] = 'another-control'
            raw = json.dumps(modified, separators=(',', ':'), ensure_ascii=True)
            changed.update(members_json=raw,
                           members_sha256=hashlib.sha256(('routervpn-ordered-protection-members-v1\n'+raw).encode()).hexdigest())
            if fault == 'digest': changed['members_sha256'] = 'f'*64
            with self.subTest(fault=fault), self.assertRaises(RuntimeError, msg='CONNECT prefix borrowed another family or position'):
                D._darwin_node_chain_capture(changed)
        self.assertEqual(self.commands, [])

    def test_connect_prefix_checks_every_original_saved_member(self):
        import copy
        capture, rows = self.connect_prefix_capture(6)
        original = copy.deepcopy(self.store)
        for position, row in enumerate(rows):
            for fault in ('missing', 'duplicate', 'policy', 'lan', 'ipv6', 'kind'):
                changed = copy.deepcopy(original)
                member = next(value for value in changed['profiles'] if value['id'] == row[0])
                if fault == 'missing': changed['profiles'].remove(member)
                elif fault == 'duplicate': changed['profiles'].append(copy.deepcopy(member))
                elif fault == 'policy': member['kill_switch_policy'] = 'always'
                elif fault == 'lan': member['home_lan_access'] = not row[5]
                elif fault == 'ipv6': member['ipv6_mode'] = 'off' if row[4] == 'on' else 'on'
                elif fault == 'kind': member['node_kind'] = 'router-vpn' if row[2] == 'external' else 'external'
                self.private_json(self.root/'routers.json', changed)
                before = list(self.commands)
                with self.subTest(position=position, fault=fault), self.assertRaises(RuntimeError, msg='changed CONNECT prefix member reached native mutation'):
                    D.darwin_node_chain('apply', dict(capture=capture, expected=None))
                self.assertEqual(self.commands, before)
                self.assertEqual(D._linux.read_state(self.root), {})
        self.private_json(self.root/'routers.json', original)

    def test_node_chain_original_members_preserve_strongest_policy(self):
        capture = self.node_chain_capture('off')
        rows = json.loads(capture['members_json'])
        rows[0][3] = 'always'
        self.store['profiles'][-1]['kill_switch_policy'] = 'always'
        # The explicit ordered draft remains independent of unrelated saved
        # pair references. The exact captured IDs supply this operation.
        self.selected['multihop_nodes'] = [{'id': 'unrelated', 'mode': 'wg'}]
        self.private_json(self.root/'routers.json', self.store)
        raw = json.dumps(rows, separators=(',', ':'), ensure_ascii=True)
        capture.update(policy='always', members_json=raw,
                       members_sha256=hashlib.sha256(('routervpn-ordered-protection-members-v1\n'+raw).encode()).hexdigest())
        try:
            active = D.darwin_node_chain('apply', dict(capture=capture, expected=None))
        except RuntimeError as error:
            self.fail('ordered original aggregate did not reach native baseline: '+str(error))
        self.assertEqual(self.saved()['policy'], 'always', 'ordered original aggregate did not reach native baseline')
        self.assertTrue(active['baseline']['present'])
        held = D.darwin_node_chain('retire', dict(capture=capture, expected=active))
        self.assertTrue(held['baseline']['present'])
        self.assertEqual(D.darwin_reassert(), 0)
        self.assertEqual(self.saved()['policy'], 'always')
        retired = D.darwin_node_chain('release', dict(capture=capture, expected=held))
        self.assertTrue(retired['baseline']['present'])

    def test_node_chain_member_changes_refused_before_mutation(self):
        import copy
        capture = self.node_chain_capture('always')
        original = copy.deepcopy(self.store)
        for fault in ('missing', 'duplicate', 'policy', 'lan', 'ipv6', 'kind', 'source-kind'):
            changed = copy.deepcopy(original)
            entry = changed['profiles'][-1]
            if fault == 'missing': changed['profiles'].pop()
            elif fault == 'duplicate': changed['profiles'].append(copy.deepcopy(entry))
            elif fault == 'policy': entry['kill_switch_policy'] = 'off'
            elif fault == 'lan': entry['home_lan_access'] = True
            elif fault == 'ipv6': entry['ipv6_mode'] = 'off'
            elif fault == 'kind': entry['node_kind'] = 'external'
            elif fault == 'source-kind': entry['external'] = {'protocol': 'shadowsocks'}
            self.private_json(self.root/'routers.json', changed)
            before = list(self.commands)
            with self.subTest(fault=fault), self.assertRaises(RuntimeError, msg='changed original ordered member reached native mutation'):
                D.darwin_node_chain('apply', dict(capture=capture, expected=None))
            self.assertEqual(self.commands, before)
        self.private_json(self.root/'routers.json', original)

    def test_node_chain_legacy_readback_retirement_reassert_without_fresh_admission(self):
        capture = self.node_chain_capture('always')
        active = D.darwin_node_chain('apply', dict(capture=capture, expected=None))
        legacy = {key: value for key, value in capture.items() if key not in ('members_json', 'members_sha256')}
        legacy['schema'] = 2
        state = self.saved()
        state['native_node_chain_capture'] = legacy
        self.private_json(self.root/'run/kill-switch.json', state)
        receipt = dict(active, schema=2, capture=legacy)
        self.assertEqual(D.darwin_node_chain('current', dict(capture=legacy, expected=receipt)), receipt)
        self.assertEqual(D.darwin_reassert(), 0)
        self.assertEqual(self.saved()['native_node_chain_capture'], legacy)
        before = list(self.commands)
        with self.assertRaises(RuntimeError):
            D.darwin_node_chain('apply', dict(capture=dict(legacy, source_sha256='f'*64), expected=None))
        self.assertEqual(self.commands, before)
        held = D.darwin_node_chain('retire', dict(capture=legacy, expected=receipt))
        self.assertTrue(held['baseline']['present'])
        self.assertTrue(D.darwin_node_chain('release', dict(capture=legacy, expected=held))['baseline']['present'])

    def test_node_chain_off_storage_rejects_changed_member_pin(self):
        import copy
        capture = self.node_chain_capture('off')
        D.darwin_node_chain('apply', dict(capture=capture, expected=None))
        original = self.saved()
        self.assertTrue(D._linux._darwin_isolated_native_state(original))
        for fault in ('missing', 'digest', 'policy', 'final', 'lan', 'duplicate'):
            state = copy.deepcopy(original)
            value = state['native_node_chain_capture']
            rows = json.loads(value['members_json'])
            if fault == 'missing': del value['members_json']
            elif fault == 'digest': value['members_sha256'] = 'f'*64
            else:
                if fault == 'policy': rows[0][3] = 'always'
                elif fault == 'final': rows[-1][0] = 'foreign'
                elif fault == 'lan': rows[0][5] = rows[-1][5] = True
                elif fault == 'duplicate': rows[0][0] = rows[-1][0]
                value['members_json'] = json.dumps(rows, separators=(',', ':'), ensure_ascii=True)
                value['members_sha256'] = hashlib.sha256(('routervpn-ordered-protection-members-v1\n'+value['members_json']).encode()).hexdigest()
            with self.subTest(fault=fault):
                self.assertFalse(D._linux._darwin_isolated_native_state(state))

    def test_node_chain_uses_original_journal_and_exact_retirement(self):
        for policy in ('on-connect', 'always'):
            with self.subTest(policy=policy):
                capture = self.node_chain_capture(policy)
                active = D.darwin_node_chain('apply', dict(capture=capture, expected=None))
                self.assertEqual(active['schema'], 3)
                self.assertEqual(active['capture'], capture)
                state = self.saved()
                self.assertEqual(state['native_socket_family'], 'ordered-node-chain-v1')
                self.assertEqual(state['native_node_chain_capture'], capture)
                self.assertNotIn('native_external_capture', state)
                self.assertEqual(state[P._baseline.STATE_KEY]['request']['session_id'], capture['session_id'])
                self.assertEqual(state[P._baseline.STATE_KEY]['request']['source_sha256'], capture['source_sha256'])
                self.assertEqual(state['endpoint_ips'], [])
                self.assertNotIn('pass out quick', self.rules[P.OWNED_PF_ANCHOR])
                self.assertEqual(D.darwin_node_chain('apply', dict(capture=capture, expected=None)), active)
                self.assertEqual(D.darwin_node_chain('current', dict(capture=capture, expected=active)), active)
                try:
                    held = D.darwin_node_chain('retire', dict(capture=capture, expected=active))
                except RuntimeError as error:
                    self.fail('ordered switch released its deny baseline: '+str(error))
                self.assertTrue(held['baseline']['present'], 'ordered switch released its deny baseline')
                self.assertEqual(held['phase'], 'held')
                self.assertEqual(held['pf_token'], active['pf_token'])
                self.assertEqual(self.saved()[P._baseline.STATE_KEY]['request']['session_id'], '')
                self.assertEqual(D.darwin_node_chain('retire', dict(capture=capture, expected=held)), held)
                retired = D.darwin_node_chain('release', dict(capture=capture, expected=held))
                self.assertEqual(retired['baseline']['present'], policy == 'always')
                self.assertEqual(retired['pf_token'], active['pf_token'])
                self.assertEqual(D.darwin_node_chain('release', dict(capture=capture, expected=retired)), retired)
                if policy == 'on-connect':
                    self.assertEqual(self.references, {'999'})
                else:
                    self.assertEqual(self.references, {active['pf_token'], '999'})
                    self.assertNotIn('anchor ', self.rules[P.OWNED_PF_ANCHOR])
        self.watcher.assert_not_called()
        self.resolver.assert_not_called()

    def test_node_chain_stale_source_or_reference_cannot_release(self):
        capture = self.node_chain_capture('on-connect')
        active = D.darwin_node_chain('apply', dict(capture=capture, expected=None))
        before, commands = self.saved(), list(self.commands)
        for field, other in (('session_id', 'f'*32), ('source_sha256', 'f'*64), ('config_sha256', 'f'*64),
                             ('home_lan_access', True), ('profile_id', 'foreign-profile'), ('policy', 'always')):
            with self.subTest(field=field), self.assertRaises(RuntimeError, msg='stale ordered capture retired another native owner'):
                D.darwin_node_chain('release', dict(capture={**capture, field: other}, expected=None))
            self.assertEqual(self.saved(), before)
            self.assertEqual(self.commands, commands)
        with self.assertRaisesRegex(RuntimeError, 'original PF reference', msg='ordered cleanup released another captured PF reference'):
            D.darwin_node_chain('release', dict(capture=capture, expected={**active, 'pf_token': '999'}))
        self.assertEqual(self.saved(), before)
        self.assertEqual(self.commands, commands)

    def test_node_chain_receipt_rejects_ordinary_and_ambiguous_families(self):
        capture = self.node_chain_capture()
        changed = [dict(capture, schema=1), dict(capture, family='external-v1'),
                   dict(capture, protocol='shadowsocks'), dict(capture, home_lan_access=0),
                   dict(capture, schema=True), dict(capture, family=None)]
        changed.append({key: value for key, value in capture.items() if key != 'family'})
        for value in changed:
            with self.subTest(capture=value), self.assertRaises(RuntimeError):
                D.darwin_node_chain('apply', dict(capture=value, expected=None))
        self.assertEqual(self.commands, [])
        active = D.darwin_node_chain('apply', dict(capture=capture, expected=None))
        with self.assertRaises(RuntimeError):
            D.darwin_external('release', dict(capture=capture, expected=active))
        state = self.saved()
        self.private_json(self.root/'run/kill-switch.json', {**state, 'native_external_capture': capture})
        with self.assertRaisesRegex(RuntimeError, 'another retained owner'):
            D.darwin_node_chain('release', dict(capture=capture, expected=active))

    def test_node_chain_saved_control_and_policy_are_checked_before_mutation(self):
        capture = self.node_chain_capture()
        active = D.darwin_node_chain('apply', dict(capture=capture, expected=None))
        before, commands = self.saved(), list(self.commands)
        for field, value in (('kill_switch_policy', 'off'), ('home_lan_access', True),
                             ('node_kind', 'external'), ('external', {'protocol': 'shadowsocks'})):
            previous = dict(self.selected)
            self.selected[field] = value
            self.private_json(self.root/'routers.json', self.store)
            with self.subTest(field=field), self.assertRaisesRegex(RuntimeError, 'captured saved Router protection policy',
                    msg='ordered baseline reused a changed saved control policy'):
                D.darwin_node_chain('apply', dict(capture=capture, expected=None))
            self.selected.clear()
            self.selected.update(previous)
            self.private_json(self.root/'routers.json', self.store)
            self.assertEqual(self.saved(), before)
            self.assertEqual(self.commands, commands)
        self.store['selected_id'] = 'another-selection'
        self.private_json(self.root/'routers.json', self.store)
        with self.assertRaisesRegex(RuntimeError, 'original selected Router control',
                msg='ordered baseline adopted a new selected control'):
            D.darwin_node_chain('apply', dict(capture=capture, expected=None))
        self.assertEqual(self.saved(), before)
        self.assertEqual(self.commands, commands)
        self.assertEqual(active['capture'], capture)

    def test_node_chain_failed_apply_keeps_original_cleanup_and_reassert_scope(self):
        capture = self.node_chain_capture('on-connect')
        self.fail_after_load = True
        with self.assertRaisesRegex(RuntimeError, 'ambiguous applied'):
            D.darwin_node_chain('apply', dict(capture=capture, expected=None))
        state = self.saved()
        self.assertEqual(state['native_node_chain_capture'], capture)
        self.assertTrue(state['darwin_transition_pending'])
        self.assertFalse(state[P._baseline.STATE_KEY]['complete'])
        self.assertNotIn(['-X', '417'], self.commands)
        self.fail_after_load = False
        retired = D.darwin_node_chain('release', dict(capture=capture, expected=None))
        self.assertFalse(retired['baseline']['present'])
        self.assertEqual(self.references, {'999'})
        capture = self.node_chain_capture()
        D.darwin_node_chain('apply', dict(capture=capture, expected=None))
        self.assertEqual(D.darwin_reassert(), 0)
        state = self.saved()
        self.assertEqual(state['native_socket_family'], 'ordered-node-chain-v1')
        self.assertEqual(state['native_node_chain_capture'], capture)
        self.assertEqual(state[P._baseline.STATE_KEY]['request']['session_id'], '')
        self.assertEqual(state[P._baseline.STATE_KEY]['request']['source_sha256'], '')
        self.assertNotIn('anchor ', self.rules[P.OWNED_PF_ANCHOR])
        with self.assertRaisesRegex(RuntimeError, 'current native session proof'):
            D.darwin_node_chain('apply', dict(capture=capture, expected=None))

    def test_node_chain_and_ordinary_successors_keep_distinct_cleanup_owners(self):
        ordered = self.node_chain_capture('on-connect')
        active = D.darwin_node_chain('apply', dict(capture=ordered, expected=None))
        held = D.darwin_node_chain('retire', dict(capture=ordered, expected=active))
        ordinary = self.external_capture('on-connect')
        self.selected['node_kind'] = 'external'
        self.private_json(self.root/'routers.json', self.store)
        ordinary.update(session_id='1'*32, source_sha256='2'*64)
        replacement = D.darwin_external('apply', dict(capture=ordinary, expected=None))
        with self.assertRaisesRegex(RuntimeError, 'another retained owner'):
            D.darwin_node_chain('release', dict(capture=ordered, expected=held))
        self.assertEqual(D.darwin_external('current', dict(capture=ordinary, expected=replacement)), replacement)
        held_external = D.darwin_external('retire', dict(capture=ordinary, expected=replacement))
        successor = self.node_chain_capture('on-connect')
        successor.update(session_id='3'*32, source_sha256='4'*64)
        result = D.darwin_node_chain('apply', dict(capture=successor, expected=None))
        before, commands = self.saved(), list(self.commands)
        with self.assertRaisesRegex(RuntimeError, 'another retained owner'):
            D.darwin_external('release', dict(capture=ordinary, expected=held_external))
        self.assertEqual(self.saved(), before)
        self.assertEqual(self.commands, commands)
        self.assertEqual(D.darwin_node_chain('current', dict(capture=successor, expected=result)), result)

    def test_node_chain_entry_retains_original_authority_and_state_guard(self):
        capture = self.node_chain_capture()
        events = []
        @contextlib.contextmanager
        def authority():
            events.append('authority')
            yield
            events.append('authority-closed')
        @contextlib.contextmanager
        def guard(root):
            self.assertEqual(root, self.root)
            self.assertEqual(events, ['authority'])
            events.append('state')
            yield
            events.append('state-closed')
        def dispatch(action, value):
            self.assertEqual(events, ['authority', 'state'], 'ordered action escaped original controller/state authority')
            self.assertEqual(action, 'apply')
            self.assertEqual(value, dict(capture=capture, expected=None))
            events.append('operation')
            return {'bounded_fixture': True}
        with patch.object(D, '_darwin_external_authority', side_effect=authority), \
             patch.object(D, '_darwin_action_guard', side_effect=guard), \
             patch.object(P._baseline, 'ROOT', self.root), \
             patch.object(D.os, 'getuid', return_value=0), patch.object(D.os, 'geteuid', return_value=0), \
             patch.object(D, 'darwin_external_input', return_value=dict(capture=capture, expected=None)), \
             patch.object(D, 'darwin_node_chain', side_effect=dispatch), \
             patch.object(D.sys, 'argv', ['dispatcher', 'ordered-native', 'apply']), \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(D.main(), 0)
        self.assertEqual(events, ['authority', 'state', 'operation', 'state-closed', 'authority-closed'])

    def candidate_prefix_capture(self, policy='always'):
        self.selected['node_kind'] = 'router-vpn'
        self.selected.pop('external', None)
        self.selected.update(kill_switch_policy=policy, kill_switch=policy != 'off', ipv6_mode='on',
                             multihop_enabled=True, multihop_execution='local',
                             multihop_nodes=[dict(id='prefix-entry', mode='wg'), dict(id='direct-tor', mode='shadowsocks')])
        entry = dict(id='prefix-entry', node_kind='router-vpn', kill_switch_policy=policy,
                     kill_switch=policy != 'off', home_lan_access=False, ipv6_mode='on')
        self.store['profiles'] = [profile for profile in self.store['profiles'] if profile.get('id') != 'prefix-entry'] + [entry]
        self.private_json(self.root/'routers.json', self.store)
        self.stack.enter_context(patch.dict(os.environ, {
            'HOMEVPN_TOR_PHYSICAL_BROKER': '', 'HOMEVPN_TOR_SESSION': '',
            'HOMEVPN_TOR_SOURCE_SHA256': '', 'HOMEVPN_ENDPOINT': ''}))
        digest, aggregate, lan = D._darwin_candidate_prefix_members(self.store, self.selected)
        return dict(schema=3, family='node-candidate-prefix-v1', profile_id='direct-tor',
                    session_id='c'*32, source_sha256='d'*64, config_sha256='e'*64,
                    members_sha256=digest, home_lan_access=lan, policy=aggregate)

    def test_candidate_prefix_mixed_members_use_original_aggregate_before_native_plan(self):
        capture = self.candidate_prefix_capture('on-connect')
        self.selected.update(kill_switch_policy='off', kill_switch=False, home_lan_access=True)
        digest, aggregate, lan = D._darwin_candidate_prefix_members(self.store, self.selected)
        capture.update(members_sha256=digest, policy=aggregate, home_lan_access=lan)
        self.private_json(self.root/'routers.json', self.store)
        try:
            active = D.darwin_candidate_prefix('apply', dict(capture=capture, expected=None))
        except RuntimeError as error:
            self.fail('prefix original aggregate did not reach its native baseline: '+str(error))
        state = self.saved()
        self.assertEqual(state['policy'], 'on-connect', 'prefix original aggregate did not reach its native baseline')
        self.assertFalse(state['home_lan_access'], 'prefix original aggregate did not reach its native baseline')
        self.assertEqual(state['native_candidate_prefix_capture'], capture)
        self.assertEqual(active['schema'], 3)
        self.assertFalse(state[D._darwin._baseline.STATE_KEY]['request'].get('isolated_only', False))
        retired = D.darwin_candidate_prefix('release', dict(capture=capture, expected=active))
        self.assertFalse(retired['baseline']['present'])

    def test_candidate_prefix_bound_members_reject_replacement_without_native_mutation(self):
        import copy
        capture = self.candidate_prefix_capture('always')
        original = copy.deepcopy(self.store)
        before = list(self.commands)
        for fault in ('missing', 'duplicate-profile', 'duplicate-reference', 'reordered', 'foreign', 'suffix-policy', 'suffix-lan', 'suffix-ipv6', 'mode'):
            changed = copy.deepcopy(original)
            control = next(p for p in changed['profiles'] if p['id'] == 'direct-tor')
            if fault == 'missing': changed['profiles'] = [p for p in changed['profiles'] if p['id'] != 'prefix-entry']
            elif fault == 'duplicate-profile': changed['profiles'].append(copy.deepcopy(changed['profiles'][-1]))
            elif fault == 'duplicate-reference': control['multihop_nodes'][0] = dict(control['multihop_nodes'][-1])
            elif fault == 'reordered': control['multihop_nodes'].reverse()
            elif fault == 'foreign': control['multihop_nodes'][0]['id'] = 'unrelated'
            elif fault == 'suffix-policy': control['kill_switch_policy'] = 'off'
            elif fault == 'suffix-lan': control['home_lan_access'] = True
            elif fault == 'suffix-ipv6': control['ipv6_mode'] = 'off'
            elif fault == 'mode': control['multihop_nodes'][0]['mode'] = 'awg2-fast'
            self.private_json(self.root/'routers.json', changed)
            with self.subTest(fault=fault), self.assertRaises(RuntimeError, msg='changed full prefix member reached native mutation'):
                D.darwin_candidate_prefix('apply', dict(capture=capture, expected=None))
            self.assertEqual(self.commands, before)
        self.private_json(self.root/'routers.json', original)

    def test_candidate_prefix_legacy_retained_readback_cleanup_and_reassert_only(self):
        import copy
        capture = self.candidate_prefix_capture('always')
        active = D.darwin_candidate_prefix('apply', dict(capture=capture, expected=None))
        legacy = dict(capture, schema=2)
        del legacy['members_sha256']
        state = self.saved()
        state['native_candidate_prefix_capture'] = legacy
        self.private_json(self.root/'run/kill-switch.json', state)
        receipt = dict(active, schema=2, capture=legacy)
        self.assertEqual(D.darwin_candidate_prefix('current', dict(capture=legacy, expected=receipt)), receipt)
        self.assertEqual(D.darwin_candidate_prefix('apply', dict(capture=legacy, expected=None)), receipt)
        self.assertEqual(D.darwin_reassert(), 0)
        self.assertEqual(self.saved()['native_candidate_prefix_capture'], legacy)
        changed = dict(legacy, source_sha256='f'*64)
        before, commands = copy.deepcopy(self.saved()), list(self.commands)
        with self.assertRaises(RuntimeError): D.darwin_candidate_prefix('apply', dict(capture=changed, expected=None))
        self.assertEqual(self.saved(), before)
        self.assertEqual(self.commands, commands)
        retired = D.darwin_candidate_prefix('release', dict(capture=legacy, expected=receipt))
        self.assertTrue(retired['baseline']['present'])
        D.darwin_release(True)
        commands = list(self.commands)
        with self.assertRaisesRegex(RuntimeError, 'legacy.*cannot authorize'):
            D.darwin_candidate_prefix('apply', dict(capture=legacy, expected=None))
        self.assertEqual(self.commands, commands)

    def test_candidate_prefix_uses_original_journal_and_exact_retirement(self):
        for policy in ('on-connect', 'always'):
            with self.subTest(policy=policy):
                capture = self.candidate_prefix_capture(policy)
                active = D.darwin_candidate_prefix('apply', dict(capture=capture, expected=None))
                self.assertEqual(active['schema'], 3)
                self.assertEqual(active['capture'], capture)
                state = self.saved()
                self.assertEqual(state['native_socket_family'], 'node-candidate-prefix-v1')
                self.assertEqual(state['native_candidate_prefix_capture'], capture)
                self.assertNotIn('native_external_capture', state)
                self.assertNotIn('native_node_chain_capture', state)
                self.assertEqual(state[P._baseline.STATE_KEY]['request']['session_id'], capture['session_id'])
                self.assertEqual(state[P._baseline.STATE_KEY]['request']['source_sha256'], capture['source_sha256'])
                self.assertEqual(state['endpoint_ips'], [])
                self.assertNotIn('pass out quick', self.rules[P.OWNED_PF_ANCHOR])
                self.assertEqual(D.darwin_candidate_prefix('apply', dict(capture=capture, expected=None)), active)
                self.assertEqual(D.darwin_candidate_prefix('current', dict(capture=capture, expected=active)), active)
                try:
                    held = D.darwin_candidate_prefix('retire', dict(capture=capture, expected=active))
                except RuntimeError as error:
                    self.fail('prefix switch released its deny baseline: '+str(error))
                self.assertTrue(held['baseline']['present'], 'prefix switch released its deny baseline')
                self.assertEqual(held['phase'], 'held')
                self.assertEqual(held['pf_token'], active['pf_token'])
                self.assertEqual(self.saved()[P._baseline.STATE_KEY]['request']['session_id'], '')
                self.assertEqual(D.darwin_candidate_prefix('retire', dict(capture=capture, expected=held)), held)
                retired = D.darwin_candidate_prefix('release', dict(capture=capture, expected=held))
                self.assertEqual(retired['baseline']['present'], policy == 'always')
                self.assertEqual(retired['pf_token'], active['pf_token'])
                self.assertEqual(D.darwin_candidate_prefix('release', dict(capture=capture, expected=retired)), retired)
                if policy == 'on-connect':
                    self.assertEqual(self.references, {'999'})
                else:
                    self.assertEqual(self.references, {active['pf_token'], '999'})
                    self.assertNotIn('anchor ', self.rules[P.OWNED_PF_ANCHOR])
        self.watcher.assert_not_called()
        self.resolver.assert_not_called()

    def test_candidate_prefix_stale_source_or_reference_cannot_release(self):
        capture = self.candidate_prefix_capture('on-connect')
        active = D.darwin_candidate_prefix('apply', dict(capture=capture, expected=None))
        before, commands = self.saved(), list(self.commands)
        for field, other in (('session_id', 'f'*32), ('source_sha256', 'f'*64), ('config_sha256', 'f'*64),
                             ('home_lan_access', True), ('profile_id', 'foreign-profile'), ('policy', 'always')):
            with self.subTest(field=field), self.assertRaises(RuntimeError, msg='stale prefix capture retired another native owner'):
                D.darwin_candidate_prefix('release', dict(capture={**capture, field: other}, expected=None))
            self.assertEqual(self.saved(), before)
            self.assertEqual(self.commands, commands)
        with self.assertRaisesRegex(RuntimeError, 'original PF reference', msg='prefix cleanup released another captured PF reference'):
            D.darwin_candidate_prefix('release', dict(capture=capture, expected={**active, 'pf_token': '999'}))
        self.assertEqual(self.saved(), before)
        self.assertEqual(self.commands, commands)

    def test_candidate_prefix_receipt_rejects_ordinary_and_ambiguous_families(self):
        capture = self.candidate_prefix_capture()
        changed = [dict(capture, schema=1), dict(capture, family='external-v1'), dict(capture, family='ordered-node-chain-v1'),
                   dict(capture, protocol='shadowsocks'), dict(capture, home_lan_access=0),
                   dict(capture, schema=True), dict(capture, family=None)]
        changed.append({key: value for key, value in capture.items() if key != 'family'})
        for value in changed:
            with self.subTest(capture=value), self.assertRaises(RuntimeError):
                D.darwin_candidate_prefix('apply', dict(capture=value, expected=None))
        self.assertEqual(self.commands, [])
        active = D.darwin_candidate_prefix('apply', dict(capture=capture, expected=None))
        with self.assertRaises(RuntimeError):
            D.darwin_external('release', dict(capture=capture, expected=active))
        with self.assertRaises(RuntimeError):
            D.darwin_node_chain('release', dict(capture=capture, expected=active))
        state = self.saved()
        self.private_json(self.root/'run/kill-switch.json', {**state, 'native_external_capture': capture})
        with self.assertRaisesRegex(RuntimeError, 'another retained owner'):
            D.darwin_candidate_prefix('release', dict(capture=capture, expected=active))

    def test_candidate_prefix_saved_control_and_policy_are_checked_before_mutation(self):
        capture = self.candidate_prefix_capture()
        active = D.darwin_candidate_prefix('apply', dict(capture=capture, expected=None))
        before, commands = self.saved(), list(self.commands)
        for field, value in (('kill_switch_policy', 'off'), ('home_lan_access', True),
                             ('node_kind', 'external'), ('external', {'protocol': 'shadowsocks'})):
            previous = dict(self.selected)
            self.selected[field] = value
            self.private_json(self.root/'routers.json', self.store)
            with self.subTest(field=field), self.assertRaisesRegex(RuntimeError, 'captured saved Router protection policy',
                    msg='prefix baseline reused a changed saved control policy'):
                D.darwin_candidate_prefix('apply', dict(capture=capture, expected=None))
            self.selected.clear()
            self.selected.update(previous)
            self.private_json(self.root/'routers.json', self.store)
            self.assertEqual(self.saved(), before)
            self.assertEqual(self.commands, commands)
        self.store['selected_id'] = 'another-selection'
        self.private_json(self.root/'routers.json', self.store)
        with self.assertRaisesRegex(RuntimeError, 'original selected Router control',
                msg='prefix baseline adopted a new selected control'):
            D.darwin_candidate_prefix('apply', dict(capture=capture, expected=None))
        self.assertEqual(self.saved(), before)
        self.assertEqual(self.commands, commands)
        self.assertEqual(active['capture'], capture)

    def test_candidate_prefix_failed_apply_keeps_original_cleanup_and_reassert_scope(self):
        capture = self.candidate_prefix_capture('on-connect')
        self.fail_after_load = True
        with self.assertRaisesRegex(RuntimeError, 'ambiguous applied'):
            D.darwin_candidate_prefix('apply', dict(capture=capture, expected=None))
        state = self.saved()
        self.assertEqual(state['native_candidate_prefix_capture'], capture)
        self.assertTrue(state['darwin_transition_pending'])
        self.assertFalse(state[P._baseline.STATE_KEY]['complete'])
        self.assertNotIn(['-X', '417'], self.commands)
        self.fail_after_load = False
        retired = D.darwin_candidate_prefix('release', dict(capture=capture, expected=None))
        self.assertFalse(retired['baseline']['present'])
        self.assertEqual(self.references, {'999'})
        capture = self.candidate_prefix_capture()
        D.darwin_candidate_prefix('apply', dict(capture=capture, expected=None))
        self.assertEqual(D.darwin_reassert(), 0)
        state = self.saved()
        self.assertEqual(state['native_socket_family'], 'node-candidate-prefix-v1')
        self.assertEqual(state['native_candidate_prefix_capture'], capture)
        self.assertEqual(state[P._baseline.STATE_KEY]['request']['session_id'], '')
        self.assertEqual(state[P._baseline.STATE_KEY]['request']['source_sha256'], '')
        self.assertNotIn('anchor ', self.rules[P.OWNED_PF_ANCHOR])
        with self.assertRaisesRegex(RuntimeError, 'current native session proof'):
            D.darwin_candidate_prefix('apply', dict(capture=capture, expected=None))

    def test_candidate_prefix_and_ordinary_successors_keep_distinct_cleanup_owners(self):
        prefix = self.candidate_prefix_capture('on-connect')
        active = D.darwin_candidate_prefix('apply', dict(capture=prefix, expected=None))
        held = D.darwin_candidate_prefix('retire', dict(capture=prefix, expected=active))
        ordinary = self.external_capture('on-connect')
        self.selected['node_kind'] = 'external'
        self.private_json(self.root/'routers.json', self.store)
        ordinary.update(session_id='1'*32, source_sha256='2'*64)
        replacement = D.darwin_external('apply', dict(capture=ordinary, expected=None))
        with self.assertRaisesRegex(RuntimeError, 'another retained owner'):
            D.darwin_candidate_prefix('release', dict(capture=prefix, expected=held))
        self.assertEqual(D.darwin_external('current', dict(capture=ordinary, expected=replacement)), replacement)
        held_external = D.darwin_external('retire', dict(capture=ordinary, expected=replacement))
        successor = self.candidate_prefix_capture('on-connect')
        successor.update(session_id='3'*32, source_sha256='4'*64)
        result = D.darwin_candidate_prefix('apply', dict(capture=successor, expected=None))
        before, commands = self.saved(), list(self.commands)
        with self.assertRaisesRegex(RuntimeError, 'another retained owner'):
            D.darwin_external('release', dict(capture=ordinary, expected=held_external))
        self.assertEqual(self.saved(), before)
        self.assertEqual(self.commands, commands)
        self.assertEqual(D.darwin_candidate_prefix('current', dict(capture=successor, expected=result)), result)

    def test_candidate_prefix_entry_retains_original_authority_and_state_guard(self):
        capture = self.candidate_prefix_capture()
        events = []
        @contextlib.contextmanager
        def authority():
            events.append('authority')
            yield
            events.append('authority-closed')
        @contextlib.contextmanager
        def guard(root):
            self.assertEqual(root, self.root)
            self.assertEqual(events, ['authority'])
            events.append('state')
            yield
            events.append('state-closed')
        def dispatch(action, value):
            self.assertEqual(events, ['authority', 'state'], 'prefix action escaped original controller/state authority')
            self.assertEqual(action, 'apply')
            self.assertEqual(value, dict(capture=capture, expected=None))
            events.append('operation')
            return {'bounded_fixture': True}
        with patch.object(D, '_darwin_external_authority', side_effect=authority), \
             patch.object(D, '_darwin_action_guard', side_effect=guard), \
             patch.object(P._baseline, 'ROOT', self.root), \
             patch.object(D.os, 'getuid', return_value=0), patch.object(D.os, 'geteuid', return_value=0), \
             patch.object(D, 'darwin_external_input', return_value=dict(capture=capture, expected=None)), \
             patch.object(D, 'darwin_candidate_prefix', side_effect=dispatch), \
             patch.object(D.sys, 'argv', ['dispatcher', 'candidate-prefix-native', 'apply']), \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(D.main(), 0)
        self.assertEqual(events, ['authority', 'state', 'operation', 'state-closed', 'authority-closed'])

    @staticmethod
    def private_json(path, value):
        path.write_text(json.dumps(value)+'\n')
        path.chmod(0o600)

    def saved(self):
        return json.loads((self.root/'run/kill-switch.json').read_text())

    def legacy_state(self, policy='always'):
        state = D._darwin_state_base('direct-tor', 'direct-tor', '198.51.100.44',
                                     ['198.51.100.44'], False, policy)
        state.update(pf_token='398', darwin_pf_anchor=P.PF_ANCHOR, darwin_watcher_pid=0,
                     darwin_baseline_utun=[], darwin_tunnel_interfaces=[], darwin_physical_interfaces=['en0'])
        self.private_json(self.root/'run/kill-switch.json', state)
        self.rules = {P.PF_ANCHOR: 'previous endpoint policy\n', 'com.apple/foreign': 'block out all\n'}
        self.references = {'398', '999'}
        return state

    @contextlib.contextmanager
    def legacy_environment(self):
        with patch.dict(os.environ, {'HOMEVPN_TOR_PHYSICAL_BROKER': '', 'HOMEVPN_ENDPOINT': '',
                                     'HOMEVPN_KILLSWITCH_DARWIN_TEST': '1', 'HOMEVPN_KILLSWITCH_DARWIN_UTUNS': ''}), \
             patch.object(P, 'current_utuns', return_value=[]), \
             patch.object(P, 'public_route_interfaces', return_value=['en0']):
            os.environ.pop('HOMEVPN_NATIVE_ENDPOINTS_JSON', None)
            os.environ.pop('HOMEVPN_NATIVE_EGRESS_JSON', None)
            yield

    def dispatch(self, action):
        output = io.StringIO()
        with patch.object(D.sys, 'argv', ['dispatcher', action]), contextlib.redirect_stderr(output):
            result = D.main()
        return result, output.getvalue()

    def captured_lease(self, state=None):
        state = dict(state or self.legacy_state())
        with D._private_run(self.root) as parent:
            generation = os.urandom(16).hex()
            descriptor = D._private_descriptor(parent, 'darwin-watcher-'+generation+'.lease', create=True, exclusive=True)
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            info = os.fstat(descriptor)
        record = {'schema': 1, 'generation': generation, 'device': info.st_dev, 'inode': info.st_ino, 'phase': 'active'}
        state.update(darwin_watcher_pid=os.getpid(), darwin_watcher=record)
        self.private_json(self.root/'run/kill-switch.json', state)
        return state, descriptor

    def start_real_watcher(self, command=None):
        children = []
        def spawn(argv, **kwargs):
            proc = POPEN(command(argv) if command else argv, **kwargs)
            children.append(proc)
            return proc
        def cleanup():
            for child in children:
                if child.poll() is None:
                    child.terminate()  # retained, unreaped test child, never a saved numeric identity
                child.wait(timeout=5)
        self.addCleanup(cleanup)
        self.watcher.side_effect = SPAWN_WATCHER
        with patch.object(D.subprocess, 'Popen', side_effect=spawn):
            result, error = self.dispatch('apply')
        self.assertEqual(result, 0, 'new owned watcher did not start: '+error)
        self.assertEqual(len(children), 1)
        state = self.saved()
        self.assertEqual(state['darwin_watcher_pid'], children[0].pid)
        self.assertEqual(D._watcher_record(state)['phase'], 'active')
        return children[0], state

    def reference(self, token):
        P._baseline.token(token)
        self.reference_reads.append(token)
        return token in self.references

    def native(self, phase, request):
        self.native_calls.append((phase, request))
        present = P.OWNED_PF_ANCHOR in self.rules
        previous = {'present': present, 'rules_sha256': hashlib.sha256(self.rules[P.OWNED_PF_ANCHOR].encode()).hexdigest() if present else ''}
        if previous not in request['expected']:
            raise RuntimeError('native baseline has another exact preimage')
        capture = (request['session_id'], request['source_sha256']) if request['session_id'] else None
        rules = P.render_owned_pf_rules(request['home_lan_access'], capture, request.get('isolated_only', False)) if request['action'] == 'replace' else None
        target = {'present': rules is not None, 'rules_sha256': hashlib.sha256(rules.encode()).hexdigest() if rules is not None else ''}
        if phase == 'apply':
            saved = self.saved()
            self.saved_before_load.append(saved)
            journal = saved[P._baseline.STATE_KEY]
            self.assertTrue(saved['darwin_transition_pending'])
            self.assertFalse(journal['complete'])
            self.assertEqual(journal['previous'], previous)
            self.assertEqual(journal['target'], target)
            if rules is None:
                self.rules.pop(P.OWNED_PF_ANCHOR, None)
            else:
                self.rules[P.OWNED_PF_ANCHOR] = rules
            if self.fail_after_load:
                raise RuntimeError('ambiguous applied PF load failure')
        return {'schema': 1, 'request_sha256': hashlib.sha256(P._baseline._canonical(request)).hexdigest(),
                'previous': previous, 'target': target, 'applied': phase == 'apply'}

    def pf(self, arguments, *, check=True, input_text=None):
        self.commands.append(list(arguments))
        result = ''
        if arguments == ['-E']:
            token = str(self.next_reference)
            self.next_reference += 1
            self.references.add(token)
            result = 'Token : '+token+'\n'
        elif arguments[:1] == ['-X']:
            self.references.discard(arguments[1])
        elif arguments == ['-s', 'Anchors']:
            result = 'com.apple\n' if self.rules else ''
        elif arguments[:1] == ['-a']:
            anchor = arguments[1]
            if arguments[2:] == ['-n', '-f', '-']:
                pass
            elif arguments[2:] == ['-f', '-']:
                self.saved_before_load.append(self.saved())
                self.rules[anchor] = input_text
                if self.fail_after_load:
                    raise RuntimeError('ambiguous applied PF load failure')
            elif arguments[2:] == ['-F', 'rules']:
                self.rules[anchor] = ''
            elif arguments[2:] in (['-s', 'rules'], ['-sr']):
                result = self.rules.get(anchor, '')
            elif arguments[2:] == ['-s', 'Anchors']:
                result = '\n'.join(sorted({name.removeprefix(anchor+'/').split('/')[0] for name in self.rules if name.startswith(anchor+'/')}))
            else:
                self.fail('unexpected PF fixture operation '+repr(arguments))
        else:
            self.fail('unexpected PF fixture operation '+repr(arguments))
        return subprocess.CompletedProcess(arguments, 0, result, '')

    def test_temporary_parent_alias_keeps_real_fixture_and_private_path_rejection(self):
        physical = self.root/'physical-temp'
        physical.mkdir(mode=0o700)
        alias = self.root/'temp-alias'
        alias.symlink_to(physical, target_is_directory=True)
        temporary = types.SimpleNamespace(name=str(alias), cleanup=lambda: None)
        independent = OwnedDarwinPF('test_actual_dispatch_captures_empty_baseline_and_reasserts_without_session')
        try:
            with patch.object(tempfile, 'TemporaryDirectory', return_value=temporary):
                independent.setUp()
            self.assertEqual(physical, independent.root, 'temporary PF fixture retained its symlink parent spelling')
            self.assertEqual(physical, D._linux.root_dir())
            for unsafe in (alias, alias/'run'):
                with self.subTest(unsafe=unsafe), patch.dict(os.environ, HOMEVPN_ROOT=str(unsafe)):
                    with self.assertRaisesRegex(RuntimeError, 'symlink private'):
                        D._linux.root_dir()
            independent.test_actual_dispatch_captures_empty_baseline_and_reasserts_without_session()
        finally:
            independent.doCleanups()

    def test_fixture_owner_preserves_native_metadata_and_root_only_admission(self):
        uid, gid = os.getuid(), os.getgid()
        regular = dict(st_mode=stat.S_IFREG | 0o600, st_nlink=1, st_uid=uid, st_gid=gid)
        directory = dict(st_mode=stat.S_IFDIR | 0o700, st_nlink=2, st_uid=uid, st_gid=gid)
        self.assertTrue(P._baseline._owned_info(types.SimpleNamespace(**regular)))
        self.assertTrue(P._baseline._owned_info(types.SimpleNamespace(**directory), directory=True))
        for changed in ({'st_uid': uid+1}, {'st_gid': gid+1}, {'st_nlink': 2},
                        {'st_mode': stat.S_IFREG | 0o644}, {'st_mode': stat.S_IFREG | 0o622},
                        {'st_mode': stat.S_IFLNK | 0o600}, {'st_mode': stat.S_IFDIR | 0o700}):
            with self.subTest(changed=changed):
                self.assertFalse(P._baseline._owned_info(types.SimpleNamespace(**{**regular, **changed})))
        for changed in ({'st_uid': uid+1}, {'st_gid': gid+1}, {'st_mode': stat.S_IFDIR | 0o722},
                        {'st_mode': stat.S_IFREG | 0o600}, {'st_mode': stat.S_IFLNK | 0o700}):
            with self.subTest(directory_changed=changed):
                self.assertFalse(P._baseline._owned_info(types.SimpleNamespace(**{**directory, **changed}), directory=True))
        for uid, gid in ((0, 0), (501, 0), (0, 20), (501, 20)):
            with self.subTest(native_owner=(uid, gid)):
                info = types.SimpleNamespace(**{**regular, 'st_uid': uid, 'st_gid': gid})
                self.assertEqual(NATIVE_OWNED_INFO(info), uid == 0 and gid == 0,
                                 'portable ownership fixture weakened the production root predicate')

    def test_actual_dispatch_captures_empty_baseline_and_reasserts_without_session(self):
        self.assertEqual(D.darwin_apply(), 0)
        state = self.saved()
        self.assertTrue(state['native_socket_broker'])
        self.assertEqual(state['endpoint_ips'], [])
        self.assertEqual(state['endpoint'], '')
        self.assertEqual(state['pf_token'], '417')
        self.assertNotIn('darwin_transition_pending', state)
        self.assertNotIn('native_egress', state)
        self.assertEqual(state[P._baseline.STATE_KEY]['request']['session_id'], 'a'*32)
        self.assertEqual(state[P._baseline.STATE_KEY]['request']['source_sha256'], 'b'*64)
        self.assertTrue(state[P._baseline.STATE_KEY]['complete'])
        active = self.rules[P.OWNED_PF_ANCHOR]
        self.assertIn('anchor "p'+'a'*32+'" out', active)
        self.assertNotIn(' user ', active)
        self.assertNotIn('utun', active)
        self.assertNotIn('198.51.100.44', active)
        self.assertNotIn('pass out quick', active)
        self.assertIn('block drop out quick all ! tagged ', active)
        self.watcher.assert_not_called()
        with patch.dict(os.environ, {'HOMEVPN_TOR_SESSION': '', 'HOMEVPN_TOR_SOURCE_SHA256': '',
                                     'HOMEVPN_TOR_PHYSICAL_BROKER': '', 'HOMEVPN_ENDPOINT': '198.51.100.44'}):
            self.assertEqual(D.darwin_reassert(), 0)
        inactive = self.rules[P.OWNED_PF_ANCHOR]
        self.assertNotIn('anchor ', inactive)
        self.assertNotIn('a'*32, inactive)
        self.assertNotIn('a'*32, json.dumps(self.saved()))
        self.assertNotIn('b'*64, json.dumps(self.saved()))
        self.assertEqual(D.darwin_release(), 0)
        self.assertEqual(self.rules[P.OWNED_PF_ANCHOR], inactive)
        self.assertEqual(self.commands.count(['-E']), 1)
        self.resolver.assert_not_called()

    def test_ambiguous_load_failure_retains_exact_reference_before_mutation(self):
        self.fail_after_load = True
        with self.assertRaisesRegex(RuntimeError, 'ambiguous applied'):
            D.darwin_apply()
        self.assertEqual(self.saved_before_load[0], self.saved())
        self.assertEqual(self.saved()['pf_token'], '417')
        self.assertTrue(self.saved()['darwin_transition_pending'])
        self.assertFalse(P.status_darwin(self.saved(), dry_run=False))
        self.assertIn('block drop out quick', self.rules[P.OWNED_PF_ANCHOR])
        self.assertNotIn(['-X', '417'], self.commands)
        self.fail_after_load = False
        self.assertEqual(D.darwin_release(True), 0)
        self.assertIn(['-X', '417'], self.commands)
        self.assertNotIn(P.OWNED_PF_ANCHOR, self.rules)
        self.assertEqual(self.references, {'999'})

    def test_state_write_failure_balances_new_reference_without_filter_mutation(self):
        with patch.object(D._linux, 'write_state', side_effect=RuntimeError('private state write rejected')):
            with self.assertRaisesRegex(RuntimeError, 'private state write rejected'):
                D.darwin_apply()
        self.assertEqual(self.rules, {})
        self.assertIn(['-X', '417'], self.commands)
        self.assertFalse((self.root/'run/kill-switch.json').exists())

    def test_adopted_but_unsynced_journal_retains_reference_for_same_retry(self):
        with patch.object(P._baseline, 'sync_state', side_effect=OSError('directory sync failed')):
            with self.assertRaises(RuntimeError):
                D.darwin_apply()
        saved = self.saved()
        self.assertTrue(saved['darwin_transition_pending'])
        self.assertFalse(saved[P._baseline.STATE_KEY]['complete'])
        self.assertEqual(saved['pf_token'], '417')
        self.assertEqual(self.rules, {})
        self.assertNotIn(['-X', '417'], self.commands, 'unsynced adopted journal lost its captured reference')
        self.assertEqual(self.references, {'417', '999'})
        self.assertEqual(D.darwin_apply(), 0)
        self.assertEqual(self.commands.count(['-E']), 1)
        self.assertEqual(self.saved()['pf_token'], '417')

    def test_unknown_journal_read_does_not_balance_a_possibly_adopted_reference(self):
        with patch.object(D._linux, 'write_state', side_effect=OSError('uncertain write')), \
             patch.object(D._linux, 'read_state', side_effect=[{}, RuntimeError('unknown private read')]):
            with self.assertRaisesRegex(RuntimeError, 'retained captured PF reference 417'):
                D.darwin_apply()
        self.assertEqual(self.rules, {})
        self.assertNotIn(['-X', '417'], self.commands)
        self.assertEqual(self.references, {'417', '999'})

    def test_reboot_reassert_proves_absence_then_acquires_a_new_exact_reference(self):
        self.assertEqual(D.darwin_apply(), 0)
        self.references.remove('417')
        self.rules.clear()
        self.assertEqual(D.darwin_reassert(), 0)
        self.assertEqual(self.saved()['pf_token'], '418', 'native reboot reused a dead PF reference')
        self.assertEqual(self.commands.count(['-E']), 2)
        self.assertNotIn(['-X', '417'], self.commands)
        self.assertEqual(self.references, {'418', '999'})
        self.assertNotIn('a'*32, json.dumps(self.saved()))

    def test_missing_reference_cannot_adopt_a_different_present_baseline(self):
        self.assertEqual(D.darwin_apply(), 0)
        before = self.saved()
        self.references.remove('417')
        self.rules[P.OWNED_PF_ANCHOR] = 'independently changed owner\n'
        with self.assertRaisesRegex(RuntimeError, 'another exact preimage'):
            D.darwin_reassert()
        self.assertEqual(self.saved(), before)
        self.assertEqual(self.commands.count(['-E']), 1)
        self.assertEqual(self.rules[P.OWNED_PF_ANCHOR], 'independently changed owner\n')

    def test_reference_release_uses_exact_absence_after_a_lost_reply(self):
        self.assertEqual(D.darwin_apply(), 0)
        actual = P.run_pf
        def lost_reply(arguments, **kwargs):
            result = actual(arguments, **kwargs)
            if arguments == ['-X', '417']:
                return subprocess.CompletedProcess(arguments, 1, '', 'reply lost after release')
            return result
        with patch.object(P, 'run_pf', side_effect=lost_reply):
            self.assertEqual(D.darwin_release(True), 0)
        self.assertFalse((self.root/'run/kill-switch.json').exists())
        self.assertEqual(self.references, {'999'})

    def test_failed_reference_release_retains_exact_clear_receipt_until_same_retry(self):
        self.assertEqual(D.darwin_apply(), 0)
        actual = P.run_pf
        def reject_release(arguments, **kwargs):
            if arguments == ['-X', '417']:
                return subprocess.CompletedProcess(arguments, 1, '', 'release rejected')
            return actual(arguments, **kwargs)
        with patch.object(P, 'run_pf', side_effect=reject_release):
            try:
                D.darwin_release(True)
            except RuntimeError as error:
                self.assertIn('did not prove exact absence', str(error))
            else:
                self.fail('native reference release discarded a still-present exact owner')
        saved = self.saved()
        self.assertTrue(saved[P._baseline.STATE_KEY]['complete'])
        self.assertFalse(saved[P._baseline.STATE_KEY]['target']['present'])
        self.assertEqual(self.references, {'417', '999'})
        self.assertEqual(D.darwin_release(True), 0)
        self.assertEqual(self.references, {'999'})
        self.assertFalse((self.root/'run/kill-switch.json').exists())

    def test_unknown_post_release_read_keeps_exact_removal_and_retry_does_not_replay_x(self):
        self.assertEqual(D.darwin_apply(), 0)
        calls = []
        def unknown_after_release(token):
            calls.append(token)
            if len(calls) == 2:
                raise RuntimeError('native reference read unknown')
            return self.reference(token)
        with patch.object(P._baseline, 'reference', side_effect=unknown_after_release), self.assertRaisesRegex(RuntimeError, 'reference read unknown'):
            D.darwin_release(True)
        saved = self.saved()
        self.assertTrue(saved['darwin_transition_pending'])
        self.assertTrue(saved[P._baseline.STATE_KEY]['complete'])
        self.assertFalse(saved[P._baseline.STATE_KEY]['target']['present'])
        self.assertEqual(self.references, {'999'})
        self.assertEqual(self.commands.count(['-X', '417']), 1)
        with self.assertRaisesRegex(RuntimeError, 'retirement is pending'):
            D.darwin_apply()
        self.assertEqual(self.saved(), saved)
        self.assertEqual(D.darwin_release(True), 0)
        self.assertEqual(self.commands.count(['-X', '417']), 1)
        self.assertFalse((self.root/'run/kill-switch.json').exists())

    def test_existing_legacy_owner_is_preserved_before_native_transition(self):
        prior = D._darwin_state_base('direct-tor', 'direct-tor', '198.51.100.44', [], False, 'always')
        prior.update(pf_token='398', darwin_pf_anchor=P.PF_ANCHOR, darwin_watcher_pid=0)
        self.private_json(self.root/'run/kill-switch.json', prior)
        self.rules[P.PF_ANCHOR] = 'previous endpoint policy\n'
        self.references.add('398')
        with self.assertRaisesRegex(RuntimeError, 'retained legacy PF namespace'):
            D.darwin_apply()
        self.assertEqual(self.saved(), prior)
        self.assertEqual(self.rules, {P.PF_ANCHOR: 'previous endpoint policy\n'})
        self.assertEqual(self.native_calls, [])
        self.assertNotIn(['-E'], self.commands)
        self.assertNotIn(['-X', '398'], self.commands)

    def test_native_transition_does_not_kill_a_saved_unjoined_watcher_pid(self):
        prior = D._darwin_state_base('direct-tor', 'direct-tor', '198.51.100.44', [], False, 'always')
        prior.update(pf_token='398', darwin_pf_anchor=P.PF_ANCHOR, darwin_watcher_pid=991)
        self.private_json(self.root/'run/kill-switch.json', prior)
        with patch.object(D.os, 'kill') as kill, self.assertRaisesRegex(RuntimeError, 'prior watcher retirement'):
            D.darwin_apply()
        kill.assert_not_called()
        self.assertEqual(self.saved(), prior)
        self.assertEqual(self.native_calls, [])
        self.assertEqual(self.commands, [])

    def test_legacy_actions_retain_unresolved_watcher_without_signaling(self):
        missing = object()
        # A stored PID has no creation identity or retained child handle. Even
        # the current process, a missing field and zero-like values cannot
        # establish that the old watcher has relinquished its authority.
        identities = (991, os.getpid(), 1, -1, '991', '0', '', None, False, True, 0.0, [], {}, missing)
        for label, action, policy in (('Off', 'apply', 'off'), ('release', 'release', 'on-connect'),
                                      ('Always release', 'release', 'always'), ('force-off', 'force-off', 'always'),
                                      ('reassert', 'reassert', 'always'), ('legacy apply', 'apply', 'always')):
            for identity in identities:
                with self.subTest(action=label, identity=repr(identity)):
                    self.selected['kill_switch_policy'] = policy
                    self.private_json(self.root/'routers.json', self.store)
                    prior = D._darwin_state_base('direct-tor', 'direct-tor', '198.51.100.44',
                                                ['198.51.100.44'], False, 'always' if policy == 'off' else policy)
                    prior.update(pf_token='398', darwin_pf_anchor=P.PF_ANCHOR,
                                 darwin_baseline_utun=[], darwin_tunnel_interfaces=[],
                                 darwin_physical_interfaces=['en0'])
                    if identity is not missing:
                        prior['darwin_watcher_pid'] = identity
                    path = self.root/'run/kill-switch.json'
                    self.private_json(path, prior)
                    saved, saved_identity = path.read_bytes(), path.stat()
                    self.rules = {P.PF_ANCHOR: 'previous endpoint policy\n', 'com.apple/foreign': 'block out all\n'}
                    rules_before = dict(self.rules)
                    self.references = {'398', '999'}
                    self.commands.clear(); self.native_calls.clear(); self.reference_reads.clear()
                    self.watcher.reset_mock(); self.watcher.return_value = 0
                    stdout, stderr = io.StringIO(), io.StringIO()
                    with patch.object(D.os, 'kill') as kill, patch.object(P, 'current_utuns', return_value=[]), \
                         patch.object(P, 'public_route_interfaces', return_value=['en0']), \
                         patch.dict(os.environ, {'HOMEVPN_TOR_PHYSICAL_BROKER': '', 'HOMEVPN_ENDPOINT': ''}), \
                         patch.object(D.sys, 'argv', ['dispatcher', action]), \
                         contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                        os.environ.pop('HOMEVPN_NATIVE_ENDPOINTS_JSON', None)
                        os.environ.pop('HOMEVPN_NATIVE_EGRESS_JSON', None)
                        result = D.main()
                    self.assertEqual(kill.call_count, 0, 'legacy saved PID was signaled without captured ownership')
                    self.assertEqual(result, 1, 'legacy watcher action did not retain unresolved ownership')
                    self.assertIn('prior watcher retirement', stderr.getvalue())
                    self.assertEqual(stdout.getvalue(), '')
                    self.assertEqual(path.read_bytes(), saved, 'unresolved watcher changed its private recovery record')
                    self.assertTrue(os.path.samestat(saved_identity, path.stat()))
                    self.assertEqual(self.rules, rules_before)
                    self.assertEqual(self.references, {'398', '999'})
                    self.assertEqual(self.commands, [], 'unresolved watcher reached PF operations')
                    self.assertEqual(self.native_calls, [])
                    self.assertEqual(self.reference_reads, [])
                    self.watcher.assert_not_called()

    def test_explicit_zero_watcher_preserves_legacy_off_release_and_reassert(self):
        for action, policy in (('apply', 'off'), ('release', 'on-connect'), ('release', 'always'),
                               ('force-off', 'always'), ('reassert', 'always')):
            with self.subTest(action=action, policy=policy):
                self.selected['kill_switch_policy'] = policy
                self.private_json(self.root/'routers.json', self.store)
                prior = D._darwin_state_base('direct-tor', 'direct-tor', '198.51.100.44',
                                            ['198.51.100.44'], False, 'always' if policy == 'off' else policy)
                prior.update(pf_token='398', darwin_pf_anchor=P.PF_ANCHOR, darwin_watcher_pid=0,
                             darwin_baseline_utun=[], darwin_tunnel_interfaces=[], darwin_physical_interfaces=['en0'])
                path = self.root/'run/kill-switch.json'
                self.private_json(path, prior)
                self.rules = {P.PF_ANCHOR: 'previous endpoint policy\n', 'com.apple/foreign': 'block out all\n'}
                self.references = {'398', '999'}
                self.commands.clear(); self.native_calls.clear()
                with patch.object(D.os, 'kill') as kill, patch.object(P, 'current_utuns', return_value=[]), \
                     patch.object(P, 'public_route_interfaces', return_value=['en0']), \
                     patch.dict(os.environ, {'HOMEVPN_TOR_PHYSICAL_BROKER': '', 'HOMEVPN_ENDPOINT': ''}), \
                     patch.object(D.sys, 'argv', ['dispatcher', action]), \
                     contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(D.main(), 0, 'explicit no-watcher legacy operation was blocked')
                kill.assert_not_called()
                self.assertEqual(self.rules['com.apple/foreign'], 'block out all\n')
                if policy == 'off' or policy == 'on-connect' or action == 'force-off':
                    self.assertFalse(path.exists())
                    self.assertEqual(self.references, {'999'})
                else:
                    self.assertEqual(self.saved()['darwin_watcher_pid'], 0)
                    self.assertEqual(self.saved()['policy'], 'always')
                    self.assertEqual(self.references, {'398', '999'})
                    self.assertIn('block drop out quick all', self.rules[P.PF_ANCHOR])

    def test_absent_legacy_owner_with_zero_watcher_uses_existing_native_transaction(self):
        # This already-supported inactive case needs no new migration authority.
        # A present namespace or unresolved watcher remains a different case.
        prior = D._darwin_state_base('direct-tor', 'direct-tor', '198.51.100.44', [], False, 'always')
        prior.update(pf_token='398', darwin_pf_anchor=P.PF_ANCHOR, darwin_watcher_pid=0)
        self.private_json(self.root/'run/kill-switch.json', prior)
        settings = (self.root/'routers.json').read_bytes()
        self.rules = {'com.apple/foreign': 'block out all\n'}
        with patch.object(D.os, 'kill') as kill:
            self.assertEqual(D.darwin_apply(), 0)
        kill.assert_not_called()
        state = self.saved()
        self.assertTrue(state['native_socket_broker'])
        self.assertEqual(state['darwin_watcher_pid'], 0)
        self.assertEqual(state['pf_token'], '417')
        self.assertTrue(state[P._baseline.STATE_KEY]['complete'])
        self.assertEqual(state[P._baseline.STATE_KEY]['previous'], {'present': False, 'rules_sha256': ''})
        self.assertEqual(self.references, {'417', '999'})
        self.assertEqual(self.rules['com.apple/foreign'], 'block out all\n')
        self.assertEqual((self.root/'routers.json').read_bytes(), settings)
        self.assertNotIn(['-X', '398'], self.commands)
        self.assertFalse(any(command[:1] == ['-a'] and '-F' in command for command in self.commands))
        self.watcher.assert_not_called()

    def test_shipping_actions_hold_one_complete_state_transaction(self):
        for action, name in (('apply', 'darwin_apply'), ('release', 'darwin_release'),
                             ('force-off', 'darwin_release'), ('reassert', 'darwin_reassert')):
            events = []
            @contextlib.contextmanager
            def guard(root):
                self.assertEqual(root, self.root)
                events.append('enter')
                try:
                    yield
                finally:
                    events.append('leave')
            def operation(*args):
                self.assertEqual(events, ['enter'], 'shipping PF mutation escaped its complete private state lock')
                lock = self.root/'run/darwin-watcher-state.lock'
                self.assertTrue(lock.is_file(), 'shipping PF mutation escaped its real per-root transaction')
                probe = os.open(lock, os.O_RDWR)
                try:
                    with self.assertRaises(BlockingIOError, msg='shipping PF mutation escaped its real per-root transaction'):
                        fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
                finally:
                    os.close(probe)
                events.append('operation')
                return 0
            with self.subTest(action=action), patch.object(P._baseline, 'state_guard', side_effect=guard), \
                 patch.object(D, name, side_effect=operation), patch.object(D.sys, 'argv', ['dispatcher', action]):
                self.assertEqual(D.main(), 0, 'shipping PF mutation escaped its complete private state lock')
            self.assertEqual(events, ['enter', 'operation', 'leave'])
        with patch.object(P._baseline, 'state_guard', side_effect=BlockingIOError('captured state owner busy')), \
             patch.object(D, '_WATCHER_ADMISSION_SECONDS', 0.04), \
             patch.object(D, 'darwin_apply') as operation, patch.object(D.sys, 'argv', ['dispatcher', 'apply']):
            self.assertEqual(D.main(), 1)
            operation.assert_not_called()

    def test_action_waits_for_real_watcher_contention_before_one_mutation(self):
        with self.legacy_environment():
            self.legacy_state('on-connect')
            with D._private_run(self.root) as parent:
                holder = D._private_descriptor(parent, 'darwin-watcher-state.lock', create=True)
            original_flock = fcntl.flock
            original_flock(holder, fcntl.LOCK_EX | fcntl.LOCK_NB)
            events, collisions = [], []
            @contextlib.contextmanager
            def outer_guard(root):
                events.append('enter')
                try:
                    yield
                finally:
                    events.append('leave')
            def contended(descriptor, operation):
                try:
                    return original_flock(descriptor, operation)
                except BlockingIOError:
                    collisions.append(descriptor)
                    original_flock(holder, fcntl.LOCK_UN)
                    raise
            try:
                with patch.object(P._baseline, 'state_guard', side_effect=outer_guard), \
                     patch.object(D.fcntl, 'flock', side_effect=contended), \
                     patch.object(D, 'darwin_release', wraps=D.darwin_release) as release:
                    result, error = self.dispatch('release')
                self.assertEqual(result, 0, 'brief real watcher contention rejected Disconnect: '+error)
                self.assertEqual(len(collisions), 1)
                release.assert_called_once_with(False)
                self.assertEqual(events, ['enter', 'leave', 'enter', 'leave'], 'admission retry retained the outer lock')
                self.assertFalse((self.root/'run/kill-switch.json').exists())
                self.assertEqual(self.references, {'999'})
                self.assertEqual(self.rules['com.apple/foreign'], 'block out all\n')
            finally:
                os.close(holder)

    def test_admitted_action_errors_are_never_retried(self):
        with patch.object(D, 'darwin_release', side_effect=BlockingIOError('owned operation failed after admission')) as release:
            result, error = self.dispatch('release')
        self.assertEqual(result, 1)
        self.assertIn('owned operation failed after admission', error)
        release.assert_called_once_with(False)
        self.assertIsNone(D._WATCHER_GUARD_FD)

    def test_busy_admission_never_bypasses_or_releases_a_foreign_watcher_lock(self):
        with D._private_run(self.root) as parent:
            holder = D._private_descriptor(parent, 'darwin-watcher-state.lock', create=True)
        fcntl.flock(holder, fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            with patch.object(D, '_WATCHER_ADMISSION_SECONDS', 0.04), \
                 patch.object(D, 'darwin_release') as release:
                result, error = self.dispatch('release')
            self.assertEqual(result, 1)
            self.assertIn('still owned by another operation', error)
            release.assert_not_called()
            self.assertIsNone(D._WATCHER_GUARD_FD)
            probe = os.open(self.root/'run/darwin-watcher-state.lock', os.O_RDWR)
            try:
                with self.assertRaises(BlockingIOError):
                    fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
            finally:
                os.close(probe)
        finally:
            os.close(holder)

    def test_legacy_watcher_locks_its_iteration_and_never_rewrites_native_timeout(self):
        prior, descriptor = self.captured_lease()
        held = []
        @contextlib.contextmanager
        def guard(root):
            self.assertEqual(root, self.root)
            held.append(True)
            try:
                yield
            finally:
                held.pop()
        def refresh(*args, **kwargs):
            self.assertEqual(held, [True], 'legacy watcher changed PF outside its captured state lock')
            probe = os.open(self.root/'run/darwin-watcher-state.lock', os.O_RDWR)
            try:
                with self.assertRaises(BlockingIOError, msg='legacy watcher bypassed its real per-root lock'):
                    fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
            finally:
                os.close(probe)
            self.assertEqual(set(P._baseline.process_authority_fds()), {descriptor, D._WATCHER_GUARD_FD})
            return {}
        with patch.object(P._baseline, 'state_guard', side_effect=guard), \
             patch.object(P, 'apply_darwin', side_effect=refresh), patch.object(D._linux, 'retained_native_policy', return_value=None):
            self.assertEqual(D.darwin_watch(prior['darwin_watcher']['generation'], descriptor), 0)
        self.assertEqual(self.saved()['darwin_watcher']['phase'], 'finished')
        for timeout in (False, True):
            native, descriptor = self.captured_lease({**prior, 'native_socket_broker': True, 'darwin_pf_anchor': P.OWNED_PF_ANCHOR})
            with self.subTest(timeout=timeout), patch.object(P._baseline, 'state_guard', side_effect=guard), \
                 patch.object(P, 'apply_darwin', return_value={}) as refresh, patch.object(D, '_write_watcher_state') as write, \
                 patch.object(D.time, 'monotonic', side_effect=[0, 91] if timeout else [0, 1]):
                self.assertEqual(D.darwin_watch(native['darwin_watcher']['generation'], descriptor), 1 if timeout else 0)
                self.assertEqual(refresh.call_count, 0, 'older watcher changed a replacement native journal')
                self.assertEqual(write.call_count, 0, 'older watcher timeout rewrote a replacement native journal')
            self.assertEqual(self.saved(), native)
        with self.assertRaisesRegex(RuntimeError, 'inherited lease'), patch.object(P, 'apply_darwin') as refresh:
            D.darwin_watch()
        refresh.assert_not_called()

    def test_watcher_rechecks_exact_generation_inside_its_transaction(self):
        prior, descriptor = self.captured_lease()
        replacement, replacement_descriptor = self.captured_lease(prior)
        self.addCleanup(os.close, replacement_descriptor)
        self.private_json(self.root/'run/kill-switch.json', prior)
        @contextlib.contextmanager
        def intervening_replacement(root):
            self.private_json(root/'run/kill-switch.json', replacement)
            yield
        with patch.object(P._baseline, 'state_guard', side_effect=intervening_replacement), \
             patch.object(P, 'apply_darwin', return_value={}) as refresh:
            self.assertEqual(D.darwin_watch(prior['darwin_watcher']['generation'], descriptor), 0)
        self.assertEqual(refresh.call_count, 0, 'stale watcher changed PF after a captured generation replacement')
        self.assertEqual(self.saved(), replacement)

    def test_new_real_watchers_retire_for_off_release_always_and_reassert(self):
        for action, policy in (('apply', 'off'), ('release', 'on-connect'), ('release', 'always'),
                               ('force-off', 'always'), ('reassert', 'always')):
            with self.subTest(action=action, policy=policy), self.legacy_environment():
                initial_policy = 'always' if policy == 'off' else policy
                self.selected['kill_switch_policy'] = initial_policy
                self.private_json(self.root/'routers.json', self.store)
                self.legacy_state(initial_policy)
                child, active = self.start_real_watcher()
                lease = self.root/'run'/D._watcher_leaf(active['darwin_watcher'])
                self.assertTrue(lease.is_file())
                self.selected['kill_switch_policy'] = policy
                self.private_json(self.root/'routers.json', self.store)
                with patch.object(D.os, 'kill') as kill:
                    result, error = self.dispatch(action)
                self.assertEqual(result, 0, 'new watcher prevented normal lifecycle retirement: '+error)
                self.assertEqual(kill.call_count, 0, 'new watcher retirement signaled a saved PID')
                self.assertEqual(child.wait(timeout=4), 0)
                self.assertFalse(lease.exists(), 'retired new watcher left its owned lease')
                self.assertEqual(self.rules['com.apple/foreign'], 'block out all\n')
                if policy in ('off', 'on-connect') or action == 'force-off':
                    self.assertFalse((self.root/'run/kill-switch.json').exists())
                    self.assertEqual(self.references, {'999'})
                else:
                    self.assertEqual(self.saved()['darwin_watcher_pid'], 0)
                    self.assertNotIn('darwin_watcher', self.saved())
                    self.assertEqual(self.references, {'398', '999'})
                    self.assertIn('block drop out quick all', self.rules[P.PF_ANCHOR])

    def test_failed_cancellation_persistence_retains_owner_and_same_retry(self):
        with self.legacy_environment():
            self.legacy_state()
            child, active = self.start_real_watcher()
            before_rules, before_references = dict(self.rules), set(self.references)
            original = D._write_watcher_state
            def adopted_then_failed(root, state):
                original(root, state)
                raise OSError('fixture cancellation directory sync failed after adoption')
            with patch.object(D, '_write_watcher_state', side_effect=adopted_then_failed):
                result, error = self.dispatch('force-off')
            self.assertEqual(result, 1, 'uncertain cancellation was reported as successful retirement')
            self.assertIn('directory sync failed', error)
            self.assertEqual(self.saved()['darwin_watcher']['generation'], active['darwin_watcher']['generation'])
            self.assertEqual(self.saved()['darwin_watcher']['phase'], 'cancel')
            self.assertEqual(self.rules, before_rules)
            self.assertEqual(self.references, before_references)
            result, error = self.dispatch('force-off')
            self.assertEqual(result, 0, error)
            self.assertEqual(child.wait(timeout=4), 0)
            self.assertFalse((self.root/'run/kill-switch.json').exists())

    def test_unresolved_lease_retains_cancel_until_exact_holder_retires(self):
        active, holder = self.captured_lease()
        original = self.saved()
        with self.legacy_environment(), patch.object(D, '_WATCHER_RETIRE_SECONDS', 0.04):
            result, error = self.dispatch('force-off')
        self.assertEqual(result, 1, 'held watcher lease was treated as retired')
        self.assertIn('not yet retired', error)
        self.assertEqual(self.saved(), {**original, 'darwin_watcher': {**original['darwin_watcher'], 'phase': 'cancel'}})
        self.assertEqual(self.rules[P.PF_ANCHOR], 'previous endpoint policy\n')
        os.close(holder)
        with self.legacy_environment():
            result, error = self.dispatch('force-off')
        self.assertEqual(result, 0, error)
        self.assertEqual(self.references, {'999'})

    def test_retired_lease_cleanup_failures_keep_exact_receipt_for_retry(self):
        for failure in ('unlink', 'parent-sync'):
            with self.subTest(failure=failure), self.legacy_environment():
                active, holder = self.captured_lease()
                os.close(holder)
                leaf = D._watcher_leaf(active['darwin_watcher'])
                lease = self.root/'run'/leaf
                original_unlink, original_sync = os.unlink, os.fsync
                failures = []
                def unlink(path, *args, **kwargs):
                    if failure == 'unlink' and path == leaf:
                        failures.append('unlink')
                        raise OSError('fixture exact lease unlink failed')
                    return original_unlink(path, *args, **kwargs)
                def sync(descriptor):
                    if failure == 'parent-sync' and stat.S_ISDIR(os.fstat(descriptor).st_mode) and not lease.exists():
                        failures.append('parent-sync')
                        raise OSError('fixture exact lease parent sync failed')
                    return original_sync(descriptor)
                self.commands.clear()
                with patch.object(D.os, 'unlink', side_effect=unlink), patch.object(D.os, 'fsync', side_effect=sync), \
                     patch.object(D.os, 'kill') as kill:
                    result, error = self.dispatch('force-off')
                self.assertEqual(result, 1, 'failed lease cleanup was reported as complete')
                self.assertEqual(failures, [failure])
                self.assertEqual(kill.call_count, 0)
                receipt = self.saved()
                self.assertIn('darwin_watcher', receipt, 'failed lease cleanup lost its exact retry receipt')
                self.assertEqual(receipt['darwin_watcher']['phase'], 'retired', 'failed lease cleanup lost its exact retry receipt')
                self.assertEqual(receipt['darwin_watcher_pid'], 0)
                self.assertEqual(receipt['darwin_watcher']['generation'], active['darwin_watcher']['generation'])
                self.assertEqual(lease.exists(), failure == 'unlink')
                self.assertEqual(self.commands, [], 'PF release overtook uncertain lease cleanup')
                self.assertEqual(self.references, {'398', '999'})
                if failure == 'unlink':
                    retained = lease.with_suffix('.retained-fixture')
                    lease.rename(retained)
                    lease.write_text('foreign replacement\n')
                    lease.chmod(0o600)
                    result, error = self.dispatch('force-off')
                    self.assertEqual(result, 1)
                    self.assertEqual(lease.read_text(), 'foreign replacement\n')
                    self.assertEqual(self.saved(), receipt)
                    lease.unlink()
                    retained.rename(lease)
                result, error = self.dispatch('force-off')
                self.assertEqual(result, 0, 'exact retired lease cleanup was not retryable: '+error)
                self.assertFalse(lease.exists())
                self.assertFalse((self.root/'run/kill-switch.json').exists())
                self.assertEqual(self.references, {'999'})

    def test_failed_watcher_launch_keeps_a_recoverable_unactivated_lease(self):
        with self.legacy_environment():
            self.legacy_state()
            self.watcher.side_effect = SPAWN_WATCHER
            with patch.object(D.subprocess, 'Popen', side_effect=OSError('fixture process creation failed')):
                result, error = self.dispatch('apply')
            self.assertEqual(result, 1)
            self.assertIn('process creation failed', error)
            state = self.saved()
            self.assertEqual(state['darwin_watcher']['phase'], 'starting')
            self.assertEqual(state['darwin_watcher_pid'], 0)
            lease = self.root/'run'/D._watcher_leaf(state['darwin_watcher'])
            self.assertTrue(lease.is_file())
            result, error = self.dispatch('force-off')
            self.assertEqual(result, 0, 'failed launch prevented exact owned cleanup: '+error)
            self.assertFalse(lease.exists())

    def test_failed_initial_watcher_publication_cleans_only_proved_unadopted_lease(self):
        for adopted in (False, True):
            with self.subTest(adopted=adopted), self.legacy_environment():
                self.legacy_state()
                self.watcher.side_effect = SPAWN_WATCHER
                original = D._write_watcher_state
                def fail(root, state):
                    if adopted:
                        original(root, state)
                    raise OSError('fixture initial lease publication failed')
                with patch.object(D, '_write_watcher_state', side_effect=fail), patch.object(D.subprocess, 'Popen') as spawn:
                    result, error = self.dispatch('apply')
                self.assertEqual(result, 1)
                self.assertIn('initial lease publication failed', error)
                spawn.assert_not_called()
                leases = list((self.root/'run').glob('darwin-watcher-*.lease'))
                self.assertEqual(len(leases), 1 if adopted else 0, 'failed lease publication lost its exact adoption/cleanup distinction')
                self.assertEqual('darwin_watcher' in self.saved(), adopted)
                result, error = self.dispatch('force-off')
                self.assertEqual(result, 0, error)
                self.assertEqual(list((self.root/'run').glob('darwin-watcher-*.lease')), [])

    def test_malformed_or_replaced_lease_never_clears_ownership(self):
        active, holder = self.captured_lease()
        self.addCleanup(os.close, holder)
        valid = active['darwin_watcher']
        mutations = ({'schema': True}, {'generation': '../other'}, {'device': False}, {'inode': 0},
                     {'inode': valid['inode']+1}, {'phase': 'unknown'}, {'phase': None}, {'extra': 1})
        for changed in mutations:
            current = {**active, 'darwin_watcher': {**valid, **changed}}
            self.private_json(self.root/'run/kill-switch.json', current)
            before = (self.root/'run/kill-switch.json').read_bytes()
            with self.subTest(changed=changed), self.legacy_environment(), patch.object(D.os, 'kill') as kill:
                result, error = self.dispatch('force-off')
            self.assertEqual(result, 1, 'malformed watcher lease authorized retirement')
            self.assertIn('watcher lease', error)
            self.assertEqual(kill.call_count, 0)
            self.assertEqual((self.root/'run/kill-switch.json').read_bytes(), before)
            self.assertEqual(self.commands, [])
            self.assertEqual(self.references, {'398', '999'})

    def test_pf_child_retains_both_locks_after_its_watcher_crashes(self):
        self._assert_child_retains_installed_locks('pfctl')

    def test_fixed_native_child_retains_installed_locks_after_its_watcher_crashes(self):
        self._assert_child_retains_installed_locks('native')

    def _assert_child_retains_installed_locks(self, kind):
        # The shipping watcher and run_pf really spawn processes here. Only
        # the PF executable and interface observations are fixture boundaries;
        # no command can reach the host's PF table.
        ready, finish, completed = (self.root/name for name in ('pf-ready.json', 'pf-finish', 'pf-completed'))
        fake_pf = self.root/'fixture-pfctl'
        fake_pf.write_text('#!'+sys.executable+'\n'+r'''
import fcntl,json,os,sys,time
from pathlib import Path
root=Path(__file__).parent
args=sys.argv[1:]
if args != ['--darwin-owned-pf','apply'] and (args[-2:] != ['-f','-'] or '-n' in args):
    raise SystemExit(0)
sys.stdin.read()
proof={'descriptors': [], 'error': ''}
try:
    for fd in json.loads((root/'pf-expected.json').read_text()):
        info=os.fstat(fd)
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        proof['descriptors'].append([info.st_dev,info.st_ino])
except OSError as error:
    proof['error']=str(error)
temporary=root/'pf-ready.tmp'
temporary.write_text(json.dumps(proof))
temporary.replace(root/'pf-ready.json')
if proof['error']:
    raise SystemExit(2)
deadline=time.monotonic()+6
while not (root/'pf-finish').exists():
    if time.monotonic()>=deadline:
        raise SystemExit(3)
    time.sleep(.01)
(root/'pf-completed').write_text('exact fixture PF mutation completed\n')
''')
        fake_pf.chmod(0o700)
        harness = r'''
import importlib.util,json,os,sys,types
from pathlib import Path
modes=Path(sys.argv[1]); binary=sys.argv[2]; kind=sys.argv[3]; arguments=sys.argv[4:]
sys.path.insert(0,str(modes))
spec=importlib.util.spec_from_file_location('real_child_dispatcher',modes/'kill-switch-platform.py')
D=importlib.util.module_from_spec(spec); spec.loader.exec_module(D)
P=D._darwin
root=Path(os.environ['HOMEVPN_ROOT'])
# Explicit portable fixture for the protected installation and root helper.
# Real no-follow opens, flock operations and child exec boundaries remain.
# No fixture override is accepted by production code or its environment.
uid,gid=os.getuid(),os.getgid()
proxy=types.SimpleNamespace(**vars(os)); proxy.getuid=lambda:0; proxy.geteuid=lambda:0
P.os=proxy; P._baseline.os=proxy
P._baseline.ROOT=root
P._baseline.INSTALL_LOCK=root/'fixture-install.lock'
P._baseline.CONTROLLER=Path(binary)
ancestors={(path.stat().st_dev,path.stat().st_ino) for path in root.parents}
actual_owner=P._baseline._owned_info
def fixture_owner(info, *, directory=False):
    if directory and (info.st_dev,info.st_ino) in ancestors:
        return True
    if info.st_uid!=uid or info.st_gid!=gid:
        return False
    scoped=types.SimpleNamespace(st_mode=info.st_mode,st_nlink=info.st_nlink,st_uid=0,st_gid=0)
    return actual_owner(scoped,directory=directory)
P._baseline._owned_info=fixture_owner
P.current_utuns=lambda:['utun9']
P.route_utuns=lambda:['utun9']
def pf_binary():
    (root/'pf-expected.json').write_text(json.dumps(P._baseline.process_authority_fds()))
    return binary
P._pfctl=pf_binary
if kind=='native':
    def native_refresh(*args,**kwargs):
        pf_binary()
        P._baseline._native('apply',b'{"fixture":"owned-child-lifetime"}')
        return {}
    P.apply_darwin=native_refresh
sys.argv=['fixture-dispatcher',*arguments]
raise SystemExit(D.main())
'''
        def command(argv):
            return [sys.executable, '-EsS', '-c', harness, str(HERE), str(fake_pf), kind, *argv[-3:]]
        def available(path, timeout=4):
            deadline = time.monotonic()+timeout
            while not path.exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertTrue(path.exists(), 'PF child did not retain its actual operation lifetime')
        self.addCleanup(finish.touch)
        with self.legacy_environment():
            self.legacy_state()
            child, active = self.start_real_watcher(command)
            self.addCleanup(finish.touch)
            available(ready)
            proof = json.loads(ready.read_text())
            self.assertEqual(proof['error'], '', 'PF child lost its captured lifetime or transaction descriptor')
            lease = self.root/'run'/D._watcher_leaf(active['darwin_watcher'])
            guard = self.root/'run/darwin-watcher-state.lock'
            locks = (lease, guard, self.root/'fixture-install.lock', self.root/'pf-state.lock')
            self.assertEqual(set(map(tuple, proof['descriptors'])),
                             {(path.stat().st_dev, path.stat().st_ino) for path in locks},
                             'PF child lost its captured lifetime or transaction descriptor')
            child.kill()  # captured, unreaped child created by this test
            child.wait(timeout=3)
            for path in locks:
                descriptor = os.open(path, os.O_RDWR)
                try:
                    with self.assertRaises(BlockingIOError, msg='crashed watcher released an in-flight PF child lock'):
                        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                finally:
                    os.close(descriptor)
            before, calls = self.saved(), list(self.commands)
            result, error = self.dispatch('force-off')
            self.assertEqual(result, 1, 'PF release overtook an in-flight orphaned operation')
            self.assertEqual(self.saved(), before)
            self.assertEqual(self.commands, calls)
            self.assertFalse(completed.exists())
            finish.touch()
            available(completed)
            deadline = time.monotonic()+3
            while True:
                try:
                    with D._watcher_state_guard(self.root):
                        break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        self.fail('completed PF child did not release its retained transaction')
                    time.sleep(0.01)
            result, error = self.dispatch('force-off')
            self.assertEqual(result, 0, 'captured child completion did not permit same-owner release: '+error)
            self.assertFalse(lease.exists())
            self.assertEqual(self.references, {'999'})
            self.assertEqual(self.rules['com.apple/foreign'], 'block out all\n')

    def test_nonroot_pf_explicitly_preserves_descriptors_or_fails_without_retry(self):
        # Exercise the real runner and argv with a policy-denying sudo fixture;
        # no UID change or actual privilege operation is involved.
        sudo = self.root/'fixture-sudo'
        evidence = self.root/'sudo-invocations.jsonl'
        sudo.write_text('#!'+sys.executable+'\n'+
                        'import json,sys\nfrom pathlib import Path\n'+
                        'with Path('+repr(str(evidence))+').open("a") as stream: stream.write(json.dumps(sys.argv[1:])+"\\n")\n'+
                        'print("fixture policy does not permit -C",file=sys.stderr)\nraise SystemExit(1)\n')
        sudo.chmod(0o700)
        state, lifetime = self.captured_lease()
        self.addCleanup(os.close, lifetime)
        with D._watcher_state_guard(self.root), P.pf_process_authority((lifetime,)), \
             patch.object(P.os, 'geteuid', return_value=501), patch.object(P.shutil, 'which', return_value=str(sudo)), \
             patch.object(P, '_pfctl', return_value='/fixture-only/pfctl'):
            descriptors = P._baseline.process_authority_fds()
            with self.assertRaisesRegex(RuntimeError, 'explicit -C descriptor preservation; no unpreserved retry'):
                RUN_PF(['-a', P.PF_ANCHOR, '-s', 'rules'])
        requests = [json.loads(line) for line in evidence.read_text().splitlines()]
        self.assertEqual(requests, [['-n', '-C', str(max(descriptors)+1), '/fixture-only/pfctl', '-a', P.PF_ANCHOR, '-s', 'rules']],
                         'owned PF command retried without its captured descriptors')
        self.assertEqual(self.saved(), state)
        self.assertEqual(self.rules[P.PF_ANCHOR], 'previous endpoint policy\n')

    def test_physical_retirement_failure_keeps_exact_native_cleanup(self):
        self.retire.side_effect = RuntimeError('physical address changed')
        with self.assertRaisesRegex(RuntimeError, 'physical address changed'):
            D.darwin_apply()
        saved = self.saved()
        self.assertEqual(saved['pf_token'], '417')
        self.assertTrue(saved['darwin_transition_pending'])
        self.assertFalse(saved[P._baseline.STATE_KEY]['complete'])
        self.assertIn('block drop out quick', self.rules[P.OWNED_PF_ANCHOR])
        self.assertNotIn(['-X', '417'], self.commands)
        self.assertEqual(D.darwin_release(True), 0)
        self.assertNotIn(P.OWNED_PF_ANCHOR, self.rules)
        self.assertEqual(self.commands[-1], ['-X', '417'])

    def test_failed_absence_never_releases_owned_reference(self):
        self.assertEqual(D.darwin_apply(), 0)
        original = self.native
        def fail_clear(phase, request):
            if phase == 'apply' and request['action'] == 'clear':
                raise RuntimeError('owned clear did not complete')
            return original(phase, request)
        with patch.object(P._baseline, '_invoke', side_effect=fail_clear):
            with self.assertRaisesRegex(RuntimeError, 'did not complete'):
                D.darwin_release(True)
        self.assertNotIn(['-X', '417'], self.commands)
        self.assertTrue((self.root/'run/kill-switch.json').exists())

    def test_other_owner_or_broad_endpoint_rejected_before_any_pf_operation(self):
        for override in ({'HOMEVPN_ENDPOINT': '198.51.100.44'},
                         {'HOMEVPN_NATIVE_ENDPOINTS_JSON': '["198.51.100.44"]'},
                         {'HOMEVPN_EXTERNAL_SESSION': 'a'*32}, {'HOMEVPN_TOR_SESSION': 'A'*32}):
            with self.subTest(override=override), patch.dict(os.environ, override):
                with self.assertRaises(RuntimeError):
                    D.darwin_apply()
            self.assertEqual(self.commands, [])
        for state in ({'darwin_pf_anchor': 'com.apple/foreign'},
                      {'native_socket_broker': True, 'darwin_previous_pf_anchor': 'com.apple/foreign'}):
            with self.subTest(state=state), self.assertRaises(RuntimeError):
                P.remove_darwin(state, dry_run=False)
            self.assertEqual(self.commands, [])

    def test_corrupt_state_cannot_adopt_a_present_native_namespace(self):
        poisoned = self.root/'run/kill-switch.json'
        raw = '{"incomplete":'
        for native_rules in ('old native owner\n', ''):
            with self.subTest(native_rules=native_rules):
                poisoned.write_text(raw)
                poisoned.chmod(0o600)
                self.rules = {P.PF_ANCHOR: 'old fixed owner\n', P.OWNED_PF_ANCHOR: native_rules}
                before = dict(self.rules)
                self.commands.clear()
                with patch.object(P, '_clear_anchor') as clear, self.assertRaisesRegex(RuntimeError, 'unreadable state cannot authorize'):
                    D.darwin_release(True)
                clear.assert_not_called()
                self.assertEqual(poisoned.read_text(), raw)
                self.assertEqual(self.rules, before)
                self.assertEqual(self.native_calls, [])
                self.assertFalse(any(row[:1] in (['-X'], ['-E']) for row in self.commands))

    def test_corrupt_state_force_off_requires_real_namespace_absence(self):
        poisoned = self.root/'run/kill-switch.json'
        raw = '{"incomplete":'
        actual = P.run_pf
        for fault in ('clear', 'legacy-readback', 'native-readback', 'empty-retained-namespace'):
            with self.subTest(fault=fault):
                poisoned.write_text(raw)
                poisoned.chmod(0o600)
                self.rules = {} if fault == 'native-readback' else {P.PF_ANCHOR: 'old fixed owner\n'}
                self.commands.clear()
                def failing(arguments, **kwargs):
                    if fault == 'clear' and arguments == ['-a', P.PF_ANCHOR, '-F', 'rules']:
                        self.assertTrue(kwargs.get('check'))
                        raise RuntimeError('owned clear failed')
                    if fault == 'legacy-readback' and arguments == ['-a', P.PF_ANCHOR, '-s', 'rules']:
                        raise RuntimeError('owned absence readback failed')
                    if fault == 'native-readback' and arguments == ['-a', P.OWNED_PF_ANCHOR, '-s', 'rules']:
                        raise RuntimeError('owned absence readback failed')
                    return actual(arguments, **kwargs)
                with patch.object(P, 'run_pf', side_effect=failing), self.assertRaises(RuntimeError):
                    D.darwin_release(True)
                self.assertEqual(poisoned.read_text(), raw, 'failed Off discarded its only recovery record')
                self.assertFalse(any(row[:1] in (['-X'], ['-E']) for row in self.commands), 'corrupt state guessed a PF reference')
                # Only an independently absent pair can complete recovery. An
                # empty rules string alone must retain the actual old namespace.
                self.rules.clear()
                self.assertEqual(D.darwin_release(True), 0)
                self.assertFalse(poisoned.exists())
                for anchor in (P.PF_ANCHOR, P.OWNED_PF_ANCHOR):
                    self.assertIn(['-a', anchor, '-s', 'rules'], self.commands)
                self.assertFalse(any(row[:1] in (['-X'], ['-E']) for row in self.commands))

    def test_state_capture_includes_other_adapters_and_temporary_ipv6(self):
        # Use the original code loaded in a separate module, without replacing
        # state capture, to exercise the real ifconfig parser off-host.
        spec = importlib.util.spec_from_file_location('darwin_owned_physical_parser', HERE/'darwin_kill_switch.py')
        physical = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(physical)
        listing = '''lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
\tinet 127.0.0.1 netmask 0xff000000
utun1: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1500
\tinet6 fd00::1 prefixlen 64
 en-invalid line
 en1-invalid
 en2-invalid
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tinet 192.0.2.1 netmask 0xffffff00
\tinet6 2001:db8::1 prefixlen 64
\tinet6 2001:db8::2 prefixlen 64 autoconf temporary
en1: flags=8863<UP,BROADCAST,RUNNING,MULTICAST> mtu 1500
\tinet 198.51.100.3 netmask 0xffffff00
'''
        with patch.object(physical, '_command_output', return_value=listing):
            self.assertEqual(physical.physical_state_interfaces(), {'en0': ['192.0.2.1', '2001:db8::1', '2001:db8::2'], 'en1': ['198.51.100.3']})
        captured = {'en0': ['192.0.2.1', '2001:db8::1', '2001:db8::2'], 'en1': ['198.51.100.3']}
        commands = []
        with patch.object(physical, 'physical_state_interfaces', return_value=captured), \
             patch.object(physical, 'run_pf', side_effect=lambda argv: commands.append(argv)):
            physical.retire_physical_states(captured)
        self.assertIn(['-k', '::/0', '-k', '2001:db8::2'], commands)
        self.assertIn(['-k', '0.0.0.0/0', '-k', '198.51.100.3'], commands)
        self.assertNotIn(['-F', 'states'], commands)
        self.assertFalse(any('lo0' in command or 'utun1' in command for command in commands))


class DarwinStatefulComposition(unittest.TestCase):
    def test_stock_scrub_dispatch_preserves_first_filter_and_negative_controls(self):
        anchor = 'anchor "com.apple/*" all\n'
        scrub = 'scrub-anchor "com.apple/*" all fragment reassemble\n'
        for raw in (anchor, scrub+anchor, scrub+anchor+'block out on utun42 all\n'):
            with self.subTest(valid=raw):
                P._owned_system_filters(raw)
        for raw in ('', scrub, anchor.replace(' all', ' out'),
                    'pass out all no state\n'+anchor,
                    scrub.replace('com.apple', 'foreign')+anchor,
                    scrub.replace('reassemble', 'crop')+anchor,
                    scrub+scrub+anchor, anchor+scrub,
                    scrub+anchor+'pass out all keep state\n'):
            with self.subTest(invalid=raw), self.assertRaises(RuntimeError):
                P._owned_system_filters(raw)

    def test_root_owned_and_foreign_translation_or_stateful_owners_are_rejected(self):
        spec = importlib.util.spec_from_file_location('darwin_owned_composition_test', HERE/'darwin_kill_switch.py')
        policy = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(policy)
        for fault in ('none', 'root-nat', 'owned-nat', 'owned-child-nat', 'root-anchor-nat', 'root-anchor-in-state', 'foreign-out-state', 'earlier-filter', 'legacy-slot', 'legacy-generation'):
            seen = []
            def run(arguments, **kwargs):
                seen.append(arguments)
                anchor = arguments[1] if arguments[:1] == ['-a'] else ''
                command = arguments[2:] if anchor else arguments
                output = ''
                if command == ['-s', 'rules']:
                    if not anchor:
                        output = 'anchor "com.apple/*" all\nanchor "foreign/*" all\n'
                    elif anchor == 'foreign/*':
                        output = 'pass in all keep state\n' if fault == 'root-anchor-in-state' else 'block out on utun42 all\n'
                    elif anchor == 'com.apple/zzz.foreign':
                        output = 'pass out all keep state\n' if fault == 'foreign-out-state' else 'block out on utun43 all\n'
                    elif anchor == 'com.apple/000.before' and fault == 'earlier-filter':
                        output = 'pass out all no state\n'
                    elif (anchor == policy.OWNED_PF_ANCHOR+'/physical' and fault == 'legacy-slot'
                          or anchor == policy.OWNED_PF_ANCHOR+'/physical/legacy' and fault == 'legacy-generation'):
                        output = 'block out on lo0 all\n'
                elif command == ['-s', 'Anchors']:
                    if not anchor:
                        output = 'com.apple\nforeign\n'
                    elif anchor == 'com.apple':
                        output = '000.before\n000.router-vpn\nzzz.foreign\n'
                    elif anchor == policy.OWNED_PF_ANCHOR and fault in ('legacy-slot', 'legacy-generation'):
                        output = 'physical\n'
                    elif anchor == policy.OWNED_PF_ANCHOR+'/physical' and fault == 'legacy-generation':
                        output = '  '+anchor+'/legacy\n'
                elif command == ['-s', 'nat']:
                    bad = {'root-nat': '', 'owned-nat': policy.OWNED_PF_ANCHOR,
                           'owned-child-nat': policy.OWNED_PF_ANCHOR+'/*', 'root-anchor-nat': 'foreign/*'}
                    if fault in bad and anchor == bad[fault]:
                        output = 'nat on en0 from any to any -> (en0)\n'
                else:
                    raise AssertionError('preflight attempted an unscoped mutation '+repr(arguments))
                return subprocess.CompletedProcess(arguments, 0, output, '')
            with self.subTest(fault=fault), patch.object(policy, 'run_pf', side_effect=run):
                if fault == 'none':
                    policy.owned_pf_preflight({})
                    self.assertIn(['-a', 'foreign/*', '-s', 'rules'], seen)
                else:
                    with self.assertRaises(RuntimeError):
                        policy.owned_pf_preflight({})
            self.assertFalse(any('-F' in row or '-k' in row or '-f' in row for row in seen))

    def test_legacy_inventory_reads_unreferenced_children_without_mutation(self):
        root = P.OWNED_PF_ANCHOR+'/physical'
        for retained in (False, True):
            seen = []
            def run(arguments):
                anchor = arguments[1] if arguments[:1] == ['-a'] else ''
                command = arguments[2:] if anchor else arguments
                parents = {'': 'com.apple\n', 'com.apple': '000.router-vpn\n', P.OWNED_PF_ANCHOR: 'physical\n'}
                self.assertTrue(anchor in parents or anchor == root or anchor.startswith(root+'/'))
                self.assertIn(command, (['-s', 'rules'], ['-s', 'Anchors']))
                seen.append(arguments)
                output = ''
                if command == ['-s', 'Anchors']:
                    output = (parents | {root: '  '+root+'/previous\n', root+'/previous': 'generation\n'}).get(anchor, '')
                elif anchor == root+'/previous/generation' and retained:
                    output = 'block out on lo0 all\n'
                return subprocess.CompletedProcess(arguments, 0, output, '')
            with self.subTest(retained=retained), patch.object(P, 'run_pf', side_effect=run):
                if retained:
                    with self.assertRaisesRegex(RuntimeError, 'earlier nested physical owner'):
                        P._owned_reject_legacy_layout()
                else:
                    P._owned_reject_legacy_layout()
            self.assertEqual([row[1] for row in seen if row[2:] == ['-s', 'rules']],
                             [root, root+'/previous', root+'/previous/generation'])

    def test_legacy_inventory_rejects_escape_ambiguity_and_excess(self):
        root = P.OWNED_PF_ANCHOR+'/physical'
        for raw in ('../other', 'other/child', '/foreign/child', root, root+'/child/deeper',
                    '.', '..', '*', 'child\nchild', 'child\n'+root+'/child', 'child with spaces',
                    'x'*(64*1024+1), '\n'.join('child'+str(i) for i in range(257))):
            def run(arguments):
                self.assertEqual(arguments[1], root)
                output = raw if arguments[2:] == ['-s', 'Anchors'] else ''
                return subprocess.CompletedProcess(arguments, 0, output, '')
            with self.subTest(raw=raw[:80]), patch.object(P, 'run_pf', side_effect=run):
                with self.assertRaises(RuntimeError):
                    P._owned_legacy_children(root)
        queries = []
        def deep(arguments):
            output = ''
            anchor = arguments[1] if arguments[:1] == ['-a'] else ''
            command = arguments[2:] if anchor else arguments
            if command == ['-s', 'Anchors']:
                parents = {'': 'com.apple\n', 'com.apple': '000.router-vpn\n', P.OWNED_PF_ANCHOR: 'physical\n'}
                if anchor in parents:
                    output = parents[anchor]
                else:
                    queries.append(anchor)
                    output = 'child\n'
            return subprocess.CompletedProcess(arguments, 0, output, '')
        with patch.object(P, 'run_pf', side_effect=deep), self.assertRaisesRegex(RuntimeError, 'bounded tree'):
            P._owned_reject_legacy_layout()
        self.assertEqual(len(queries), 9)

    def test_missing_legacy_tree_is_proved_from_existing_parents(self):
        root = P.OWNED_PF_ANCHOR+'/physical'
        parents = {'': 'com.apple\n', 'com.apple': '000.router-vpn\n', P.OWNED_PF_ANCHOR: 'physical\n'}
        for missing_parent in parents:
            seen = []
            def run(arguments):
                anchor = arguments[1] if arguments[:1] == ['-a'] else ''
                command = arguments[2:] if anchor else arguments
                self.assertEqual(command, ['-s', 'Anchors'])
                self.assertIn(anchor, parents)
                seen.append(anchor)
                return subprocess.CompletedProcess(arguments, 0, '' if anchor == missing_parent else parents[anchor], '')
            with self.subTest(parent=missing_parent), patch.object(P, 'run_pf', side_effect=run):
                P._owned_reject_legacy_layout()
            self.assertEqual(seen[-1], missing_parent)

    def test_same_shipping_prelaunch_witness_accepts_only_its_actual_unix_capture(self):
        wrapper_spec = importlib.util.spec_from_file_location('darwin_owned_wrapper_fixture', HERE.parent/'deploy/test_desktop_tor_unix_wrapper.py')
        wrapper = importlib.util.module_from_spec(wrapper_spec)
        wrapper_spec.loader.exec_module(wrapper)
        spec = importlib.util.spec_from_file_location('darwin_owned_witness', HERE/'tor-prelaunch-witness.py')
        witness = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(witness)
        for target in ('linux', 'darwin'):
            for transport in ('tor', 'meek', 'snowflake', 'webtunnel', 'mixed'):
                with self.subTest(target=target, transport=transport), tempfile.TemporaryDirectory() as directory, patch.object(witness.sys, 'platform', target):
                    fixture = wrapper.Fixture(Path(directory))
                    fixture.physical_broker(transport)
                    with patch.dict(os.environ, fixture.env, clear=True):
                        witness.validate_launch(str(fixture.runtime), '', str(fixture.tor))
                        capture = json.loads(fixture.inputs['tor-capture.json'])
                        capture['target_os'] = 'darwin' if target == 'linux' else 'linux'
                        fixture.set_input('tor-capture.json', capture)
                    with patch.dict(os.environ, fixture.env, clear=True), self.assertRaises(ValueError):
                        witness.validate_launch(str(fixture.runtime), '', str(fixture.tor))


if __name__ == '__main__':
    unittest.main(verbosity=2)
