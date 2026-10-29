#!/usr/bin/env python3
"""Exercise the shipping Darwin dispatcher without touching the host PF table."""
from pathlib import Path
import contextlib
import importlib.util
import json
import os
import subprocess
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('darwin_owned_dispatch_test', HERE/'kill-switch-platform.py')
D = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(D)
P = D._darwin


class OwnedDarwinPF(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='darwin-owned-policy-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
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
        self.fail_after_load = False
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.dict(os.environ, self.env))
        self.stack.enter_context(patch.object(D.sys, 'platform', 'darwin'))
        self.stack.enter_context(patch.object(P, 'run_pf', side_effect=self.pf))
        self.stack.enter_context(patch.object(P, 'owned_pf_preflight'))
        self.stack.enter_context(patch.object(P, 'physical_state_interfaces', return_value={'en0': ['192.0.2.1', '2001:db8::1']}))
        self.retire = self.stack.enter_context(patch.object(P, 'retire_physical_states'))
        self.watcher = self.stack.enter_context(patch.object(D, '_spawn_watcher'))
        self.resolver = self.stack.enter_context(patch('socket.getaddrinfo', side_effect=AssertionError('pre-tunnel DNS')))

    @staticmethod
    def private_json(path, value):
        path.write_text(json.dumps(value)+'\n')
        path.chmod(0o600)

    def saved(self):
        return json.loads((self.root/'run/kill-switch.json').read_text())

    def pf(self, arguments, *, check=True, input_text=None):
        self.commands.append(list(arguments))
        result = ''
        if arguments == ['-E']:
            result = 'Token : 417\n'
        elif arguments[:1] == ['-X']:
            pass
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
            else:
                self.fail('unexpected PF fixture operation '+repr(arguments))
        else:
            self.fail('unexpected PF fixture operation '+repr(arguments))
        return subprocess.CompletedProcess(arguments, 0, result, '')

    def test_actual_dispatch_captures_empty_baseline_and_reasserts_without_session(self):
        self.assertEqual(D.darwin_apply(), 0)
        state = self.saved()
        self.assertTrue(state['native_socket_broker'])
        self.assertEqual(state['endpoint_ips'], [])
        self.assertEqual(state['endpoint'], '')
        self.assertEqual(state['pf_token'], '417')
        self.assertNotIn('darwin_transition_pending', state)
        self.assertNotIn('native_egress', state)
        self.assertNotIn('a'*32, json.dumps(state))
        self.assertNotIn('b'*64, json.dumps(state))
        active = self.rules[P.OWNED_PF_ANCHOR]
        self.assertIn('anchor "physical/'+'a'*32+'" out', active)
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
        self.assertEqual(self.rules[P.OWNED_PF_ANCHOR], '')

    def test_state_write_failure_balances_new_reference_without_filter_mutation(self):
        with patch.object(D._linux, 'write_state', side_effect=RuntimeError('private state write rejected')):
            with self.assertRaisesRegex(RuntimeError, 'private state write rejected'):
                D.darwin_apply()
        self.assertEqual(self.rules, {})
        self.assertIn(['-X', '417'], self.commands)
        self.assertFalse((self.root/'run/kill-switch.json').exists())

    def test_state_retirement_failure_keeps_cleanup_for_both_owned_anchors(self):
        prior = D._darwin_state_base('direct-tor', 'direct-tor', '198.51.100.44', [], False, 'always')
        prior.update(pf_token='398', darwin_pf_anchor=P.PF_ANCHOR)
        self.private_json(self.root/'run/kill-switch.json', prior)
        self.rules[P.PF_ANCHOR] = 'previous endpoint policy\n'
        self.retire.side_effect = RuntimeError('physical address changed')
        with self.assertRaisesRegex(RuntimeError, 'physical address changed'):
            D.darwin_apply()
        saved = self.saved()
        self.assertEqual(saved['pf_token'], '398')
        self.assertEqual(saved['darwin_pf_anchor'], P.OWNED_PF_ANCHOR)
        self.assertEqual(saved['darwin_previous_pf_anchor'], P.PF_ANCHOR)
        self.assertNotIn(['-E'], self.commands)
        self.assertNotIn(['-X', '398'], self.commands)
        self.assertEqual(D.darwin_release(True), 0)
        self.assertEqual(self.rules[P.PF_ANCHOR], '')
        self.assertEqual(self.rules[P.OWNED_PF_ANCHOR], '')
        self.assertEqual(self.commands[-1], ['-X', '398'])

    def test_failed_absence_never_releases_owned_reference(self):
        self.assertEqual(D.darwin_apply(), 0)
        original = P.run_pf
        def fail_clear(arguments, **kwargs):
            if arguments[-2:] == ['-F', 'rules']:
                raise RuntimeError('owned clear did not complete')
            return original(arguments, **kwargs)
        with patch.object(P, 'run_pf', side_effect=fail_clear):
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

    def test_corrupt_state_force_off_requires_both_actual_absence_readbacks(self):
        poisoned = self.root/'run/kill-switch.json'
        raw = '{"incomplete":'
        actual = P.run_pf
        for fault in ('first-clear', 'second-clear', 'first-readback', 'second-readback', 'first-present', 'second-present'):
            with self.subTest(fault=fault):
                poisoned.write_text(raw)
                poisoned.chmod(0o600)
                self.rules = {P.PF_ANCHOR: 'old fixed owner\n', P.OWNED_PF_ANCHOR: 'old native owner\n'}
                self.commands.clear()
                def failing(arguments, **kwargs):
                    selected = P.PF_ANCHOR if fault.startswith('first') else P.OWNED_PF_ANCHOR
                    if arguments[:2] == ['-a', selected]:
                        if fault.endswith('clear') and arguments[2:] == ['-F', 'rules']:
                            self.assertTrue(kwargs.get('check'))
                            raise RuntimeError('owned clear failed')
                        if fault.endswith('readback') and arguments[2:] == ['-s', 'rules']:
                            raise RuntimeError('owned absence readback failed')
                        if fault.endswith('present') and arguments[2:] == ['-s', 'rules']:
                            return subprocess.CompletedProcess(arguments, 0, 'block out all\n', '')
                    return actual(arguments, **kwargs)
                with patch.object(P, 'run_pf', side_effect=failing), self.assertRaises(RuntimeError):
                    D.darwin_release(True)
                self.assertEqual(poisoned.read_text(), raw, 'failed Off discarded its only recovery record')
                self.assertFalse(any(row[:1] in (['-X'], ['-E']) for row in self.commands), 'corrupt state guessed a PF reference')
                self.assertEqual(D.darwin_release(True), 0)
                self.assertFalse(poisoned.exists())
                self.assertEqual(self.rules, {P.PF_ANCHOR: '', P.OWNED_PF_ANCHOR: ''})
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
    def test_root_owned_and_foreign_translation_or_stateful_owners_are_rejected(self):
        spec = importlib.util.spec_from_file_location('darwin_owned_composition_test', HERE/'darwin_kill_switch.py')
        policy = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(policy)
        for fault in ('none', 'root-nat', 'owned-nat', 'owned-child-nat', 'root-anchor-nat', 'root-anchor-in-state', 'foreign-out-state', 'earlier-filter'):
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
                elif command == ['-s', 'Anchors']:
                    output = 'com.apple\nforeign\n' if not anchor else '000.before\n000.router-vpn\nzzz.foreign\n'
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
