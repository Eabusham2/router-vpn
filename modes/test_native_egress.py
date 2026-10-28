#!/usr/bin/env python3
"""Exercise shipping tuple parsing and nft/PF commands without a live firewall."""
from __future__ import annotations

import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import sys
import tempfile
from unittest import mock

HERE = Path(__file__).resolve().parent


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


linux = load('egress_linux_fixture', 'kill-switch.py')
darwin = load('egress_darwin_fixture', 'kill-switch-platform.py')
hosts = ['203.0.113.20', '203.0.113.21', '2001:db8::20']
addresses = [ipaddress.ip_address(value) for value in hosts]
tuples = [dict(host=hosts[0], port=8388, network='udp'),
          dict(host=hosts[1], port=8390, network='tcp'),
          dict(host=hosts[2], port=8389, network='udp')]
raw = json.dumps(tuples, separators=(',', ':'))
authority = dict(HOMEVPN_STANDARD_ENGINE='native', HOMEVPN_EXTERNAL_SESSION='a' * 32,
                 HOMEVPN_NATIVE_ENDPOINTS_JSON=json.dumps(hosts), HOMEVPN_NATIVE_EGRESS_JSON=raw)

with mock.patch.dict(os.environ, authority), mock.patch('socket.getaddrinfo') as resolver:
    assert linux.captured_native_egress(addresses) == tuples
    invalid = ['null', '{}', '[]', raw.replace('8388', '0'), raw.replace('8388', '65536'),
               raw.replace('8388', '8388.0'), raw.replace('8388', '"8388"'),
               raw.replace('8388', 'true'), raw.replace('"udp"', '"UDP"'),
               raw.replace('"udp"', '"icmp"'), raw.replace(hosts[0], 'vpn.example.test'),
               raw.replace(hosts[0], '203.0.113.22'),
               raw.replace('"port":8388', '"port":8388,"port":8389'),
               raw.replace('"port":8388', '"port":8388,"extra":true'),
               json.dumps(tuples[:1]), json.dumps(tuples + tuples), json.dumps([tuples]),
               ' ' * 4097]
    for value in invalid:
        with mock.patch.dict(os.environ, {'HOMEVPN_NATIVE_EGRESS_JSON': value}):
            try:
                linux.captured_native_egress(addresses)
            except RuntimeError:
                pass
            else:
                raise AssertionError('malformed native egress was accepted')
    for override in ({'HOMEVPN_STANDARD_ENGINE': 'openvpn'}, {'HOMEVPN_EXTERNAL_SESSION': ''},
                     {'HOMEVPN_EXTERNAL_SESSION': 'A' * 32}):
        with mock.patch.dict(os.environ, override):
            try:
                linux.captured_native_egress(addresses)
            except RuntimeError:
                pass
            else:
                raise AssertionError('unowned native egress was accepted')
    resolver.assert_not_called()


def check_rules(text, platform):
    assert '8388' in text and '8390' in text and '8389' in text, text
    if platform == 'linux':
        assert 'ip daddr 203.0.113.20 udp dport 8388 accept' in text
        assert 'ip daddr 203.0.113.21 tcp dport 8390 accept' in text
        assert 'ip6 daddr 2001:db8::20 udp dport 8389 accept' in text
        assert 'ip daddr { 203.0.113.20' not in text and 'ip6 daddr { 2001:db8::20' not in text
        assert 'policy drop' in text
    else:
        assert 'inet proto udp to 203.0.113.20 port 8388' in text
        assert 'inet proto tcp to 203.0.113.21 port 8390' in text
        assert 'inet6 proto udp to 2001:db8::20 port 8389' in text
        assert 'inet to { 203.0.113.20' not in text and 'inet6 to { 2001:db8::20' not in text
        assert 'block drop out quick all' in text
    assert 'port 1194' not in text and 'port 443' not in text
    assert '192.168.0.0/16' not in text and 'fc00::/7' not in text


check_rules(linux.render_rules(addresses, False, False, tuples), 'linux')
check_rules(darwin._darwin.render_pf_rules(addresses, False, [], tuples), 'darwin')

# Execute the real apply/reassert/release functions and their subprocess
# command boundary. Only nft, pfctl and sudo are private test executables.
# They record exactly the supplied rules and cannot change a real firewall.
fake = r'''#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
name = Path(sys.argv[0]).name
args = sys.argv[1:]
if name == 'sudo':
    assert args[0] == '-n'
    os.execv(args[1], args[1:])
rules = ''
if '-f' in args:
    source = args[args.index('-f') + 1]
    rules = sys.stdin.read() if source == '-' else Path(source).read_text()
with open(os.environ['ROUTERVPN_EGRESS_COMMAND_LOG'], 'a') as output:
    output.write(json.dumps(dict(tool=name, args=args, rules=rules)) + '\n')
if name == 'nft' and args[:2] == ['list', 'table']:
    sys.exit(1)
if name == 'pfctl' and args == ['-E']:
    print('Token : 123456')
'''

for platform in ('linux', 'darwin'):
    with tempfile.TemporaryDirectory(prefix='routervpn-egress-') as directory:
        root = Path(directory)
        (root / 'run').mkdir(mode=0o700)
        binary = root / 'bin'
        binary.mkdir(mode=0o700)
        for name in ('nft', 'pfctl', 'sudo'):
            path = binary / name
            path.write_text(fake)
            path.chmod(0o700)
        store = root / 'routers.json'
        # The captured ordinary entry owns physical sockets. The separately
        # saved Tor exit owns strict protection and LAN policy; the selected
        # unrelated profile and the entry's independent defaults grant none.
        store.write_text(json.dumps(dict(selected_id='unrelated', profiles=[dict(
            id='physical', node_kind='external', endpoint=hosts[0],
            external=dict(protocol='openvpn', expected_public_ip='203.0.113.88'),
            kill_switch_policy='off', home_lan_access=True), dict(
            id='tor-exit', node_kind='external', endpoint='198.51.100.44',
            external=dict(protocol='tor-bridge'), kill_switch_policy='always', home_lan_access=False,
            multihop_enabled=True, multihop_entry_id='physical', multihop_exit_id='tor-exit', multihop_execution='local'), dict(
            id='unrelated', endpoint='198.51.100.99', kill_switch_policy='off', home_lan_access=True)])))
        store.chmod(0o600)
        log = root / 'commands.jsonl'
        env = dict(authority, HOMEVPN_ROOT=str(root), HOMEVPN_PROFILE_ID='physical',
                   HOMEVPN_POLICY_PROFILE_ID='tor-exit', HOMEVPN_ENDPOINT=hosts[0],
                   HOMEVPN_KILLSWITCH_DRY_RUN='0', PATH=str(binary) + os.pathsep + os.environ['PATH'],
                   ROUTERVPN_EGRESS_COMMAND_LOG=str(log), HOMEVPN_KILLSWITCH_DARWIN_UTUNS='',
                   HOMEVPN_KILLSWITCH_DARWIN_PHYSICAL_INTERFACES='en0')
        with mock.patch.dict(os.environ, env), mock.patch.object(darwin, '_spawn_watcher', return_value=0):
            apply = linux.apply if platform == 'linux' else darwin.darwin_apply
            reassert = linux.reassert if platform == 'linux' else darwin.darwin_reassert
            release = linux.release if platform == 'linux' else darwin.darwin_release
            assert apply() == 0
            state_path = root / 'run' / 'kill-switch.json'
            state = json.loads(state_path.read_text())
            assert state['native_egress'] == tuples and state['endpoint_ips'] == hosts
            assert state['policy'] == 'always' and state['profile_id'] == 'physical'
            assert state['policy_profile_id'] == 'tor-exit' and not state['home_lan_access']
            commands = [json.loads(line) for line in log.read_text().splitlines()]
            written = [entry for entry in commands if entry['rules']]
            assert len(written) == 2, commands
            for entry in written:
                check_rules(entry['rules'], platform)

            # A newly supplied malformed tuple cannot mutate the old guard.
            before_state, before_commands = state_path.read_bytes(), log.read_bytes()
            os.environ['HOMEVPN_NATIVE_EGRESS_JSON'] = raw.replace('8388', '0')
            try:
                apply()
            except RuntimeError:
                pass
            else:
                raise AssertionError('invalid tuple reached firewall apply')
            assert state_path.read_bytes() == before_state and log.read_bytes() == before_commands

            # Reassert owns its persisted policy and discards inherited inputs.
            # It must retain exact port restrictions, not return to host-wide
            # permissions when the original native process no longer runs.
            os.environ['HOMEVPN_EXTERNAL_SESSION'] = ''
            assert reassert() == 0
            assert json.loads(state_path.read_text())['native_egress'] == tuples
            assert release() == 0
            assert json.loads(state_path.read_text())['native_egress'] == tuples
            for entry in [json.loads(line) for line in log.read_text().splitlines()]:
                if entry['rules']:
                    check_rules(entry['rules'], platform)

            # Corrupted retained tuples are not interpreted as legacy policy.
            broken = json.loads(state_path.read_text())
            broken['native_egress'][0]['port'] = 0
            state_path.write_text(json.dumps(broken))
            before_commands = log.read_bytes()
            try:
                reassert()
            except RuntimeError:
                pass
            else:
                raise AssertionError('corrupt retained tuples widened persistent guard')
            assert log.read_bytes() == before_commands

            # On-connect can release only its captured guard. It must use the
            # same bounded sockets even when both non-owning profiles allow LAN.
            state_path.write_bytes(before_state)
            profiles = json.loads(store.read_text())
            profiles['profiles'][1]['kill_switch_policy'] = 'on-connect'
            store.write_text(json.dumps(profiles))
            os.environ.update(authority)
            assert apply() == 0
            state = json.loads(state_path.read_text())
            assert state['policy'] == 'on-connect' and state['native_egress'] == tuples
            assert state['policy_profile_id'] == 'tor-exit' and not state['home_lan_access']
            assert release() == 0 and not state_path.exists()
            for entry in [json.loads(line) for line in log.read_text().splitlines()]:
                if entry['rules']:
                    check_rules(entry['rules'], platform)

def check_fixed_bridge_rules(text, platform, expected):
    for item in expected:
        address = ipaddress.ip_address(item['host'])
        if platform == 'linux':
            family = 'ip' if address.version == 4 else 'ip6'
            assert f"{family} daddr {address} tcp dport {item['port']} accept" in text, text
            assert f'{family} daddr {{ {address}' not in text, text
            assert f'{family} daddr {address} udp ' not in text, text
        else:
            family = 'inet' if address.version == 4 else 'inet6'
            assert f"{family} proto tcp to {address} port {item['port']}" in text, text
            assert f'{family} to {{ {address}' not in text, text
            assert f'{family} proto udp to {address}' not in text, text
    assert 'policy drop' in text if platform == 'linux' else 'block drop out quick all' in text
    for forbidden in ('1.1.1.1', '9.9.9.9', '192.168.0.0/16', 'fc00::/7'):
        assert forbidden not in text, text


# Direct Tor uses the same retained, bounded tuple owner as a predecessor.
# The shipping prelaunch witness independently derives these tuples from all
# captured bridge credentials; this test executes the actual nft/PF handoff,
# renewal and release without ever installing a host firewall.
for platform in ('linux', 'darwin'):
    for count in (1, 2, 8):
        with tempfile.TemporaryDirectory(prefix='routervpn-direct-egress-') as directory:
            root = Path(directory)
            (root / 'run').mkdir(mode=0o700)
            binary = root / 'bin'
            binary.mkdir(mode=0o700)
            for name in ('nft', 'pfctl', 'sudo'):
                path = binary / name
                path.write_text(fake)
                path.chmod(0o700)
            captured = [dict(host=(f'2001:db8::{50 + i}' if (i + count) % 2 else f'198.51.100.{50 + i}'),
                             port=8443 + i, network='tcp') for i in range(count)]
            captured_hosts = [item['host'] for item in captured]
            profile = dict(id='tor-direct', node_kind='external', endpoint=captured_hosts[0],
                           external=dict(protocol='tor-bridge'), kill_switch_policy='always', home_lan_access=False)
            store = root / 'routers.json'
            store.write_text(json.dumps(dict(selected_id='unrelated', profiles=[profile, dict(
                id='unrelated', endpoint='203.0.113.99', kill_switch_policy='off', home_lan_access=True)])))
            store.chmod(0o600)
            log = root / 'commands.jsonl'
            env = dict(HOMEVPN_ROOT=str(root), HOMEVPN_PROFILE_ID=profile['id'],
                       HOMEVPN_POLICY_PROFILE_ID=profile['id'], HOMEVPN_ENDPOINT=captured_hosts[0],
                       HOMEVPN_STANDARD_ENGINE='native', HOMEVPN_EXTERNAL_SESSION='b' * 32,
                       HOMEVPN_NATIVE_ENDPOINTS_JSON=json.dumps(captured_hosts),
                       HOMEVPN_NATIVE_EGRESS_JSON=json.dumps(captured), HOMEVPN_KILLSWITCH_DRY_RUN='0',
                       PATH=str(binary) + os.pathsep + os.environ['PATH'],
                       ROUTERVPN_EGRESS_COMMAND_LOG=str(log), HOMEVPN_KILLSWITCH_DARWIN_UTUNS='',
                       HOMEVPN_KILLSWITCH_DARWIN_PHYSICAL_INTERFACES='en0')
            with mock.patch.dict(os.environ, env), mock.patch.object(darwin, '_spawn_watcher', return_value=0):
                apply = linux.apply if platform == 'linux' else darwin.darwin_apply
                reassert = linux.reassert if platform == 'linux' else darwin.darwin_reassert
                release = linux.release if platform == 'linux' else darwin.darwin_release
                state_path = root / 'run' / 'kill-switch.json'
                assert apply() == 0
                state = json.loads(state_path.read_text())
                assert state['profile_id'] == profile['id'] == state['policy_profile_id']
                assert state['native_egress'] == captured and state['endpoint_ips'] == captured_hosts
                assert state['policy'] == 'always' and not state['home_lan_access']
                before_state, before_commands = state_path.read_bytes(), log.read_bytes()
                for broken in (captured + captured, [dict(captured[0], port=0)],
                               captured + [dict(host='1.1.1.1', port=443, network='tcp')]):
                    os.environ['HOMEVPN_NATIVE_EGRESS_JSON'] = json.dumps(broken)
                    try:
                        apply()
                    except RuntimeError:
                        pass
                    else:
                        raise AssertionError('malformed replacement changed a Direct Tor guard')
                    assert state_path.read_bytes() == before_state and log.read_bytes() == before_commands
                # A renewal and Always disconnect may not adopt caller-supplied
                # extra sockets or lose any of the original exact TCP ports.
                os.environ['HOMEVPN_EXTERNAL_SESSION'] = ''
                assert reassert() == 0 and release() == 0
                assert json.loads(state_path.read_text())['native_egress'] == captured
                written = [json.loads(line) for line in log.read_text().splitlines() if json.loads(line)['rules']]
                assert len(written) == (4 if platform == 'linux' else 6)
                for entry in written:
                    check_fixed_bridge_rules(entry['rules'], platform, captured)
                # A new owned capture replaces all old ports atomically at the
                # backend boundary. On-connect tears down its dedicated guard.
                replacement = [dict(item, port=item['port'] + 100) for item in captured]
                profile['kill_switch_policy'] = 'on-connect'
                store.write_text(json.dumps(dict(selected_id='unrelated', profiles=[profile, dict(
                    id='unrelated', endpoint='203.0.113.99', kill_switch_policy='off', home_lan_access=True)])))
                os.environ.update(env)
                os.environ['HOMEVPN_NATIVE_EGRESS_JSON'] = json.dumps(replacement)
                assert apply() == 0
                state = json.loads(state_path.read_text())
                assert state['policy'] == 'on-connect' and state['native_egress'] == replacement
                commands = [json.loads(line) for line in log.read_text().splitlines()]
                for entry in [entry for entry in commands if entry['rules']][-2:]:
                    check_fixed_bridge_rules(entry['rules'], platform, replacement)
                    for item in captured:
                        assert f"port {item['port']}" not in entry['rules']
                assert release() == 0 and not state_path.exists()

print('PASS native tuple parsing and actual nft/PF command boundaries, persisted reassert, Direct obfs4 1/2/8 exact TCP guards and malformed replacement rejection')
