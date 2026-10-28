#!/usr/bin/env python3
from __future__ import annotations
import importlib.util, json, os, pathlib, subprocess, sys, tempfile

SCRIPT=pathlib.Path(__file__).with_name('kill-switch.py')
spec=importlib.util.spec_from_file_location('router_vpn_killswitch',SCRIPT);mod=importlib.util.module_from_spec(spec);assert spec and spec.loader;spec.loader.exec_module(mod)

# Input validation must not touch DNS before the strict firewall is installed,
# including diagnostic/error formatting. This contract is entirely offline.
from unittest import mock
with mock.patch('socket.getaddrinfo', return_value=[]) as resolver:
    for endpoint in ('example.com', 'vpn.example.test', '203.0.113.7:51820'):
        try:
            mod.resolve_literal_endpoint(endpoint)
        except RuntimeError as exc:
            assert 'literal IPv4/IPv6' in str(exc), str(exc)
        else:
            raise AssertionError('non-literal strict endpoint was accepted')
    for endpoint, expected in (('203.0.113.7', '203.0.113.7'), ('[2001:db8::7]', '2001:db8::7')):
        assert [str(ip) for ip in mod.resolve_literal_endpoint(endpoint)] == [expected]
    assert resolver.call_count == 0, 'strict endpoint validation leaked pre-tunnel DNS'


# Only an owned native physical path can supply additional literal remotes. No
# invalid list may trigger a lookup or partially widen the firewall exception.
native_env = {
    'HOMEVPN_STANDARD_ENGINE': 'native',
    'HOMEVPN_EXTERNAL_SESSION': 'a' * 32,
    'HOMEVPN_NATIVE_ENDPOINTS_JSON': '["203.0.113.7","198.51.100.20","2001:db8::7"]',
}
with mock.patch.dict(os.environ, native_env), mock.patch('socket.getaddrinfo') as resolver:
    captured = mod.captured_endpoint_ips('203.0.113.7')
    assert [str(ip) for ip in captured] == ['203.0.113.7', '198.51.100.20', '2001:db8::7']
    rules = mod.render_rules(captured, False, False)
    assert 'ip daddr { 203.0.113.7, 198.51.100.20 } accept' in rules
    assert 'ip6 daddr { 2001:db8::7 } accept' in rules
    assert 'policy drop' in rules and '192.168.0.0/16' not in rules
    invalid = ['null', '{}', '[]', '"203.0.113.7"', '["198.51.100.20"]',
               '["203.0.113.7","203.0.113.7"]', '["203.0.113.7",null]',
               '["203.0.113.7",7]', '["203.0.113.7",["198.51.100.20"]]',
               json.dumps(['203.0.113.7'] * 17)]
    invalid += [json.dumps(['203.0.113.7', value]) for value in (
        'vpn.example.test', '198.51.100.20/24', ' 198.51.100.20', '127.0.0.1',
        '0.0.0.0', '255.255.255.255', '224.0.0.1', '169.254.1.2', '::', '::1',
        'ff02::1', 'fe80::1', 'fe80::1%eth0', '::ffff:198.51.100.20', '2001:DB8::7')]
    for raw in invalid:
        with mock.patch.dict(os.environ, {'HOMEVPN_NATIVE_ENDPOINTS_JSON': raw}):
            try:
                mod.captured_endpoint_ips('203.0.113.7')
            except RuntimeError:
                pass
            else:
                raise AssertionError('unsafe native remote list was accepted: ' + raw)
    for overrides in ({'HOMEVPN_STANDARD_ENGINE': 'openvpn'},
                      {'HOMEVPN_EXTERNAL_SESSION': ''},
                      {'HOMEVPN_EXTERNAL_SESSION': 'A' * 32},
                      {'HOMEVPN_NATIVE_ENDPOINTS_JSON': ' ' * 1025}):
        with mock.patch.dict(os.environ, overrides):
            try:
                mod.captured_endpoint_ips('203.0.113.7')
            except RuntimeError as exc:
                assert 'captured external session' in str(exc), str(exc)
            else:
                raise AssertionError('unowned native endpoint exceptions were accepted')
    resolver.assert_not_called()


def write_private_json(path, value):
    path.write_text(json.dumps(value)+'\n')
    os.chmod(path,0o600)


rules=mod.render_rules([mod.ipaddress.ip_address('203.0.113.7'),mod.ipaddress.ip_address('2001:db8::7')],False,False)
assert 'policy drop' in rules and '203.0.113.7' in rules and '2001:db8::7' in rules
assert 'ct state established,related accept' not in rules
assert '192.168.0.0/16' not in rules
rules_lan=mod.render_rules([mod.ipaddress.ip_address('203.0.113.7')],True,False)
assert '192.168.0.0/16' in rules_lan and 'fc00::/7' in rules_lan

# The dynamic Tor guardian's baseline owns no public destination exemption.
# Exercise the actual apply/reassert paths and saved Always policy while only
# replacing nft execution; no fixture command can alter the host firewall.
with tempfile.TemporaryDirectory(prefix='router-vpn-tor-socket-guard-') as td:
    root = pathlib.Path(td)
    (root / 'run').mkdir(mode=0o700)
    selected = {'id': 'dynamic-tor', 'node_kind': 'external', 'endpoint': '198.51.100.40',
                'external': {'protocol': 'tor'}, 'kill_switch_policy': 'always',
                'kill_switch': True, 'home_lan_access': False, 'multihop_enabled': False}
    store = {'selected_id': selected['id'], 'profiles': [selected]}
    write_private_json(root / 'routers.json', store)
    env = {'HOMEVPN_ROOT': str(root), 'HOMEVPN_PROFILE_ID': selected['id'],
           'HOMEVPN_POLICY_PROFILE_ID': selected['id'], 'HOMEVPN_STANDARD_ENGINE': 'native',
           'HOMEVPN_TOR_SESSION': 'a' * 32, 'HOMEVPN_TOR_SOURCE_SHA256': 'b' * 64,
           'HOMEVPN_TOR_PHYSICAL_BROKER': '1', 'HOMEVPN_ENDPOINT': '',
           'HOMEVPN_NATIVE_ENDPOINTS_JSON': '', 'HOMEVPN_NATIVE_EGRESS_JSON': '',
           'HOMEVPN_EXTERNAL_SESSION': '', 'HOMEVPN_KILLSWITCH_DRY_RUN': '0'}
    written = []
    def observe_nft(arguments, **_):
        if '-f' in arguments:
            written.append(pathlib.Path(arguments[arguments.index('-f') + 1]).read_text())
        return subprocess.CompletedProcess(arguments, 0, '', '')
    with mock.patch.dict(os.environ, env), mock.patch.object(mod.sys, 'platform', 'linux'), \
            mock.patch.object(mod, 'table_exists', return_value=False), \
            mock.patch.object(mod, 'run_nft', side_effect=observe_nft), mock.patch('socket.getaddrinfo') as resolver:
        assert mod.apply() == 0
        state_path = root / 'run' / 'kill-switch.json'
        state = json.loads(state_path.read_text())
        assert state['native_socket_broker'] is True and state['endpoint'] == '' and state['endpoint_ips'] == []
        assert 'native_egress' not in state
        assert len(written) == 2 and all('policy drop' in text for text in written)
        assert all('comment "routervpn-owned-baseline:' + 'a' * 32 + ':' + 'b' * 64 + '"' in text for text in written)
        assert all('198.51.100.40' not in text and ' daddr ' not in text and 'meta skuid' not in text for text in written)
        # The native guardian, never this launcher, will admit expiring exact
        # socket tuples after independent kernel ownership readback.
        before = state_path.read_bytes()
        count = len(written)
        for override in ({'HOMEVPN_TOR_PHYSICAL_BROKER': 'true'},
                         {'HOMEVPN_TOR_SESSION': 'A' * 32},
                         {'HOMEVPN_TOR_SOURCE_SHA256': ''},
                         {'HOMEVPN_STANDARD_ENGINE': 'stock'},
                         {'HOMEVPN_ENDPOINT': '198.51.100.40'},
                         {'HOMEVPN_NATIVE_ENDPOINTS_JSON': '["198.51.100.40"]'},
                         {'HOMEVPN_NATIVE_EGRESS_JSON': '[{"host":"198.51.100.40","port":443,"network":"tcp"}]'},
                         {'HOMEVPN_EXTERNAL_SESSION': 'a' * 32}):
            with mock.patch.dict(os.environ, override):
                try:
                    mod.apply()
                except RuntimeError:
                    pass
                else:
                    raise AssertionError('unowned dynamic Tor baseline reached nft: ' + str(override))
            assert len(written) == count and state_path.read_bytes() == before
        for edit in ({'multihop_enabled': True}, {'node_kind': 'router-vpn'},
                     {'external': {'protocol': 'shadowsocks'}}):
            write_private_json(root / 'routers.json', {'selected_id': selected['id'], 'profiles': [{**selected, **edit}]})
            try:
                mod.apply()
            except RuntimeError:
                pass
            else:
                raise AssertionError('another saved source acquired dynamic Tor guard')
            assert len(written) == count and state_path.read_bytes() == before
        write_private_json(root / 'routers.json', store)
        # Reboot has no native session or guardian. Only the empty DROP policy
        # can be restored, even with the saved node's nonempty display endpoint.
        with mock.patch.dict(os.environ, {'HOMEVPN_TOR_SESSION': '', 'HOMEVPN_TOR_SOURCE_SHA256': '',
                                         'HOMEVPN_TOR_PHYSICAL_BROKER': '', 'HOMEVPN_ENDPOINT': '198.51.100.40'}):
            assert mod.reassert() == 0
        restored = json.loads(state_path.read_text())
        assert restored['endpoint_ips'] == [] and restored['native_socket_broker'] is True
        assert all('comment "routervpn-owned-baseline:inactive"' in text for text in written[-2:])
        assert all(' daddr ' not in text and 'meta skuid' not in text for text in written)
        count = len(written)
        for poison in ({'native_socket_broker': False}, {'endpoint_ips': ['198.51.100.40']},
                       {'endpoint': '198.51.100.40'}, {'native_egress': []}):
            write_private_json(state_path, {**restored, **poison})
            try:
                mod.reassert()
            except RuntimeError:
                pass
            else:
                raise AssertionError('corrupt retained guardian baseline widened policy')
            assert len(written) == count
        write_private_json(state_path, restored)
        assert mod.release() == 0 and state_path.exists(), 'Always guard was removed by ordinary disconnect'
        resolver.assert_not_called()

for endpoints, tuples, capture, protected in (
        ([mod.ipaddress.ip_address('203.0.113.1')], None, ('a' * 32, 'b' * 64), True),
        ([], [], ('a' * 32, 'b' * 64), True),
        ([], None, ('A' * 32, 'b' * 64), True),
        ([], None, ('a' * 32, ''), True),
        ([], None, ('a' * 32, 'b' * 64), False)):
    try:
        mod.render_rules(endpoints, False, False, tuples, socket_broker=protected, socket_capture=capture)
    except RuntimeError:
        pass
    else:
        raise AssertionError('captured baseline marker accepted a different firewall authority')

with tempfile.TemporaryDirectory(prefix='router-vpn-killswitch-') as td:
    root=pathlib.Path(td);(root/'run').mkdir();
    store={'selected_id':'node','profiles':[{'id':'node','endpoint':'203.0.113.7','kill_switch_policy':'on-connect','home_lan_access':False}]}
    write_private_json(root/'routers.json',store)
    env=os.environ.copy();env.update({'HOMEVPN_ROOT':str(root),'HOMEVPN_PROFILE_ID':'node','HOMEVPN_ENDPOINT':'203.0.113.7','HOMEVPN_KILLSWITCH_DRY_RUN':'1'})
    p=subprocess.run([sys.executable,str(SCRIPT),'apply'],env=env,text=True,capture_output=True);assert p.returncode==0,p.stderr
    state=json.loads((root/'run'/'kill-switch.json').read_text());assert state['policy']=='on-connect' and state['endpoint_ips']==['203.0.113.7'] and state['policy_profile_id']=='node'
    p=subprocess.run([sys.executable,str(SCRIPT),'release'],env=env,text=True,capture_output=True);assert p.returncode==0,p.stderr;assert not (root/'run'/'kill-switch.json').exists()

# Execute both shipping Unix dispatchers with their normal persisted state. The
# dry-run boundary omits privileged nft/PF installation, not path validation.
for darwin in (False, True):
    with tempfile.TemporaryDirectory(prefix='router-vpn-native-remotes-') as td:
        root=pathlib.Path(td);(root/'run').mkdir()
        write_private_json(root/'routers.json', {'selected_id':'node','profiles':[
            {'id':'node','endpoint':'203.0.113.7','kill_switch_policy':'always','home_lan_access':False}]})
        env=os.environ.copy();env.update(native_env)
        env.update({'HOMEVPN_ROOT':str(root),'HOMEVPN_PROFILE_ID':'node',
            'HOMEVPN_ENDPOINT':'203.0.113.7','HOMEVPN_KILLSWITCH_DRY_RUN':'1',
            'HOMEVPN_KILLSWITCH_DARWIN_TEST':'1' if darwin else '0',
            'HOMEVPN_KILLSWITCH_DARWIN_UTUNS':'', 'HOMEVPN_KILLSWITCH_DARWIN_PHYSICAL_INTERFACES':'en0'})
        script=SCRIPT.with_name('kill-switch-platform.py') if darwin else SCRIPT
        p=subprocess.run([sys.executable,str(script),'apply'],env=env,text=True,capture_output=True)
        assert p.returncode==0,p.stderr
        state_path=root/'run'/'kill-switch.json'
        state=json.loads(state_path.read_text())
        assert state['endpoint_ips']==['203.0.113.7','198.51.100.20','2001:db8::7'],state
        assert state['home_lan_access'] is False
        # An independently reasserted policy cannot inherit a former session's
        # environment authority, even when its session token is well formed.
        p=subprocess.run([sys.executable,str(script),'reassert'],env=env,text=True,capture_output=True)
        assert p.returncode==0,p.stderr
        state=json.loads(state_path.read_text())
        assert state['endpoint_ips']==['203.0.113.7'],state
        previous=state_path.read_bytes()
        env['HOMEVPN_NATIVE_ENDPOINTS_JSON']='["203.0.113.7","vpn.example.test"]'
        p=subprocess.run([sys.executable,str(script),'apply'],env=env,text=True,capture_output=True)
        assert p.returncode!=0 and 'captured literal physical remotes' in p.stderr,p.stderr
        assert state_path.read_bytes()==previous,'rejected remote list changed active firewall state'

with tempfile.TemporaryDirectory(prefix='router-vpn-killswitch-hostname-') as td:
    root=pathlib.Path(td);(root/'run').mkdir();write_private_json(root/'routers.json',{'selected_id':'node','profiles':[{'id':'node','endpoint':'example.com','kill_switch_policy':'on-connect'}]})
    env=os.environ.copy();env.update({'HOMEVPN_ROOT':str(root),'HOMEVPN_PROFILE_ID':'node','HOMEVPN_ENDPOINT':'example.com','HOMEVPN_KILLSWITCH_DRY_RUN':'1'})
    p=subprocess.run([sys.executable,str(SCRIPT),'apply'],env=env,text=True,capture_output=True);assert p.returncode!=0;assert 'literal IPv4/IPv6' in p.stderr

with tempfile.TemporaryDirectory(prefix='router-vpn-killswitch-reassert-') as td:
    root=pathlib.Path(td);(root/'run').mkdir()
    store={'selected_id':'node','profiles':[{'id':'node','endpoint':'203.0.113.9','kill_switch_policy':'always','home_lan_access':True}]}
    write_private_json(root/'routers.json',store)
    env=os.environ.copy();env.update({'HOMEVPN_ROOT':str(root),'HOMEVPN_KILLSWITCH_DRY_RUN':'1'})
    p=subprocess.run([sys.executable,str(SCRIPT),'reassert'],env=env,text=True,capture_output=True);assert p.returncode==0,p.stderr
    state=json.loads((root/'run'/'kill-switch.json').read_text());assert state['policy']=='always' and state['endpoint']=='203.0.113.9' and state['home_lan_access'] is True
    store['profiles'][0]['kill_switch_policy']='off';write_private_json(root/'routers.json',store)
    p=subprocess.run([sys.executable,str(SCRIPT),'reassert'],env=env,text=True,capture_output=True);assert p.returncode==0,p.stderr
    assert not (root/'run'/'kill-switch.json').exists(),p.stderr

# Multihop persistent `always`: policy comes from control, public exception comes
# from the physical entry. The exit endpoint must never be opened directly.
with tempfile.TemporaryDirectory(prefix='router-vpn-killswitch-multihop-') as td:
    root=pathlib.Path(td);(root/'run').mkdir()
    store={'selected_id':'control','profiles':[
      {'id':'control','endpoint':'198.51.100.100','kill_switch_policy':'always','home_lan_access':False,'multihop_enabled':True,'multihop_entry_id':'entry','multihop_exit_id':'exit'},
      {'id':'entry','endpoint':'203.0.113.11','kill_switch_policy':'off','home_lan_access':True},
      {'id':'exit','endpoint':'203.0.113.12','kill_switch_policy':'off','home_lan_access':True},
    ]}
    write_private_json(root/'routers.json',store)
    env=os.environ.copy();env.update({'HOMEVPN_ROOT':str(root),'HOMEVPN_KILLSWITCH_DRY_RUN':'1'})
    p=subprocess.run([sys.executable,str(SCRIPT),'reassert'],env=env,text=True,capture_output=True);assert p.returncode==0,p.stderr
    state=json.loads((root/'run'/'kill-switch.json').read_text())
    assert state['policy']=='always' and state['profile_id']=='entry' and state['policy_profile_id']=='control'
    assert state['endpoint']=='203.0.113.11' and state['endpoint_ips']==['203.0.113.11'] and state['home_lan_access'] is False
    assert '203.0.113.12' not in json.dumps(state)

with tempfile.TemporaryDirectory(prefix='router-vpn-killswitch-failclosed-') as td:
    root=pathlib.Path(td);(root/'run').mkdir();write_private_json(root/'run'/'kill-switch.json',{'policy':'always','profile_id':'node','policy_profile_id':'node','endpoint':'203.0.113.9'})
    env=os.environ.copy();env.update({'HOMEVPN_ROOT':str(root),'HOMEVPN_KILLSWITCH_DRY_RUN':'1'})
    p=subprocess.run([sys.executable,str(SCRIPT),'reassert'],env=env,text=True,capture_output=True);assert p.returncode!=0
    assert 'cannot safely read routers.json' in p.stderr


# Corrupt/symlinked persistent state must never become an implicit "off" state.
with tempfile.TemporaryDirectory(prefix='router-vpn-killswitch-state-safety-') as td:
    root=pathlib.Path(td);(root/'run').mkdir()
    write_private_json(root/'routers.json',{'selected_id':'node','profiles':[{'id':'node','endpoint':'203.0.113.21','kill_switch_policy':'always','home_lan_access':False}]})
    state=root/'run'/'kill-switch.json'
    state.write_text('{broken\n');os.chmod(state,0o600)
    env=os.environ.copy();env.update({'HOMEVPN_ROOT':str(root),'HOMEVPN_KILLSWITCH_DRY_RUN':'1'})
    p=subprocess.run([sys.executable,str(SCRIPT),'reassert'],env=env,text=True,capture_output=True)
    assert p.returncode!=0 and 'state is corrupt' in p.stderr,p.stderr

    state.unlink()
    real=root/'run'/'real-state.json'
    write_private_json(real,{'policy':'always','profile_id':'node','policy_profile_id':'node','endpoint':'203.0.113.21'})
    try:
        state.symlink_to(real)
    except OSError:
        pass
    else:
        p=subprocess.run([sys.executable,str(SCRIPT),'reassert'],env=env,text=True,capture_output=True)
        assert p.returncode!=0 and 'symlink' in p.stderr,p.stderr
        p=subprocess.run([sys.executable,str(SCRIPT),'force-off'],env=env,text=True,capture_output=True)
        assert p.returncode==0,p.stderr
        assert not state.exists() and real.exists()

# Kill-switch cleanup is bound to the exact leaf inspected before removal.
# A foreign regular replacement (including one swapped over a force-off symlink)
# must be preserved rather than unlinked.
with tempfile.TemporaryDirectory(prefix='router-vpn-killswitch-remove-identity-') as td:
    root=pathlib.Path(td);(root/'run').mkdir()
    state=root/'run'/'kill-switch.json'
    write_private_json(state,{'policy':'on-connect'})
    run,parent_before=mod._runtime_state_dir(root)
    before=state.lstat()
    foreign=root/'run'/'foreign.json'
    write_private_json(foreign,{'foreign':True})
    os.replace(foreign,state)
    try:
        mod._require_removal_identity(state,before,run,parent_before)
    except RuntimeError as exc:
        assert 'identity changed before removal' in str(exc)
    else:
        raise AssertionError('kill-switch cleanup accepted a foreign regular replacement')
    assert json.loads(state.read_text())=={'foreign':True}

if os.name != 'nt':
    with tempfile.TemporaryDirectory(prefix='router-vpn-killswitch-forceoff-swap-') as td:
        root=pathlib.Path(td);(root/'run').mkdir()
        real=root/'run'/'real.json';write_private_json(real,{'policy':'always'})
        state=root/'run'/'kill-switch.json';state.symlink_to(real)
        run,parent_before=mod._runtime_state_dir(root)
        before=state.lstat()
        foreign=root/'run'/'foreign.json';write_private_json(foreign,{'foreign':True})
        os.replace(foreign,state)
        try:
            mod._require_removal_identity(state,before,run,parent_before)
        except RuntimeError as exc:
            assert 'identity changed before removal' in str(exc)
        else:
            raise AssertionError('force-off cleanup accepted a swapped foreign leaf')
        assert json.loads(state.read_text())=={'foreign':True}
        assert real.exists()

# A symlinked HOMEVPN_ROOT/run cannot redirect privileged state publication.
with tempfile.TemporaryDirectory(prefix='router-vpn-killswitch-parent-safety-') as td:
    root=pathlib.Path(td)
    real_run=root/'real-run';real_run.mkdir()
    try:
        (root/'run').symlink_to(real_run, target_is_directory=True)
    except OSError:
        pass
    else:
        write_private_json(root/'routers.json',{'selected_id':'node','profiles':[{'id':'node','endpoint':'203.0.113.22','kill_switch_policy':'on-connect','home_lan_access':False}]})
        env=os.environ.copy();env.update({'HOMEVPN_ROOT':str(root),'HOMEVPN_PROFILE_ID':'node','HOMEVPN_ENDPOINT':'203.0.113.22','HOMEVPN_KILLSWITCH_DRY_RUN':'1'})
        p=subprocess.run([sys.executable,str(SCRIPT),'apply'],env=env,text=True,capture_output=True)
        assert p.returncode!=0 and 'symlink' in p.stderr,p.stderr
        assert not (real_run/'kill-switch.json').exists()

subprocess.run([sys.executable, str(SCRIPT.with_name('test_native_egress.py'))], check=True, timeout=60)
print('Kill switch tests: OK')
