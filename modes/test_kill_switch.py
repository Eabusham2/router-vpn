#!/usr/bin/env python3
from __future__ import annotations
import importlib.util, json, os, pathlib, subprocess, sys, tempfile

SCRIPT=pathlib.Path(__file__).with_name('kill-switch.py')
spec=importlib.util.spec_from_file_location('router_vpn_killswitch',SCRIPT);mod=importlib.util.module_from_spec(spec);assert spec and spec.loader;spec.loader.exec_module(mod)

def write_private_json(path, value):
    path.write_text(json.dumps(value)+'\n')
    os.chmod(path,0o600)


rules=mod.render_rules([mod.ipaddress.ip_address('203.0.113.7'),mod.ipaddress.ip_address('2001:db8::7')],False,False)
assert 'policy drop' in rules and '203.0.113.7' in rules and '2001:db8::7' in rules
assert 'ct state established,related accept' not in rules
assert '192.168.0.0/16' not in rules
rules_lan=mod.render_rules([mod.ipaddress.ip_address('203.0.113.7')],True,False)
assert '192.168.0.0/16' in rules_lan and 'fc00::/7' in rules_lan

with tempfile.TemporaryDirectory(prefix='router-vpn-killswitch-') as td:
    root=pathlib.Path(td);(root/'run').mkdir();
    store={'selected_id':'node','profiles':[{'id':'node','endpoint':'203.0.113.7','kill_switch_policy':'on-connect','home_lan_access':False}]}
    write_private_json(root/'routers.json',store)
    env=os.environ.copy();env.update({'HOMEVPN_ROOT':str(root),'HOMEVPN_PROFILE_ID':'node','HOMEVPN_ENDPOINT':'203.0.113.7','HOMEVPN_KILLSWITCH_DRY_RUN':'1'})
    p=subprocess.run([sys.executable,str(SCRIPT),'apply'],env=env,text=True,capture_output=True);assert p.returncode==0,p.stderr
    state=json.loads((root/'run'/'kill-switch.json').read_text());assert state['policy']=='on-connect' and state['endpoint_ips']==['203.0.113.7'] and state['policy_profile_id']=='node'
    p=subprocess.run([sys.executable,str(SCRIPT),'release'],env=env,text=True,capture_output=True);assert p.returncode==0,p.stderr;assert not (root/'run'/'kill-switch.json').exists()

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

print('Kill switch tests: OK')
