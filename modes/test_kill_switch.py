#!/usr/bin/env python3
from __future__ import annotations
import importlib.util, json, os, pathlib, subprocess, sys, tempfile

SCRIPT=pathlib.Path(__file__).with_name('kill-switch.py')
spec=importlib.util.spec_from_file_location('router_vpn_killswitch',SCRIPT);mod=importlib.util.module_from_spec(spec);assert spec and spec.loader;spec.loader.exec_module(mod)

rules=mod.render_rules([mod.ipaddress.ip_address('203.0.113.7'),mod.ipaddress.ip_address('2001:db8::7')],False,False)
assert 'policy drop' in rules and '203.0.113.7' in rules and '2001:db8::7' in rules
assert '192.168.0.0/16' not in rules
rules_lan=mod.render_rules([mod.ipaddress.ip_address('203.0.113.7')],True,False)
assert '192.168.0.0/16' in rules_lan and 'fc00::/7' in rules_lan

with tempfile.TemporaryDirectory(prefix='router-vpn-killswitch-') as td:
    root=pathlib.Path(td);(root/'run').mkdir();
    store={'selected_id':'node','profiles':[{'id':'node','endpoint':'203.0.113.7','kill_switch_policy':'on-connect','home_lan_access':False}]}
    (root/'routers.json').write_text(json.dumps(store)+'\n')
    env=os.environ.copy();env.update({'HOMEVPN_ROOT':str(root),'HOMEVPN_PROFILE_ID':'node','HOMEVPN_ENDPOINT':'203.0.113.7','HOMEVPN_KILLSWITCH_DRY_RUN':'1'})
    p=subprocess.run([sys.executable,str(SCRIPT),'apply'],env=env,text=True,capture_output=True);assert p.returncode==0,p.stderr
    state=json.loads((root/'run'/'kill-switch.json').read_text());assert state['policy']=='on-connect' and state['endpoint_ips']==['203.0.113.7']
    p=subprocess.run([sys.executable,str(SCRIPT),'release'],env=env,text=True,capture_output=True);assert p.returncode==0,p.stderr;assert not (root/'run'/'kill-switch.json').exists()

with tempfile.TemporaryDirectory(prefix='router-vpn-killswitch-hostname-') as td:
    root=pathlib.Path(td);(root/'run').mkdir();(root/'routers.json').write_text(json.dumps({'selected_id':'node','profiles':[{'id':'node','endpoint':'example.com','kill_switch_policy':'on-connect'}]})+'\n')
    env=os.environ.copy();env.update({'HOMEVPN_ROOT':str(root),'HOMEVPN_PROFILE_ID':'node','HOMEVPN_ENDPOINT':'example.com','HOMEVPN_KILLSWITCH_DRY_RUN':'1'})
    p=subprocess.run([sys.executable,str(SCRIPT),'apply'],env=env,text=True,capture_output=True);assert p.returncode!=0;assert 'literal IPv4/IPv6' in p.stderr
print('Kill switch tests: OK')
