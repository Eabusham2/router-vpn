#!/usr/bin/env python3
from __future__ import annotations
import json, os, pathlib, subprocess, sys, tempfile

SCRIPT = pathlib.Path(__file__).with_name('mtu-policy.py')

def run_case(policy: str, expected: int, probe: str = '', manual: int = 0, jumbo: bool = False) -> None:
    with tempfile.TemporaryDirectory(prefix='router-vpn-mtu-') as td:
        root=pathlib.Path(td); conf=root/'run'/'profile-node-shadowsocks'; conf.mkdir(parents=True)
        (root/'modes.json').write_text(json.dumps([{'id':'shadowsocks','mtu':1380}])+'\n')
        profile={'id':'node','endpoint':'203.0.113.10','mtu_policy':policy,'manual_mtu':manual}
        (root/'routers.json').write_text(json.dumps({'selected_id':'node','profiles':[profile]})+'\n')
        (conf/'sing-box.json').write_text(json.dumps({'inbounds':[{'type':'tun','tag':'tun-in','mtu':1280}]})+'\n')
        (conf/'wg.conf').write_text('[Interface]\nPrivateKey = test\n')
        env=os.environ.copy();env.update({'HOMEVPN_ROOT':str(root),'HOMEVPN_PROFILE_ID':'node','HOMEVPN_MODE':'shadowsocks','HOMEVPN_ENDPOINT':'203.0.113.10','HOMEVPN_MTU':'1380','HOMEVPN_JUMBO':'true' if jumbo else 'false'})
        if probe: env['HOMEVPN_MTU_PROBE_RESULT']=probe
        p=subprocess.run([sys.executable,str(SCRIPT),'apply',str(conf)],env=env,text=True,capture_output=True)
        assert p.returncode==0,p.stderr
        sj=json.loads((conf/'sing-box.json').read_text());assert sj['inbounds'][0]['mtu']==expected,(sj,p.stderr)
        assert f'MTU = {expected}' in (conf/'wg.conf').read_text()
        store=json.loads((root/'routers.json').read_text());assert store['profiles'][0]['effective_mtu']==expected

run_case('default',1380)
run_case('manual',1312,manual=1312)
run_case('auto',1380,probe='1500')
run_case('auto',1280,probe='1400')
run_case('auto',1380,probe='0')  # filtered/unavailable -> tested default
run_case('auto',9000,probe='1500',jumbo=True)
print('MTU policy tests: OK')
