#!/usr/bin/env python3
from __future__ import annotations
import json, os, pathlib, subprocess, sys, tempfile

SCRIPT=pathlib.Path(__file__).with_name('multihop.py')

def wg_conf(endpoint='router.invalid:51820',allowed='10.77.0.0/24, 192.168.250.0/24'):
    return f'''[Interface]\nAddress = 10.77.0.2/24\nPrivateKey = test\n[Peer]\nPublicKey = test\nEndpoint = {endpoint}\nAllowedIPs = {allowed}\n'''

def awg_conf():
    return '''[Interface]\nAddress = 10.78.0.2/24\nPrivateKey = test\nJc = 3\n[Peer]\nPublicKey = test\nEndpoint = router.invalid:585\nAllowedIPs = 10.78.0.0/24, 192.168.250.0/24\n'''

def exit_cfg(kind):
    outbound={'type':kind,'tag':'proxy','server':'router.invalid','server_port':8388 if kind=='shadowsocks' else 8443}
    if kind=='shadowsocks': outbound.update({'method':'2022-blake3-aes-256-gcm','password':'secret'})
    else: outbound.update({'password':'secret','tls':{'enabled':True,'server_name':'router-vpn.home','certificate_path':'cert.pem'}})
    return {'log':{'level':'warn'},'dns':{'servers':[{'type':'udp','tag':'home-dns','server':'192.168.250.10','server_port':53,'detour':'proxy'}],'final':'home-dns'},'inbounds':[{'type':'tun','tag':'tun-in','interface_name':'router-vpn','address':['172.19.0.1/30'],'mtu':1380,'auto_route':True,'strict_route':True}],'outbounds':[outbound,{'type':'direct','tag':'direct'}],'route':{'rules':[{'protocol':'dns','action':'hijack-dns'}],'auto_detect_interface':True,'final':'proxy'}}

def setup_root(td):
    root=pathlib.Path(td);(root/'run').mkdir();
    store={'selected_id':'control','profiles':[
      {'id':'control','name':'Control','endpoint':'198.51.100.9','kill_switch_policy':'always','multihop_enabled':True,'multihop_entry_id':'entry','multihop_exit_id':'exit'},
      {'id':'entry','name':'Entry','endpoint':'203.0.113.11','socks_host':'192.168.250.10','socks_port':1080,'socks_username':'u','socks_password':'p'},
      {'id':'exit','name':'Exit','endpoint':'203.0.113.12','path_probe_url':'http://10.77.0.1:8787/health'},
    ]}
    (root/'routers.json').write_text(json.dumps(store)+'\n')
    for mode,name,content in [('wg','wg-socks.conf',wg_conf()),('awg2-fast','awg-socks.conf',awg_conf())]:
        d=root/'generated'/'entry'/mode;d.mkdir(parents=True);(d/name).write_text(content)
    for mode,kind in [('shadowsocks','shadowsocks'),('hysteria2','hysteria2')]:
        d=root/'generated'/'exit'/mode;d.mkdir(parents=True);(d/'sing-box.json').write_text(json.dumps(exit_cfg(kind))+'\n')
        if mode=='hysteria2':(d/'cert.pem').write_text('test-cert\n')
    return root

def build(root,base,mode):
    out=root/'run'/f'mh-{base}-{mode}';env=os.environ.copy();env['HOMEVPN_ROOT']=str(root)
    p=subprocess.run([sys.executable,str(SCRIPT),'build','entry','exit',base,mode,str(out)],env=env,text=True,capture_output=True)
    assert p.returncode==0,p.stderr
    return out,json.loads(p.stdout)

with tempfile.TemporaryDirectory(prefix='router-vpn-multihop-') as td:
    root=setup_root(td)
    for base in ('wg','awg'):
      for mode in ('shadowsocks','hysteria2'):
        out,manifest=build(root,base,mode)
        assert manifest['entry_id']=='entry' and manifest['exit_id']=='exit' and manifest['direct_exit_exception'] is False
        entry=(out/'entry'/('wg.conf' if base=='wg' else 'awg.conf')).read_text()
        assert '203.0.113.11:' in entry and 'AllowedIPs = 192.168.250.10/32' in entry
        assert '0.0.0.0/0' not in entry and '::/0' not in entry
        cfg=json.loads((out/'exit'/'sing-box.json').read_text())
        proxy=next(x for x in cfg['outbounds'] if x.get('tag')=='proxy')
        hop=next(x for x in cfg['outbounds'] if x.get('tag')=='entry-hop')
        assert proxy['server']=='203.0.113.12' and proxy['detour']=='entry-hop'
        assert hop['server']=='192.168.250.10' and hop['server_port']==1080 and hop['username']=='u' and hop['password']=='p'
        assert not any(x.get('tag')=='direct' for x in cfg['outbounds'])
        assert cfg['route']['final']=='proxy'
        entry_proof=next(x for x in cfg['inbounds'] if x.get('tag')=='multihop-entry-proof')
        exit_proof=next(x for x in cfg['inbounds'] if x.get('tag')=='multihop-proof')
        assert entry_proof.get('type')=='mixed' and entry_proof.get('listen')=='127.0.0.1' and entry_proof.get('listen_port')==1098
        assert exit_proof.get('type')=='mixed' and exit_proof.get('listen')=='127.0.0.1' and exit_proof.get('listen_port')==1099
        rules=cfg['route']['rules']
        assert rules[0].get('inbound')==['multihop-entry-proof'] and rules[0].get('outbound')=='entry-hop'
        assert rules[1].get('inbound')==['multihop-proof'] and rules[1].get('outbound')=='proxy'
        assert any(rule.get('protocol')=='dns' and rule.get('action')=='hijack-dns' for rule in rules[2:])
        tun=next(x for x in cfg['inbounds'] if x.get('type')=='tun');assert tun['strict_route'] is True and tun['mtu']<=1280
        assert all(s.get('detour')=='proxy' for s in cfg['dns']['servers'])
        env=(out/'runtime.env').read_text();assert 'EXIT_ENDPOINT=203.0.113.12' in env and 'ENTRY_ENDPOINT=203.0.113.11' in env

with tempfile.TemporaryDirectory(prefix='router-vpn-multihop-negative-') as td:
    root=setup_root(td);env=os.environ.copy();env['HOMEVPN_ROOT']=str(root)
    for args,needle in [
      (['entry','entry','wg','shadowsocks'],'different'),
      (['entry','exit','wg','reality-vision'],'only shadowsocks or hysteria2'),
    ]:
      p=subprocess.run([sys.executable,str(SCRIPT),'build',*args,str(root/'run'/'bad')],env=env,text=True,capture_output=True);assert p.returncode!=0 and needle in p.stderr
    # Force a dangerous full-route source; builder must rewrite to SOCKS host /32.
    (root/'generated'/'entry'/'wg'/'wg-socks.conf').write_text(wg_conf(allowed='0.0.0.0/0, ::/0'))
    out,manifest=build(root,'wg','shadowsocks');entry=(out/'entry'/'wg.conf').read_text();assert '0.0.0.0/0' not in entry and '::/0' not in entry

print('Multihop builder tests: OK')
