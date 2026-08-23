#!/usr/bin/env python3
from __future__ import annotations
import importlib.util,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent
path=HERE/'generate-setup-assets.py'; spec=importlib.util.spec_from_file_location('rvpn_setup_assets_test',path); mod=importlib.util.module_from_spec(spec); assert spec and spec.loader; sys.modules[spec.name]=mod; spec.loader.exec_module(mod)
html=mod.build_html({'socksHost':'192.168.50.133','devices':{},'methods':[],'modes':[]})
for marker in (
 'ASUS SSH username','id="routerUser"','function updateRouterInstall()','${user}@192.168.50.1',
 '/usr/sbin/iptables --version','nvram get vts_rulelist','cat /jffs/scripts/nat-start','cat /jffs/scripts/firewall-start',
 'Safe manual ASUS-GUI fallback','WAN → Virtual Server / Port Forwarding','http://192.168.50.133:8786/healthz',
 'Never use DMZ/Exposed Host','never replace an unrelated existing forward','Verify normal LAN Internet still works',
 '8786–8793','45999','router-vpn-forward.sh verify','ordinary household Internet untouched',
):
 assert marker in html, f'ASUS onboarding missing {marker!r}'
assert 'ssh ROUTER_USER@192.168.50.1' not in html, 'hard-coded placeholder SSH command survived outside generated username logic'
print('Setup Center ASUS username/compatibility/manual-fallback onboarding: PASS')
