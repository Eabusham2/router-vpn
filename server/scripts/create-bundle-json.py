#!/usr/bin/env python3
import base64, json, pathlib, sys
base=pathlib.Path(sys.argv[1])
endpoint, token, router_api, socks_host, socks_user, socks_password=sys.argv[2:8]
modes=json.load(open(base/'client-bundle/modes.json'))
profiles={}
for mode_dir in (base/'client-bundle/generated').glob('*'):
    if not mode_dir.is_dir():
        continue
    files={}
    for p in mode_dir.iterdir():
        if p.is_file():
            files[p.name]=base64.b64encode(p.read_bytes()).decode()
    if files:
        profiles[mode_dir.name]=files

dns_benchmark={}
dns_path=base/'config'/'dns-fastest.json'
if dns_path.is_file():
    try:
        dns_benchmark=json.load(open(dns_path))
    except Exception:
        dns_benchmark={}
winner=dns_benchmark.get('winner') or {}
fastest_host=str(winner.get('address') or '1.1.1.1')
fastest_name=str(winner.get('name') or 'Cloudflare IPv4 fallback')
fastest_latency=winner.get('latency_ms')
try:
    fastest_latency=float(fastest_latency) if fastest_latency is not None else 0.0
except Exception:
    fastest_latency=0.0

setup_assets={}
setup_path=base/'client-bundle'/'setup-assets.json'
if setup_path.is_file():
    try:
        setup_assets=json.load(open(setup_path))
    except Exception:
        setup_assets={}

router_profile={
    'id':'home',
    'name':'Home Router',
    'endpoint':endpoint,
    'router_api':router_api,
    'api_token':token,
    'adguard_ipv4':socks_host,
    'adguard_ipv6':'fd77:77::1',
    'socks_host':socks_host,
    'socks_port':1080,
    'socks_username':socks_user,
    'socks_password':socks_password,
    'daita_host':socks_host,
    'daita_port':45999,
    'daita_rate_kbps':192,
    'dns_mode':'fastest',
    'dns_protocol':'udp',
    'dns_host':fastest_host,
    'dns_port':53,
    'dns_server_name':'',
    'dns_path':'/dns-query',
    'fastest_dns_host':fastest_host,
    'fastest_dns_name':fastest_name,
    'fastest_dns_latency_ms':fastest_latency,
}
bundle={
    'endpoint':endpoint,
    'apiToken':token,
    'routerAPI':router_api,
    'adGuardIPv4':socks_host,
    'adGuardIPv6':'fd77:77::1',
    'socks5Host':socks_host,
    'socks5Port':1080,
    'socks5Username':socks_user,
    'socks5Password':socks_password,
    'dnsBenchmark':dns_benchmark,
    'setupAssets':setup_assets,
    'routerProfiles':[router_profile],
    'selectedRouterID':'home',
    'modes':modes,
    'profiles':profiles,
}
json.dump(bundle,open(base/'client-bundle/router-vpn-bundle.json','w'),indent=2)
open(base/'client-bundle/router-vpn-bundle.json','a').write('\n')
