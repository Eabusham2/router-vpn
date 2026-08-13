#!/usr/bin/env python3
import base64, json, pathlib, re, subprocess, sys
base=pathlib.Path(sys.argv[1])
endpoint, token, router_api, socks_host, socks_user, socks_password=sys.argv[2:8]
proof_script=pathlib.Path(__file__).with_name('ensure-node-proof.py')
subprocess.run([sys.executable,str(proof_script),str(base)],check=True,stdout=subprocess.DEVNULL)
agent_config=json.load(open(base/'config'/'router-agent.json'))
node_proof_id=str(agent_config.get('node_id') or '').strip()
if not re.fullmatch(r'[0-9a-f]{64}',node_proof_id):
    raise SystemExit('router-agent node proof id is missing or invalid')
modes=json.load(open(base/'client-bundle/modes.json'))
logical_path=base/'client-bundle'/'logical-modes.json'
if not logical_path.is_file():
    logical_path=pathlib.Path(__file__).resolve().parents[2]/'configs'/'client'/'logical-modes.json'
try:
    logical_modes=json.load(open(logical_path))
except Exception:
    logical_modes=[]
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
dns_results=dns_benchmark.get('results') or []
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
    'schema_version':2,
    'id':'home',
    'name':'Home Router',
    'node_proof_id':node_proof_id,
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
    'base_tunnel':'auto',
    'base_fallback':True,
    'custom_layers':[],
    'home_lan_access':True,
    'home_lan_cidrs':['192.168.50.0/24'],
    'kill_switch':False,
    'kill_switch_policy':'off',
    'ipv6_mode':'auto',
    'startup_mode':'manual',
    'auto_connect':False,
    'multihop_enabled':False,
    'multihop_entry_id':'',
    'multihop_exit_id':'',
    'mtu_policy':'default',
    'manual_mtu':0,
    'effective_mtu':0,
    'diagnostics_enabled':False,
    'diagnostics_retention_days':7,
    'share_diagnostics':False,
    'telemetry_enabled':False,
    'path_probe_url':'http://10.77.0.1:8787/health',
    'location':'Home',
    'use_count':0,
    'dns_mode':'home',
    'dns_protocol':'udp',
    'dns_host':socks_host,
    'dns_port':53,
    'dns_server_name':'',
    'dns_path':'/dns-query',
    'fastest_dns_host':fastest_host,
    'fastest_dns_name':fastest_name,
    'fastest_dns_latency_ms':fastest_latency,
    'dns_results':dns_results,
}
client_config={
    'listen':'127.0.0.1:8788',
    'health_url':'http://10.77.0.1:8787/health',
    'auto_test_seconds':8,
    'modes_file':'./modes.json',
    'state_file':'./state.json',
    'scripts_dir':'./modes',
    'profiles_file':'./routers.json',
}
json.dump(client_config,open(base/'client-bundle/client.json','w'),indent=2)
open(base/'client-bundle/client.json','a').write('\n')
json.dump({'schema_version':2,'selected_id':'home','profiles':[router_profile]},open(base/'client-bundle/routers.json','w'),indent=2)
open(base/'client-bundle/routers.json','a').write('\n')
bundle={
    'bundleVersion':4,
    'profileSchemaVersion':2,
    'nodeProofId':node_proof_id,
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
    'logicalModes':logical_modes,
    'modes':modes,
    'profiles':profiles,
}
json.dump(bundle,open(base/'client-bundle/router-vpn-bundle.json','w'),indent=2)
open(base/'client-bundle/router-vpn-bundle.json','a').write('\n')
