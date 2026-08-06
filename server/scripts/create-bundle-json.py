#!/usr/bin/env python3
import base64, json, pathlib, sys
base=pathlib.Path(sys.argv[1])
endpoint, token, router_api, socks_host, socks_user, socks_password=sys.argv[2:8]
modes=json.load(open(base/'client-bundle/modes.json'))
profiles={}
for mode_dir in (base/'client-bundle/generated').glob('*'):
    if not mode_dir.is_dir(): continue
    files={}
    for p in mode_dir.iterdir():
        if p.is_file():
            files[p.name]=base64.b64encode(p.read_bytes()).decode()
    if files: profiles[mode_dir.name]=files
bundle={
    'endpoint':endpoint,
    'apiToken':token,
    'routerAPI':router_api,
    'socks5Host':socks_host,
    'socks5Port':1080,
    'socks5Username':socks_user,
    'socks5Password':socks_password,
    'modes':modes,
    'profiles':profiles,
}
json.dump(bundle,open(base/'client-bundle/router-vpn-bundle.json','w'),indent=2)
open(base/'client-bundle/router-vpn-bundle.json','a').write('\n')
