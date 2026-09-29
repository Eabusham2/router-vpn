#!/usr/bin/env python3
"""Inject a native AWG endpoint into the exact pinned, disposable core checkout."""
from pathlib import Path
import argparse
import hashlib
import json
import subprocess

ROOT=Path(__file__).resolve().parents[1]
CORE='1ac1a339cb1223e9c70eae14c44411c75033c02d'
VERSION='v3.1.20260814'
MODULE='github.com/amnezia-vpn/amneziawg-go/v3'
SUM='h1:l2AhBD+sFycU8Im81n/bZORMxW7fWtlZJEuJ4Hh0+z0='

def inputs():
    return [Path(__file__).resolve()]+sorted((ROOT/'mobile/amnezia').glob('*.tmpl'))
def digest():
    h=hashlib.sha256()
    for path in inputs():h.update(str(path.relative_to(ROOT)).encode()+b'\0'+path.read_bytes())
    return h.hexdigest()
def prepare(vendor):
    vendor=vendor.resolve()
    if subprocess.check_output(['git','-C',str(vendor),'rev-parse','HEAD'],text=True).strip()!=CORE:
        raise ValueError('native AWG requires the exact pinned core')
    registry=vendor/'include/registry.go';text=registry.read_text()
    for old,extra in [('"github.com/sagernet/sing-box/protocol/tor"','\n\t"github.com/sagernet/sing-box/protocol/routervpnamnezia"'),
                      ('\tregisterWireGuardEndpoint(registry)','\n\troutervpnamnezia.RegisterEndpoint(registry)')]:
        if text.count(old)!=1:raise ValueError('native AWG registration boundary changed')
        if old+extra not in text:
            if extra.strip() in text:raise ValueError('native AWG registration duplicated or moved')
            text=text.replace(old,old+extra,1)
    output=vendor/'protocol/routervpnamnezia';output.mkdir(parents=True,exist_ok=True)
    for path in (ROOT/'mobile/amnezia').glob('*.tmpl'):(output/path.name.removesuffix('.tmpl')).write_bytes(path.read_bytes())
    registry.write_text(text)
    subprocess.run(['go','mod','edit','-require='+MODULE+'@'+VERSION],cwd=vendor,check=True)
    print('Native AmneziaWG endpoint:',VERSION,digest())
def verify(vendor):
    result=json.loads(subprocess.check_output(['go','list','-m','-json',MODULE],cwd=vendor,text=True))
    if result.get('Version')!=VERSION or result.get('Sum')!=SUM or result.get('Replace'):
        raise ValueError('native AmneziaWG backend does not match its exact pinned checksum')
    license=Path(result['Dir'])/'LICENSE'
    if not license.is_file() or license.stat().st_size<100:
        raise ValueError('native AWG license missing')
    (vendor/'routervpn-amnezia-LICENSE.txt').write_bytes(license.read_bytes())
    print('Verified native AWG version, checksum and license:',VERSION)

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('vendor',type=Path,nargs='?');parser.add_argument('--digest',action='store_true');parser.add_argument('--verify-dependency',action='store_true');args=parser.parse_args()
    if args.digest:print(digest())
    elif args.vendor and args.verify_dependency:verify(args.vendor)
    elif args.vendor:prepare(args.vendor)
    else:parser.error('vendor or --digest required')
