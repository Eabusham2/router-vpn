#!/usr/bin/env python3
"""Build the tested authenticated AES+XOR outbound into the pinned mobile core."""
from pathlib import Path
import argparse
import hashlib
import subprocess

ROOT = Path(__file__).resolve().parents[1]

def inputs():
    return [Path(__file__).resolve(), ROOT/"deploy/prepare-mobile-buffers.py", ROOT/"deploy/mobile_udp_socket_policy.py"] + sorted((ROOT/'internal/startwhitening').glob('*.go')) + sorted((ROOT/'mobile/startwhitening').glob('*.tmpl'))

def digest():
    h=hashlib.sha256()
    for p in inputs(): h.update(str(p.relative_to(ROOT)).encode()+b'\0'+p.read_bytes())
    return h.hexdigest()

PIN = '1ac1a339cb1223e9c70eae14c44411c75033c02d'

def checkout(vendor):
    if subprocess.check_output(['git','-C',str(vendor),'rev-parse','HEAD'],text=True).strip()!=PIN:
        raise ValueError('native whitening requires the exact pinned mobile core')
    if not (vendor/'go.mod').read_text().startswith('module github.com/sagernet/sing-box\n'):
        raise ValueError('expected the verified disposable native sing-box module')

def replace_once(text,old,new):
    if text.count(old)!=1: raise ValueError('native whitening registration boundary changed')
    if new in text:
        if text.count(new)!=1 or [line.strip() for line in text.splitlines()].count(new[len(old):].strip())!=1: raise ValueError('duplicate native whitening registration')
        return text
    extra=new[len(old):].strip()
    if extra in text: raise ValueError('native whitening registration moved or differs')
    return text.replace(old,new,1)

def prepare(vendor):
    vendor=vendor.resolve()
    checkout(vendor)
    registry=vendor/'include/registry.go'
    text=registry.read_text()
    old='\t"github.com/sagernet/sing-box/protocol/shadowsocks"'
    text=replace_once(text,old,old+'\n\t"github.com/sagernet/sing-box/protocol/routervpnwhitening"')
    old='\tshadowsocks.RegisterOutbound(registry)'
    text=replace_once(text,old,old+'\n\troutervpnwhitening.RegisterOutbound(registry)')
    policy=vendor/'experimental/libbox/routervpn/startwhitening';policy.mkdir(parents=True,exist_ok=True)
    for p in (ROOT/'internal/startwhitening').glob('*.go'): (policy/p.name).write_bytes(p.read_bytes())
    adapter=vendor/'protocol/routervpnwhitening';adapter.mkdir(parents=True,exist_ok=True)
    for p in (ROOT/'mobile/startwhitening').glob('*.tmpl'):
        (adapter/p.name.removesuffix('.tmpl')).write_bytes(p.read_bytes())
    registry.write_text(text)
    print('Native authenticated Start Layer source:',digest())

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('vendor',type=Path,nargs='?');parser.add_argument('--digest',action='store_true')
    args=parser.parse_args()
    if args.digest: print(digest())
    elif args.vendor: prepare(args.vendor)
    else: parser.error('verified vendor checkout or --digest required')
