#!/usr/bin/env python3
"""Install an owned PQ endpoint in the exact pinned disposable mobile core."""
from pathlib import Path
import argparse
import hashlib
import subprocess

ROOT=Path(__file__).resolve().parents[1]
CORE='1ac1a339cb1223e9c70eae14c44411c75033c02d'
WG_SHA='27e734566921fcd6d45874fcc38240008dc65dd1'
START='func (w *Endpoint) Start(stage adapter.StartStage) error {\n\tswitch stage {'
START_NEW='func (w *Endpoint) Start(stage adapter.StartStage) error {\n\tw.bindAccess.Lock()\n\tdefer w.bindAccess.Unlock()\n\tswitch stage {'
CLOSE='func (w *Endpoint) Close() error {\n\tw.bindAccess.Lock()\n\tw.started.Store(false)\n\tw.bindAccess.Unlock()\n\treturn w.endpoint.Close()\n}'
CLOSE_NEW='func (w *Endpoint) Close() error {\n\tw.bindAccess.Lock()\n\tdefer w.bindAccess.Unlock()\n\tw.started.Store(false)\n\treturn w.endpoint.Close()\n}'

def blobsha(data):return hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()
def patch_wireguard(source):
    original=source
    for old,new in ((START,START_NEW),(CLOSE,CLOSE_NEW)):
        if original.count(new)==1:original=original.replace(new,old,1)
    if blobsha(original.encode())!=WG_SHA:
        raise ValueError('Pinned WireGuard PQ lifecycle source drifted')
    result=original
    for old,new in ((START,START_NEW),(CLOSE,CLOSE_NEW)):
        if result.count(old)!=1:raise ValueError('WireGuard lifecycle anchor is not unique')
        result=result.replace(old,new,1)
    if source!=original and source!=result:raise ValueError('Partial WireGuard PQ lifecycle edit')
    return result

def inputs():
    return [Path(__file__).resolve(),ROOT/'mobile/routervpn_pq_bridge.go.tmpl']+sorted((ROOT/'mobile/pq').rglob('*.tmpl'))
def digest():
    h=hashlib.sha256()
    for p in inputs():h.update(str(p.relative_to(ROOT)).encode()+b'\0'+p.read_bytes())
    return h.hexdigest()
def insert(source,anchor,extra):
    if source.count(anchor)!=1:raise ValueError('PQ registration boundary changed')
    if anchor+extra in source:return source
    if extra.strip() in source:raise ValueError('PQ registration duplicated or moved')
    return source.replace(anchor,anchor+extra,1)
def write(vendor,path,data):
    p=vendor/path
    if p.is_symlink() or not p.resolve().is_relative_to(vendor):raise ValueError('Linked native PQ destination')
    p.parent.mkdir(parents=True,exist_ok=True)
    p.write_bytes(data)
def prepare(vendor):
    vendor=vendor.resolve()
    if subprocess.check_output(['git','-C',str(vendor),'rev-parse','HEAD'],text=True).strip()!=CORE:
        raise ValueError('Native PQ requires the exact pinned core')
    registry=vendor/'include/registry.go'
    wg=vendor/'protocol/wireguard/endpoint.go'
    if registry.is_symlink() or wg.is_symlink():raise ValueError('Linked native source')
    registration=registry.read_text()
    registration=insert(registration,'"github.com/sagernet/sing-box/protocol/routervpnamnezia"','\n\t"github.com/sagernet/sing-box/protocol/routervpnpq"')
    registration=insert(registration,'\troutervpnamnezia.RegisterEndpoint(registry)','\n\troutervpnpq.RegisterEndpoint(registry)')
    wireguard=patch_wireguard(wg.read_text())
    # Validate all boundaries before creating any endpoint file.
    copies={
        'mobile/pq/endpoint.go.tmpl':'protocol/routervpnpq/endpoint.go',
        'mobile/pq/wireguard_protocol.go.tmpl':'protocol/wireguard/routervpn_pq.go',
        'mobile/pq/wireguard_transport.go.tmpl':'transport/wireguard/routervpn_pq.go',
        'mobile/routervpn_pq_bridge.go.tmpl':'experimental/libbox/routervpn_pq_bridge.go',
    }
    for src,dst in copies.items():write(vendor,dst,(ROOT/src).read_bytes())
    write(vendor,'include/registry.go',registration.encode())
    write(vendor,'protocol/wireguard/endpoint.go',wireguard.encode())
    print('Native PQ peer/protocol bridge:',digest())
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('vendor',type=Path,nargs='?');p.add_argument('--digest',action='store_true');a=p.parse_args()
    if a.digest:print(digest())
    elif a.vendor:prepare(a.vendor)
    else:p.error('vendor or --digest required')
