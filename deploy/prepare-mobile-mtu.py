#!/usr/bin/env python3
"""Prepare retained-TUN MTU integration in the exact pinned disposable core."""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import subprocess
ROOT=Path(__file__).resolve().parents[1]
PIN='1ac1a339cb1223e9c70eae14c44411c75033c02d'
spec=importlib.util.spec_from_file_location('retained_tun',ROOT/'deploy/prepare-retained-tun.py')
RETAINED=importlib.util.module_from_spec(spec)
spec.loader.exec_module(RETAINED)
PACKAGES=('mobilemtu','mtuprobe','hopmeasure')
def inputs():
    paths=[Path(__file__).resolve(),ROOT/'deploy/prepare-retained-tun.py']+sorted((ROOT/'mobile/mtu').glob('*.tmpl'))
    for package in PACKAGES: paths+=sorted((ROOT/'internal'/package).glob('*.go'))
    return paths
def digest():
    h=hashlib.sha256()
    for p in inputs(): h.update(str(p.relative_to(ROOT)).encode()+b'\0'+p.read_bytes())
    return h.hexdigest()
def prepare(vendor):
    vendor=vendor.resolve()
    if subprocess.check_output(['git','-C',str(vendor),'rev-parse','HEAD'],text=True).strip()!=PIN: raise ValueError('MTU core pin changed')
    RETAINED.prepare(vendor)
    changes={
      'protocol/tun/inbound.go':[
        ('\t"strings"','\t"strings"\n\t"sync"'),
        ('type Inbound struct {','type Inbound struct {\n\troutervpnInitial option.TunInboundOptions\n\troutervpnLifecycle sync.Mutex\n\troutervpnReady bool'),
        ('func (t *Inbound) Start(stage adapter.StartStage) error {','func (t *Inbound) routervpnStart(stage adapter.StartStage) error {'),
        ('\tinbound := &Inbound{','\tinbound := &Inbound{\n\t\troutervpnInitial: options,'),
      ],
      'experimental/libbox/service.go':[
        ('\tmyTunName              string','\troutervpnTunAccess sync.RWMutex\n\tmyTunName              string'),
        ('\tw.myTunName = options.Name\n\tw.myTunAddress = myTunAddress(options)','\tw.routervpnTunAccess.Lock()\n\tw.myTunName = options.Name\n\tw.myTunAddress = myTunAddress(options)\n\tw.routervpnTunAccess.Unlock()'),
        ('\treturn w.myTunAddress','\tw.routervpnTunAccess.RLock()\n\tdefer w.routervpnTunAccess.RUnlock()\n\treturn append([]netip.Addr(nil), w.myTunAddress...)'),
        ('\t\tisDefault := netInterface.Name != w.myTunName && w.defaultInterface != nil && int(netInterface.Index) == w.defaultInterface.Index','\t\tw.routervpnTunAccess.RLock()\n\t\tisDefault := netInterface.Name != w.myTunName && w.defaultInterface != nil && int(netInterface.Index) == w.defaultInterface.Index\n\t\tw.routervpnTunAccess.RUnlock()'),
      ],
    }
    for signature in ['func (t *Inbound) InterfaceUpdated(ctx context.Context) {','func (t *Inbound) Close() error {']:
        tail='\n\tif !t.routervpnReady { return }' if 'InterfaceUpdated' in signature else '\n\tt.routervpnReady = false'
        changes['protocol/tun/inbound.go'].append((signature,signature+'\n\tt.routervpnLifecycle.Lock()\n\tdefer t.routervpnLifecycle.Unlock()'+tail))
    writes={}
    for name,pairs in changes.items():
        path=vendor/name
        if path.is_symlink():raise ValueError('symlink at MTU patch boundary')
        text=path.read_text()
        for old,new in pairs:
            if new in text:continue
            if text.count(old)!=1:raise ValueError('native MTU boundary changed: '+name)
            text=text.replace(old,new)
        writes[path]=text
    targets={'tun.go':'protocol/tun/routervpn_mtu.go','box.go':'routervpn_mtu.go'}
    for name in ['bridge','interface','socket_linux','socket_darwin','socket_other','bridge_test']:
        targets[name+'.go']='experimental/libbox/routervpn_mtu_'+name+'.go'
    for source,dest in targets.items():writes[vendor/dest]=(ROOT/'mobile/mtu'/(source+'.tmpl')).read_text()
    for package in PACKAGES:
        dest=vendor/'experimental/libbox/routervpn'/package
        dest.mkdir(parents=True,exist_ok=True)
        for source in (ROOT/'internal'/package).glob('*.go'):
            text=source.read_text()
            for name in PACKAGES:
                text=text.replace('"router-vpn/internal/'+name+'"','"github.com/sagernet/sing-box/experimental/libbox/routervpn/'+name+'"')
            writes[dest/source.name]=text
    for path,text in writes.items():
        if path.is_symlink() or not path.parent.resolve().is_relative_to(vendor):raise ValueError('unsafe MTU destination')
    for path,text in writes.items():path.write_text(text)
    print('Native MTU source digest:',digest())
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('vendor',type=Path,nargs='?');p.add_argument('--digest',action='store_true');a=p.parse_args()
    if a.digest:print(digest())
    elif a.vendor:prepare(a.vendor)
    else:p.error('vendor or --digest required')
