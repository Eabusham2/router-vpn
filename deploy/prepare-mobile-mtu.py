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
PACKAGES=('mobilemtu','mtuprobe','hopmeasure','nativeopenvpn')
GO_SOURCE_HASHES={
 'src/runtime/pprof/proto.go':'7db7c755f02551e22207987a6d5a6d25038fcc5119e9005e7be4f56fdcbc54dc',
 'src/runtime/pprof/elf.go':'43a1284bfc363574cb0843d2d632ea86dff94fdf5388070f3d32c1fc6329f8d6',
 'LICENSE':'911f8f5782931320f5b8d1160a76365b83aea6447ee6c04fa6d5591467db9dad',
}
def inputs():
    paths=[Path(__file__).resolve(),ROOT/'deploy/prepare-retained-tun.py',ROOT/'mobile/mtu/GO-LICENSE']+sorted((ROOT/'mobile/mtu').glob('*.tmpl'))
    for package in PACKAGES:paths+=sorted((ROOT/'internal'/package).glob('*.go'))
    return paths
def digest():
    h=hashlib.sha256()
    for p in inputs():h.update(str(p.relative_to(ROOT)).encode()+b'\0'+p.read_bytes())
    return h.hexdigest()
def mapping_source():
    # Go 1.26 rejects upstream's private parseProcSelfMaps linkname on Linux.
    # Copy the exact licensed implementation, not a linker-check exemption.
    if subprocess.check_output(['go','env','GOVERSION'],text=True).strip()!='go1.26.3':
        raise ValueError('MTU mapping compatibility requires pinned Go 1.26.3')
    goroot=Path(subprocess.check_output(['go','env','GOROOT'],text=True).strip())
    sources={}
    for name,expected in GO_SOURCE_HASHES.items():
        data=(goroot/name).read_bytes()
        if hashlib.sha256(data).hexdigest()!=expected:raise ValueError('Go mapping source checksum changed: '+name)
        sources[name]=data.decode('utf-8')
    if (ROOT/'mobile/mtu/GO-LICENSE').read_text()!=sources['LICENSE']:raise ValueError('Go license attribution changed')
    proto=sources['src/runtime/pprof/proto.go']
    start=proto.index('var space =');end=proto.index('\nfunc (b *profileBuilder) addMapping(',start)
    parser=proto[start:end].replace('func parseProcSelfMaps(', 'func stdParseProcSelfMaps(').replace('elfBuildID(file)','stdELFBuildID(file)')
    elf=sources['src/runtime/pprof/elf.go'];elf=elf[elf.index('var ('):].replace('func elfBuildID(', 'func stdELFBuildID(')
    header=proto[:proto.index('\npackage pprof')]
    return header+'\n// Adapted from checksum-pinned Go 1.26.3 pprof sources; see GO-LICENSE.\n//go:build linux || android\n\npackage oomprofile\n\nimport ("bytes";"encoding/binary";"errors";"fmt";"os";"strconv";"strings")\n\n'+parser+'\n'+elf

def prepare(vendor, *, mobile=True):
    vendor=vendor.resolve()
    if subprocess.check_output(['git','-C',str(vendor),'rev-parse','HEAD'],text=True).strip()!=PIN:raise ValueError('MTU core pin changed')
    mappings=mapping_source() if mobile else ''
    RETAINED.prepare(vendor)
    changes={
      'protocol/tun/inbound.go':[
        ('\t"strings"','\t"strings"\n\t"sync"'),
        ('type Inbound struct {','type Inbound struct {\n\troutervpnInitial option.TunInboundOptions\n\troutervpnLifecycle sync.Mutex\n\troutervpnReady bool\n\troutervpnDesktop bool\n\troutervpnDesktopFresh bool\n\troutervpnDesktopIndex int\n\troutervpnDesktopGuard func() bool'),
        ('func (t *Inbound) Start(stage adapter.StartStage) error {','func (t *Inbound) routervpnStart(stage adapter.StartStage) error {'),
        ('\tinbound := &Inbound{','\tinbound := &Inbound{\n\t\troutervpnInitial: options,'),
      ],
      'experimental/libbox/internal/oomprofile/linkname.go':[
        ('//go:linkname stdParseProcSelfMaps runtime/pprof.parseProcSelfMaps\nfunc stdParseProcSelfMaps(data []byte, addMapping func(lo uint64, hi uint64, offset uint64, file string, buildID string))','// Router VPN supplies the licensed proc-maps parser locally.'),
        ('//go:linkname stdELFBuildID runtime/pprof.elfBuildID\nfunc stdELFBuildID(file string) (string, error)','// Router VPN supplies the licensed ELF build-ID reader locally.'),
      ],
      'experimental/libbox/service.go':[
        ('\tmyTunName              string','\troutervpnTunAccess sync.RWMutex\n\tmyTunName              string'),
        ('\tw.myTunName = options.Name\n\tw.myTunAddress = myTunAddress(options)','\tw.routervpnTunAccess.Lock()\n\tw.myTunName = options.Name\n\tw.myTunAddress = myTunAddress(options)\n\tw.routervpnTunAccess.Unlock()'),
        ('\treturn w.myTunAddress','\tw.routervpnTunAccess.RLock()\n\tdefer w.routervpnTunAccess.RUnlock()\n\treturn append([]netip.Addr(nil), w.myTunAddress...)'),
        ('\t\tisDefault := netInterface.Name != w.myTunName && w.defaultInterface != nil && int(netInterface.Index) == w.defaultInterface.Index','\t\tw.routervpnTunAccess.RLock()\n\t\tisDefault := netInterface.Name != w.myTunName && w.defaultInterface != nil && int(netInterface.Index) == w.defaultInterface.Index\n\t\tw.routervpnTunAccess.RUnlock()'),
      ],
    }
    if not mobile:
        # Desktop owns the same Box/TUN transaction without a Libbox daemon or
        # mobile platform adapter. Do not install a partial mobile binding.
        del changes['experimental/libbox/internal/oomprofile/linkname.go']
        del changes['experimental/libbox/service.go']
    for signature in ['func (t *Inbound) InterfaceUpdated(ctx context.Context) {','func (t *Inbound) Close() error {']:
        tail='\n\tif !t.routervpnReady { return }' if 'InterfaceUpdated' in signature else '\n\tt.routervpnReady = false'
        changes['protocol/tun/inbound.go'].append((signature,signature+'\n\tt.routervpnLifecycle.Lock()\n\tdefer t.routervpnLifecycle.Unlock()'+tail))
    writes={
        vendor/'experimental/libbox/internal/oomprofile/routervpn_maps.go':mappings,
        vendor/'experimental/libbox/internal/oomprofile/GO-LICENSE':(ROOT/'mobile/mtu/GO-LICENSE').read_text(),
    } if mobile else {}
    for name,pairs in changes.items():
        path=vendor/name
        if path.is_symlink():raise ValueError('symlink at MTU patch boundary')
        text=path.read_text()
        for old,new in pairs:
            if new in text:continue
            previous='type Inbound struct {\n\troutervpnInitial option.TunInboundOptions\n\troutervpnLifecycle sync.Mutex\n\troutervpnReady bool'
            if old=='type Inbound struct {' and previous in text:
                text=text.replace(previous,new)
                continue
            if text.count(old)!=1:raise ValueError('native MTU boundary changed: '+name)
            text=text.replace(old,new)
        writes[path]=text
    targets={'tun.go':'protocol/tun/routervpn_mtu.go','box.go':'routervpn_mtu.go','box_test.go':'routervpn_mtu_test.go'}
    if mobile:
        targets['pprof_maps_test.go']='experimental/libbox/internal/oomprofile/routervpn_maps_test.go'
        for name in ['bridge','external_owner','interface','socket_linux','socket_darwin','socket_other','bridge_test']:
            targets[name+'.go']='experimental/libbox/routervpn_mtu_'+name+'.go'
    for source,dest in targets.items():writes[vendor/dest]=(ROOT/'mobile/mtu'/(source+'.tmpl')).read_text()
    for package in PACKAGES:
        dest=vendor/'experimental/libbox/routervpn'/package
        dest.mkdir(parents=True,exist_ok=True)
        for source in (ROOT/'internal'/package).glob('*.go'):
            text=source.read_text()
            for name in PACKAGES:text=text.replace('"router-vpn/internal/'+name+'"','"github.com/sagernet/sing-box/experimental/libbox/routervpn/'+name+'"')
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
