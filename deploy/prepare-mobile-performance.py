#!/usr/bin/env python3
"""Build owned cover/performance services into the pinned mobile dataplane."""
from pathlib import Path
import argparse
import hashlib
import subprocess
ROOT=Path(__file__).resolve().parents[1]
PIN='1ac1a339cb1223e9c70eae14c44411c75033c02d'
def inputs():return [Path(__file__).resolve()]+sorted((ROOT/'mobile/performance').glob('*.tmpl'))
def digest():
    h=hashlib.sha256()
    for path in inputs():h.update(str(path.relative_to(ROOT)).encode()+b'\0'+path.read_bytes())
    return h.hexdigest()
def prepare(vendor):
    vendor=vendor.resolve()
    if subprocess.check_output(['git','-C',str(vendor),'rev-parse','HEAD'],text=True).strip()!=PIN:raise ValueError('performance requires exact native core')
    registry=vendor/'include/registry.go';source=registry.read_text()
    for anchor,addition in [('"github.com/sagernet/sing-box/service/ssmapi"','\n\t"github.com/sagernet/sing-box/service/routervpnperformance"'),
                            ('\tssmapi.RegisterService(registry)','\n\troutervpnperformance.RegisterService(registry)')]:
        if source.count(anchor)!=1:raise ValueError('performance registration boundary changed')
        if anchor+addition not in source:
            if addition.strip() in source:raise ValueError('performance registration is misplaced')
            source=source.replace(anchor,anchor+addition)
    directory=vendor/'service/routervpnperformance';directory.mkdir(parents=True,exist_ok=True)
    (directory/'service.go').write_bytes((ROOT/'mobile/performance/service.go.tmpl').read_bytes())
    (directory/'service_test.go').write_bytes((ROOT/'mobile/performance/service_test.go.tmpl').read_bytes())
    (vendor/'routervpn_services.go').write_bytes((ROOT/'mobile/performance/box.go.tmpl').read_bytes())
    (vendor/'experimental/libbox/routervpn_performance.go').write_bytes((ROOT/'mobile/performance/bridge.go.tmpl').read_bytes())
    registry.write_text(source)
    network=vendor/'route/network.go';text=network.read_text();anchor='\tfor _, endpoint := range r.endpoint.Endpoints() {'
    addition='''\t// Invalidate native performance proofs before endpoints rebind.
\tif manager := service.FromContext[adapter.ServiceManager](r.ctx); manager != nil {
\t\tfor _, owned := range manager.Services() {
\t\t\tif listener, ok := owned.(adapter.InterfaceUpdateListener); ok { listener.InterfaceUpdated(ctx) }
\t\t}
\t}

'''
    if text.count(anchor)!=1:raise ValueError('network owner boundary changed')
    if addition+anchor not in text:
        if addition.strip() in text:raise ValueError('network proof invalidation moved')
        text=text.replace(anchor,addition+anchor)
    network.write_text(text)
    print('Native performance source:',digest())
if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('vendor',type=Path,nargs='?');parser.add_argument('--digest',action='store_true');args=parser.parse_args()
    if args.digest:print(digest())
    elif args.vendor:prepare(args.vendor)
    else:parser.error('vendor or digest required')
