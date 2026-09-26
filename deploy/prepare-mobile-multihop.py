#!/usr/bin/env python3
"""Compile the tested shared route/lease policy into each existing Libbox build."""
import argparse
import hashlib
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKAGES = ('routechoice', 'multihoprelay', 'mobilemultihop')
_whitening_spec = importlib.util.spec_from_file_location('routervpn_whitening', ROOT/'deploy/prepare-mobile-whitening.py')
WHITENING = importlib.util.module_from_spec(_whitening_spec)
_whitening_spec.loader.exec_module(WHITENING)
def inputs():
    paths = [ROOT/'mobile/routervpn_multihop_bridge.go.tmpl', ROOT/'mobile/routervpn_multihop_native_test.go.tmpl']
    for package in PACKAGES:
        paths += sorted((ROOT/'internal'/package).glob('*.go'))
    return paths + WHITENING.inputs() + [Path(__file__).resolve()]

def digest():
    h=hashlib.sha256()
    for source in inputs():
        h.update(str(source.relative_to(ROOT)).encode()+b'\0'+source.read_bytes())
    return h.hexdigest()

def prepare(vendor):
    vendor=vendor.resolve();module=vendor/'go.mod'
    if not module.is_file() or not module.read_text().startswith('module github.com/sagernet/sing-box\n'):
        raise ValueError('expected the verified disposable sing-box checkout')
    WHITENING.prepare(vendor)
    root=vendor/'experimental/libbox'
    for package in PACKAGES:
        output=root/'routervpn'/package;output.mkdir(parents=True,exist_ok=True)
        for source in (ROOT/'internal'/package).glob('*.go'):
            if source.name=='core_config_test.go':continue
            text=source.read_text()
            for name in PACKAGES:
                text=text.replace('"router-vpn/internal/'+name+'"','"github.com/sagernet/sing-box/experimental/libbox/routervpn/'+name+'"')
            (output/source.name).write_text(text)
    (root/'routervpn_multihop_bridge.go').write_bytes((ROOT/'mobile/routervpn_multihop_bridge.go.tmpl').read_bytes())
    (root/'routervpn_multihop_native_test.go').write_bytes((ROOT/'mobile/routervpn_multihop_native_test.go.tmpl').read_bytes())
    print('Shared multihop source digest:',digest())
if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('vendor',type=Path,nargs='?');parser.add_argument('--digest',action='store_true');args=parser.parse_args()
    if args.digest:print(digest())
    elif args.vendor:prepare(args.vendor)
    else:parser.error('vendor checkout or --digest is required')
