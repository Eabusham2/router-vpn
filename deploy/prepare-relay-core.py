#!/usr/bin/env python3
"""Build the private relay CLI with exactly the mobile AWG transport implementation.

This prepares a disposable, exact-pinned source checkout; it never starts a VPN,
changes routes, or reads user profiles. All application-dependent files enter the
source digest and every import is relocated without substituting another engine.
"""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import subprocess

ROOT = Path(__file__).resolve().parents[1]
CORE = '1ac1a339cb1223e9c70eae14c44411c75033c02d'
PACKAGES = ('awgpolicy', 'mobilemultihop', 'mobilepq', 'applexray', 'multihoprelay', 'routechoice', 'nativesip003', 'nativecomposite', 'mobileperf', 'hopmeasure', 'nativeopenvpn')
spec = importlib.util.spec_from_file_location('relay_amnezia', ROOT/'deploy/prepare-mobile-amnezia.py')
AMNEZIA = importlib.util.module_from_spec(spec)
spec.loader.exec_module(AMNEZIA)

xray_spec = importlib.util.spec_from_file_location('relay_xray', ROOT/'deploy/prepare-apple-xray.py')
XRAY = importlib.util.module_from_spec(xray_spec)
xray_spec.loader.exec_module(XRAY)
whitening_spec = importlib.util.spec_from_file_location('relay_whitening', ROOT/'deploy/prepare-mobile-whitening.py')
WHITENING = importlib.util.module_from_spec(whitening_spec)
whitening_spec.loader.exec_module(WHITENING)
pq_spec = importlib.util.spec_from_file_location('relay_native_pq', ROOT/'deploy/prepare-server-pq.py')
PQ = importlib.util.module_from_spec(pq_spec)
pq_spec.loader.exec_module(PQ)
composite_spec = importlib.util.spec_from_file_location('relay_composite', ROOT/'deploy/prepare-mobile-composite.py')
COMPOSITE = importlib.util.module_from_spec(composite_spec)
composite_spec.loader.exec_module(COMPOSITE)
openvpn_spec = importlib.util.spec_from_file_location('relay_openvpn_close', ROOT/'deploy/mobile_openvpn_close_policy.py')
OPENVPN_CLOSE = importlib.util.module_from_spec(openvpn_spec)
openvpn_spec.loader.exec_module(OPENVPN_CLOSE)
strategy_spec = importlib.util.spec_from_file_location('relay_native_strategy', ROOT/'deploy/prepare-mobile-strategy.py')
STRATEGY = importlib.util.module_from_spec(strategy_spec)
strategy_spec.loader.exec_module(STRATEGY)
remote_spec = importlib.util.spec_from_file_location('relay_openvpn_remote', ROOT/'deploy/mobile_openvpn_remote_policy.py')
OPENVPN_REMOTE = importlib.util.module_from_spec(remote_spec)
remote_spec.loader.exec_module(OPENVPN_REMOTE)
XRAY_VERSION = 'v1.260327.1-0.20260711155151-50231eaff98c'

def inputs():
    files = [Path(__file__).resolve(), ROOT/'deploy/test_external_openvpn_native.py', ROOT/'mobile/routervpn_openvpn_external_native_test.go.tmpl', *sorted((ROOT/'mobile/relay').glob('*.tmpl'))] + AMNEZIA.inputs() + XRAY.sources() + WHITENING.inputs() + PQ.inputs() + COMPOSITE.inputs() + OPENVPN_CLOSE.inputs() + OPENVPN_REMOTE.inputs() + STRATEGY.inputs()
    for package in PACKAGES: files += sorted((ROOT/'internal'/package).glob('*.go'))
    return list(dict.fromkeys(files))

def digest():
    h = hashlib.sha256()
    for path in inputs(): h.update(str(path.relative_to(ROOT)).encode()+b'\0'+path.read_bytes())
    return h.hexdigest()

def prepare(vendor):
    vendor = vendor.resolve()
    if subprocess.check_output(['git','-C',str(vendor),'rev-parse','HEAD'],text=True).strip()!=CORE:
        raise ValueError('Private AWG relay requires the exact native core')
    if not (vendor/'go.mod').read_text().startswith('module github.com/sagernet/sing-box\n'):
        raise ValueError('Not a disposable native sing-box checkout')
    for package in PACKAGES:
        output = vendor/'experimental/libbox/routervpn'/package
        if not output.resolve().is_relative_to(vendor): raise ValueError('Relay package target escaped the pinned checkout')
        output.mkdir(parents=True,exist_ok=True)
        if package == 'applexray':
            parent_test = output/'preparation_test.go'
            if parent_test.is_symlink(): raise ValueError('Linked parent-only test in native policy tree')
            if parent_test.exists():
                if not parent_test.is_file() or parent_test.read_bytes() != (ROOT/'internal/applexray/preparation_test.go').read_bytes():
                    raise ValueError('Unexpected parent-only test in native policy tree')
                parent_test.unlink()
        for path in (ROOT/'internal'/package).glob('*.go'):
            if path.name == 'core_config_test.go' or (package == 'applexray' and path.name == 'preparation_test.go'): continue
            text = path.read_text()
            for name in PACKAGES:
                text = text.replace('"router-vpn/internal/'+name+'"','"github.com/sagernet/sing-box/experimental/libbox/routervpn/'+name+'"')
            target=output/path.name
            if target.is_symlink(): raise ValueError('Refusing a linked relay source destination')
            target.write_text(text)
    AMNEZIA.prepare(vendor)
    OPENVPN_REMOTE.prepare(vendor)
    for source in (ROOT/'mobile/relay').glob('*.tmpl'):
        target = vendor/'cmd/sing-box'/('routervpn_relay_'+source.name.removesuffix('.tmpl'))
        if target.is_symlink(): raise ValueError('Linked native relay command destination')
        target.write_bytes(source.read_bytes())
    print('Private relay source digest:', digest())

def prepare_native(vendor, xray):
    vendor = vendor.resolve()
    xray = xray.resolve()
    # Validate both immutable checkouts before changing either dependency tree.
    XRAY.checkout(vendor, CORE, 'github.com/sagernet/sing-box')
    XRAY.checkout(xray, XRAY.XRAY_PIN, 'github.com/xtls/xray-core')
    prepare(vendor)
    WHITENING.prepare(vendor)
    XRAY.prepare(vendor, xray)
    PQ.prepare(vendor)
    COMPOSITE.prepare(vendor)
    OPENVPN_CLOSE.prepare(vendor)
    STRATEGY.prepare(vendor, mobile=False)
    subprocess.run(['go','mod','edit','-require=github.com/xtls/xray-core@'+XRAY_VERSION],cwd=vendor,check=True)
    subprocess.run(['go','mod','edit','-replace=github.com/xtls/xray-core='+str(xray)],cwd=vendor,check=True)
    license = xray/'LICENSE'
    if not license.is_file() or license.is_symlink() or license.stat().st_size < 100:
        raise ValueError('Pinned native Xray license missing')
    (vendor/'routervpn-xray-LICENSE.txt').write_bytes(license.read_bytes())
    print('Private native Xray relay:', XRAY.XRAY_PIN, digest())

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('vendor',type=Path,nargs='?')
    parser.add_argument('xray',type=Path,nargs='?')
    parser.add_argument('--digest',action='store_true')
    args=parser.parse_args()
    if args.digest: print(digest())
    elif args.vendor and args.xray: prepare_native(args.vendor,args.xray)
    else: parser.error('verified native core and Xray checkouts, or --digest, are required')
