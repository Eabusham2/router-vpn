#!/usr/bin/env python3
"""Compile the tested shared route/lease policy into each existing Libbox build."""
import argparse
import hashlib
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKAGES = ('awgpolicy', 'routechoice', 'multihoprelay', 'mobilemultihop', 'applexray', 'nativesip003', 'hopmeasure', 'mobileperf')
_whitening_spec = importlib.util.spec_from_file_location('routervpn_whitening', ROOT/'deploy/prepare-mobile-whitening.py')
WHITENING = importlib.util.module_from_spec(_whitening_spec)
_whitening_spec.loader.exec_module(WHITENING)
_amnezia_spec = importlib.util.spec_from_file_location('routervpn_amnezia', ROOT/'deploy/prepare-mobile-amnezia.py')
AMNEZIA = importlib.util.module_from_spec(_amnezia_spec)
_amnezia_spec.loader.exec_module(AMNEZIA)
_mtu_spec = importlib.util.spec_from_file_location('routervpn_mtu', ROOT/'deploy/prepare-mobile-mtu.py')
MTU = importlib.util.module_from_spec(_mtu_spec)
_mtu_spec.loader.exec_module(MTU)
_perf_spec = importlib.util.spec_from_file_location('routervpn_perf', ROOT/'deploy/prepare-mobile-performance.py')
PERFORMANCE = importlib.util.module_from_spec(_perf_spec)
_perf_spec.loader.exec_module(PERFORMANCE)
_wg_spec = importlib.util.spec_from_file_location('routervpn_wg_bind', ROOT/'deploy/mobile_wireguard_bind_policy.py')
WIREGUARD_BIND = importlib.util.module_from_spec(_wg_spec)
_wg_spec.loader.exec_module(WIREGUARD_BIND)
def inputs():
    paths = [ROOT/'deploy/test_ios_xray_exits.py', ROOT/'ios/RouterVPN/PacketTunnel/RouterVPNMultihopGraph.swift', ROOT/'deploy/testfixtures/xray-entry/main.go', ROOT/'deploy/test_ios_multihop_graph.py', ROOT/'mobile/routervpn_hop_measurement.go.tmpl', ROOT/'mobile/routervpn_multihop_bridge.go.tmpl', ROOT/'mobile/routervpn_multihop_native_test.go.tmpl', ROOT/'mobile/routervpn_sip003_bridge.go.tmpl', ROOT/'mobile/sip003/traffic_test.go.tmpl']
    for package in PACKAGES:
        paths += sorted((ROOT/'internal'/package).glob('*.go'))
    return paths + WIREGUARD_BIND.inputs() + WHITENING.inputs() + AMNEZIA.inputs() + PERFORMANCE.inputs() + MTU.inputs() + [Path(__file__).resolve()]

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
        if package == 'applexray':
            parent_test = output/'preparation_test.go'
            if parent_test.is_symlink(): raise ValueError('Linked parent-only test in native policy tree')
            if parent_test.exists():
                if not parent_test.is_file() or parent_test.read_bytes() != (ROOT/'internal/applexray/preparation_test.go').read_bytes():
                    raise ValueError('Unexpected parent-only test in native policy tree')
                parent_test.unlink()
        for source in (ROOT/'internal'/package).glob('*.go'):
            if source.name=='core_config_test.go' or (package=='applexray' and source.name=='preparation_test.go'):continue
            text=source.read_text()
            for name in PACKAGES:
                text=text.replace('"router-vpn/internal/'+name+'"','"github.com/sagernet/sing-box/experimental/libbox/routervpn/'+name+'"')
            (output/source.name).write_text(text)
    (root/'routervpn_multihop_bridge.go').write_bytes((ROOT/'mobile/routervpn_multihop_bridge.go.tmpl').read_bytes())
    (root/'routervpn_hop_measurement.go').write_bytes((ROOT/'mobile/routervpn_hop_measurement.go.tmpl').read_bytes())
    (root/'routervpn_multihop_native_test.go').write_bytes((ROOT/'mobile/routervpn_multihop_native_test.go.tmpl').read_bytes())
    (root/'routervpn_sip003_bridge.go').write_bytes((ROOT/'mobile/routervpn_sip003_bridge.go.tmpl').read_bytes())
    tests = vendor/'protocol/routervpnsip003test'
    tests.mkdir(parents=True, exist_ok=True)
    (tests/'traffic_test.go').write_bytes((ROOT/'mobile/sip003/traffic_test.go.tmpl').read_bytes())
    AMNEZIA.prepare(vendor)
    PERFORMANCE.prepare(vendor)
    MTU.prepare(vendor)
    WIREGUARD_BIND.prepare(vendor)
    print('Shared multihop source digest:',digest())
if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('vendor',type=Path,nargs='?');parser.add_argument('--digest',action='store_true');args=parser.parse_args()
    if args.digest:print(digest())
    elif args.vendor:prepare(args.vendor)
    else:parser.error('vendor checkout or --digest is required')
