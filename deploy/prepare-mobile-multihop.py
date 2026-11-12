#!/usr/bin/env python3
"""Compile the tested shared route/lease policy into each existing Libbox build."""
import argparse
import hashlib
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKAGES = ('awgpolicy', 'routechoice', 'multihoprelay', 'mobilemultihop', 'mobilepq', 'applexray', 'nativesip003', 'nativecomposite', 'nativeopenvpn', 'hopmeasure', 'dnsmeasure', 'mobileperf', 'mobilemtu', 'mtuprobe')
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
_strategy_spec = importlib.util.spec_from_file_location('routervpn_strategy', ROOT/'deploy/prepare-mobile-strategy.py')
STRATEGY = importlib.util.module_from_spec(_strategy_spec)
_strategy_spec.loader.exec_module(STRATEGY)
_external_spec = importlib.util.spec_from_file_location('routervpn_external_policy', ROOT/'deploy/prepare-mobile-external-policy.py')
EXTERNAL_POLICY = importlib.util.module_from_spec(_external_spec)
_external_spec.loader.exec_module(EXTERNAL_POLICY)
_composite_spec = importlib.util.spec_from_file_location('routervpn_composite', ROOT/'deploy/prepare-mobile-composite.py')
COMPOSITE = importlib.util.module_from_spec(_composite_spec)
_composite_spec.loader.exec_module(COMPOSITE)
_wg_spec = importlib.util.spec_from_file_location('routervpn_wg_bind', ROOT/'deploy/mobile_wireguard_bind_policy.py')
WIREGUARD_BIND = importlib.util.module_from_spec(_wg_spec)
_wg_spec.loader.exec_module(WIREGUARD_BIND)
_openvpn_spec = importlib.util.spec_from_file_location('routervpn_openvpn_close', ROOT/'deploy/mobile_openvpn_close_policy.py')
OPENVPN_CLOSE = importlib.util.module_from_spec(_openvpn_spec)
_openvpn_spec.loader.exec_module(OPENVPN_CLOSE)
_openvpn_remote_spec = importlib.util.spec_from_file_location('routervpn_openvpn_remote', ROOT/'deploy/mobile_openvpn_remote_policy.py')
OPENVPN_REMOTE = importlib.util.module_from_spec(_openvpn_remote_spec)
_openvpn_remote_spec.loader.exec_module(OPENVPN_REMOTE)
_pq_spec = importlib.util.spec_from_file_location('routervpn_pq', ROOT/'deploy/prepare-mobile-pq.py')
PQ = importlib.util.module_from_spec(_pq_spec)
_pq_spec.loader.exec_module(PQ)
_hy2_spec = importlib.util.spec_from_file_location('routervpn_hy2_deadlines', ROOT/'deploy/prepare-hysteria2-deadlines.py')
HY2_DEADLINES = importlib.util.module_from_spec(_hy2_spec)
_hy2_spec.loader.exec_module(HY2_DEADLINES)
_observation_spec = importlib.util.spec_from_file_location('routervpn_observation_policy', ROOT/'deploy/native_observation_policy.py')
OBSERVATION = importlib.util.module_from_spec(_observation_spec)
_observation_spec.loader.exec_module(OBSERVATION)
_naive_spec = importlib.util.spec_from_file_location('routervpn_naive_transport', ROOT/'deploy/native_naive_transport_policy.py')
NAIVE = importlib.util.module_from_spec(_naive_spec)
_naive_spec.loader.exec_module(NAIVE)
_chain_spec = importlib.util.spec_from_file_location('routervpn_node_chain', ROOT/'deploy/prepare-mobile-node-chain.py')
NODE_CHAIN = importlib.util.module_from_spec(_chain_spec)
_chain_spec.loader.exec_module(NODE_CHAIN)
_execution_modules = []
for _name in ('prepare-node-chain-execution-gate', 'prepare-node-chain-execution', 'prepare-node-chain-execution-owner', 'prepare-mobile-node-chain-execution'):
    _spec = importlib.util.spec_from_file_location('mobile_'+_name.replace('-', '_'), ROOT/'deploy'/(_name+'.py'))
    _module = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_module)
    _execution_modules.append(_module)

def inputs():
    paths = [ROOT/'ios/RouterVPN/App/IOSHomeDNSPolicy.swift', ROOT/'deploy/test_ios_xray_exits.py', ROOT/'ios/RouterVPN/PacketTunnel/RouterVPNMultihopGraph.swift', ROOT/'deploy/testfixtures/xray-entry/main.go', ROOT/'deploy/test_ios_multihop_graph.py', ROOT/'mobile/routervpn_hop_measurement.go.tmpl', ROOT/'mobile/routervpn_multihop_bridge.go.tmpl', ROOT/'mobile/routervpn_external_policy_bridge.go.tmpl', ROOT/'mobile/routervpn_multihop_native_test.go.tmpl', ROOT/'mobile/routervpn_sip003_bridge.go.tmpl', ROOT/'mobile/sip003/traffic_test.go.tmpl']
    paths.append(ROOT/'mobile/routervpn_external_measurement_bridge.go.tmpl')
    paths.append(ROOT/'mobile/routervpn_external_measurement_context_test.go.tmpl')
    paths.append(ROOT/'mobile/routervpn_dns_measurement.go.tmpl')
    paths.append(ROOT/'mobile/routervpn_imported_entry.go.tmpl')
    paths.append(ROOT/'mobile/daemon/instance_context.go.tmpl')
    paths.append(ROOT/'mobile/daemon/instance_context_test.go.tmpl')
    paths.append(ROOT/'mobile/routervpn_imported_entry_native_test.go.tmpl')
    paths.append(ROOT/'mobile/routervpn_imported_openvpn_native_test.go.tmpl')
    paths.append(ROOT/'mobile/routervpn_imported_packet_xray_native_test.go.tmpl')
    paths.append(ROOT/'mobile/routervpn_imported_pq_xray_native_test.go.tmpl')
    paths.append(ROOT/'mobile/routervpn_imported_xhttp_xray_native_test.go.tmpl')
    paths.append(ROOT/'mobile/routervpn_imported_naive_h2_native_test.go.tmpl')
    paths.append(ROOT/'mobile/routervpn_imported_naive_h3_native_test.go.tmpl')
    paths.append(ROOT/'mobile/routervpn_imported_naive_h2_loader_purego_test.go.tmpl')
    paths.append(ROOT/'mobile/routervpn_imported_naive_h3_loader_purego_test.go.tmpl')
    paths.append(ROOT/'mobile/routervpn_multihop_context_test.go.tmpl')
    for package in PACKAGES:
        paths += sorted((ROOT/'internal'/package).glob('*.go'))
    return paths + [path for module in _execution_modules for path in module.inputs()] + NODE_CHAIN.inputs() + NAIVE.inputs() + OBSERVATION.inputs() + HY2_DEADLINES.inputs() + PQ.inputs() + WIREGUARD_BIND.inputs() + OPENVPN_CLOSE.inputs() + OPENVPN_REMOTE.inputs() + WHITENING.inputs() + AMNEZIA.inputs() + PERFORMANCE.inputs() + MTU.inputs() + STRATEGY.inputs() + EXTERNAL_POLICY.inputs() + COMPOSITE.inputs() + [Path(__file__).resolve()]

def digest():
    h=hashlib.sha256()
    for source in inputs():
        h.update(str(source.relative_to(ROOT)).encode()+b'\0'+source.read_bytes())
    return h.hexdigest()

def prepare(vendor):
    vendor=vendor.resolve();module=vendor/'go.mod'
    if not module.is_file() or not module.read_text().startswith('module github.com/sagernet/sing-box\n'):
        raise ValueError('expected the verified disposable sing-box checkout')
    HY2_DEADLINES.prepare(vendor)
    WHITENING.prepare(vendor)
    NAIVE.prepare(vendor)
    OBSERVATION.prepare(vendor)
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
            # Preserve source bytes across hosts. Text-mode writes expand LF
            # to CRLF on Windows and invalidate the copied policy identity.
            content=OBSERVATION.rewrite(source.read_bytes())
            for name in PACKAGES:
                content=content.replace(('"router-vpn/internal/'+name+'"').encode(),('"github.com/sagernet/sing-box/experimental/libbox/routervpn/'+name+'"').encode())
            (output/source.name).write_bytes(content)
    (root/'routervpn_imported_entry_native_test.go').write_bytes((ROOT/'mobile/routervpn_imported_entry_native_test.go.tmpl').read_bytes())
    (root/'routervpn_imported_openvpn_native_test.go').write_bytes((ROOT/'mobile/routervpn_imported_openvpn_native_test.go.tmpl').read_bytes())
    (root/'routervpn_imported_packet_xray_native_test.go').write_bytes((ROOT/'mobile/routervpn_imported_packet_xray_native_test.go.tmpl').read_bytes())
    (root/'routervpn_imported_pq_xray_native_test.go').write_bytes((ROOT/'mobile/routervpn_imported_pq_xray_native_test.go.tmpl').read_bytes())
    (root/'routervpn_imported_xhttp_xray_native_test.go').write_bytes((ROOT/'mobile/routervpn_imported_xhttp_xray_native_test.go.tmpl').read_bytes())
    (root/'routervpn_imported_naive_h2_native_test.go').write_bytes((ROOT/'mobile/routervpn_imported_naive_h2_native_test.go.tmpl').read_bytes())
    (root/'routervpn_imported_naive_h3_native_test.go').write_bytes((ROOT/'mobile/routervpn_imported_naive_h3_native_test.go.tmpl').read_bytes())
    (root/'routervpn_imported_naive_h2_loader_purego_test.go').write_bytes((ROOT/'mobile/routervpn_imported_naive_h2_loader_purego_test.go.tmpl').read_bytes())
    (root/'routervpn_imported_naive_h3_loader_purego_test.go').write_bytes((ROOT/'mobile/routervpn_imported_naive_h3_loader_purego_test.go.tmpl').read_bytes())
    (root/'routervpn_multihop_context_test.go').write_bytes((ROOT/'mobile/routervpn_multihop_context_test.go.tmpl').read_bytes())
    (root/'routervpn_imported_entry.go').write_bytes((ROOT/'mobile/routervpn_imported_entry.go.tmpl').read_bytes())
    instance_context = vendor/'daemon/routervpn_instance_context.go'
    if instance_context.is_symlink() or not instance_context.resolve().is_relative_to(vendor.resolve()):
        raise ValueError('Linked native instance observation target')
    instance_context.write_bytes((ROOT/'mobile/daemon/instance_context.go.tmpl').read_bytes())
    instance_test = instance_context.with_name('routervpn_instance_context_test.go')
    if instance_test.is_symlink(): raise ValueError('Linked native instance observation fixture')
    instance_test.write_bytes((ROOT/'mobile/daemon/instance_context_test.go.tmpl').read_bytes())
    (root/'routervpn_multihop_bridge.go').write_bytes((ROOT/'mobile/routervpn_multihop_bridge.go.tmpl').read_bytes())
    (root/'routervpn_external_policy_bridge.go').write_bytes((ROOT/'mobile/routervpn_external_policy_bridge.go.tmpl').read_bytes())
    (root/'routervpn_external_measurement_bridge.go').write_bytes((ROOT/'mobile/routervpn_external_measurement_bridge.go.tmpl').read_bytes())
    (root/'routervpn_external_measurement_context_test.go').write_bytes((ROOT/'mobile/routervpn_external_measurement_context_test.go.tmpl').read_bytes())
    (root/'routervpn_hop_measurement.go').write_bytes((ROOT/'mobile/routervpn_hop_measurement.go.tmpl').read_bytes())
    (root/'routervpn_dns_measurement.go').write_bytes((ROOT/'mobile/routervpn_dns_measurement.go.tmpl').read_bytes())
    (root/'routervpn_multihop_native_test.go').write_bytes((ROOT/'mobile/routervpn_multihop_native_test.go.tmpl').read_bytes())
    (root/'routervpn_sip003_bridge.go').write_bytes((ROOT/'mobile/routervpn_sip003_bridge.go.tmpl').read_bytes())
    tests = vendor/'protocol/routervpnsip003test'
    tests.mkdir(parents=True, exist_ok=True)
    (tests/'traffic_test.go').write_bytes((ROOT/'mobile/sip003/traffic_test.go.tmpl').read_bytes())
    AMNEZIA.prepare(vendor)
    PQ.prepare(vendor)
    PERFORMANCE.prepare(vendor)
    MTU.prepare(vendor)
    STRATEGY.prepare(vendor)
    NODE_CHAIN.prepare(vendor)
    EXTERNAL_POLICY.prepare(vendor)
    for module in _execution_modules:
        module.prepare(vendor)
    COMPOSITE.prepare(vendor)
    WIREGUARD_BIND.prepare(vendor)
    OPENVPN_CLOSE.prepare(vendor)
    OPENVPN_REMOTE.prepare(vendor)
    print('Shared multihop source digest:',digest())
if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('vendor',type=Path,nargs='?');parser.add_argument('--digest',action='store_true');args=parser.parse_args()
    if args.digest:print(digest())
    elif args.vendor:prepare(args.vendor)
    else:parser.error('vendor checkout or --digest is required')
