#!/usr/bin/env python3
"""Execute encrypted WG/AWG -> imported OpenVPN -> paired SS composition.

The compiler, proof controller and all three transport owners are real. The
outer engine identity remains an explicit component fixture. This gate does
not establish installed-host, kernel TUN/firewall or physical-device acceptance.
"""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import os
import platform
import tempfile

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location('openvpn_middle_native_node_gate', ROOT / 'deploy/test_desktop_node_physical.py')
NODE = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(NODE)
TRAFFIC = 'TestRouterVPNDesktopNodeChainOpenVPNMiddleTraffic'
REFUSAL = 'TestRouterVPNDesktopNodeChainOpenVPNMiddleRefusal'
SELECTION = '^(' + TRAFFIC + '|' + REFUSAL + ')$'
MODES = ('wg', 'awg2-fast', 'awg2-strong')
NETWORKS = ('tcp', 'udp')
CASES = ('complete-proof-dns-capacity', 'reconnect-rejects-original', 'fifty-responses-original-history', 'close-joins-native-stream')
NEGATIVES = ('wrong-entry-key', 'wrong-middle-password', 'wrong-control-key', 'wrong-final-key',
             'wrong-final-identity', 'omit-middle', 'selected-dns-failure')
VERDICTS = (TRAFFIC, *(TRAFFIC + '/' + mode + '--' + network + suffix
    for mode in MODES for network in NETWORKS for suffix in ('', *('/' + case for case in CASES))),
    REFUSAL, *(REFUSAL + '/' + network + suffix
    for network in NETWORKS for suffix in ('', *('/' + case for case in NEGATIVES))))
PHASES = tuple((mode, '^' + TRAFFIC + '$/^' + mode + '--(tcp|udp)$',
    (TRAFFIC, *(name for name in VERDICTS if name.startswith(TRAFFIC + '/' + mode + '--'))))
    for mode in MODES) + (('refusal', '^' + REFUSAL + '$',
    tuple(name for name in VERDICTS if name == REFUSAL or name.startswith(REFUSAL + '/'))),)


def checked_phases():
    expected = tuple((mode, '^' + TRAFFIC + '$/^' + mode + '--(tcp|udp)$',
        (TRAFFIC, *(name for name in VERDICTS if name.startswith(TRAFFIC + '/' + mode + '--'))))
        for mode in MODES) + (('refusal', '^' + REFUSAL + '$',
        tuple(name for name in VERDICTS if name == REFUSAL or name.startswith(REFUSAL + '/'))),)
    if PHASES != expected or len(PHASES) != 4:
        raise ValueError('Ordered OpenVPN native phase inventory changed')
    flattened = tuple(name for _, _, names in PHASES for name in names)
    if set(flattened) != set(VERDICTS) or len(flattened) != 50 or any(
            flattened.count(name) != (3 if name == TRAFFIC else 1) for name in VERDICTS):
        raise ValueError('Ordered OpenVPN native phases omitted or repeated a required case')
    return PHASES


TEMPLATE = 'node_chain_openvpn_peer_test.go.tmpl'
NATIVE_TEMPLATE = 'protocol/routervpnamnezia/routervpn_desktop_node_chain_openvpn_peer_test.go'
REQUIRED = (NATIVE_TEMPLATE,
    'protocol/routervpnamnezia/routervpn_desktop_node_chain_peer_linux_test.go',
    'protocol/routervpnamnezia/routervpn_desktop_node_chain_imported_test.go',
    'protocol/routervpnamnezia/routervpn_desktop_node_imported_peer_linux_test.go',
    'protocol/routervpnamnezia/routervpn_desktop_external_openvpn_installed_test.go',
    'protocol/openvpn/client.go', 'protocol/openvpn/server.go',
    'protocol/wireguard/endpoint.go', 'protocol/shadowsocks/outbound.go',
    'common/tls/std_client.go', 'common/tls/server.go',
    'dns/router.go', 'dns/transport_manager.go', 'dns/transport/udp.go',
    'experimental/libbox/routervpn/mobilemultihop/node_chain_imported_openvpn.go',
    'experimental/libbox/routervpn/mobilemultihop/node_chain_openvpn_runtime.go',
    'experimental/libbox/routervpn/mobilemultihop/node_chain_runtime.go',
    'experimental/libbox/routervpn/mobilemultihop/node_chain_mtu.go',
    'experimental/libbox/routervpn/hopmeasure/measure.go',
    'experimental/libbox/routervpn/hopmeasure/public.go',
    'experimental/libbox/routervpn/hopmeasure/ordered_latency.go')


def checked_sources(source):
    source, records = NODE.checked_sources(source)
    if NODE.PREP.PEER_TEMPLATES.get(TEMPLATE) != NATIVE_TEMPLATE:
        raise ValueError('Ordered OpenVPN native gate lost its encrypted peer registration')
    if (source / NATIVE_TEMPLATE).read_bytes() != (ROOT / 'mobile/desktop' / TEMPLATE).read_bytes():
        raise ValueError('Ordered OpenVPN native peer differs from original source')
    for relative in REQUIRED:
        path = source / relative
        if path.is_symlink() or not path.is_file():
            raise ValueError('Ordered OpenVPN native dependency missing: ' + relative)
        records[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
    for relative in ('deploy/test_desktop_node_chain_openvpn_middle.py', 'deploy/test_desktop_node_chain_openvpn_middle_runner.py'):
        path = ROOT / relative
        if path.is_symlink() or not path.is_file():
            raise ValueError('Ordered OpenVPN native gate source missing: ' + relative)
        records['gate/' + relative] = hashlib.sha256(path.read_bytes()).hexdigest()
    return source, records


def check_verdict(output):
    NODE.require_native_verdicts(output, VERDICTS, 'captured encrypted WG/AWG/OpenVPN/SS path')


def execute_peer(image, source, captured):
    phases = checked_phases()
    identity, sources = NODE.retained_binary(image), checked_sources(source)[1]
    outputs, completed = [], []
    for phase, selection, verdicts in phases:
        if NODE.retained_binary(image) != identity or checked_sources(source)[1] != sources:
            raise ValueError('Ordered OpenVPN native image or source changed before phase')
        status, output = NODE.run([image, '-test.run=' + selection, '-test.count=1', '-test.timeout=180s', '-test.v'],
                                 cwd=source, env=captured, timeout=190)
        print(output, end='' if output.endswith('\n') else '\n', flush=True)
        if status:
            raise ValueError('Ordered OpenVPN encrypted native phase failed: ' + phase)
        NODE.require_native_verdicts(output, verdicts, 'captured encrypted OpenVPN phase ' + phase)
        if NODE.retained_binary(image) != identity or checked_sources(source)[1] != sources:
            raise ValueError('Ordered OpenVPN native image or source changed during phase')
        outputs.append(output)
        completed.append(phase)
    if tuple(completed) != (*MODES, 'refusal'):
        raise ValueError('Ordered OpenVPN native phases did not all complete')
    return ''.join(outputs)


def execute(source, go='go', *, evidence=None):
    if platform.system() != 'Linux':
        raise ValueError('Ordered OpenVPN encrypted fixture requires its actual Linux native target')
    source, before = checked_sources(source)
    compiler, captured, _ = NODE.selected_compiler(go, source, dict(os.environ))
    captured['CGO_ENABLED'] = '1'
    with tempfile.TemporaryDirectory(prefix='routervpn-openvpn-middle-native-') as directory:
        image = Path(directory) / 'openvpn-middle-peer.test'
        build = [compiler, 'test', '-c', '-race', '-p=1', '-mod=readonly',
                 '-tags=' + ','.join(NODE.TAGS), '-ldflags=-checklinkname=0', '-o', image, './protocol/routervpnamnezia']
        status, output = NODE.run(build, cwd=source, env=captured, timeout=600)
        if status:
            raise ValueError('Ordered OpenVPN native image failed to compile:\n' + output[-24000:])
        if checked_sources(source)[1] != before:
            raise ValueError('Ordered OpenVPN native sources changed during compilation')
        identity = NODE.retained_binary(image)
        output = execute_peer(image, source, captured)
        if NODE.retained_binary(image) != identity or checked_sources(source)[1] != before:
            raise ValueError('Ordered OpenVPN native image or sources changed during execution')
        receipt = {'schema': 1, 'kind': 'native-encrypted-ordered-openvpn-middle', 'verdicts': len(VERDICTS),
                   'source_sha256': before, 'image_sha256': hashlib.sha256(image.read_bytes()).hexdigest(),
                   'packet_modes': list(MODES), 'openvpn_networks': list(NETWORKS),
                   'phases': [name for name, _, _ in checked_phases()], 'executed_verdicts': 50,
                   'cases': list(CASES), 'negative_controls': list(NEGATIVES),
                   'output_sha256': hashlib.sha256(output.encode()).hexdigest(),
                   'tun_kernel_device_acceptance': False}
        if evidence:
            Path(evidence).write_text(json.dumps(receipt, indent=2) + '\n')
        return receipt


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('--go', default='go')
    parser.add_argument('--evidence', type=Path)
    args = parser.parse_args()
    execute(args.source, args.go, evidence=args.evidence)
