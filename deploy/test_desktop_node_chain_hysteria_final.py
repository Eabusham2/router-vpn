#!/usr/bin/env python3
"""Run real encrypted ordered WG/AWG prefixes and a captured Hysteria2 final.

This is a native transport composition gate. It does not install a TUN, edit
host routes, or establish kernel firewall or device acceptance. Every original
peer, compiler, DNS router and DNS transport source is pinned before execution.
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
_spec = importlib.util.spec_from_file_location('hysteria_final_native_node_gate', ROOT / 'deploy/test_desktop_node_physical.py')
NODE = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(NODE)
TEST = 'TestRouterVPNDesktopNodeChainHysteriaFinalTraffic'
MODE_PAIRS = (('wg', 'wg'), ('awg2-fast', 'awg2-strong'), ('awg2-strong', 'awg2-fast'))
CASES = ('complete-private-public-proof', 'final-selected-dns', 'final-password', 'final-sni',
         'final-trust', 'final-mask', 'prefix-key', 'final-route', 'dns-route',
         'held-cancel-join', 'stop-drains-final-socket')
VERDICTS = (TEST, *(TEST + '/' + '--'.join(modes) + suffix
    for modes in MODE_PAIRS for suffix in ('', *('/' + case for case in CASES))))
TEMPLATE = 'node_chain_hysteria_final_test.go.tmpl'
NATIVE_TEMPLATE = 'protocol/routervpnamnezia/routervpn_desktop_node_chain_hysteria_final_test.go'
REQUIRED = (NATIVE_TEMPLATE,
    'protocol/routervpnamnezia/routervpn_desktop_node_chain_peer_linux_test.go',
    'protocol/routervpnamnezia/routervpn_desktop_node_chain_imported_hostname_test.go',
    'protocol/routervpnamnezia/routervpn_imported_hysteria_final_test.go',
    'protocol/routervpnamnezia/routervpn_desktop_node_hysteria2_peer_test.go',
    'protocol/hysteria2/outbound.go', 'protocol/wireguard/endpoint.go',
    'common/tls/std_client.go', 'common/tls/server.go',
    'dns/router.go', 'dns/transport_manager.go', 'dns/transport/udp.go',
    'experimental/libbox/routervpn/mobilemultihop/node_chain_final.go',
    'experimental/libbox/routervpn/mobilemultihop/node_chain_graph.go')


def checked_sources(source):
    source, records = NODE.checked_sources(source)
    if NODE.PREP.PEER_TEMPLATES.get(TEMPLATE) != NATIVE_TEMPLATE:
        raise ValueError('Ordered Hysteria2 native gate lost its test-only encrypted peer registration')
    expected = (ROOT / 'mobile/desktop' / TEMPLATE).read_bytes()
    if (source / NATIVE_TEMPLATE).read_bytes() != expected:
        raise ValueError('Ordered Hysteria2 native peer differs from original source')
    for relative in REQUIRED:
        path = source / relative
        if path.is_symlink() or not path.is_file():
            raise ValueError('Ordered Hysteria2 native source dependency missing: ' + relative)
        records[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
    for relative in ('deploy/test_desktop_node_chain_hysteria_final.py', 'deploy/test_desktop_node_chain_hysteria_final_runner.py'):
        path = ROOT / relative
        if path.is_symlink() or not path.is_file():
            raise ValueError('Ordered Hysteria2 native gate source missing: ' + relative)
        records['gate/' + relative] = hashlib.sha256(path.read_bytes()).hexdigest()
    return source, records


def check_verdict(output):
    NODE.require_native_verdicts(output, VERDICTS, 'captured ordered encrypted WG/AWG/Hysteria2 path')


def execute_peer(image, source, captured):
    status, output = NODE.run([image, '-test.run=^' + TEST + '$', '-test.count=1', '-test.timeout=90s', '-test.v'],
                             cwd=source, env=captured, timeout=100)
    print(output, end='' if output.endswith('\n') else '\n', flush=True)
    if status:
        raise ValueError('Ordered Hysteria2 native encrypted path failed')
    check_verdict(output)
    return output


def execute(source, go='go', *, evidence=None):
    if platform.system() != 'Linux':
        raise ValueError('Ordered Hysteria2 encrypted peer fixture requires its actual Linux native target')
    source, before = checked_sources(source)
    compiler, captured, _ = NODE.selected_compiler(go, source, dict(os.environ))
    captured['CGO_ENABLED'] = '1'
    tags = NODE.TAGS
    with tempfile.TemporaryDirectory(prefix='routervpn-hysteria-final-native-') as directory:
        image = Path(directory) / 'hysteria-final-peer.test'
        build = [compiler, 'test', '-c', '-race', '-p=1', '-mod=readonly',
                 '-tags=' + ','.join(tags), '-ldflags=-checklinkname=0', '-o', image, './protocol/routervpnamnezia']
        status, output = NODE.run(build, cwd=source, env=captured, timeout=600)
        if status:
            raise ValueError('Ordered Hysteria2 native image failed to compile:\n' + output[-24000:])
        if checked_sources(source)[1] != before:
            raise ValueError('Ordered Hysteria2 native sources changed during compilation')
        identity = NODE.retained_binary(image)
        output = execute_peer(image, source, captured)
        if NODE.retained_binary(image) != identity or checked_sources(source)[1] != before:
            raise ValueError('Ordered Hysteria2 native image or captured sources changed during execution')
        receipt = {'schema': 1, 'kind': 'native-encrypted-ordered-hysteria2-final', 'verdicts': len(VERDICTS),
                   'source_sha256': before, 'image_sha256': hashlib.sha256(image.read_bytes()).hexdigest(),
                   'packet_mode_pairs': [list(modes) for modes in MODE_PAIRS], 'cases': list(CASES),
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
