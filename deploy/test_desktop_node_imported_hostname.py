#!/usr/bin/env python3
"""Run real encrypted packet-prefix / captured TCP DNS / hostname SS2022 peers.

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
_spec = importlib.util.spec_from_file_location('hostname_native_node_gate', ROOT / 'deploy/test_desktop_node_physical.py')
NODE = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(NODE)
TEST = 'TestRouterVPNDesktopNodeChainImportedHostnameTraffic'
MODES = ('wg', 'awg2-fast', 'awg2-strong')
METHODS = ('2022-blake3-aes-128-gcm', '2022-blake3-aes-256-gcm', '2022-blake3-chacha20-poly1305')
CASES = ('prefix-dns-public-middle-private-final', 'final-selected-dns', 'wrong-transport-dns',
         'wrong-middle-key', 'held-dns-cancel-join', 'stop-drains-middle-socket')
VERDICTS = (TEST, *(TEST + '/' + mode + '/' + method + suffix
    for mode in MODES for method in METHODS for suffix in ('', *('/' + case for case in CASES))))
TEMPLATE = 'node_chain_imported_hostname_test.go.tmpl'
NATIVE_TEMPLATE = 'protocol/routervpnamnezia/routervpn_desktop_node_chain_imported_hostname_test.go'
REQUIRED = (NATIVE_TEMPLATE,
    'protocol/routervpnamnezia/routervpn_desktop_node_chain_imported_test.go',
    'protocol/routervpnamnezia/routervpn_desktop_node_chain_peer_linux_test.go',
    'protocol/shadowsocks/outbound.go', 'protocol/wireguard/endpoint.go',
    'dns/router.go', 'dns/transport_manager.go', 'dns/transport/tcp.go', 'dns/transport/udp.go',
    'common/dialer/resolve.go', 'common/dialer/dialer.go',
    'experimental/libbox/routervpn/mobilemultihop/node_chain_imported_hostname.go',
    'experimental/libbox/routervpn/mobilemultihop/node_chain_imported.go',
    'experimental/libbox/routervpn/mobilemultihop/node_chain_graph.go')


def checked_sources(source):
    source, records = NODE.checked_sources(source)
    if NODE.PREP.PEER_TEMPLATES.get(TEMPLATE) != NATIVE_TEMPLATE:
        raise ValueError('Hostname native gate lost its test-only encrypted peer registration')
    expected = (ROOT / 'mobile/desktop' / TEMPLATE).read_bytes()
    if (source / NATIVE_TEMPLATE).read_bytes() != expected:
        raise ValueError('Hostname native peer differs from original source')
    for relative in REQUIRED:
        path = source / relative
        if path.is_symlink() or not path.is_file():
            raise ValueError('Hostname native source dependency missing: ' + relative)
        records[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
    for relative in ('deploy/test_desktop_node_imported_hostname.py', 'deploy/test_desktop_node_imported_hostname_runner.py'):
        path = ROOT / relative
        if path.is_symlink() or not path.is_file():
            raise ValueError('Hostname native gate source missing: ' + relative)
        records['gate/' + relative] = hashlib.sha256(path.read_bytes()).hexdigest()
    return source, records


def check_verdict(output):
    NODE.require_native_verdicts(output, VERDICTS, 'captured hostname encrypted DNS/SS path')


def execute_peer(image, source, captured):
    status, output = NODE.run([image, '-test.run=^' + TEST + '$', '-test.count=1', '-test.timeout=90s', '-test.v'],
                             cwd=source, env=captured, timeout=100)
    print(output, end='' if output.endswith('\n') else '\n', flush=True)
    if status:
        raise ValueError('Hostname native encrypted path failed')
    check_verdict(output)
    return output


def execute(source, go='go', *, evidence=None):
    if platform.system() != 'Linux':
        raise ValueError('Hostname encrypted peer fixture requires its actual Linux native target')
    source, before = checked_sources(source)
    compiler, captured, _ = NODE.selected_compiler(go, source, dict(os.environ))
    captured['CGO_ENABLED'] = '1'
    tags = NODE.TAGS
    with tempfile.TemporaryDirectory(prefix='routervpn-hostname-native-') as directory:
        image = Path(directory) / 'hostname-peer.test'
        build = [compiler, 'test', '-c', '-race', '-p=1', '-mod=readonly',
                 '-tags=' + ','.join(tags), '-ldflags=-checklinkname=0', '-o', image, './protocol/routervpnamnezia']
        status, output = NODE.run(build, cwd=source, env=captured, timeout=600)
        if status:
            raise ValueError('Hostname native image failed to compile:\n' + output[-24000:])
        if checked_sources(source)[1] != before:
            raise ValueError('Hostname native sources changed during compilation')
        identity = NODE.retained_binary(image)
        output = execute_peer(image, source, captured)
        if NODE.retained_binary(image) != identity or checked_sources(source)[1] != before:
            raise ValueError('Hostname native image or captured sources changed during execution')
        receipt = {'schema': 1, 'kind': 'native-encrypted-hostname-middle', 'verdicts': len(VERDICTS),
                   'source_sha256': before, 'image_sha256': hashlib.sha256(image.read_bytes()).hexdigest(),
                   'packet_modes': list(MODES), 'ss2022_methods': list(METHODS), 'cases': list(CASES),
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
