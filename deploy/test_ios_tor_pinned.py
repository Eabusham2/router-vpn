#!/usr/bin/env python3
"""Check shipping Apple Tor graphs with the pinned real Linux native engines.

The positive pass calls Libbox.CheckConfig on the unchanged Swift/Go output.
The negative pass uses a temporary Go overlay removing only Tor registration,
and checks all the same configurations again. Neither pass starts a VPN.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import itertools
import json
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT/'ios/RouterVPN/App'
TUN = ROOT/'ios/RouterVPN/PacketTunnel'
TEMPLATE = ROOT/'mobile/routervpn_tor_ios_graph_test.go.tmpl'
PADDING_TEMPLATE = ROOT/'mobile/routervpn_tor_ios_padding_graph_test.go.tmpl'
FIXTURE = ROOT/'deploy/test_ios_tor_profile.py'
SERVER_FIXTURE = ROOT/'deploy/test_ios_tor_server_profile.py'
TEST = 'TestRouterTorAppleGeneratedGraphs'
PADDING_TEST = 'TestRouterTorAppleLocalPaddingGraphs'
TAGS = 'with_quic,with_wireguard,with_gvisor,with_openvpn,with_naive_outbound,routervpn_tor_native_test'
MODES = ('wg', 'awg2-fast', 'awg2-strong', 'wg-pq', 'awg2-pq', 'shadowsocks',
         'hysteria2', 'naive-h2', 'naive-h3', 'reality-vision', 'reality-pq-vision',
         'reality-xhttp', 'ss-v2ray', 'split', 'max', 'max-tls-wg', 'max-tls-awg',
         'max-quic-wg', 'max-quic-awg')
KINDS = ('tor', 'obfs4', 'meek_lite', 'snowflake', 'webtunnel', 'custom')
LAYERS = ('off', 'aes-256-gcm', 'aes-256-gcm+xor-whitening')
ORDINARY_MODES = ('wireguard', 'amneziawg', 'socks5', 'http-connect', 'https-connect',
                  'shadowsocks', 'hysteria2', 'openvpn')


def module(name: str, relative: str):
    spec = importlib.util.spec_from_file_location(name, ROOT/relative)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


TOR = module('apple_tor_preparation', 'deploy/prepare-mobile-tor.py')
MULTIHOP = module('apple_tor_entry_preparation', 'deploy/prepare-mobile-multihop.py')
XRAY = module('apple_tor_xray_preparation', 'deploy/prepare-apple-xray.py')
HOST = module('apple_tor_native_host', 'deploy/native_tor_graph_host.py')
PIN = TOR.CORE


def host_sources(execution: str = 'local') -> list[Path]:
    # This is the exact source list recorded by the executable Swift fixture.
    return [FIXTURE, *([SERVER_FIXTURE] if execution == 'server' else []), ROOT/'mobile/routervpn_openvpn.go', ROOT/'mobile/toroutbound/bridge.go.tmpl', APP/'IOSExternalNodeBuilderView.swift', TUN/'PacketTunnelProvider.swift',
            *[APP/(name+'.swift') for name in ('Models', 'IOSExternalExecution', 'IOSMultihopExecution', 'IOSDNSRuntimePolicy',
                'IOSNativeXrayProfile', 'IOSNativePQProfile', 'IOSMultihopStartLayer', 'IOSRuntimeSelection')],
            *[TUN/(name+'.swift') for name in ('WireGuardQuickConfig', 'RouterVPNMultihopGraph',
                'RouterVPNMTUPolicy', 'IOSStartLayer', 'IOSXrayDevicePolicy', 'RouterVPNExternalExit')]]


def inputs() -> list[Path]:
    # These additional inputs have their own Swift 6 executable delivery gate;
    # they are not compiled by the graph-emitter source list above.
    extra = [Path(__file__).resolve(), TEMPLATE, PADDING_TEMPLATE, ROOT/'deploy/test_ios_tor_pinned_contract.py',
             TUN/'RouterVPNTorPaddingReceipt.swift', TUN/'RouterVPNLibboxEngine.swift',
             ROOT/'deploy/test_ios_libbox_delivery.py', ROOT/'ios/RouterVPN/prepare-libbox.sh',
             ROOT/'ios/RouterVPN/test_libbox_build_contract.py',
             ROOT/'deploy/test_ios_pq_selection.py', ROOT/'deploy/test_ios_wireguard_parser.py',
             ROOT/'deploy/test_ios_native_base_selection.py', ROOT/'android/test_android_multihop_graph.py',
             ROOT/'deploy/testfixtures/composite/main.go', ROOT/'go.mod']
    if (ROOT/'go.sum').exists():
        extra.append(ROOT/'go.sum')
    return sorted(set(extra + host_sources('server') + TOR.inputs() + MULTIHOP.inputs() + XRAY.sources() + HOST.inputs()))


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_hashes() -> dict[str, str]:
    return {str(path.relative_to(ROOT)): sha(path) for path in inputs()}


def digest() -> str:
    value = hashlib.sha256()
    for path in inputs():
        value.update(str(path.relative_to(ROOT)).encode()+b'\0'+path.read_bytes()+b'\0')
    return value.hexdigest()


def cases(execution: str = 'local') -> dict[str, tuple[str, str, str]]:
    if execution not in ('local', 'server'):
        raise ValueError('Unknown Apple Tor execution matrix')
    values = [(mode, layer, kind) for mode, layer, kind in itertools.product(MODES, LAYERS, KINDS)]
    if execution == 'local':
        values += [('direct', 'off', kind) for kind in KINDS]
        values += [('external-'+mode, 'off', kind) for mode, kind in itertools.product(ORDINARY_MODES, KINDS)]
    return {'-'.join(value): value for value in values}


def native_cases() -> set[str]:
    return {execution+'-'+name for execution in ('local', 'server') for name in cases(execution)}


def padding_cases() -> dict[str, tuple[str, str, str, int]]:
    values = list(itertools.product(MODES, LAYERS, ('tor', 'obfs4'), (0, 32, 64, 192)))
    values += [('direct', 'off', kind, rate) for kind, rate in itertools.product(('tor', 'obfs4'), (0, 32, 64, 192))]
    values += [('external-'+mode, 'off', kind, rate) for mode, kind, rate in itertools.product(ORDINARY_MODES, ('tor', 'obfs4'), (0, 32, 64, 192))]
    return {'-'.join(map(str, value)): value for value in values}


def require_padding_matrix(folder: Path) -> dict[str, str]:
    if folder.is_symlink() or not folder.is_dir():
        raise ValueError('Apple padding matrix requires an owned directory')
    expected = padding_cases()
    if len(expected) != 528 or {path.name for path in folder.iterdir()} != set(expected) | {'source-evidence.json'}:
        raise ValueError('Apple padding matrix must contain exactly 528 named graphs and source evidence')
    report = json.loads(regular(folder/'source-evidence.json'))
    required = dict(schema=1, execution='local', padding_enabled=True, graphs=528,
        private_graphs=456, direct_graphs=8, ordinary_graphs=64, rates_kbps=[0, 32, 64, 192],
        entry_layers=list(LAYERS), public_tor_traffic=False, native_handles='boundary doubles',
        sources={str(path.relative_to(ROOT)): sha(path) for path in host_sources()})
    if report != required:
        raise ValueError('Apple padding export is stale or has different source ownership')
    result = {'source-evidence.json': sha(folder/'source-evidence.json')}
    sessions = set()
    for name, (mode, layer, kind, rate) in sorted(expected.items()):
        entry = folder/name
        if entry.is_symlink() or not entry.is_dir():
            raise ValueError('Unowned Apple padding directory: '+name)
        assets = {'fixture.json', 'sing-box.json'}
        if mode in ('naive-h2', 'naive-h3', 'hysteria2'):
            assets.add('trust.pem')
        if mode.startswith('reality-'):
            assets.add('xray.json')
        if {path.name for path in entry.iterdir()} != assets:
            raise ValueError('Missing or extra Apple padding graph asset: '+name)
        data = {asset: regular(entry/asset) for asset in sorted(assets)}
        fixture, graph = json.loads(data['fixture.json']), json.loads(data['sing-box.json'])
        if (set(fixture) != {'mode', 'layer', 'transport', 'rate_kbps', 'session', 'source_sha256'}
                or (fixture['mode'], fixture['layer'], fixture['transport'], fixture['rate_kbps']) != (mode, layer, kind, rate)
                or type(fixture['rate_kbps']) is not int
                or not isinstance(fixture['session'], str) or not 0 < len(fixture['session']) <= 512
                or fixture['session'] in sessions or not isinstance(fixture['source_sha256'], str)
                or len(fixture['source_sha256']) != 64 or any(c not in '0123456789abcdef' for c in fixture['source_sha256'])):
            raise ValueError('Apple padding fixture lost its exact selection or source identity: '+name)
        sessions.add(fixture['session'])
        owners = [row for row in graph.get('outbounds', []) if row.get('type') in ('routervpn-tor', 'routervpn-server-tor')]
        if (len(owners) != 1 or owners[0].get('type') != 'routervpn-tor'
                or owners[0].get('tag') != 'routervpn-tor-exit' or owners[0].get('session_id') != fixture['session']):
            raise ValueError('Apple padding graph lost its unique native Local owner: '+name)
        source = owners[0].get('padding_source')
        keys = {'profile'} if mode == 'direct' else {'profile', 'predecessor_profile', 'predecessor_config'}
        if (not isinstance(source, dict) or set(source) != keys
                or any(not isinstance(value, str) or not isinstance(json.loads(value), dict) for value in source.values())):
            raise ValueError('Apple padding graph lost its complete typed source: '+name)
        selected = json.loads(source['profile'])
        if (selected.get('daita_enabled') is not True or type(selected.get('daita_rate_kbps')) is not int
                or selected['daita_rate_kbps'] != rate or selected.get('multihop_execution', 'local') != 'local'):
            raise ValueError('Apple padding graph changed selected rate or execution: '+name)
        if mode != 'direct':
            previous = json.loads(source['predecessor_profile'])
            if selected.get('multihop_entry_id') != previous.get('id') or selected.get('multihop_entry_mode') != mode.removeprefix('external-'):
                raise ValueError('Apple padding graph substituted its captured predecessor: '+name)
            if mode.startswith('external-'):
                if (previous.get('node_kind') != 'external' or previous.get('external', {}).get('protocol') != mode.removeprefix('external-')
                        or any(previous.get(key) not in ('', None) for key in ('node_proof_id', 'router_api', 'api_token'))):
                    raise ValueError('Apple ordinary padding graph acquired private authority: '+name)
            elif previous.get('node_kind') == 'external' or previous.get('start_layer', 'off') != layer:
                raise ValueError('Apple private padding graph changed its captured Start Layer: '+name)
        for asset, content in data.items():
            result[name+'/'+asset] = hashlib.sha256(content).hexdigest()
    return result


def regular(path: Path, maximum: int = 4*1024*1024) -> bytes:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= maximum:
        raise ValueError('Missing, empty, oversized or linked Apple fixture: '+str(path))
    return path.read_bytes()


def require_matrix(folder: Path, execution: str = 'local') -> dict[str, str]:
    if folder.is_symlink() or not folder.is_dir():
        raise ValueError('Apple Tor matrix requires an owned directory')
    expected = cases(execution)
    count = 342 if execution == 'server' else 396
    if len(expected) != count or {path.name for path in folder.iterdir()} != set(expected) | {'source-evidence.json'}:
        raise ValueError(f'Apple Tor {execution} matrix must contain exactly {count} named graphs and source evidence')
    report = json.loads(regular(folder/'source-evidence.json'))
    hashes = {str(path.relative_to(ROOT)): sha(path) for path in host_sources(execution)}
    if (report.get('schema') != 1 or report.get('graphs') != count
            or report.get('home_dns_combinations') != (5 if execution == 'server' else 285)
            or (report.get('execution') != 'server' if execution == 'server' else report.get('profile_policy_combinations') != 320)
            or (execution == 'local' and (report.get('router_tor_graphs') != 348 or report.get('ordinary_tor_graphs') != 48))
            or report.get('public_tor_traffic') is not False
            or report.get('native_handles') != 'boundary doubles' or report.get('sources') != hashes):
        raise ValueError('Apple Tor export is stale or has different source ownership')
    result = {'source-evidence.json': sha(folder/'source-evidence.json')}
    for name, (mode, layer, kind) in sorted(expected.items()):
        entry = folder/name
        if entry.is_symlink() or not entry.is_dir():
            raise ValueError('Unowned Apple graph directory: '+name)
        assets = {'fixture.json', 'sing-box.json'}
        if mode in ('naive-h2', 'naive-h3', 'hysteria2'):
            assets.add('trust.pem')
        if mode in ('reality-vision', 'reality-pq-vision', 'reality-xhttp'):
            assets.add('xray.json')
        if {path.name for path in entry.iterdir()} != assets:
            raise ValueError('Missing or extra Apple graph asset: '+name)
        data = {asset: regular(entry/asset) for asset in sorted(assets)}
        fixture = json.loads(data['fixture.json'])
        if (set(fixture) != {'mode', 'layer', 'transport', 'session'}
                or (fixture['mode'], fixture['layer'], fixture['transport']) != (mode, layer, kind)
                or not isinstance(fixture['session'], str) or not 0 < len(fixture['session']) <= 512):
            raise ValueError('Apple graph disagrees with its captured fixture: '+name)
        graph = json.loads(data['sing-box.json'])
        owners = [out for out in graph.get('outbounds', []) if out.get('type') in ('routervpn-tor', 'routervpn-server-tor')]
        owner_type = 'routervpn-server-tor' if execution == 'server' else 'routervpn-tor'
        if len(owners) != 1 or owners[0].get('type') != owner_type or owners[0].get('session_id') != fixture['session']:
            raise ValueError('Apple graph lost its exact native Tor session: '+name)
        if execution == 'server':
            owner = owners[0]
            if (set(owner) != {'type', 'tag', 'profile', 'session_id', 'entry_config', 'entry_profile'}
                    or owner.get('tag') != 'routervpn-tor-exit'
                    or any(not isinstance(owner.get(key), str) or not isinstance(json.loads(owner[key]), dict)
                           for key in ('profile', 'entry_config', 'entry_profile'))):
                raise ValueError('Apple Server graph lost its exact private source inputs: '+name)
        elif mode.startswith('external-'):
            owner = owners[0]
            fields = ('external_tor_profile', 'external_predecessor_profile', 'external_predecessor_config')
            if (owner.get('tag') != 'routervpn-tor-exit' or owner.get('detour') != 'custom-exit'
                    or any(not isinstance(owner.get(key), str) or not isinstance(json.loads(owner[key]), dict) for key in fields)):
                raise ValueError('Apple ordinary Tor graph lost its exact typed source inputs: '+name)
            selected, predecessor, source = (json.loads(owner[key]) for key in fields)
            external = predecessor.get('external', {})
            protocol = mode.removeprefix('external-')
            if (predecessor.get('node_kind') != 'external' or not isinstance(external, dict)
                    or external.get('protocol') != protocol or not external.get('expected_public_ip')
                    or any(predecessor.get(key) not in ('', None) for key in ('node_proof_id', 'router_api', 'api_token'))
                    or selected.get('multihop_execution') != 'local' or selected.get('multihop_enabled') is not True
                    or selected.get('multihop_entry_id') != predecessor.get('id') or not predecessor.get('id')
                    or selected.get('multihop_entry_mode') != protocol
                    or selected.get('multihop_exit_id') != selected.get('id') or not selected.get('id')
                    or selected.get('multihop_exit_mode') != ('tor' if kind == 'tor' else 'tor-bridge')
                    or not isinstance(source.get('route'), dict) or source['route'].get('final') != 'custom-exit'):
                raise ValueError('Apple ordinary Tor graph changed its captured role or acquired private authority: '+name)
        elif any(key in owners[0] for key in ('external_tor_profile', 'external_predecessor_profile', 'external_predecessor_config')):
            raise ValueError('Apple private or direct Tor graph acquired an ordinary predecessor: '+name)
        for asset, content in data.items():
            result[name+'/'+asset] = hashlib.sha256(content).hexdigest()
    return result


def verify_prepared(vendor: Path) -> None:
    record = json.loads(regular(TOR.destination(vendor, TOR.OWNER)))
    copied = TOR.copies()
    hashes = {name: hashlib.sha256(data).hexdigest() for name, data in copied.items()}
    if (record.get('schema') != 1 or record.get('core') != PIN
            or record.get('source_sha256') != TOR.digest() or record.get('files') != hashes):
        raise ValueError('Prepared native Tor source differs from the shipping source')
    for name, data in copied.items():
        if TOR.destination(vendor, name).read_bytes() != data:
            raise ValueError('Prepared native Tor source changed: '+name)
    dns = (ROOT/'mobile/toroutbound/dns_adapter.go.tmpl').read_bytes()
    if (record.get('dns_adapter_sha256') != hashlib.sha256(dns).hexdigest()
            or TOR.destination(vendor, 'dns/transport_adapter.go').read_bytes() != dns):
        raise ValueError('Prepared native Tor DNS adapter changed')
    pack = TOR.TORPACK
    loader = {'routervpn/nativetor/'+name: (pack.SOURCE/(name+'.tmpl')).read_bytes()
              for name in ('native.go', 'backend.go', 'unavailable.go')}
    loader['routervpn/nativetor/routervpn_tor_host.h'] = (ROOT/'mobile/tor/routervpn_tor_host.h').read_bytes()
    loader['experimental/libbox/routervpn_tor_native.go'] = (pack.SOURCE/'bridge.go.tmpl').read_bytes()
    record = json.loads(regular(pack.destination(vendor, pack.OWNER)))
    if (record.get('schema') != 1 or record.get('core') != PIN
            or record.get('source_sha256') != pack.digest() or not isinstance(record.get('files'), dict)):
        raise ValueError('Prepared C Tor loader ownership is stale')
    for name, data in loader.items():
        if (record['files'].get(name) != hashlib.sha256(data).hexdigest()
                or pack.destination(vendor, name).read_bytes() != data):
            raise ValueError('Prepared C Tor loader differs from the shipping source')


def missing_tor_registry(source: bytes) -> bytes:
    """Remove the actual registry entry; every generated graph remains intact."""
    source = source.decode()
    for line in ('\t"github.com/sagernet/sing-box/protocol/routervpntor"\n',
                 '\troutervpntor.RegisterOutbound(registry)\n'):
        if source.count(line) != 1:
            raise ValueError('Native Tor registration boundary changed')
        source = source.replace(line, '', 1)
    return source.encode()


def host_environment(go: str, library: Path, clang: str | None = None) -> dict[str, str]:
    return HOST.environment(go, library, clang, require_swift=True)


def run_native(command: list[str], vendor: Path, env: dict[str, str], log: Path) -> None:
    with log.open('x') as stream:
        result = subprocess.run(command, cwd=vendor, env=env, stdout=stream, stderr=subprocess.STDOUT, timeout=600)
    content = log.read_text(errors='replace')
    if result.returncode:
        raise RuntimeError('Apple native Tor parser failed:\n'+content[-10000:])
    passed, padded = set(), set()
    for line in content.splitlines():
        event = json.loads(line)
        if event.get('Action') == 'pass' and event.get('Test', '').startswith(TEST+'/'):
            passed.add(event['Test'][len(TEST)+1:])
        if event.get('Action') == 'pass' and event.get('Test', '').startswith(PADDING_TEST+'/'):
            padded.add(event['Test'][len(PADDING_TEST)+1:])
    if passed != native_cases():
        raise ValueError('Native parser did not execute every one of the 738 Apple Local and Server configurations')
    if padded != set(padding_cases()):
        raise ValueError('Native parser did not execute every one of the 528 additional enabled Apple Local padding configurations')


def run(vendor: Path, package: Path, go: str, graphs: Path | None = None,
        output: Path | None = None, clang: str | None = None, server_graphs: Path | None = None,
        padding_graphs: Path | None = None) -> None:
    if vendor.is_symlink() or package.is_symlink():
        raise ValueError('Native source and C package must be owned directories')
    vendor, package = vendor.resolve(strict=True), package.resolve(strict=True)
    if subprocess.check_output(['git', '-C', str(vendor), 'rev-parse', 'HEAD'], text=True).strip() != PIN:
        raise ValueError('Apple Tor gate needs the exact pinned native core')
    package_record = TOR.TORPACK.PACKAGE.verify(package, 'host-test')
    verify_prepared(vendor)
    library = package/'lib/libroutervpn_tor.so'
    native = sha(library)
    env = host_environment(go, library, clang)
    before = source_hashes()
    modules = {name: sha(vendor/name) for name in ('go.mod', 'go.sum')}
    registry = TOR.destination(vendor, 'include/registry.go')
    registry_source = registry.read_bytes()
    absent = missing_tor_registry(registry_source)
    target = TOR.destination(vendor, 'experimental/libbox/routervpn_tor_ios_graph_test.go')
    padding_target = TOR.destination(vendor, 'experimental/libbox/routervpn_tor_ios_padding_graph_test.go')
    data = TEMPLATE.read_bytes()
    padding_data = PADDING_TEMPLATE.read_bytes()
    if target.exists() or padding_target.exists():
        raise ValueError('Apple native parser test destination must be unused')
    if output is not None:
        output.mkdir(parents=True, exist_ok=False)
    with tempfile.TemporaryDirectory(prefix='routervpn-apple-tor-native-') as temporary:
        work = Path(temporary)
        logs = output or work
        generator_env = env.copy()
        # Fixture compilers are ordinary host programs. Their nested build
        # helpers may set link flags, so never inject the Tor DSO into them.
        generator_env.pop('CGO_LDFLAGS', None)
        generate_padding = padding_graphs is None
        if generate_padding:
            padding_graphs = work/'padding-graphs'; padding_graphs.mkdir()
        if graphs is None:
            graphs = work/'graphs'; graphs.mkdir()
            subprocess.run([sys.executable, str(FIXTURE), '--output', str(graphs)] +
                           (['--padding-output', str(padding_graphs)] if generate_padding else []),
                           cwd=ROOT, env=generator_env, check=True, timeout=600)
        elif generate_padding:
            subprocess.run([sys.executable, str(FIXTURE), '--padding-only', '--padding-output', str(padding_graphs)],
                           cwd=ROOT, env=generator_env, check=True, timeout=600)
        graph_hashes = require_matrix(graphs)
        padding_hashes = require_padding_matrix(padding_graphs)
        if server_graphs is None:
            server_graphs = work/'server-graphs'; server_graphs.mkdir()
            subprocess.run([sys.executable, str(SERVER_FIXTURE), '--output', str(server_graphs)],
                           cwd=ROOT, env=generator_env, check=True, timeout=600)
        server_hashes = require_matrix(server_graphs, 'server')
        env['ROUTERVPN_IOS_TOR_GRAPHS'] = str(graphs.resolve())
        env['ROUTERVPN_IOS_TOR_SERVER_GRAPHS'] = str(server_graphs.resolve())
        env['ROUTERVPN_IOS_LOCAL_PADDING_GRAPHS'] = str(padding_graphs.resolve())
        # Both suites share one process-owned Tor state; their disposable
        # Libbox directories must not replace that retained native identity.
        env['ROUTERVPN_IOS_TOR_STATE'] = str(work/'tor-state')
        (work/'registry.go').write_bytes(absent)
        overlay = work/'overlay.json'
        overlay.write_text(json.dumps({'Replace': {str(registry): str(work/'registry.go')}}))
        command = [go, 'test', '-mod=readonly', '-json', '-ldflags=-checklinkname=0',
                   '-tags', TAGS, './experimental/libbox', '-run', '^('+TEST+'|'+PADDING_TEST+')$', '-count=1', '-timeout=240s']
        try:
            with target.open('xb') as stream:
                stream.write(data)
            with padding_target.open('xb') as stream:
                stream.write(padding_data)
            run_native(command, vendor, env, logs/'native-positive.jsonl')
            print('PASS Apple Tor: 738 original Local/Server and 528 additional enabled Local padding configurations accepted by real native engines', flush=True)
            negative = dict(env, ROUTERVPN_IOS_TOR_MISSING_ENGINE='1')
            run_native(command[:2]+['-overlay', str(overlay)]+command[2:], vendor, negative, logs/'native-missing-engine.jsonl')
            print('PASS Apple Tor: all 1,266 unchanged configurations reject missing Tor registration', flush=True)
            if (source_hashes() != before or sha(library) != native or require_matrix(graphs) != graph_hashes
                    or require_matrix(server_graphs, 'server') != server_hashes
                    or require_padding_matrix(padding_graphs) != padding_hashes
                    or registry.read_bytes() != registry_source
                    or {name: sha(vendor/name) for name in modules} != modules):
                raise ValueError('Apple/native source, captured graphs or module closure changed during validation')
            verify_prepared(vendor)
            TOR.TORPACK.PACKAGE.verify(package, 'host-test')
            report = dict(schema=1, core=PIN, tags=TAGS, sources=before,
                          native_library_sha256=native, native_package=package_record,
                          prepared_source_sha256=TOR.digest(), module_sha256=modules,
                          graph_sha256=graph_hashes, server_graph_sha256=server_hashes, padding_graph_sha256=padding_hashes,
                          registry_sha256=hashlib.sha256(registry_source).hexdigest(),
                          missing_registry_sha256=hashlib.sha256(absent).hexdigest(),
                          verified=dict(apple_graphs=738, local_graphs=396, router_local_graphs=348, ordinary_local_graphs=48,
                                        server_graphs=342, enabled_local_padding_graphs=528,
                                        enabled_private_padding_graphs=456, enabled_direct_padding_graphs=8,
                                        enabled_ordinary_padding_graphs=64, padding_source_controls=528,
                                        missing_engine_controls=1266,
                                        exact_c_tor_abi=True, native_config_constructor=True,
                                        vpn_started=False, public_tor_traffic=False, apple_sdk_build=False))
            (logs/'apple-tor-native-evidence.json').write_text(json.dumps(report, indent=2, sort_keys=True)+'\n')
        finally:
            if target.is_file() and not target.is_symlink() and target.read_bytes() == data:
                target.unlink()
            if padding_target.is_file() and not padding_target.is_symlink() and padding_target.read_bytes() == padding_data:
                padding_target.unlink()
    print('Apple Tor native configuration gate passed; no VPN or public Tor circuit was started.')


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--vendor', type=Path)
    parser.add_argument('--native-package', type=Path)
    parser.add_argument('--go', default=shutil.which('go'))
    parser.add_argument('--graphs', type=Path, help='previous export from the exact current shipping Swift fixture')
    parser.add_argument('--server-graphs', type=Path, help='previous export from the exact current Server Swift fixture')
    parser.add_argument('--padding-graphs', type=Path, help='previous separate enabled Local padding export from the exact current Swift fixture')
    parser.add_argument('--output', type=Path, help='new directory for complete native logs and source evidence')
    parser.add_argument('--clang', help='Clang21+ next to matching clang++ and ld.lld; defaults to the Swift toolchain')
    parser.add_argument('--digest', action='store_true')
    args = parser.parse_args()
    if args.digest:
        print(digest())
    elif args.vendor and args.native_package and args.go:
        run(args.vendor, args.native_package, args.go, args.graphs, args.output, args.clang, args.server_graphs, args.padding_graphs)
    else:
        parser.error('--vendor, --native-package and Go are required')


if __name__ == '__main__':
    main()
