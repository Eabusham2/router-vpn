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
FIXTURE = ROOT/'deploy/test_ios_tor_profile.py'
TEST = 'TestRouterTorAppleGeneratedGraphs'
TAGS = 'with_quic,with_wireguard,with_gvisor,with_naive_outbound,routervpn_tor_native_test'
MODES = ('wg', 'awg2-fast', 'awg2-strong', 'wg-pq', 'awg2-pq', 'shadowsocks',
         'hysteria2', 'naive-h2', 'naive-h3', 'reality-vision', 'reality-pq-vision',
         'reality-xhttp', 'ss-v2ray', 'split', 'max', 'max-tls-wg', 'max-tls-awg',
         'max-quic-wg', 'max-quic-awg')
KINDS = ('tor', 'obfs4', 'meek_lite', 'snowflake', 'webtunnel', 'custom')
LAYERS = ('off', 'aes-256-gcm', 'aes-256-gcm+xor-whitening')


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


def host_sources() -> list[Path]:
    # This is the exact source list recorded by the executable Swift fixture.
    return [FIXTURE, APP/'IOSExternalNodeBuilderView.swift', TUN/'PacketTunnelProvider.swift',
            *[APP/(name+'.swift') for name in ('Models', 'IOSExternalExecution', 'IOSMultihopExecution', 'IOSDNSRuntimePolicy',
                'IOSNativeXrayProfile', 'IOSNativePQProfile', 'IOSMultihopStartLayer', 'IOSRuntimeSelection')],
            *[TUN/(name+'.swift') for name in ('WireGuardQuickConfig', 'RouterVPNMultihopGraph',
                'RouterVPNMTUPolicy', 'IOSStartLayer', 'IOSXrayDevicePolicy', 'RouterVPNExternalExit')]]


def inputs() -> list[Path]:
    extra = [Path(__file__).resolve(), TEMPLATE, ROOT/'deploy/test_ios_tor_pinned_contract.py',
             ROOT/'deploy/test_ios_pq_selection.py', ROOT/'deploy/test_ios_wireguard_parser.py',
             ROOT/'deploy/test_ios_native_base_selection.py', ROOT/'android/test_android_multihop_graph.py',
             ROOT/'deploy/testfixtures/composite/main.go', ROOT/'go.mod']
    if (ROOT/'go.sum').exists():
        extra.append(ROOT/'go.sum')
    return sorted(set(extra + host_sources() + TOR.inputs() + MULTIHOP.inputs() + XRAY.sources() + HOST.inputs()))


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_hashes() -> dict[str, str]:
    return {str(path.relative_to(ROOT)): sha(path) for path in inputs()}


def digest() -> str:
    value = hashlib.sha256()
    for path in inputs():
        value.update(str(path.relative_to(ROOT)).encode()+b'\0'+path.read_bytes()+b'\0')
    return value.hexdigest()


def cases() -> dict[str, tuple[str, str, str]]:
    values = [(mode, layer, kind) for mode, layer, kind in itertools.product(MODES, LAYERS, KINDS)]
    values += [('direct', 'off', kind) for kind in KINDS]
    return {'-'.join(value): value for value in values}


def regular(path: Path, maximum: int = 4*1024*1024) -> bytes:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= maximum:
        raise ValueError('Missing, empty, oversized or linked Apple fixture: '+str(path))
    return path.read_bytes()


def require_matrix(folder: Path) -> dict[str, str]:
    if folder.is_symlink() or not folder.is_dir():
        raise ValueError('Apple Tor matrix requires an owned directory')
    expected = cases()
    if len(expected) != 348 or {path.name for path in folder.iterdir()} != set(expected) | {'source-evidence.json'}:
        raise ValueError('Apple Tor matrix must contain exactly 348 named graphs and source evidence')
    report = json.loads(regular(folder/'source-evidence.json'))
    hashes = {str(path.relative_to(ROOT)): sha(path) for path in host_sources()}
    if (report.get('schema') != 1 or report.get('graphs') != 348
            or report.get('home_dns_combinations') != 285
            or report.get('profile_policy_combinations') != 320
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
        owners = [out for out in graph.get('outbounds', []) if out.get('type') == 'routervpn-tor']
        if len(owners) != 1 or owners[0].get('session_id') != fixture['session']:
            raise ValueError('Apple graph lost its exact native Tor session: '+name)
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
    passed = set()
    for line in content.splitlines():
        event = json.loads(line)
        if event.get('Action') == 'pass' and event.get('Test', '').startswith(TEST+'/'):
            passed.add(event['Test'][len(TEST)+1:])
    if passed != set(cases()):
        raise ValueError('Native parser did not execute every one of the 348 Apple configurations')


def run(vendor: Path, package: Path, go: str, graphs: Path | None = None,
        output: Path | None = None, clang: str | None = None) -> None:
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
    data = TEMPLATE.read_bytes()
    if target.exists():
        raise ValueError('Apple native parser test destination must be unused')
    if output is not None:
        output.mkdir(parents=True, exist_ok=False)
    with tempfile.TemporaryDirectory(prefix='routervpn-apple-tor-native-') as temporary:
        work = Path(temporary)
        logs = output or work
        if graphs is None:
            graphs = work/'graphs'; graphs.mkdir()
            generator_env = env.copy()
            # Fixture compilers are ordinary host programs. Their nested build
            # helpers may set link flags, so never inject the Tor DSO into them.
            generator_env.pop('CGO_LDFLAGS', None)
            subprocess.run([sys.executable, str(FIXTURE), '--output', str(graphs)],
                           cwd=ROOT, env=generator_env, check=True, timeout=600)
        graph_hashes = require_matrix(graphs)
        env['ROUTERVPN_IOS_TOR_GRAPHS'] = str(graphs.resolve())
        (work/'registry.go').write_bytes(absent)
        overlay = work/'overlay.json'
        overlay.write_text(json.dumps({'Replace': {str(registry): str(work/'registry.go')}}))
        command = [go, 'test', '-mod=readonly', '-json', '-ldflags=-checklinkname=0',
                   '-tags', TAGS, './experimental/libbox', '-run', '^'+TEST+'$', '-count=1', '-timeout=180s']
        with target.open('xb') as stream:
            stream.write(data)
        try:
            run_native(command, vendor, env, logs/'native-positive.jsonl')
            print('PASS Apple Tor: 348 shipping configurations accepted by real native engines', flush=True)
            negative = dict(env, ROUTERVPN_IOS_TOR_MISSING_ENGINE='1')
            run_native(command[:2]+['-overlay', str(overlay)]+command[2:], vendor, negative, logs/'native-missing-engine.jsonl')
            print('PASS Apple Tor: all 348 unchanged configurations reject missing Tor registration', flush=True)
            if (source_hashes() != before or sha(library) != native or require_matrix(graphs) != graph_hashes
                    or registry.read_bytes() != registry_source
                    or {name: sha(vendor/name) for name in modules} != modules):
                raise ValueError('Apple/native source, captured graphs or module closure changed during validation')
            verify_prepared(vendor)
            TOR.TORPACK.PACKAGE.verify(package, 'host-test')
            report = dict(schema=1, core=PIN, tags=TAGS, sources=before,
                          native_library_sha256=native, native_package=package_record,
                          prepared_source_sha256=TOR.digest(), module_sha256=modules,
                          graph_sha256=graph_hashes, registry_sha256=hashlib.sha256(registry_source).hexdigest(),
                          missing_registry_sha256=hashlib.sha256(absent).hexdigest(),
                          verified=dict(apple_graphs=348, missing_engine_controls=348,
                                        exact_c_tor_abi=True, native_config_constructor=True,
                                        vpn_started=False, public_tor_traffic=False, apple_sdk_build=False))
            (logs/'apple-tor-native-evidence.json').write_text(json.dumps(report, indent=2, sort_keys=True)+'\n')
        finally:
            if target.is_file() and not target.is_symlink() and target.read_bytes() == data:
                target.unlink()
    print('Apple Tor native configuration gate passed; no VPN or public Tor circuit was started.')


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--vendor', type=Path)
    parser.add_argument('--native-package', type=Path)
    parser.add_argument('--go', default=shutil.which('go'))
    parser.add_argument('--graphs', type=Path, help='previous export from the exact current shipping Swift fixture')
    parser.add_argument('--output', type=Path, help='new directory for complete native logs and source evidence')
    parser.add_argument('--clang', help='Clang21+ next to matching clang++ and ld.lld; defaults to the Swift toolchain')
    parser.add_argument('--digest', action='store_true')
    args = parser.parse_args()
    if args.digest:
        print(digest())
    elif args.vendor and args.native_package and args.go:
        run(args.vendor, args.native_package, args.go, args.graphs, args.output, args.clang)
    else:
        parser.error('--vendor, --native-package and Go are required')


if __name__ == '__main__':
    main()
