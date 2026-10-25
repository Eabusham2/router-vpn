#!/usr/bin/env python3
"""Require shipping host external graphs to construct in the pinned native core."""
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
def module(name: str, relative: str):
    spec = importlib.util.spec_from_file_location(name, ROOT/relative)
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded

HOST = module('external_graph_native_host', 'deploy/native_tor_graph_host.py')
PIN = '1ac1a339cb1223e9c70eae14c44411c75033c02d'
TAGS = 'with_wireguard,with_quic,with_gvisor,with_openvpn,with_naive_outbound,routervpn_tor_native_test'
TEST = 'TestRouterExternalGeneratedNativeGraphs'
MODES = ('wg', 'awg2-fast', 'awg2-strong', 'wg-pq', 'awg2-pq', 'shadowsocks', 'hysteria2',
         'reality-vision', 'reality-pq-vision', 'reality-xhttp', 'max-tls-wg', 'max-tls-awg',
         'max-quic-wg', 'max-quic-awg', 'ss-v2ray', 'split', 'max', 'naive-h2', 'naive-h3')
LAYERS = ('off', 'aes-256-gcm', 'aes-256-gcm+xor-whitening')
EXECUTIONS = ('server', 'auto')
PROTOCOLS = {
    'android': ('wireguard', 'amneziawg', 'socks5', 'http', 'https', 'shadowsocks', 'hysteria2', 'openvpn'),
    'ios': ('wireguard', 'amneziawg', 'socks5', 'http-connect', 'https-connect', 'shadowsocks', 'hysteria2', 'openvpn'),
}


def inputs() -> list[Path]:
    # Host changes must invalidate the package's cached native verification,
    # even when the linked Go code and its public binding signatures stay put.
    return [Path(__file__).resolve(), ROOT/'deploy/test_mobile_external_graphs_contract.py',
            ROOT/'mobile/externalpolicy/graph_test.go.tmpl',
            ROOT/'android/test_android_external_entries.py', ROOT/'android/test_android_tor_profile.py',
            ROOT/'deploy/test_ios_tor_profile.py',
            ROOT/'deploy/fixtures/external-openvpn-client.json',
            ROOT/'deploy/fixtures/external-openvpn-multihost-client.json',
            *sorted((ROOT/'android/app/src/main/java/com/eabusham/routervpn').glob('*.java')),
            *sorted((ROOT/'ios/RouterVPN/App').glob('*.swift')),
            *sorted((ROOT/'ios/RouterVPN/PacketTunnel').glob('*.swift'))] + HOST.inputs()


def digest() -> str:
    result = hashlib.sha256()
    for path in inputs():
        result.update(str(path.relative_to(ROOT)).encode()+b'\0'+path.read_bytes())
    return result.hexdigest()


def expected_names(target: str) -> set[str]:
    local = {'-'.join(case)+'.json' for case in itertools.product(MODES, LAYERS, PROTOCOLS[target])}
    # Paired execution uses the same pinned constructors for eight supported
    # authenticated transports, including distinct WG/AWG peers and OpenVPN owners. Both exit layers also
    # cross every entry-layer choice on the representative native WG entry.
    supported = PROTOCOLS[target]
    paired = {'-'.join(case)+'.json'
              for case in itertools.product(MODES, LAYERS, supported, EXECUTIONS)}
    layered = {'wg-'+entry+'-'+protocol+'-exit-'+layer+'-'+execution+'.json'
               for entry, protocol, layer, execution in itertools.product(LAYERS, supported, LAYERS[1:], ('local', *EXECUTIONS))}
    # A distinct multi-remote OpenVPN capture must retain its full response map
    # through every Router predecessor and entry layer for all execution choices.
    mapped = {mode+'-'+layer+'-openvpn-mapped-'+execution+'.json'
              for mode, layer, execution in itertools.product(MODES, LAYERS, ('local', *EXECUTIONS))}
    return local | paired | layered | mapped


def require_matrix(directory: Path, target: str) -> int:
    expected = expected_names(target)
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError('Missing, extra or stale '+target+' external graph combinations')
    actual = {p.name for p in directory.iterdir()}
    if actual != expected:
        raise ValueError('Missing, extra or stale '+target+' external graph combinations: '
                         +str(len(expected-actual))+' missing, '+str(len(actual-expected))+' extra')
    for name in expected:
        info = (directory/name).lstat()
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= 4*1024*1024:
            raise ValueError('Unsafe or invalid emitted external graph: '+name)
    return len(expected)


def run(vendor: Path, target: str, package: Path, go: str, clang: str | None = None) -> None:
    if vendor.is_symlink() or package.is_symlink():
        raise ValueError('Native source and host package require owned directories')
    vendor = vendor.resolve(strict=True)
    package = package.resolve(strict=True)
    if subprocess.check_output(['git', '-C', str(vendor), 'rev-parse', 'HEAD'], text=True).strip() != PIN:
        raise ValueError('External graph native core differs from the shipping pin')
    reader = vendor/'experimental/libbox/routervpn_external_policy_graph_test.go'
    if reader.is_symlink() or reader.read_bytes() != (ROOT/'mobile/externalpolicy/graph_test.go.tmpl').read_bytes():
        raise ValueError('External graph native reader differs from shipping source')
    # The full graph registry includes Naive/Cronet and the real Tor C owner.
    # Use the same verified Linux native host as the mandatory Tor graph gates;
    # a package cross-compiler or a platform stub cannot validate this matrix.
    tor = module('external_graph_native_package', 'deploy/prepare-mobile-tor.py')
    tor.TORPACK.PACKAGE.verify(package, 'host-test')
    library = package/'lib/libroutervpn_tor.so'
    native = hashlib.sha256(library.read_bytes()).hexdigest()
    modules = {name: hashlib.sha256((vendor/name).read_bytes()).hexdigest() for name in ('go.mod', 'go.sum')}
    before = digest()
    env = HOST.environment(go, library, clang, require_swift=target == 'ios')
    with tempfile.TemporaryDirectory(prefix='routervpn-'+target+'-external-native-') as temp:
        graphs = Path(temp)/'graphs'; graphs.mkdir()
        env['ROUTERVPN_'+('ANDROID' if target == 'android' else 'IOS')+'_EXTERNAL_GRAPHS'] = str(graphs)
        if target == 'android':
            android = module('external_graph_android_json', 'deploy/test_android_multihop_pinned.py')
            env['ANDROID_JSON_JAR'] = str(android.android_json_dependency(Path(temp), env))
        script = ROOT/('android/test_android_external_entries.py' if target == 'android' else 'deploy/test_ios_tor_profile.py')
        profile_env = env.copy(); profile_env.pop('CGO_LDFLAGS', None)
        subprocess.run([sys.executable, str(script)], cwd=ROOT, env=profile_env, check=True, timeout=600)
        count = require_matrix(graphs, target)
        env.update(ROUTERVPN_NATIVE_EXTERNAL_GRAPHS=str(graphs), ROUTERVPN_REQUIRE_EXTERNAL_GRAPHS='1',
                   ROUTERVPN_NATIVE_EXTERNAL_GRAPH_COUNT=str(count))
        command = [go, 'test', '-mod=readonly', '-json', '-ldflags=-checklinkname=0',
                   '-tags', TAGS, './experimental/libbox', '-run', '^'+TEST+'$', '-count=1', '-timeout=180s']
        result = subprocess.run(command, cwd=vendor, env=env, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=600)
        if result.returncode:
            diagnostics = []
            for line in result.stdout.splitlines():
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    diagnostics.append(line)
                    continue
                output = event.get('Output', '')
                if event.get('Action') == 'fail' or 'native registry rejected' in output:
                    diagnostics.append(event.get('Test', '')+': '+output.strip())
            raise RuntimeError('Native external graph constructors failed:\n'+'\n'.join(diagnostics)[-18000:])
        passed = set()
        for line in result.stdout.splitlines():
            event = json.loads(line)
            if event.get('Action') == 'pass' and event.get('Test', '').startswith(TEST+'/'):
                passed.add(event['Test'][len(TEST)+1:])
        if passed != expected_names(target):
            raise ValueError('Native constructors did not verify every generated external graph')
        if (before != digest() or native != hashlib.sha256(library.read_bytes()).hexdigest()
                or modules != {name: hashlib.sha256((vendor/name).read_bytes()).hexdigest() for name in modules}):
            raise ValueError('Shipping host, native module or linked package changed during verification')
        tor.TORPACK.PACKAGE.verify(package, 'host-test')
    print(f'Pinned native core accepted {count} {target} external graphs and rejected {count} missing-engine cases')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--platform', choices=PROTOCOLS)
    parser.add_argument('--vendor', type=Path)
    parser.add_argument('--native-package', type=Path)
    parser.add_argument('--go', default=shutil.which('go'))
    parser.add_argument('--clang', help='Clang21+ with matching sibling clang++ and ld.lld')
    parser.add_argument('--digest', action='store_true')
    args = parser.parse_args()
    if args.digest:
        print(digest())
    elif args.vendor and args.platform and args.native_package and args.go:
        run(args.vendor, args.platform, args.native_package, args.go, args.clang)
    else:
        parser.error('--vendor, --platform, --native-package and Go, or --digest, are required')
