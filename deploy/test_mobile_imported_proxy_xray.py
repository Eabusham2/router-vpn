#!/usr/bin/env python3
"""Mandatory captured SS2022/Hysteria2 -> REALITY native composition gates.

The eighteen shared/mobile captures and the desktop encrypted reference are
separate bounded stages. Neither grants an OS tunnel or physical-device proof.
"""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'deploy' / filename)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


SOCKS = module('proxy_reality_reference', 'test_mobile_imported_socks_xray.py')
IMPORTED = SOCKS.IMPORTED
KINDS = ('shadowsocks', 'hysteria2')
LAYERS = ('off', 'aes-256-gcm', 'aes-256-gcm+xor-whitening')
METHODS = ('2022-blake3-aes-128-gcm', '2022-blake3-aes-256-gcm', '2022-blake3-chacha20-poly1305')
FILES = {kind + '--reality-vision--' + first + '--' + final + '.json'
         for kind in KINDS for first in LAYERS for final in LAYERS}
SHARED_ENV = 'ROUTERVPN_IMPORTED_PROXY_XRAY_FIXTURES'
ANDROID_ENV = 'ROUTERVPN_ANDROID_IMPORTED_PROXY_XRAY_FIXTURES'
APPLE_ENV = 'ROUTERVPN_APPLE_IMPORTED_PROXY_XRAY_FIXTURES'
SHARED_PARSER = 'TestRouterImportedProxyRealitySourceGraphs'
ANDROID_PARSER = 'TestRouterImportedProxyRealityAndroidSourceGraphs'
APPLE_PARSER = 'TestRouterImportedProxyRealityAppleGraphs'
PEER_COPY = ('mobile/desktop/node_imported_proxy_xray_test.go.tmpl',
             'protocol/routervpnamnezia/routervpn_imported_proxy_xray_test.go')
SUPPORT = ('TestRouterVPNImportedProxyRealityPhysicalOwner',)
XRAY_VERSION = 'v1.260327.1-0.20260711155151-50231eaff98c'


def kind_cases(suffix, leaves):
    return {"TestImportedProxyRealityVision" + suffix:
            [value for kind in KINDS for value in (kind, *(kind + '/' + leaf for leaf in leaves))]}


CORE = kind_cases('IndependentLayers', [a + '/' + b for a in LAYERS for b in LAYERS])
CORE.update(kind_cases('SelectedPolicy', ('default-home', 'custom-udp', 'custom-tcp', 'tls', 'https', 'h3', 'ipv6-off', 'lan-off', 'fixed-mtu')))
CORE.update(kind_cases('RejectsChangedAuthority', (
    'entry-password', 'entry-endpoint', 'entry-foreign-protocol', 'entry-invalid-transport',
    'entry-layer-missing', 'entry-layer-mode', 'entry-layer-foreign', 'entry-layer-unused',
    'entry-route', 'entry-paired-proof', 'entry-paired-api', 'same-node', 'final-not-paired',
    'final-missing-proof', 'final-missing-token', 'final-missing-xray', 'final-wrapper',
    'final-plaintext', 'final-layer-missing', 'final-layer-foreign', 'final-layer-unused',
    'server', 'compare', 'foreign-bootstrap')))
CORE.update(kind_cases('EncryptedDNSBootstrap', ('tls', 'https', 'h3')))
CORE.update(kind_cases('KeepsScope', ('reality-pq-vision', 'reality-xhttp', 'split', 'max')))
CORE.update(kind_cases('RequiresBothProofsAndDNS', ('success', 'wrong-public-ip', 'wrong-paired-final', 'dns-failure', 'cancel-during-dns', 'missing-dns-capability', 'changed-owner')))
CORE.update(kind_cases('RetainedRuntime', ('close', 'network-change', 'replacement')))
CORE['TestImportedProxyRealityVisionSS2022Methods'] = [name for method in METHODS
    for name in (method, *(method + '/' + fault for fault in ('malformed', 'empty', 'short', 'long', 'identity-chain', 'empty-identity')))]


def native_cases(kind):
    result = []
    for first in LAYERS:
        for final in LAYERS:
            label = first + '--' + final
            faults = ['success', 'cancel', 'close-owner']
            if first == final == 'off':
                faults += ['entry-auth', 'wrong-entry-ip', 'final-reality-key', 'final-user',
                           'final-route', 'dns-route', 'final-identity', 'final-token']
                if kind == 'hysteria2':
                    faults += ['entry-sni', 'entry-trust']
            if first != 'off':
                faults.append('entry-layer-key')
            if first == 'aes-256-gcm+xor-whitening':
                faults.append('entry-layer-whitening')
            if final != 'off':
                faults.append('final-layer-key')
            if final == 'aes-256-gcm+xor-whitening':
                faults.append('final-layer-whitening')
            result += [label, *(label + '/' + fault for fault in faults)]
    return result


PEERS = {'TestRouterVPNImported' + label + 'RealityVisionNativeTraffic': native_cases(kind)
         for kind, label in (('shadowsocks', 'Shadowsocks'), ('hysteria2', 'Hysteria2'))}
PEERS['TestRouterVPNImportedShadowsocksRealityVisionMethods'] = [name for method in METHODS
    for name in (method, method + '/success', method + '/entry-auth')]


def captured_matrix(directory, prefix=''):
    expected = {prefix + name for name in FILES}
    if directory.is_symlink() or not directory.is_dir() or {p.name for p in directory.iterdir()} != expected:
        raise ValueError('Proxy REALITY requires exactly eighteen separately owned source files')
    result = {}
    for name in sorted(expected):
        path = directory / name
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= 1 << 20:
            raise ValueError('Proxy REALITY source is not a bounded regular file: ' + name)
        result[name] = path.read_bytes()
    return result


def inputs():
    result = {Path(__file__).resolve(), ROOT / 'deploy/test_mobile_imported_proxy_xray_runner.py',
              ROOT / 'deploy/test_mobile_imported_socks_xray.py', ROOT / 'deploy/test_mobile_imported_socks_xray_runner.py',
              ROOT / 'deploy/test_mobile_imported_entry.py', ROOT / 'deploy/test_mobile_imported_entry_runner.py',
              ROOT / 'deploy/test_ios_imported_router_pinned.py', ROOT / 'deploy/test_android_multihop_pinned.py',
              ROOT / 'deploy/build-native-runtime.py',
              ROOT / 'deploy/ios_test_crypto_bridge.py', ROOT / 'deploy/prepare-desktop-external.py', ROOT / 'go.mod'}
    if (ROOT / 'go.sum').exists() or (ROOT / 'go.sum').is_symlink():
        result.add(ROOT / 'go.sum')
    for directory, pattern in (('internal', '*.go'), ('mobile', '*.tmpl'),
                               ('android', '*.java'), ('android', '*.py'), ('ios', '*.swift')):
        result.update((ROOT / directory).rglob(pattern))
    result.update((ROOT / 'deploy').glob('prepare-*.py'))
    result.update((ROOT / 'deploy').glob('test_ios_*.py'))
    result.update(SOCKS.XRAY.sources())
    result.update(SOCKS.RELAY.inputs())
    return sorted(result)


def source_receipt():
    records = {}
    for path in inputs():
        if path.is_symlink() or not path.is_file():
            raise ValueError('Proxy REALITY lost a retained gate source')
        records[path.relative_to(ROOT).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    return records


def checked_sources(vendor, peers):
    if subprocess.check_output(['git', '-C', str(vendor), 'rev-parse', 'HEAD'], text=True).strip() != SOCKS.PIN:
        raise ValueError('Proxy REALITY requires the original pinned native core')
    if peers:
        records = SOCKS.checked_sources(vendor)
        SOCKS.check_file(vendor / PEER_COPY[1], (ROOT / PEER_COPY[0]).read_bytes(), records, PEER_COPY[1])
    else:
        IMPORTED.checked_sources(vendor, False)
        records = source_receipt()
        for template, target in (
                ('outbound.go.tmpl', 'protocol/routervpnxray/outbound.go'),
                ('bridge.go.tmpl', 'experimental/libbox/routervpn_xray_compiler.go'),
                ('bridge_test.go.tmpl', 'experimental/libbox/routervpn_xray_compiler_test.go')):
            SOCKS.check_file(vendor / target, (ROOT / 'mobile/applexray' / template).read_bytes(), records, 'prepared/' + target)
    return records


def resolved_xray(compiler, vendor, env):
    status, output = SOCKS.run_command(
        [compiler, 'list', '-m', '-mod=readonly', '-json', 'github.com/xtls/xray-core'], vendor, env, 30)
    if status:
        raise ValueError('Proxy REALITY cannot resolve its original Xray dependency')
    module = json.loads(output)
    path = Path(module.get('Dir', ''))
    replacement = module.get('Replace', {}).get('Dir')
    if module.get('Path') != 'github.com/xtls/xray-core' or module.get('Version') != XRAY_VERSION or not path.is_absolute() or path.is_symlink() or replacement != str(path):
        raise ValueError('Proxy REALITY requires the exact locally prepared Xray source and version')
    return path, SOCKS.checked_xray(path)


def execute(command, cwd, env, expected, timeout):
    status, output = SOCKS.run_command(command, cwd, env, timeout)
    SOCKS.require_verdicts(output, status, expected)
    print(output, end='' if output.endswith('\n') else '\n', flush=True)
    return output


def shared_sources(compiler, workspace, env):
    directory = workspace / 'shared'
    directory.mkdir()
    env[SHARED_ENV] = str(directory)
    env['ROUTERVPN_REQUIRE_IMPORTED_PROXY_XRAY_FIXTURES'] = '1'
    execute([compiler, 'test', '-mod=readonly', '-race', '-json', './internal/mobilemultihop',
             '-run', '^TestImportedProxyReality', '-count=1', '-timeout=60s'],
            ROOT, env, IMPORTED.names(CORE), 240)
    return directory, captured_matrix(directory)


def android_sources(workspace, env):
    directory = workspace / 'android'
    directory.mkdir()
    for kind in KINDS:
        phase = workspace / ('android-' + kind)
        phase.mkdir()
        child_env = dict(env)
        for key in tuple(child_env):
            if key.startswith('ROUTERVPN_ANDROID_'):
                child_env.pop(key)
        child_env[ANDROID_ENV] = str(phase)
        subprocess.run([sys.executable, str(ROOT / 'android/test_android_imported_router.py'),
                        '--phase', 'proxy-reality--' + kind], cwd=ROOT, env=child_env,
                       check=True, timeout=240)
        expected = {'android-' + name for name in FILES if name.startswith(kind + '--')}
        IMPORTED.merge_android_exports(phase, directory, expected)
    env[ANDROID_ENV] = str(directory)
    return directory, captured_matrix(directory, 'android-')


def run(vendor, peers=False, android=False):
    vendor = vendor.resolve(strict=True)
    compiler = shutil.which('go')
    if not compiler:
        raise ValueError('Proxy REALITY requires the shipping Go compiler')
    compiler = Path(compiler).resolve(strict=True)
    env = dict(os.environ, GOTOOLCHAIN=SOCKS.TOOLCHAIN, GOWORK='off')
    for key, value in (('GOMAXPROCS', '1'), ('GOGC', '5'), ('GOMEMLIMIT', '256MiB')):
        env.setdefault(key, value)
    if subprocess.check_output([compiler, 'env', 'GOVERSION'], env=env, text=True).strip() != SOCKS.TOOLCHAIN:
        raise ValueError('Proxy REALITY compiler differs from the shipping toolchain')
    for key in ('GOOS', 'GOARCH'):
        env[key] = subprocess.check_output([compiler, 'env', 'GOHOST' + key[2:]], env=env, text=True).strip()
    before = source_receipt()
    prepared = checked_sources(vendor, peers)
    original_xray = resolved_xray(compiler, vendor, env)
    subprocess.run([sys.executable, str(ROOT / 'deploy/test_mobile_imported_proxy_xray_runner.py')],
                   cwd=ROOT, env=env, check=True, timeout=30)
    receipt = {'scope': 'desktop-reference-only' if peers else 'native-source-parsers',
               'core_pin': SOCKS.PIN, 'toolchain': SOCKS.TOOLCHAIN,
               'source_sha256': SOCKS.record_digest(before), 'source_count': len(before),
               'xray_version': XRAY_VERSION, 'xray_source_sha256': SOCKS.record_digest(original_xray[1]),
               'shared_verdicts': sorted(IMPORTED.names(CORE))}
    with tempfile.TemporaryDirectory(prefix='routervpn-imported-proxy-reality-') as temporary:
        workspace = Path(temporary).resolve()
        shared, original_shared = shared_sources(compiler, workspace, env)
        receipt['shared'] = {name: hashlib.sha256(raw).hexdigest() for name, raw in original_shared.items()}
        if peers:
            xray, xray_before, reference, digest, overlay, instrumentation = SOCKS.build_reference(compiler, vendor, workspace, env)
            image, image_digest = SOCKS.compile_image(compiler, vendor, workspace, env, './protocol/routervpnamnezia', 'proxy-reality-peers')
            receipt['support'] = SOCKS.execute_image(compiler, vendor, env, image, image_digest, 'routervpnamnezia', SUPPORT[0], SUPPORT)
            receipt['peers'] = {}
            for parent, leaves in PEERS.items():
                receipt['peers'][parent] = SOCKS.execute_image(compiler, vendor, env, image, image_digest,
                    'routervpnamnezia', parent, sorted(IMPORTED.names({parent: leaves})), timeout=180)
            if reference.is_symlink() or hashlib.sha256(reference.read_bytes()).hexdigest() != digest or SOCKS.checked_xray(xray) != xray_before:
                raise ValueError('Proxy REALITY reference source or image changed during execution')
            SOCKS.check_reference_instrumentation(xray, workspace, overlay, instrumentation)
            receipt['reference'] = {'sha256': digest, 'source_sha256': SOCKS.record_digest(xray_before),
                                    'detector_instrumentation': instrumentation, 'detector_verdicts': list(SOCKS.REFERENCE_DETECTOR_TESTS)}
        else:
            groups = {SHARED_PARSER: sorted(FILES)}
            if android:
                original_android = android_sources(workspace, env)
                groups[ANDROID_PARSER] = sorted(original_android[1])
            execute([compiler, 'test', '-mod=readonly', '-json', '-ldflags=-checklinkname=0',
                     '-tags', SOCKS.TAGS, './experimental/libbox', '-run', '^(' + '|'.join(groups) + ')$',
                     '-count=1', '-timeout=90s'], vendor, env, IMPORTED.names(groups), 600)
            receipt['native_verdicts'] = sorted(IMPORTED.names(groups))
            if android and captured_matrix(original_android[0], 'android-') != original_android[1]:
                raise ValueError('Actual Android proxy REALITY source changed during native parsing')
        if captured_matrix(shared) != original_shared or source_receipt() != before or checked_sources(vendor, peers) != prepared or resolved_xray(compiler, vendor, env) != original_xray:
            raise ValueError('Proxy REALITY original captures or prepared shipping source changed during verification')
    print(json.dumps(receipt, sort_keys=True), flush=True)
    print('Proxy REALITY receipts cover these eighteen Local independent-layer compositions; source parsing, encrypted reference traffic and OS/device acceptance remain distinct.', flush=True)
    return receipt


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('vendor', type=Path)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--native-parsers', action='store_true')
    mode.add_argument('--reference-only', action='store_true')
    parser.add_argument('--android', action='store_true')
    args = parser.parse_args()
    if args.reference_only and args.android:
        parser.error('Actual Android sources belong to the native-parser gate')
    run(args.vendor, args.reference_only, args.android)
