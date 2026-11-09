#!/usr/bin/env python3
"""Validate the separate imported-entry -> paired XHTTP REALITY native inventory.

The existing ordinary REALITY gates remain mandatory. This gate uses the exact
prepared desktop core; a declared test overlay adds only a Libbox parser reader.
Protocol loopback and physical imported-peer verdicts are separate stages.
"""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import os
import re
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT/'deploy'/filename)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


PACKET = module('xhttp_packet_reference', 'test_native_imported_packet_xray.py')
SOCKS = PACKET.SOCKS
UDP443 = module('xhttp_selected_dns', 'test_native_xray_udp443.py')
BUILD = module('xhttp_shipping_inputs', 'build-native-runtime.py')
KINDS = ('socks5', 'shadowsocks', 'hysteria2', 'http-connect', 'https-connect',
         'wireguard', 'amneziawg', 'openvpn-tcp', 'openvpn-udp')
LAYERS = ('off', 'aes-256-gcm', 'aes-256-gcm+xor-whitening')
MODE = 'reality-xhttp'
NAMES = {kind+'--'+MODE+'--'+first+'--'+last+'.json'
         for kind in KINDS for first in LAYERS for last in LAYERS}
SHARED_ROOT = 'TestImportedXHTTPIndependentLayers'
READER = 'mobile/routervpn_imported_xhttp_xray_native_test.go.tmpl'
READER_TARGET = 'experimental/libbox/routervpn_imported_xhttp_xray_native_test.go'
PARSER_ROOTS = {
    'shared': ('TestRouterImportedXHTTPSourceGraphs', 'ROUTERVPN_IMPORTED_XHTTP_XRAY_FIXTURES'),
    'android': ('TestRouterImportedXHTTPAndroidSourceGraphs', 'ROUTERVPN_ANDROID_IMPORTED_XHTTP_XRAY_FIXTURES'),
    'apple': ('TestRouterImportedXHTTPAppleGraphs', 'ROUTERVPN_APPLE_IMPORTED_XHTTP_XRAY_FIXTURES'),
    'desktop': ('TestRouterImportedXHTTPDesktopGraphs', 'ROUTERVPN_DESKTOP_IMPORTED_XHTTP_XRAY_FIXTURES'),
}


def faults(first, last):
    result = ['success', 'final-pq-key', 'final-xhttp-path', 'cancel', 'close-owner']
    if first == last == 'off':
        result += ['wrong-entry-ip', 'final-reality-key', 'final-user', 'final-route',
                   'dns-route', 'final-identity', 'final-token']
    if first != 'off': result += ['entry-layer-key']
    if first == LAYERS[2]: result += ['entry-layer-whitening']
    if last != 'off': result += ['final-layer-key']
    if last == LAYERS[2]: result += ['final-layer-whitening']
    return result


PEERS = {
    'TestRouterVPNImportedXHTTPProxyTraffic': KINDS[:5],
    'TestRouterVPNImportedXHTTPPacketTraffic': KINDS[5:],
}
LOOPBACK = {
    'TestNativeXHTTPAuthenticationRefusal': ['matching-key', 'wrong-xhttp-path', 'restored-path', 'wrong-pq-key', 'restored-key'],
    'TestNativeXHTTPConfigurationRefusal': ['ordinary-key', 'missing-key', 'malformed-key', 'vision-flow', 'vision-udp443-flow', 'raw-network', 'relative-path', 'download-settings', 'foreign-mode'],
    'TestNativeXHTTPSelectedDNSUDP443': [name for name in UDP443.CASES if name != 'plain-vision-udp443'],
}



def inventory(directory, role):
    directory = Path(directory)
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError('XHTTP inventory must be an owned directory')
    prefix = 'android-' if role == 'android' else ''
    expected = {prefix+name for name in NAMES}
    paths = list(directory.iterdir())
    if {path.name for path in paths} != expected or len(paths) != 81:
        raise ValueError('XHTTP inventory requires all 81 separate exact source names')
    records = {}
    for path in paths:
        if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= 4*1024*1024:
            raise ValueError('XHTTP inventory contains an unowned or unbounded file')
        raw = path.read_bytes()
        value = json.loads(raw)
        name = path.name.removeprefix(prefix) if prefix else path.name
        kind, mode, first, last = name.removesuffix('.json').split('--')
        if role in ('shared', 'android'):
            if not isinstance(value, list) or len(value) != 9 or not all(isinstance(v, str) for v in value) or value[2] != mode:
                raise ValueError('XHTTP source lost its exact original receipt')
            capture, final = json.loads(value[1]), json.loads(value[4])
            expected_kind = 'openvpn' if kind.startswith('openvpn-') else kind
            norm = lambda v: v or 'off'
            if capture.get('protocol') != expected_kind or norm(capture['profile'].get('start_layer')) != first or norm(final.get('start_layer')) != last:
                raise ValueError('XHTTP source name substituted another original kind or layer')
            if expected_kind == 'openvpn':
                graph = json.loads(value[8])
                entry = next((v for v in graph.get('endpoints', []) if v.get('tag') == 'entry-wg'), {})
                if entry.get('network') != kind.removeprefix('openvpn-'):
                    raise ValueError('XHTTP source name substituted OpenVPN wire transport')
        elif not isinstance(value, dict):
            raise ValueError('XHTTP host graph is not an object')
        records[path.name] = hashlib.sha256(raw).hexdigest()
    return records


def source_receipt():
    paths = set(BUILD.inputs()) | {Path(__file__), ROOT/READER,
        ROOT/'deploy/test_mobile_imported_xhttp_xray_runner.py'}
    for directory, suffix in (('android/app/src/main/java/com/eabusham/routervpn', '*.java'),
                              ('ios/RouterVPN/App', '*.swift'), ('ios/RouterVPN/PacketTunnel', '*.swift')):
        paths.update((ROOT/directory).glob(suffix))
    paths.update((ROOT/'internal/mobilemultihop').glob('*.go'))
    records = {}
    for path in sorted(paths):
        if path.is_symlink() or not path.is_file():
            raise ValueError('XHTTP gate lost an original shipping source dependency')
        records[path.relative_to(ROOT).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    return records


def parser_image(compiler, vendor, work, env):
    reader = work/'xhttp-native-reader.go'
    reader.write_bytes((ROOT/READER).read_bytes())
    target = vendor/READER_TARGET
    if target.exists() and target.read_bytes() != reader.read_bytes():
        raise ValueError('Prepared XHTTP parser differs from the shipping reader')
    overlay = work/'xhttp-parser-overlay.json'
    overlay.write_text(json.dumps({'Replace': {str(target): str(reader)}}, sort_keys=True))
    image = work/'xhttp-parser'
    status, output = SOCKS.run_command([compiler, 'test', '-mod=readonly', '-race', '-c',
        '-overlay', overlay, '-ldflags=-checklinkname=0', '-tags', SOCKS.TAGS,
        '-o', image, './experimental/libbox'], vendor, env, 600)
    if status or not image.is_file():
        raise ValueError('XHTTP actual native parser did not compile:\n'+output[-20000:])
    return image, hashlib.sha256(image.read_bytes()).hexdigest()


def parser_inventory_controls(compiler, vendor, work, env, image, digest, role, directory):
    """Renaming a valid original must fail in the actual compiled native reader."""
    captured = work/'renamed-native-inventory'
    shutil.copytree(directory, captured)
    parent, variable = PARSER_ROOTS[role]
    child_env = dict(env, **{variable: str(captured)})
    prefix = 'android-' if role == 'android' else ''
    name = lambda kind, first='off', last='off': prefix+'--'.join((kind, MODE, first, last))+'.json'
    controls = (
        ('entry-kind', name('socks5'), name('wireguard'), 'substituted another imported transport'),
        ('entry-layer', name('socks5'), name('socks5', 'aes-256-gcm'), 'substituted an independent Start Layer'),
        ('final-layer', name('socks5'), name('socks5', last='aes-256-gcm'), 'substituted an independent Start Layer'),
        ('openvpn-wire', name('openvpn-tcp'), name('openvpn-udp'), 'substituted another OpenVPN wire transport'),
        ('connect-tls', name('http-connect'), name('https-connect'), 'substituted CONNECT TLS policy'),
    )
    records = []
    for fault, target, replacement, reason in controls:
        destination = captured/target
        original = destination.read_bytes()
        destination.write_bytes((captured/replacement).read_bytes())
        selected = '^'+parent+'$/^'+re.escape(target)+'$'
        try:
            if image.is_symlink() or hashlib.sha256(image.read_bytes()).hexdigest() != digest:
                raise ValueError('XHTTP native reader changed before renamed-source control')
            status, output = SOCKS.run_command([compiler, 'tool', 'test2json', '-t', '-p', 'libbox', image,
                '-test.v', '-test.run='+selected, '-test.count=1', '-test.timeout=30s'], vendor, child_env, 45)
            events = []
            for line in output.splitlines():
                try: events.append(json.loads(line))
                except json.JSONDecodeError: pass
            names = {parent, parent+'/'+target}
            failed = [event.get('Test') for event in events if event.get('Action') == 'fail' and event.get('Test')]
            started = [event.get('Test') for event in events if event.get('Action') == 'run' and event.get('Test')]
            if status == 0 or set(failed) != names or len(failed) != 2 or set(started) != names or len(started) != 2 or reason not in output or any(marker in output for marker in ('panic:', 'fatal error:', 'DATA RACE')) or any(event.get('Action') == 'skip' for event in events):
                raise ValueError('XHTTP native renamed-source control failed at the wrong boundary: '+fault+'\n'+output[-12000:])
            records.append(fault)
        finally:
            destination.write_bytes(original)
    if inventory(captured, role) != inventory(directory, role) or hashlib.sha256(image.read_bytes()).hexdigest() != digest:
        raise ValueError('XHTTP native inventory control did not restore the original graph bytes')
    print('XHTTP native reader rejected all five renamed kind, layer and wire controls', flush=True)
    return {'producer': role, 'rejected': records, 'reader_sha256': digest}


def run(vendor, *, stage='parser', android=None, apple=None, desktop=None):
    vendor = Path(vendor).resolve(strict=True)
    compiler = Path(shutil.which('go') or '').resolve(strict=True)
    env = dict(os.environ, GOTOOLCHAIN=SOCKS.TOOLCHAIN, GOWORK='off')
    if subprocess.check_output([compiler, 'env', 'GOVERSION'], env=env, text=True).strip() != SOCKS.TOOLCHAIN:
        raise ValueError('XHTTP gate requires the exact shipping Go toolchain')
    for key in ('GOOS', 'GOARCH'):
        env[key] = subprocess.check_output([compiler, 'env', 'GOHOST'+key[2:]], env=env, text=True).strip()
    before, prepared = source_receipt(), PACKET.checked_sources(vendor)
    print('XHTTP native preflight passed: exact toolchain, shipping sources and prepared core; stage='+stage, flush=True)
    receipt = {'schema': 1, 'mode': MODE, 'source_sha256': SOCKS.record_digest(before),
               'prepared_sha256': SOCKS.record_digest(prepared), 'stage': stage,
               'device_acceptance': False, 'production_router_acceptance': False}
    with tempfile.TemporaryDirectory(prefix='routervpn-imported-xhttp-') as temporary:
        work = Path(temporary)
        sources = work/'shared'; sources.mkdir()
        env['ROUTERVPN_IMPORTED_XHTTP_XRAY_FIXTURES'] = str(sources)
        env['ROUTERVPN_REQUIRE_IMPORTED_XHTTP_XRAY_FIXTURES'] = '1'
        expected = [SHARED_ROOT]+[SHARED_ROOT+'/'+kind+'/'+first+'/'+last
            for kind in KINDS for first in LAYERS for last in LAYERS]
        status, output = SOCKS.run_command([compiler, 'test', '-mod=readonly', '-race', '-json',
            './internal/mobilemultihop', '-run', '^'+SHARED_ROOT+'$', '-count=1', '-timeout=60s'], ROOT, env, 180)
        SOCKS.require_verdicts(output, status, expected)
        original_sources = inventory(sources, 'shared')
        print('XHTTP shared producer passed all 81 exact independent graphs', flush=True)
        receipt['shared'] = {'graphs': 81, 'sha256': SOCKS.record_digest(original_sources)}
        if stage == 'parser':
            image, digest = parser_image(compiler, vendor, work, env)
            receipt['parsers'] = {}
            for role, directory in (('shared', sources), ('android', android), ('apple', apple), ('desktop', desktop)):
                if directory is None: continue
                captured = inventory(directory, role)
                parent, variable = PARSER_ROOTS[role]
                env[variable] = str(Path(directory).resolve(strict=True))
                prefix = 'android-' if role == 'android' else ''
                names = [parent]+[parent+'/'+prefix+name for name in sorted(NAMES)]
                receipt['parsers'][role] = SOCKS.execute_image(compiler, vendor, env, image, digest,
                    'libbox', parent, names, timeout=120)
                if inventory(directory, role) != captured:
                    raise ValueError('XHTTP host source changed during actual native parsing')
            control_role, control_source = ('apple', apple) if apple is not None else ('shared', sources)
            receipt['inventory_controls'] = parser_inventory_controls(compiler, vendor, work, env, image, digest, control_role, control_source)
        elif stage in ('loopback', 'reference'):
            print('XHTTP native reference: compiling the pinned encrypted peer and readiness controls', flush=True)
            xray, old_xray, reference, reference_digest, overlay, instrumentation = SOCKS.build_reference(compiler, vendor, work, env)
            if stage == 'loopback':
                image, digest = UDP443.compile_image(compiler, vendor, work, env)
                receipt['loopback'] = {}
                for parent, children in LOOPBACK.items():
                    receipt['loopback'][parent] = SOCKS.execute_image(compiler, vendor, env, image, digest,
                        'routervpnxray', parent, [parent]+[parent+'/'+child for child in children], timeout=120)
                receipt['physical_interface_proof'] = False
            else:
                image, digest = PACKET.compile_image(compiler, vendor, work, env)
                receipt['peers'] = {}
                for parent, kinds in PEERS.items():
                    children = [kind+'/'+first+'/'+last+'/'+fault for kind in kinds
                        for first in LAYERS for last in LAYERS for fault in faults(first, last)]
                    receipt['peers'][parent] = SOCKS.execute_image(compiler, vendor, env, image, digest,
                        'routervpnamnezia', parent, [parent]+children, timeout=600)
                receipt['physical_interface_proof'] = 'captured reference tuples; no OS TUN acceptance'
            if reference.is_symlink() or hashlib.sha256(reference.read_bytes()).hexdigest() != reference_digest or SOCKS.checked_xray(xray) != old_xray:
                raise ValueError('XHTTP original reference source or binary changed')
            SOCKS.check_reference_instrumentation(xray, work, overlay, instrumentation)
            receipt['reference_sha256'] = reference_digest
        else:
            raise ValueError('Unknown finite XHTTP evidence stage')
        if inventory(sources, 'shared') != original_sources or source_receipt() != before or PACKET.checked_sources(vendor) != prepared:
            raise ValueError('XHTTP source or prepared image changed during evidence collection')
    print(json.dumps(receipt, sort_keys=True), flush=True)
    return receipt


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('vendor', type=Path)
    stages = parser.add_mutually_exclusive_group()
    stages.add_argument('--reference-only', action='store_true')
    stages.add_argument('--loopback-only', action='store_true')
    parser.add_argument('--android', type=Path, help='Complete actual Android XHTTP source export')
    parser.add_argument('--apple', type=Path, help='Complete actual Swift XHTTP graph export')
    parser.add_argument('--desktop', type=Path, help='Complete desktop shipping XHTTP graph export')
    args = parser.parse_args()
    if (args.reference_only or args.loopback_only) and (args.android or args.apple or args.desktop):
        parser.error('Host producer exports belong to the separate parser stage')
    run(args.vendor, stage='reference' if args.reference_only else 'loopback' if args.loopback_only else 'parser',
        android=args.android, apple=args.apple, desktop=args.desktop)
