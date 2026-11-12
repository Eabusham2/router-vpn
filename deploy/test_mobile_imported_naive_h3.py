#!/usr/bin/env python3
"""Validate the separate imported-entry -> paired Naive H3 native inventory.

The existing ordinary, PQ, XHTTP and H2 gates remain mandatory. This gate uses the exact
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


PACKET = module('naive-h3_packet_reference', 'test_native_imported_packet_xray.py')
SOCKS = PACKET.SOCKS
BUILD = module('naive-h3_shipping_inputs', 'build-native-runtime.py')
KINDS = ('socks5', 'shadowsocks', 'hysteria2',
         'wireguard', 'amneziawg', 'openvpn-tcp', 'openvpn-udp')
LAYERS = ('off', 'aes-256-gcm', 'aes-256-gcm+xor-whitening')
MODE = 'naive-h3'
NAMES = {kind+'--'+MODE+'--'+first+'--'+last+'.json'
         for kind in KINDS for first in LAYERS for last in LAYERS}
SHARED_ROOT = 'TestImportedNaiveH3IndependentLayers'
READER = 'mobile/routervpn_imported_naive_h3_native_test.go.tmpl'
READER_TARGET = 'experimental/libbox/routervpn_imported_naive_h3_native_test.go'
LOADER = 'mobile/routervpn_imported_naive_h3_loader_purego_test.go.tmpl'
LOADER_TARGET = 'experimental/libbox/routervpn_imported_naive_h3_loader_purego_test.go'
PARSER_COPIES = ((READER, READER_TARGET), (LOADER, LOADER_TARGET))
PARSER_ROOTS = {
    'shared': ('TestRouterImportedNaiveH3SourceGraphs', 'ROUTERVPN_IMPORTED_NAIVE_H3_FIXTURES'),
    'android': ('TestRouterImportedNaiveH3AndroidSourceGraphs', 'ROUTERVPN_ANDROID_IMPORTED_NAIVE_H3_FIXTURES'),
    'apple': ('TestRouterImportedNaiveH3AppleGraphs', 'ROUTERVPN_APPLE_IMPORTED_NAIVE_H3_FIXTURES'),
    'desktop': ('TestRouterImportedNaiveH3DesktopGraphs', 'ROUTERVPN_DESKTOP_IMPORTED_NAIVE_H3_FIXTURES'),
}


def faults(kind, first, last):
    result = ['success', 'cancel', 'close-owner', 'replacement-owner']
    if kind == 'socks5': result += ['socks-relay-route', 'socks-control-eof']
    if first == last == 'off':
        result += ['entry-route', 'wrong-entry-ip', 'final-password', 'final-user',
                   'final-server-name', 'final-certificate', 'final-route',
                   'bootstrap-route', 'dns-route', 'final-identity', 'final-token']
        if kind in ('wireguard', 'amneziawg'):
            result += ['entry-private-key', 'entry-public-key', 'entry-psk']
            if kind == 'amneziawg': result += ['entry-awg-parameter']
        else:
            result += ['entry-auth']
        if kind == 'hysteria2': result += ['entry-sni', 'entry-trust']
    if first != 'off': result += ['entry-layer-key']
    if first == LAYERS[2]: result += ['entry-layer-whitening']
    if last != 'off': result += ['final-layer-key', 'bootstrap-route']
    if last == LAYERS[2]: result += ['final-layer-whitening']
    return result


PEERS = {
    'TestRouterVPNImportedNaiveH3ProxyTraffic': KINDS[:3],
    'TestRouterVPNImportedNaiveH3PacketTraffic': KINDS[3:],
}
LOOPBACK = {
    'TestRouterVPNDesktopNodeNaiveH3Literal': PACKET.NODE.NAIVE_LITERAL_CASES,
    'TestRouterVPNImportedNaiveH3SOCKSAssociation': tuple(layer+'/'+fault for layer in LAYERS
        for fault in ('success', 'relay-route', 'control-eof', 'cancelled')),
    'TestRouterVPNDesktopNodeNaiveH3StreamOwner': ('owner-cancellation', 'caller-deadline'),
    'TestRouterVPNImportedNaiveH3PacketIngress': tuple(kind+'/'+state+'/'+network
        for kind in ('wireguard', 'amneziawg')
        for state in ('active', 'retiring', 'cancelled') for network in ('tcp', 'udp')),
    'TestRouterVPNImportedNaiveH3RetiredUDPIngress': tuple(kind+'/'+api+'/'+fault
        for kind in ('wireguard', 'amneziawg') for api in ('dial', 'listen')
        for fault in ('closed', 'closing-joined', 'closing-failed', 'active', 'cancelled-caller',
                      'replacement', 'replacement-remote', 'foreign-remote-ip', 'foreign-remote-port', 'foreign-local-ip',
                      'foreign-local-port', 'unwritten', 'close-failed', 'foreign-entry', 'foreign-kind',
                      'origin', 'rewrite')),
}


def peer_verdicts(parent, kinds):
    return [parent] + [parent+'/'+kind+'/'+first+'/'+last+'/'+fault for kind in kinds
                      for first in LAYERS for last in LAYERS for fault in faults(kind, first, last)]


def inventory(directory, role):
    directory = Path(directory)
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError('Naive H3 inventory must be an owned directory')
    prefix = 'android-' if role == 'android' else ''
    expected = {prefix+name for name in NAMES}
    paths = list(directory.iterdir())
    if {path.name for path in paths} != expected or len(paths) != 63:
        raise ValueError('Naive H3 inventory requires all 63 separate exact source names')
    records = {}
    for path in paths:
        if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= 4*1024*1024:
            raise ValueError('Naive H3 inventory contains an unowned or unbounded file')
        raw = path.read_bytes()
        value = json.loads(raw)
        name = path.name.removeprefix(prefix) if prefix else path.name
        kind, mode, first, last = name.removesuffix('.json').split('--')
        if role in ('shared', 'android'):
            if not isinstance(value, list) or len(value) != 9 or not all(isinstance(v, str) for v in value) or value[2] != mode:
                raise ValueError('Naive H3 source lost its exact original receipt')
            capture, final = json.loads(value[1]), json.loads(value[4])
            expected_kind = 'openvpn' if kind.startswith('openvpn-') else kind
            norm = lambda v: v or 'off'
            if capture.get('protocol') != expected_kind or norm(capture['profile'].get('start_layer')) != first or norm(final.get('start_layer')) != last:
                raise ValueError('Naive H3 source name substituted another original kind or layer')
            if expected_kind == 'openvpn':
                graph = json.loads(value[8])
                entry = next((v for v in graph.get('endpoints', []) if v.get('tag') == 'entry-wg'), {})
                if entry.get('network') != kind.removeprefix('openvpn-'):
                    raise ValueError('Naive H3 source name substituted OpenVPN wire transport')
        elif not isinstance(value, dict):
            raise ValueError('Naive H3 host graph is not an object')
        records[path.name] = hashlib.sha256(raw).hexdigest()
    return records


def source_receipt():
    paths = set(BUILD.inputs()) | {Path(__file__), ROOT/READER, ROOT/LOADER,
        ROOT/'deploy/test_mobile_imported_naive_h3_runner.py'}
    for directory, suffix in (('android/app/src/main/java/com/eabusham/routervpn', '*.java'),
                              ('ios/RouterVPN/App', '*.swift'), ('ios/RouterVPN/PacketTunnel', '*.swift')):
        paths.update((ROOT/directory).glob(suffix))
    paths.update((ROOT/'internal/mobilemultihop').glob('*.go'))
    records = {}
    for path in sorted(paths):
        if path.is_symlink() or not path.is_file():
            raise ValueError('Naive H3 gate lost an original shipping source dependency')
        records[path.relative_to(ROOT).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    return records


def parser_image(compiler, vendor, work, env):
    replacements = {}
    for original, relative in PARSER_COPIES:
        reader = work/Path(relative).name
        source, target = ROOT/original, vendor/relative
        if source.is_symlink() or not source.is_file():
            raise ValueError('Naive H3 parser lost an owned shipping source')
        reader.write_bytes(source.read_bytes())
        if target.is_symlink() or target.exists() and (not target.is_file() or target.read_bytes() != reader.read_bytes()):
            raise ValueError('Prepared Naive H3 parser differs from the shipping reader')
        replacements[str(target)] = str(reader)
    overlay = work/'naive-h3-parser-overlay.json'
    overlay.write_text(json.dumps({'Replace': replacements}, sort_keys=True))
    image = work/'naive-h3-parser'
    status, output = SOCKS.run_command([compiler, 'test', '-mod=readonly', '-race', '-c',
        '-overlay', overlay, '-ldflags=-checklinkname=0', '-tags', SOCKS.TAGS,
        '-o', image, './experimental/libbox'], vendor, env, 600)
    if status or image.is_symlink() or not image.is_file():
        raise ValueError('Naive H3 actual native parser did not compile:\n'+output[-20000:])
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
        ('second-entry-layer', name('socks5', 'aes-256-gcm'), name('socks5', LAYERS[2]), 'substituted an independent Start Layer'),
    )
    records = []
    for fault, target, replacement, reason in controls:
        destination = captured/target
        original = destination.read_bytes()
        destination.write_bytes((captured/replacement).read_bytes())
        selected = '^'+parent+'$/^'+re.escape(target)+'$'
        try:
            if image.is_symlink() or hashlib.sha256(image.read_bytes()).hexdigest() != digest:
                raise ValueError('Naive H3 native reader changed before renamed-source control')
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
                raise ValueError('Naive H3 native renamed-source control failed at the wrong boundary: '+fault+'\n'+output[-12000:])
            records.append(fault)
        finally:
            destination.write_bytes(original)
    if inventory(captured, role) != inventory(directory, role) or hashlib.sha256(image.read_bytes()).hexdigest() != digest:
        raise ValueError('Naive H3 native inventory control did not restore the original graph bytes')
    print('Naive H3 native reader rejected all five renamed kind, layer and wire controls', flush=True)
    return {'producer': role, 'rejected': records, 'reader_sha256': digest}


def parser_transport_controls(compiler, vendor, work, env, image, digest, shared, desktop=None):
    """Mutate exact exported graph bytes, never a replacement compiler receipt."""
    graphs = work/'transport-native-inventory'; graphs.mkdir()
    original_desktop = inventory(desktop, 'desktop') if desktop is not None else None
    for name in sorted(NAMES):
        if desktop is not None:
            (graphs/name).write_bytes((Path(desktop)/name).read_bytes())
        else:
            source = json.loads((Path(shared)/name).read_bytes())
            (graphs/name).write_text(source[8])
    # Shared-origin raw graphs use the same fixed Home tuple as the Apple raw
    # reader. This control is not an Apple producer result. Actual desktop
    # captures retain their different original Home tuple and desktop reader.
    reader = 'desktop' if desktop is not None else 'apple'
    captured = inventory(graphs, reader)
    parent, variable = PARSER_ROOTS[reader]
    name = 'socks5--naive-h3--off--off.json'
    path = graphs/name; original = path.read_bytes()
    changes = [
        ('h2-downgrade', 'Naive H3 parser lost its exact QUIC'),
        ('selected-tcp', 'changed captured Home UDP transport or resolver owner'),
        ('selected-entry', 'changed captured Home UDP transport or resolver owner'),
        ('bootstrap-final', 'changed captured Home UDP transport or resolver owner'),
    ]
    if desktop is not None:
        changes.append(('home-server-substitution', 'changed captured Home UDP transport or resolver owner'))
    rejected = []
    for fault, reason in changes:
        graph = json.loads(original)
        if fault == 'h2-downgrade':
            next(row for row in graph['outbounds'] if row.get('type') == 'naive')['quic'] = False
        elif fault == 'selected-tcp': graph['dns']['servers'][0]['type'] = 'tcp'
        elif fault == 'selected-entry': graph['dns']['servers'][0]['detour'] = 'entry-wg'
        elif fault == 'bootstrap-final': graph['dns']['servers'][1]['detour'] = 'proxy'
        else:
            for row in graph['dns']['servers']:
                row['server'] = '192.0.2.53'
        path.write_text(json.dumps(graph))
        try:
            if image.is_symlink() or hashlib.sha256(image.read_bytes()).hexdigest() != digest:
                raise ValueError('Naive H3 native reader changed before transport control')
            names = [parent, parent+'/'+name]
            status, output = SOCKS.run_command([compiler, 'tool', 'test2json', '-t', '-p', 'libbox', image,
                '-test.v', '-test.run=^'+parent+'$/^'+re.escape(name)+'$', '-test.count=1', '-test.timeout=30s'],
                vendor, dict(env, **{variable: str(graphs)}), 45)
            events = []
            for line in output.splitlines():
                try: events.append(json.loads(line))
                except json.JSONDecodeError: pass
            started = [event.get('Test') for event in events if event.get('Action') == 'run' and event.get('Test')]
            failed = [event.get('Test') for event in events if event.get('Action') == 'fail' and event.get('Test')]
            if status == 0 or started != names or set(failed) != set(names) or len(failed) != 2 or reason not in output or any(
                    event.get('Action') == 'skip' for event in events) or any(
                    marker in output for marker in ('panic:', 'fatal error:', 'DATA RACE')):
                raise ValueError('Naive H3 native transport refusal failed at the wrong boundary: '+fault+'\n'+output[-12000:])
            rejected.append(fault)
        finally:
            path.write_bytes(original)
    if inventory(graphs, reader) != captured or hashlib.sha256(image.read_bytes()).hexdigest() != digest or (
            desktop is not None and inventory(desktop, 'desktop') != original_desktop):
        raise ValueError('Naive H3 native transport control changed its original graph bytes')
    return {'producer': 'original desktop source graph' if desktop is not None else 'exact shared source graph',
            'raw_reader': reader, 'rejected': rejected, 'reader_sha256': digest}


def parser_library_controls(compiler, vendor, work, env, image, digest):
    """An actual native reader must refuse a missing, linked or changed library."""
    parent, _ = PARSER_ROOTS['shared']
    linked = work/'linked-cronet-library'
    linked.symlink_to(env['ROUTERVPN_NODE_CRONET_LIBRARY'])
    controls = (
        ('missing-seal', {'ROUTERVPN_NODE_CRONET_SHA256': ''}, 'requires its exact native-library module seal'),
        ('wrong-digest', {'ROUTERVPN_NODE_CRONET_SHA256': '0'*64}, 'differs from its captured module'),
        ('wrong-size', {'ROUTERVPN_NODE_CRONET_BYTES': str(int(env['ROUTERVPN_NODE_CRONET_BYTES'])+1)}, 'library is absent, linked or changed'),
        ('linked-library', {'ROUTERVPN_NODE_CRONET_LIBRARY': str(linked)}, 'library is absent, linked or changed'),
    )
    rejected = []
    for name, changes, reason in controls:
        if image.is_symlink() or hashlib.sha256(image.read_bytes()).hexdigest() != digest:
            raise ValueError('Naive H3 parser changed before native-library control')
        status, output = SOCKS.run_command([compiler, 'tool', 'test2json', '-t', '-p', 'libbox', image,
            '-test.v', '-test.run=^'+parent+'$', '-test.count=1', '-test.timeout=30s'],
            vendor, dict(env, **changes), 45)
        events = []
        for line in output.splitlines():
            try: events.append(json.loads(line))
            except json.JSONDecodeError: pass
        started = [event.get('Test') for event in events if event.get('Action') == 'run' and event.get('Test')]
        failed = [event.get('Test') for event in events if event.get('Action') == 'fail' and event.get('Test')]
        if status == 0 or started != [parent] or failed != [parent] or reason not in output or any(
                event.get('Action') == 'skip' for event in events) or any(
                marker in output for marker in ('panic:', 'fatal error:', 'DATA RACE')):
            raise ValueError('Naive H3 native-library refusal failed at the wrong boundary: '+name+'\n'+output[-12000:])
        rejected.append(name)
    if hashlib.sha256(image.read_bytes()).hexdigest() != digest:
        raise ValueError('Naive H3 parser changed during native-library controls')
    print('Naive H3 native reader rejected all four missing, changed and linked library controls', flush=True)
    return {'rejected': rejected, 'reader_sha256': digest}


def run(vendor, *, stage='parser', android=None, apple=None, desktop=None):
    vendor = Path(vendor).resolve(strict=True)
    compiler = Path(shutil.which('go') or '').resolve(strict=True)
    env = dict(os.environ, GOTOOLCHAIN=SOCKS.TOOLCHAIN, GOWORK='off')
    if subprocess.check_output([compiler, 'env', 'GOVERSION'], env=env, text=True).strip() != SOCKS.TOOLCHAIN:
        raise ValueError('Naive H3 gate requires the exact shipping Go toolchain')
    for key in ('GOOS', 'GOARCH'):
        env[key] = subprocess.check_output([compiler, 'env', 'GOHOST'+key[2:]], env=env, text=True).strip()
    before, prepared = source_receipt(), PACKET.checked_sources(vendor)
    print('Naive H3 native preflight passed: exact toolchain, shipping sources and prepared core; stage='+stage, flush=True)
    receipt = {'schema': 1, 'mode': MODE, 'source_sha256': SOCKS.record_digest(before),
               'prepared_sha256': SOCKS.record_digest(prepared), 'stage': stage,
               'device_acceptance': False, 'production_router_acceptance': False}
    with tempfile.TemporaryDirectory(prefix='routervpn-imported-naive-h3-') as temporary:
        work = Path(temporary)
        sources = work/'shared'; sources.mkdir()
        env['ROUTERVPN_IMPORTED_NAIVE_H3_FIXTURES'] = str(sources)
        env['ROUTERVPN_REQUIRE_IMPORTED_NAIVE_H3_FIXTURES'] = '1'
        expected = [SHARED_ROOT]+[SHARED_ROOT+'/'+kind+'/'+first+'/'+last
            for kind in KINDS for first in LAYERS for last in LAYERS]
        status, output = SOCKS.run_command([compiler, 'test', '-mod=readonly', '-race', '-json',
            './internal/mobilemultihop', '-run', '^'+SHARED_ROOT+'$', '-count=1', '-timeout=60s'], ROOT, env, 180)
        SOCKS.require_verdicts(output, status, expected)
        original_sources = inventory(sources, 'shared')
        print('Naive H3 shared producer passed all 63 exact independent graphs', flush=True)
        receipt['shared'] = {'graphs': 63, 'sha256': SOCKS.record_digest(original_sources)}
        library = PACKET.NODE.stage_naive_library(compiler, vendor, work, env)
        receipt['native_library'] = {'sha256': library[2], 'bytes': library[3]}
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
                    raise ValueError('Naive H3 host source changed during actual native parsing')
            control_role, control_source = ('apple', apple) if apple is not None else ('shared', sources)
            receipt['inventory_controls'] = parser_inventory_controls(compiler, vendor, work, env, image, digest, control_role, control_source)
            receipt['library_controls'] = parser_library_controls(compiler, vendor, work, env, image, digest)
            receipt['transport_controls'] = parser_transport_controls(compiler, vendor, work, env, image, digest, sources, desktop)
        elif stage in ('loopback', 'reference'):
            image, digest = PACKET.compile_image(compiler, vendor, work, env)
            if stage == 'loopback':
                receipt['loopback'] = {}
                for parent, children in LOOPBACK.items():
                    receipt['loopback'][parent] = SOCKS.execute_image(compiler, vendor, env, image, digest,
                        'routervpnamnezia', parent, [parent]+[parent+'/'+child for child in children], timeout=90)
                receipt['physical_interface_proof'] = False
            else:
                receipt['peers'] = {}
                for parent, kinds in PEERS.items():
                    receipt['peers'][parent] = SOCKS.execute_image(compiler, vendor, env, image, digest,
                        'routervpnamnezia', parent, peer_verdicts(parent, kinds), timeout=600)
                receipt['physical_interface_proof'] = 'captured reference tuples; no OS TUN acceptance'
        else:
            raise ValueError('Unknown finite Naive H3 evidence stage')
        PACKET.NODE.verify_naive_library(library)
        if inventory(sources, 'shared') != original_sources or source_receipt() != before or PACKET.checked_sources(vendor) != prepared:
            raise ValueError('Naive H3 source or prepared image changed during evidence collection')
    print(json.dumps(receipt, sort_keys=True), flush=True)
    return receipt


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('vendor', type=Path)
    stages = parser.add_mutually_exclusive_group()
    stages.add_argument('--reference-only', action='store_true')
    stages.add_argument('--loopback-only', action='store_true')
    parser.add_argument('--android', type=Path, help='Complete actual Android Naive H3 source export')
    parser.add_argument('--apple', type=Path, help='Complete actual Swift Naive H3 graph export')
    parser.add_argument('--desktop', type=Path, help='Complete desktop shipping Naive H3 graph export')
    args = parser.parse_args()
    if (args.reference_only or args.loopback_only) and (args.android or args.apple or args.desktop):
        parser.error('Host producer exports belong to the separate parser stage')
    run(args.vendor, stage='reference' if args.reference_only else 'loopback' if args.loopback_only else 'parser',
        android=args.android, apple=args.apple, desktop=args.desktop)
