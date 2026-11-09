#!/usr/bin/env python3
"""Execute the separate protected Windows imported Naive H3 inventory.

The seven existing Windows native phases and fourteen receipts remain separate.
Portable graphs and completed-package constructor checks never satisfy this
actual BFE/native peer gate. A CI phase binds its independent result to the
original checkout, architecture, run and attempt; prepared runs retain the
shipping compiler environment without requiring GitHub metadata.
"""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import os
import platform
import re
import stat
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'deploy' / filename)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


NATIVE = module('imported_h3_windows_native', 'test_windows_node_physical.py')
CI = module('imported_h3_windows_ci', 'test_windows_node_physical_ci.py')
BUILD = module('imported_h3_windows_build', 'build-native-runtime.py')
KINDS = ('socks5', 'shadowsocks', 'hysteria2', 'wireguard', 'amneziawg', 'openvpn-tcp', 'openvpn-udp')
LAYERS = ('off', 'aes-256-gcm', 'aes-256-gcm+xor-whitening')
ARCHITECTURES = ('amd64', 'arm64')
PREFIX = 'TestRouterVPNWindowsImportedNaiveH3'
RUNTIME, REFUSALS, ASSOCIATIONS, SUCCESSION, OWNERSHIP, CANCELLATION = (PREFIX + name for name in
    ('Runtime', 'Refusals', 'Associations', 'Succession', 'Ownership', 'Cancellation'))
ROOTS = (RUNTIME, REFUSALS, ASSOCIATIONS, SUCCESSION, OWNERSHIP, CANCELLATION)
PEER = PREFIX + 'Peer'
CELLS = tuple(kind + '--' + first + '--' + last for kind in KINDS for first in LAYERS for last in LAYERS)
NEGATIVES = tuple('entry-auth--' + kind for kind in KINDS) + (
    'final-password', 'final-sni', 'final-trust', 'bootstrap-route', 'selected-route',
    'socks-forged-relay', 'socks-auth-downgrade', 'entry-layer-key', 'final-layer-key')
OWNER_CASES = ('original-caller', 'foreign-physical-root', 'retired-owner')
REQUIRED = (RUNTIME, *(RUNTIME + '/' + cell for cell in CELLS),
            REFUSALS, *(REFUSALS + '/' + value for value in NEGATIVES),
            ASSOCIATIONS, SUCCESSION, CANCELLATION, OWNERSHIP, *(OWNERSHIP + '/' + value for value in OWNER_CASES))
CONTROL = 'ordinary-udp-deny'
CONTROL_WITNESS = 'ordinary token bypassed actual imported H3 WFP deny: independent peer marker'
FORMAT = 'routervpn-windows-imported-naive-h3-ci-v1'
NATIVE_FORMAT = 'routervpn-windows-imported-naive-h3-native-v1'
SCOPE = 'windows-protected-imported-naive-h3'
TAG = b'//go:build windows && routervpn_windows_node_composition && with_purego\n\npackage box\n'
TEMPLATES = {
    'node_imported_naive_h3_windows_test.go.tmpl': 'routervpn_desktop_node_imported_naive_h3_windows_test.go',
    'node_imported_naive_h3_windows_peer_test.go.tmpl': 'routervpn_desktop_node_imported_naive_h3_windows_peer_test.go',
}
HEX = re.compile(r'[0-9a-f]{64}')
SHARED = 'TestImportedNaiveH3IndependentLayers'


def digest(records):
    return NATIVE.source_digest(records)


def regular(path, maximum=4 << 20):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or not stat.S_ISREG(path.stat().st_mode) or not 0 < path.stat().st_size <= maximum:
        raise ValueError('Protected imported H3 lost a bounded original regular file')
    return path.read_bytes()


def checked_sources(source):
    source, records = NATIVE.checked_sources(source)
    records = dict(records)
    for name, target in TEMPLATES.items():
        original = ROOT / 'mobile/desktop' / name
        raw = regular(original)
        if not raw.startswith(TAG) or regular(source / target) != raw:
            raise ValueError('Protected imported H3 prepared fixture differs from its Windows-only original')
        records['imported-h3/' + name] = hashlib.sha256(raw).hexdigest()
    for path in (*sorted((ROOT / 'internal/mobilemultihop').glob('*.go')),
                 ROOT / 'deploy/test_windows_imported_naive_h3.py',
                 ROOT / 'deploy/test_windows_imported_naive_h3_runner.py'):
        records['gate/' + path.relative_to(ROOT).as_posix()] = hashlib.sha256(regular(path)).hexdigest()
    return source, records


def inventory(directory):
    directory = Path(directory)
    expected = {kind + '--naive-h3--' + first + '--' + last + '.json'
                for kind in KINDS for first in LAYERS for last in LAYERS}
    if directory.is_symlink() or not directory.is_dir() or {p.name for p in directory.iterdir()} != expected:
        raise ValueError('Protected imported H3 requires exactly63 original source captures')
    records = {}
    for path in sorted(directory.iterdir()):
        raw = regular(path)
        source = json.loads(raw)
        kind, mode, first, last = path.stem.split('--')
        if not isinstance(source, list) or len(source) != 9 or not all(isinstance(v, str) for v in source) or source[2] != mode or not HEX.fullmatch(source[7]):
            raise ValueError('Protected imported H3 source lost its nine original captured strings')
        captured, final, graph = json.loads(source[1]), json.loads(source[4]), json.loads(source[8])
        protocol = 'openvpn' if kind.startswith('openvpn-') else kind
        if captured.get('protocol') != protocol or (captured['profile'].get('start_layer') or 'off') != first or (final.get('start_layer') or 'off') != last:
            raise ValueError('Protected imported H3 source filename substituted another entry or layer')
        rows = graph.get('outbounds', []) + graph.get('endpoints', [])
        naive = [v for v in rows if v.get('type') == 'naive']
        if len(naive) != 1 or naive[0].get('quic') is not True:
            raise ValueError('Protected imported H3 original final lost its exact QUIC transport')
        if protocol == 'openvpn' and not any(v.get('tag') == 'entry-wg' and v.get('network') == kind.removeprefix('openvpn-') for v in rows):
            raise ValueError('Protected imported H3 substituted the original OpenVPN wire transport')
        records[path.name] = hashlib.sha256(raw).hexdigest()
    return records


def require_verdicts(status, output, required):
    observed = re.findall(r'^\s*--- PASS: (\S+) \(', output, re.MULTILINE)
    if (status or len(observed) != len(required) or set(observed) != set(required) or
            any(observed.count(case) != 1 for case in required) or NATIVE.socks_native_aborted(output) or
            '--- FAIL:' in output or re.search(r'^FAIL(?:\s|$)', output, re.MULTILINE)):
        raise ValueError('Protected imported H3 omitted or substituted an exact native verdict:\n' + output[-16384:])


def require_discovery(status, output):
    # Inspect the original compiled image, not a source-string approximation.
    # The independent peer is intentionally invoked only by its captured parent.
    observed = output.splitlines()
    expected = (*ROOTS, PEER)
    if status or len(observed) != len(expected) or set(observed) != set(expected):
        raise ValueError('Protected imported H3 compiled root inventory changed:\n' + output[-16384:])


def invocations():
    # One actual Go process owns each captured root, temporary TLS root and
    # deadline. Parent verdicts may repeat across these disjoint invocations;
    # every original leaf must occur exactly once in its own required set.
    for kind in KINDS:
        cells = tuple(cell for cell in CELLS if cell.startswith(kind + '--'))
        yield '^' + RUNTIME + '$/^' + re.escape(kind) + '--', (RUNTIME, *(RUNTIME + '/' + cell for cell in cells)), 180
    for value in NEGATIVES:
        yield '^' + REFUSALS + '$/^' + re.escape(value) + '$', (REFUSALS, REFUSALS + '/' + value), 180
    for root, children in ((ASSOCIATIONS, ()), (SUCCESSION, ()), (CANCELLATION, ()), (OWNERSHIP, OWNER_CASES)):
        yield '^' + root + '$', (root, *(root + '/' + value for value in children)), 180


def execute(source, go='go', *, prospective=False, env=None, bootstrap_only=False):
    if prospective or platform.system() != 'Windows' or not NATIVE.BOOT.IDENTITY.ctypes.windll.shell32.IsUserAnAdmin():
        raise ValueError('Protected imported H3 requires actual elevated native Windows execution')
    source, before = checked_sources(source)
    compiler, captured, architecture = NATIVE.BOOT.IDENTITY.selected_compiler(go, source, dict(os.environ if env is None else env))
    # Standalone preparation already captures CGO0. Prepared package execution
    # keeps the matching shipping CGO setting and complete shipping tag set.
    cgo = captured.get('CGO_ENABLED')
    if cgo not in ('0', '1') or bootstrap_only and cgo != '0':
        raise ValueError('Protected imported H3 lost its original compiler environment')
    race = ['-race'] if cgo == '1' and architecture == 'amd64' else []
    tags = NATIVE.TAGS if bootstrap_only else (*BUILD.tags('windows/' + architecture), 'routervpn_windows_node_composition')
    for name in ('ROUTERVPN_WINDOWS_IMPORTED_H3_PEER', 'ROUTERVPN_EXTERNAL_WFP_PEER', 'ROUTERVPN_NODE_WFP_REFERENCE_CHILD'):
        captured.pop(name, None)
    with tempfile.TemporaryDirectory(prefix='routervpn-imported-h3-wfp-') as temporary:
        work = Path(temporary)
        sources = work / 'source-captures'; sources.mkdir()
        captured['ROUTERVPN_IMPORTED_NAIVE_H3_FIXTURES'] = str(sources)
        shared_cases = (SHARED, *(SHARED + '/' + kind + '/' + first + '/' + last for kind in KINDS for first in LAYERS for last in LAYERS))
        status, output = NATIVE.BOOT.IDENTITY.run([compiler, 'test', '-mod=readonly', *race, '-v', './internal/mobilemultihop', '-run', '^' + SHARED + '$', '-count=1', '-timeout=60s'], cwd=ROOT, env=captured, timeout=180)
        require_verdicts(status, output, shared_cases)
        source_records = inventory(sources)
        library = NATIVE.NODE.stage_naive_library(compiler, source, work, captured)
        build = [compiler, 'test', '-c', '-mod=readonly', '-tags=' + ','.join(tags), *race, '-ldflags=-checklinkname=0']
        base = work / 'baseline'; base.mkdir()
        selected = NATIVE.overlay(source, base)
        binary = base / 'imported-naive-h3.test.exe'
        status, output = NATIVE.BOOT.IDENTITY.run([*build, '-overlay=' + str(selected), '-o', binary, '.'], cwd=source, env=captured, timeout=600)
        if status:
            raise ValueError('Protected imported H3 native fixture did not compile:\n' + output[-32768:])
        image_digest = NATIVE.executable_digest(binary)
        status, output = NATIVE.BOOT.IDENTITY.run([binary, '-test.list=^' + PREFIX], cwd=source, env=captured, timeout=30)
        require_discovery(status, output)
        if NATIVE.executable_digest(binary) != image_digest:
            raise ValueError('Protected imported H3 original image changed during root discovery')
        all_cases = set()
        for expression, expected, budget in invocations():
            status, output = NATIVE.BOOT.IDENTITY.run([binary, '-test.run=' + expression, '-test.count=1', '-test.timeout=' + str(budget) + 's', '-test.v'], cwd=source, env=captured, timeout=budget + 15)
            print(output, end='' if output.endswith('\n') else '\n', flush=True)
            require_verdicts(status, output, expected)
            all_cases.update(expected)
            if NATIVE.executable_digest(binary) != image_digest or inventory(sources) != source_records:
                raise ValueError('Protected imported H3 native executable or original capture changed')
        if all_cases != set(REQUIRED):
            raise ValueError('Protected imported H3 did not execute its complete separate native inventory')
        # Deliberately restore the original actual WFP UDP-permit defect. The
        # positive reference process must remain live, and the exact receiving
        # marker must make this ownership leaf fail. Build/panic/timeout is not
        # evidence that the native deny observation detects the defect.
        control = work / CONTROL; control.mkdir()
        selected = NATIVE.overlay(source, control, NATIVE.mutants(source)[2])
        changed = control / 'imported-naive-h3.test.exe'
        status, output = NATIVE.BOOT.IDENTITY.run([*build, '-overlay=' + str(selected), '-o', changed, '.'], cwd=source, env=captured, timeout=600)
        if status:
            raise ValueError('Protected imported H3 WFP control did not compile:\n' + output[-16384:])
        changed_digest = NATIVE.executable_digest(changed)
        leaf = OWNERSHIP + '/foreign-physical-root'
        status, output = NATIVE.BOOT.IDENTITY.run([changed, '-test.run=^' + OWNERSHIP + '$/^foreign-physical-root$', '-test.count=1', '-test.timeout=60s', '-test.v'], cwd=source, env=captured, timeout=75)
        if status == 0 or not NATIVE.exact_native_verdict(output, 'FAIL', leaf) or CONTROL_WITNESS not in output or NATIVE.socks_native_aborted(output):
            raise ValueError('Protected imported H3 deny control missed its exact actual defect:\n' + output[-16384:])
        if NATIVE.executable_digest(changed) != changed_digest:
            raise ValueError('Protected imported H3 original control executable changed')
        NATIVE.NODE.verify_naive_library(library)
        if checked_sources(source)[1] != before or inventory(sources) != source_records:
            raise ValueError('Protected imported H3 original source changed during native execution')
        result = {'format': NATIVE_FORMAT, 'scope': SCOPE, 'goos': 'windows', 'architecture': architecture,
                  'cgo': cgo, 'race': bool(race), 'source_sha256': digest(before),
                  'source_inventory_sha256': digest(source_records), 'compiled_roots': list(ROOTS), 'verdicts': list(REQUIRED),
                  'controls': [CONTROL], 'executables': {'baseline': image_digest, CONTROL: changed_digest},
                  'library': {'sha256': library[2], 'bytes': library[3], 'target': 'windows/' + architecture},
                  'physical_device_acceptance': False}
        validate_native(result, architecture)
        return result


def validate_native(value, architecture):
    fields = {'format', 'scope', 'goos', 'architecture', 'cgo', 'race', 'source_sha256', 'source_inventory_sha256', 'compiled_roots', 'verdicts', 'controls', 'executables', 'library', 'physical_device_acceptance'}
    if not isinstance(value, dict) or set(value) != fields or value['format'] != NATIVE_FORMAT or value['scope'] != SCOPE or value['goos'] != 'windows' or architecture not in ARCHITECTURES or value['architecture'] != architecture:
        raise ValueError('Protected imported H3 receipt lost its actual scope/architecture')
    if value['cgo'] not in ('0', '1') or type(value['race']) is not bool or value['race'] != (value['cgo'] == '1' and architecture == 'amd64') or value['physical_device_acceptance'] is not False:
        raise ValueError('Protected imported H3 receipt invented compiler or device evidence')
    if value['compiled_roots'] != list(ROOTS) or value['verdicts'] != list(REQUIRED) or value['controls'] != [CONTROL]:
        raise ValueError('Protected imported H3 receipt omitted original native verdicts/controls')
    if any(not isinstance(value[k], str) or not HEX.fullmatch(value[k]) for k in ('source_sha256', 'source_inventory_sha256')):
        raise ValueError('Protected imported H3 receipt lost its source identities')
    images, library = value['executables'], value['library']
    if not isinstance(images, dict) or set(images) != {'baseline', CONTROL} or any(not isinstance(v, str) or not HEX.fullmatch(v) for v in images.values()):
        raise ValueError('Protected imported H3 receipt has another native executable inventory')
    if not isinstance(library, dict) or set(library) != {'sha256', 'bytes', 'target'} or library['target'] != 'windows/' + architecture or not isinstance(library['sha256'], str) or not HEX.fullmatch(library['sha256']) or type(library['bytes']) is not int or not 0 < library['bytes'] <= 128 << 20:
        raise ValueError('Protected imported H3 receipt has another native library')


def filename(architecture):
    if architecture not in ARCHITECTURES:
        raise ValueError('Protected imported H3 requires its actual Windows architecture')
    return 'windows-imported-naive-h3-' + architecture + '.json'


def validate(value, expected, architecture):
    if not isinstance(value, dict) or set(value) != {'format', *expected, 'native', 'comparable_source_sha256'} or value['format'] != FORMAT or any(value[k] != expected[k] for k in ('repository', 'commit', 'run_id')) or not isinstance(value['run_attempt'], str) or not re.fullmatch(r'[1-9][0-9]{0,19}', value['run_attempt']) or int(value['run_attempt']) > int(expected['run_attempt']):
        raise ValueError('Protected imported H3 CI receipt belongs to another checkout/run')
    if not isinstance(value['comparable_source_sha256'], str) or not HEX.fullmatch(value['comparable_source_sha256']):
        raise ValueError('Protected imported H3 CI receipt lost its prepared closure')
    validate_native(value['native'], architecture)


def phase(architecture, destination, go='go', *, env=None):
    expected = CI.context(os.environ if env is None else env)
    destination = Path(destination)
    if destination.name != filename(architecture) or destination.exists() or destination.is_symlink():
        raise ValueError('Protected imported H3 CI receipt requires a new owned architecture path')
    CI.verify_checkout(expected)
    observed = []
    def selected(source, compiler, **kwargs):
        source, before = checked_sources(source)
        comparable = CI.comparable_source(source, before, compiler, kwargs['env'])
        result = execute(source, compiler, **kwargs)
        if result['source_sha256'] != digest(before) or checked_sources(source)[1] != before or CI.comparable_source(source, before, compiler, kwargs['env']) != comparable:
            raise ValueError('Protected imported H3 source changed across CI execution')
        value = {'format': FORMAT, **expected, 'native': result, 'comparable_source_sha256': comparable}
        validate(value, expected, architecture)
        observed.append(value)
    NATIVE.BOOT.standalone(go, native_test=selected)
    if len(observed) != 1:
        raise ValueError('Protected imported H3 must execute its original native phase exactly once')
    CI.verify_checkout(expected)
    with destination.open('x', encoding='utf-8') as stream:
        json.dump(observed[0], stream, sort_keys=True); stream.write('\n')
    return observed[0]


def aggregate(directory, needs_result, *, env=None):
    if needs_result != 'success':
        raise ValueError('Protected imported H3 completion requires both native architecture jobs')
    expected = CI.context(os.environ if env is None else env)
    CI.verify_checkout(expected)
    directory = Path(directory)
    if directory.is_symlink() or not directory.is_dir() or {p.name for p in directory.iterdir()} != {filename(a) for a in ARCHITECTURES}:
        raise ValueError('Protected imported H3 requires exactly two separate architecture receipts')
    result = []
    for architecture in ARCHITECTURES:
        value = CI.read_receipt(directory / filename(architecture)); validate(value, expected, architecture); result.append(value)
    if len({value['comparable_source_sha256'] for value in result}) != 1:
        raise ValueError('Protected imported H3 architectures used different prepared source closures')
    CI.verify_checkout(expected)
    print('Protected imported Naive H3: both exact Windows native inventories passed for ' + expected['commit'], flush=True)
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    selected = commands.add_parser('phase'); selected.add_argument('--architecture', choices=ARCHITECTURES, required=True); selected.add_argument('--output', type=Path, required=True); selected.add_argument('--go', default='go')
    prepared = commands.add_parser('prepared'); prepared.add_argument('source', type=Path); prepared.add_argument('--go', default='go')
    complete = commands.add_parser('aggregate'); complete.add_argument('--receipts', type=Path, required=True); complete.add_argument('--needs-result', required=True)
    args = parser.parse_args()
    if args.command == 'phase': phase(args.architecture, args.output, args.go)
    elif args.command == 'prepared': execute(args.source, args.go)
    else: aggregate(args.receipts, args.needs_result)
