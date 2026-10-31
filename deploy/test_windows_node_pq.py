#!/usr/bin/env python3
"""Prove captured PQ graphs using actual Windows WFP and the verified Rust ABI.

Only the native test executable's AppID scopes the WFP fixture. The separately
retained peer exchanges real Rosenpass/WG/AWG/Start Layer bytes. TUN stays a
harmless test boundary. --prospective admits exactly the two future PQ modes
in the test compilation and first proves current shipping admission is closed.
"""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import os
import platform
import re
import shlex
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'deploy' / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


PQ = load('windows_node_pq_crypto', 'test_desktop_node_pq.py')
WFP = load('windows_node_pq_scope', 'test_windows_node_physical.py')
NODE = PQ.NODE
REFERENCE = PQ.REFERENCE
PREDICATE = 'experimental/libbox/routervpn/mobilemultihop/desktop_node_admission.go'
PEER = 'protocol/routervpnpq/node_pq_peer_windows_test.go'
PEER_TEMPLATE = 'mobile/desktop/node_pq_peer_windows_test.go.tmpl'
PREFIX = b'//go:build windows && cgo && routervpn_native_pq && routervpn_pq_traffic_test && routervpn_windows_node_composition\n\npackage routervpnpq\n'
TAGS = REFERENCE.TAGS + ',routervpn_windows_node_composition'
CLOSED = 'TestRouterVPNDesktopNodeWindowsPQCapabilityClosed'
OPEN = 'TestRouterVPNDesktopNodeWindowsPQCapabilityOpen'
TRAFFIC = 'TestRouterVPNDesktopNodeWindowsPQTraffic'
CREDENTIALS = 'TestRouterVPNDesktopNodeWindowsPQCredentials'
SUCCESSION = 'TestRouterVPNDesktopNodeWindowsPQSuccession'
FOREIGN = 'TestRouterVPNDesktopNodeWindowsPQForeignPredecessor'
PROSPECTIVE_BEFORE = '\tswitch mode {\n'
PROSPECTIVE_AFTER = PROSPECTIVE_BEFORE + '\tcase "wg-pq", "awg2-pq":\n\t\treturn true\n'
CLEANUP_DIAGNOSTICS = (
    'owned PQ reference did not join', 'PQ reference ignored its owned input EOF',
    'retained PQ reference executable changed', 'unacknowledged PQ state has no exact cleanup owner',
    'exact PQ test-owned deny did not retire', 'actual PQ Node did not join its captured physical owner',
    'captured Node Box did not join', 'cancelled PQ Node startup did not join',
    'failed PQ credential startup did not join', 'cancelled native PQ handshake did not join',
    'actual Windows PQ owner did not join', 'rejected PQ successor did not join',
    'PQ native drain did not retain only its exact deny',
)


def checked_sources(source):
    source, records = PQ.checked_sources(source)
    actual, scope = WFP.checked_sources(source)
    if actual != source:
        raise ValueError('PQ WFP observer changed the captured core')
    for name, digest in scope.items():
        if name in records and records[name] != digest:
            raise ValueError('PQ and native WFP source records disagree')
        records[name] = digest
    path = ROOT / PEER_TEMPLATE
    if path.is_symlink() or not path.read_bytes().startswith(PREFIX):
        raise ValueError('Windows PQ peer escaped its native/CGO/test-only scope')
    for relative in ('deploy/test_windows_node_pq.py', 'deploy/test_windows_node_pq_runner.py',
                     PEER_TEMPLATE, 'deploy/setup-desktop-native-toolchain.py',
                     'deploy/install-desktop-windows-toolchain.py'):
        records['windows-pq/' + relative] = PQ.regular_digest(ROOT / relative)
    return source, records


def prospective_predicate(raw):
    # Only the exact current two-mode addition is permitted. A predicate which
    # already mentions either PQ name must be exercised without this overlay.
    if ('func DesktopNodePhysicalGraphSupported(mode, startLayer string) bool {' not in raw or
            '"wg-pq"' in raw or '"awg2-pq"' in raw):
        raise ValueError('Prospective PQ admission lost its exact closed source')
    return WFP.BOOT.IDENTITY.replace_once(raw, PROSPECTIVE_BEFORE, PROSPECTIVE_AFTER)


def mutations(source):
    kernel = WFP.mutants(source)
    result = (
        ('legacy-pq-adoption', FOREIGN, '^' + FOREIGN + '$',
         'foreign PQ predecessor reached actual native encrypted startup', kernel[0], None),
        ('late-pq-handshake', TRAFFIC, '^' + TRAFFIC + '$/^wg-pq$/^off$',
         'actual PQ Node startup', kernel[1], None),
        ('ordinary-pq-udp-deny', TRAFFIC, '^' + TRAFFIC + '$/^wg-pq$/^off$',
         'independent peer marker receipt', kernel[2], None),
    )
    raw = (source / PEER).read_text(encoding='utf-8')
    for name, suffix, witness, before, after in (
        ('valid-native-kem-peer', 'off$/^kem-peer', 'actual WFP PQ accepted untrusted KEM or Start Layer credentials',
         'peerName = "other"', 'peerName = "server"'),
        ('valid-native-packet-peer', 'off$/^packet-peer', 'actual WFP PQ accepted the wrong captured packet peer after native KEM',
         'packetPublic = other.PublicKey().Bytes()', '_ = other\n\t\tpacketPublic = p.reply.Public'),
        ('valid-native-aes-key', 'aes-256-gcm$/^aes-key', 'actual WFP PQ accepted untrusted KEM or Start Layer credentials',
         'password = base64.StdEncoding.EncodeToString(secret[:])', 'password = p.request.Password'),
    ):
        changed = WFP.BOOT.IDENTITY.replace_once(raw, before, after)
        result += ((name, CREDENTIALS, '^' + CREDENTIALS + '$/^wg-pq$/^' + suffix + '$',
                    witness, None, (PEER, changed)),)
    return result


def overlay(source, directory, *, prospective, mutation=None):
    if mutation is not None and mutation not in mutations(source):
        raise ValueError('PQ mutation is not one of its exact compiled controls')
    kernel = mutation[4] if mutation is not None else None
    result = WFP.overlay(source, directory, kernel)
    records = json.loads(result.read_text(encoding='utf-8'))
    mapping = records['Replace']

    def add(relative, raw, label):
        actual = source / relative
        if str(actual) in mapping or Path(relative).is_absolute() or '..' in Path(relative).parts:
            raise ValueError('PQ overlay overlaps native scope or escapes captured source')
        path = directory / (label + '.go')
        path.write_text(raw, encoding='utf-8')
        mapping[str(actual)] = str(path)

    if prospective:
        add(PREDICATE, prospective_predicate((source / PREDICATE).read_text(encoding='utf-8')), 'prospective-pq-predicate')
    if mutation is not None and mutation[5] is not None:
        add(*mutation[5], 'pq-negative')
    result.write_text(json.dumps(records, sort_keys=True), encoding='utf-8')
    return result


def required_output(output, test, cases):
    if ('--- PASS: ' + test + ' (' not in output or
            any('--- PASS: ' + test + '/' + case + ' (' not in output for case in cases) or
            any(value in output for value in ('--- SKIP:', 'DATA RACE'))):
        raise ValueError('Windows PQ omitted a required real native case: ' + test)


def rejected_control(status, output, mutation):
    name, test, selector, witness, _, _ = mutation
    selected = selector.split('/')
    if any(re.fullmatch(r'\^[A-Za-z0-9_-]+\$', part) is None for part in selected):
        raise ValueError('Windows PQ control lost its exact test selector: ' + name)
    leaf = '/'.join(part[1:-1] for part in selected)
    expected = {test} if test == FOREIGN else {test, leaf}
    # The fixture uses one t.Run with slash-separated names, so only its exact
    # leaf and parent may fail. An unrelated fatal/cleanup error is not proof.
    failed = re.findall(r'^\s*--- FAIL: ([^\s]+) \([0-9.]+s\)\r?$', output, re.MULTILINE)
    failure_lines = re.findall(r'^\s*--- FAIL:.*$', output, re.MULTILINE)
    invalid = ('--- SKIP:', 'DATA RACE', 'panic:', 'fatal error:', 'fatal:', 'no tests to run',
               'testing: warning:', *CLEANUP_DIAGNOSTICS)
    if (status != 1 or leaf.split('/')[0] != test or
            (test == FOREIGN and leaf != FOREIGN) or
            len(failed) != len(expected) or len(failure_lines) != len(expected) or
            set(failed) != expected or witness not in output or
            re.search(r'^FAIL\r?$', output, re.MULTILINE) is None or
            any(value.casefold() in output.casefold() for value in invalid)):
        raise ValueError('Windows PQ compiled control missed its actual defect: ' + name + '\n' + output[-16384:])


def new_receipt_path(receipt_path):
    if receipt_path is None:
        return None
    receipt_path = Path(receipt_path).absolute()
    if receipt_path.exists() or receipt_path.is_symlink() or not receipt_path.parent.is_dir():
        raise ValueError('Windows PQ receipt requires a new owned file')
    return receipt_path


def publish_receipt(receipt_path, result, retired_workspace):
    if retired_workspace.exists() or retired_workspace.is_symlink():
        raise ValueError('Windows PQ owned workspace cleanup was not acknowledged')
    if receipt_path is not None:
        with receipt_path.open('x', encoding='utf-8') as output:
            json.dump(result, output, sort_keys=True, indent=2)
            output.write('\n')


def execute(source, pq, cache, go='go', *, prospective=False, env=None, receipt_path=None):
    if platform.system() != 'Windows' or not WFP.BOOT.IDENTITY.ctypes.windll.shell32.IsUserAnAdmin():
        raise ValueError('PQ WFP execution requires actual elevated Windows')
    source, before = checked_sources(Path(source))
    compiler, captured, architecture = NODE.selected_compiler(go, source, dict(os.environ if env is None else env))
    target = captured['GOOS'] + '/' + architecture
    if target not in ('windows/amd64', 'windows/arm64') or captured.get('CGO_ENABLED', '1') != '1':
        raise ValueError('PQ WFP requires matching-host Windows and the real CGO ABI')
    pq, cache = Path(pq).absolute(), Path(cache).absolute()
    native = REFERENCE.BUILD.PQ.verify(pq, target)
    captured['CGO_ENABLED'] = '1'
    captured['CGO_LDFLAGS'] = shlex.join(['-static', '-L' + str(pq), *native['native_static_libs']])
    captured.pop('ROUTERVPN_NODE_PQ_WFP_REFERENCE_CHILD', None)
    race = ['-race'] if architecture == 'amd64' else []
    status, output = NODE.run([compiler, 'mod', 'verify'], cwd=source, env=captured, timeout=300)
    if status:
        raise ValueError('Windows PQ module verification failed:\n' + output[-8192:])
    packet = REFERENCE.BUILD.POLICY.AMNEZIA
    status, output = NODE.run([compiler, 'list', '-m', '-mod=readonly', '-json', packet.MODULE], cwd=source, env=captured, timeout=60)
    dependency = json.loads(output) if status == 0 else {}
    if dependency.get('Version') != packet.VERSION or dependency.get('Sum') != packet.SUM or dependency.get('Replace'):
        raise ValueError('Windows PQ requires the unmodified pinned packet implementation')
    receipt_path = new_receipt_path(receipt_path)
    with tempfile.TemporaryDirectory(prefix='routervpn-windows-pq-') as directory:
        work = Path(directory)
        keys = work / 'private' / 'keys'
        REFERENCE.generate_keys(target, cache, keys)
        key_records = REFERENCE.key_files(keys)
        captured['ROUTERVPN_PQ_TEST_KEYS'] = str(keys)
        relay, relay_digest = NODE.build_layer_reference(compiler, work, captured, race)
        build = [compiler, 'test', '-c', '-p=1', '-mod=readonly', '-tags=' + TAGS, *race, '-ldflags=-checklinkname=0']
        controls = []
        with REFERENCE.test_sources(source):
            def compile_in(name, prospective, mutation=None):
                owned = work / name
                owned.mkdir()
                mapping = overlay(source, owned, prospective=prospective, mutation=mutation)
                binary = owned / 'node-pq-native.test.exe'
                status, output = NODE.run([*build, '-overlay=' + str(mapping), '-o', binary, './protocol/routervpnpq'],
                                          cwd=source, env=captured, timeout=600)
                if status:
                    raise ValueError('Windows PQ native compilation failed: ' + name + '\n' + output[-32768:])
                return binary

            if prospective:
                closed = compile_in('current-closed-capability', False)
                status, output = NODE.run([closed, '-test.run=^' + CLOSED + '$', '-test.count=1', '-test.timeout=120s', '-test.v'],
                                          cwd=source, env=captured, timeout=135)
                print(output, end='', flush=True)
                if status:
                    raise ValueError('Current unmodified PQ admission no longer rejects before native ownership')
                required_output(output, CLOSED, PQ.MODES)
            binary = compile_in('native-composition', prospective)
            digest = PQ.regular_digest(binary)
            # Succession constructs original, trial and restored owners for all
            # three Start Layers: nine complete native owners versus Traffic's
            # six. Keep each socket/handshake/cleanup bound unchanged and scale
            # only this aggregate execution budget for the required work.
            for test, cases, timeout in ((OPEN, (), 15), (TRAFFIC, PQ.TRAFFIC, 480),
                                         (CREDENTIALS, PQ.CREDENTIALS, 900), (SUCCESSION, PQ.LAYERS, 720), (FOREIGN, (), 90)):
                status, output = NODE.run([binary, '-test.run=^' + test + '$', '-test.count=1', '-test.timeout=' + str(timeout) + 's', '-test.v'],
                                          cwd=source, env=captured, timeout=timeout + 15)
                print(output, end='', flush=True)
                if status:
                    raise ValueError('Actual Windows PQ composition failed: ' + test)
                required_output(output, test, cases)
                if PQ.regular_digest(binary) != digest:
                    raise ValueError('Windows PQ executable changed during native execution')
            for mutation in mutations(source):
                name, test, selector, witness, _, _ = mutation
                negative = compile_in(name, prospective, mutation)
                negative_digest = PQ.regular_digest(negative)
                status, output = NODE.run([negative, '-test.run=' + selector, '-test.count=1', '-test.timeout=90s', '-test.v'],
                                          cwd=source, env=captured, timeout=105)
                rejected_control(status, output, mutation)
                if PQ.regular_digest(negative) != negative_digest:
                    raise ValueError('Windows PQ control executable changed during execution')
                controls.append({'name': name, 'binary_sha256': negative_digest, 'output_sha256': hashlib.sha256(output.encode()).hexdigest(), 'witness': witness})
                negative.unlink()
                if negative.exists() or negative.is_symlink():
                    raise ValueError('Windows PQ joined control executable did not retire: ' + name)
                print('Rejected actual Windows PQ compiled control: ' + name, flush=True)
            if REFERENCE.key_files(keys) != key_records or PQ.regular_digest(relay) != relay_digest:
                raise ValueError('Windows PQ keys or shipping relay changed during native execution')
        if REFERENCE.BUILD.PQ.verify(pq, target) != native or checked_sources(source)[1] != before:
            raise ValueError('Windows PQ native archive or prepared source changed')
        result = {'schema': 1, 'target': target, 'source': before, 'native_pq': native,
                  'test_binary_sha256': digest, 'relay_sha256': relay_digest, 'prospective': prospective,
                  'prospective_predicate': {'before': PROSPECTIVE_BEFORE, 'after': PROSPECTIVE_AFTER} if prospective else None,
                  'current_closed_admission_proved': prospective, 'native_firewall': 'actual-appid-scoped-wfp',
                  'native_socket_source': 'actual-isolated-token', 'tun': 'modeled',
                  'traffic_cases': PQ.TRAFFIC, 'credential_cases': PQ.CREDENTIALS,
                  'succession_cases': PQ.LAYERS, 'compiled_negative_controls': controls,
                  'public_admission': 'separate' if prospective else 'shipping-predicate', 'device_acceptance': 'separate'}
    publish_receipt(receipt_path, result, work)
    print('Actual Windows WFP, isolated two-root PQ transport, native rekey/readback, selected Home DNS, all three Start Layers, joined reversal and credential/ordinary-token controls passed; TUN, public host and device acceptance are separate.', flush=True)
    return result


def standalone(go='go', *, prospective=False, receipt_path=None):
    if platform.system() != 'Windows' or not WFP.BOOT.IDENTITY.ctypes.windll.shell32.IsUserAnAdmin():
        raise ValueError('Standalone PQ requires actual elevated Windows')
    compiler, captured, architecture = NODE.selected_compiler(go, ROOT, dict(os.environ))
    target = 'windows/' + architecture
    if captured.get('CGO_ENABLED', '1') != '1':
        raise ValueError('Standalone PQ cannot disable its native cryptographic ABI')
    receipt_path = new_receipt_path(receipt_path)
    captured['CGO_ENABLED'] = '1'
    native = REFERENCE.BUILD
    previous = dict(os.environ)
    with tempfile.TemporaryDirectory(prefix='routervpn-windows-pq-core-') as directory:
        workspace = Path(directory)
        source, xray, pq, cache = (workspace / name for name in ('core', 'xray', 'pq', 'cargo-cache'))
        try:
            os.environ.clear()
            os.environ.update(captured)
            native.checkout(source, 'https://github.com/SagerNet/sing-box.git', native.PIN)
            native.checkout(xray, 'https://github.com/XTLS/Xray-core.git', native.POLICY.XRAY.XRAY_PIN)
            native.pristine(source, native.PIN)
            native.pristine(xray, native.POLICY.XRAY.XRAY_PIN)
            native.PQ.build(target, pq, cache)
            native.POLICY.prepare_native(source, xray)
            native.PERFORMANCE.prepare(source)
            native.OPENVPN.prepare(source)
            native.EXTERNAL.prepare(source, go=str(compiler), env=captured)
            native.BUFFERS.prepare(source)
            native.run([compiler, 'mod', 'tidy'], cwd=source, env=captured)
            native.run([compiler, 'mod', 'verify'], cwd=source, env=captured)
            native.POLICY.AMNEZIA.verify(source)
            result = execute(source, pq, cache, str(compiler), prospective=prospective, env=captured)
        finally:
            os.environ.clear()
            os.environ.update(previous)
    publish_receipt(receipt_path, result, workspace)
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path, nargs='?')
    parser.add_argument('pq', type=Path, nargs='?')
    parser.add_argument('--cache', type=Path, default=ROOT / 'dist/.native-pq-cache')
    parser.add_argument('--go', default='go')
    parser.add_argument('--prospective', action='store_true')
    parser.add_argument('--standalone', action='store_true')
    parser.add_argument('--receipt', type=Path)
    arguments = parser.parse_args()
    if arguments.standalone:
        if arguments.source is not None or arguments.pq is not None:
            parser.error('--standalone owns its exact source and native archive')
        standalone(arguments.go, prospective=arguments.prospective, receipt_path=arguments.receipt)
    else:
        if arguments.source is None or arguments.pq is None:
            parser.error('an exact prepared source and native PQ archive are required')
        execute(arguments.source, arguments.pq, arguments.cache, arguments.go,
                prospective=arguments.prospective, receipt_path=arguments.receipt)
