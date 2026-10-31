#!/usr/bin/env python3
"""Execute complete MAX Node graphs against real pinned PQ and outer peers.

The four complete MAX families retain their mandatory Rosenpass/WG or AWG,
SS2022 middle and TLS/PQ-REALITY/XHTTP or Hysteria2 outer. This gate captures
actual source, compiler, native ABI/archive, fresh private keys, Xray and the
shipping whitening relay. OS permits and TUN remain explicit fixtures; native
firewall admission, public host integration and device acceptance are separate.
"""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import os
import re
import shlex
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'deploy' / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


PQ = load('complete_max_pq_gate', 'test_desktop_node_pq.py')
NODE, REFERENCE = PQ.NODE, PQ.REFERENCE
LAYERS = PQ.LAYERS
FAMILIES = {
    'QUIC': ('max-quic-wg', 'max-quic-awg'),
    'TLS': ('max-tls-wg', 'max-tls-awg'),
}
OUTER_FAULTS = {
    'QUIC': ('outer-password', 'outer-trust', 'outer-name'),
    'TLS': ('outer-reality-key', 'outer-mlkem-key', 'outer-user'),
}
TRAFFIC = {family: tuple(mode + '/' + layer for mode in modes for layer in LAYERS)
           for family, modes in FAMILIES.items()}
# The generated MAX middle and outer AES Start Layer intentionally share the
# paired node's one SS2022 key/port. Off proves the mandatory middle; layered
# middle-key faults prove rejection by the outer AES before the outer transport.
CREDENTIALS = {family: tuple(mode + '/' + layer + '/' + fault
                            for mode in modes for layer in LAYERS
                            for fault in ('kem-peer', 'packet-peer', 'middle-key',
                                          *(OUTER_FAULTS[family] if layer == 'off' else ())))
               for family, modes in FAMILIES.items()}
TEMPLATES = tuple('node_max_' + name + '_test.go.tmpl'
                  for name in ('peer', 'stream', 'tls_reference', 'credentials'))
TAG = b'//go:build cgo && routervpn_native_pq && routervpn_pq_traffic_test\n\npackage routervpnpq\n'
STARTUP_RECORDS = 'TestRouterVPNDesktopNodeMAXTLSStartupRecords'
PASS = re.compile(r'^\s*--- PASS: ([^\s]+) \([0-9.]+s\)$', re.MULTILINE)
FAIL = re.compile(r'^\s*--- FAIL: ([^\s]+) \([0-9.]+s\)$', re.MULTILINE)
INVALID_OUTPUT = ('--- SKIP:', 'DATA RACE', 'panic:', 'fatal error:', 'no tests to run')
JOIN_FAILURES = (
    'actual PQ Node did not join its captured physical owner',
    'cancelled PQ Node startup did not join',
    'MAX TLS retained its unjoined reference and private workspace',
    'MAX TLS owned workspace cleanup',
    'MAX TLS cannot replace its unjoined captured process',
    'MAX cancelled credential trial did not join',
    'MAX credential failure escaped its captured owner',
    'MAX failed joined captured retirement',
)


def regular_digest(path):
    return PQ.regular_digest(Path(path))


def checked_sources(source):
    for name in TEMPLATES:
        relative = 'protocol/routervpnpq/' + name.removesuffix('.tmpl')
        path = ROOT / 'mobile/desktop' / name
        if NODE.PREP.PEER_TEMPLATES.get(name) != relative or path.is_symlink() or not path.read_bytes().startswith(TAG):
            raise ValueError('Complete MAX lost its exact tagged preparation mapping: ' + name)
    source, records = PQ.checked_sources(Path(source))
    for name in TEMPLATES:
        records['max-source/mobile/desktop/' + name] = regular_digest(ROOT / 'mobile/desktop' / name)
    for name in ('test_desktop_node_max.py', 'test_desktop_node_max_runner.py'):
        records['max-source/deploy/' + name] = regular_digest(ROOT / 'deploy' / name)
    # The Hysteria2 outbound is unmodified pinned core source. Bind its entire
    # implementation file set before the explicit production-fault overlays.
    listed = subprocess.check_output(['git', 'ls-tree', '-r', '--name-only', NODE.PREP.PIN,
                                      '--', 'protocol/hysteria2'], cwd=source, text=True).splitlines()
    expected = {name for name in listed if name.endswith('.go')}
    actual = {path.relative_to(source).as_posix() for path in (source / 'protocol/hysteria2').rglob('*.go')}
    if not expected or actual != expected:
        raise ValueError('Complete MAX lost the exact pinned Hysteria2 file set')
    for relative in sorted(expected):
        path = source / relative
        original = subprocess.check_output(['git', 'show', NODE.PREP.PIN + ':' + relative], cwd=source)
        if path.is_symlink() or not path.is_file() or path.read_bytes() != original:
            raise ValueError('Complete MAX Hysteria2 implementation changed: ' + relative)
        records[relative] = regular_digest(path)
    return source, records


def required_output(status, output, parent, cases):
    if status or any(value in output for value in INVALID_OUTPUT) or FAIL.search(output):
        raise ValueError('Complete MAX baseline failed or omitted real execution: ' + parent)
    passed = PASS.findall(output)
    required = (parent, *(parent + '/' + case for case in cases))
    if any(passed.count(name) != 1 for name in required):
        raise ValueError('Complete MAX omitted or duplicated a required captured case: ' + parent)


def rejected_output(status, output, parent, selector_case, witness):
    failed = FAIL.findall(output)
    # A compiler error, crash, race, timeout, unrelated failed case or successful
    # run cannot substitute for the exact intentional Go assertion.
    expected = {parent, parent + '/' + selector_case}
    if status != 1 or any(value in output for value in (*INVALID_OUTPUT, *JOIN_FAILURES)) or \
            len(failed) != 2 or set(failed) != expected or witness not in output:
        raise ValueError('Complete MAX control missed its exact executable rejection')


def selector(parent, case):
    return '/'.join('^' + re.escape(part) + '$' for part in (parent, *case.split('/')))


def tuple_witness(protocol):
    return 'MAX captured lower rejected uncaptured ' + protocol + ' tuple'


def control_sources(source, label, relative, replacement):
    result = {relative: replacement}
    protocol = {'different-outer-tcp-tuple': 'tcp', 'different-outer-udp-tuple': 'udp'}.get(label)
    if protocol is not None:
        # Xray may collapse an asynchronous lower-dial rejection to a generic
        # PQ write error. Observe the unchanged rejection predicate itself:
        # only a live, open owner with the wrong captured tuple can emit this
        # witness. A stale owner or unrelated transport failure cannot pass.
        physical = 'routervpn/desktoppt/node_physical.go'
        original = (source / physical).read_text(encoding='utf-8')
        boundary = '\tif closed || !allowed || owner == nil || !owner.SocketCurrent() {\n'
        if original.count(boundary) != 1:
            raise ValueError('Complete MAX lost its exact captured tuple rejection boundary')
        observation = ('\tif !closed && !allowed && owner != nil && owner.SocketCurrent() && base == ' +
                       json.dumps(protocol) + ' {\n\t\tprintln(' + json.dumps(tuple_witness(protocol)) + ')\n\t}\n')
        result[physical] = original.replace(boundary, observation + boundary)
    return result


def mutations(source):
    def changed(relative, before, after, count=1):
        raw = (source / relative).read_text(encoding='utf-8')
        if raw.count(before) != count:
            raise ValueError('Complete MAX control lost its unique production boundary: ' + relative)
        return raw.replace(before, after)

    xray = 'protocol/routervpnxray/outbound.go'
    hy2 = 'protocol/hysteria2/outbound.go'
    middle = 'protocol/shadowsocks/outbound.go'
    owner = 'experimental/libbox/routervpn/mobilepq/peer.go'
    dns = 'routervpn_strategy_dns.go'
    result = []

    def add(label, relative, family, case, witness, before, after, *, credentials=False, count=1):
        parent = 'TestRouterVPNDesktopNodeCompleteMAX' + family + ('Credentials' if credentials else '')
        result.append((label, relative, parent, case, witness, changed(relative, before, after, count)))

    for family, mode in (('TLS', 'max-tls-wg'), ('QUIC', 'max-quic-wg')):
        if family == 'TLS':
            before = 'conn, err := b.dialer.DialContext(cctx, N.NetworkTCP, M.ParseSocksaddr(b.server.String()))'
            add('uncaptured-outer-tcp', xray, family, mode + '/off',
                'MAX bypassed its exact outermost captured physical grant', before,
                'conn, err := (&net.Dialer{}).DialContext(cctx, N.NetworkTCP, b.server.String())')
            add('different-outer-tcp-tuple', xray, family, mode + '/off',
                tuple_witness('tcp'), before,
                'destination := M.ParseSocksaddr(b.server.String())\n\tdestination.Port++\n\tconn, err := b.dialer.DialContext(cctx, N.NetworkTCP, destination)')
        else:
            add('uncaptured-outer-udp', hy2, family, mode + '/off',
                'MAX bypassed its exact outermost captured physical grant',
                'Dialer:             outboundDialer,',
                'Dialer:             func() N.Dialer { _ = outboundDialer; return N.SystemDialer }(),')
            add('different-outer-udp-tuple', hy2, family, mode + '/off',
                tuple_witness('udp'),
                'ServerAddress:      options.ServerOptions.Build(),',
                'ServerAddress:      func() M.Socksaddr { destination := options.ServerOptions.Build(); destination.Port++; return destination }(),')
        add('middle-substituted-tcp-' + family.lower(), middle, family, mode + '/off',
            'actual PQ Node startup',
            'h.dialer.DialContext(ctx, N.NetworkUDP, h.serverAddr)',
            'h.dialer.DialContext(ctx, N.NetworkTCP, h.serverAddr)', count=2)

    add('dropped-negotiated-psk', owner, 'QUIC', 'max-quic-wg/off',
        'invalid or ambiguous native test peer readback',
        'return p.peer.SetPQKey(p.public[:], key)', 'return nil')
    add('cached-selected-dns', dns, 'TLS', 'max-tls-wg/off',
        'complete MAX cached or bypassed selected DNS',
        'DisableCache: true, DisableOptimisticCache: true, Timeout: 5 * time.Second,',
        'DisableCache: false, DisableOptimisticCache: false, Timeout: 5 * time.Second,')
    peer = 'protocol/routervpnpq/node_max_peer_test.go'
    tls = 'protocol/routervpnpq/node_max_tls_reference_test.go'
    for family, modes in FAMILIES.items():
        for fault in OUTER_FAULTS[family]:
            relative = tls if family == 'TLS' else peer
            before = 'case "' + fault + '":' if family == 'TLS' else 'if fault == "' + fault + '" {'
            after = 'case "disabled-' + fault + '":' if family == 'TLS' else 'if false && fault == "' + fault + '" {'
            add('valid-' + fault + '-control', relative, family, modes[0] + '/off/' + fault,
                'MAX accepted the substituted authenticated layer credential', before, after, credentials=True)
    # One paired SS key governs both positions. These two controls separately
    # prove the Off middle-key assertion and the layered outer-key assertion.
    for family, case in (('QUIC', 'max-quic-wg/off/middle-key'),
                         ('TLS', 'max-tls-wg/aes-256-gcm/middle-key')):
        add('valid-middle-key-' + family.lower(), peer, family, case,
            'MAX accepted the substituted authenticated layer credential',
            'if fault == "middle-key" {', 'if false && fault == "middle-key" {', credentials=True)
    if len(result) != 16 or len({item[0] for item in result}) != len(result):
        raise ValueError('Complete MAX lost its independent production controls')
    return tuple(result)


def compiled_controls(source, workspace, build, captured, suffix):
    controls = []
    for label, relative, parent, case, witness, replacement in mutations(source):
        replacements, overlay_digests = {}, {}
        for index, (path, contents) in enumerate(sorted(control_sources(source, label, relative, replacement).items())):
            changed = workspace / (label + '-' + str(index) + '.go')
            changed.write_text(contents, encoding='utf-8')
            replacements[str(source / path)] = str(changed)
            overlay_digests[path] = regular_digest(changed)
        overlay = workspace / (label + '.json')
        overlay.write_text(json.dumps({'Replace': replacements}), encoding='utf-8')
        mutant = workspace / (label + '.test' + suffix)
        status, output = NODE.run([*build, '-overlay=' + str(overlay), '-o', mutant, './protocol/routervpnpq'],
                                  cwd=source, env=captured, timeout=600)
        if status:
            raise ValueError('Complete MAX control failed to compile: ' + label + '\n' + output[-16384:])
        mutant_digest = regular_digest(mutant)
        status, output = NODE.run([mutant, '-test.run=' + selector(parent, case),
                                  '-test.v', '-test.count=1', '-test.timeout=90s'], cwd=source, env=captured, timeout=105)
        try:
            rejected_output(status, output, parent, case, witness)
        except ValueError as error:
            raise ValueError(str(error) + ': ' + label + '\n' + output[-16384:]) from error
        if regular_digest(mutant) != mutant_digest:
            raise ValueError('Complete MAX control executable changed: ' + label)
        controls.append({'label': label, 'source': relative, 'parent': parent, 'case': case,
                         'witness': witness, 'binary_sha256': mutant_digest,
                         'overlay_sha256': overlay_digests[relative],
                         'source_overlays_sha256': overlay_digests, 'exit_status': status,
                         'output_sha256': hashlib.sha256(output.encode('utf-8')).hexdigest()})
        # The runner has synchronously joined this process. Retain its
        # digest and exact assertion/output receipt, not sixteen large
        # executables until the complete matrix ends.
        mutant.unlink()
        print('Rejected compiled complete MAX control: ' + label +
              ' output_sha256=' + controls[-1]['output_sha256'], flush=True)
    return controls


def tool_receipts(source, compiler, captured, target, cache):
    rust_env = REFERENCE.BUILD.PQ.environment(target, cache)
    result = {}
    for name, program, arguments, environment, expected in (
        ('go', str(compiler), ('version',), captured,
         'go version ' + REFERENCE.BUILD.TOOLCHAIN + ' ' + target),
        ('rustc', 'rustc', ('--version',), rust_env, 'rustc ' + REFERENCE.BUILD.PQ.RUST + ' '),
        ('cargo', 'cargo', ('--version',), rust_env, 'cargo ' + REFERENCE.BUILD.PQ.RUST + ' '),
    ):
        executable = shutil.which(program, path=environment.get('PATH', os.defpath))
        if executable is None:
            raise ValueError('Complete MAX lost its pinned tool: ' + name)
        resolved = Path(executable).resolve(strict=True)
        status, output = NODE.run([executable, *arguments], cwd=source, env=environment, timeout=30)
        version = output.strip()
        if status or (version != expected if name == 'go' else not version.startswith(expected)):
            raise ValueError('Complete MAX tool identity changed: ' + name)
        result[name] = {'invoked_path': executable, 'resolved_path': str(resolved),
                        'sha256': regular_digest(resolved), 'version': version}
    return result


def dependency_receipt(source, compiler, captured):
    policy = NODE.PREP.RELAY.HY2_DEADLINES
    policy.verify(source, compiler, captured)
    result = {}
    for module in policy.MODULES:
        directory = source / module['copy']
        records = {path.relative_to(directory).as_posix(): regular_digest(path)
                   for path in sorted(directory.rglob('*')) if path.is_file()}
        result[module['module']] = {'version': module['version'], 'upstream_sum': module['sum'],
                                   'prepared_files': records}
    return result


def execute(source, pq, cache, go='go', *, env=None, receipt_path=None):
    if receipt_path is not None:
        receipt_path = Path(receipt_path).absolute()
        if receipt_path.exists() or receipt_path.is_symlink() or not receipt_path.parent.is_dir():
            raise ValueError('Complete MAX receipt must use a new owned output file')
    source, before = checked_sources(Path(source))
    compiler, captured, architecture = NODE.selected_compiler(go, source, dict(os.environ if env is None else env))
    target = captured['GOOS'] + '/' + architecture
    pq, cache = Path(pq).absolute(), Path(cache).absolute()
    native = REFERENCE.BUILD.PQ.verify(pq, target)
    if captured.get('CGO_ENABLED', '1') != '1':
        raise ValueError('Complete MAX requires the real compiled Rust/C ABI')
    captured['CGO_ENABLED'] = '1'
    flags = ['-static'] if target.startswith('windows/') else []
    captured['CGO_LDFLAGS'] = shlex.join([*flags, '-L' + str(pq), *native['native_static_libs']])
    race = [] if target == 'windows/arm64' else ['-race']
    tools = tool_receipts(source, compiler, captured, target, cache)
    dependencies = dependency_receipt(source, compiler, captured)
    status, output = NODE.run([compiler, 'mod', 'verify'], cwd=source, env=captured, timeout=300)
    if status:
        raise ValueError('Complete MAX dependencies failed checksum verification:\n' + output[-8192:])
    packet = REFERENCE.BUILD.POLICY.AMNEZIA
    status, output = NODE.run([compiler, 'list', '-m', '-mod=readonly', '-json', packet.MODULE], cwd=source, env=captured, timeout=60)
    dependency = json.loads(output) if status == 0 else {}
    if dependency.get('Version') != packet.VERSION or dependency.get('Sum') != packet.SUM or dependency.get('Replace'):
        raise ValueError('Complete MAX requires its exact unmodified packet-crypto dependency')
    with tempfile.TemporaryDirectory(prefix='routervpn-node-max-') as directory:
        workspace = Path(directory)
        keys = workspace / 'private' / 'keys'
        REFERENCE.generate_keys(target, cache, keys)
        original_keys = REFERENCE.key_files(keys)
        key_generator = cache / REFERENCE.BUILD.PQ.TARGETS[target] / 'release/examples' / ('native_keys.exe' if target.startswith('windows/') else 'native_keys')
        generator_digest = regular_digest(key_generator)
        captured['ROUTERVPN_PQ_TEST_KEYS'] = str(keys)
        relay, relay_digest = NODE.build_layer_reference(compiler, workspace, captured, race)
        xray, xray_digest, xray_source, xray_records = NODE.build_xray_reference(compiler, source, workspace, captured, race)
        build = [compiler, 'test', '-c', '-p=1', '-mod=readonly', '-tags=' + REFERENCE.TAGS,
                 *race, '-ldflags=-checklinkname=0']
        suffix = '.exe' if target.startswith('windows/') else ''
        binary = workspace / ('node-max.test' + suffix)
        with REFERENCE.test_sources(source):
            status, output = NODE.run([*build, '-o', binary, './protocol/routervpnpq'], cwd=source, env=captured, timeout=600)
            if status:
                raise ValueError('Complete MAX native compilation failed:\n' + output[-32768:])
            digest = regular_digest(binary)
            status, output = NODE.run([binary, '-test.run=^Test(RealPinnedFactory|RealFactory|RealPQTraffic|RouterVPNDesktopNodeMAXTLSStartupRecords)',
                                      '-test.v', '-test.count=1', '-test.timeout=120s'], cwd=source, env=captured, timeout=135)
            print(output, end='' if output.endswith('\n') else '\n', flush=True)
            for parent in PQ.NATIVE_CASES:
                required_output(status, output, parent, ('v2', 'v3') if parent == 'TestRealPinnedFactoryExchangeAndRekey' else ())
            required_output(status, output, STARTUP_RECORDS, ())
            for family in FAMILIES:
                for credentials, cases, duration in ((False, TRAFFIC[family], 600), (True, CREDENTIALS[family], 1800)):
                    parent = 'TestRouterVPNDesktopNodeCompleteMAX' + family + ('Credentials' if credentials else '')
                    # Bound the complete matrix, keeping the original native
                    # constructor, handshake, query and retirement deadlines.
                    status, output = NODE.run([binary, '-test.run=^' + parent + '$', '-test.v', '-test.count=1',
                                              '-test.timeout=' + str(duration) + 's'], cwd=source, env=captured, timeout=duration + 15)
                    print(output, end='' if output.endswith('\n') else '\n', flush=True)
                    required_output(status, output, parent, cases)
                    if regular_digest(binary) != digest:
                        raise ValueError('Complete MAX executable changed during execution')
            controls = compiled_controls(source, workspace, build, captured, suffix)
            if regular_digest(relay) != relay_digest or regular_digest(xray) != xray_digest or \
                    NODE.xray_reference_sources(xray_source) != xray_records or \
                    REFERENCE.key_files(keys) != original_keys or regular_digest(key_generator) != generator_digest:
                raise ValueError('Complete MAX reference executable, source or private keys changed')
        if REFERENCE.BUILD.PQ.verify(pq, target) != native or checked_sources(source)[1] != before or \
                tool_receipts(source, compiler, captured, target, cache) != tools or \
                dependency_receipt(source, compiler, captured) != dependencies:
            raise ValueError('Complete MAX captured source, archive or tool identity changed')
        result = {'schema': 1, 'target': target, 'source': before, 'native_pq': native,
                  'tools': tools, 'prepared_quic_dependencies': dependencies,
                  'test_binary_sha256': digest, 'relay_sha256': relay_digest,
                  'xray_sha256': xray_digest, 'xray_pin': NODE.PREP.RELAY.XRAY.XRAY_PIN, 'xray_source': xray_records,
                  'key_generator_sha256': generator_digest, 'fresh_independent_keypairs': 3,
                  'traffic_cases': TRAFFIC, 'credential_cases': CREDENTIALS,
                  'native_abi_cases': PQ.NATIVE_CASES, 'compiled_negative_controls': controls,
                  'startup_record_case': STARTUP_RECORDS,
                  'os_permits': 'modeled', 'tun': 'modeled', 'public_graph_admission': 'separate'}
    if workspace.exists():
        raise ValueError('Complete MAX retained its disposable private workspace')
    # Publication follows joined test-source cleanup and private-key removal.
    # A cleanup failure cannot leave a successful final receipt behind.
    result['private_key_workspace_removed'] = True
    if receipt_path is not None:
        with receipt_path.open('x', encoding='utf-8') as output:
            json.dump(result, output, sort_keys=True, indent=2)
            output.write('\n')
    print('All four complete MAX families, 12 Start Layer paths, 48 credential cases, real KEM/rekey, selected DNS and compiled controls passed; OS permits/TUN and public admission remain separate.', flush=True)
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('pq', type=Path)
    parser.add_argument('--cache', type=Path, default=ROOT / 'dist/.native-pq-cache')
    parser.add_argument('--go', default='go')
    parser.add_argument('--receipt', type=Path)
    arguments = parser.parse_args()
    execute(arguments.source, arguments.pq, arguments.cache, arguments.go, receipt_path=arguments.receipt)
