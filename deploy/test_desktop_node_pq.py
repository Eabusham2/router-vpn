#!/usr/bin/env python3
"""Run real WG-PQ/AWG-PQ Node graphs against the exact pinned native ABI.

The source, native archive, compiler, disposable KEM keys and whitening relay
are captured before execution and checked again afterwards. Only OS permits
and TUN remain explicit fixtures. This prerequisite does not open public graph
admission or establish native firewall, installation or device acceptance.
"""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import os
import shlex
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'deploy' / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


NODE = load('node_pq_composition', 'test_desktop_node_physical.py')
REFERENCE = load('node_pq_reference', 'build_pq_reference_fixture.py')
MODES = ('wg-pq', 'awg2-pq')
LAYERS = ('off', 'aes-256-gcm', 'aes-256-gcm+xor-whitening')
TRAFFIC = tuple(mode + '/' + layer for mode in MODES for layer in LAYERS)
CREDENTIALS = tuple(case + '/' + fault for case in TRAFFIC
                    for fault in ('kem-peer', 'packet-peer', *(() if case.endswith('/off') else ('aes-key',))))
NATIVE_CASES = (
    'TestRealPinnedFactoryExchangeAndRekey', 'TestRealPinnedFactoryRejectsWrongPeer',
    'TestRealFactoryNeverRetainsCallerKeyBuffers', 'TestRealPQTrafficNegotiatedKeysAndRekey',
    'TestRealPQTrafficWrongPeerCannotStartOrFallback', 'TestRealPQTrafficChangedReferenceKeyRejectsData',
    'TestRealPQTrafficInitialBarrierHonorsCancellation',
)


def regular_digest(path):
    if path.is_symlink() or not path.is_file():
        raise ValueError('PQ Node lost its captured regular file: ' + str(path))
    return hashlib.sha256(path.read_bytes()).hexdigest()


def checked_sources(source):
    source, records = NODE.checked_sources(source)
    if REFERENCE.verify_sources(source) != source:
        raise ValueError('PQ Node source identity changed during capture')
    for relative in ('mobile/desktop/node_pq_peer_test.go.tmpl', 'mobile/amnezia/pq_reference_fixture.go.tmpl',
                     'deploy/build_pq_reference_fixture.py', 'deploy/build-desktop-pq.py', 'deploy/test_server_pq_traffic.py',
                     'deploy/test_desktop_node_pq.py', 'mobile/rosenpass/examples/native_keys.rs', *REFERENCE.COPIES):
        records['pq-source/' + relative] = regular_digest(ROOT / relative)
    for relative in REFERENCE.SERVER.COPIES:
        records['pq-source/' + relative] = regular_digest(ROOT / relative)
    for path in sorted((ROOT / 'mobile/pq').glob('*.go.tmpl')):
        records['pq-source/' + path.relative_to(ROOT).as_posix()] = regular_digest(path)
    return source, records


def required_output(output, test, cases):
    if any(value in output for value in ('--- SKIP:', 'DATA RACE', 'panic: test timed out')) or \
            '--- PASS: ' + test + ' (' not in output or \
            any('--- PASS: ' + test + '/' + case + ' (' not in output for case in cases):
        raise ValueError('PQ Node omitted a real captured mode, Start Layer or credential case')


def mutations(source):
    def changed(relative, before, after):
        return NODE.BOOT.IDENTITY.replace_once((source / relative).read_text(encoding='utf-8'), before, after)

    endpoint = 'protocol/routervpnpq/endpoint.go'
    owner = 'experimental/libbox/routervpn/mobilepq/peer.go'
    dns = 'routervpn_strategy_dns.go'
    production = (
        ('uncaptured-kem-dial', endpoint, 'PQ Node omitted a captured KEM/packet lane, bypassed admission or leaked plaintext',
         changed(endpoint, 'return d.DialContext(call, N.NetworkUDP, destination)',
                 '_ = d; return (&net.Dialer{}).DialContext(call, N.NetworkUDP, destination.String())')),
        ('substituted-kem-port', endpoint, 'actual PQ Node did not finish authenticated startup',
         changed(endpoint, 'destination := M.ParseSocksaddr(runtime.PQ.Endpoint)',
                 'destination := M.SocksaddrFrom(netip.MustParseAddr(options.Peers[0].Address), uint16(options.Peers[0].Port))')),
        # Without SetPQKey the real device still reports the zero PSK. Its
        # strict native readback rejects that before comparing key digests.
        ('dropped-negotiated-psk', owner, 'invalid or ambiguous native test peer readback',
         changed(owner, 'return p.peer.SetPQKey(p.public[:], key)', 'return nil')),
        ('substituted-packet-identity', owner, 'actual PQ Node startup',
         changed(owner, 'return p.peer.SetPQKey(p.public[:], key)', 'return p.peer.SetPQKey(make([]byte, 32), key)')),
        ('cached-selected-dns', dns, 'PQ Node reused cached DNS success or bypassed its selected resolver',
         changed(dns, 'DisableCache: true, DisableOptimisticCache: true, Timeout: 5 * time.Second,',
                 'DisableCache: false, DisableOptimisticCache: false, Timeout: 5 * time.Second,')),
    )
    traffic = 'TestRouterVPNDesktopNodePQTraffic'
    result = tuple((name, relative, traffic, '^' + traffic + '$/^wg-pq$/^off$', witness, replacement)
                   for name, relative, witness, replacement in production)
    peer = 'protocol/routervpnpq/node_pq_peer_test.go'
    credentials = 'TestRouterVPNDesktopNodePQCredentials'
    # These three compiled fixture controls prove that a successful real peer
    # cannot satisfy a wrong-credential case through early cancellation.
    for name, suffix, witness, before, after in (
        ('valid-kem-peer-control', 'off$/^kem-peer', 'PQ Node accepted untrusted KEM or Start Layer credentials',
         'peerName := "server"\n\tif fault == "kem-peer" {', 'peerName := "server"\n\tif false && fault == "kem-peer" {'),
        ('valid-packet-peer-control', 'off$/^packet-peer', 'PQ Node accepted the wrong captured packet peer after KEM authentication',
         'packetPublic := f.reference.Public\n\tif fault == "packet-peer" {', 'packetPublic := f.reference.Public\n\tif false && fault == "packet-peer" {'),
        ('valid-aes-key-control', 'aes-256-gcm$/^aes-key', 'PQ Node accepted untrusted KEM or Start Layer credentials',
         'if fault == "aes-key" {', 'if false && fault == "aes-key" {'),
    ):
        result += ((name, peer, credentials, '^' + credentials + '$/^wg-pq$/^' + suffix + '$', witness,
                    changed(peer, before, after)),)
    return result


def execute(source, pq, cache, go='go', *, env=None, receipt_path=None):
    source, before = checked_sources(Path(source))
    compiler, captured, architecture = NODE.selected_compiler(go, source, dict(os.environ if env is None else env))
    target = captured['GOOS'] + '/' + architecture
    pq, cache = Path(pq).absolute(), Path(cache).absolute()
    native = REFERENCE.BUILD.PQ.verify(pq, target)
    if captured.get('CGO_ENABLED', '1') != '1':
        raise ValueError('PQ Node requires the real compiled Rust/C ABI')
    captured['CGO_ENABLED'] = '1'
    flags = ['-static'] if target.startswith('windows/') else []
    captured['CGO_LDFLAGS'] = shlex.join([*flags, '-L' + str(pq), *native['native_static_libs']])
    race = [] if target == 'windows/arm64' else ['-race']
    status, output = NODE.run([compiler, 'mod', 'verify'], cwd=source, env=captured, timeout=300)
    if status:
        raise ValueError('PQ Node dependencies failed checksum verification:\n' + output[-8192:])
    packet = REFERENCE.BUILD.POLICY.AMNEZIA
    status, output = NODE.run([compiler, 'list', '-m', '-mod=readonly', '-json', packet.MODULE], cwd=source, env=captured, timeout=60)
    dependency = json.loads(output) if status == 0 else {}
    if dependency.get('Version') != packet.VERSION or dependency.get('Sum') != packet.SUM or dependency.get('Replace'):
        raise ValueError('PQ Node requires the exact unmodified packet-crypto dependency')
    if receipt_path is not None:
        receipt_path = Path(receipt_path).absolute()
        if receipt_path.exists() or receipt_path.is_symlink() or not receipt_path.parent.is_dir():
            raise ValueError('PQ Node receipt must use a new owned output file')
    with tempfile.TemporaryDirectory(prefix='routervpn-node-pq-') as directory:
        workspace = Path(directory)
        keys = workspace / 'private' / 'keys'
        # Reuse only the compiler cache. Every gate creates independent actual
        # KEM keypairs, and the existing generator proves no-reuse ownership.
        REFERENCE.generate_keys(target, cache, keys)
        original_keys = REFERENCE.key_files(keys)
        captured['ROUTERVPN_PQ_TEST_KEYS'] = str(keys)
        relay, relay_digest = NODE.build_layer_reference(compiler, workspace, captured, race)
        build = [compiler, 'test', '-c', '-p=1', '-mod=readonly', '-tags=' + REFERENCE.TAGS,
                 *race, '-ldflags=-checklinkname=0']
        suffix = '.exe' if target.startswith('windows/') else ''
        binary = workspace / ('node-pq.test' + suffix)
        with REFERENCE.test_sources(source):
            status, output = NODE.run([*build, '-o', binary, './protocol/routervpnpq'], cwd=source, env=captured, timeout=600)
            if status:
                raise ValueError('PQ Node exact native compilation failed:\n' + output[-32768:])
            digest = regular_digest(binary)
            status, output = NODE.run([binary, '-test.run=^Test(RealPinnedFactory|RealFactory|RealPQTraffic)',
                                      '-test.v', '-test.count=1', '-test.timeout=120s'], cwd=source, env=captured, timeout=135)
            print(output, end='' if output.endswith('\n') else '\n', flush=True)
            if status:
                raise ValueError('PQ Node native ABI and reference isolation failed')
            for test in NATIVE_CASES:
                required_output(output, test, ())
            required_output(output, 'TestRealPinnedFactoryExchangeAndRekey', ('v2', 'v3'))
            for test, cases in (('TestRouterVPNDesktopNodePQTraffic', TRAFFIC), ('TestRouterVPNDesktopNodePQCredentials', CREDENTIALS)):
                # Full PQ public assets are deliberately revalidated by each
                # original compiler/Box constructor. Keep per-network startup
                # and query deadlines unchanged; allow this whole real matrix.
                status, output = NODE.run([binary, '-test.run=^' + test + '$', '-test.v', '-test.count=1', '-test.timeout=600s'],
                                          cwd=source, env=captured, timeout=615)
                print(output, end='' if output.endswith('\n') else '\n', flush=True)
                if status:
                    raise ValueError('PQ Node actual encrypted graph failed')
                required_output(output, test, cases)
                if regular_digest(binary) != digest:
                    raise ValueError('PQ Node executable changed during actual execution')
            controls = []
            for name, relative, parent, selector, witness, replacement in mutations(source):
                changed = workspace / (name + '.go')
                changed.write_text(replacement, encoding='utf-8')
                overlay = workspace / (name + '.json')
                overlay.write_text(json.dumps({'Replace': {str(source / relative): str(changed)}}), encoding='utf-8')
                mutant = workspace / (name + '.test' + suffix)
                status, output = NODE.run([*build, '-overlay=' + str(overlay), '-o', mutant, './protocol/routervpnpq'],
                                          cwd=source, env=captured, timeout=600)
                if status:
                    raise ValueError('PQ Node negative failed to compile: ' + name + '\n' + output[-16384:])
                status, output = NODE.run([mutant, '-test.run=' + selector,
                                          '-test.v', '-test.count=1', '-test.timeout=90s'], cwd=source, env=captured, timeout=105)
                if status == 0 or '--- FAIL: ' + parent + ' (' not in output or witness not in output or \
                        any(value in output for value in ('--- SKIP:', 'DATA RACE', 'panic: test timed out')):
                    raise ValueError('PQ Node negative missed its real production defect: ' + name + '\n' + output[-16384:])
                controls.append(name)
                print('Rejected compiled real PQ Node control: ' + name, flush=True)
            if regular_digest(relay) != relay_digest or REFERENCE.key_files(keys) != original_keys:
                raise ValueError('PQ Node reference source or captured key workspace changed')
        if REFERENCE.BUILD.PQ.verify(pq, target) != native or checked_sources(source)[1] != before:
            raise ValueError('PQ Node native library or prepared source changed during execution')
        result = {'schema': 1, 'target': target, 'source': before, 'native_pq': native,
                  'test_binary_sha256': digest, 'relay_sha256': relay_digest, 'traffic_cases': TRAFFIC,
                  'credential_cases': CREDENTIALS, 'native_abi_cases': NATIVE_CASES, 'compiled_negative_controls': controls,
                  'os_permits': 'modeled', 'tun': 'modeled', 'public_graph_admission': 'separate'}
        if receipt_path is not None:
            with receipt_path.open('x', encoding='utf-8') as output:
                json.dump(result, output, sort_keys=True, indent=2)
                output.write('\n')
    print('Real WG-PQ/AWG-PQ Node KEM, packet encryption, rekey, selected Home DNS, AES/XOR and retirement passed; OS permits/TUN and public graph admission remain separate.', flush=True)
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
