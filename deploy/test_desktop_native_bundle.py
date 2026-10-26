#!/usr/bin/env python3
"""Reject altered, foreign and incomplete payloads using a real built engine."""
from pathlib import Path
import argparse
import copy
import importlib.util
import json
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('native_runtime_test', ROOT/'deploy/build-native-runtime.py')
BUILD = importlib.util.module_from_spec(spec)
spec.loader.exec_module(BUILD)


NATIVE_CAPTURE_SELECTOR = '^Test(NativeMultihop|NativeServerGraph)'
NATIVE_GRAPH_NAMES = (
    'TestNativeMultihopCapturedBaseLocalServerAndExactNativeCompiler',
    'TestNativeMultihopRetainedGraphFinalizesServerAndOnlyRestoresSystemMTU',
)
NATIVE_TRAFFIC_NAMES = (
    'TestNativeMultihopWGNaiveEncryptedLoopback',
    'TestNativeMultihopWGWireGuardEncryptedLoopback',
)


def native_capture_groups(discovered):
    """Partition every actual target test from the previous aggregate exactly once."""
    names = [line.strip() for line in discovered.splitlines()
             if line.startswith('Test')]
    if not names or len(names) != len(set(names)) or any(
            re.fullmatch(r'[A-Za-z0-9_]+', name) is None or
            re.match(NATIVE_CAPTURE_SELECTOR, name) is None for name in names):
        raise RuntimeError('Native capture test discovery is empty or ambiguous')
    required = set(NATIVE_GRAPH_NAMES + NATIVE_TRAFFIC_NAMES)
    if not required.issubset(names):
        raise RuntimeError('Native graph or encrypted-traffic coverage disappeared')
    exact = lambda selected: '^(' + '|'.join(re.escape(name) for name in selected) + ')$'
    groups = (
        ('captured graph/parser matrix', exact(NATIVE_GRAPH_NAMES), None),
        ('policy, source, proof and restoration ownership', NATIVE_CAPTURE_SELECTOR,
         exact(NATIVE_GRAPH_NAMES + NATIVE_TRAFFIC_NAMES)),
        ('encrypted WG/Naive and WG/WG paths', exact(NATIVE_TRAFFIC_NAMES), None),
    )
    counts = {name: 0 for name in names}
    for _, include, exclude in groups:
        selected = [name for name in names if re.match(include, name) and
                    (exclude is None or not re.match(exclude, name))]
        if not selected:
            raise RuntimeError('Native capture partition selected no actual tests')
        for name in selected:
            counts[name] += 1
    if any(count != 1 for count in counts.values()):
        raise RuntimeError('Native capture partition omitted or duplicated an actual test')
    return groups, len(names)


def test(bundle, target):
    bundle = Path(bundle)
    BUILD.reuse(bundle, target)
    with tempfile.TemporaryDirectory(prefix='routervpn-native-relocation-') as temporary:
        moved = Path(temporary)/'relocated app'/'runtime'/'native'
        shutil.copytree(bundle, moved)
        receipt = moved/'NATIVE-RUNTIME.json'
        original = receipt.read_bytes()
        expected = json.loads(original)
        BUILD.reuse(moved, target)
        engine = moved/BUILD.binary_name(target)
        output = subprocess.check_output([str(engine), 'version'], text=True, timeout=20)
        assert output.startswith('sing-box version '+BUILD.marker(BUILD.digest())+'\n')
        checks = 2

        def rejected(label):
            nonlocal checks
            try:
                BUILD.reuse(moved, target)
            except (ValueError, OSError, subprocess.CalledProcessError):
                checks += 1
                return
            raise AssertionError('accepted altered native bundle: '+label)

        for key, value in [('schema_version', 2), ('runtime', 'sing-box'), ('target', 'linux/riscv64'),
                           ('toolchain', 'go1.23.0'), ('rust_toolchain', '1.88.0'), ('native_pq_abi', 0),
                           ('upstream_revision', '0'*40), ('xray_revision', '0'*40),
                           ('amnezia_version', 'v0.0.0'), ('amnezia_sum', 'h1:changed'),
                           ('rosenpass_revision', '0'*40), ('policy_sha256', '0'*64),
                           ('sha256', '0'*64), ('size', expected['size']+1)]:
            changed = copy.deepcopy(expected)
            changed[key] = value
            receipt.write_text(json.dumps(changed))
            rejected(key)
            receipt.write_bytes(original)
        receipt.write_bytes(b'{"schema_version":1,'+original.lstrip()[1:])
        rejected('duplicate key')
        receipt.write_bytes(original)
        extra = moved/'ambient-engine'
        extra.write_bytes(b'unowned')
        rejected('unowned extra payload')
        extra.unlink()
        for name in BUILD.expected_names(target):
            path = moved/name
            saved = path.read_bytes()
            path.write_bytes(saved[:-1]+bytes([saved[-1]^1]))
            rejected('changed '+name)
            path.write_bytes(saved)
        license_path = moved/'XRAY-LICENSE'
        saved = license_path.read_bytes()
        license_path.unlink()
        rejected('missing Xray license')
        license_path.write_bytes(saved)
        BUILD.reuse(moved, target)
        checks += 1
        print(f'{checks} complete native runtime receipt/relocation checks passed for {target}', flush=True)
        # These captured graphs retain both nodes' DNS, cover, authenticated
        # Start Layers and exact WG/AWG parameters. Only the complete shipping
        # runtime owns those registrations; the AWG diagnostic CLI does not.
        env = BUILD.environment(target, compiler=True)
        env['ROUTERVPN_VIA_ENTRY_NATIVE_CLI'] = str(engine)
        # Go1.26.3 src/internal/platform/supported.go supports the race
        # detector on all six shipping targets except Windows ARM64. `dist
        # list` has no -race flag; an unrelated compiler failure must not be
        # caught and silently retried without race instrumentation.
        race = [] if target == 'windows/arm64' else ['-race']
        # The old aggregate includes multiple real encrypted network matrices
        # plus hundreds of complete-parser invocations. Give each coherent
        # phase its original bounded budget; do not stretch an individual
        # handshake/assertion or silently omit platform-only ACL negatives.
        discovered = subprocess.check_output(
            ['go', 'test', *race, './cmd/client', '-list', NATIVE_CAPTURE_SELECTOR],
            cwd=ROOT, env=env, text=True, timeout=300)
        groups, total = native_capture_groups(discovered)
        for label, include, exclude in groups:
            command = ['go', 'test', *race, '-count=1', '-timeout=180s',
                       './cmd/client', '-run', include]
            if exclude is not None:
                command += ['-skip', exclude]
            subprocess.run(command, cwd=ROOT, env=env, check=True, timeout=300)
            print('Complete native runtime passed ' + label, flush=True)
        print(f'All {total} original native capture/ownership/traffic tests executed exactly once with unchanged per-test assertions', flush=True)
        # Every additional entry preserves its full engine/DNS/cover closure
        # through the same shipping capture and Server transformation. Keep
        # this new matrix bounded independently of the established groups.
        subprocess.run(['go', 'test', *race, '-count=1', '-timeout=240s',
                        './cmd/client', '-run', '^TestNativeEntryMultihop'],
                       cwd=ROOT, env=env, check=True, timeout=360)
        print('Complete native runtime passed exact 19-mode entry capture/parser and retained-owner checks, plus SS/HY2/Naive encrypted Local/Server TCP and UDP', flush=True)
        # Complete MAX retains mandatory PQ, SS2022 and outer owners. Its host
        # capture/Server substitution and retained identity checks form a new
        # bounded phase; the established native phases keep their old budgets.
        subprocess.run(['go', 'test', *race, '-count=1', '-timeout=180s',
                        './cmd/client', '-run', '^TestNativeMAXDesktop(Capture|Rejects|Independent|ServerMoves)'],
                       cwd=ROOT, env=env, check=True, timeout=240)
        print('Complete native runtime passed complete-MAX capture/parser, Server closure and paired-identity restoration checks', flush=True)
        # The production AWG endpoint deliberately accepts only client peers.
        # Build a separate test-only cryptographic server; never widen that
        # production boundary or add the helper to the sealed runtime payload.
        # Build may reuse a cache and removes its disposable core, so this gate
        # owns a fresh exact-pinned checkout and prepares the shared AWG sources
        # on every invocation. No stale helper can silently satisfy the gate.
        core = Path(temporary)/'reference-core'
        BUILD.checkout(core, 'https://github.com/SagerNet/sing-box.git', BUILD.PIN)
        subprocess.run([sys.executable, str(ROOT/'deploy/prepare-mobile-amnezia.py'), str(core)],
                       cwd=ROOT, env=env, check=True, timeout=300)
        subprocess.run(['go', 'mod', 'tidy'], cwd=core, env=env, check=True, timeout=300)
        subprocess.run([sys.executable, str(ROOT/'deploy/prepare-mobile-amnezia.py'),
                        '--verify-dependency', str(core)], cwd=ROOT, env=env, check=True, timeout=60)
        reference = Path(temporary)/('awg-reference.exe' if target.startswith('windows/') else 'awg-reference')
        subprocess.run([sys.executable, str(ROOT/'deploy/build_awg_reference_fixture.py'),
                        '--core', str(core), '--output', str(reference), *(['--race'] if race else [])],
                       cwd=ROOT, env=env, check=True, timeout=660)
        subprocess.run([str(reference), '-test.run', '^TestDesktopAWGReference', '-test.count=1',
                        '-test.timeout=45s'], cwd=ROOT, env=env, check=True, timeout=60)
        env['ROUTERVPN_AWG_REFERENCE_CLI'] = str(reference)
        subprocess.run(['go', 'test', *race, '-count=1', '-timeout=180s', './cmd/client',
                        '-run', '^TestNativeAmneziaMultihopEncryptedLoopback$'],
                       cwd=ROOT, env=env, check=True, timeout=240)
        print('Complete native runtime passed actual AWG Fast/Strong Local and Server encrypted traffic with independent reference peers', flush=True)
        # Composite exits own independent authenticated TCP and UDP lanes. Feed
        # fresh reference-node assets through the actual desktop capture and
        # Server lease compiler, then execute those graphs with this sealed
        # engine. Keep this mandatory matrix separate from the existing bounded
        # native and AWG groups; none may silently skip a missing helper.
        xray = Path(temporary)/'reference-xray'
        BUILD.checkout(xray, 'https://github.com/XTLS/Xray-core.git', BUILD.POLICY.XRAY.XRAY_PIN)
        subprocess.run([sys.executable, str(ROOT/'deploy/prepare-relay-core.py'), str(core), str(xray)],
                       cwd=ROOT, env=env, check=True, timeout=300)
        subprocess.run(['go', 'mod', 'tidy'], cwd=core, env=env, check=True, timeout=300)
        suffix = '.exe' if target.startswith('windows/') else ''
        composite_reference = Path(temporary)/('composite-reference'+suffix)
        xray_reference = Path(temporary)/('xray-reference'+suffix)
        subprocess.run([sys.executable, str(ROOT/'deploy/build_composite_reference_fixture.py'),
                        '--core', str(core), '--output', str(composite_reference),
                        '--xray-output', str(xray_reference), *(['--race'] if race else [])],
                       cwd=ROOT, env=env, check=True, timeout=1260)
        subprocess.run([str(composite_reference), '-test.run', '^TestDesktopCompositeReferenceRejectsEscapedInputs$',
                        '-test.count=1', '-test.timeout=30s'], cwd=ROOT, env=env, check=True, timeout=45)
        env['ROUTERVPN_COMPOSITE_REFERENCE_CLI'] = str(composite_reference)
        env['ROUTER_VPN_XRAY_TEST_BINARY'] = str(xray_reference)
        subprocess.run(['go', 'test', *race, '-count=1', '-timeout=180s', './cmd/client',
                        '-run', '^TestNativeCompositeDesktopEncryptedLoopback$'],
                       cwd=ROOT, env=env, check=True, timeout=240)
        print('Complete native runtime passed SS-V2Ray, Split and MAX Local and Server encrypted TCP/UDP through captured WG/AWG entry graphs', flush=True)
        # PQ exits require two independently pinned identities and genuine
        # Rosenpass negotiation before packet traffic. Build the test peer with
        # the exact production Rust/C ABI, generate fresh disposable keys, and
        # keep this mandatory matrix separate from the existing bounded groups.
        # The helper, keys and link input never enter the sealed payload.
        pq = Path(temporary)/'reference-pq'
        pq_cache = ROOT/'dist/.native-pq-cache'
        BUILD.PQ.build(target, pq, pq_cache)
        pq_reference = Path(temporary)/('pq-reference'+suffix)
        pq_keys = Path(temporary)/'pq-private'/'keys'
        subprocess.run([sys.executable, str(ROOT/'deploy/build_pq_reference_fixture.py'),
                        '--core', str(core), '--pq', str(pq), '--keys', str(pq_keys),
                        '--output', str(pq_reference), '--target', target, '--cache', str(pq_cache),
                        *(['--race'] if race else [])],
                       cwd=ROOT, env=env, check=True, timeout=2520)
        env['ROUTERVPN_PQ_REFERENCE_CLI'] = str(pq_reference)
        env['ROUTERVPN_PQ_TEST_KEYS'] = str(pq_keys)
        subprocess.run(['go', 'test', *race, '-count=1', '-timeout=180s', './cmd/client',
                        '-run', '^TestNativePQDesktopEncryptedLoopback$'],
                       cwd=ROOT, env=env, check=True, timeout=240)
        print('Complete native runtime passed genuine PQ-keyed WG/AWG Local and Server encrypted traffic, independent identity pins and rekey checks', flush=True)
        # The TLS reference is the same exact-pinned Xray already built above.
        # Prove its real encrypted UDP and precise rejection witnesses before
        # trusting it to observe the complete captured MAX chain. Each packet
        # family/execution has a separate bounded phase; WG Local also exercises
        # wrong outer/middle/private-route/KEM credentials and exact restore.
        subprocess.run(['go', 'test', *race, '-count=1', '-timeout=45s', './cmd/client',
                        '-run', '^TestNativeMAXTLSReference'],
                       cwd=ROOT, env=env, check=True, timeout=90)
        for family in ('tls', 'quic'):
            for base in ('wg', 'awg'):
                mode = 'max-' + family + '-' + base
                for execution in ('local', 'server'):
                    subprocess.run(['go', 'test', *race, '-count=1', '-timeout=180s', './cmd/client',
                                    '-run', '^TestNativeMAXDesktopEncryptedLoopback$/^' + family + '$/^' + mode + '$/^' + execution + '$'],
                                   cwd=ROOT, env=env, check=True, timeout=240)
        print('Complete native runtime passed genuine complete-MAX TLS/QUIC Local/Server TCP/UDP, paired-key rekey and witnessed rejection/restoration', flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('bundle', type=Path)
    parser.add_argument('target', choices=BUILD.TARGETS)
    args = parser.parse_args()
    test(args.bundle, args.target)
