#!/usr/bin/env python3
"""Reject altered, foreign and incomplete payloads using a real built engine."""
from pathlib import Path
import argparse
import copy
import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('native_runtime_test', ROOT/'deploy/build-native-runtime.py')
BUILD = importlib.util.module_from_spec(spec)
spec.loader.exec_module(BUILD)


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
        subprocess.run(['go', 'test', *race, '-count=1', '-timeout=180s',
                        './cmd/client', '-run', '^Test(NativeMultihop|NativeServerGraph)'],
                       cwd=ROOT, env=env, check=True, timeout=300)
        print('Complete native runtime accepted captured WG/AWG Local and Server graphs with exact layers, DNS and cover; stale proof/source regressions passed', flush=True)
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


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('bundle', type=Path)
    parser.add_argument('target', choices=BUILD.TARGETS)
    args = parser.parse_args()
    test(args.bundle, args.target)
