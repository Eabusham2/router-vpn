#!/usr/bin/env python3
"""Reject altered, foreign and incomplete payloads using a real built engine."""
from pathlib import Path
import argparse
import copy
import importlib.util
import json
import shutil
import subprocess
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


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('bundle', type=Path)
    parser.add_argument('target', choices=BUILD.TARGETS)
    args = parser.parse_args()
    test(args.bundle, args.target)
