#!/usr/bin/env python3
"""Verify the Windows packet-only overlay against the actual pinned source."""
from pathlib import Path
import argparse
import copy
import importlib.util
import json
import subprocess
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('packet_overlay', ROOT/'deploy/prepare-desktop-rosenpass.py')
P = importlib.util.module_from_spec(spec)
spec.loader.exec_module(P)


def reject(call):
    try:
        call()
    except (ValueError, FileNotFoundError):
        return
    raise AssertionError('mutated packet-only source or dependency was accepted')


def run(source):
    count = 0
    with tempfile.TemporaryDirectory(prefix='routervpn-packet-source-test-') as temp:
        root = Path(temp)
        manifest = P.prepare(source, root/'first')
        receipt = json.loads((root/'first/PACKET-PROTOCOL.json').read_text())
        assert set(receipt['changes']) == set(P.FILES)
        for name in receipt['upstream_files']:
            if name in P.FILES or name in P.DOCUMENT_LINKS:
                continue
            assert (root/'first/upstream'/name).read_bytes() == (source/name).read_bytes(), name
            count += 1
        # These actual protocol/crypto/allocator trees must not be patched.
        for prefix in ('rosenpass/src/protocol/', 'rosenpass/src/msgs', 'rosenpass/src/hash_domains',
                       'ciphers/', 'cipher-traits/', 'oqs/', 'secret-memory/', 'constant-time/'):
            assert any(name.startswith(prefix) for name in receipt['upstream_files'])
            assert not any(name.startswith(prefix) for name in receipt['changes'])
            count += 1
        for path in (ROOT/'mobile/rosenpass/src').rglob('*.rs'):
            assert (manifest.parent/'src'/path.relative_to(ROOT/'mobile/rosenpass/src')).read_bytes() == path.read_bytes()
            count += 1
        before = (ROOT/'mobile/rosenpass/Cargo.lock').read_bytes()
        subprocess.run(['cargo', 'metadata', '--offline', '--format-version=1', '--manifest-path', manifest],
                       check=True, stdout=subprocess.DEVNULL, timeout=120)
        after = manifest.with_name('Cargo.lock').read_bytes()
        P.verify_lock(before, after)
        count += 1
        # Mutate parsed records through the same validator without relying on
        # formatting changes to accidentally invalidate TOML.
        original_loads = P.tomllib.loads
        parsed = original_loads(after.decode())
        for mutation in ('version', 'registry-checksum', 'missing-crypto', 'new-dependency'):
            changed = copy.deepcopy(parsed)
            if mutation == 'version':
                next(p for p in changed['package'] if p['name'] == 'rosenpass')['version'] = '9.0.0'
            elif mutation == 'registry-checksum':
                next(p for p in changed['package'] if p.get('checksum'))['checksum'] = '0'*64
            elif mutation == 'missing-crypto':
                changed['package'] = [p for p in changed['package'] if p['name'] != 'rosenpass-ciphers']
            else:
                changed['package'].append({'name': 'unowned-crypto', 'version': '1.0.0'})
            P.tomllib.loads = lambda value, changed=changed: changed if value == 'mutant' else original_loads(value)
            try:
                reject(lambda: P.verify_lock(before, b'mutant'))
            finally:
                P.tomllib.loads = original_loads
            count += 1
        reject(lambda: P.prepare(source, root/'first'))
        count += 1
        # Each permitted source rewrite is anchored to its exact Git blob.
        fixture = root/'mutations'
        for name in P.FILES:
            path = fixture/name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes((source/name).read_bytes())
        for name in P.FILES:
            path = fixture/name
            raw = path.read_bytes()
            path.write_bytes(raw+b'\n// different upstream source\n')
            reject(lambda: P.patches(fixture))
            path.write_bytes(raw)
            count += 1
    print(f'{count} actual pinned-source portability and negative checks passed')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    args = parser.parse_args()
    run(args.source.resolve())
