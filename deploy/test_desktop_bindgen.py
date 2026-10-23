#!/usr/bin/env python3
"""Verify the exact Clang 22 bindgen backport and its locked build-only scope."""
from pathlib import Path
import argparse
import copy
import hashlib
import importlib.util
import io
import json
import os
import tarfile
import tempfile
import tomllib
import unittest
import urllib.request
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('bindgen_desktop_pq', ROOT/'deploy/build-desktop-pq.py')
PQ = importlib.util.module_from_spec(spec)
spec.loader.exec_module(PQ)
P = PQ.PACKET
CRATE = None


def pinned_crate():
    if CRATE is not None:
        return Path(CRATE).read_bytes()
    cache = Path(os.environ.get('CARGO_HOME', str(Path.home()/'.cargo')))/'registry/cache'
    for path in sorted(cache.glob('*/bindgen-0.71.1.crate')):
        if path.is_file() and not path.is_symlink() and path.stat().st_size == P.BINDGEN_SIZE:
            raw = path.read_bytes()
            if hashlib.sha256(raw).hexdigest() == P.BINDGEN_CHECKSUM:
                return raw
    url = 'https://static.crates.io/crates/bindgen/bindgen-0.71.1.crate'
    with urllib.request.urlopen(url, timeout=30) as response:
        raw = response.read(P.BINDGEN_SIZE+1)
    if len(raw) != P.BINDGEN_SIZE or hashlib.sha256(raw).hexdigest() != P.BINDGEN_CHECKSUM:
        raise AssertionError('The real bindgen fixture does not match its exact Cargo.lock pin')
    return raw


def lock_bytes(packages):
    records = ['version = 4\n']
    for item in packages:
        records.append('[[package]]\n'+'\n'.join(key+' = '+json.dumps(value)
                                                for key, value in item.items())+'\n')
    return '\n'.join(records).encode('utf-8')


class BindgenBackport(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = pinned_crate()
        cls.before = (ROOT/'mobile/rosenpass/Cargo.lock').read_bytes()
        cls.original = tomllib.loads(cls.before.decode('utf-8'))['package']

    def local_packages(self):
        packages = copy.deepcopy(self.original)
        for item in packages:
            if item['name'] in P.CRATES or item['name'] == 'bindgen':
                item.pop('source', None)
                item.pop('checksum', None)
        return packages

    def test_real_archive_sources_are_exact_except_upstream_definition_fix(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root/'source.crate'; archive.write_bytes(self.raw)
            output = root/'private-build-tool'
            receipt = P.prepare_bindgen(archive, output)
            with tarfile.open(fileobj=io.BytesIO(self.raw), mode='r:gz') as package:
                original = {member.name.split('/', 1)[1]: package.extractfile(member).read()
                            for member in package}
            copied = {path.relative_to(output).as_posix(): path.read_bytes()
                      for path in output.rglob('*') if path.is_file()}
            self.assertEqual(set(copied), set(original))
            self.assertEqual([name for name in copied if copied[name] != original[name]], ['clang.rs'])
            self.assertEqual(hashlib.sha256(copied['clang.rs']).hexdigest(),
                             '2e1e65a56cf7434733dc87e8cc837d64add8358cb3d57f81a1424d7aea4858a5')
            self.assertIn(b'decl.definition().unwrap_or(decl)', copied['clang.rs'])
            self.assertEqual(receipt['crate_sha256'], P.BINDGEN_CHECKSUM)
            self.assertEqual(receipt['upstream_backport'], '2426dd68cd12e0ac022bca18efb9c7d0acd27e12')
            self.assertEqual(archive.read_bytes(), self.raw)

    def test_changed_or_wrong_sized_archive_is_rejected_before_output(self):
        for raw in (self.raw[:-1], self.raw+b'\0', self.raw[:100]+bytes([self.raw[100]^1])+self.raw[101:]):
            with self.subTest(size=len(raw)), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary); archive = root/'source.crate'; archive.write_bytes(raw)
                with self.assertRaises(ValueError):
                    P.prepare_bindgen(archive, root/'output')
                self.assertFalse((root/'output').exists())

    def test_unowned_output_is_preserved(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); archive = root/'source.crate'; archive.write_bytes(self.raw)
            output = root/'output'; output.mkdir(); (output/'owned-by-another-task').write_bytes(b'keep')
            with self.assertRaises(ValueError):
                P.prepare_bindgen(archive, output)
            self.assertEqual((output/'owned-by-another-task').read_bytes(), b'keep')

    def test_changed_patch_does_not_publish_a_different_generator(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); archive = root/'source.crate'; archive.write_bytes(self.raw)
            with patch.object(P, 'BINDGEN_NEW', P.BINDGEN_OLD), self.assertRaisesRegex(ValueError, 'exact upstream'):
                P.prepare_bindgen(archive, root/'output')
            self.assertFalse((root/'output').exists())

    def test_only_explicit_exact_local_build_tool_substitution_is_allowed(self):
        local = lock_bytes(self.local_packages())
        P.verify_lock(self.before, local, bindgen=True)
        with self.assertRaises(ValueError):
            P.verify_lock(self.before, local)

    def test_changed_missing_or_duplicate_build_tool_is_rejected(self):
        for mutation in ('version', 'source', 'checksum', 'missing', 'duplicate', 'registry-dependency'):
            packages = self.local_packages()
            item = next(item for item in packages if item['name'] == 'bindgen')
            if mutation == 'version':
                item['version'] = '0.72.1'
            elif mutation == 'source':
                item['source'] = P.BINDGEN_SOURCE
            elif mutation == 'checksum':
                item['checksum'] = ''
            elif mutation == 'missing':
                packages.remove(item)
            elif mutation == 'duplicate':
                packages.append(copy.deepcopy(item))
            else:
                next(value for value in packages if value.get('checksum'))['checksum'] = '0'*64
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                P.verify_lock(self.before, lock_bytes(packages), bindgen=True)

    def test_source_pin_cannot_be_changed_or_omitted(self):
        for mutation in ('version', 'source', 'checksum', 'missing', 'duplicate'):
            packages = copy.deepcopy(self.original)
            item = next(item for item in packages if item['name'] == 'bindgen')
            if mutation == 'version':
                item['version'] = '0.72.1'
            elif mutation == 'source':
                item['source'] = 'registry+https://example.invalid/index'
            elif mutation == 'checksum':
                item['checksum'] = '0'*64
            elif mutation == 'missing':
                packages.remove(item)
            else:
                packages.append(copy.deepcopy(item))
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                P.bindgen_pin(lock_bytes(packages))

    def test_metadata_selects_only_the_locked_archive(self):
        manifest = ROOT/'fixture/registry/src/pinned-index/bindgen-0.71.1/Cargo.toml'
        item = {'name': 'bindgen', 'version': P.BINDGEN_VERSION, 'source': P.BINDGEN_SOURCE,
                'manifest_path': str(manifest)}
        expected = ROOT/'fixture/registry/cache/pinned-index/bindgen-0.71.1.crate'
        self.assertEqual(PQ.bindgen_archive({'packages': [item]}), expected)
        for packages in ([], [item, item], [{**item, 'version': '0.72.1'}],
                         [{**item, 'source': 'git+https://example.invalid/build-tool'}],
                         [item, {**item, 'version': '0.72.1'}]):
            with self.subTest(packages=packages), self.assertRaises(ValueError):
                PQ.bindgen_archive({'packages': packages})


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__, add_help=False)
    parser.add_argument('--crate', type=Path)
    args, remaining = parser.parse_known_args()
    CRATE = args.crate
    unittest.main(argv=[__file__, *remaining])
