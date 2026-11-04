#!/usr/bin/env python3
"""Exercise actual repeated native preparation and incomplete-source refusal."""
from pathlib import Path, PureWindowsPath
import argparse
import base64
import hashlib
import importlib.util
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('native_retirement_projection', ROOT/'deploy/prepare-desktop-mtu.py')
PREP = importlib.util.module_from_spec(spec)
spec.loader.exec_module(PREP)
SOURCE = None


class NativeRetirementProjection(unittest.TestCase):
    def test_actual_reprepare_and_incomplete_refusal(self):
        with tempfile.TemporaryDirectory(prefix='native-retirement-reprepare-') as directory:
            vendor = Path(directory)
            for name in ('go.mod', 'protocol/tun/inbound.go', 'cmd/sing-box/cmd_run.go'):
                target = vendor/name
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(SOURCE/name, target)
            # A later tidy drops the replaced module's original sum. Preparation
            # checks the pinned original before applying its local replacement.
            (vendor/'go.sum').write_bytes(subprocess.check_output(['git', 'show', 'HEAD:go.sum'], cwd=SOURCE))
            PREP.prepare(vendor)
            projected = {path.relative_to(vendor): path.read_bytes() for path in vendor.rglob("*") if path.is_file()}
            inbound = vendor/'protocol/tun/inbound.go'
            original = inbound.read_bytes()
            PREP.prepare(vendor)
            self.assertEqual({path.relative_to(vendor): path.read_bytes() for path in vendor.rglob("*") if path.is_file()}, projected)
            self.assertEqual(inbound.read_bytes(), original)
            self.assertEqual(original.count(b'routervpnStandardStartup bool'), 1)
            self.assertEqual(original.count(b'routervpnRetirementReceipt string'), 1)
            self.assertEqual(original.count(b't.tunIf = tunInterface // retain'), 1)
            for before, after in PREP.INBOUND_RETIREMENT_EDITS:
                for label, mutant in (('partial', original.replace(after, before, 1)),
                                      ('duplicate', original + after)):
                    with self.subTest(boundary=before, mutation=label):
                        inbound.write_bytes(mutant)
                        with self.assertRaises(ValueError):
                            PREP.prepare(vendor)
                        self.assertEqual(inbound.read_bytes(), mutant)
            for mutant in (original + b'\n// unrelated source replacement\n',
                           original.replace(b'RouterVPNNetworkContext: ctx,', b'RouterVPNNetworkContext: nil,', 1)):
                inbound.write_bytes(mutant)
                with self.assertRaises(ValueError):
                    PREP.prepare(vendor)
                self.assertEqual(inbound.read_bytes(), mutant)
            inbound.write_bytes(original)
            PREP.prepare(vendor)
            self.assertEqual(inbound.read_bytes(), original)


class WindowsOrderedPath(type(Path())):
    """Use actual host I/O with the exact Windows filename comparison rule."""
    def __lt__(self, other):
        return PureWindowsPath(str(self)) < PureWindowsPath(str(other))


class PinnedDBusModuleInventory(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.preparer = PREP.dbus_preparer()
        cache = subprocess.check_output(['go', 'env', 'GOMODCACHE'], cwd=SOURCE, text=True, timeout=30).strip()
        cls.module = Path(cache)/(cls.preparer.MODULE+'@'+cls.preparer.VERSION)
        if not cls.module.is_dir():
            raise ValueError('actual checksum-pinned godbus module is required')

    def hash_order(self, paths):
        digest = hashlib.sha256()
        for path in paths:
            filename = self.preparer.MODULE+'@'+self.preparer.VERSION+'/'+path.relative_to(self.module).as_posix()
            digest.update((hashlib.sha256(path.read_bytes()).hexdigest()+'  '+filename+'\n').encode())
        return 'h1:'+base64.b64encode(digest.digest()).decode()

    def test_actual_module_uses_go_filename_order_on_both_platforms(self):
        files = [p for p in self.module.rglob('*') if p.is_file()]
        canonical = sorted(files, key=lambda p: p.relative_to(self.module).as_posix())
        windows = sorted(files, key=lambda p: PureWindowsPath(str(p)))
        self.assertNotEqual(canonical, windows, 'actual corpus no longer distinguishes Windows sorting')
        self.assertEqual(self.hash_order(canonical), self.preparer.SUM)
        self.assertNotEqual(self.hash_order(windows), self.preparer.SUM)
        expected = {p.relative_to(self.module).as_posix():p.read_bytes() for p in canonical}
        # The actual shipping function must retain all original byte content
        # under both real host and Windows comparison semantics.
        self.assertEqual(self.preparer.pinned_files(self.module), expected)
        with patch.object(self.preparer, 'Path', WindowsOrderedPath):
            self.assertEqual(self.preparer.pinned_files(self.module), expected)
        self.assertTrue(any('/' in name for name in expected))
        self.assertFalse(any('\\' in name for name in expected))

    def test_actual_module_changes_are_never_normalized_or_omitted(self):
        with tempfile.TemporaryDirectory(prefix='godbus-original-inventory-') as directory:
            original = Path(directory)/'module'
            shutil.copytree(self.module, original)
            target = original/'decoder.go'
            raw = target.read_bytes()
            self.assertIn(b'\n', raw)
            target.chmod(0o600)
            extra = original/'unreceived-module-file.go'
            for label in ('changed-byte', 'crlf', 'missing-file', 'extra-file'):
                with self.subTest(mutation=label):
                    target.write_bytes(raw)
                    if label == 'changed-byte':
                        target.write_bytes(raw+b'\n// changed original module bytes\n')
                    elif label == 'crlf':
                        target.write_bytes(raw.replace(b'\n', b'\r\n'))
                    elif label == 'missing-file':
                        target.unlink()
                    else:
                        extra.write_bytes(b'package dbus\n')
                    with self.assertRaisesRegex(ValueError, 'Complete pinned godbus module checksum changed'):
                        self.preparer.pinned_files(original)
                    if extra.exists():
                        extra.unlink()
            target.write_bytes(raw)
            self.assertEqual(self.preparer.pinned_files(original), self.preparer.pinned_files(self.module))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True, help='actual pinned core with retained/mobile MTU inbound preparation')
    args = parser.parse_args()
    SOURCE = args.source.resolve()
    if subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=SOURCE, text=True).strip() != '1ac1a339cb1223e9c70eae14c44411c75033c02d':
        raise ValueError('exact pinned prepared core is required')
    unittest.main(argv=[__file__])
