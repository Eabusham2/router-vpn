#!/usr/bin/env python3
"""Exercise the pinned header/license source closure without Darwin privilege."""
from pathlib import Path
import importlib.util
import shutil
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('darwin_pf_abi_fixture', ROOT/'deploy/darwin-pf-abi.py')
ABI = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ABI)


class PinnedApplePFABI(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='routervpn-pf-header-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        original = ROOT/'internal/mobiletor'
        shutil.copytree(original/ABI.DIRECTORY, self.root/ABI.DIRECTORY)
        shutil.copyfile(original/'desktop_socket_darwin_pfabi.h', self.root/'desktop_socket_darwin_pfabi.h')

    def test_actual_pinned_source_identity_and_exact_copy(self):
        original = ABI.checked_files(ROOT/'internal/mobiletor')
        self.assertEqual(ABI.checked_files(self.root), original)
        self.assertEqual(len(original), 6)
        self.assertIn(b'Private interfaces', original[ABI.DIRECTORY+'/net/pfvar.h'])
        self.assertIn(b'Apple Public Source License', original[ABI.DIRECTORY+'/APPLE_LICENSE'])

    def test_changed_header_cannot_be_blessed_by_a_changed_manifest(self):
        header = self.root/ABI.DIRECTORY/'net/pfvar.h'
        header.write_bytes(header.read_bytes()+b'\n#define UNREVIEWED_PF_ABI 1\n')
        with self.assertRaisesRegex(ValueError, 'Pinned Apple PF dependency bytes differ'):
            ABI.checked_files(self.root)
        manifest = self.root/ABI.DIRECTORY/'UPSTREAM.json'
        manifest.write_bytes(manifest.read_bytes().replace(ABI.COMMIT.encode(), b'0'*40))
        with self.assertRaises(ValueError):
            ABI.checked_files(self.root)

    def test_missing_license_or_unknown_source_is_rejected(self):
        license_path = self.root/ABI.DIRECTORY/'APPLE_LICENSE'
        original = license_path.read_bytes()
        license_path.unlink()
        with self.assertRaisesRegex(ValueError, 'closure differs'):
            ABI.checked_files(self.root)
        license_path.write_bytes(original)
        (self.root/ABI.DIRECTORY/'unreviewed.h').write_text('/* extra dependency */')
        with self.assertRaisesRegex(ValueError, 'closure differs'):
            ABI.checked_files(self.root)

    def test_linked_header_or_ancestor_is_rejected(self):
        original = ROOT/'internal/mobiletor'/ABI.DIRECTORY
        header = self.root/ABI.DIRECTORY/'net/pfvar.h'
        header.unlink()
        header.symlink_to(original/'net/pfvar.h')
        with self.assertRaisesRegex(ValueError, 'linked'):
            ABI.checked_files(self.root)
        header.unlink()
        header.parent.rmdir()
        header.parent.symlink_to(original/'net', target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'linked'):
            ABI.checked_files(self.root)


if __name__ == '__main__':
    unittest.main(verbosity=2)
