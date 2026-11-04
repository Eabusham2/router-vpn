#!/usr/bin/env python3
"""Exercise actual repeated native preparation and incomplete-source refusal."""
from pathlib import Path
import argparse
import importlib.util
import shutil
import subprocess
import tempfile
import unittest

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


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True, help='actual pinned core with retained/mobile MTU inbound preparation')
    args = parser.parse_args()
    SOURCE = args.source.resolve()
    if subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=SOURCE, text=True).strip() != '1ac1a339cb1223e9c70eae14c44411c75033c02d':
        raise ValueError('exact pinned prepared core is required')
    unittest.main(argv=[__file__])
