#!/usr/bin/env python3
"""Execute the shipped OpenVPN binding after its real native-module copy."""
from pathlib import Path
import importlib.util
import os
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('native_openvpn_copy', ROOT/'deploy/prepare-mobile-openvpn.py')
COPY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(COPY)


class NativeOpenVPNSource(unittest.TestCase):
    def test_native_copy_executes_all_existing_mobile_parser_cases(self):
        with tempfile.TemporaryDirectory() as temporary:
            vendor = Path(temporary)
            (vendor/'go.mod').write_text('module github.com/sagernet/sing-box\n\ngo 1.23\n')
            COPY.prepare(vendor)
            native = vendor/'experimental/libbox'
            for name in ('routervpn_openvpn_test.go', 'routervpn_openvpn_parser_test.go'):
                (native/name).write_bytes((ROOT/'mobile'/name).read_bytes())
            original = {str(path.relative_to(vendor)): path.read_bytes() for path in vendor.rglob('*.go')}
            COPY.prepare(vendor)
            self.assertEqual(original, {str(path.relative_to(vendor)): path.read_bytes() for path in vendor.rglob('*.go')})
            for path in vendor.rglob('*.go'):
                self.assertNotIn('"router-vpn/internal/', path.read_text())
            completed = subprocess.run(['go', 'test', '-count=1', './experimental/libbox'], cwd=vendor,
                                       text=True, capture_output=True, timeout=60, env=os.environ.copy())
            self.assertEqual(completed.returncode, 0, completed.stdout+completed.stderr)
            self.assertIn(ROOT/'internal/nativeopenvpn/profile.go', COPY.inputs())
            self.assertIn(ROOT/'mobile/routervpn_openvpn.go', COPY.inputs())

    def test_foreign_module_and_linked_target_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            vendor = Path(temporary)
            (vendor/'go.mod').write_text('module unrelated\n')
            with self.assertRaises(ValueError):
                COPY.prepare(vendor)
            (vendor/'go.mod').write_text('module github.com/sagernet/sing-box\n')
            target = vendor/'untouched'
            target.write_text('existing source')
            output = vendor/'experimental/libbox/routervpn/nativeopenvpn'
            output.mkdir(parents=True)
            try:
                (output/'profile.go').symlink_to(target)
            except OSError as error:
                self.skipTest('this host cannot create a test symlink: '+str(error))
            with self.assertRaises(ValueError):
                COPY.prepare(vendor)
            self.assertEqual(target.read_text(), 'existing source')


if __name__ == '__main__':
    unittest.main()
