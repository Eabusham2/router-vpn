#!/usr/bin/env python3
"""Check actual Go source selection for the retained paired-node desktop owner.

This uses the Go toolchain's real target/tag matching, including ios implying
Darwin. It is a source boundary check, not an iOS SDK or native-host pass.
"""
from pathlib import Path
import argparse
import os
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
GO = 'go'
GROUPS = {
    'command': ('node_command_control_darwin.go.tmpl', 'node_command_run_darwin.go.tmpl',
                'node_command_retirement_darwin.go.tmpl', 'node_command_run_darwin_other.go.tmpl'),
    'box': ('node_box_darwin.go.tmpl',),
    'physical': ('node_paired_physical_darwin.go.tmpl',),
}


def verify(root=ROOT, go=GO, transform=None, environment=None):
    captured = dict(os.environ if environment is None else environment)
    selected = {}
    for target in ('darwin', 'ios', 'linux', 'windows'):
        for group, names in GROUPS.items():
            with tempfile.TemporaryDirectory(prefix='routervpn-paired-platform-') as temp:
                folder = Path(temp)
                for name in names:
                    raw = (root / 'mobile/desktop' / name).read_bytes()
                    if transform:
                        raw = transform(name, raw)
                    if raw is not None:
                        (folder / name.removesuffix('.tmpl')).write_bytes(raw)
                env = dict(captured, GO111MODULE='off', GOOS=target,
                           GOARCH='arm64' if target in ('darwin', 'ios') else 'amd64', CGO_ENABLED='0')
                run = subprocess.run([go, 'list', '-e', '-f', r'{{join .GoFiles "\n"}}', '.'],
                                     cwd=folder, env=env, capture_output=True, text=True, timeout=30)
                if run.returncode:
                    raise ValueError('Go platform source selection failed: ' + run.stderr[-4000:])
                actual = set(run.stdout.split())
                expected = {name.removesuffix('.tmpl') for name in names
                            if (target == 'darwin') != name.endswith('_other.go.tmpl')}
                if actual != expected:
                    raise ValueError('paired-node desktop platform source mismatch: ' + target + '/' + group)
                selected[target + '/' + group] = sorted(actual)
    return selected


class PairedNodePlatforms(unittest.TestCase):
    def test_actual_go_targets(self):
        result = verify(go=GO)
        self.assertEqual(result['ios/command'], ['node_command_run_darwin_other.go'])
        self.assertEqual(result['ios/box'], [])
        self.assertEqual(result['ios/physical'], [])

    def test_missing_ios_linux_stub_is_refused(self):
        with self.assertRaisesRegex(ValueError, 'platform source mismatch'):
            verify(go=GO, transform=lambda name, raw: None if name.endswith('_other.go.tmpl') else raw)

    def test_darwin_alias_cannot_admit_ios_owner(self):
        with self.assertRaisesRegex(ValueError, 'platform source mismatch: ios'):
            verify(go=GO, transform=lambda name, raw: raw.replace(b'darwin && !ios', b'darwin', 1)
                   if name == 'node_command_control_darwin.go.tmpl' else raw)

    def test_wrong_stub_platform_is_refused(self):
        with self.assertRaisesRegex(ValueError, 'platform source mismatch: ios'):
            verify(go=GO, transform=lambda name, raw: raw.replace(b'!darwin || ios', b'!darwin', 1)
                   if name.endswith('_other.go.tmpl') else raw)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--go', default='go')
    args = parser.parse_args()
    GO = args.go
    unittest.main(argv=[__file__])
