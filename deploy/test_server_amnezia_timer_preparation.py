#!/usr/bin/env python3
"""Check pinned server timer repair and rejection without touching shared source."""
from pathlib import Path
import importlib.util
import json
import os
import subprocess
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location('server_amnezia_timer_preparation', ROOT / 'deploy/prepare-server-amnezia-timers.py')
SERVER = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(SERVER)


class ServerTimerPreparation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        info = json.loads(subprocess.check_output(
            ['go', 'mod', 'download', '-json', SERVER.TIMERS.MODULE + '@' + SERVER.TIMERS.VERSION], cwd=ROOT, text=True))
        if info.get('Sum') != SERVER.TIMERS.SUM or info.get('Error'):
            raise ValueError('Server timer fixture did not retrieve the exact original blob')
        with zipfile.ZipFile(info['Zip']) as archive:
            cls.original = archive.read(SERVER.TIMERS.PREFIX + SERVER.TIMERS.TIMER)
        if SERVER.TIMERS.git_blob(cls.original) != SERVER.TIMERS.BLOB:
            raise ValueError('Server and native timer source identities differ')

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.source = Path(temporary.name).resolve()
        self.timer = self.source / SERVER.TIMERS.TIMER
        self.timer.parent.mkdir()
        self.timer.write_bytes(self.original)
        self.test = self.source / SERVER.TIMERS.TEST

    def test_exact_patch_is_repeatable_and_preserves_every_other_source_byte(self):
        other = self.source / 'private-unrelated-source'
        other.write_bytes(b'preserved source')
        SERVER.prepare(self.source, SERVER.REVISION)
        self.assertEqual(SERVER.TIMERS.original(self.timer.read_bytes()), self.original)
        self.assertEqual(self.test.read_bytes(), SERVER.TIMERS.test_source())
        SERVER.prepare(self.source, SERVER.REVISION)
        SERVER.verify(self.source, SERVER.REVISION)
        self.assertEqual(other.read_bytes(), b'preserved source')
        self.assertEqual(list(self.timer.parent.glob('.routervpn-timer-*')), [])

    def test_wrong_revision_unknown_timer_and_foreign_test_cannot_mutate_source(self):
        for fault in ('revision', 'timer', 'test'):
            with self.subTest(fault=fault):
                timer = self.original + (b'// foreign modification\n' if fault == 'timer' else b'')
                self.timer.write_bytes(timer)
                self.test.unlink(missing_ok=True)
                if fault == 'test':
                    self.test.write_bytes(b'foreign test source')
                with self.assertRaises(ValueError):
                    SERVER.prepare(self.source, 'f' * 40 if fault == 'revision' else SERVER.REVISION)
                self.assertEqual(self.timer.read_bytes(), timer)
                if fault == 'test':
                    self.assertEqual(self.test.read_bytes(), b'foreign test source')
                else:
                    self.assertFalse(self.test.exists())

    def test_borrowed_source_and_parent_alias_are_rejected(self):
        original_owner = self.source / 'other-owner'
        original_owner.write_bytes(self.original)
        self.timer.unlink()
        os.link(original_owner, self.timer)
        with self.assertRaises(ValueError):
            SERVER.prepare(self.source, SERVER.REVISION)
        self.assertEqual(original_owner.read_bytes(), self.original)
        self.assertFalse(self.test.exists())
        self.timer.unlink()
        self.timer.symlink_to(original_owner)
        with self.assertRaises(ValueError):
            SERVER.prepare(self.source, SERVER.REVISION)
        self.assertEqual(original_owner.read_bytes(), self.original)
        self.timer.unlink()
        self.timer.parent.rmdir()
        real_device = self.source / 'other-device'
        real_device.mkdir()
        (real_device / 'timers.go').write_bytes(self.original)
        self.timer.parent.symlink_to(real_device, target_is_directory=True)
        with self.assertRaises(ValueError):
            SERVER.prepare(self.source, SERVER.REVISION)
        self.assertEqual((real_device / 'timers.go').read_bytes(), self.original)

    def test_server_image_executes_regression_before_shipping_build(self):
        docker = (ROOT / 'server/awg2/Dockerfile').read_text()
        self.assertIn('ARG AWG_GO_COMMIT=' + SERVER.REVISION, docker)
        self.assertIn('FROM golang:1.25.12-bookworm AS go-build', docker)
        self.assertIn('COPY deploy/prepare-amnezia-timers.py deploy/prepare-server-amnezia-timers.py ', docker)
        self.assertIn('COPY mobile/amneziatimers/timers_test.go.tmpl ', docker)
        test = "go test -race -count=1 -timeout=30s ./device -run '^TestRouterVPNAmneziaTimer'"
        self.assertLess(docker.index(test), docker.index('go build -ldflags'))
        self.assertLess(docker.index('--verify;'), docker.index('go build -ldflags'))


if __name__ == '__main__':
    unittest.main()
