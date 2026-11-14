#!/usr/bin/env python3
"""Causal validation of the separate native race compiler identity."""
from pathlib import Path
import importlib.util
import tempfile
import types
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('darwin_race_test', Path(__file__).with_name('darwin_race_toolchain.py'))
RACE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RACE)


class CompilerIdentity(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.root = Path(self.folder.name)
        (self.root/'bin').mkdir()
        (self.root/'bin/go').write_text('fixture')
        (self.root/'bin/go').chmod(0o755)
        self.identity = dict(GOROOT=str(self.root), GOVERSION=RACE.TOOLCHAIN,
                             GOHOSTOS='darwin', GOHOSTARCH='arm64', GOOS='darwin', GOARCH='arm64')
        self.environment = dict(GOTOOLCHAIN='local', GOROOT='/production/go1.26.3', PATH='/production/bin', CGO_ENABLED='1')
        self.enterContext(patch.object(RACE.platform, 'system', return_value='Darwin'))
        self.enterContext(patch.object(RACE.platform, 'machine', return_value='arm64'))

    def test_capture_resolves_then_freezes_actual_compiler_without_mutating_product(self):
        before = dict(self.environment)
        with patch.object(RACE, 'readback', return_value=self.identity) as read:
            compiler, captured = RACE.capture(self.root, '/production/go', self.environment)
        self.assertEqual(compiler, self.root/'bin/go')
        self.assertEqual(self.environment, before)
        self.assertNotIn('GOROOT', read.call_args_list[0].args[2])
        self.assertEqual(read.call_args_list[0].args[2]['GOTOOLCHAIN'], 'go1.26.5')
        self.assertEqual(captured['GOTOOLCHAIN'], 'local')
        self.assertEqual(captured['GOROOT'], str(self.root))
        self.assertEqual(captured['PATH'].split(':')[0], str(self.root/'bin'))

    def test_rejects_old_compiler_cross_host_and_cross_target(self):
        for key, value in [('GOVERSION', 'go1.26.3'), ('GOHOSTOS', 'linux'),
                           ('GOHOSTARCH', 'amd64'), ('GOOS', 'linux'), ('GOARCH', 'amd64'),
                           ('GOROOT', 'relative')]:
            with self.subTest(key=key), patch.object(RACE, 'readback', return_value=dict(self.identity, **{key:value})):
                with self.assertRaises(ValueError): RACE.capture(self.root, 'go', self.environment)

    def test_rejects_changed_identity_after_freeze(self):
        with patch.object(RACE, 'readback', side_effect=[self.identity, dict(self.identity, GOVERSION='go1.26.3')]):
            with self.assertRaisesRegex(ValueError, 'changed'): RACE.capture(self.root, 'go', self.environment)

    def test_requires_available_executable(self):
        (self.root/'bin/go').chmod(0o644)
        with patch.object(RACE, 'readback', return_value=self.identity):
            with self.assertRaisesRegex(ValueError, 'executable'): RACE.capture(self.root, 'go', self.environment)

    def test_only_native_race_commands_select_validation_toolchain(self):
        for command in (['go','build','./cmd/client'], ['go','test','./...'], ['go','env','GOVERSION'], ['python3','test.py']):
            with self.subTest(command=command), patch.object(RACE, 'capture') as capture:
                self.assertEqual(RACE.command(command, self.root, self.environment), (command, self.environment))
                capture.assert_not_called()
        for verb in ('test', 'build'):
            with patch.object(RACE, 'capture', return_value=(self.root/'bin/go', {'RACE':'1'})):
                command, env = RACE.command(['go',verb,'-race','./...'], self.root, self.environment)
            self.assertEqual(command, [self.root/'bin/go',verb,'-race','./...'])
            self.assertEqual(env, {'RACE':'1'})

    def test_preserves_non_darwin_race_compiler(self):
        with patch.object(RACE.platform, 'system', return_value='Linux'), patch.object(RACE, 'capture') as capture:
            command = ['go','test','-race','./...']
            self.assertEqual(RACE.command(command, self.root, self.environment), (command, self.environment))
            capture.assert_not_called()

    def test_image_readback_cannot_label_an_original_product_compiler_as_validation(self):
        image = self.root/'native.test'
        for version in ('go1.26.3', 'go1.26.5', 'go1.26.6'):
            with self.subTest(version=version), patch.object(RACE.subprocess, 'run',
                    return_value=types.SimpleNamespace(stdout=str(image)+': '+version+'\n')):
                if version == RACE.TOOLCHAIN:
                    RACE.verify_image(self.root/'bin/go', image, self.root, self.environment)
                else:
                    with self.assertRaises(ValueError):
                        RACE.verify_image(self.root/'bin/go', image, self.root, self.environment)


if __name__ == '__main__': unittest.main()
