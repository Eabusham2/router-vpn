#!/usr/bin/env python3
"""Execute the real MAX fixture entrypoints with compiler boundaries doubled.

These checks cover Python fixture composition and restoration only. The separate
preparation and service gates still compile and execute their actual Java/Go
cases; no runtime or device acceptance is supplied by this runner test.
"""
from pathlib import Path
import ast
import importlib.util
import os
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
OWNER = 'com/eabusham/routervpn/AndroidMAXProfilePreparation.java'
ENV = 'ROUTERVPN_MAX_PROFILE_FIXTURES'


def fixture(name):
    path = ROOT / 'android' / ('test_android_max_' + name + '.py')
    spec = importlib.util.spec_from_file_location('max_composition_' + name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def entrypoint(module):
    path = Path(module.__file__)
    node = ast.parse(path.read_text()).body[-1]
    if not isinstance(node, ast.If) or ast.unparse(node.test) != "__name__ == '__main__'":
        raise AssertionError('MAX fixture lost its explicit executable entrypoint')
    scope = dict(vars(module), __name__='__main__')
    exec(compile(ast.Module(body=[node], type_ignores=[]), str(path), 'exec'), scope)


class MAXFixtureComposition(unittest.TestCase):
    def launch(self, module, fail_watch=False):
        preparation = module.F if hasattr(module, 'F') else module
        harness = preparation.P
        original_harness, original_source = harness.HARNESS, harness.M.STUBS[OWNER]
        exports, launches = [], []

        def export(command, **options):
            self.assertEqual(command, ['go', 'test', '-count=1', '-run',
                                      '^TestExportMAXMobileProfiles$', './internal/mobilemultihop'])
            self.assertEqual(options['cwd'], ROOT)
            self.assertTrue(options['check'])
            captured = Path(options['env'][ENV])
            captured.write_text('{}')
            exports.append(captured)

        def run():
            self.assertEqual(Path(os.environ[ENV]), exports[0])
            self.assertEqual(exports[0].read_text(), '{}')
            launches.append((harness.HARNESS, harness.M.STUBS[OWNER]))
            if fail_watch and len(launches) == 2:
                raise RuntimeError('captured watcher compiler failed')

        with mock.patch.dict(os.environ, {ENV: 'prior-fixture-owner'}), \
             mock.patch.object(preparation.subprocess, 'run', side_effect=export), \
             mock.patch.object(harness, 'run', side_effect=run):
            if fail_watch:
                with self.assertRaisesRegex(RuntimeError, 'captured watcher compiler failed'):
                    entrypoint(module)
            else:
                entrypoint(module)
            self.assertEqual(os.environ[ENV], 'prior-fixture-owner')
            self.assertEqual(harness.HARNESS, original_harness)
            self.assertEqual(harness.M.STUBS[OWNER], original_source)
        self.assertEqual(len(exports), 1)
        self.assertFalse(exports[0].exists())
        return original_harness, original_source, launches

    def test_preparation_entrypoint_keeps_both_original_and_watcher_cases(self):
        original, source, launches = self.launch(fixture('preparation'))
        self.assertEqual(len(launches), 2)
        self.assertEqual(launches[0], (original, source))
        self.assertIn('watchRetirement(root);noThreads();', launches[1][0])
        self.assertIn('PASS 6 original Java/Go ownership cases', launches[1][0])
        self.assertEqual(launches[1][1].count('PQSelectionHarness.WatchBoundary.pause();'), 1)

    def test_service_entrypoint_keeps_its_complete_independent_harness(self):
        original, source, launches = self.launch(fixture('service'))
        self.assertEqual(launches, [(original, source)])
        for phase in ('rejectedPreflight(root)', 'serviceSuccess(root)', 'cancelledClaim(root)',
                      'startupMutation(root)', 'afterBindMutation(root)'):
            self.assertIn(phase, original)
        self.assertNotIn('PQSelectionHarness.WatchBoundary.pause();', source)

    def test_failed_watcher_restores_original_harness_source_and_fixture_owner(self):
        _, _, launches = self.launch(fixture('preparation'), fail_watch=True)
        self.assertEqual(len(launches), 2)


if __name__ == '__main__':
    unittest.main(verbosity=2)
