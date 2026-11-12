#!/usr/bin/env python3
"""Keep native form compilation separate from complete bounded execution."""
from pathlib import Path
import contextlib
import importlib.util
import io
import re
import subprocess
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('amnezia_forms', Path(__file__).with_name('test_desktop_amnezia_forms.py'))
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)


def verdicts(roots):
    return ''.join('=== RUN   '+name+'\n--- PASS: '+name+' (0.01s)\n' for name in roots)+'PASS\n'


class FormExecutionPhases(unittest.TestCase):
    def test_build_is_race_enabled_bounded_and_separate_from_execution(self):
        with patch.object(GATE.subprocess, 'run') as run, contextlib.redirect_stdout(io.StringIO()):
            binary = GATE.compile_form_image(Path('captured-image'))
        run.assert_called_once_with(['go', 'test', '-c', '-race', '-o', str(binary), './cmd/client'],
                                    cwd=GATE.ROOT, check=True, timeout=300)

    def test_failed_compilation_does_not_become_an_execution_receipt(self):
        error = subprocess.CalledProcessError(2, ['go', 'test', '-c'])
        with patch.object(GATE.subprocess, 'run', side_effect=error), contextlib.redirect_stdout(io.StringIO()), \
                self.assertRaises(subprocess.CalledProcessError) as caught:
            GATE.compile_form_image(Path('captured-image'))
        self.assertIs(caught.exception, error)

    def test_original_catalog_and_all_five_payload_roots_keep_exact_execution(self):
        self.assertEqual(GATE.CATALOG_ROOTS, ('TestDesktopExternalEntryModeFormCatalog',))
        self.assertEqual(GATE.PAYLOAD_ROOTS, (
            'TestDesktopAmneziaFormPayload', 'TestDesktopExternalProxyFormPayload',
            'TestDesktopExternalPacketFormPayload', 'TestDesktopExternalEntryModeFormPayload',
            'TestDesktopExternalOpenVPNFormPayload'))
        for roots in (GATE.CATALOG_ROOTS, GATE.PAYLOAD_ROOTS):
            result = subprocess.CompletedProcess(['captured-image'], 0, verdicts(roots))
            with patch.object(GATE.subprocess, 'run', return_value=result) as run, contextlib.redirect_stdout(io.StringIO()):
                GATE.run_go_form_phase(Path('captured-image'), roots, {'captured': 'environment'})
            command = run.call_args.args[0]
            self.assertEqual(command[0], 'captured-image')
            self.assertEqual(command[2:], ['-test.count=1', '-test.v', '-test.timeout=180s'])
            selector = command[1].removeprefix('-test.run=')
            for root in roots:
                self.assertTrue(re.fullmatch(selector, root))
                self.assertFalse(re.fullmatch(selector, root+'Unrelated'))
            self.assertEqual(run.call_args.kwargs['timeout'], 180)
            self.assertEqual(run.call_args.kwargs['cwd'], GATE.ROOT/'cmd/client')
            self.assertEqual(run.call_args.kwargs['env'], {'captured': 'environment'})

    def test_missing_skipped_duplicate_and_incomplete_receipts_fail(self):
        roots = GATE.PAYLOAD_ROOTS
        original = verdicts(roots)
        bad = [original.replace('--- PASS: '+roots[0], '--- SKIP: '+roots[0]),
               original.replace('=== RUN   '+roots[0]+'\n', ''),
               original.replace('--- PASS: '+roots[0]+' (0.01s)\n', ''),
               original+original, original.removesuffix('PASS\n'),
               original+'after-package\n', 'WARNING: DATA RACE\n'+original]
        for output in bad:
            with self.subTest(output=output), patch.object(GATE.subprocess, 'run', return_value=
                    subprocess.CompletedProcess(['image'], 0, output)), contextlib.redirect_stdout(io.StringIO()), \
                    self.assertRaises(RuntimeError):
                GATE.run_go_form_phase(Path('image'), roots, {})

    def test_nonzero_exit_and_timeout_remain_failures(self):
        result = subprocess.CompletedProcess(['original-image'], 7, verdicts(GATE.PAYLOAD_ROOTS))
        with patch.object(GATE.subprocess, 'run', return_value=result), contextlib.redirect_stdout(io.StringIO()), \
                self.assertRaises(subprocess.CalledProcessError) as caught:
            GATE.run_go_form_phase(Path('image'), GATE.PAYLOAD_ROOTS, {})
        self.assertEqual(caught.exception.returncode, 7)
        expired = subprocess.TimeoutExpired(['original-image'], 180)
        with patch.object(GATE.subprocess, 'run', side_effect=expired), contextlib.redirect_stdout(io.StringIO()), \
                self.assertRaises(subprocess.TimeoutExpired) as caught:
            GATE.run_go_form_phase(Path('image'), GATE.PAYLOAD_ROOTS, {})
        self.assertIs(caught.exception, expired)

    def test_each_original_windows_shell_keeps_catalog_producer_and_consumer(self):
        events = []
        def phase(binary, roots, env):
            directory = Path(env['ROUTERVPN_AWG_FORM_PAYLOADS'])
            self.assertEqual(str(directory), env['ROUTERVPN_EXTERNAL_FORM_PAYLOADS'])
            self.assertTrue((directory/'external-openvpn-multihost-layered-aes-client.json').is_file())
            events.append(('phase', roots, directory))
        def producer(directory, shell):
            events.append(('producer', shell, directory))
        with patch.object(GATE, 'run_go_form_phase', side_effect=phase), \
                patch.object(GATE, 'windows_form', side_effect=producer):
            GATE.run_forms('windows', ['pwsh', 'powershell.exe'], Path('original-race-image'))
        self.assertEqual([(kind, value) for kind, value, _ in events], [
            ('phase', GATE.CATALOG_ROOTS), ('producer', 'pwsh'), ('phase', GATE.PAYLOAD_ROOTS),
            ('phase', GATE.CATALOG_ROOTS), ('producer', 'powershell.exe'), ('phase', GATE.PAYLOAD_ROOTS)])
        self.assertEqual(events[0][2], events[1][2])
        self.assertEqual(events[1][2], events[2][2])
        self.assertNotEqual(events[0][2], events[3][2])


if __name__ == '__main__':
    unittest.main()
