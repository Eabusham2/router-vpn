#!/usr/bin/env python3
"""Validate the native privileged UID gate at its compiler/privilege boundaries."""
from pathlib import Path
import contextlib
import importlib.util
import io
import os
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('owned_uid_runner', ROOT/'deploy/test_desktop_socket_uid.py')
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)


def passed():
    test = 'TestDesktopSocketPrivilegedUIDSurvivesTransferImportAndDup'
    return '\n'.join(['--- PASS: '+test+' (0.1s)',
                      *['    --- PASS: '+test+'/'+kind+' (0.1s)' for kind in ('tcp4', 'udp4', 'tcp6', 'udp6')],
                      '--- PASS: TestDesktopSocketPrivilegedWrongKernelUIDCannotGrant (0.1s)', 'PASS', ''])


class OwnedUIDRunner(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='uid-runner-contract-')
        self.addCleanup(self.temp.cleanup)
        self.source = Path(self.temp.name)/'core'
        target = self.source/'routervpn/mobiletor'
        target.mkdir(parents=True)
        for path in (ROOT/'internal/mobiletor').glob('desktop_socket_*.go'):
            (target/path.name).write_bytes(path.read_bytes())
        self.addCleanup(patch.stopall)
        patch.object(GATE.PREP, 'checked_vendor', side_effect=lambda source: Path(source).resolve()).start()
        patch.object(GATE.platform, 'system', return_value='Linux').start()
        patch.object(GATE.os, 'geteuid', return_value=0).start()

    def execute(self, fault=''):
        calls = []

        def run(command, **kwargs):
            args = [str(value) for value in command]
            calls.append((args, kwargs))
            if args[:2] == ['/captured/go', 'test']:
                self.assertIn('-c', args)
                self.assertIn('-race', args)
                self.assertIn('-mod=readonly', args)
                self.assertIn('-tags=routervpn_privileged', args)
                self.assertEqual(args[-1], './routervpn/mobiletor')
                self.assertNotIn('sudo', args)
                self.assertEqual(kwargs['cwd'], self.source.resolve())
                self.assertEqual(kwargs['env']['GOTOOLCHAIN'], 'local')
                binary = Path(args[args.index('-o')+1])
                binary.write_bytes(b'owned compiler output')
                binary.chmod(0o755)
                if fault == 'source-after-build':
                    path = self.source/'routervpn/mobiletor/desktop_socket_source.go'
                    path.write_bytes(path.read_bytes()+b'\n// replaced\n')
                if fault == 'writable-binary':
                    binary.chmod(0o777)
                return ''
            if fault == 'sudo':
                self.assertEqual(args[:3], ['/usr/bin/sudo', '-n', '--'])
                self.assertEqual(kwargs['sudo'], '/usr/bin/sudo')
                args = args[3:]
            self.assertEqual(args[1:], ['-test.run=^TestDesktopSocketPrivileged', '-test.count=1', '-test.timeout=45s', '-test.v'])
            self.assertLessEqual(kwargs['timeout'], 60)
            if fault == 'binary-after-run':
                Path(args[0]).write_bytes(b'changed compiler output')
            if fault == 'source-after-run':
                path = self.source/'routervpn/mobiletor/desktop_socket_source.go'
                path.write_bytes(path.read_bytes()+b'\n// replaced\n')
            if fault == 'missing-tests':
                return 'testing: warning: no tests to run\nPASS\n'
            if fault == 'skipped-test':
                return passed()+'--- SKIP: missing privileged kernel\n'
            if fault == 'missing-family':
                return passed().replace('/udp6 (', '/foreign (')
            return passed()

        with patch.object(GATE, 'run', side_effect=run), contextlib.redirect_stdout(io.StringIO()):
            GATE.execute(self.source, '/captured/go', env={'GOOS': 'linux', 'GOTOOLCHAIN': 'ambient'})
        return calls

    def test_exact_source_is_compiled_before_only_privileged_fixture_executes(self):
        calls = self.execute()
        self.assertEqual(len(calls), 2)

    def test_nonroot_build_compiles_normally_before_bounded_noprompt_sudo(self):
        with patch.object(GATE, 'privilege_tool', return_value='/usr/bin/sudo'):
            calls = self.execute('sudo')
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[0][0][0], '/captured/go')

    def test_missing_privilege_is_a_failure_before_compilation(self):
        with patch.object(GATE, 'privilege_tool', side_effect=ValueError('missing privilege')), patch.object(GATE, 'run') as run:
            with self.assertRaisesRegex(ValueError, 'missing privilege'):
                GATE.execute(self.source, '/captured/go', env={})
            run.assert_not_called()

    def test_source_and_executable_replacement_never_acknowledge_execution(self):
        for fault in ('source-after-build', 'writable-binary', 'binary-after-run', 'source-after-run',
                      'missing-tests', 'skipped-test', 'missing-family'):
            with self.subTest(fault=fault):
                for path in (ROOT/'internal/mobiletor').glob('desktop_socket_*.go'):
                    (self.source/'routervpn/mobiletor'/path.name).write_bytes(path.read_bytes())
                with self.assertRaises(ValueError):
                    self.execute(fault)

    def test_missing_or_changed_source_cannot_invoke_privilege(self):
        path = self.source/'routervpn/mobiletor/desktop_socket_source_unix.go'
        for fault in ('changed', 'missing', 'linked'):
            with self.subTest(fault=fault), patch.object(GATE, 'run') as run:
                if path.exists() or path.is_symlink(): path.unlink()
                if fault == 'changed': path.write_bytes(b'changed source')
                if fault == 'linked': path.symlink_to(ROOT/'internal/mobiletor'/path.name)
                with self.assertRaises(ValueError):
                    GATE.execute(self.source, '/captured/go', env={})
                run.assert_not_called()

    def test_non_unix_or_cross_host_is_not_silently_skipped(self):
        with patch.object(GATE.platform, 'system', return_value='Windows'), patch.object(GATE, 'run') as run:
            with self.assertRaisesRegex(ValueError, 'matching Linux/macOS'):
                GATE.execute(self.source)
            run.assert_not_called()
        with patch.object(GATE, 'run') as run:
            with self.assertRaisesRegex(ValueError, 'cross-compiled'):
                GATE.execute(self.source, env={'GOOS': 'darwin'})
            run.assert_not_called()


if __name__ == '__main__':
    unittest.main()
