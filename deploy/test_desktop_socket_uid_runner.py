#!/usr/bin/env python3
"""Validate the native privileged UID gate at its compiler/privilege boundaries."""
from pathlib import Path
import contextlib
import importlib.util
import io
import json
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


def copied(path):
    # This real shared ACL import is relocated by the actual native preparer.
    # The fixture keeps every other source byte intact.
    return path.read_bytes().replace(b'"router-vpn/internal/common"',
                                     b'"github.com/sagernet/sing-box/routervpn/common"')


class OwnedUIDRunner(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='uid-runner-contract-')
        self.addCleanup(self.temp.cleanup)
        self.source = Path(self.temp.name)/'core'
        target = self.source/'routervpn/mobiletor'
        target.mkdir(parents=True)
        for path in (ROOT/'internal/mobiletor').glob('desktop_socket_*.go'):
            (target/path.name).write_bytes(copied(path))
        self.toolchain = Path(self.temp.name)/'selected toolchain'
        self.compiler = self.toolchain/'bin/go'
        self.compiler.parent.mkdir(parents=True)
        self.compiler.write_bytes(b'compiler boundary fixture')
        self.compiler.chmod(0o755)
        self.addCleanup(patch.stopall)
        patch.object(GATE.PREP, 'checked_vendor', side_effect=lambda source: Path(source).resolve()).start()
        patch.object(GATE.platform, 'system', return_value='Linux').start()
        patch.object(GATE.os, 'geteuid', return_value=0).start()

    def execute(self, fault=''):
        calls = []

        def run(command, **kwargs):
            args = [str(value) for value in command]
            calls.append((args, kwargs))
            if args[1:] == ['env', '-json', 'GOROOT', 'GOVERSION']:
                self.assertEqual(kwargs['cwd'], self.source.resolve())
                self.assertEqual(kwargs['env']['GOWORK'], 'off')
                if args[0] == '/captured/go':
                    self.assertEqual(kwargs['env']['GOTOOLCHAIN'], 'go1.26.3')
                    if fault == 'toolchain-absent': self.compiler.unlink()
                    return json.dumps({'GOROOT': 'relative/toolchain' if fault == 'toolchain-relative' else str(self.toolchain),
                                       'GOVERSION': 'go1.26.3'})
                self.assertEqual(args[0], str(self.compiler))
                self.assertEqual(kwargs['env']['GOTOOLCHAIN'], 'local')
                self.assertEqual(kwargs['env']['GOROOT'], str(self.toolchain))
                return json.dumps({'GOROOT': str(self.toolchain),
                                   'GOVERSION': 'go1.24.13' if fault == 'toolchain-changed' else 'go1.26.3'})
            if args[:2] == [str(self.compiler), 'test']:
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
            GATE.execute(self.source, '/captured/go', env={'GOOS': 'linux', 'GOTOOLCHAIN': 'go1.26.3'})
        return calls

    def test_exact_source_is_compiled_before_only_privileged_fixture_executes(self):
        calls = self.execute()
        self.assertEqual(len(calls), 4)

    def test_actual_preparer_supplies_the_complete_unix_source_gate(self):
        # The older synthetic setUp copied every matching file and concealed
        # omissions in the shipping preparer's explicit shared-test list.
        # Execute that real copy stage into an empty checkout, then require the
        # unchanged UID source gate to accept all original relocated bytes.
        class SharedStageComplete(Exception):
            pass

        source = Path(self.temp.name)/'actual-preparation'
        source.mkdir()
        write = GATE.PREP.write
        def copy_shared(vendor, relative, raw):
            if not relative.startswith('routervpn/'):
                raise SharedStageComplete()
            write(vendor, relative, raw)

        with patch.object(GATE.PREP, 'prepare_desktop_pt'), \
             patch.object(GATE.PREP, 'comparison_client_contract', return_value={}), \
             patch.object(GATE.PREP.PFABI, 'checked_files', return_value={}), \
             patch.object(GATE.PREP, 'write', side_effect=copy_shared), \
             self.assertRaises(SharedStageComplete):
            GATE.PREP.prepare(source)
        _, records = GATE.checked_sources(source)
        self.assertEqual(set(records), {path.name for path in (ROOT/'internal/mobiletor').glob('desktop_socket_*.go')})

    def test_nonroot_build_compiles_normally_before_bounded_noprompt_sudo(self):
        with patch.object(GATE, 'privilege_tool', return_value='/usr/bin/sudo'):
            calls = self.execute('sudo')
        self.assertEqual(len(calls), 4)
        self.assertEqual(calls[0][0][0], '/captured/go')
        self.assertEqual(calls[2][0][0], str(self.compiler))

    def test_selected_toolchain_must_remain_exact_before_compiling(self):
        for fault in ('toolchain-relative', 'toolchain-changed', 'toolchain-absent'):
            with self.subTest(fault=fault), self.assertRaises(ValueError):
                self.execute(fault)

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
                    (self.source/'routervpn/mobiletor'/path.name).write_bytes(copied(path))
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

    def test_only_the_declared_shipping_import_relocation_is_accepted(self):
        fixture_root = Path(self.temp.name)/'source-repository'
        original = fixture_root/'internal/mobiletor'
        original.mkdir(parents=True)
        for item in (ROOT/'internal/mobiletor').glob('desktop_socket_*.go'):
            (original/item.name).write_bytes(item.read_bytes())
        source = original/'desktop_socket_copy_mapping.go'
        source.write_bytes(b'package mobiletor\nimport "router-vpn/internal/common"\n// unrelated import text remains exact\n')
        path = self.source/'routervpn/mobiletor'/source.name
        path.write_bytes(copied(source))
        expected = b'"github.com/sagernet/sing-box/routervpn/common"'
        self.assertIn(expected, path.read_bytes())
        with patch.object(GATE, 'ROOT', fixture_root):
            GATE.checked_sources(self.source)
            path.write_bytes(path.read_bytes().replace(expected, b'"unrelated.example/borrowed/common"'))
            with patch.object(GATE, 'run') as run, self.assertRaisesRegex(ValueError, 'differs'):
                GATE.execute(self.source, env={})
        run.assert_not_called()


if __name__ == '__main__':
    unittest.main()
