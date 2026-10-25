#!/usr/bin/env python3
"""Exercise Cargo's actual pipe boundary independently of the host code page."""
from pathlib import Path
import contextlib
import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('desktop_pq_output', ROOT/'deploy/build-desktop-pq.py')
PQ = importlib.util.module_from_spec(spec)
spec.loader.exec_module(PQ)
spec = importlib.util.spec_from_file_location('desktop_native_output', ROOT/'deploy/build-native-runtime.py')
NATIVE = importlib.util.module_from_spec(spec)
spec.loader.exec_module(NATIVE)


class CargoOutput(unittest.TestCase):
    def child(self, stdout=b'', stderr=b'', exit_code=0):
        return [sys.executable, '-c',
                'import sys; '
                f'sys.stdout.buffer.write({stdout!r}); '
                'sys.stdout.buffer.flush(); '
                f'sys.stderr.buffer.write({stderr!r}); '
                'sys.stderr.buffer.flush(); '
                f'sys.exit({exit_code})']

    def metadata(self, stdout, stderr=b'', exit_code=0):
        real_run = subprocess.run
        environment = {**os.environ, 'ROUTERVPN_METADATA_TEST': 'captured'}
        expected = ['cargo', 'metadata', '--locked', '--format-version=1',
                    '--manifest-path', str(ROOT/'mobile/rosenpass/Cargo.toml')]
        calls = []

        def execute(command, **kwargs):
            self.assertEqual(command, expected)
            self.assertEqual(kwargs['env'], environment)
            self.assertEqual(kwargs['timeout'], 1800)
            calls.append(command)
            # Substitute only the executable boundary; keep the real pipes,
            # reader threads, decoding and exit handling of subprocess.run.
            return real_run(self.child(stdout, stderr, exit_code), **kwargs)

        with mock.patch.object(subprocess, '_text_encoding', return_value='cp1252'), \
                mock.patch.object(subprocess, 'run', side_effect=execute):
            result = PQ.locked_metadata(environment)
        self.assertEqual(len(calls), 1)
        return result

    def test_utf8_metadata_isolated_from_utf8_stderr_on_legacy_codepage(self):
        expected = {'packages': [{'name': 'rosenpass',
                                 'description': 'captured-\u3041',
                                 'source': 'git+https://example.invalid/pinned#'+PQ.REVISION}]}
        encoded = json.dumps(expected, ensure_ascii=False).encode('utf-8')
        self.assertIn(b'\x81', encoded)  # Undefined in Windows CP1252.
        diagnostics = '  Downloaded dépendance · \u3041\n'.encode('utf-8')
        self.assertEqual(self.metadata(encoded, diagnostics), expected)

    def test_malformed_utf8_metadata_is_rejected(self):
        with self.assertRaises(UnicodeDecodeError):
            self.metadata(b'{"packages":[],"description":"\xff"}')

    def test_cargo_progress_stays_outside_json(self):
        self.assertEqual(self.metadata(b'{"packages":[]}', b'Updating registry\nDownloaded crate\n'),
                         {'packages': []})

    def test_stdout_progress_cannot_be_recovered_as_metadata(self):
        with self.assertRaises(json.JSONDecodeError):
            self.metadata(b'Downloading dependency\n{"packages":[]}')

    def test_second_json_record_is_rejected(self):
        with self.assertRaises(json.JSONDecodeError):
            self.metadata(b'{"packages":[]}\n{"packages":[]}')

    def test_failed_cargo_does_not_publish_valid_looking_json(self):
        diagnostics = io.StringIO()
        with contextlib.redirect_stdout(diagnostics), self.assertRaises(subprocess.CalledProcessError) as error:
            self.metadata(b'{"packages":[]}', 'metadata failed · \u3041\n'.encode('utf-8')+b'\xff', 17)
        self.assertEqual(error.exception.returncode, 17)
        self.assertIn('metadata failed · \u3041', diagnostics.getvalue())
        self.assertIn('\ufffd', diagnostics.getvalue())

    def test_combined_compiler_output_keeps_exact_dependency_note(self):
        stderr = ('Compiling dépendance · \u3041\n'
                  'note: native-static-libs: -lwindows -ladvapi32 -lws2_32\n').encode('utf-8')
        with mock.patch.object(subprocess, '_text_encoding', return_value='cp1252'):
            output = PQ.run(self.child('Building protocole · \u3041\n'.encode('utf-8'), stderr))
        self.assertIn('Compiling dépendance · \u3041', output)
        self.assertIn('Building protocole · \u3041', output)
        self.assertEqual(PQ.link_flags(output), ['-lwindows', '-ladvapi32', '-lws2_32'])

    def test_dependency_note_must_be_single_and_exact(self):
        for stderr in (b'no dependency note\n',
                       b'note: native-static-libs: -lc\nnote: native-static-libs: -lm\n',
                       b'note: native-static-libs: -lc -Lunowned\n',
                       b'note: native-static-libs: -lc @response\n'):
            with self.subTest(stderr=stderr), self.assertRaises(ValueError):
                PQ.link_flags(PQ.run(self.child(stderr=stderr)))

    def test_uncaptured_command_keeps_inherited_output(self):
        self.assertEqual(PQ.run(self.child(), capture=False), '')


class NativeRuntimeOutput(unittest.TestCase):
    child = CargoOutput.child

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='native-license-output-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.stage = self.root/'bundle'
        self.stage.mkdir()
        source = self.root/'pinned-source'
        (source/'rosenpass').mkdir(parents=True)
        self.licenses = {'LICENSE-MIT': 'MIT license · \u3041\n'.encode(),
                         'LICENSE-APACHE': b'Apache license\n'}
        for name, raw in self.licenses.items():
            (source/name).write_bytes(raw)
        self.package = {'name': 'rosenpass', 'description': 'protocol-\u3041',
                        'source': 'git+https://example.invalid/rosenpass#'+PQ.REVISION,
                        'manifest_path': str(source/'rosenpass/Cargo.toml')}

    def metadata(self, stdout, stderr=b'', exit_code=0):
        real_run = subprocess.run
        env = {**os.environ, 'ROUTERVPN_NATIVE_LICENSE_TEST': 'captured'}
        expected = ['cargo', 'metadata', '--locked', '--format-version=1',
                    '--manifest-path', str(ROOT/'mobile/rosenpass/Cargo.toml')]
        calls = []

        def execute(command, **kwargs):
            self.assertEqual(command, expected)
            self.assertEqual(kwargs['env'], env)
            self.assertEqual(kwargs['timeout'], 1800)
            # Exercise the shipping license collector and real pipe/exit
            # handling. Only replace the Cargo executable at its boundary.
            self.assertEqual(kwargs['stdout'], subprocess.PIPE)
            self.assertEqual(kwargs['stderr'], subprocess.PIPE)
            self.assertTrue(kwargs['check'])
            self.assertNotIn('text', kwargs)
            self.assertNotIn('encoding', kwargs)
            calls.append(command)
            return real_run(self.child(stdout, stderr, exit_code), **kwargs)

        with mock.patch.object(subprocess, '_text_encoding', return_value='cp1252'), \
                mock.patch.object(subprocess, 'run', side_effect=execute):
            try:
                NATIVE.stage_pq_licenses(self.stage, env)
            finally:
                self.assertEqual(len(calls), 1)

    def encoded(self, packages=None):
        return json.dumps({'packages': [self.package] if packages is None else packages},
                          ensure_ascii=False).encode('utf-8')

    def test_actual_license_metadata_utf8_and_stderr_on_legacy_codepage(self):
        metadata = self.encoded()
        self.assertIn(b'\x81', metadata)
        self.metadata(metadata, 'Cargo license diagnostic · \u3041\n'.encode())
        self.assertEqual({p.name: p.read_bytes() for p in self.stage.iterdir()},
                         {'ROSENPASS-'+name: raw for name, raw in self.licenses.items()})

    def test_invalid_utf8_or_non_json_stdout_cannot_stage_licenses(self):
        for raw, error in ((b'{"packages":[],"description":"\xff"}', UnicodeDecodeError),
                           (b'Downloading dependency\n'+self.encoded(), json.JSONDecodeError),
                           (self.encoded()+b'\n{"packages":[]}', json.JSONDecodeError)):
            with self.subTest(raw=raw), self.assertRaises(error):
                self.metadata(raw)
            self.assertEqual(list(self.stage.iterdir()), [])

    def test_failed_cargo_cannot_stage_valid_looking_license_metadata(self):
        with self.assertRaises(subprocess.CalledProcessError) as error:
            self.metadata(self.encoded(), b'license metadata failed\n', 17)
        self.assertEqual(error.exception.returncode, 17)
        self.assertEqual(error.exception.output, self.encoded())
        self.assertEqual(list(self.stage.iterdir()), [])

    def test_license_provenance_stays_exact_and_unambiguous(self):
        foreign = {**self.package, 'source': 'git+https://example.invalid/rosenpass#'+'0'*40}
        for packages in ([], [foreign], [self.package, self.package]):
            with self.subTest(packages=packages), self.assertRaisesRegex(ValueError, 'provenance'):
                self.metadata(self.encoded(packages))
            self.assertEqual(list(self.stage.iterdir()), [])

    def test_runtime_command_keeps_cwd_environment_and_strips_utf8_stdout(self):
        env = {**os.environ, 'ROUTERVPN_NATIVE_OUTPUT_TEST': 'captured-\u3041'}
        command = [sys.executable, '-c',
                   'import json, os, sys; '
                   'raw=json.dumps([os.getcwd(), os.environ["ROUTERVPN_NATIVE_OUTPUT_TEST"]], '
                   'ensure_ascii=False).encode(); sys.stdout.buffer.write(b" "+raw+b"\\n ")']
        with mock.patch.object(subprocess, '_text_encoding', return_value='cp1252'):
            output = NATIVE.run(command, cwd=self.root, env=env, timeout=30)
        self.assertEqual(json.loads(output), [str(self.root.resolve()), 'captured-\u3041'])
        self.assertEqual(output, output.strip())

    def test_runtime_stdout_retains_universal_newline_behavior(self):
        self.assertEqual(NATIVE.run(self.child(b' \r\none\r\ntwo\rthree\n ')),
                         'one\ntwo\nthree')


if __name__ == '__main__':
    unittest.main()
