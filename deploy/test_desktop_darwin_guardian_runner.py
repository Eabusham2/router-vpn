#!/usr/bin/env python3
"""Exercise actual subprocess success/failure reporting without native privilege."""
from pathlib import Path
import contextlib
import importlib.util
import io
import os
import shlex
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
GATES = []
for name in ('test_desktop_darwin_guardian', 'test_macos_controller_privilege'):
    spec = importlib.util.spec_from_file_location(name+'_diagnostic_fixture', ROOT/'deploy'/f'{name}.py')
    gate = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gate)
    GATES.append(gate)


class DarwinNativeDiagnostics(unittest.TestCase):
    def test_actual_failed_command_exposes_bounded_tail_and_remains_failure(self):
        diagnostic = 'actual compiler fixture: missing required declaration'
        command = [sys.executable, '-c',
                   "import os,sys; os.write(2, b'x'*60000+b'\\xff\\n'+"+repr(diagnostic.encode())+"); sys.exit(42)"]
        for gate in GATES:
            with self.subTest(runner=gate.__name__):
                shown = io.StringIO()
                with contextlib.redirect_stderr(shown), self.assertRaises(subprocess.CalledProcessError) as failed:
                    gate.reported_run(command, timeout=5)
                self.assertEqual(failed.exception.returncode, 42)
                self.assertIn(diagnostic, shown.getvalue())
                self.assertIn('Darwin native command failure output (bounded tail):', shown.getvalue())
                self.assertIn('\ufffd', shown.getvalue())
                self.assertLessEqual(len(shown.getvalue()), 24*1024+128)
                self.assertGreater(len(failed.exception.output), 60000, 'the original failure evidence was discarded')

    def test_actual_success_returns_evidence_without_fabricating_failure_output(self):
        for gate in GATES:
            with self.subTest(runner=gate.__name__):
                shown = io.StringIO()
                with contextlib.redirect_stderr(shown):
                    output = gate.reported_run([sys.executable, '-c', "print('actual successful command')"], timeout=5)
                self.assertEqual(output, 'actual successful command\n')
                self.assertEqual(shown.getvalue(), '')


class MacOSPythonDiscovery(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='routervpn-python-discovery-')
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        source = (ROOT / 'client/install-macos-native.sh').read_text()
        start = source.index('routervpn_discover_install_python() {\n')
        self.function = source[start:source.index('\n}\n', start) + 3]

    def candidate(self, name, code=0, executable=True):
        path = self.root / name
        path.write_text('#!/bin/sh\n'
                        '[ "$1" = -EsS ] && [ "$2" = -c ] && [ "$#" -eq 3 ] || exit 91\n'
                        'printf ran >> ' + shlex.quote(str(self.root / (name + '.ran'))) + '\n'
                        'printf suppressed-output\n'
                        'exit ' + str(code) + '\n')
        path.chmod(0o700 if executable else 0o600)
        return path

    def discover(self, *candidates, env=None):
        return subprocess.run(['/bin/bash', '-c', self.function + '\nroutervpn_discover_install_python "$@"',
                               'discovery-fixture', *map(str, candidates)], cwd=self.root,
                              env=env, text=True, capture_output=True, timeout=5)

    def test_actual_shipping_selector_preserves_priority_and_hides_probe_output(self):
        first, second = self.candidate('first'), self.candidate('second')
        result = self.discover(first, second)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, str(first) + '\n')
        self.assertFalse((self.root / 'second.ran').exists())

    def test_actual_shipping_selector_skips_missing_nonexecuting_and_unsupported_candidates(self):
        blocked, old, selected = self.candidate('blocked', executable=False), self.candidate('old', code=1), self.candidate('selected')
        result = self.discover(self.root / 'missing', blocked, old, selected)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, str(selected) + '\n')
        self.assertFalse((self.root / 'blocked.ran').exists())
        self.assertTrue((self.root / 'old.ran').exists())

    def test_actual_shipping_selector_never_substitutes_ambient_path_python(self):
        self.candidate('python3')
        result = self.discover(self.root / 'missing', env=dict(os.environ, PATH=str(self.root)))
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, '')
        self.assertIn('Install Python 3.9 or newer', result.stderr)
        self.assertFalse((self.root / 'python3.ran').exists())

    def test_native_wrapper_captures_ordinary_user_before_any_discovery_execution(self):
        gate = GATES[1]
        account = type('Account', (), {'pw_gid': 41, 'pw_dir': '/Users/fixture'})()
        reply = subprocess.CompletedProcess([], 0, '/Library/Developer/CommandLineTools/usr/bin/python3\n', '')
        with mock.patch.object(gate.os, 'geteuid', return_value=0), mock.patch.object(gate.pwd, 'getpwuid', return_value=account), mock.patch.object(gate.subprocess, 'run', return_value=reply) as run:
            self.assertEqual(gate.discover_python(501), reply.stdout.rstrip('\n'))
            arguments, options = run.call_args
            self.assertEqual(arguments[0], ['/bin/bash', str(ROOT / 'client/install-macos-native.sh'), '--discover-python'])
            self.assertEqual((options['user'], options['group'], options['extra_groups']), (501, 41, []))
            self.assertEqual(options['env'], {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'HOME': '/Users/fixture', 'LC_ALL': 'C'})
        with mock.patch.object(gate.os, 'geteuid', return_value=0), mock.patch.object(gate.subprocess, 'run') as run:
            with self.assertRaises(ValueError):
                gate.discover_python(0)
            run.assert_not_called()


if __name__ == '__main__':
    unittest.main(verbosity=2)
