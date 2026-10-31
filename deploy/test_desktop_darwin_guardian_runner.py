#!/usr/bin/env python3
"""Exercise actual subprocess success/failure reporting without native privilege."""
from pathlib import Path
import ast
import contextlib
import importlib.util
import io
import json
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


class DarwinMutationOverlays(unittest.TestCase):
    def setUp(self):
        self.gate = GATES[0]
        tree = ast.parse(Path(self.gate.__file__).read_text())
        function = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
                        and node.name == 'execute_mutations')
        assignment = next(node for node in function.body if isinstance(node, ast.Assign)
                          and any(isinstance(name, ast.Name) and name.id == 'mutations' for name in node.targets))
        self.mutations = ast.literal_eval(assignment.value)
        self.quick = next(value for value in self.mutations if value[0] == 'quick deny before foreign pass')
        self.directory = tempfile.TemporaryDirectory(prefix='routervpn-darwin-mutation-')
        self.addCleanup(self.directory.cleanup)
        self.output = Path(self.directory.name)
        self.target = ROOT/'internal/mobiletor'

    def test_all_current_mutations_capture_their_actual_source_without_editing_it(self):
        for index, (label, case, witness, names, replacements) in enumerate(self.mutations):
            with self.subTest(label=label):
                paths = (names,) if isinstance(names, str) else names
                original = {str(self.target/name): (self.target/name).read_text() for name in paths}
                overlay = self.gate.write_mutation_overlay(self.output, index, self.target, names, replacements, label)
                actual = json.loads(overlay.read_text())['Replace']
                self.assertEqual(set(actual), set(original))
                for source, changed in actual.items():
                    self.assertEqual(Path(source).read_text(), original[source])
                    self.assertNotEqual(Path(changed).read_text(), original[source])
                    self.assertEqual(Path(changed).parent, self.output)
                self.assertTrue(case and witness)

    def test_quick_deny_control_reaches_both_baselines_without_changing_another_field(self):
        label, case, witness, names, replacements = self.quick
        self.assertEqual(case, 'ForeignBlockAndLaterPass')
        self.assertEqual(witness, 'later foreign pass bypassed nested quick deny')
        self.assertEqual(names, ('desktop_socket_darwin_pf.go', 'desktop_socket_pf_baseline.go'))
        overlay = self.gate.write_mutation_overlay(self.output, 0, self.target, names, replacements, label)
        changes = json.loads(overlay.read_text())['Replace']
        altered = []
        for source, changed in changes.items():
            before, after = Path(source).read_text(), Path(changed).read_text()
            self.assertEqual(len(before.splitlines()), len(after.splitlines()))
            for old, new in zip(before.splitlines(), after.splitlines()):
                if old != new:
                    self.assertIn('block drop out quick ', old)
                    self.assertEqual(new, old.replace('block drop out quick ', 'block drop out ', 1))
                    altered.append((Path(source).name, old))
        self.assertEqual([name for name, _ in altered], [names[0], names[1], names[1]])
        self.assertIn('desktopDarwinPFTestScope', altered[0][1])
        self.assertIn('scope, allowed, label', altered[1][1])
        self.assertIn('quick all ! tagged', altered[2][1])
        # Reproduce the obsolete single-file overlay's masking: the shared
        # production and scoped baseline guards remain quick in that version.
        old = self.gate.write_mutation_overlay(self.output, 1, self.target, names[0],
                                               (('block drop out quick ', 'block drop out '),), label)
        self.assertEqual(len(json.loads(old.read_text())['Replace']), 1)
        baseline = (self.target/names[1]).read_text()
        self.assertIn('block drop out quick %s ! tagged', baseline)
        self.assertIn('block drop out quick all ! tagged', baseline)

    def test_paired_control_rejects_missing_duplicate_or_repeated_targets_before_writing(self):
        label, _, _, names, replacements = self.quick
        for fault in ('missing', 'duplicate', 'repeated-target'):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory(prefix='routervpn-mutation-seam-') as temporary:
                root = Path(temporary)
                target, output = root/'source', root/'overlay'
                target.mkdir(); output.mkdir()
                for name in names:
                    (target/name).write_bytes((self.target/name).read_bytes())
                seam = replacements[1][0][0]
                baseline = target/names[1]
                if fault == 'missing':
                    baseline.write_text(baseline.read_text().replace(seam, '// changed captured guard', 1))
                elif fault == 'duplicate':
                    baseline.write_text(baseline.read_text()+'\n'+seam+'\n')
                selected = (names[0], names[0]) if fault == 'repeated-target' else names
                with self.assertRaises(ValueError):
                    self.gate.write_mutation_overlay(output, 0, target, selected, replacements, label)
                self.assertEqual(list(output.iterdir()), [], 'partial mutation files escaped an unproved second source')


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
