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


class MacOSNativeVerdicts(unittest.TestCase):
    def setUp(self):
        self.gate = GATES[1]
        names = ['TestMacOSOwnedControllerNative'+name for name in self.gate.CASES]
        names += ['TestDesktopMacOS'+name for name in self.gate.PARENT_CASES]
        self.lines = ['--- PASS: '+name+' (0.01s)' for name in names]
        self.output = '\n'.join(self.lines+['PASS', ''])

    def test_exact_complete_native_and_parent_cases_pass_once(self):
        self.gate.require_native_verdicts(self.output)

    def test_missing_duplicate_prefixed_subcase_and_incomplete_verdicts_fail(self):
        first = self.lines[0]
        for changed in ('', first+'\n'+first, 'diagnostic '+first,
                        first+' diagnostic', first.replace(' (', '/subcase ('),
                        first.replace('0.01s', 'unknown')):
            with self.subTest(verdict=changed), self.assertRaises(RuntimeError):
                self.gate.require_native_verdicts(self.output.replace(first, changed, 1))
        for ending in ('', 'PASS\nPASS\n', 'PASS\nextra\n'):
            with self.subTest(ending=ending), self.assertRaises(RuntimeError):
                self.gate.require_native_verdicts('\n'.join(self.lines)+'\n'+ending)

    def test_fixture_events_metadata_requires_its_unique_native_verdict(self):
        name = 'TestMacOSOwnedControllerNativeFixtureEventsPreserveCapturedDirectoryMetadata'
        line = '--- PASS: '+name+' (0.01s)'
        self.assertIn(line, self.lines)
        for changed in ('', line+'\n'+line, 'diagnostic '+line):
            with self.subTest(verdict=changed), self.assertRaises(RuntimeError):
                self.gate.require_native_verdicts(self.output.replace(line, changed, 1))

    def test_fail_skip_race_panic_fatal_or_build_failure_never_becomes_pass(self):
        for failure in ('--- FAIL: SomeOtherCase (0.01s)', '    --- SKIP: SomeCase/child (0.00s)',
                        'FAIL', 'SKIP', 'WARNING: DATA RACE', 'panic: broken',
                        'fatal error: concurrent map writes', 'FAIL package [build failed]'):
            with self.subTest(failure=failure), self.assertRaises(RuntimeError):
                self.gate.require_native_verdicts(failure+'\n'+self.output)


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


class DarwinSOCKSBoundaries(unittest.TestCase):
    def setUp(self):
        self.gate = GATES[0]
        self.address = '10.254.77.10'
        self.before = {'destination': 'default', 'gateway': '192.0.2.1', 'interface': 'en0',
                       'flags': '<UP,GATEWAY,DONE,STATIC>'}
        self.owned = {'destination': self.address, 'gateway': self.address, 'interface': 'lo0',
                      'flags': '<UP,HOST,DONE,LLINFO,STATIC,IFSCOPE,IFREF>'}
        self.present = 'lo0: flags=8049<UP,LOOPBACK,RUNNING> mtu 16384\n\tinet '+self.address+' netmask 0xffffffff\n'
        self.absent = 'lo0: flags=8049<UP,LOOPBACK,RUNNING> mtu 16384\n\tinet 127.0.0.1 netmask 0xff000000\n'

    def route(self, values):
        return '\n'.join('   '+key+': '+value for key, value in values.items())+'\n'

    def test_original_route_must_be_unambiguous_default(self):
        self.gate.require_default_route(self.gate.native_route(self.route(self.before)))
        for changed in (dict(self.before, destination=self.address), dict(self.before, mask='255.0.0.0'),
                        dict(self.before, flags='<UP,HOST>')):
            with self.subTest(route=changed), self.assertRaises(ValueError):
                self.gate.require_default_route(self.gate.native_route(self.route(changed)))
        for raw in ('destination: default\n', self.route(self.before)+'interface: lo0\n'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                self.gate.native_route(raw)

    def test_exact_private_alias_rejects_changed_interface_mask_and_duplicate(self):
        self.assertTrue(self.gate.private_alias_present(self.present, self.address))
        self.assertFalse(self.gate.private_alias_present(self.absent, self.address))
        for changed in (self.present.replace('lo0:', 'en0:'), self.present.replace('0xffffffff', '0xffffff00'),
                        self.present+self.present):
            with self.subTest(alias=changed), self.assertRaises(ValueError):
                self.gate.private_alias_present(changed, self.address)

    def test_native_route_requires_exact_host_on_owned_interface(self):
        for changed in (dict(self.owned, destination='10.254.77'), dict(self.owned, interface='en0'),
                        dict(self.owned, flags='<UP,DONE>'), dict(self.owned, mask='255.255.255.0')):
            with self.subTest(route=changed), mock.patch.object(self.gate, 'system', return_value=(self.route(changed), '')), self.assertRaises(ValueError):
                self.gate.private_alias_route(self.address)
        with mock.patch.object(self.gate, 'system', return_value=(self.route(self.owned), '')):
            self.assertEqual(self.gate.private_alias_route(self.address), self.owned)

    def test_joined_alias_retirement_deletes_only_original_address_and_reads_absence(self):
        replies = [(self.present, ''), (self.route(self.owned), ''), ('', ''),
                   (self.absent, ''), (self.route(self.before), '')]
        with mock.patch.object(self.gate, 'system', side_effect=replies) as call:
            self.gate.retire_private_alias(self.address, self.before, self.owned)
        self.assertEqual([item.args[0] for item in call.call_args_list], [
            ['/sbin/ifconfig', '-a'], ['/sbin/route', '-n', 'get', self.address],
            ['/sbin/ifconfig', 'lo0', 'inet', self.address, '-alias'],
            ['/sbin/ifconfig', '-a'], ['/sbin/route', '-n', 'get', self.address]])

    def test_partial_creation_is_joined_but_changed_route_never_deleted(self):
        with mock.patch.object(self.gate, 'system', side_effect=[(self.present, ''), (self.route(self.owned), ''), ('', ''), (self.absent, ''), (self.route(self.before), '')]):
            self.gate.retire_private_alias(self.address, self.before, None)
        with mock.patch.object(self.gate, 'system', side_effect=[(self.present, ''), (self.route(dict(self.owned, gateway='10.254.77.11')), '')]) as call, self.assertRaises(ValueError):
            self.gate.retire_private_alias(self.address, self.before, self.owned)
        self.assertFalse(any('-alias' in item.args[0] for item in call.call_args_list))
        with mock.patch.object(self.gate, 'system', side_effect=[(self.absent, ''), (self.absent, ''), (self.route(dict(self.before, gateway='192.0.2.2')), '')]), self.assertRaises(ValueError):
            self.gate.retire_private_alias(self.address, self.before, self.owned)

    def verdicts(self):
        root = self.gate.native_case_name('SOCKSAssociations')
        names = [root]+[root+'/ipv'+family for family in ('4', '6')]
        names += [root+'/ipv'+family+'/'+leaf for family in ('4', '6') for leaf in self.gate.SOCKS_LEAVES]
        return ['--- PASS: '+name+' (0.01s)' for name in names]

    def test_all_seventeen_actual_socks_verdicts_are_required_once(self):
        lines = self.verdicts()
        self.assertEqual(len(lines), 17)
        self.gate.require_socks_verdicts('\n'.join(lines))
        for line in lines:
            for change in ('', line+'\n'+line, 'diagnostic '+line, line.replace('PASS', 'FAIL'), line.replace('PASS', 'SKIP')):
                with self.subTest(line=line, change=change), self.assertRaises(ValueError):
                    self.gate.require_socks_verdicts('\n'.join(lines).replace(line, change, 1))
        for failure in ('WARNING: DATA RACE', 'panic: fixture', 'fatal error: fixture', 'FAIL package [build failed]'):
            with self.subTest(failure=failure), self.assertRaises(ValueError):
                self.gate.require_socks_verdicts('\n'.join(lines+[failure]))

    def test_default_gate_runs_separate_owned_private_fixture_and_requires_its_verdicts(self):
        gate = self.gate
        original = ['--- PASS: '+gate.native_case_name(name)+' (0.01s)' for name in gate.CASES+gate.READBACK_CASES]
        original += ['--- PASS: TestDesktopPFABIRejectsUnprovedKernel (0.01s)']
        original += ['--- PASS: TestDesktopDarwinGuardian'+name+' (0.01s)' for name in
                     ('ChannelFragmentsAndDescriptorClosure', 'CurrentFreshnessAndStateScope', 'UIDAbsenceWait', 'UIDObserverProtocol')]
        original += ['--- PASS: TestDesktopDarwinGuardianKernelTCPAndUDP/'+network+' (0.01s)' for network in ('tcp4', 'udp4', 'tcp6', 'udp6')]
        for missing in (False, True):
            calls = []
            def run(command, **kwargs):
                calls.append(command)
                if 'test' in command:
                    Path(command[command.index('-o')+1]).write_bytes(b'runner invocation fixture only')
                    return ''
                if '--case' in command:
                    self.assertEqual(command[-2:], ['--case', 'SOCKSAssociations'])
                    return '\n'.join(self.verdicts()[1:] if missing else self.verdicts())+'\n'
                return '\n'.join(original)+'\n'
            with self.subTest(missing=missing), mock.patch.object(gate.platform, 'system', return_value='Darwin'), mock.patch.dict(os.environ, {'GOOS': 'darwin'}), mock.patch.object(gate.UID, 'compiler_toolchain', side_effect=lambda source, go, env: ('fixture-go', env)), mock.patch.object(gate.UID, 'privilege_tool', return_value=None), mock.patch.object(gate, 'reported_run', side_effect=run), contextlib.redirect_stdout(io.StringIO()):
                if missing:
                    with self.assertRaises(ValueError):
                        gate.execute(ROOT)
                else:
                    gate.execute(ROOT)
            self.assertEqual(len(calls), 3)
            self.assertNotIn('--case', calls[1])
            self.assertEqual(calls[2], calls[1]+['--case', 'SOCKSAssociations'])

    def test_mutation_requires_exact_assertion_and_join_without_timeout_or_race(self):
        witness = 'SOCKS control retired before its original UDP descriptor'
        line = '--- FAIL: TestDesktopDarwinGuardianKernelSOCKSAssociations (0.01s)'
        output = '    fixture.go:1: '+witness+'\n'+line+'\nFAIL\n'
        self.gate.require_mutation_failure(output, 'SOCKSAssociations', witness)
        for changed in ('diagnostic '+line, line+'\n'+line, line.replace('FAIL', 'PASS'), ''):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                self.gate.require_mutation_failure(output.replace(line, changed), 'SOCKSAssociations', witness)
        for failure in ('panic: test timed out', 'WARNING: DATA RACE', 'fatal error: fixture',
                        'Native fixture cleanup retained its recovery record', 'Darwin kernel test exceeded its bounded lifetime',
                        '--- SKIP: MissingBoundary (0.00s)', 'FAIL package [build failed]'):
            with self.subTest(failure=failure), self.assertRaises(ValueError):
                self.gate.require_mutation_failure(output+failure, 'SOCKSAssociations', witness)

    def test_six_controls_are_shipping_source_mutations_with_exact_required_witnesses(self):
        tree = ast.parse(Path(self.gate.__file__).read_text())
        function = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'execute_mutations')
        assignment = next(node for node in function.body if isinstance(node, ast.Assign) and any(isinstance(name, ast.Name) and name.id == 'mutations' for name in node.targets))
        mutations = [value for value in ast.literal_eval(assignment.value) if value[1] == 'SOCKSAssociations']
        self.assertEqual(len(mutations), 6)
        self.assertEqual(len({value[0] for value in mutations}), 6)
        test = (ROOT/'internal/mobiletor/desktop_socket_darwin_guardian_test.go').read_text()
        for label, _, witness, name, replacements in mutations:
            self.assertIn(witness, test)
            names, changes = ((name,), (replacements,)) if isinstance(name, str) else (name, replacements)
            for path, edits in zip(names, changes):
                raw = (ROOT/'internal/mobiletor'/path).read_text()
                for old, new in edits:
                    self.assertEqual(raw.count(old), 1, label)
                    self.assertNotEqual(old, new)


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


class DarwinOriginalControlLifetime(unittest.TestCase):
    def test_actual_control_method_joins_rejected_grant_and_preserves_other_operations(self):
        spec = importlib.util.spec_from_file_location('darwin_control_lifetime', ROOT/'deploy/test_desktop_darwin_control_lifetime.py')
        regression = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(regression)
        regression.execute(ROOT)


if __name__ == '__main__':
    unittest.main(verbosity=2)
