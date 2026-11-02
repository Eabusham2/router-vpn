#!/usr/bin/env python3
"""Keep the serial Tor importer gate complete, bounded and fail closed."""
from pathlib import Path
from contextlib import redirect_stdout, redirect_stderr
import importlib.util
import io
import json
import re
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('tor_forms', Path(__file__).with_name('test_desktop_tor_bridge_forms.py'))
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)


def events(cases):
    package, root = RUNNER.PAYLOAD_PACKAGE, RUNNER.PAYLOAD_ROOT
    result = [dict(Action='start', Package=package), dict(Action='run', Package=package, Test=root)]
    for case in sorted(cases):
        result += [dict(Action='run', Package=package, Test=case), dict(Action='pass', Package=package, Test=case)]
    result += [dict(Action='pass', Package=package, Test=root), dict(Action='pass', Package=package)]
    return result


def encoded(records):
    return ''.join(json.dumps(record) + '\n' for record in records)


class TorImporterPhases(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='routervpn-tor-phase-contract-')
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        for name in RUNNER.CATALOG_FILES:
            (self.directory / name).write_text('{}')
        self.transports = {'obfs4': ['fixture'], 'meek_lite': ['fixture'], 'snowflake': ['fixture'],
                           'webtunnel': ['fixture'], 'tor': []}
        (self.directory / 'tor-update-input-lines.json').write_text(json.dumps(self.transports))
        self.expected = RUNNER.payload_cases(self.directory, 'windows')
        self.env = {'ROUTERVPN_TOR_FORM_PAYLOADS': str(self.directory), 'CAPTURED_COMPILER': 'exact'}

    def test_every_windows_leaf_belongs_to_exactly_one_bounded_phase(self):
        self.assertEqual(len(self.expected), 365)
        phases = RUNNER.payload_phases(self.expected)
        self.assertEqual([(name, len(cases)) for name, _, cases in phases],
                         [('direct-and-router', 109), ('ordinary-entry', 128), ('plain-ordinary-entry', 128)])
        observed = []
        for _, selector, required in phases:
            root, choice = selector.split('/', 1)
            selected = {case for case in self.expected
                        if re.fullmatch(root, case.split('/')[0]) and re.fullmatch(choice, case.split('/')[1])}
            self.assertEqual(selected, set(required))
            observed.extend(selected)
        self.assertEqual(len(observed), len(set(observed)))
        self.assertEqual(set(observed), set(self.expected))

    def test_linux_requires_all_eight_actual_dynamic_direct_outputs(self):
        with self.assertRaisesRegex(RuntimeError, 'Direct form payload'):
            RUNNER.payload_cases(self.directory, 'linux')
        for transport in ('meek_lite', 'snowflake', 'webtunnel', 'tor'):
            for kill in ('on-connect', 'always'):
                (self.directory / f'tor-create-dynamic-{transport}-{kill}.json').write_text('{}')
        cases = RUNNER.payload_cases(self.directory, 'linux')
        self.assertEqual(len(cases), 373)
        self.assertEqual(len(RUNNER.payload_phases(cases)[0][2]), 117)
        with self.assertRaisesRegex(RuntimeError, 'Direct form payload'):
            RUNNER.payload_cases(self.directory, 'windows')

    def test_missing_or_new_go_source_catalog_cannot_silently_drop_selection(self):
        catalog = self.directory / 'tor-update-source-catalog.json'
        catalog.unlink()
        with patch.object(RUNNER.subprocess, 'run') as execute, self.assertRaisesRegex(RuntimeError, 'complete Go source catalog'):
            RUNNER.run_payload_phases(self.directory, 'windows', self.env)
        execute.assert_not_called()
        catalog.write_text('{}')
        (self.directory / 'tor-update-new-mode-source-catalog.json').write_text('{}')
        with self.assertRaisesRegex(RuntimeError, 'complete Go source catalog'):
            RUNNER.payload_cases(self.directory, 'windows')

    def test_actual_catalog_transport_requires_all_its_leaf_verdicts(self):
        self.transports['new-transport'] = ['fixture']
        (self.directory / 'tor-update-input-lines.json').write_text(json.dumps(self.transports))
        expanded = RUNNER.payload_cases(self.directory, 'windows')
        self.assertEqual(len(expanded - self.expected), 22 * 3)
        with self.assertRaisesRegex(RuntimeError, 'omitted'):
            RUNNER.verify_payload_verdicts(encoded(events(self.expected)), expanded)

    def test_every_leaf_must_have_both_run_and_pass_verdicts(self):
        original = events(self.expected)
        for case in self.expected:
            for action in ('run', 'pass'):
                with self.subTest(case=case, action=action), self.assertRaisesRegex(RuntimeError, 'omitted'):
                    RUNNER.verify_payload_verdicts(encoded(record for record in original
                        if not (record.get('Test') == case and record['Action'] == action)), self.expected)

    def test_duplicate_leaf_and_package_verdicts_are_rejected(self):
        for index in (2, 3, -1):
            modified = events(self.expected)
            position = index if index >= 0 else len(modified) - 1
            modified.insert(position + 1, dict(modified[position]))
            with self.subTest(index=index), self.assertRaisesRegex(RuntimeError, 'duplicated'):
                RUNNER.verify_payload_verdicts(encoded(modified), self.expected)

    def test_failed_and_skipped_verdicts_stay_failed_even_with_success_exit(self):
        for action in ('fail', 'skip'):
            modified = events(self.expected)
            modified[3]['Action'] = action
            with self.subTest(action=action), self.assertRaisesRegex(RuntimeError, 'failed or skipped'):
                RUNNER.verify_payload_verdicts(encoded(modified), self.expected)

    def test_unexpected_case_or_foreign_package_cannot_satisfy_coverage(self):
        modified = events(self.expected)
        modified[2]['Test'] = RUNNER.PAYLOAD_ROOT + '/unrequested-source'
        with self.assertRaisesRegex(RuntimeError, 'unexpected case'):
            RUNNER.verify_payload_verdicts(encoded(modified), self.expected)
        modified = events(self.expected)
        modified[3]['Package'] = 'foreign/package'
        with self.assertRaisesRegex(RuntimeError, 'different package'):
            RUNNER.verify_payload_verdicts(encoded(modified), self.expected)

    def test_root_and_package_completion_are_mandatory(self):
        for remove in (-2, -1):
            modified = events(self.expected)
            del modified[remove]
            with self.subTest(remove=remove), self.assertRaisesRegex(RuntimeError, 'omitted'):
                RUNNER.verify_payload_verdicts(encoded(modified), self.expected)

    def test_malformed_output_and_out_of_order_pass_cannot_be_verdicts(self):
        for malformed in ('not json\n', '[]\n'):
            with self.subTest(malformed=malformed), self.assertRaisesRegex(RuntimeError, 'malformed'):
                RUNNER.verify_payload_verdicts(malformed, self.expected)
        modified = events(self.expected)
        modified[2], modified[3] = modified[3], modified[2]
        with self.assertRaisesRegex(RuntimeError, 'omitted'):
            RUNNER.verify_payload_verdicts(encoded(modified), self.expected)

    def test_serial_commands_preserve_race_counts_timeouts_environment_and_all_leaves(self):
        completed = []
        def execute(command, **options):
            self.assertEqual(command[:7], ['go', 'test', '-json', '-race', '-count=1', './cmd/client', '-run'])
            self.assertEqual(command[-1], '-timeout=60s')
            self.assertEqual(options['timeout'], 180)
            self.assertIs(options['env'], self.env)
            self.assertEqual(options['cwd'], RUNNER.ROOT)
            self.assertEqual(options['stdout'], subprocess.PIPE)
            self.assertEqual(options['stderr'], subprocess.PIPE)
            root, choice = command[7].split('/', 1)
            cases = {case for case in self.expected
                     if re.fullmatch(root, case.split('/')[0]) and re.fullmatch(choice, case.split('/')[1])}
            completed.extend(cases)
            return subprocess.CompletedProcess(command, 0, encoded(events(cases)))
        with patch.object(RUNNER.subprocess, 'run', side_effect=execute) as run, redirect_stdout(io.StringIO()):
            RUNNER.run_payload_phases(self.directory, 'windows', self.env)
        self.assertEqual(run.call_count, 3)
        self.assertEqual(set(completed), set(self.expected))
        self.assertEqual(len(completed), len(self.expected))

    def test_omitted_or_overlapping_phase_fails_before_executing_anything(self):
        phases = RUNNER.payload_phases(self.expected)
        for broken in (phases[:-1], phases + [phases[0]]):
            with patch.object(RUNNER, 'payload_phases', return_value=broken), patch.object(RUNNER.subprocess, 'run') as run:
                with self.assertRaisesRegex(RuntimeError, 'phases'):
                    RUNNER.run_payload_phases(self.directory, 'windows', self.env)
                run.assert_not_called()

    def test_nonzero_child_keeps_original_failure_and_does_not_run_later_phases(self):
        result = subprocess.CompletedProcess(['go'], 17, 'original fixture refusal\n', 'original compiler diagnostic\n')
        output, diagnostic = io.StringIO(), io.StringIO()
        with patch.object(RUNNER.subprocess, 'run', return_value=result) as run, redirect_stdout(output), redirect_stderr(diagnostic):
            with self.assertRaises(subprocess.CalledProcessError) as raised:
                RUNNER.run_payload_phases(self.directory, 'windows', self.env)
        self.assertEqual(raised.exception.returncode, 17)
        self.assertEqual(output.getvalue(), result.stdout)
        self.assertEqual(diagnostic.getvalue(), result.stderr)
        run.assert_called_once()

    def test_zero_exit_missing_leaf_keeps_output_and_stops_serial_gate(self):
        cases = RUNNER.payload_phases(self.expected)[0][2]
        incomplete = set(cases) - {next(iter(cases))}
        result = subprocess.CompletedProcess(['go'], 0, encoded(events(incomplete)))
        output = io.StringIO()
        with patch.object(RUNNER.subprocess, 'run', return_value=result) as run, redirect_stdout(output):
            with self.assertRaisesRegex(RuntimeError, 'omitted'):
                RUNNER.run_payload_phases(self.directory, 'windows', self.env)
        self.assertEqual(output.getvalue(), result.stdout)
        run.assert_called_once()

    def test_outer_timeout_keeps_output_and_does_not_retry_or_continue(self):
        original = subprocess.TimeoutExpired(['go'], 180, output=b'original timed out importer\n', stderr=b'original driver diagnostic\n')
        output, diagnostic = io.StringIO(), io.StringIO()
        with patch.object(RUNNER.subprocess, 'run', side_effect=original) as run, redirect_stdout(output), redirect_stderr(diagnostic):
            with self.assertRaises(subprocess.TimeoutExpired) as raised:
                RUNNER.run_payload_phases(self.directory, 'windows', self.env)
        self.assertIs(raised.exception, original)
        self.assertEqual(output.getvalue(), 'original timed out importer\n')
        self.assertEqual(diagnostic.getvalue(), 'original driver diagnostic\n')
        run.assert_called_once()

    def test_actual_os_pipes_keep_driver_diagnostics_separate_from_strict_json(self):
        actual_run = subprocess.run
        runs = []
        def execute(command, **options):
            _, choice = command[7].split('/', 1)
            cases = {case for case in self.expected if re.fullmatch(choice, case.split('/')[1])}
            payload = self.directory / ('pipe-' + str(len(runs)) + '.jsonl')
            payload.write_text(encoded(events(cases)))
            runs.append(command)
            script = ('import pathlib,sys; sys.stderr.write("go: compiler diagnostic on stderr\\n"); '
                      'sys.stdout.write(pathlib.Path(sys.argv[1]).read_text())')
            return actual_run([sys.executable, '-c', script, str(payload)], **options)
        output, diagnostic = io.StringIO(), io.StringIO()
        with patch.object(RUNNER.subprocess, 'run', side_effect=execute), redirect_stdout(output), redirect_stderr(diagnostic):
            RUNNER.run_payload_phases(self.directory, 'windows', self.env)
        self.assertEqual(len(runs), 3)
        self.assertEqual(diagnostic.getvalue(), 'go: compiler diagnostic on stderr\n' * 3)
        self.assertIn('365 distinct leaves PASS', output.getvalue())

    def test_main_keeps_actual_catalog_and_each_windows_shell_before_importer(self):
        for shell in ('powershell.exe', 'pwsh.exe'):
            calls = []
            def catalog(command, **options):
                self.assertIn('^TestDesktopTorBridgeUpdateFormCatalog$', command)
                self.assertEqual(command[-1], '-timeout=60s')
                self.assertEqual(options['timeout'], 180)
                self.assertTrue(options['check'])
                calls.append('catalog')
            with self.subTest(shell=shell), patch.object(sys, 'argv', ['tor', '--platform', 'windows', '--shell', shell]), \
                    patch.object(RUNNER.subprocess, 'run', side_effect=catalog), \
                    patch.object(RUNNER, 'windows_form', side_effect=lambda directory, selected: calls.append(selected)), \
                    patch.object(RUNNER, 'run_payload_phases', side_effect=lambda *args: calls.append('importer')), redirect_stdout(io.StringIO()):
                RUNNER.main()
            self.assertEqual(calls, ['catalog', shell, 'importer'])


def editor_progress():
    phases = [('ast-extraction', 0), ('input-controls', 0), ('wpf-initialization', 0)]
    phases += [('selection', index) for index in range(1, 23)]
    phases += [('direct-cases', 0), ('window-close', 0)]
    lines = []
    elapsed = checks = 0
    for phase, ordinal in phases:
        lines.append(f'RouterVPN Tor editor phase={phase} event=start selection={ordinal} '
                     f'checks={checks} elapsed_ms={elapsed} phase_ms=0')
        elapsed += 3
        if phase == 'selection':
            checks += 100
        elif phase == 'direct-cases':
            checks = 4186
        lines.append(f'RouterVPN Tor editor phase={phase} event=complete selection={ordinal} '
                     f'checks={checks} elapsed_ms={elapsed} phase_ms=3')
    return lines


class WindowsEditorPhaseDiagnostics(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='routervpn-tor-editor-diagnostics-')
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.progress = self.directory / RUNNER.WINDOWS_EDITOR_PROGRESS
        self.lines = editor_progress()
        self.write(self.lines)

    def write(self, lines):
        self.progress.write_text('\n'.join(lines) + '\n', encoding='ascii')

    def test_complete_trace_is_exact_and_cannot_enter_importer_payloads(self):
        self.assertEqual(len(self.lines), 54)
        self.assertEqual(RUNNER.WINDOWS_EDITOR_CHECKS, 4186)
        self.assertEqual(len(RUNNER.SELECTIONS), 22)
        RUNNER.verify_windows_editor_progress(self.directory)
        self.assertNotEqual(self.progress.suffix, '.json')
        self.assertNotIn(self.progress.name, RUNNER.CATALOG_FILES)
        self.assertEqual(list(self.directory.glob('tor-update-*source-catalog.json')), [])
        self.assertEqual(list(self.directory.glob('tor-create-dynamic-*.json')), [])

    def test_every_phase_start_and_completion_is_mandatory(self):
        for index in range(len(self.lines)):
            with self.subTest(index=index):
                self.write(self.lines[:index] + self.lines[index + 1:])
                with self.assertRaisesRegex(RuntimeError, 'omitted or added'):
                    RUNNER.verify_windows_editor_progress(self.directory)

    def test_duplicate_reordered_and_foreign_ordinals_stay_failed(self):
        variants = [self.lines + [self.lines[-1]]]
        changed = self.lines.copy(); changed[7], changed[8] = changed[8], changed[7]; variants.append(changed)
        changed = self.lines.copy(); changed[8] = changed[8].replace('selection=2', 'selection=1'); variants.append(changed)
        for lines in variants:
            self.write(lines)
            with self.assertRaises(RuntimeError):
                RUNNER.verify_windows_editor_progress(self.directory)

    def test_incomplete_assertions_and_invented_times_cannot_pass(self):
        mutations = [(53, 'checks=4186', 'checks=4185'), (1, 'phase_ms=3', 'phase_ms=2'),
                     (8, 'phase_ms=0', 'phase_ms=1'), (8, 'elapsed_ms=12', 'elapsed_ms=1')]
        for index, before, after in mutations:
            with self.subTest(index=index, field=before):
                self.assertIn(before, self.lines[index])
                changed = self.lines.copy(); changed[index] = changed[index].replace(before, after)
                self.write(changed)
                with self.assertRaises(RuntimeError):
                    RUNNER.verify_windows_editor_progress(self.directory)

    def test_private_fields_are_rejected_without_echoing_their_contents(self):
        private = 'private-provider-secret'
        for before, after in [('phase=ast-extraction', 'phase=' + private),
                              ('checks=0', 'checks=' + private),
                              ('phase_ms=0', 'phase_ms=0 body=' + private)]:
            changed = self.lines.copy(); changed[0] = changed[0].replace(before, after)
            self.write(changed)
            with self.assertRaises(RuntimeError) as raised:
                RUNNER.verify_windows_editor_progress(self.directory)
            self.assertNotIn(private, str(raised.exception))
        self.progress.write_bytes(b'private\xffvalue')
        with self.assertRaisesRegex(RuntimeError, 'private field'):
            RUNNER.verify_windows_editor_progress(self.directory)
        self.progress.write_bytes(b'x' * 16385)
        with self.assertRaisesRegex(RuntimeError, 'bounded record'):
            RUNNER.verify_windows_editor_progress(self.directory)

    def test_both_shells_keep_original_callback_child_and_all_seven_mutants(self):
        witnesses = ('Update checkbox did not load the saved Always policy and name',
                     'Tor update adopted selected', 'Tor update adopted display-mutated',
                     'Tor update adopted ordinary-fixed-bypass', 'Tor update adopted ordinary-mixed-udp',
                     'Tor update adopted plain-lines', 'Direct custom set admitted dynamic bridge meek_lite')
        for shell in ('powershell.exe', 'pwsh.exe'):
            with self.subTest(shell=shell), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                for name in RUNNER.CATALOG_FILES:
                    (directory / name).write_text('{}')
                (directory / RUNNER.WINDOWS_EDITOR_PROGRESS).write_text('\n'.join(self.lines) + '\n')
                calls = []
                def execute(command, **options):
                    self.assertEqual(command[:6], [shell, '-STA', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File'])
                    self.assertEqual(command[6], str(RUNNER.ROOT / 'client/test-windows-tor-bridge-update.ps1'))
                    self.assertEqual(options['timeout'], 60)
                    calls.append(command)
                    if len(calls) == 1:
                        self.assertTrue(options['check'])
                        self.assertNotIn('capture_output', options)
                        return subprocess.CompletedProcess(command, 0)
                    self.assertTrue(options['capture_output'])
                    self.assertIn('-Root', command)
                    return subprocess.CompletedProcess(command, 1, '', witnesses[len(calls) - 2])
                with patch.object(RUNNER.sys, 'platform', 'win32'), patch.object(RUNNER.subprocess, 'run', side_effect=execute), redirect_stdout(io.StringIO()):
                    RUNNER.windows_form(directory, shell)
                self.assertEqual(len(calls), 8)

    def test_child_timeout_or_failure_keeps_original_error_and_stops_before_mutants(self):
        for failure in (subprocess.TimeoutExpired(['pwsh.exe'], 60), subprocess.CalledProcessError(23, ['pwsh.exe'])):
            with self.subTest(failure=type(failure).__name__), patch.object(RUNNER.subprocess, 'run', side_effect=failure) as run, redirect_stdout(io.StringIO()):
                with self.assertRaises(type(failure)) as raised:
                    RUNNER.windows_form(self.directory, 'pwsh.exe')
                self.assertIs(raised.exception, failure)
                run.assert_called_once()
                self.assertEqual(run.call_args.kwargs['timeout'], 60)
                self.assertTrue(run.call_args.kwargs['check'])

    def test_zero_child_exit_with_missing_progress_is_not_a_success(self):
        self.progress.unlink()
        with patch.object(RUNNER.subprocess, 'run', return_value=subprocess.CompletedProcess(['pwsh.exe'], 0)) as run, redirect_stdout(io.StringIO()):
            with self.assertRaises(FileNotFoundError):
                RUNNER.windows_form(self.directory, 'pwsh.exe')
            run.assert_called_once()

    def test_phase_wiring_preserves_actual_ast_wpf_callbacks_and_close(self):
        source = (RUNNER.ROOT / 'client/test-windows-tor-bridge-update.ps1').read_text()
        ordered = ["Write-TorEditorPhase 'ast-extraction' 'start'", '$Ast=[ScriptBlock]::Create($Source).Ast',
                   "Write-TorEditorPhase 'ast-extraction' 'complete'", "Write-TorEditorPhase 'input-controls' 'start'",
                   "Write-TorEditorPhase 'input-controls' 'complete'", "Write-TorEditorPhase 'wpf-initialization' 'start'",
                   'Add-Type -AssemblyName PresentationFramework,PresentationCore,WindowsBase',
                   '$D=[Windows.Markup.XamlReader]::Load([Xml.XmlNodeReader]::new($XML))',
                   '$Button.Add_Click($Save)', "Write-TorEditorPhase 'wpf-initialization' 'complete'",
                   'foreach($Execution in $Selections){', "Write-TorEditorPhase 'selection' 'start' $SelectionOrdinal",
                   "foreach($ID in @('obfs4','meek_lite','snowflake','webtunnel','tor')){",
                   "Write-TorEditorPhase 'selection' 'complete' $SelectionOrdinal",
                   "Write-TorEditorPhase 'direct-cases' 'start'", "foreach($ID in @('obfs4','custom')){",
                   "Write-TorEditorPhase 'direct-cases' 'complete'", "Write-TorEditorPhase 'window-close' 'start'",
                   'if($NativeWPF){$D.Close()}', "Write-TorEditorPhase 'window-close' 'complete'",
                   'Write-Host "Windows actual Tor editor callbacks: $script:Checks checks PASS; WPF=$NativeWPF"']
        position = -1
        for marker in ordered:
            self.assertEqual(source.count(marker), 1, marker)
            found = source.index(marker)
            self.assertGreater(found, position, marker)
            position = found
        calls = re.findall(r'^\s*Write-TorEditorPhase ', source, re.M)
        self.assertEqual(len(calls), 12)
        emitter = source[source.index('function Write-TorEditorPhase {'):source.index("Write-TorEditorPhase 'ast-extraction' 'start'")]
        self.assertIn("[ValidateSet('ast-extraction','input-controls','wpf-initialization','selection','direct-cases','window-close')]", emitter)
        self.assertIn('[Console]::Out.WriteLine($Line);[Console]::Out.Flush()', emitter)
        line = next(value for value in emitter.splitlines() if value.strip().startswith('$Line='))
        self.assertTrue(line.endswith('-f$Phase,$Event,$Selection,[int]$script:Checks,$Now,$Duration'))
        for private in ('$Source', '$Raw', '$Saved', '$Body', '$Root', '$Output', '$Execution'):
            self.assertNotIn(private, line)


if __name__ == '__main__':
    unittest.main()
