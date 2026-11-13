#!/usr/bin/env python3
"""Exercise orchestration refusal paths; native execution belongs to hosted validation."""
from pathlib import Path
import hashlib
import importlib.util
import json
import os
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('focused_hy2_validator', ROOT/'deploy/validate-linux-hy2-source.py')
V = importlib.util.module_from_spec(spec)
spec.loader.exec_module(V)
PARSER = V.load_gate(ROOT).NODE.require_native_verdicts


def verdict(names):
    return ''.join('=== RUN   '+name+'\n--- PASS: '+name+' (0.01s)\n' for name in names)+'PASS\n'


def mask_verdict(fault=None):
    rows = [dict(Action='run', Package=V.CLIENT_PACKAGE, Test=V.MASK_CASES[0])]
    leaves = V.MASK_CASES[1:]
    if fault == 'control-missing-leaf':
        leaves = leaves[:-1]
    for leaf in leaves:
        rows.append(dict(Action='run', Package=V.CLIENT_PACKAGE, Test=leaf))
        if not (fault == 'control-wrong-leaf' and leaf == leaves[-1]):
            rows.append(dict(Action='output', Package=V.CLIENT_PACKAGE, Test=leaf, Output=V.MASK_WITNESS+'\n'))
        rows.append(dict(Action='fail', Package=V.CLIENT_PACKAGE, Test=leaf))
    if fault == 'control-wrong-leaf':
        rows.append(dict(Action='output', Package=V.CLIENT_PACKAGE, Test=V.MASK_CASES[0], Output=V.MASK_WITNESS+'\n'))
    rows.append(dict(Action='fail', Package=V.CLIENT_PACKAGE, Test=V.MASK_CASES[0]))
    rows.append(dict(Action='fail', Package=V.CLIENT_PACKAGE))
    if fault == 'control-early-root':
        rows.insert(1, rows.pop(-2))
    return ''.join(json.dumps(row)+'\n' for row in rows)


class Composition:
    def __init__(self, directory, fault=None):
        self.directory, self.fault = directory, fault
        self.source = directory/'candidate'
        self.source.mkdir()
        self.output = directory/'validation-output'/'tests'
        self.output.parent.mkdir()
        self.metadata = dict(schema=1, suite='linux-hy2', repository='Eabusham2/router-vpn',
                             workflow_ref='Eabusham2/router-vpn/.github/workflows/focused-source-validation.yml@main',
                             validator_sha='a'*40, validator_tree='b'*40, base_sha='c'*40, base_tree='d'*40,
                             source_sha='e'*40, source_tree='f'*40, relation='single-parent', changes=[],
                             validation_scope='read-only-source-candidate')
        self.selection_file = self.output.parent/'selection.json'
        self.selection_file.write_text(json.dumps(self.metadata))
        helper = self.source/V.HELPER
        helper.parent.mkdir(parents=True)
        helper.write_text('var out = map[string]any{"password": mask}\n')
        template = self.source/V.PEER_TEMPLATE
        template.parent.mkdir(parents=True)
        template.write_text('original encrypted fixture template\n')
        self.calls, self.prepared = [], False
        self.gate = types.SimpleNamespace(
            NODE_CHAIN_HOST_AUTHORITY_CASES=V.AUTHORITY,
            HYSTERIA_FINAL=types.SimpleNamespace(VERDICTS=V.ENCRYPTED),
            BUILD=types.SimpleNamespace(TOOLCHAIN='go1.26.3'),
            NODE=types.SimpleNamespace(TAGS=('with_wireguard', 'with_quic', 'with_purego'),
                run=self.run, require_native_verdicts=PARSER,
                selected_compiler=lambda go, core, env: (Path('/captured/go'), env, 'amd64')),
            checked_sources=self.checked_sources)

    def git(self, source, *args):
        if args == ('status', '--porcelain', '--untracked-files=all'):
            return ''
        if args == ('rev-parse', 'HEAD'):
            return self.metadata['source_sha' if source == self.source else 'validator_sha']
        if args == ('rev-parse', 'HEAD^{tree}'):
            return self.metadata['source_tree' if source == self.source else 'validator_tree']
        raise AssertionError(args)

    def prepare(self, gate, core, xray, env):
        self.prepared = True
        assert os.environ['PATH'] == env['PATH'] and os.environ['GOTOOLCHAIN'] == 'local'
        projection = core/V.PEER_PROJECTION
        projection.parent.mkdir(parents=True)
        projection.write_bytes((self.source/V.PEER_TEMPLATE).read_bytes())
        if self.fault == 'projection':
            projection.write_text('wrong native projection')

    def checked_sources(self, core):
        records = {'app/'+V.HELPER: hashlib.sha256((self.source/V.HELPER).read_bytes()).hexdigest(),
                   'native/'+V.PEER_PROJECTION: hashlib.sha256((core/V.PEER_PROJECTION).read_bytes()).hexdigest()}
        if self.fault == 'missing-source':
            records.pop('app/'+V.HELPER)
        return core, records

    def run(self, command, *, cwd, env, timeout):
        self.calls.append((list(command), timeout))
        index = len(self.calls)
        if index in (1, 4):
            image = Path(command[command.index('-o')+1])
            image.write_bytes(('original-image-'+str(index)).encode())
            if index == 1:
                self.controller = image
            if self.fault == 'compile-failure' and index == 1:
                return 1, 'compiler refused source\n'
            return 0, ''
        if index == 2:
            names = V.AUTHORITY[:-1] if self.fault == 'missing-authority' else V.AUTHORITY
            return 0, verdict(names)
        if index == 3:
            overlay = Path(next(value.split('=', 1)[1] for value in command if value.startswith('-overlay=')))
            replacement = Path(json.loads(overlay.read_text())['Replace'][str(self.source/V.HELPER)])
            self.mutated = replacement.read_text()
            if self.fault == 'control-pass':
                return 0, V.MASK_WITNESS
            if self.fault == 'control-wrong':
                return 1, 'some unrelated assertion'
            if self.fault == 'control-build':
                return 1, V.MASK_WITNESS+'\n[build failed]'
            if self.fault == 'control-race':
                return 1, V.MASK_WITNESS+'\nWARNING: DATA RACE'
            if self.fault == 'control-panic':
                return 1, mask_verdict()+'panic: unrelated worker failed\n'
            if self.fault == 'control-signal':
                return -9, mask_verdict()
            return 1, mask_verdict(self.fault)
        if index == 5:
            names = V.ENCRYPTED[:-1] if self.fault == 'missing-encrypted' else V.ENCRYPTED
            if self.fault == 'foreign-encrypted':
                names = (*names, 'TestForeignPeer')
            if self.fault == 'source-change':
                (self.source/V.HELPER).write_text('replacement source\n')
            if self.fault == 'image-change':
                self.controller.write_bytes(b'replacement image')
            if self.fault == 'selection-change':
                self.selection_file.write_text(json.dumps(dict(self.metadata, suite='other')))
            return (1 if self.fault == 'encrypted-failure' else 0), verdict(names)
        raise AssertionError('Unexpected extra compiler or execution')

    def execute_process(self, command, cwd, env, log, bound):
        status, text = self.run(list(map(str, command)), cwd=cwd, env=env, timeout=bound)
        log.write_text(text)
        control = len(self.calls) == 3
        return status, control and self.fault == 'control-timeout', not (control and self.fault == 'control-unjoined')

    def execute(self):
        with patch.object(V, 'load_gate', return_value=self.gate), patch.object(V, 'prepare', side_effect=self.prepare), \
                patch.object(V, 'git', side_effect=self.git), patch.object(V, 'execute', side_effect=self.execute_process), patch.object(V.platform, 'system', return_value='Linux'):
            return V.validate(self.source, self.metadata['source_sha'], self.output, '/captured/go')


class FocusedLinuxHysteriaValidation(unittest.TestCase):
    def test_trusted_process_executor_loads_and_joins_original_child(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            result = V.execute([sys.executable, '-c', "print('original-child')"], work,
                               dict(os.environ), work/'process.log', 3)
            self.assertEqual(result, (0, False, True))
            self.assertEqual((work/'process.log').read_text().strip(), 'original-child')

    def test_complete_inventory_original_bounds_and_distinct_native_scope(self):
        with tempfile.TemporaryDirectory() as directory:
            f = Composition(Path(directory))
            result = f.execute()
            self.assertEqual(tuple(result['authority_cases']), V.AUTHORITY)
            self.assertEqual((len(V.AUTHORITY), len(V.ENCRYPTED)), (21, 37))
            self.assertEqual([bound for _, bound in f.calls], [300, 40, 300, 600, 100])
            self.assertIn('-test.timeout=30s', f.calls[1][0])
            self.assertIn('-timeout=30s', f.calls[2][0])
            self.assertIn('-json', f.calls[2][0])
            self.assertIn('-test.timeout=90s', f.calls[4][0])
            self.assertIn(V.MASK_AFTER, f.mutated)
            self.assertNotEqual(f.mutated, (f.source/V.HELPER).read_text())
            self.assertEqual(result['selection'], f.metadata)
            self.assertNotEqual(result['selection']['validator_sha'], result['selection']['source_sha'])
            self.assertNotEqual(result['selection']['base_sha'], result['selection']['source_sha'])
            self.assertFalse(result['installed_native_accepted'])
            self.assertEqual(result['scope'], 'source-authority-and-encrypted-reference-only')
            self.assertTrue(result['completed'])
            self.assertEqual(len(result['images']), 2)
            self.assertTrue((f.output/'receipt.json').is_file())
            self.assertEqual(result['compiler'], '/captured/go')
            self.assertEqual(json.loads((f.output/'receipt.json').read_text()), result)
            progress = json.loads((f.output/'progress.json').read_text())
            self.assertEqual(progress['compiler'], '/captured/go')
            self.assertEqual(len(progress['phases']), 5)

    def test_path_compiler_preserves_failed_and_exception_receipts(self):
        for failure in ('compile-failure', 'spawn-exception'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory:
                f = Composition(Path(directory), failure)
                if failure == 'spawn-exception':
                    def refused(command, cwd, env, log, bound):
                        raise OSError('original captured compiler spawn refused')
                    f.execute_process = refused
                with self.assertRaises((ValueError, OSError)) as caught:
                    f.execute()
                self.assertNotIsInstance(caught.exception, TypeError)
                progress = json.loads((f.output/'progress.json').read_text())
                self.assertEqual(progress['compiler'], '/captured/go')
                self.assertEqual(len(progress['phases']), 1)
                phase = progress['phases'][0]
                self.assertEqual(phase['command'][0], '/captured/go')
                self.assertEqual(phase['timeout'], 300)
                if failure == 'compile-failure':
                    self.assertEqual(phase['status'], 1)
                    self.assertFalse(phase['timed_out'])
                    self.assertTrue(phase['process_group_joined'])
                    self.assertIn('compiler refused source', (f.output/'controller-build.log').read_text())
                else:
                    self.assertEqual(phase['error'], 'OSError')
                    self.assertIn('original captured compiler spawn refused', (f.output/'controller-build.log').read_text())
                self.assertFalse((f.output/'receipt.json').exists())

    def test_each_observed_failure_prevents_acceptance_receipt(self):
        for fault in ('missing-source', 'projection', 'compile-failure', 'missing-authority',
                      'control-pass', 'control-wrong', 'control-build', 'control-race',
                      'control-missing-leaf', 'control-wrong-leaf', 'control-panic', 'control-signal',
                      'control-timeout', 'control-unjoined', 'control-early-root',
                      'missing-encrypted', 'foreign-encrypted', 'encrypted-failure',
                      'source-change', 'image-change', 'selection-change'):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as directory:
                f = Composition(Path(directory), fault)
                with self.assertRaises((ValueError, RuntimeError)):
                    f.execute()
                self.assertFalse((f.output/'receipt.json').exists(), fault)

    def test_scope_and_exact_inventory_refusals_precede_preparation(self):
        for fault in ('foreign-source', 'foreign-suite', 'missing-selection', 'widened-authority', 'missing-encrypted'):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as directory:
                f = Composition(Path(directory))
                if fault == 'foreign-source':
                    f.selection_file.write_text(json.dumps(dict(f.metadata, source_sha='1'*40)))
                elif fault == 'foreign-suite':
                    f.selection_file.write_text(json.dumps(dict(f.metadata, suite='legacy-clock')))
                elif fault == 'missing-selection':
                    f.selection_file.unlink()
                elif fault == 'widened-authority':
                    f.gate.NODE_CHAIN_HOST_AUTHORITY_CASES = (*V.AUTHORITY, 'TestForeign')
                elif fault == 'missing-encrypted':
                    f.gate.HYSTERIA_FINAL.VERDICTS = V.ENCRYPTED[:-1]
                with self.assertRaises(ValueError):
                    f.execute()
                self.assertFalse(f.prepared)

    def test_existing_or_candidate_output_is_never_reused(self):
        for inside in (False, True):
            with self.subTest(inside=inside), tempfile.TemporaryDirectory() as directory:
                f = Composition(Path(directory))
                if inside:
                    f.output = f.source/'results'
                else:
                    f.output.mkdir()
                with self.assertRaises(ValueError):
                    f.execute()
                self.assertFalse(f.prepared)

    def test_control_must_change_one_original_source_occurrence(self):
        for content in ('no captured mask here\n', V.MASK_BEFORE+'\n'+V.MASK_BEFORE+'\n'):
            with self.subTest(content=content), tempfile.TemporaryDirectory() as directory:
                f = Composition(Path(directory))
                (f.source/V.HELPER).write_text(content)
                with self.assertRaisesRegex(ValueError, 'source-control seam'):
                    f.execute()
                self.assertEqual(len(f.calls), 2)
                self.assertFalse((f.output/'receipt.json').exists())


if __name__ == '__main__':
    unittest.main(verbosity=2)
