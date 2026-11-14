#!/usr/bin/env python3
"""Exercise orchestration refusal paths; native execution belongs to hosted validation."""
from pathlib import Path
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('focused_hy2_validator', ROOT/'deploy/validate-darwin-hy2-source.py')
V = importlib.util.module_from_spec(spec)
spec.loader.exec_module(V)
PARSER = V.load_gate(ROOT).EXTERNAL.NODE.require_native_verdicts


def verdict(names):
    return ''.join('=== RUN   '+name+'\n--- PASS: '+name+' (0.01s)\n' for name in names)+'PASS\n'


def mask_verdict(fault=None):
    rows = [dict(Action='start', Package=V.CLIENT_PACKAGE), dict(Action='run', Package=V.CLIENT_PACKAGE, Test=V.MASK_CASES[0])]
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
        self.metadata = dict(schema=1, suite='darwin-hy2', repository='Eabusham2/router-vpn',
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
        self.projected = b'original Darwin encrypted fixture projection\n'
        self.gate = types.SimpleNamespace(
            AUTHORITY_CASES=V.IMPORTED, HYSTERIA_AUTHORITY_CASES=V.HYSTERIA,
            ORIGINAL_CASES=tuple('old-'+str(i) for i in range(28)),
            CASES=tuple('old-'+str(i) for i in range(28))+tuple('new-'+str(i) for i in range(9)),
            MEASUREMENT_CASES=tuple('measurement-'+str(i) for i in range(24)),
            PEER_TAGS='with_wireguard,with_quic,with_purego,routervpn_darwin_node_chain',
            BUILD=types.SimpleNamespace(TOOLCHAIN='go1.26.3', digest=lambda:'original-source-policy',
                EXTERNAL=types.SimpleNamespace(darwin_node_chain_peer_copies=lambda:
                    {V.PEER_PROJECTION:self.projected, **{str(i):b'original projection' for i in range(6)}})),
            CONTROLLER=types.SimpleNamespace(UID=types.SimpleNamespace(compiler_toolchain=lambda source, go, env:
                (Path('/captured/go'), env), privilege_tool=lambda:'/usr/bin/sudo')),
            EXTERNAL=types.SimpleNamespace(NODE=types.SimpleNamespace(require_native_verdicts=PARSER)),
            source_identity=self.checked_sources)

    def git(self, source, *args):
        if args == ('status', '--porcelain', '--untracked-files=all'):
            return ''
        if args == ('rev-parse', 'HEAD'):
            return self.metadata['source_sha' if source == self.source else 'validator_sha']
        if args == ('rev-parse', 'HEAD^{tree}'):
            return self.metadata['source_tree' if source == self.source else 'validator_tree']
        raise AssertionError(args)

    def prepare(self, gate, work, env):
        self.prepared = True
        assert os.environ['PATH'] == env['PATH'] and os.environ['GOTOOLCHAIN'] == 'local'
        core = work/'core'
        projection = core/V.PEER_PROJECTION
        projection.parent.mkdir(parents=True)
        projection.write_bytes(self.projected)
        if self.fault == 'projection':
            projection.write_text('wrong native projection')
        return core

    def checked_sources(self, core):
        records = dict(application={V.HELPER: hashlib.sha256((self.source/V.HELPER).read_bytes()).hexdigest()},
                       peer={V.PEER_PROJECTION:hashlib.sha256((core/V.PEER_PROJECTION).read_bytes()).hexdigest()})
        if self.fault == 'missing-source':
            records['application'].pop(V.HELPER)
        return records

    def run(self, command, *, cwd, env, timeout):
        self.calls.append((list(command), timeout))
        index = len(self.calls)
        if index in (1, 4, 6):
            image = Path(command[command.index('-o')+1])
            image.write_bytes(('original-image-'+str(index)).encode())
            if index == 1:
                self.controller = image
            if index == 4:
                self.mutated_image = image
                overlay = Path(next(value.split('=', 1)[1] for value in command if value.startswith('-overlay=')))
                replacement = Path(json.loads(overlay.read_text())['Replace'][str(self.source/V.HELPER)])
                self.mutated = replacement.read_text()
            if self.fault == 'compile-failure' and index == 1 or self.fault == 'control-compile' and index == 4:
                return 1, 'compiler refused source\n'
            return 0, ''
        if index in (2, 3):
            names = V.IMPORTED if index == 2 else V.HYSTERIA
            if self.fault == 'missing-authority' and index == 3 or self.fault == 'missing-imported' and index == 2:
                names = names[:-1]
            return 0, verdict(names)
        if index == 5:
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
            if self.fault == 'control-image':
                self.mutated_image.write_bytes(b'foreign image')
            return 1, mask_verdict(self.fault)
        if index in (7, 8, 9):
            self.assert_reference_command(command, index)
        if index == 7:
            text = verdict((V.CAPTURE_ROOT,)).replace('--- PASS:', '    desktop_node_chain_hysteria_darwin_native_test.go:300: '+V.CAPTURE_MARKER+'10.20.30.40\n--- PASS:', 1)
            if self.fault == 'capture-missing':
                text = verdict((V.CAPTURE_ROOT,))
            if self.fault == 'capture-duplicate':
                text += '    desktop_node_chain_hysteria_darwin_native_test.go:300: '+V.CAPTURE_MARKER+'10.20.30.40\n'
            return (1 if self.fault == 'capture-failure' else 0), text
        if index == 8:
            names = V.REFERENCE_CASES[:-1] if self.fault == 'missing-reference-authority' else V.REFERENCE_CASES
            return (1 if self.fault == 'reference-failure' else 0), verdict(names)
        if index == 9:
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

    def assert_reference_command(self, command, index):
        if command[:5] != ['/usr/bin/sudo', '-n', '--', '/usr/bin/env', '-i']:
            raise AssertionError('Reference lost original elevation or clean environment')
        if command.count('ROUTERVPN_DARWIN_NODE_CHAIN_REFERENCE=1') != 1:
            raise AssertionError('Reference lost its explicit captured purpose')
        if index == 7:
            if 'ROUTERVPN_DARWIN_NODE_CHAIN_CAPTURE=1' not in command or any(
                    value.startswith('ROUTERVPN_DARWIN_NODE_CHAIN_ADDRESS=') for value in command):
                raise AssertionError('Capture borrowed an ambient address')
        elif command.count('ROUTERVPN_DARWIN_NODE_CHAIN_ADDRESS=10.20.30.40') != 1:
            raise AssertionError('Reference lost its original physical capture')

    def execute_privileged(self, gate, command, cwd, env, log, bound, sudo):
        if gate is not self.gate or sudo != '/usr/bin/sudo':
            raise AssertionError('Reference lost its original privilege cleanup')
        return self.execute_process(command, cwd, env, log, bound)

    def execute_process(self, command, cwd, env, log, bound):
        status, text = self.run(list(map(str, command)), cwd=cwd, env=env, timeout=bound)
        log.write_text(text)
        control = len(self.calls) == 5
        return status, control and self.fault == 'control-timeout', not (control and self.fault == 'control-unjoined')

    def execute(self):
        with patch.object(V.RACE, 'capture', side_effect=lambda source, go, env: (Path('/captured/go'), dict(env, VALIDATION_COMPILER='go1.26.5'))), patch.object(V, 'load_gate', return_value=self.gate), patch.object(V, 'prepare', side_effect=self.prepare), \
                patch.object(V, 'git', side_effect=self.git), patch.object(V, 'execute', side_effect=self.execute_process), patch.object(V, 'execute_privileged', side_effect=self.execute_privileged), patch.object(V.platform, 'system', return_value='Darwin'), patch.object(V.platform, 'machine', return_value='arm64'):
            return V.validate(self.source, self.metadata['source_sha'], self.output, '/captured/go')


class FocusedDarwinHysteriaValidation(unittest.TestCase):

    def test_mask_json_requires_one_original_package_and_only_exact_framed_events(self):
        original = [json.loads(line) for line in mask_verdict().splitlines()]
        V.require_mask_verdict(mask_verdict(), 1)
        package_output = dict(Action='output', Package=V.CLIENT_PACKAGE, Output='FAIL\n')
        valid = original[:-1]+[package_output]+original[-1:]
        V.require_mask_verdict(''.join(json.dumps(row)+'\n' for row in valid), 1)
        faults = {
            'unframed': mask_verdict()+'foreign raw output\n',
            'non-object': mask_verdict().replace(json.dumps(original[0]), '[]', 1),
            'missing-start': ''.join(json.dumps(row)+'\n' for row in original[1:]),
            'duplicate-start': json.dumps(original[0])+'\n'+mask_verdict(),
            'foreign-package': mask_verdict().replace(V.CLIENT_PACKAGE, 'foreign/package', 1),
            'unknown-package-action': json.dumps(dict(Action='mystery', Package=V.CLIENT_PACKAGE))+'\n'+mask_verdict(),
            'output-before-start': json.dumps(package_output)+'\n'+mask_verdict(),
            'late-package-output': mask_verdict()+json.dumps(package_output)+'\n',
            'duplicate-package-terminal': mask_verdict()+json.dumps(original[-1])+'\n',
            'late-test': mask_verdict()+json.dumps(original[1])+'\n',
            'package-pass': ''.join(json.dumps(row)+'\n' for row in original[:-1]+[dict(Action='pass', Package=V.CLIENT_PACKAGE)]),
            'empty-test': mask_verdict().replace(json.dumps(original[1]), json.dumps(dict(Action='run', Package=V.CLIENT_PACKAGE, Test='')), 1),
            'non-string-output': mask_verdict().replace(json.dumps(original[3]), json.dumps(dict(original[3], Output=None)), 1),
        }
        for place in ('root', 'package'):
            event = dict(Action='output', Package=V.CLIENT_PACKAGE, Output=V.MASK_WITNESS+'\n')
            if place == 'root':
                event['Test'] = V.MASK_CASES[0]
            changed = original[:2]+[event]+original[2:]
            faults[place+'-witness'] = ''.join(json.dumps(row)+'\n' for row in changed)
        for name, transcript in faults.items():
            with self.subTest(fault=name), self.assertRaises(ValueError):
                V.require_mask_verdict(transcript, 1)

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
            self.assertEqual((len(V.AUTHORITY), len(V.ENCRYPTED)), (8, 37))
            self.assertEqual([bound for _, bound in f.calls], [300, 40, 40, 300, 40, 600, 40, 40, 100])
            self.assertIn('-test.timeout=30s', f.calls[1][0])
            self.assertIn('-test.timeout=30s', f.calls[4][0])
            self.assertEqual(f.calls[4][0][1:3], ['tool', 'test2json'])
            self.assertIn('-test.timeout=90s', f.calls[8][0])
            self.assertEqual(result['reference_cases'], list(V.REFERENCE_CASES))
            self.assertEqual(result['reference_capture']['address'], '10.20.30.40')
            self.assertIn(V.MASK_AFTER, f.mutated)
            self.assertNotEqual(f.mutated, (f.source/V.HELPER).read_text())
            self.assertEqual(result['selection'], f.metadata)
            self.assertNotEqual(result['selection']['validator_sha'], result['selection']['source_sha'])
            self.assertNotEqual(result['selection']['base_sha'], result['selection']['source_sha'])
            self.assertFalse(result['installed_native_accepted'])
            self.assertEqual(result['scope'], 'source-authority-and-encrypted-reference-only')
            self.assertTrue(result['completed'])
            self.assertEqual(len(result['images']), 3)
            self.assertTrue((f.output/'receipt.json').is_file())
            self.assertEqual(result['compiler'], '/captured/go')
            self.assertEqual(json.loads((f.output/'receipt.json').read_text()), result)
            progress = json.loads((f.output/'progress.json').read_text())
            self.assertEqual(progress['compiler'], '/captured/go')
            self.assertEqual(len(progress['phases']), 9)

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
        for fault in ('missing-source', 'projection', 'compile-failure', 'missing-authority', 'missing-imported',
                      'control-compile', 'control-image',
                      'control-pass', 'control-wrong', 'control-build', 'control-race',
                      'control-missing-leaf', 'control-wrong-leaf', 'control-panic', 'control-signal',
                      'control-timeout', 'control-unjoined', 'control-early-root',
                      'capture-failure', 'capture-missing', 'capture-duplicate', 'missing-reference-authority', 'reference-failure',
                      'missing-encrypted', 'foreign-encrypted', 'encrypted-failure',
                      'source-change', 'image-change', 'selection-change'):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as directory:
                f = Composition(Path(directory), fault)
                with self.assertRaises((ValueError, RuntimeError)):
                    f.execute()
                self.assertFalse((f.output/'receipt.json').exists(), fault)

    def test_scope_and_exact_inventory_refusals_precede_preparation(self):
        for fault in ('foreign-source', 'foreign-suite', 'missing-selection', 'widened-authority', 'missing-hysteria', 'missing-projection', 'wrong-installed'):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as directory:
                f = Composition(Path(directory))
                if fault == 'foreign-source':
                    f.selection_file.write_text(json.dumps(dict(f.metadata, source_sha='1'*40)))
                elif fault == 'foreign-suite':
                    f.selection_file.write_text(json.dumps(dict(f.metadata, suite='legacy-clock')))
                elif fault == 'missing-selection':
                    f.selection_file.unlink()
                elif fault == 'widened-authority':
                    f.gate.AUTHORITY_CASES = (*V.IMPORTED, 'TestForeign')
                elif fault == 'missing-hysteria':
                    f.gate.HYSTERIA_AUTHORITY_CASES = V.HYSTERIA[:-1]
                elif fault == 'missing-projection':
                    f.gate.BUILD.EXTERNAL.darwin_node_chain_peer_copies = lambda: {}
                elif fault == 'wrong-installed':
                    f.gate.CASES = f.gate.CASES[:-1]
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
                self.assertEqual(len(f.calls), 3)
                self.assertFalse((f.output/'receipt.json').exists())



    def test_physical_receipt_is_unique_canonical_and_from_original_native_root(self):
        text = verdict((V.CAPTURE_ROOT,)).replace('--- PASS:', '    desktop_node_chain_hysteria_darwin_native_test.go:300: '+V.CAPTURE_MARKER+'10.20.30.40\n--- PASS:', 1)
        self.assertEqual(V.captured_reference_address(text, PARSER), '10.20.30.40')
        for changed in (text.replace('10.20.30.40', address) for address in
                        ('127.0.0.1', '0.0.0.0', '224.0.0.1', '169.254.1.2', '255.255.255.255',
                         '::1', '010.20.30.40', '10.20.30.40;foreign')):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                V.captured_reference_address(changed, PARSER)
        for changed in (verdict((V.CAPTURE_ROOT,)), text+text,
                        text.replace('desktop_node_chain_hysteria_darwin_native_test.go', 'foreign.go'),
                        text.replace('--- PASS:', '--- FAIL:'), text.replace('=== RUN', '=== SKIP')):
            with self.assertRaises(ValueError):
                V.captured_reference_address(changed, PARSER)

    def test_reference_argv_captures_privilege_address_and_finite_original_bounds(self):
        for root in (V.CAPTURE_ROOT, V.REFERENCE_ROOT, V.ENCRYPTED_ROOT):
            address = None if root == V.CAPTURE_ROOT else '10.20.30.40'
            command = V.reference_command('/original/peer.test', root, '/usr/bin/sudo', address)
            self.assertEqual(command[:5], ['/usr/bin/sudo', '-n', '--', '/usr/bin/env', '-i'])
            self.assertEqual(command.count('ROUTERVPN_DARWIN_NODE_CHAIN_REFERENCE=1'), 1)
            self.assertIn('-test.run=^'+root+'$', command)
            self.assertIn('-test.timeout='+('90s' if root == V.ENCRYPTED_ROOT else '30s'), command)
            if address:
                self.assertIn('ROUTERVPN_DARWIN_NODE_CHAIN_ADDRESS='+address, command)
            else:
                self.assertFalse(any(value.startswith('ROUTERVPN_DARWIN_NODE_CHAIN_ADDRESS=') for value in command))
        with patch.object(V.os, 'geteuid', return_value=0):
            self.assertEqual(V.reference_command('/original/peer.test', V.CAPTURE_ROOT, None)[:2], ['/usr/bin/env', '-i'])
        with patch.object(V.os, 'geteuid', return_value=501), self.assertRaises(ValueError):
            V.reference_command('/original/peer.test', V.CAPTURE_ROOT, None)
        for root, sudo, address in (('foreign', '/usr/bin/sudo', None),
                                   (V.CAPTURE_ROOT, '/tmp/sudo', None),
                                   (V.CAPTURE_ROOT, '/usr/bin/sudo', '10.20.30.40'),
                                   (V.ENCRYPTED_ROOT, '/usr/bin/sudo', None),
                                   (V.ENCRYPTED_ROOT, '/usr/bin/sudo', '127.0.0.1')):
            with self.assertRaises(ValueError):
                V.reference_command('/original/peer.test', root, sudo, address)

    def test_privileged_executor_keeps_original_cleanup_and_never_accepts_failed_join(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            calls = []
            def original(command, **kwargs):
                calls.append((command, kwargs))
                return 'original root output\n'
            gate = types.SimpleNamespace(CONTROLLER=types.SimpleNamespace(UID=types.SimpleNamespace(run=original)))
            args = (gate, ['/usr/bin/sudo', '-n', '--', '/original/image'], root, {},
                    root/'root.log', 100, '/usr/bin/sudo')
            self.assertEqual(V.execute_privileged(*args), (0, False, True))
            self.assertEqual(calls[0][1]['sudo'], '/usr/bin/sudo')
            self.assertEqual(calls[0][1]['timeout'], 100)
            self.assertEqual(args[4].read_text(), 'original root output\n')
            def failed(*unused, **kwargs):
                raise subprocess.CalledProcessError(1, 'original', output=b'original native failure\n')
            gate.CONTROLLER.UID.run = failed
            self.assertEqual(V.execute_privileged(*args), (1, False, True))
            self.assertEqual(args[4].read_text(), 'original native failure\n')
            for error in (RuntimeError('original group timeout was joined'),
                          RuntimeError('original group could not be joined'), OSError('spawn refused')):
                def refused(*unused, **kwargs):
                    raise error
                gate.CONTROLLER.UID.run = refused
                with self.assertRaises(type(error)):
                    V.execute_privileged(*args)
                self.assertIn(str(error), args[4].read_text())

    def test_orchestration_rejects_omitted_reference_flag_elevation_and_address(self):
        original = V.reference_command
        for omitted in ('elevation', 'flag', 'address'):
            def mutant(image, root, sudo, address=None):
                command = original(image, root, sudo, address)
                if root != V.ENCRYPTED_ROOT:
                    return command
                if omitted == 'elevation':
                    return command[3:]
                if omitted == 'flag':
                    return [value for value in command if value != 'ROUTERVPN_DARWIN_NODE_CHAIN_REFERENCE=1']
                return [value for value in command if not value.startswith('ROUTERVPN_DARWIN_NODE_CHAIN_ADDRESS=')]
            with self.subTest(omitted=omitted), tempfile.TemporaryDirectory() as directory:
                f = Composition(Path(directory))
                with patch.object(V, 'reference_command', side_effect=mutant), self.assertRaises(AssertionError):
                    f.execute()
                self.assertFalse((f.output/'receipt.json').exists())

if __name__ == '__main__':
    unittest.main(verbosity=2)
