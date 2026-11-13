#!/usr/bin/env python3
"""Require exact owner verdicts and joined original process groups."""
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
spec = importlib.util.spec_from_file_location('socks_owner_validator', ROOT/'deploy/validate-node-chain-socks-owner.py')
V = importlib.util.module_from_spec(spec)
spec.loader.exec_module(V)
PARSER = V.load_gate(ROOT).NODE.require_native_verdicts


def verdict(names):
    return ''.join('=== RUN   '+name+'\n--- PASS: '+name+' (0.01s)\n' for name in names)+'PASS\n'


def control_events(control):
    expected = set(control['cases'])
    leaves, failures = V.required_failures(control)
    rows = [dict(Action='start', Package=V.PACKAGE)]
    def enter(name):
        rows.append(dict(Action='run', Package=V.PACKAGE, Test=name))
        for child in control['cases']:
            if child.rsplit('/', 1)[0] == name and child != name:
                enter(child)
        if name in leaves:
            rows.append(dict(Action='output', Package=V.PACKAGE, Test=name, Output=control['witness']+'\n'))
        rows.append(dict(Action='fail' if name in failures else 'pass', Package=V.PACKAGE, Test=name))
    enter(control['root'])
    rows.append(dict(Action='fail', Package=V.PACKAGE))
    return rows


def encoded(rows):
    return ''.join(json.dumps(row)+'\n' for row in rows)


class Composition:
    def __init__(self, directory, fault=None):
        self.fault, self.calls = fault, []
        self.source = directory/'candidate'
        self.source.mkdir()
        self.output = directory/'validation-output'/'tests'
        self.output.parent.mkdir()
        self.metadata = dict(schema=1, suite=V.SUITE, repository='Eabusham2/router-vpn',
            validator_sha='a'*40, validator_tree='b'*40, base_sha='c'*40, base_tree='d'*40,
            source_sha='e'*40, source_tree='f'*40, relation='single-parent',
            validation_scope='read-only-source-candidate')
        self.selection_file = self.output.parent/'selection.json'
        self.selection_file.write_text(json.dumps(self.metadata))
        self.owner = '\n'.join(control['before'] for control in V.CONTROLS)+'\n'
        for name in V.PROJECTIONS:
            path = self.source/name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(self.owner if name == V.OWNER else 'original '+name+'\n')
        self.prepared = False
        self.gate = types.SimpleNamespace(BUILD=types.SimpleNamespace(TOOLCHAIN='go1.26.3'),
            NODE=types.SimpleNamespace(TAGS=('with_wireguard', 'with_quic', 'with_purego'),
                selected_compiler=lambda go, core, env: (Path('/captured/go'), env, 'amd64'),
                require_native_verdicts=PARSER))

    def git(self, source, *args):
        if args == ('status', '--porcelain', '--untracked-files=all'):
            return ' M source' if self.fault == 'dirty-source' else ''
        if args == ('rev-parse', 'HEAD'):
            return self.metadata['source_sha' if source == self.source else 'validator_sha']
        if args == ('rev-parse', 'HEAD^{tree}'):
            return self.metadata['source_tree' if source == self.source else 'validator_tree']
        raise AssertionError(args)

    def prepare(self, gate, core, xray, env):
        self.prepared = True
        self.core = core
        assert os.environ['PATH'] == env['PATH']
        for original, projection in V.PROJECTIONS.items():
            path = core/projection
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes((self.source/original).read_bytes())

    def checked(self, gate, source, core):
        records = {}
        for original, projection in V.PROJECTIONS.items():
            path = core/projection
            if path.read_bytes() != (source/original).read_bytes():
                raise ValueError('original projection changed')
            records[projection] = hashlib.sha256(path.read_bytes()).hexdigest()
        if self.fault == 'source-refusal':
            raise ValueError('original closure refused')
        return records

    def execute_process(self, command, cwd, env, log, bound):
        self.calls.append((command, bound))
        number = len(self.calls)
        if self.fault == 'spawn-exception' and number == 1:
            raise OSError('original compiler spawn refused')
        status, text = 0, ''
        if number == 1:
            self.image = Path(command[command.index('-o')+1])
            self.image.write_bytes(b'original compiled owner')
            if self.fault == 'compile-fail':
                status, text = 1, 'compiler refused actual source'
        elif number == 2:
            cases = V.VERDICTS[:-1] if self.fault == 'missing-baseline' else V.VERDICTS
            if self.fault == 'foreign-baseline':
                cases = (*cases, 'TestForeignOwner')
            text = verdict(cases)
            if self.fault == 'baseline-fail':
                status = 1
        elif number == 3:
            text = verdict(V.ORIGINAL[:-1] if self.fault == 'missing-original' else V.ORIGINAL)
        elif 4 <= number <= 6:
            control = V.CONTROLS[number-4]
            overlay = Path(next(arg.split('=', 1)[1] for arg in command if arg.startswith('-overlay=')))
            replacement = Path(json.loads(overlay.read_text())['Replace'][str(cwd/V.OWNER_PROJECTION)])
            changed = replacement.read_text()
            assert changed != self.owner and control['before'] not in changed
            rows = control_events(control)
            status, text = 1, encoded(rows)
            if number == 4 and self.fault == 'control-pass':
                status = 0
            if number == 4 and self.fault == 'control-signal':
                status = -9
            if number == 4 and self.fault == 'control-unrelated':
                text += 'panic: unrelated worker\n'
            if number == 6:
                if self.fault == 'image-change':
                    self.image.write_bytes(b'replaced owner image')
                if self.fault == 'source-change':
                    (self.core/V.OWNER_PROJECTION).write_text('replacement owner')
                if self.fault == 'selection-change':
                    self.selection_file.write_text(json.dumps(dict(self.metadata, suite='foreign')))
        else:
            raise AssertionError('extra native compiler phase')
        log.write_text(text)
        return status, number == 4 and self.fault == 'control-timeout', not (number == 4 and self.fault == 'control-unjoined')

    def run(self):
        with patch.object(V, 'load_gate', return_value=self.gate), patch.object(V, 'prepare', side_effect=self.prepare), \
                patch.object(V, 'checked_sources', side_effect=self.checked), patch.object(V, 'git', side_effect=self.git), \
                patch.object(V, 'execute', side_effect=self.execute_process), patch.object(V.platform, 'system', return_value='Linux'):
            return V.validate(self.source, self.metadata['source_sha'], self.output, '/captured/go')


class NativeSOCKSOwnerValidator(unittest.TestCase):
    def test_original_process_executor_retains_child_output_and_join(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            result = V.execute([sys.executable, '-c', "print('original-owner-child')"],
                               work, dict(os.environ), work/'child.log', 3)
            self.assertEqual(result, (0, False, True))
            self.assertEqual((work/'child.log').read_text().strip(), 'original-owner-child')

    def test_complete_native_inventory_and_original_bounds(self):
        with tempfile.TemporaryDirectory() as directory:
            f = Composition(Path(directory))
            receipt = f.run()
            self.assertEqual(len(V.VERDICTS), 21)
            self.assertEqual((len(V.ENCRYPTED), len(V.FACTORY)), (16, 5))
            self.assertEqual(receipt['cases'], list(V.VERDICTS))
            self.assertEqual(len(receipt['controls']), 3)
            self.assertEqual(len(receipt['original_peer_cases']), 15)
            self.assertEqual([bound for _, bound in f.calls], [600, 100, 100, 600, 600, 600])
            self.assertIn('-test.timeout=90s', f.calls[1][0])
            for command, _ in f.calls[3:]:
                self.assertIn('-timeout=90s', command)
                self.assertIn('-json', command)
                self.assertIn('-race', command)
            self.assertEqual(receipt['compiler'], '/captured/go')
            self.assertFalse(receipt['installed_native_accepted'])
            self.assertFalse(receipt['public_native_admission'])
            self.assertEqual(receipt['scope'], 'encrypted-box-owner-only')
            self.assertEqual(json.loads((f.output/'receipt.json').read_text()), receipt)
            self.assertEqual(len(json.loads((f.output/'progress.json').read_text())['phases']), 6)
            self.assertNotEqual(receipt['selection']['validator_sha'], receipt['selection']['source_sha'])

    def test_every_phase_failure_withholds_acceptance(self):
        for fault in ('source-refusal', 'compile-fail', 'spawn-exception', 'missing-baseline',
                      'foreign-baseline', 'baseline-fail', 'missing-original', 'control-pass', 'control-signal',
                      'control-unrelated', 'control-timeout', 'control-unjoined',
                      'image-change', 'source-change', 'selection-change'):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as directory:
                f = Composition(Path(directory), fault)
                with self.assertRaises((ValueError, RuntimeError, OSError)) as caught:
                    f.run()
                self.assertNotIsInstance(caught.exception, TypeError)
                self.assertFalse((f.output/'receipt.json').exists())
                if fault in ('compile-fail', 'spawn-exception'):
                    progress = json.loads((f.output/'progress.json').read_text())
                    self.assertEqual(progress['compiler'], '/captured/go')
                    self.assertEqual(len(progress['phases']), 1)
                    self.assertEqual(progress['phases'][0]['timeout'], 600)

    def test_exact_selection_and_fresh_output_precede_preparation(self):
        for fault in ('dirty-source', 'foreign-suite', 'foreign-sha', 'missing-selection', 'existing-output', 'inside-output'):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as directory:
                f = Composition(Path(directory), fault)
                if fault == 'foreign-suite':
                    f.selection_file.write_text(json.dumps(dict(f.metadata, suite='linux-hy2')))
                elif fault == 'foreign-sha':
                    f.selection_file.write_text(json.dumps(dict(f.metadata, source_sha='1'*40)))
                elif fault == 'missing-selection':
                    f.selection_file.unlink()
                elif fault == 'existing-output':
                    f.output.mkdir()
                elif fault == 'inside-output':
                    f.output = f.source/'result'
                with self.assertRaises(ValueError):
                    f.run()
                self.assertFalse(f.prepared)

    def test_every_control_requires_original_unique_source_mutation(self):
        for index in range(3):
            for duplicate in (False, True):
                with self.subTest(index=index, duplicate=duplicate), tempfile.TemporaryDirectory() as directory:
                    f = Composition(Path(directory))
                    before = V.CONTROLS[index]['before']
                    f.owner = f.owner.replace(before, before+'\n'+before if duplicate else 'unrelated source', 1)
                    (f.source/V.OWNER).write_text(f.owner)
                    with self.assertRaisesRegex(ValueError, 'causal seam'):
                        f.run()
                    self.assertEqual(len(f.calls), 3+index)
                    self.assertFalse((f.output/'receipt.json').exists())

    def test_control_requires_every_original_sibling_and_exact_leaf_witness(self):
        faults = ('missing-leaf', 'wrong-witness', 'moved-witness', 'duplicate-witness', 'missing-sibling',
                  'extra-test', 'skip', 'wrong-pass', 'unrelated-fail', 'early-parent', 'repeat-run',
                  'late-output', 'wrong-package', 'no-package-start', 'package-pass', 'no-package-end',
                  'panic', 'race', 'build-fail', 'signal', 'unframed', 'foreign-build', 'late-build')
        for control in V.CONTROLS:
            V.require_control(encoded(control_events(control)), 1, control)
            leaves, failures = V.required_failures(control)
            failed_leaf = sorted(leaves)[0]
            passed_leaf = next(name for name in control['cases'] if name not in failures and
                               not any(other.startswith(name+'/') for other in control['cases']))
            for fault in faults:
                with self.subTest(control=control['name'], fault=fault):
                    rows = control_events(control)
                    status = 1
                    def index(action, name):
                        return next(i for i, row in enumerate(rows) if row.get('Action') == action and row.get('Test') == name)
                    if fault == 'missing-leaf':
                        rows = [row for row in rows if row.get('Test') != failed_leaf]
                    elif fault == 'wrong-witness':
                        rows[index('output', failed_leaf)]['Output'] = 'other failure\n'
                    elif fault == 'moved-witness':
                        rows[index('output', failed_leaf)]['Test'] = control['root']
                    elif fault == 'duplicate-witness':
                        rows[index('output', failed_leaf)]['Output'] *= 2
                    elif fault == 'missing-sibling':
                        rows = [row for row in rows if row.get('Test') != passed_leaf]
                    elif fault == 'extra-test':
                        rows.insert(2, dict(Action='run', Package=V.PACKAGE, Test='TestForeign'))
                    elif fault in ('skip', 'wrong-pass'):
                        rows[index('fail', failed_leaf)]['Action'] = 'skip' if fault == 'skip' else 'pass'
                    elif fault == 'unrelated-fail':
                        rows[index('pass', passed_leaf)]['Action'] = 'fail'
                    elif fault == 'early-parent':
                        rows.insert(2, rows.pop(index('fail', control['root'])))
                    elif fault == 'repeat-run':
                        rows.insert(2, dict(rows[1]))
                    elif fault == 'late-output':
                        rows.append(dict(Action='output', Package=V.PACKAGE, Test=failed_leaf, Output=control['witness']))
                    elif fault == 'wrong-package':
                        rows[index('fail', failed_leaf)]['Package'] = 'foreign/package'
                    elif fault == 'no-package-start':
                        rows.pop(0)
                    elif fault == 'package-pass':
                        rows[-1]['Action'] = 'pass'
                    elif fault == 'no-package-end':
                        rows.pop()
                    elif fault == 'build-fail':
                        rows.insert(0, dict(Action='build-fail', ImportPath=V.PACKAGE))
                    elif fault == 'signal':
                        status = -9
                    elif fault == 'foreign-build':
                        rows.insert(0, dict(Action='build-output', ImportPath='foreign.test', Output='linker warning\n'))
                    elif fault == 'late-build':
                        rows.append(dict(Action='build-output', ImportPath=V.PACKAGE+'.test', Output='late linker warning\n'))
                    text = encoded(rows)
                    text += {'panic':'panic: unrelated\n', 'race':'WARNING: DATA RACE\n', 'unframed':'foreign output\n'}.get(fault, '')
                    with self.assertRaises(ValueError):
                        V.require_control(text, status, control)
            rows = control_events(control)
            rows.insert(0, dict(Action='build-output', ImportPath=V.PACKAGE+'.test', Output='original linker warning\n'))
            V.require_control(encoded(rows), 1, control)

    def test_actual_source_capture_requires_native_projection_and_pinned_callers(self):
        for fault in (None, 'missing-projection', 'changed-projection', 'linked-projection',
                      'changed-pinned', 'ordinary-registration', 'changed-sing'):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as directory:
                work = Path(directory)
                source, core = work/'candidate', work/'native'
                source.mkdir(); core.mkdir()
                for original, projection in V.PROJECTIONS.items():
                    a, b = source/original, core/projection
                    a.parent.mkdir(parents=True, exist_ok=True)
                    b.parent.mkdir(parents=True, exist_ok=True)
                    a.write_text('exact original '+original); b.write_bytes(a.read_bytes())
                pinned = ('dns/transport/conn_pool.go', 'dns/transport/multiplexer.go',
                          'dns/transport/udp.go', 'protocol/socks/outbound.go')
                for relative in pinned:
                    path = core/relative; path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(('pinned '+relative).encode())
                registry = core/'include/registry.go'; registry.parent.mkdir()
                registry.write_text('original ordinary registry\n')
                sing = core/'patched-sing'; sing.mkdir()
                (sing/'association.go').write_text('original patched control reader\n')
                packet = types.SimpleNamespace(COPY='patched-sing')
                verified = []
                def verify(path):
                    verified.append(path)
                    if fault == 'changed-sing':
                        raise ValueError('patched association differs from original')
                packet.verify = verify
                owner = core/V.OWNER_PROJECTION
                if fault == 'missing-projection':
                    owner.unlink()
                elif fault == 'changed-projection':
                    owner.write_text('foreign owner')
                elif fault == 'linked-projection':
                    owner.unlink(); owner.symlink_to(source/V.OWNER)
                elif fault == 'changed-pinned':
                    (core/pinned[0]).write_text('changed pool')
                elif fault == 'ordinary-registration':
                    registry.write_text('routervpnnodesocks.Register(registry)')
                gate = types.SimpleNamespace(NODE=types.SimpleNamespace(
                    checked_sources=lambda path: (path, {'original-full-closure':'a'*64})),
                    BUILD=types.SimpleNamespace(PIN='b'*40))
                def pinned_read(command, cwd, timeout):
                    relative = command[2].split(':', 1)[1]
                    return ('pinned '+relative).encode()
                with patch.object(V, 'module', return_value=packet), \
                        patch.object(V.COMMON.subprocess, 'check_output', side_effect=pinned_read):
                    if fault:
                        with self.assertRaises(ValueError):
                            V.checked_sources(gate, source, core)
                    else:
                        records = V.checked_sources(gate, source, core)
                        self.assertEqual(verified, [core])
                        self.assertEqual(len(records), 9)
                        self.assertEqual(records['original-full-closure'], 'a'*64)
                        self.assertIn('owner-sing/association.go', records)


if __name__ == '__main__':
    unittest.main(verbosity=2)
