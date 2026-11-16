#!/usr/bin/env python3
"""Adversarial checks for the required typed connected candidate controller gate."""
import ast
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('typed_candidate_gate', Path(__file__).with_name('test_desktop_typed_candidate_controller.py'))
G = importlib.util.module_from_spec(spec)
spec.loader.exec_module(G)


def events(root, children=(), failure=None):
    rows = [{'Action': 'start', 'Package': G.PACKAGE}, {'Action': 'run', 'Package': G.PACKAGE, 'Test': root}]
    for child in children:
        case = root+'/'+child
        rows.append({'Action': 'run', 'Package': G.PACKAGE, 'Test': case})
        if failure:
            rows.append({'Action': 'output', 'Package': G.PACKAGE, 'Test': case, 'Output': failure})
        rows.append({'Action': 'fail' if failure else 'pass', 'Package': G.PACKAGE, 'Test': case})
    rows.extend(({'Action': 'fail' if failure else 'pass', 'Package': G.PACKAGE, 'Test': root},
                 {'Action': 'fail' if failure else 'pass', 'Package': G.PACKAGE}))
    return '\n'.join(json.dumps(row) for row in rows)


class TypedCandidateControllerGateTests(unittest.TestCase):
    def test_exact_disjoint_inventory_and_every_missing_verdict(self):
        all_roots = set()
        for phase, roots, count in (('source', 7, 49), ('receipts', 3, 81), ('mailbox', 3, 21)):
            inventory = G.inventory(phase)
            self.assertEqual((len(inventory), len(G.COMMON.expected(inventory))), (roots, count))
            self.assertFalse(all_roots.intersection(inventory))
            all_roots.update(inventory)
            for root, children in inventory.items():
                raw = events(root, children)
                G.COMMON.BUILDER.verify_imported_native_verdicts(raw, G.PACKAGE, G.COMMON.expected({root: children}))
                for missing in G.COMMON.expected({root: children}):
                    changed = '\n'.join(line for line in raw.splitlines() if json.loads(line).get('Test') != missing)
                    with self.subTest(phase=phase, missing=missing), self.assertRaises(ValueError):
                        G.COMMON.BUILDER.verify_imported_native_verdicts(changed, G.PACKAGE, G.COMMON.expected({root: children}))
        self.assertEqual(len(all_roots), 13)
        with self.assertRaises(ValueError):
            G.inventory('unbounded')

    def test_causal_controls_reject_aborts_races_missing_and_success(self):
        self.assertEqual(len(G.CONTROLS), 3)
        for relative, before, after, root, child, witness in G.CONTROLS:
            self.assertEqual((G.ROOT/relative).read_text().count(before), 1)
            self.assertNotEqual(before, after)
            raw = events(root, (child,), witness)
            G.verify_control_result(subprocess.CompletedProcess([], 1, raw, ''), root, root+'/'+child, witness)
            for fault in ('pass', 'exit2', 'stderr', 'panic', 'race', 'missing', 'skip', 'foreign-test', 'root-pass', 'duplicate-key', 'duplicate-root-failure'):
                output, code, stderr = raw, 1, ''
                if fault == 'pass': code = 0
                elif fault == 'exit2': code = 2
                elif fault == 'stderr': stderr = 'compiler failure'
                elif fault in ('panic', 'race'):
                    output = output.replace(witness, witness+(' panic: aborted' if fault == 'panic' else ' DATA RACE'))
                elif fault == 'missing': output = output.replace(witness, 'unrelated failure')
                elif fault == 'skip': output = output.replace('"Action": "fail"', '"Action": "skip"', 1)
                elif fault == 'duplicate-key': output = output.replace('"Action": "start"', '"Action":"run", "Action":"start"', 1)
                elif fault in ('foreign-test', 'root-pass', 'duplicate-root-failure'):
                    rows = [json.loads(line) for line in output.splitlines()]
                    if fault == 'foreign-test':
                        rows[1:1] = [{'Action': 'run', 'Package': G.PACKAGE, 'Test': 'TestForeign'},
                                     {'Action': 'fail', 'Package': G.PACKAGE, 'Test': 'TestForeign'}]
                    elif fault == 'root-pass':
                        rows[-2]['Action'] = 'pass'
                    else:
                        rows.insert(-1, dict(rows[-2]))
                    output = '\n'.join(json.dumps(row) for row in rows)
                with self.subTest(root=root, fault=fault), self.assertRaises(ValueError):
                    G.verify_control_result(subprocess.CompletedProcess([], code, output, stderr), root, root+'/'+child, witness)

    def exercise(self, phase, fault=None, target='linux/amd64'):
        calls, images = [], []
        roots = G.inventory(phase)
        selected = list(roots)
        sequence = 0
        def invoke(command, environment, cwd, timeout):
            nonlocal sequence
            calls.append(command)
            self.assertEqual(environment, {'CAPTURED': 'original'})
            if command[1:3] == ['test', '-c']:
                self.assertEqual(timeout, 240)
                self.assertEqual(cwd, G.ROOT)
                self.assertEqual('-race' in command, target != 'windows/arm64')
                self.assertFalse(any(item.startswith('-vet=') for item in command))
                image = Path(command[command.index('-o')+1])
                image.write_bytes(b'original compiled image')
                images.append(image)
                return subprocess.CompletedProcess(command, 1 if fault == 'compile' else 0, '', '')
            self.assertEqual(timeout, 135)
            self.assertEqual(cwd, G.ROOT/'cmd/client')
            self.assertIn('-test.timeout=120s', command)
            self.assertIn('-test.count=1', command)
            root = selected[sequence]
            sequence += 1
            if phase == 'controls':
                control = G.CONTROLS[sequence-1]
                raw, code = events(root, (control[4],), control[5]), 1
            else:
                raw, code = events(root, roots[root]), 0
            if fault == 'missing':
                raw = '\n'.join(line for line in raw.splitlines() if json.loads(line).get('Test') != root)
            elif fault == 'status': code = 1 if phase != 'controls' else 0
            elif fault == 'image': images[-1].write_bytes(b'replaced image')
            elif fault == 'timeout': raise subprocess.TimeoutExpired(command, timeout)
            return subprocess.CompletedProcess(command, code, raw, '')
        with patch.object(G.COMMON, 'native_environment', return_value=('go', {'CAPTURED': 'original'}, target)), \
             patch.object(G, 'source_identity', return_value='original-source'), patch.object(G.COMMON, 'invoke', side_effect=invoke), contextlib.redirect_stdout(io.StringIO()):
            if fault:
                with self.assertRaises((ValueError, subprocess.TimeoutExpired)):
                    G.run(without_race=target == 'windows/arm64', phase=phase)
            else:
                result = G.run(without_race=target == 'windows/arm64', phase=phase)
                self.assertEqual(result['status'], 'passed')
                self.assertEqual(len(result['records']), len(roots))
        return calls

    def test_each_finite_phase_uses_original_compile_and_test_clocks(self):
        for target in ('linux/amd64', 'linux/arm64', 'windows/amd64', 'windows/arm64', 'darwin/amd64', 'darwin/arm64'):
            for phase in G.PHASES:
                with self.subTest(target=target, phase=phase):
                    calls = self.exercise(phase, target=target)
                    self.assertEqual(len(calls), 6 if phase == 'controls' else 1+len(G.inventory(phase)))
        for phase in G.PHASES:
            for fault in ('compile', 'missing', 'status', 'image', 'timeout'):
                with self.subTest(phase=phase, fault=fault):
                    self.assertLessEqual(len(self.exercise(phase, fault)), 2)

    def test_all_phases_and_inputs_remain_mandatory(self):
        source = (G.ROOT/'deploy/build-native-runtime.py').read_text()
        def required(text):
            tree = ast.parse(text)
            loops = [node for node in ast.walk(tree) if isinstance(node, ast.For) and isinstance(node.target, ast.Name) and node.target.id == 'typed_candidate_controller_phase']
            self.assertEqual(len(loops), 1)
            loop = loops[0]
            self.assertEqual(ast.literal_eval(loop.iter), G.PHASES)
            self.assertEqual(len(loop.body), 1)
            call = loop.body[0].value
            self.assertIsInstance(call, ast.Call)
            self.assertEqual(call.func.id, 'run')
            self.assertTrue(any(isinstance(node, ast.Constant) and node.value == 'deploy/test_desktop_typed_candidate_controller.py' for node in ast.walk(call)))
            self.assertEqual(next(ast.literal_eval(keyword.value) for keyword in call.keywords if keyword.arg == 'timeout'), 1800)
        required(source)
        original = "('source', 'receipts', 'mailbox', 'controls')"
        self.assertEqual(source.count(original), 1)
        for missing in G.PHASES:
            with self.subTest(missing=missing), self.assertRaises(AssertionError):
                required(source.replace(original, repr(tuple(item for item in G.PHASES if item != missing)), 1))
        self.assertLess(240+7*135+30, 1800)
        self.assertLess(3*(240+135)+30, 1800)
        registered = set(G.COMMON.BUILDER.inputs())
        for name in ('deploy/test_desktop_typed_candidate_controller.py', 'deploy/test_desktop_typed_candidate_controller_runner.py'):
            self.assertIn(G.ROOT/name, registered)
        self.assertIn('test_desktop_typed_candidate_controller_runner.py', source)
        self.assertEqual(len(G.source_identity()), 64)

    def test_source_workflow_independently_requires_both_gate_runners(self):
        source = (G.ROOT/'.github/workflows/multihop-contract.yml').read_text()
        commands = ('          python3 deploy/test_desktop_typed_candidate_controller_runner.py',
                    '          python3 deploy/test_desktop_typed_connected_candidates_runner.py')
        def required(text):
            marker = '      - name: Real-chain and shipping-route markers\n'
            self.assertEqual(text.count(marker), 1)
            step = text.split(marker, 1)[1].split('\n      - ', 1)[0]
            self.assertIn('        run: |\n', step)
            self.assertEqual(step.count('          python3 deploy/test_native_shipping_audit_gates.py'), 1)
            for command in commands:
                self.assertEqual(step.count(command), 1)
                self.assertLess(step.index('          python3 deploy/test_native_shipping_audit_gates.py'), step.index(command))
        required(source)
        for command in commands:
            with self.subTest(command=command), self.assertRaises(AssertionError):
                required(source.replace(command+'\n', '', 1))


if __name__ == '__main__':
    unittest.main()
