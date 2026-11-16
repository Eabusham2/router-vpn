#!/usr/bin/env python3
"""Strict encrypted Local OpenVPN inventory and required-build controls."""
import ast
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('openvpn_local_components', ROOT/'deploy/test_node_chain_openvpn_encrypted_local.py')
RUN = importlib.util.module_from_spec(spec)
spec.loader.exec_module(RUN)


def transcript(case, failed=False, witness=''):
    child = RUN.TEST+'/'+case.replace('/', '_')
    def row(action, test=None, **fields):
        return dict(Action=action, Package=RUN.PACKAGE, **({'Test': test} if test else {}), **fields)
    rows = [row('start'), row('run', RUN.TEST), row('run', child)]
    if witness:
        rows.append(row('output', child, Output=witness))
    action = 'fail' if failed else 'pass'
    return rows+[row(action, child), row(action, RUN.TEST), row(action)]


def output(rows):
    return '\n'.join(json.dumps(row) for row in rows)+'\n'


CALL = "openvpn_local.execute(source, target, ','.join(tags(target)), env, run)"


def required_wiring(source):
    tree = ast.parse(source)
    parents = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}
    expected = ast.dump(ast.parse(CALL).body[0].value, include_attributes=False)
    calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)
             and ast.dump(node, include_attributes=False) == expected]
    if len(calls) != 1:
        raise ValueError('Required encrypted Local native invocation missing or duplicated')
    parent = parents.get(calls[0])
    while parent is not None and not isinstance(parent, ast.If):
        parent = parents.get(parent)
    guard = ast.dump(ast.parse("target.startswith('linux/')", mode='eval').body, include_attributes=False)
    if parent is None or ast.dump(parent.test, include_attributes=False) != guard:
        raise ValueError('Required encrypted Local invocation lost its native Linux guard')


class EncryptedLocalOpenVPNRunner(unittest.TestCase):
    def test_complete_native_matrix(self):
        self.assertEqual(len(RUN.CASES), 14)
        self.assertEqual(len(set(RUN.CASES)), 14)
        for network in ('tcp', 'udp'):
            for layer in ('off', 'aes-256-gcm', 'aes-256-gcm+xor-whitening'):
                self.assertIn(f'{network}/{layer}/original', RUN.CASES)
            for fault in ('provider-password', 'selected-dns', 'final-identity', 'reconnect'):
                self.assertIn(f'{network}/off/{fault}', RUN.CASES)
        for case in RUN.CASES:
            self.assertEqual(RUN.verdict(output(transcript(case)), case), 2)

    def test_every_omission_duplicate_and_order_is_refused(self):
        case = RUN.CASES[0]
        rows = transcript(case)
        changed = [rows[:i]+rows[i+1:] for i in range(len(rows))]
        changed += [rows[:i]+[rows[i]]+rows[i:] for i in range(len(rows))]
        changed += [rows[:2]+[rows[3], rows[2]]+rows[4:], rows[:-1], rows+[rows[-1]]]
        for bad in changed:
            with self.subTest(rows=bad), self.assertRaises(ValueError):
                RUN.verdict(output(bad), case)

    def test_skip_fail_foreign_case_package_and_terminal_are_refused(self):
        case = RUN.CASES[0]
        for mode in ('skip', 'fail', 'foreign-case', 'foreign-package', 'false-terminal'):
            rows = transcript(case)
            if mode == 'skip': rows[3]['Action'] = 'skip'
            if mode == 'fail': rows = transcript(case, True)
            if mode == 'foreign-case': rows = transcript(RUN.CASES[1])
            if mode == 'foreign-package': rows[0]['Package'] = 'foreign'
            if mode == 'false-terminal': rows[-1] = dict(Action='output', Package=RUN.PACKAGE, Output='PASS')
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                RUN.verdict(output(rows), case)
        with self.assertRaises(ValueError): RUN.verdict(output(transcript(case)), 'foreign')

    def test_success_cannot_conceal_race_or_fatal_output(self):
        for marker in ('panic:', 'fatal error:', 'test timed out', 'WARNING: DATA RACE'):
            with self.subTest(marker=marker), self.assertRaises(ValueError):
                RUN.verdict(output(transcript(RUN.CASES[0], witness=marker)), RUN.CASES[0])

    def test_actual_controls_require_exact_failure_and_join(self):
        for _, case, _, _, _, witness in RUN.CONTROLS:
            self.assertTrue(RUN.rejected(output(transcript(case, True, witness)), case, witness))
            self.assertFalse(RUN.rejected(output(transcript(case, True, 'unrelated failure')), case, witness))
            self.assertFalse(RUN.rejected(output(transcript(case, False, witness)), case, witness))
            for marker in ('panic:', 'fatal error:', 'test timed out', 'WARNING: DATA RACE',
                           'original retirement did not join', 'reference source did not join', 'failed retirement'):
                try:
                    accepted = RUN.rejected(output(transcript(case, True, witness+'\n'+marker)), case, witness)
                except ValueError:
                    accepted = False
                self.assertFalse(accepted)
        with self.assertRaises(ValueError): RUN.rejected('build failed', RUN.CASES[0], 'witness')

    def test_source_helpers_are_original_bytes(self):
        originals = RUN.load('test_server_node_chain_openvpn_native.py').sources()
        projected = RUN.sources()
        self.assertEqual(set(projected), {*originals, 'openvpn_execution_component_test.go'})
        for name, raw in originals.items(): self.assertEqual(projected[name], raw)
        self.assertEqual(projected['openvpn_execution_component_test.go'], (ROOT/RUN.TEMPLATE).read_bytes())

    def test_original_production_causal_anchors_are_unique(self):
        prep = RUN.load('prepare-mobile-node-chain.py')
        targets = {target: name for name, target in prep.TEMPLATES.items()}
        for _, case, target, before, after, witness in RUN.CONTROLS:
            self.assertEqual((ROOT/'mobile/chain'/targets[target]).read_text().count(before), 1)
            self.assertNotEqual(before, after)
            self.assertIn(case, RUN.CASES)
            self.assertIn(witness, (ROOT/RUN.TEMPLATE).read_text())

    def test_native_registration_and_architecture_are_required(self):
        bad = [('linux/amd64', 'with_wireguard', {'GOOS': 'linux', 'GOARCH': 'amd64', 'CGO_ENABLED': '1'}),
               ('windows/amd64', 'with_openvpn', {'GOOS': 'windows', 'GOARCH': 'amd64', 'CGO_ENABLED': '1'}),
               ('linux/amd64', 'with_openvpn', {'GOOS': 'linux', 'GOARCH': 'arm64', 'CGO_ENABLED': '1'}),
               ('linux/amd64', 'with_openvpn', {'GOOS': 'linux', 'GOARCH': 'amd64', 'CGO_ENABLED': '0'})]
        for target, tags, env in bad:
            with self.subTest(target=target, tags=tags, env=env), self.assertRaises(ValueError):
                RUN.execute(ROOT, target, tags, env, lambda *a, **k: self.fail('wrong target executed'))

    def test_required_release_and_source_closure(self):
        builder = RUN.load('build-native-runtime.py')
        inputs = set(builder.inputs())
        for path in ('deploy/test_node_chain_openvpn_encrypted_local.py',
                     'deploy/test_node_chain_openvpn_encrypted_local_runner.py', RUN.TEMPLATE):
            self.assertIn(ROOT/path, inputs)
        required_wiring((ROOT/'deploy/build-native-runtime.py').read_text())

    def test_required_native_call_omission_duplicate_or_bypass_is_refused(self):
        source = (ROOT/'deploy/build-native-runtime.py').read_text()
        self.assertEqual(source.count(CALL), 1)
        for replacement in ('pass', '# '+CALL, CALL+'; '+CALL,
                            CALL.replace('target,', '"windows/amd64",', 1), 'None'):
            with self.subTest(replacement=replacement), self.assertRaises(ValueError):
                required_wiring(source.replace(CALL, replacement, 1))
        with self.assertRaises(ValueError):
            required_wiring(source.replace('                '+CALL,
                                          '                if False:\n                    '+CALL, 1))


if __name__ == '__main__': unittest.main()
