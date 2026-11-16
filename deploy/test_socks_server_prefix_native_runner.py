#!/usr/bin/env python3
"""Strict parser controls; these are not encrypted native acceptance."""
from pathlib import Path
import ast
import importlib.util
import json
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('socks_prefix_native', ROOT/'deploy/test_socks_server_prefix_native.py')
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)



def require_registration(source):
    tree = ast.parse(source)
    expected = ast.parse("""if target.startswith('linux/'):
    run([sys.executable, ROOT/'deploy/test_socks_server_prefix_native_runner.py'], cwd=ROOT, env=env, timeout=60)
    socks_prefix = load('socks_server_prefix_native', 'test_socks_server_prefix_native.py')
    socks_prefix.execute(source, target, ','.join(tags(target)), env, run)
""").body[0]
    blocks = [node for node in ast.walk(tree) if isinstance(node, ast.If)
              and any(isinstance(child, ast.Constant) and child.value == 'deploy/test_socks_server_prefix_native_runner.py'
                      for child in ast.walk(node))]
    exact = [node for node in blocks if ast.dump(node) == ast.dump(expected)]
    if len(exact) != 1:
        raise ValueError('original mandatory SOCKS prefix native invocation changed')
    inputs = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'inputs')
    paths = [node.value for node in ast.walk(inputs) if isinstance(node, ast.Constant)]
    for name in ('deploy/test_socks_server_prefix_native.py', 'deploy/test_socks_server_prefix_native_runner.py'):
        if paths.count(name) != 1:
            raise ValueError('SOCKS prefix gate lost original artifact inputs')


def events(family):
    root = GATE.PREFIX+family
    rows = [{'Action': 'start', 'Package': GATE.PACKAGE}, {'Action': 'run', 'Package': GATE.PACKAGE, 'Test': root}]
    for child in GATE.CASES[family]:
        rows += [{'Action': action, 'Package': GATE.PACKAGE, 'Test': root+'/'+child} for action in ('run', 'pass')]
    return rows+[{'Action': 'pass', 'Package': GATE.PACKAGE, 'Test': root}, {'Action': 'pass', 'Package': GATE.PACKAGE}]


def wire(rows):
    return '\n'.join(json.dumps(row) for row in rows)


class NativePrefix(unittest.TestCase):
    def test_complete_original_inventory(self):
        self.assertEqual(sum(GATE.verdict(wire(events(family)), family) for family in GATE.CASES), 24)
        self.assertEqual(tuple(GATE.CASES), ('EncryptedWG', 'EncryptedFast', 'EncryptedStrong', 'Refusals'))
        for family in GATE.CASES:
            self.assertIn('func '+GATE.PREFIX+family+'(t *testing.T)', (ROOT/'mobile/desktop/node_chain_socks_server_prefix_test.go.tmpl').read_text())

    def test_every_omission_refused(self):
        for family in GATE.CASES:
            original = events(family)
            for i in range(len(original)):
                with self.subTest(family=family, omitted=i), self.assertRaises(ValueError):
                    GATE.verdict(wire(original[:i]+original[i+1:]), family)

    def test_fail_skip_duplicate_unknown_and_foreign_package_refused(self):
        for fault in ('fail', 'skip', 'duplicate', 'unknown', 'foreign-package', 'late'):
            rows = events('EncryptedWG')
            if fault in ('fail', 'skip'):
                rows[3]['Action'] = fault
            elif fault == 'duplicate':
                rows.insert(4, dict(rows[3]))
            elif fault == 'unknown':
                rows[2]['Test'] += '-foreign'; rows[3]['Test'] += '-foreign'
            elif fault == 'foreign-package':
                rows[3]['Package'] += '/foreign'
            else:
                rows.append(dict(rows[3]))
            with self.subTest(fault=fault), self.assertRaises(ValueError):
                GATE.verdict(wire(rows), 'EncryptedWG')

    def test_mandatory_builder_and_original_bounds(self):
        source = (ROOT/'deploy/build-native-runtime.py').read_text()
        require_registration(source)
        for old, new in (("socks_prefix.execute(source, target", "socks_prefix.execute(foreign, target"),
                         ("socks_prefix.execute(source, target", "False and socks_prefix.execute(source, target"),
                         ("ROOT/'deploy/test_socks_server_prefix_native.py',", "ROOT/'deploy/omitted.py',")):
            with self.subTest(control=old), self.assertRaises(ValueError):
                require_registration(source.replace(old, new, 1))
        runner = (ROOT/'deploy/test_socks_server_prefix_native.py').read_text()
        self.assertIn("'-test.timeout=120s'", runner)
        self.assertIn('timeout=135', runner)
        self.assertIn("'installed_carrier_acceptance': False", runner)
        prep = (ROOT/'deploy/prepare-desktop-external.py').read_text()
        self.assertEqual(prep.count("'node_chain_socks_server_prefix_test.go.tmpl'"), 2)


if __name__ == '__main__':
    unittest.main()
