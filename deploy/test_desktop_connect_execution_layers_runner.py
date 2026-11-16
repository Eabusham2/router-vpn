#!/usr/bin/env python3
"""Keep the compiled CONNECT layer inventory and causal controls mandatory."""
import importlib.util
import json
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('connect_layers_gate', ROOT/'deploy/test_desktop_connect_execution_layers.py')
G = importlib.util.module_from_spec(spec)
spec.loader.exec_module(G)


def events(roots):
    expected = G.DRIVER.expected(roots)
    result = [{'Package':G.PACKAGE,'Action':'start'}]
    def node(name):
        result.append({'Package':G.PACKAGE,'Action':'run','Test':name})
        descendants = {value for value in expected if value.startswith(name+'/')}
        children = [value for value in descendants if not any(value.startswith(parent+'/') for parent in descendants if parent != value)]
        for child in sorted(children): node(child)
        result.append({'Package':G.PACKAGE,'Action':'pass','Test':name})
    for root in roots: node(root)
    result.append({'Package':G.PACKAGE,'Action':'pass'})
    return result


def encode(rows):
    return '\n'.join(json.dumps(row) for row in rows)


class Gate(unittest.TestCase):
    def test_complete_native_target_inventories(self):
        for system in ('linux','windows','darwin'):
            for arch in ('amd64','arm64'):
                roots = G.inventory(system+'/'+arch)
                self.assertEqual(set(roots), set(G.SOURCE) | (set() if system == 'darwin' else set(G.PUBLIC)))
                self.assertEqual(len(G.DRIVER.expected(roots)), 15 if system == 'darwin' else 31)
                G.require_verdicts(encode(events(roots)), roots)
        for target in ('linux/386','android/arm64','darwin/arm',''):
            with self.assertRaises(ValueError): G.inventory(target)

    def test_every_original_record_is_required_once(self):
        roots = G.inventory('linux/amd64')
        original = events(roots)
        for name in G.DRIVER.expected(roots):
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    G.require_verdicts(encode([row for row in original if row.get('Test') != name]), roots)
                duplicate = next(row for row in original if row.get('Test') == name and row['Action'] == 'run')
                with self.assertRaises(ValueError):
                    G.require_verdicts(encode(original[:-1]+[duplicate]+original[-1:]), roots)

    def test_fail_skip_race_and_wrong_package_are_not_passes(self):
        roots = G.inventory('linux/amd64')
        original = events(roots)
        for action in ('skip','fail','build-fail'):
            rows = [dict(row) for row in original]
            rows[2]['Action'] = action
            with self.assertRaises(ValueError): G.require_verdicts(encode(rows), roots)
        rows = [dict(row) for row in original]; rows[1]['Package']='foreign'
        with self.assertRaises(ValueError): G.require_verdicts(encode(rows), roots)
        rows = [dict(row) for row in original]; rows.insert(2,{'Package':G.PACKAGE,'Action':'output','Test':rows[1]['Test'],'Output':'WARNING: DATA RACE'})
        with self.assertRaises(ValueError): G.require_verdicts(encode(rows), roots)
        with self.assertRaises(ValueError): G.require_verdicts(encode([original[0], original[-1]]), roots)

    def test_actual_go_roots_and_original_control_boundaries(self):
        source=(ROOT/'cmd/client/desktop_node_chain_connect_execution_layers_test.go').read_text()
        roots=set(re.findall(r'^func (Test\w+)\(',source,re.M))
        self.assertEqual(roots,set(G.SOURCE)|set(G.PUBLIC))
        self.assertEqual(len(G.CONTROLS),2)
        for path,before,after,root,child,witness in G.CONTROLS:
            self.assertEqual((ROOT/path).read_text().count(before),1)
            self.assertIn(root,G.SOURCE)
            self.assertIn(child,G.SOURCE[root])
            self.assertIn(witness,source)
            self.assertNotEqual(before,after)

    def test_actual_native_build_requires_both_phases_and_runner(self):
        source=(ROOT/'deploy/build-native-runtime.py').read_text()
        self.assertEqual(source.count("for connect_layer_phase in ('source', 'controls'):"),1)
        self.assertIn("ROOT/'deploy/test_desktop_connect_execution_layers_runner.py'],",source)
        self.assertIn("'--phase', connect_layer_phase, '--receipt', temp/('connect-layers-'+connect_layer_phase+'.json')",source)
        self.assertIn("*(['--without-race'] if not race else [])], cwd=ROOT, env=env, timeout=1200)",source)
        self.assertRegex(G.source_identity(),r'^[0-9a-f]{64}$')


if __name__ == '__main__': unittest.main()
