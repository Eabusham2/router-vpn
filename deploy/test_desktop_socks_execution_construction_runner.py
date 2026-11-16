#!/usr/bin/env python3
"""Strict native construction inventory and shipping selection checks."""
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('socks_desktop_construction', ROOT/'deploy/test_desktop_socks_execution_construction.py')
G = importlib.util.module_from_spec(spec)
spec.loader.exec_module(G)


class ConstructionRunner(unittest.TestCase):
    def records(self):
        def event(action, name=None):
            result = {'Package': 'github.com/sagernet/sing-box/'+G.PACKAGE, 'Action': action}
            if name:
                result['Test'] = name
            return result
        result = [event('start')]
        for root, children in G.CASES.items():
            result.append(event('run', root))
            for child in children:
                result.extend((event('run', root+'/'+child), event('pass', root+'/'+child)))
            result.append(event('pass', root))
        return result+[event('pass')]

    def check(self, rows, code=0):
        return G.verdict('\n'.join(map(json.dumps, rows)), code)

    def test_complete_original_roots_and_children(self):
        self.assertEqual(len(self.check(self.records())), 20)

    def test_each_missing_root_or_child_is_refused(self):
        for name in G.expected():
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.check([row for row in self.records() if row.get('Test') != name])

    def test_skip_failure_race_and_nonzero_cannot_be_acceptance(self):
        for action in ('skip', 'fail'):
            rows = self.records(); rows[3]['Action'] = action
            with self.subTest(action=action), self.assertRaises(ValueError):
                self.check(rows)
        rows = self.records(); rows.insert(3, dict(rows[2], Action='output', Output='DATA RACE'))
        with self.assertRaises(ValueError): self.check(rows)
        with self.assertRaises(ValueError): self.check(self.records(), 1)

    def test_foreign_duplicate_or_late_events_are_refused(self):
        for field, value in (('Package', 'foreign'), ('Test', 'TestForeign')):
            rows = self.records(); rows[1][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError): self.check(rows)
        rows = self.records(); rows.insert(2, rows[1])
        with self.assertRaises(ValueError): self.check(rows)
        rows = self.records(); rows.append(rows[1])
        with self.assertRaises(ValueError): self.check(rows)

    def test_build_or_partial_output_cannot_replace_runtime(self):
        with self.assertRaises(ValueError): self.check(self.records()[:-1])
        with self.assertRaises(ValueError): self.check([])

    def test_original_native_limits_and_causal_selection(self):
        command = G.command('pinned-go', G.TAGS, True, 'selected')
        for value in ('-race', '-mod=readonly', '-p=1', '-timeout=120s', './cmd/sing-box'):
            self.assertIn(value, command)
        self.assertNotIn('-race', G.command('pinned-go', G.TAGS, False, 'selected'))
        source = (ROOT/'deploy/test_desktop_socks_execution_construction.py').read_text()
        self.assertEqual(source.count('timeout=600'), 2)
        self.assertIn("before = 'c.self != c || '", source)
        self.assertIn("test+'/copy'", source)

    def test_all_shipping_hosts_require_this_gate(self):
        source = (ROOT/'deploy/build-native-runtime.py').read_text()
        common = source.split('if target == host:', 1)[1].split("            if target.startswith(('linux/', 'windows/')):", 1)[0]
        self.assertIn("            run([sys.executable, ROOT/'deploy/test_desktop_socks_execution_construction_runner.py'],", common)
        self.assertIn("            run([sys.executable, ROOT/'deploy/test_desktop_socks_execution_construction.py',", common)
        self.assertIn("'--core', source, '--tags='+','.join(tags(target))", common)
        self.assertIn("*(['--without-race'] if not race else [])", common)
        inputs = source.split('def inputs():', 1)[1].split('\ndef ', 1)[0]
        for name in ('test_desktop_socks_execution_construction.py', 'test_desktop_socks_execution_construction_runner.py', 'test_mobile_node_chain_execution.py'):
            self.assertIn("ROOT/'deploy/"+name+"'", inputs)


if __name__ == '__main__':
    unittest.main()
