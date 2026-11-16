#!/usr/bin/env python3
"""Reject incomplete child/Box evidence and require every shipping host phase."""
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('socks_child', ROOT/'deploy/test_desktop_socks_execution_child.py')
G = importlib.util.module_from_spec(spec); spec.loader.exec_module(G)


class ChildRunner(unittest.TestCase):
    def records(self, package, roots):
        expected = G.MODULE if package == '.' else G.MODULE+'/'+package
        def row(action, name=None):
            value = {'Package': expected, 'Action': action}
            if name: value['Test'] = name
            return value
        records = [row('start')]
        for root, children in roots.items():
            records.append(row('run', root))
            for child in children:
                records.extend((row('run', root+'/'+child), row('pass', root+'/'+child)))
            records.append(row('pass', root))
        return records+[row('pass')]

    def check(self, rows, package, roots, code=0):
        return G.verdict('\n'.join(map(json.dumps, rows)), code, package, roots)

    def test_every_original_package_and_case(self):
        for darwin, total in ((False, 55), (True, 82)):
            actual = 0
            for package, roots in G.inventory(darwin).items():
                actual += len(self.check(self.records(package, roots), package, roots))
            self.assertEqual(actual, total)

    def test_each_missing_root_or_child_is_refused(self):
        for package, roots in G.inventory(True).items():
            for missing in G.names(roots):
                with self.subTest(package=package, missing=missing), self.assertRaises(ValueError):
                    self.check([row for row in self.records(package, roots) if row.get('Test') != missing], package, roots)

    def test_no_skip_failure_race_or_nonzero_acceptance(self):
        for package, roots in G.inventory().items():
            for action in ('fail', 'skip'):
                rows=self.records(package, roots); rows[3]['Action']=action
                with self.assertRaises(ValueError): self.check(rows, package, roots)
            rows=self.records(package, roots); rows.insert(3, dict(rows[2], Action='output', Output='DATA RACE'))
            with self.assertRaises(ValueError): self.check(rows, package, roots)
            with self.assertRaises(ValueError): self.check(self.records(package, roots), package, roots, 1)

    def test_foreign_duplicate_and_late_events_are_refused(self):
        for package, roots in G.inventory().items():
            for field, value in (('Package', 'foreign'), ('Test', 'TestForeign')):
                rows=self.records(package, roots); rows[1][field]=value
                with self.assertRaises(ValueError): self.check(rows, package, roots)
            rows=self.records(package, roots); rows.insert(2, rows[1])
            with self.assertRaises(ValueError): self.check(rows, package, roots)
            rows=self.records(package, roots); rows.append(rows[1])
            with self.assertRaises(ValueError): self.check(rows, package, roots)
            rows=self.records(package, roots)
            root=next(iter(roots)); index=next(i for i,row in enumerate(rows) if row.get('Test')==root and row['Action']=='pass')
            rows.insert(2,rows.pop(index))
            with self.assertRaises(ValueError): self.check(rows, package, roots)

    def test_bounded_build_diagnostics_do_not_replace_execution(self):
        for package, roots in G.inventory().items():
            wanted=G.MODULE if package=='.' else G.MODULE+'/'+package
            build={'Action':'build-output','ImportPath':wanted+'.test','Output':'original linker diagnostic\n'}
            rows=self.records(package, roots)
            self.assertEqual(len(self.check([build]+rows, package, roots)),len(G.names(roots)))
            for changed in ([build], rows[:-1], rows+[build], [dict(build,Output='x'*65537)]+rows, [dict(build,ImportPath='foreign')]+rows):
                with self.assertRaises(ValueError): self.check(changed, package, roots)

    def test_exact_native_deadlines_and_two_causal_controls(self):
        self.assertEqual(len(G.CONTROLS),2)
        for relative,before,after,test,child,witness in G.CONTROLS:
            self.assertNotEqual(before,after);self.assertTrue(witness);self.assertIn(test,G.CASES['cmd/sing-box']);self.assertIn(child,G.CASES['cmd/sing-box'][test])
        for package in G.CASES:
            command=G.command('go',G.TAGS,True,package,'selected')
            for argument in ('-race','-mod=readonly','-p=1','-timeout=120s'):self.assertIn(argument,command)
        self.assertEqual((ROOT/'deploy/test_desktop_socks_execution_child.py').read_text().count('timeout=600'),2)

    def test_all_shipping_hosts_require_both_serial_phases(self):
        source=(ROOT/'deploy/build-native-runtime.py').read_text()
        common=source.split('if target == host:',1)[1].split("            if target.startswith(('linux/', 'windows/')):",1)[0]
        self.assertIn("for socks_phase in ('baselines', 'controls'):",common)
        self.assertIn("ROOT/'deploy/test_desktop_socks_execution_child.py'",common)
        self.assertIn("'--phase', socks_phase",common)
        self.assertIn("*(['--without-race'] if not race else [])",common)
        inputs=source.split('def inputs():',1)[1].split('\ndef ',1)[0]
        for name in ('test_desktop_socks_execution_child.py','test_desktop_socks_execution_child_runner.py'):self.assertIn("ROOT/'deploy/"+name+"'",inputs)


if __name__ == '__main__':
    unittest.main()
