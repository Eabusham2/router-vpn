#!/usr/bin/env python3
"""Check strict required inventories; synthetic records are parser tests only."""
import importlib.util
import json
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('typed_connected_native', ROOT/'deploy/test_desktop_typed_connected_candidates.py')
G = importlib.util.module_from_spec(spec); spec.loader.exec_module(G)


class TypedConnectedNativeRunner(unittest.TestCase):
    def records(self, package, roots, failed=False, witness=''):
        wanted = G.MODULE if package == '.' else G.MODULE+'/'+package
        def row(action, name=None, output=None):
            value = {'Package': wanted, 'Action': action}
            if name: value['Test'] = name
            if output is not None: value['Output'] = output
            return value
        records = [row('start')]
        action = 'fail' if failed else 'pass'
        for root, children in roots.items():
            records.append(row('run', root))
            for child in children:
                records.append(row('run', root+'/'+child))
                if failed:
                    records.append(row('output', root+'/'+child, witness))
                records.append(row(action, root+'/'+child))
            records.append(row(action, root))
        return records+[row(action)]

    def encode(self, rows):
        return '\n'.join(map(json.dumps, rows))

    def test_exact_actual_source_inventory(self):
        self.assertEqual(sum(len(G.names(roots)) for roots in G.CASES.values()), 78)
        self.assertEqual(len(G.positive_phases()), 17)
        source = (ROOT/'mobile/desktop/node_chain_socks_candidates_test.go.tmpl').read_text()
        for variable, expected in (('desktopTypedCandidateAdmissionFaults', G.ADMISSION), ('desktopTypedCandidateDrainFaults', G.DRAIN)):
            body = source.split('var '+variable+' = []string{',1)[1].split('}',1)[0]
            self.assertEqual(tuple(re.findall(r'"([^\"]+)"',body)), expected)
        roots = set()
        for family in ('socks', 'connect'):
            text = (ROOT/'mobile/desktop'/('node_chain_'+family+'_candidates_test.go.tmpl')).read_text()
            roots.update(re.findall(r'^func (Test\w+)\(', text, re.M))
        self.assertEqual(roots, set(G.CASES['cmd/sing-box']))
        self.assertIn('[]int{3, 4, 8}', source)
        self.assertIn('dials.Load() != 50', source)
        self.assertIn('accepted.Load() != 50', source)
        self.assertIn('x509.SetFallbackRoots(roots)', source)
        self.assertIn('box.New(box.Options', source)
        self.assertIn('newRouterVPNNodeMTUContext(', source)

    def test_complete_ordered_partitions_and_original_box_controls(self):
        results = [(label, self.encode(self.records(package, roots)), 0)
                   for label, package, roots in G.positive_phases()]
        union = G.partition_verdict(results)
        self.assertEqual(union, {package: G.names(roots) for package, roots in G.CASES.items()})
        for i in range(len(results)):
            with self.subTest(missing=i), self.assertRaises(ValueError):
                G.partition_verdict(results[:i]+results[i+1:])
        for changed in (results[::-1], [results[0]]+results[:-1], results+[results[-1]]):
            with self.assertRaises(ValueError): G.partition_verdict(changed)

    def test_every_missing_native_case_is_refused(self):
        for _, package, roots in G.positive_phases():
            rows = self.records(package, roots)
            for missing in G.names(roots):
                with self.subTest(package=package, missing=missing), self.assertRaises(ValueError):
                    G.verdict(self.encode([row for row in rows if row.get('Test') != missing]), 0, package, roots)

    def test_duplicate_foreign_early_or_late_native_events_are_refused(self):
        for _, package, roots in G.positive_phases():
            original = self.records(package, roots)
            for field, value in (('Package','foreign'), ('Test','TestForeign'), ('Action','skip'), ('Action','fail')):
                rows = [dict(row) for row in original]; rows[1][field] = value
                with self.assertRaises(ValueError): G.verdict(self.encode(rows), 0, package, roots)
            root = next(iter(roots)); index = next(i for i,row in enumerate(original) if row.get('Test')==root and row['Action']=='pass')
            early = list(original); early.insert(2,early.pop(index))
            mutations = [original[:2]+[original[1]]+original[2:], original+[original[1]],
                         original[:2]+[dict(original[1], Action='output',Output='DATA RACE')]+original[2:]]
            if roots[root]:
                mutations.append(early)
            for rows in mutations:
                self.assertNotEqual(rows, original)
                with self.assertRaises(ValueError): G.verdict(self.encode(rows), 0, package, roots)
            encoded = self.encode(original).splitlines()
            duplicate = '{"Action":"skip",'+encoded[0][1:]
            with self.assertRaises(ValueError):
                G.verdict('\n'.join([duplicate, *encoded[1:]]), 0, package, roots)
            with self.assertRaises(ValueError): G.verdict(self.encode(original), 1, package, roots)

    def test_build_diagnostics_never_substitute_for_native_execution(self):
        _, package, roots = G.positive_phases()[0]
        rows = self.records(package, roots)
        build = {'Action':'build-output','ImportPath':G.MODULE+'/'+package+'.test','Output':'original linker diagnostic\n'}
        self.assertEqual(len(G.verdict(self.encode([build]+rows),0,package,roots)),len(G.names(roots)))
        for changed in ([build], rows+[build], [dict(build,ImportPath='foreign')]+rows,
                        [dict(build,Output='x'*65537)]+rows, rows[:-1]):
            with self.assertRaises(ValueError): G.verdict(self.encode(changed),0,package,roots)

    def test_each_control_has_one_real_source_boundary_and_exact_witness(self):
        self.assertEqual(len(G.CONTROLS),3)
        for label, relative, before, after, root, child, witness in G.CONTROLS:
            self.assertNotEqual(before,after); self.assertTrue(witness)
            self.assertIn(child,G.CASES['cmd/sing-box'][root])
            template = relative.split('/')[-1].removeprefix('routervpn_')+'.tmpl'
            self.assertEqual((ROOT/'mobile/desktop'/template).read_text().count(before),1,label)
            roots = {root:(child,)}
            rows = self.records('cmd/sing-box',roots,True,witness)
            self.assertTrue(G.control_verdict(self.encode(rows),1,root,child,witness))
            for changed in (self.records('cmd/sing-box',roots),
                            self.records('cmd/sing-box',roots,True,'different assertion'),
                            rows[:-1], rows+[rows[-1]],
                            [dict(row,Action='skip') if row.get('Test')==root+'/'+child and row['Action']=='fail' else row for row in rows],
                            [dict(row,Output='DATA RACE '+witness) if row['Action']=='output' else row for row in rows]):
                with self.assertRaises(ValueError): G.control_verdict(self.encode(changed),1,root,child,witness)
            for code in (0, 2, -9):
                with self.assertRaises(ValueError): G.control_verdict(self.encode(rows),code,root,child,witness)
            for failure in ('panic: aborted', 'fatal error: aborted', 'signal: killed', 'test timed out', 'compile: invalid', 'link: invalid', 'exit status 2'):
                changed = [dict(row,Output=witness+' '+failure) if row['Action']=='output' else row for row in rows]
                with self.assertRaises(ValueError): G.control_verdict(self.encode(changed),1,root,child,witness)
            encoded = self.encode(rows).splitlines()
            duplicate = '{"Action":"skip",'+encoded[0][1:]
            with self.assertRaises(ValueError):
                G.control_verdict('\n'.join([duplicate, *encoded[1:]]),1,root,child,witness)

    def test_original_fifty_and_native_bounds_are_explicit(self):
        for _,package,roots in G.positive_phases():
            command = G.command('go',G.TAGS,True,package,roots)
            for argument in ('-race','-mod=readonly','-p=1','-count=1','-timeout=150s'):
                self.assertIn(argument,command)
        source = (ROOT/'deploy/test_desktop_typed_connected_candidates.py').read_text()
        self.assertIn('remaining = 900-',source)
        self.assertIn('timeout=min(600, remaining)',source)
        self.assertIn('timeout=600)',source)
        self.assertIn('if source_identity(core) != before:',source)
        tests = (ROOT/'mobile/desktop/node_chain_socks_candidates_test.go.tmpl').read_text()
        self.assertIn('time.Now().Add(hopmeasure.RequestTimeout)',tests)
        self.assertNotIn('Skip(',tests)

    def test_all_new_native_files_are_shipping_command_templates(self):
        prep = G.load('prepare-desktop-external')
        excluded = set(prep.PT_TEMPLATES)|set(prep.BOX_TEMPLATES)|set(prep.PEER_TEMPLATES)
        for family in ('socks','connect'):
            for suffix in ('','_test'):
                name = 'node_chain_'+family+'_candidates'+suffix+'.go.tmpl'
                self.assertNotIn(name,excluded)
                self.assertIn(b'\npackage main\n',b'\n'+(ROOT/'mobile/desktop'/name).read_bytes())
                self.assertEqual(G.TEMPLATES[name.removesuffix('.go.tmpl')], 'cmd/sing-box/routervpn_'+name.removesuffix('.tmpl'))
        self.assertIn("glob('node*.go.tmpl')",(ROOT/'deploy/prepare-desktop-external.py').read_text())

    def test_matching_native_hosts_require_positive_and_causal_phases(self):
        source = (ROOT/'deploy/build-native-runtime.py').read_text()
        common = source.split('if target == host:',1)[1].split("            if target.startswith(('linux/', 'windows/')):",1)[0]
        self.assertIn("for typed_candidate_phase in ('baselines', 'controls'):",common)
        self.assertIn("ROOT/'deploy/test_desktop_typed_connected_candidates.py'",common)
        self.assertIn("'--phase', typed_candidate_phase",common)
        inputs = source.split('def inputs():',1)[1].split('\ndef ',1)[0]
        for name in ('test_desktop_typed_connected_candidates.py','test_desktop_typed_connected_candidates_runner.py'):
            self.assertIn("ROOT/'deploy/"+name+"'",inputs)


if __name__=='__main__':
    unittest.main()
