#!/usr/bin/env python3
"""Strict inventory tests; synthetic JSON here proves only the parser."""
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('selected_latency_gate', ROOT/'deploy/test_desktop_selected_latency.py')
G = importlib.util.module_from_spec(spec); spec.loader.exec_module(G)


class SelectedLatencyRunner(unittest.TestCase):
    def rows(self, root, children):
        package = G.ORIGINAL.CHILD.MODULE+'/cmd/sing-box'
        def event(action, name=None):
            return dict(Package=package, Action=action, **({'Test': name} if name else {}))
        rows = [event('start'), event('run', root)]
        for child in children:
            rows += [event('run', root+'/'+child), event('pass', root+'/'+child)]
        return rows+[event('pass', root), event('pass')]

    def check(self, rows, root, children):
        return G.ORIGINAL.CHILD.verdict('\n'.join(map(json.dumps, rows)), 0, 'cmd/sing-box', {root: children})

    def test_complete_exact_records(self):
        count = 0
        for root, children in G.ROOTS.items():
            count += len(self.check(self.rows(root, children), root, children))
        self.assertEqual(count, 55)

    def test_every_missing_failed_skipped_or_duplicate_case_refused(self):
        for root, children in G.ROOTS.items():
            rows = self.rows(root, children)
            for name in (root, *(root+'/'+child for child in children)):
                with self.subTest(name=name):
                    with self.assertRaises(ValueError):
                        self.check([v for v in rows if v.get('Test') != name], root, children)
                    for action in ('skip', 'fail'):
                        changed = [dict(v, Action=action) if v.get('Test') == name and v['Action'] == 'pass' else v for v in rows]
                        with self.assertRaises(ValueError): self.check(changed, root, children)
            with self.assertRaises(ValueError): self.check(rows[:2]+[rows[1]]+rows[2:], root, children)

    def test_actual_projection_and_tagged_boundary(self):
        value = G.FIXTURE.copies()
        self.assertEqual(list(value), [G.FIXTURE.TARGET])
        raw = value[G.FIXTURE.TARGET].decode()
        self.assertTrue(raw.startswith('//go:build '+G.FIXTURE.TAG+'\n'))
        self.assertIn('NewNodeChainExecutionRuntime(projection, e)', raw)
        self.assertIn('count.Add(1) // actual benchmark request', raw)
        self.assertIn('peer := netip.MustParseAddr(f.engine.projection.policy.source.Request.Peer)', raw)
        helper = 'desktopLatencyOriginalMultipleImportedExecutionPublicFixtures('
        self.assertEqual(raw.count('func '+helper), 1)
        self.assertIn(helper+'t, f, local, serverProofs, trust)', raw)
        for method in ('ObserveMultipleImportedExecutionContext', 'MultipleImportedExecutionRetiredContext'):
            self.assertEqual(raw.count('func (e *desktopLatencyOriginalNodeChainExecutionRuntimeEngine) '+method+'('), 1)
        self.assertNotIn('func Test', raw)

    def test_original_deadlines_and_causal_anchors(self):
        command = G.command('go', 'with_openvpn', True, 'selected')
        for item in ('-race', '-mod=readonly', '-p=1', '-timeout=120s'):
            self.assertIn(item, command)
        self.assertIn('-tags=with_openvpn,'+G.FIXTURE.TAG, command)
        self.assertEqual(len(G.CONTROLS), 3)
        for relative, before, after, root, child, witness in G.CONTROLS:
            template = ROOT/'mobile/desktop'/relative.removeprefix('cmd/sing-box/routervpn_')
            template = Path(str(template)+'.tmpl')
            self.assertEqual(template.read_text().count(before), 1)
            self.assertNotEqual(before, after)
            self.assertIn(child, G.ROOTS[root]); self.assertTrue(witness)

    def test_all_hosts_require_both_phases_and_exact_sources(self):
        source = (ROOT/'deploy/build-native-runtime.py').read_text()
        self.assertIn("for selected_latency_phase in ('baselines', 'controls'):", source)
        for name in ('test_desktop_selected_latency.py', 'test_desktop_selected_latency_runner.py', 'prepare-desktop-selected-latency-test.py'):
            self.assertIn("ROOT/'deploy/"+name+"'", source)
        prepare = (ROOT/'deploy/prepare-desktop-external.py').read_text()
        self.assertIn('*SELECTED_LATENCY_TEST.inputs()', prepare)
        self.assertIn('SELECTED_LATENCY_TEST.copies()', prepare)


if __name__ == '__main__':
    unittest.main()
