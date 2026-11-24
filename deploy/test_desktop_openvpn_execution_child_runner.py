#!/usr/bin/env python3
"""Reject incomplete native OpenVPN receipts and omitted shipping phases."""
import importlib.util
import json
from pathlib import Path
import re
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('openvpn_desktop_child_gate', ROOT/'deploy/test_desktop_openvpn_execution_child.py')
G = importlib.util.module_from_spec(spec)
spec.loader.exec_module(G)


class DesktopOpenVPNChildRunner(unittest.TestCase):
    def records(self, phase, darwin=False):
        package, roots = G.inventory(phase, darwin)
        full = G.CHILD.MODULE if package == '.' else G.CHILD.MODULE+'/'+package
        def event(action, name=None, **values):
            row = dict(Action=action, Package=full, **values)
            if name: row['Test'] = name
            return row
        result = [event('start')]
        for root, children in roots.items():
            result.append(event('run', root))
            for child in children:
                result.extend((event('run', root+'/'+child), event('pass', root+'/'+child)))
            result.append(event('pass', root))
        return package, roots, result+[event('pass')]

    def verdict(self, package, roots, rows, code=0):
        return G.CHILD.verdict('\n'.join(map(json.dumps, rows)), code, package, roots)

    def test_complete_exact_inventory(self):
        for phase, count in (('source', 67), ('lifecycle', 18), ('longest', 5), ('box', 26)):
            with self.subTest(phase=phase):
                package, roots, rows = self.records(phase)
                self.assertEqual(len(self.verdict(package, roots, rows)), count)
        package, roots, rows = self.records('source', True)
        self.assertEqual(len(self.verdict(package, roots, rows)), 83)

    def test_every_omitted_or_duplicated_root_and_leaf_refused(self):
        for phase in G.CASES:
            package, roots, rows = self.records(phase, True)
            for name in G.CHILD.names(roots):
                with self.subTest(phase=phase, name=name, fault='missing'), self.assertRaises(ValueError):
                    self.verdict(package, roots, [row for row in rows if row.get('Test') != name])
                duplicate = next(row for row in rows if row.get('Test') == name and row['Action'] == 'run')
                with self.subTest(phase=phase, name=name, fault='duplicate'), self.assertRaises(ValueError):
                    self.verdict(package, roots, rows[:-1]+[duplicate]+rows[-1:])

    def test_unstarted_partial_foreign_skip_race_and_nonzero_refused(self):
        package, roots, rows = self.records('source')
        for broken in (rows[1:], rows[:-1], [], rows+[rows[1]]):
            with self.assertRaises(ValueError): self.verdict(package, roots, broken)
        for change in ({'Action':'skip'}, {'Action':'fail'}, {'Package':'foreign'}, {'Test':'TestForeign'}, {'Action':'output', 'Output':'DATA RACE'}):
            broken = [dict(row) for row in rows]; broken[3].update(change)
            with self.subTest(change=change), self.assertRaises(ValueError): self.verdict(package, roots, broken)
        with self.assertRaises(ValueError): self.verdict(package, roots, rows, 1)

    def failure(self):
        root, child, witness = G.PREFIX+'ConstructionRefusal', 'physical', 'owned refusal'
        package = G.CHILD.MODULE+'/cmd/sing-box'
        def event(action, name=None, **values):
            return dict(Action=action, Package=package, **({'Test':name} if name else {}), **values)
        rows = [event('start'), event('run', root), event('run', root+'/'+child),
                event('output', root+'/'+child, Output=witness), event('fail', root+'/'+child),
                event('fail', root), event('fail')]
        return root, child, witness, rows

    def rejected(self, root, child, witness, rows, code=1):
        return G.rejected('\n'.join(map(json.dumps, rows)), code, root, child, witness)

    def test_exact_compiled_negative_receipt(self):
        root, child, witness, rows = self.failure()
        self.assertTrue(self.rejected(root, child, witness, rows))
        for code in (0, -9, 2): self.assertFalse(self.rejected(root, child, witness, rows, code))
        for i in range(len(rows)):
            self.assertFalse(self.rejected(root, child, witness, rows[:i]+rows[i+1:]))
        for marker in ('DATA RACE', 'build failed', 'panic:', 'fatal error:', 'test timed out'):
            broken = [dict(row) for row in rows]; broken[3]['Output'] += marker
            self.assertFalse(self.rejected(root, child, witness, broken))
        for fault in ({'Package':'foreign'}, {'Test':root+'/other'}, {'Action':'pass'}):
            broken = [dict(row) for row in rows]; broken[4].update(fault)
            self.assertFalse(self.rejected(root, child, witness, broken))

    def test_build_diagnostics_are_never_test_receipts(self):
        root, child, witness, rows = self.failure()
        record = {'Action':'build-output', 'ImportPath':G.CHILD.MODULE+'/cmd/sing-box.test', 'Output':'native linker diagnostic\n'}
        self.assertTrue(self.rejected(root, child, witness, [record]+rows))
        self.assertFalse(self.rejected(root, child, witness, rows[:1]+[record]+rows[1:]))
        self.assertFalse(self.rejected(root, child, witness, [dict(record, ImportPath='foreign')]+rows))
        self.assertFalse(self.rejected(root, child, witness, [dict(record, Output='x'*(64*1024+1))]+rows))
        self.assertFalse(self.rejected(root, child, witness, [record]))

    def test_actual_test_roots_and_preparer_membership(self):
        sources = ('node_chain_openvpn_execution_command_test', 'node_chain_openvpn_execution_child_test',
                   'node_chain_openvpn_execution_darwin_test', 'node_chain_openvpn_execution_box_test')
        actual = set()
        for name in sources:
            actual.update(re.findall(r'^func (TestRouterVPNDesktopOpenVPNExecution\w+)\(t \*testing.T\)',
                                     (ROOT/'mobile/desktop'/(name+'.go.tmpl')).read_text(), re.M))
        expected = {root for phase in G.CASES for root in G.inventory(phase, True)[1]}
        self.assertEqual(actual, expected)
        copied = G.PREP.pt_copies()
        for template, target in G.TEMPLATES.items():
            source = ROOT/'mobile/desktop'/(template+'.go.tmpl')
            self.assertIn(source, G.PREP.inputs())
            if not target.startswith('cmd/'):
                self.assertEqual(copied[target], source.read_bytes())
            else:
                self.assertNotIn(source.name, G.PREP.PT_TEMPLATES)
                self.assertNotIn(source.name, G.PREP.BOX_TEMPLATES)
                self.assertIn(b'package main\n', source.read_bytes())

    def test_original_native_and_provider_tags_and_limits(self):
        for phase in G.CASES:
            package, roots = G.inventory(phase)
            cmd = G.CHILD.command('pinned-go', G.CHILD.TAGS, True, package, 'selected')
            for value in ('-race', '-p=1', '-mod=readonly', '-timeout=120s', '-count=1'):
                self.assertIn(value, cmd)
            self.assertIn('with_openvpn', G.CHILD.TAGS.split(','))
        source = (ROOT/'deploy/test_desktop_openvpn_execution_child.py').read_text()
        self.assertIn('ROOT, env, 300)', source)
        self.assertEqual(source.count('core, env, 600)'), 2)
        for _, relative, before, _, _, _, _ in G.CONTROLS:
            name = next(name for name, target in G.TEMPLATES.items() if target == relative)
            self.assertEqual((ROOT/'mobile/desktop'/(name+'.go.tmpl')).read_text().count(before), 1)

    def test_actual_desktop_projection_refuses_every_omission_and_forgery(self):
        # These are source-only fixtures containing the exact shipping bytes;
        # they make no claim about a compiled or running native engine.
        projections = G.native_projections()
        native = {name for _, content in projections for name in content}
        self.assertIn('routervpn_node_chain_openvpn_execution.go', native)
        self.assertIn('routervpn_node_chain_execution_readback.go', native)
        self.assertIn('protocol/routervpnamnezia/routervpn_connect_reference_test.go', native)
        self.assertIn('protocol/routervpnwhitening/routervpn_connect_final.go', native)
        self.assertIn('experimental/libbox/routervpn/mobilemultihop/routervpn_candidate_response_cipher.go', native)
        self.assertIn('experimental/libbox/routervpn/mobilemultihop/routervpn_candidate_response_cipher_test.go', native)
        self.assertFalse(any(name.startswith('experimental/libbox/') and
                             not name.startswith('experimental/libbox/routervpn/') for name in native))
        with tempfile.TemporaryDirectory(prefix='desktop-openvpn-projection-') as temporary:
            core = Path(temporary).resolve()
            for module, content in projections:
                wanted = {name: G.sha(raw) for name, raw in content.items()}
                record = {'schema': 1, 'core': module.PIN, 'files': wanted}
                owner = core/module.OWNER
                for name, raw in content.items():
                    path = core/name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(raw)
                owner.write_text(json.dumps(record))
                self.assertEqual(G.verify_projection(core, module, content), wanted)
                for name, raw in content.items():
                    path = core/name; path.unlink()
                    with self.subTest(owner=module.OWNER, missing=name), self.assertRaises(ValueError):
                        G.verify_projection(core, module, content)
                    path.write_bytes(raw)
                name, raw = next(iter(content.items()))
                path = core/name
                path.write_bytes(raw+b'\n// foreign source\n')
                record['files'][name] = G.sha(path.read_bytes())
                owner.write_text(json.dumps(record))
                with self.assertRaises(ValueError): G.verify_projection(core, module, content)
                path.write_bytes(raw)
                record['files'][name] = G.sha(raw)
                for changed in ({**record, 'core': 'foreign'}, {**record, 'files': {**record['files'], 'foreign.go': G.sha(raw)}}):
                    owner.write_text(json.dumps(changed))
                    with self.assertRaises(ValueError): G.verify_projection(core, module, content)
                owner.write_text(json.dumps(record))

    def test_native_projection_matches_shipping_desktop_preparer(self):
        # Execute the shipping template selection and manifest writer. Only
        # unrelated pinned-core edits are doubled in this source-only fixture.
        # A verifier that drops desktop-shared cipher sources must fail here.
        module = G.NATIVE.NATIVE
        content = next(content for candidate, content in G.native_projections()
                       if candidate.OWNER == module.OWNER)
        with tempfile.TemporaryDirectory(prefix='desktop-openvpn-shipping-projection-') as temporary:
            core = Path(temporary).resolve()
            (core/'box.go').write_text('original box\n')
            (core/'route').mkdir()
            (core/'route/network.go').write_text('original network\n')
            (core/'option').mkdir()
            (core/'option/shadowsocks.go').write_text('package option\ntype ShadowsocksOutboundOptions struct {\n}\n')
            (core/'protocol/shadowsocks').mkdir(parents=True)
            (core/'protocol/shadowsocks/outbound.go').write_text('package shadowsocks\nfunc NewOutbound() {\n\toutbound := &Outbound{\n\t}\n}\n')
            with mock.patch.object(module.subprocess, 'check_output', return_value=module.PIN+'\n'), \
                    mock.patch.object(module, 'box_source', side_effect=lambda raw: raw.encode()), \
                    mock.patch.object(module, 'network_source', side_effect=lambda raw: raw.encode()):
                module.prepare(core, mobile=False)
            self.assertEqual(G.verify_projection(core, module, content),
                             {name: G.sha(raw) for name, raw in content.items()})
            self.assertFalse((core/'experimental/libbox/routervpn_node_chain.go').exists())
            self.assertFalse((core/'experimental/libbox/command_server.go').exists())

    def test_all_shipping_hosts_require_every_phase_and_inputs(self):
        source = (ROOT/'deploy/build-native-runtime.py').read_text()
        common = source.split('if target == host:', 1)[1].split("            if target.startswith(('linux/', 'windows/')):", 1)[0]
        for name in ('test_desktop_openvpn_execution_child_runner.py', 'test_desktop_openvpn_execution_child.py'):
            self.assertIn("ROOT/'deploy/"+name+"'", common)
            self.assertIn("ROOT/'deploy/"+name+"'", source.split('def inputs():', 1)[1].split('\ndef ', 1)[0])
        self.assertIn("for openvpn_phase in ('source', 'lifecycle', 'longest', 'box', 'controls'):", common)
        self.assertIn("'--phase', openvpn_phase", common)
        self.assertIn("timeout=2400 if openvpn_phase == 'controls' else 1050", common)


if __name__ == '__main__':
    unittest.main()
