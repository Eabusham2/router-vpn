#!/usr/bin/env python3
"""Require real, complete native OpenVPN owner verdicts and compiled witnesses."""
import importlib.util
import json
from pathlib import Path
import re
import tempfile
import unittest
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('openvpn_execution_owner_runner_checks', ROOT/'deploy/test_node_chain_openvpn_execution_owner.py')
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)


def events(parser):
    rows = []
    for package, roots in parser.ROOTS.items():
        rows.append(dict(Package=package, Action='start'))
        for root in roots:
            name = parser.PREFIX+root
            rows.append(dict(Package=package, Action='run', Test=name))
            for child in parser.CHILDREN.get(root, ()):
                rows.append(dict(Package=package, Action='run', Test=name+'/'+child))
                rows.append(dict(Package=package, Action='pass', Test=name+'/'+child))
            rows.append(dict(Package=package, Action='pass', Test=name))
        rows.append(dict(Package=package, Action='pass'))
    return rows


def encoded(rows):
    return '\n'.join(json.dumps(row) for row in rows)


class NativeOpenVPNVerdicts(unittest.TestCase):
    def test_independent_positive_stub_and_real_shared_fixture_inventories(self):
        for parser, expected in (
                (RUNNER.POSITIVE, {'roots': 7, 'test_records': 56}),
                (RUNNER.STUB, {'roots': 1, 'test_records': 1}),
                (RUNNER.GENERATOR, {'roots': 1, 'test_records': 7})):
            with self.subTest(prefix=parser.PREFIX):
                self.assertEqual(parser.verdict(encoded(events(parser)), 0), expected)
        # The pre-existing gate is still separately required, with no inventory
        # replacement when the three additional phases are configured.
        self.assertEqual(RUNNER.BASE.PREFIX, 'TestRouterVPNExecution')
        rows = events(RUNNER.BASE)
        self.assertEqual(RUNNER.BASE.verdict(encoded(rows), 0),
                         {'roots': 45, 'test_records': 182})
        original_permit = RUNNER.BASE.PREFIX+'CandidateStopRetainsOriginalPermit'
        for action in ('run', 'pass'):
            with self.subTest(original_permit=action), self.assertRaises(ValueError):
                RUNNER.BASE.verdict(encoded([r for r in rows if not (
                    r.get('Test') == original_permit and r['Action'] == action)]), 0)

    def test_original_mobile_and_desktop_connect_source_inventories_remain_closed(self):
        for desktop in (False, True):
            expected = {relative: (ROOT/'mobile/chain'/template).read_bytes()
                        for template, relative in RUNNER.BASE.CONNECT.TEMPLATES.items()
                        if not (desktop and relative.startswith('experimental/libbox/') or
                                not desktop and template in RUNNER.BASE.CONNECT.DESKTOP_ONLY)}
            with self.subTest(desktop=desktop), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                for relative, raw in expected.items():
                    path = root/relative; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(raw)
                self.assertEqual(set(RUNNER.BASE.verify_connect_sources(root, desktop=desktop)), set(expected))
                for relative, raw in expected.items():
                    path = root/relative; path.unlink()
                    with self.subTest(missing=relative), self.assertRaises(FileNotFoundError):
                        RUNNER.BASE.verify_connect_sources(root, desktop=desktop)
                    path.write_bytes(raw+b'\n')
                    with self.subTest(changed=relative), self.assertRaises(ValueError):
                        RUNNER.BASE.verify_connect_sources(root, desktop=desktop)
                    path.write_bytes(raw)
                with self.assertRaises(FileNotFoundError):
                    RUNNER.BASE.verify_connect_sources(root, desktop=not desktop)

    def test_each_omitted_run_pass_and_terminal_is_rejected(self):
        for parser in (RUNNER.POSITIVE, RUNNER.STUB, RUNNER.GENERATOR):
            rows = events(parser)
            for index, row in enumerate(rows):
                if row['Action'] in ('run', 'pass'):
                    with self.subTest(prefix=parser.PREFIX, index=index), self.assertRaises(ValueError):
                        parser.verdict(encoded(rows[:index]+rows[index+1:]), 0)

    def test_skip_failure_race_nonzero_and_foreign_phase_cannot_pass(self):
        for parser in (RUNNER.POSITIVE, RUNNER.STUB, RUNNER.GENERATOR):
            rows = events(parser)
            package = next(iter(parser.ROOTS))
            for action, output in (('skip', ''), ('fail', ''), ('output', 'WARNING: DATA RACE')):
                bad = dict(Package=package, Action=action, Output=output)
                with self.subTest(action=action), self.assertRaises(ValueError):
                    parser.verdict(encoded(rows[:1]+[bad]+rows[1:]), 0)
            for code in (1, -9, 124):
                with self.subTest(code=code), self.assertRaises(ValueError):
                    parser.verdict(encoded(rows), code)
            with self.assertRaises(ValueError):
                parser.verdict(encoded(rows+[dict(Package='foreign', Action='pass')]), 0)
        with self.assertRaises(ValueError):
            RUNNER.POSITIVE.verdict(encoded(events(RUNNER.STUB)), 0)

    def test_duplicate_unrun_late_and_incomplete_parent_are_rejected(self):
        parser = RUNNER.POSITIVE
        rows = events(parser)
        for extra in (rows[1], rows[2], dict(Package=RUNNER.PACKAGE, Action='pass', Test=RUNNER.PREFIX+'Foreign')):
            with self.assertRaises(ValueError):
                parser.verdict(encoded(rows[:2]+[extra]+rows[2:]), 0)
        with self.assertRaises(ValueError):
            parser.verdict(encoded(rows+[dict(Package=RUNNER.PACKAGE, Action='output', Output='late')]), 0)
        index = next(i for i, row in enumerate(rows) if '/' in row.get('Test', '') and row['Action'] == 'pass')
        child = rows.pop(index)
        parent = next(i for i, row in enumerate(rows) if row.get('Test') == child['Test'].split('/')[0] and row['Action'] == 'pass')
        rows.insert(parent+1, child)
        with self.assertRaises(ValueError):
            parser.verdict(encoded(rows), 0)

    def test_linker_diagnostic_cannot_substitute_for_execution(self):
        row = dict(ImportPath=RUNNER.PACKAGE+'.test', Action='build-output', Output='ld: warning: ignoring duplicate libraries\n')
        parser = RUNNER.POSITIVE
        complete = events(parser)
        self.assertEqual(parser.verdict(encoded([row]+complete), 0), parser.verdict(encoded(complete), 0))
        for malformed in ([row], [row]+complete[:-1], complete[:1]+[row]+complete[1:],
                          [dict(row, ImportPath='foreign.test')]+complete,
                          [dict(row, Output='DATA RACE')]+complete):
            with self.assertRaises(ValueError):
                parser.verdict(encoded(malformed), 0)

    def test_exact_selection_excludes_other_native_and_stub_roots(self):
        selection = re.compile(RUNNER.POSITIVE.selection())
        for root in RUNNER.ROOTS:
            self.assertIsNotNone(selection.fullmatch(RUNNER.PREFIX+root))
        for foreign in (RUNNER.PREFIX+'WithoutSupport', RUNNER.PREFIX+'OriginalExtra', 'TestRouterVPNExecutionNativeCloseReceipt'):
            self.assertIsNone(selection.fullmatch(foreign))

    def test_each_compiled_control_requires_reached_failure_and_exact_witness(self):
        for label, relative, before, after, selected, witness in RUNNER.CONTROLS:
            with self.subTest(label=label):
                name = RUNNER.PREFIX+selected
                self.assertIn(name, RUNNER.POSITIVE.expected(RUNNER.PACKAGE))
                rows = [dict(Package=RUNNER.PACKAGE, Action='run', Test=name),
                        dict(Package=RUNNER.PACKAGE, Action='output', Test=name, Output=witness),
                        dict(Package=RUNNER.PACKAGE, Action='fail', Test=name)]
                self.assertTrue(RUNNER.POSITIVE.rejected(encoded(rows), 1, selected, witness))
                self.assertFalse(RUNNER.POSITIVE.rejected(encoded(rows), 0, selected, witness))
                for index in range(3):
                    self.assertFalse(RUNNER.POSITIVE.rejected(encoded(rows[:index]+rows[index+1:]), 1, selected, witness))
                self.assertFalse(RUNNER.POSITIVE.rejected('build failed', 1, selected, witness))
                self.assertFalse(RUNNER.POSITIVE.rejected(encoded(rows+[dict(Output='WARNING: DATA RACE')]), 1, selected, witness))
                result = SimpleNamespace(stdout=encoded(rows), stderr='', returncode=1)
                self.assertTrue(RUNNER.rejected(result, selected, witness))
                for marker in ('DATA RACE', 'build failed', 'panic:', 'fatal error:', 'test timed out'):
                    for output in ('stdout', 'stderr'):
                        broken = SimpleNamespace(**vars(result))
                        setattr(broken, output, getattr(broken, output)+'\n'+marker)
                        self.assertFalse(RUNNER.rejected(broken, selected, witness))
                for code in (0, -9, 124):
                    self.assertFalse(RUNNER.rejected(SimpleNamespace(stdout=encoded(rows), stderr='', returncode=code), selected, witness))
                source = next((ROOT/'mobile/chain'/template for template, target in
                               (list(RUNNER.NATIVE.TEMPLATES.items())+list(RUNNER.BASE.PREP.TEMPLATES.items())) if target == relative), None)
                self.assertIsNotNone(source, relative)
                self.assertEqual(source.read_text().count(before), 1, label)
                self.assertNotEqual(before, after)

    def test_preparation_owns_every_new_native_source_and_build_variant(self):
        required = {
            'openvpn_execution_box.go.tmpl', 'openvpn_execution_endpoint.go.tmpl',
            'openvpn_execution_endpoint_stub.go.tmpl', 'openvpn_execution_public.go.tmpl',
            'openvpn_execution_retirement.go.tmpl', 'openvpn_execution_fixture_test.go.tmpl',
            'openvpn_execution_box_test.go.tmpl', 'openvpn_execution_stub_test.go.tmpl',
        }
        self.assertTrue(required <= set(RUNNER.NATIVE.TEMPLATES))
        for template in required:
            self.assertTrue((ROOT/'mobile/chain'/template).is_file())
        self.assertTrue((ROOT/'mobile/chain/openvpn_execution_endpoint.go.tmpl').read_text().startswith('//go:build with_openvpn\n'))
        for name in ('openvpn_execution_endpoint_stub.go.tmpl', 'openvpn_execution_stub_test.go.tmpl'):
            self.assertTrue((ROOT/'mobile/chain'/name).read_text().startswith('//go:build !with_openvpn\n'))
        for name in ('openvpn_execution_box.go.tmpl', 'openvpn_execution_endpoint_stub.go.tmpl', 'openvpn_execution_retirement.go.tmpl'):
            self.assertNotIn('"github.com/sagernet/sing-box/protocol/openvpn"', (ROOT/'mobile/chain'/name).read_text())

    def test_cache_identities_include_required_gate_and_runner(self):
        required = {
            ROOT/'deploy/test_node_chain_openvpn_execution_owner.py',
            ROOT/'deploy/test_node_chain_openvpn_execution_owner_runner.py',
        }
        # The mobile cache stamps and desktop runtime receipts derive from
        # these real input closures. A gate-only correction must invalidate
        # each cache before it can reuse an earlier validation result.
        for name, preparer in (
                ('native chain', RUNNER.NATIVE),
                ('mobile artifacts', RUNNER.load('openvpn_execution_mobile_cache_inputs', 'prepare-mobile-multihop.py')),
                ('desktop artifacts', RUNNER.load('openvpn_execution_desktop_cache_inputs', 'build-native-runtime.py'))):
            with self.subTest(preparer=name):
                self.assertTrue(required <= set(preparer.inputs()), name)

    def test_both_shipping_mobile_builds_require_old_and_new_execution_gates(self):
        for relative in ('android/build-sing-box-libbox.sh', 'ios/RouterVPN/prepare-libbox.sh'):
            text = (ROOT/relative).read_text()
            with self.subTest(relative=relative):
                old = 'deploy/test_node_chain_execution_owner.py" --core "$VENDOR"'
                check = 'deploy/test_node_chain_openvpn_execution_owner_runner.py"'
                new = 'deploy/test_node_chain_openvpn_execution_owner.py" --core "$VENDOR"'
                self.assertEqual(text.count(old), 1)
                self.assertEqual(text.count(check), 1)
                self.assertEqual(text.count(new), 1)
                self.assertLess(text.index(old), text.index(check))
                self.assertLess(text.index(check), text.index(new))
                line = next(line for line in text.splitlines() if new in line)
                self.assertIn('--race --tags ', line)
                self.assertIn('with_openvpn', line)
                self.assertNotIn('--tagged-only', line)
                self.assertNotIn('||', line)
                self.assertIn('set -e', text)

    def test_desktop_requires_actual_tagged_positive_and_controls(self):
        text = (ROOT/'deploy/build-native-runtime.py').read_text()
        self.assertEqual(text.count("ROOT/'deploy/test_node_chain_openvpn_execution_owner_runner.py'"), 1)
        self.assertEqual(text.count("ROOT/'deploy/test_node_chain_openvpn_execution_owner.py'"), 1)
        self.assertIn("'--core', source, '--go', 'go', '--tags', ','.join(tags(target))", text)
        self.assertIn("'--tagged-only', *(['--race'] if race else [])", text)
        self.assertIn("'without_openvpn': stub, 'tagged_only': tagged_only", (ROOT/'deploy/test_node_chain_openvpn_execution_owner.py').read_text())


if __name__ == '__main__':
    unittest.main()
