#!/usr/bin/env python3
"""Require complete native ownership verdicts and causal execution witnesses."""
import importlib.util
import json
import re
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('execution_owner_runner_checks', ROOT/'deploy/test_node_chain_execution_owner.py')
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)


def events():
    rows = []
    for package in RUNNER.ROOTS:
        rows.append(dict(Package=package, Action='start'))
        for root in RUNNER.ROOTS[package]:
            name = RUNNER.PREFIX+root
            rows.append(dict(Package=package, Action='run', Test=name))
            for child in RUNNER.CHILDREN.get(root, ()):
                rows.append(dict(Package=package, Action='run', Test=name+'/'+child))
                rows.append(dict(Package=package, Action='pass', Test=name+'/'+child))
            rows.append(dict(Package=package, Action='pass', Test=name))
        rows.append(dict(Package=package, Action='pass'))
    return rows


def encoded(rows):
    return '\n'.join(json.dumps(row) for row in rows)


class Verdict(unittest.TestCase):
    def build_output(self, package=RUNNER.PACKAGE, output=None):
        return dict(ImportPath=package+'.test', Action='build-output',
                    Output=output if output is not None else
                    '# '+package+'.test\nld: warning: ignoring duplicate libraries: \'-lobjc\'\n')

    def test_observed_darwin_linker_record_preserves_every_required_verdict(self):
        rows = events()
        augmented = []
        for row in rows:
            if row['Action'] == 'start':
                augmented.extend((self.build_output(row['Package'], 'first linker fragment\n'),
                                  self.build_output(row['Package'])))
            augmented.append(row)
        self.assertEqual(RUNNER.verdict(encoded(augmented), 0), RUNNER.verdict(encoded(rows), 0))

    def test_build_diagnostics_cannot_replace_tests_or_terminal_results(self):
        rows = events()
        for changed in ([self.build_output()], [self.build_output()]+rows[:-1],
                        [self.build_output()]+[row for row in rows if row['Action'] != 'run']):
            with self.assertRaises(ValueError): RUNNER.verdict(encoded(changed), 0)

    def test_build_event_requires_exact_binary_shape_and_pre_runtime_position(self):
        base = self.build_output()
        for changed in (dict(base, ImportPath='foreign.test'), dict(base, ImportPath=RUNNER.PACKAGE),
                        dict(base, Package=RUNNER.PACKAGE), dict(base, Test=RUNNER.PREFIX+'NativeCloseReceipt'),
                        dict(base, Output=None), dict(base, Output=''), dict(base, Output='DATA RACE'),
                        dict(base, Action='build-fail'), dict(base, Action='build-unknown')):
            with self.subTest(event=changed), self.assertRaises(ValueError):
                RUNNER.verdict(encoded([changed]+events()), 0)
        for position in (1, 2, len(events())):
            rows = events(); rows.insert(position, base)
            with self.subTest(position=position), self.assertRaises(ValueError):
                RUNNER.verdict(encoded(rows), 0)

    def test_build_byte_bound_accumulates_utf8_fragments(self):
        exact = 'é'*(RUNNER.MAX_BUILD_OUTPUT_BYTES//2)
        self.assertEqual(RUNNER.verdict(encoded([self.build_output(output=exact)]+events()), 0),
                         RUNNER.verdict(encoded(events()), 0))
        for rows in ([self.build_output(output=exact+'x')],
                     [self.build_output(output=exact), self.build_output(output='x')]):
            with self.assertRaises(ValueError): RUNNER.verdict(encoded(rows+events()), 0)
        for code in (1, 124, -9):
            with self.assertRaises(ValueError): RUNNER.verdict(encoded([self.build_output()]+events()), code)

    def test_exact_complete_three_package_inventory(self):
        result = RUNNER.verdict(encoded(events()), 0)
        self.assertEqual(result, {'roots': 42, 'test_records': 165})
        self.assertEqual(len(RUNNER.CONTROLS), 33)

    def test_complete_connect_prefix_native_inventory_is_additive(self):
        self.assertEqual(RUNNER.CHILDREN['NativeCONNECTCompletePrefixes'], ('4/server', '4/auto', '8/server', '8/auto'))
        source=(ROOT/'mobile/chain/connect_execution_box_test.go.tmpl').read_text()
        self.assertIn('func TestRouterVPNExecutionNativeCONNECTCompletePrefixes(t *testing.T)', source)
        self.assertIn('newCONNECTExecutionNativePrefixFixture(t, count-2, "wg", "https-connect", execution)', source)
        script=(ROOT/'deploy/test_node_chain_execution_owner.py').read_text()
        self.assertIn("'-timeout=120s'",script)

    def test_generic_public_family_and_selection_controls_are_mandatory(self):
        controls = {item[0]: item for item in RUNNER.CONTROLS}
        for label, selected in (
            ('generic original penultimate position', 'NativeImportedPublicPrefixes/wg/6/local'),
            ('generic original public family', 'NativeImportedPublicDNS/original'),
            ('generic public selected epoch', 'NativeImportedPublicDNS/changed-selector'),
            ('generic remote selected epoch', 'NativeImportedPublicServer/away-and-back'),
        ):
            self.assertEqual(controls[label][5], selected)
            self.assertIn(RUNNER.PREFIX+selected, RUNNER.expected(RUNNER.PACKAGE))
        preparer = (ROOT/'deploy/prepare-node-chain-execution-owner.py').read_text()
        for name in ('execution_public.go.tmpl', 'execution_public_test.go.tmpl'):
            self.assertEqual(preparer.count("'"+name+"'"), 1)

    def test_selection_keeps_only_exact_owner_inventory(self):
        pattern = re.compile(RUNNER.selection())
        for roots in RUNNER.ROOTS.values():
            for root in roots:
                self.assertIsNotNone(pattern.fullmatch(RUNNER.PREFIX+root))
        self.assertIsNone(pattern.fullmatch(RUNNER.PREFIX+'TUNDNSAddressCannotBypass'))
        self.assertIsNone(pattern.fullmatch(RUNNER.PREFIX+'NativeCloseReceiptForeign'))

    def test_omitted_root_child_or_package_cannot_pass(self):
        rows = events()
        for index, row in enumerate(rows):
            if row['Action'] in ('run', 'pass'):
                with self.subTest(index=index), self.assertRaises(ValueError):
                    RUNNER.verdict(encoded(rows[:index]+rows[index+1:]), 0)

    def test_failed_skipped_racing_or_nonzero_cannot_pass(self):
        for action, output in (('fail', ''), ('skip', ''), ('output', 'WARNING: DATA RACE')):
            rows = events()
            rows.insert(1, dict(Package=RUNNER.PACKAGE, Action=action, Output=output))
            with self.subTest(action=action), self.assertRaises(ValueError):
                RUNNER.verdict(encoded(rows), 0)
        with self.assertRaises(ValueError):
            RUNNER.verdict(encoded(events()), 1)

    def test_foreign_duplicate_late_and_unrun_pass_refused(self):
        rows = events()
        for extra in (dict(Package='foreign', Action='pass'), rows[1], rows[2],
                      dict(Package=RUNNER.PACKAGE, Action='pass', Test='TestForeign')):
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                RUNNER.verdict(encoded(rows[:2]+[extra]+rows[2:]), 0)
        with self.assertRaises(ValueError):
            RUNNER.verdict(encoded(rows+[dict(Package=RUNNER.PACKAGE, Action='output', Output='late')]), 0)

    def test_incomplete_child_before_parent_pass_refused(self):
        rows = events()
        child = next(i for i, r in enumerate(rows) if '/' in r.get('Test', '') and r['Action'] == 'pass')
        row = rows.pop(child)
        parent = next(i for i, r in enumerate(rows) if r.get('Test') == row['Test'].split('/')[0] and r['Action'] == 'pass')
        rows.insert(parent+1, row)
        with self.assertRaises(ValueError):
            RUNNER.verdict(encoded(rows), 0)

    def test_compiled_control_requires_exact_reached_failure_and_witness(self):
        selected, witness = 'NativeOpenCannotFinishAfterRevoke', 'older pending native open completed after revoke'
        name = RUNNER.PREFIX+selected
        rows = [dict(Package=RUNNER.PACKAGE, Action='run', Test=name),
                dict(Package=RUNNER.PACKAGE, Action='output', Test=name, Output=witness),
                dict(Package=RUNNER.PACKAGE, Action='fail', Test=name)]
        self.assertTrue(RUNNER.rejected(encoded(rows), 1, selected, witness))
        self.assertFalse(RUNNER.rejected(encoded(rows), 0, selected, witness))
        for index in range(3):
            self.assertFalse(RUNNER.rejected(encoded(rows[:index]+rows[index+1:]), 1, selected, witness))
        self.assertFalse(RUNNER.rejected('build failed', 1, selected, witness))
        self.assertFalse(RUNNER.rejected(encoded(rows+[dict(Output='WARNING: DATA RACE')]), 1, selected, witness))


if __name__ == '__main__':
    unittest.main()
