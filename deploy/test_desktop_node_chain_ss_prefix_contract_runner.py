#!/usr/bin/env python3
"""Keep ImportedSS original source/runtime and Box MTU phases mandatory."""
from pathlib import Path
import copy
import importlib.util
import json
import sys
import unittest

from test_native_xray_shared_workflow import declared_groups, shared_plan

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('ss_contract_runner', ROOT / 'deploy/test_desktop_node_chain_ss_prefix_contract.py')
G = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = G
spec.loader.exec_module(G)


def events(package, case):
    result = []
    action = 'fail' if case.mutation else 'pass'
    for name in sorted(case.expected):
        result.append({'Action': 'run', 'Package': package, 'Test': name})
        if name in case.witness_tests:
            result.append({'Action': 'output', 'Package': package, 'Test': name, 'Output': case.witness})
        result.append({'Action': action, 'Package': package, 'Test': name})
    result.append({'Action': action, 'Package': package})
    return ('\n'.join(json.dumps(row) for row in result) + '\n').encode()


class ImportedSSContracts(unittest.TestCase):
    def test_shared_partition_matches_required_source_contract_and_xray_shards(self):
        spec = importlib.util.spec_from_file_location('shared_multihop_partition', ROOT / 'deploy/test_mobile_multihop_groups.py')
        shared = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(shared)
        actual = shared.prefix_inventory()
        dedicated = [(package, case) for package, case in G.source_cases() if case.name.startswith('shared-prefix-')]
        self.assertEqual(len(dedicated), 6)
        self.assertEqual([(selection, expected) for _, _, selection, expected in actual],
                         [(case.selection, case.expected) for _, case in dedicated])
        self.assertEqual({package for package, _ in dedicated}, {G.MOBILE})
        # The original required SS workflow owns these same actual source cases;
        # no duplicated release job or reduction of its strict provenance.
        workflow_spec = importlib.util.spec_from_file_location('ss_prefix_workflow_required', ROOT / 'deploy/test_desktop_node_chain_ss_prefix_runner.py')
        workflow = importlib.util.module_from_spec(workflow_spec)
        workflow_spec.loader.exec_module(workflow)
        source = (ROOT / '.github/workflows/ss-node-chain-prefix.yml').read_text()
        release = (ROOT / '.github/workflows/release-candidate.yml').read_text()
        workflow.workflow_contract(source, release)
        with self.assertRaises(ValueError):
            workflow.workflow_contract(source, release.replace('desktop-connect-child, ss-prefix-native]', 'desktop-connect-child]'))
        xray = (ROOT / '.github/workflows/native-xray-exits.yml').read_text()
        selected = shared_plan(xray, declared_groups())
        self.assertEqual([roots for label, roots in selected if label == shared.PREFIX_PHASE],
                         [[shared.PREFIX_ROOT]])

    def test_preserved_and_additive_exact_inventories(self):
        phases = G.source_cases()
        self.assertEqual(len(phases), 17)
        self.assertEqual(len({case.name for _, case in phases}), 17)
        self.assertEqual([len(case.expected) for _, case in phases], [10, 40, 19, 19, 19, 19, 19, 19, 14, 17, 7, 13, 17, 52, 22, 11, 2])
        self.assertEqual(len(G.BOX_CASES), 160)
        self.assertEqual(len(set(G.BOX_CASES)), 160)
        self.assertIn(G.BOX_OLD, G.BOX_CASES)
        self.assertEqual(len(G.G.NODE.ORDERED_PHYSICAL_VERDICTS), 119)
        self.assertEqual(G.BOX_CASES[-119:], tuple(G.G.NODE.ORDERED_PHYSICAL_VERDICTS))


    def test_each_actual_go_event_required_and_control_witness_not_optional(self):
        for package, case in G.source_cases():
            G.CORE.PACKAGE = package
            raw = events(package, case)
            self.assertTrue(G.CORE.verdict(raw, case, 1 if case.mutation else 0)['accepted'], case.name)
            lines = raw.splitlines()
            for index, line in enumerate(lines):
                event = json.loads(line)
                if event['Action'] not in ('run', 'pass', 'fail', 'output'):
                    continue
                altered = b'\n'.join(lines[:index] + lines[index + 1:])
                with self.subTest(case=case.name, index=index):
                    self.assertFalse(G.CORE.verdict(altered, case, 1 if case.mutation else 0)['accepted'])
            for code, timed, joined in ((-9, False, True), (1 if case.mutation else 0, True, True), (1 if case.mutation else 0, False, False)):
                self.assertFalse(G.CORE.verdict(raw, case, code, timed, joined)['accepted'])

    def test_source_commands_preserve_real_race_bounds_and_exact_package(self):
        for package, case in G.source_cases():
            command = G.source_command('/captured/go', package, case, Path('/captured/overlay.json') if G.needs_pointer_overlay(case) else None)
            self.assertEqual(command[:8], ['/captured/go', 'test', '-json', '-race', '-count=1', '-p=1', '-mod=readonly', '-timeout=120s'])
            self.assertEqual(command[-1], './' + package.removeprefix('router-vpn/'))
            self.assertEqual(command[8:10], ['-run', case.selection])
            self.assertEqual(case.outer_seconds, 600)
            self.assertEqual(any(value.startswith('-overlay=') for value in command), G.needs_pointer_overlay(case))

    def test_independent_policy_refusal_survives_the_same_pointer_omission(self):
        phases = {record.name: (package, record) for package, record in G.source_cases()}
        baseline = phases['original-prefix-pointers'][1]
        omitted = phases['omitted-original-prefix-pointers'][1]
        package, retained = phases[G.INDEPENDENT_POLICY_CASE]
        self.assertIn(G.POINTER+'/policy', baseline.expected)
        self.assertEqual(omitted.expected, frozenset(G.rows(G.POINTER,
            (*(str(index) for index in range(8)), 'whole', 'hostname'))))
        self.assertNotIn('policy', omitted.selection)
        self.assertEqual(package, G.MOBILE)
        self.assertEqual(retained.expected, frozenset(G.rows(G.POINTER, ('policy',))))
        self.assertEqual(retained.selection, '^'+G.POINTER+'$/^policy$')
        self.assertFalse(retained.mutation)
        self.assertTrue(G.needs_pointer_overlay(omitted))
        self.assertTrue(G.needs_pointer_overlay(retained))
        self.assertFalse(G.needs_pointer_overlay(baseline))
        original = (ROOT/G.POINTER_SOURCE).read_text()
        self.assertEqual(G.pointer_overlay_source(original), original.replace(G.POINTER_GUARD, '', 1))
        for invalid in (original.replace(G.POINTER_GUARD, '', 1), original+'\n// '+G.POINTER_GUARD):
            with self.assertRaises(ValueError): G.pointer_overlay_source(invalid)
        G.CORE.PACKAGE = package
        raw = events(package, retained)
        self.assertTrue(G.CORE.verdict(raw, retained, 0)['accepted'])
        # The independent policy must actually reject its copied owner. A
        # failing/omitted/skipped policy test cannot certify that protection.
        for altered in (raw.replace(b'"Action": "pass"', b'"Action": "fail"'),
                        raw.replace(b'"Action": "pass"', b'"Action": "skip"')):
            self.assertFalse(G.CORE.verdict(altered, retained, 0)['accepted'])

    def receipt(self):
        repository, selection, files = {'commit': 'a' * 40}, {'source_sha': 'a' * 40}, {'source.go': {'sha256': 'b' * 64}}
        attempts = []
        for package, case in G.source_cases():
            G.CORE.PACKAGE = package
            raw = events(package, case)
            attempts.append({'name': case.name, 'package': package,
                             **G.CORE.verdict(raw, case, 1 if case.mutation else 0), 'output_sha256': 'c' * 64})
        controls = []
        for record in G.physical_controls():
            G.CORE.PACKAGE = 'box'
            controls.append({'name': record.name, **G.CORE.verdict(events('box', record), record, 1),
                             'output_sha256': 'a' * 64, 'image_sha256': 'b' * 64})
        receipt = {'schema': 1, 'gate': 'ss-prefix-source-runtime-mtu', 'repository': repository, 'selection': selection,
                   'validator': G.G.validator_identity(), 'source_files': files, 'attempts': attempts,
                   'native': {'verdicts': list(G.BOX_CASES), 'controls': controls, 'original_physical_sha256': G.ORIGINAL_PHYSICAL_SHA256, 'scope': 'original-box-component', 'kernel_tun_accepted': False,
                              'source_files': {key: 'd' * 64 for key in G.BOX_FILES}, 'image_sha256': 'e' * 64, 'output_sha256': 'f' * 64},
                   'installed_host_accepted': False, 'kernel_tun_accepted': False}
        return receipt, repository, selection, files

    def test_native_inventory_refuses_old_duplicate_and_reordered_records(self):
        receipt, repository, selection, files = self.receipt()
        original = receipt['native']['verdicts']
        for names in (original[:-32], original + [original[-1]],
                      [*original[:-2], original[-1], original[-2]],
                      [*original[:-1], original[0]]):
            altered = copy.deepcopy(receipt)
            altered['native']['verdicts'] = names
            with self.subTest(verdicts=names), self.assertRaises(ValueError):
                G.check_receipt(altered, repository, selection, files)

    def test_physical_control_restores_exact_published_factory(self):
        path = ROOT / 'mobile/desktop/node_chain_box_physical.go.tmpl'
        original = path.read_text()
        mutant = G.original_physical_mutant(original)
        self.assertEqual(mutant, original.replace(G.PHYSICAL_GUARD, G.ORIGINAL_PHYSICAL_GUARD, 1))
        exit_guard = 'exit.SourceSHA256 != captured[last].SourceSHA256'
        self.assertEqual(mutant.count(exit_guard), 1)
        with self.assertRaises(ValueError):
            G.original_physical_mutant(original.replace(exit_guard, 'false', 1))
        for changed in (original.replace(G.PHYSICAL_GUARD, 'true', 1),
                        original + '// ' + G.PHYSICAL_GUARD + '\n'):
            with self.assertRaises(ValueError):
                G.original_physical_mutant(changed)
        self.assertEqual(G.hashlib.sha256(mutant.encode()).hexdigest(), G.ORIGINAL_PHYSICAL_SHA256)
        with self.assertRaises(ValueError): G.original_physical_mutant(mutant)
        with self.assertRaises(ValueError): G.original_physical_mutant(original + "// unrelated source change\n")
        self.assertEqual([len(record.expected) for record in G.physical_controls()], [7])
        for record in G.physical_controls():
            G.CORE.PACKAGE = 'box'
            raw = events('box', record)
            self.assertTrue(G.CORE.verdict(raw, record, 1)['accepted'])
            self.assertFalse(G.CORE.verdict(raw.replace(record.witness.encode(), b'wrong witness'), record, 1)['accepted'])

    def test_physical_fixture_is_captured_only_in_desktop_preparation(self):
        self.assertIn('node_chain_imported_prefix_physical_test.go.tmpl', G.DESKTOP_BOX_TEMPLATES)
        for template, generated in G.DESKTOP_BOX_TEMPLATES.items():
            self.assertEqual(G.G.NODE.PREP.BOX_TEMPLATES.get(template), generated)
            self.assertIn(generated, G.BOX_FILES)
            self.assertTrue((ROOT / 'mobile/desktop' / template).is_file())
        common = (ROOT / 'mobile/chain/imported_prefix_box_test.go.tmpl').read_text()
        self.assertNotIn('routerVPNDesktopNodeChainPhysicalTarget', common)
        self.assertIn('func ' + G.BOX + '(', common)


    def test_contract_receipt_cannot_omit_phase_or_borrow_native_pass(self):
        receipt, repository, selection, files = self.receipt()
        G.check_receipt(receipt, repository, selection, files)
        for index in range(len(receipt['attempts'])):
            for key, value in (('accepted', False), ('timed_out', True), ('process_group_joined', False), ('ran', []), ('output_sha256', ''), ('exit', True)):
                altered = copy.deepcopy(receipt); altered['attempts'][index][key] = value
                with self.subTest(index=index, key=key), self.assertRaises(ValueError):
                    G.check_receipt(altered, repository, selection, files)
        for index in range(len(G.BOX_CASES)):
            altered = copy.deepcopy(receipt); del altered['native']['verdicts'][index]
            with self.assertRaises(ValueError): G.check_receipt(altered, repository, selection, files)
        for index in range(1):
            altered = copy.deepcopy(receipt); altered['native']['controls'][index]['failed'] = []
            with self.assertRaises(ValueError): G.check_receipt(altered, repository, selection, files)
        for key, value in (('source_files', {}), ('selection', {}), ('schema', True), ('installed_host_accepted', True)):
            altered = copy.deepcopy(receipt); altered[key] = value
            with self.assertRaises(ValueError): G.check_receipt(altered, repository, selection, files)


if __name__ == '__main__':
    unittest.main()
