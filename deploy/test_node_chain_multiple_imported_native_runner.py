#!/usr/bin/env python3
"""Validator-only transcripts and required native schema6 wiring controls."""
import ast
import importlib.util
import json
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('multiple_imported_native', ROOT/'deploy/test_node_chain_multiple_imported_native.py')
RUN = importlib.util.module_from_spec(spec)
spec.loader.exec_module(RUN)
CALL = "multiple_imported.execute(source, target, ','.join(tags(target)), env, run)"


def transcript(root, leaf=None, failed=False, witness=''):
    names = tuple(RUN.expected(root, leaf))
    package = RUN.PEER_PACKAGE if root in RUN.PEER_CASES else RUN.BOX_PACKAGE
    def row(action, test=None, **fields):
        return dict(Action=action, Package=package, **({'Test': test} if test else {}), **fields)
    rows = [row('start'), row('run', root)]
    for name in names[1:]:
        rows.append(row('run', name))
        if root == RUN.POSITIVE_ROOT and leaf in ('wg/extended-nine/off', 'wg/extended-sixteen/off'):
            count = 9 if leaf == 'wg/extended-nine/off' else 16
            rows.append(row('output', name, Output=f'QUALIFIED_LATENCY_HISTORY nodes={count} receipts={count} samples={count*50}'))
        if root == RUN.SELECTED_ROOT:
            rows.append(row('output',name,Output=RUN.selected_marker(leaf)))
        if root == RUN.THROUGHPUT_ROOT:
            count = 9 if leaf == 'extended-nine' else 16
            rows.append(row('output', name, Output=f'QUALIFIED_ORIGINAL_THROUGHPUT nodes={count} bytes_per_direction={8<<20} bytes_total={count*(16<<20)}'))
        if witness:
            rows.append(row('output', name, Output=witness))
        rows.append(row('fail' if failed else 'pass', name))
    return rows+[row('fail' if failed else 'pass', root), row('fail' if failed else 'pass')]


def output(rows):
    return '\n'.join(json.dumps(row) for row in rows)+'\n'


def required_wiring(source):
    tree = ast.parse(source)
    parents = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}
    expected = ast.dump(ast.parse(CALL).body[0].value, include_attributes=False)
    calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)
             and ast.dump(node, include_attributes=False) == expected]
    if len(calls) != 1:
        raise ValueError('Required independent imported invocation omitted or duplicated')
    parent = parents[calls[0]]
    while not isinstance(parent, (ast.If, ast.FunctionDef)):
        if isinstance(parent, (ast.Try, ast.For, ast.While)):
            raise ValueError('Required independent imported invocation became optional')
        parent = parents[parent]
    guard = ast.dump(ast.parse("target.startswith('linux/')", mode='eval').body, include_attributes=False)
    if not isinstance(parent, ast.If) or ast.dump(parent.test, include_attributes=False) != guard:
        raise ValueError('Required independent imported invocation lost both Linux architectures')


class MultipleImportedNativeRunner(unittest.TestCase):
    def test_native_traversal_budget_matches_the_five_host_selections(self):
        def bound(path, pattern):
            matches = re.findall(pattern, (ROOT/path).read_text())
            self.assertEqual(len(matches), 1, path)
            return int(matches[0])
        native = bound("internal/hopmeasure/ordered.go", r"const PhysicalTraversalDepth = (\d+)")
        for path, pattern in (
            ("internal/common/profile_node_chain.go", r"const MultihopPhysicalTraversalDepth = (\d+)"),
            ("android/app/src/main/java/com/eabusham/routervpn/AndroidNodeStore.java", r"PHYSICAL_TRAVERSAL_DEPTH = (\d+)"),
            ("ios/RouterVPN/App/Models.swift", r"static let physicalTraversalDepth = (\d+)"),
            ("ios/RouterVPN/App/IOSSessionIdentity.swift", r"private static let physicalTraversalDepth = (\d+)"),
            ("client/linux/routervpn-ordered-nodes-v1.inc", r"ROUTERVPN_PHYSICAL_TRAVERSAL_DEPTH = (\d+)"),
            ("client/macos/RouterVPNConnectionProfiles.swift", r"static let physicalTraversalDepth = (\d+)"),
            ("client/RouterVPN-Windows-ProfileSettings.ps1", r"function global:Get-RouterVPNOrderedPhysicalTraversalDepth \{ return (\d+) \}"),
        ):
            self.assertEqual(bound(path, pattern), native, path)

    def test_exact_encrypted_matrix(self):
        self.assertEqual((len(RUN.POSITIVE), len(RUN.NEGATIVE)), (32, 21))
        self.assertEqual(len(set(RUN.POSITIVE)), 32)
        for mode in ('wg', 'awg2-fast', 'awg2-strong'):
            for layout in ('adjacent', 'maximum-sparse'):
                for layer in ('off', 'aes-256-gcm', 'aes-256-gcm+xor-whitening'):
                    self.assertIn('/'.join((mode, layout, layer)), RUN.POSITIVE)
        for layout in ('extended-nine', 'extended-sixteen'):
            self.assertIn('wg/'+layout+'/off', RUN.POSITIVE)
            self.assertIn('late-key-'+layout, RUN.NEGATIVE)
        for root, cases in ((RUN.POSITIVE_ROOT, RUN.POSITIVE), (RUN.NEGATIVE_ROOT, RUN.NEGATIVE)):
            for case in cases:
                self.assertEqual(RUN.verdict(output(transcript(root, case)), root, case), 2)

    def test_encrypted_throughput_requires_both_exact_peer_byte_counts(self):
        self.assertEqual(RUN.THROUGHPUT, ('extended-nine', 'extended-sixteen'))
        for leaf in RUN.THROUGHPUT:
            rows = transcript(RUN.THROUGHPUT_ROOT, leaf)
            self.assertEqual(RUN.verdict(output(rows), RUN.THROUGHPUT_ROOT, leaf), 2)
            marker = next(row for row in rows if 'QUALIFIED_ORIGINAL_THROUGHPUT' in row.get('Output', ''))
            for changed in ([row for row in rows if row is not marker], rows[:-2]+[marker]+rows[-2:],
                            [dict(row, Output=row['Output'].replace('8388608', '65536')) if row is marker else row for row in rows]):
                with self.assertRaises(ValueError):
                    RUN.verdict(output(changed), RUN.THROUGHPUT_ROOT, leaf)

    def test_mixed_candidate_roots_require_original_positions_and_samples(self):
        self.assertEqual(len(set(RUN.MIXED_CANDIDATES)), 17)
        self.assertIn('5-1-2-wg-connected-original', RUN.MIXED_CANDIDATES)
        self.assertIn('5-1-3-wg-closed-wrong-private-id', RUN.MIXED_CANDIDATES)
        for leaf in RUN.MIXED_CANDIDATES:
            count, packets, pos = leaf.split('-')[:3]
            scope = 'closed' if '-closed-' in leaf else 'connected'
            outcome = leaf.split('-'+scope+'-')[1]
            n = 50 if outcome == 'original' else 0
            witness = f'MIXED_CANDIDATE_NATIVE nodes={count} packets={packets} position={pos} scope={scope} outcome={outcome} samples={n} joined=true'
            self.assertEqual(RUN.verdict(output(transcript(RUN.MIXED_CANDIDATE_ROOT,leaf,witness=witness)),RUN.MIXED_CANDIDATE_ROOT,leaf),2)
            for field in ('samples=', 'packets=', 'position=', 'scope=', 'joined='):
                with self.assertRaises(ValueError):
                    RUN.verdict(output(transcript(RUN.MIXED_CANDIDATE_ROOT,leaf,witness=witness.replace(field,field+'x'))),RUN.MIXED_CANDIDATE_ROOT,leaf)

    def test_mixed_sources_require_actual_bidirectional_bytes_or_rejected_late_key(self):
        self.assertEqual(len(set(RUN.MIXED)), 12)
        for count in (9, 16):
            for mode, packets in (('wg', 2), ('awg2-fast', 1), ('awg2-strong', 2)):
                for outcome in ('traffic', 'late-key'):
                    leaf = f'{count}-{mode}-{packets}-{outcome}'
                    size = 8 << 20 if outcome == 'traffic' else 0
                    marker = f'MIXED_LOCAL_NATIVE nodes={count} packets={packets} mode={mode} outcome={outcome} down={size} up={size} joined=true'
                    rows = transcript(RUN.MIXED_ROOT, leaf, witness=marker)
                    self.assertEqual(RUN.verdict(output(rows), RUN.MIXED_ROOT, leaf), 2)
                    for altered in ('', marker.replace(f'up={size}', 'up=1'), marker.replace('joined=true', 'joined=false')):
                        with self.assertRaises(ValueError):
                            RUN.verdict(output(transcript(RUN.MIXED_ROOT, leaf, witness=altered)), RUN.MIXED_ROOT, leaf)

    def test_selected_evidence_requires_every_original_count_winner_and_transfer(self):
        self.assertEqual(len(RUN.SELECTED_CASES), 18)
        positions = [i for part in RUN.PARTS for first,last in [map(int,part.split('-')[-2:])] for i in range(first,last+1)]
        self.assertEqual(positions, list(range(1,17)))
        for leaf in RUN.SELECTED_CASES:
            rows = transcript(RUN.SELECTED_ROOT, leaf)
            name = RUN.SELECTED_ROOT+'/'+leaf
            marker = next(row for row in rows if 'QUALIFIED_SELECTED_NATIVE' in row.get('Output', ''))
            self.assertEqual(RUN.verdict(output(rows), RUN.SELECTED_ROOT, leaf), 2)
            for changed in ('', marker['Output'].replace('nodes=', 'foreign='), marker['Output']+'0'):
                bad = [dict(row) for row in rows]
                bad[rows.index(marker)]['Output'] = changed
                with self.assertRaises(ValueError):
                    RUN.verdict(output(bad), RUN.SELECTED_ROOT, leaf)

    def test_exact_box_inventory(self):
        self.assertEqual(sum(len(cases)+1 for cases in RUN.BOX_CASES.values()), 17)
        for root, cases in RUN.BOX_CASES.items():
            self.assertEqual(RUN.verdict(output(transcript(root)), root), len(cases)+1)
        self.assertIn('equal-source', RUN.BOX_CASES[RUN.BOX_NEGATIVE])

    def test_extended_encrypted_history_witness_is_mandatory(self):
        for leaf in ('wg/extended-nine/off', 'wg/extended-sixteen/off'):
            original = transcript(RUN.POSITIVE_ROOT, leaf)
            marker = next(row for row in original if 'QUALIFIED_LATENCY_HISTORY' in row.get('Output', ''))
            for rows in ([row for row in original if row is not marker], original[:-2] + [marker] + original[-2:]):
                with self.assertRaises(ValueError):
                    RUN.verdict(output(rows), RUN.POSITIVE_ROOT, leaf)

    def test_each_missing_duplicate_or_reordered_record_fails(self):
        for root, leaf in ((RUN.POSITIVE_ROOT, RUN.POSITIVE[0]), (RUN.NEGATIVE_ROOT, RUN.NEGATIVE[0]),
                           (RUN.BOX_POSITIVE, None), (RUN.BOX_NEGATIVE, None)):
            rows = transcript(root, leaf)
            changes = [rows[:i]+rows[i+1:] for i in range(len(rows))]
            changes += [rows[:i]+[rows[i]]+rows[i:] for i in range(len(rows))]
            changes += [rows[:2]+[rows[3], rows[2]]+rows[4:], rows[:-1], rows+[rows[-1]]]
            for changed in changes:
                with self.subTest(root=root, leaf=leaf, changed=changed), self.assertRaises(ValueError):
                    RUN.verdict(output(changed), root, leaf)

    def test_skip_fail_foreign_case_package_and_false_terminal_fail(self):
        root, leaf = RUN.POSITIVE_ROOT, RUN.POSITIVE[0]
        for mode in ('skip', 'fail', 'foreign-case', 'foreign-package', 'false-terminal'):
            rows = transcript(root, leaf)
            if mode == 'skip': rows[3]['Action'] = 'skip'
            if mode == 'fail': rows = transcript(root, leaf, True)
            if mode == 'foreign-case': rows = transcript(root, RUN.POSITIVE[1])
            if mode == 'foreign-package': rows[0]['Package'] = 'foreign'
            if mode == 'false-terminal': rows[-1] = dict(Action='output', Package=RUN.PEER_PACKAGE, Output='PASS')
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                RUN.verdict(output(rows), root, leaf)
        with self.assertRaises(ValueError): RUN.expected(root)
        with self.assertRaises(ValueError): RUN.expected(root, 'foreign')
        with self.assertRaises(ValueError): RUN.expected('foreign')

    def test_fatal_and_unjoined_output_cannot_pass(self):
        for marker in (*RUN.FATAL, *RUN.JOIN_FAILURES):
            with self.subTest(marker=marker), self.assertRaises(ValueError):
                RUN.verdict(output(transcript(RUN.POSITIVE_ROOT, RUN.POSITIVE[0], witness=marker)), RUN.POSITIVE_ROOT, RUN.POSITIVE[0])

    def test_exact_actual_omission_witness_is_required(self):
        c = RUN.CONTROL
        self.assertTrue(RUN.rejected(output(transcript(c['root'], c['leaf'], True, c['witness']))))
        for failed, witness in ((False, c['witness']), (True, 'unrelated failure')):
            self.assertFalse(RUN.rejected(output(transcript(c['root'], c['leaf'], failed, witness))))
        for marker in (*RUN.FATAL, *RUN.JOIN_FAILURES):
            try:
                accepted = RUN.rejected(output(transcript(c['root'], c['leaf'], True, c['witness']+' '+marker)))
            except ValueError:
                accepted = False
            self.assertFalse(accepted)
        with self.assertRaises(ValueError): RUN.rejected('build failed')

    def test_source_control_removes_only_original_pointer_guard(self):
        source = (ROOT/'mobile/chain/box.go.tmpl').read_text()
        self.assertEqual(source.count(RUN.CONTROL['before']), 1)
        changed = source.replace(RUN.CONTROL['before'], RUN.CONTROL['after'], 1)
        self.assertEqual(changed.count('r.source != r.originalSource'), 0)
        for retained in ('r.self != r', 'r.observation != owner', 'r.source.PublicMeasurementCaptures()',
                         'capture != r.captured[position]', 'owner.prefixes[capture.Tag] == nil'):
            self.assertIn(retained, changed)
        self.assertIn(RUN.CONTROL['witness'], (ROOT/RUN.BOX_TEMPLATE).read_text())

    def test_case_selectors_anchor_each_original_path_component(self):
        for root, cases in RUN.inventory().items():
            for leaf in cases:
                parts = RUN.selector(root, leaf).split('/')
                self.assertEqual(len(parts), len((root+'/'+leaf.replace('/', '_')).split('/')))
                for pattern, name in zip(parts, (root+'/'+leaf.replace('/', '_')).split('/')):
                    self.assertTrue(pattern.startswith('^') and pattern.endswith('$'))
                    self.assertIsNotNone(re.fullmatch(pattern, name))
                    self.assertIsNone(re.fullmatch(pattern, name+'foreign'))

    def test_only_actual_linux_race_target_is_admitted(self):
        for target, tags, env in (
            ('linux/amd64', '', {'GOOS':'linux','GOARCH':'amd64','CGO_ENABLED':'1'}),
            ('windows/amd64', 'with_wireguard', {'GOOS':'windows','GOARCH':'amd64','CGO_ENABLED':'1'}),
            ('linux/amd64', 'with_wireguard', {'GOOS':'linux','GOARCH':'arm64','CGO_ENABLED':'1'}),
            ('linux/amd64', 'with_wireguard', {'GOOS':'linux','GOARCH':'amd64','CGO_ENABLED':'0'})):
            with self.subTest(target=target, env=env), self.assertRaises(ValueError):
                RUN.execute(ROOT, target, tags, env, lambda *a, **k:self.fail('wrong target executed'))

    def test_canonical_box_mapping_and_all_required_inputs(self):
        prep = RUN.load('prepare-mobile-node-chain.py')
        self.assertEqual(prep.TEMPLATES[Path(RUN.BOX_TEMPLATE).name], RUN.BOX_TARGET)
        self.assertIn(ROOT/RUN.BOX_TEMPLATE, prep.inputs())
        inputs = set(RUN.load('build-native-runtime.py').inputs())
        for path in (RUN.BOX_TEMPLATE, RUN.PEER_TEMPLATE, *RUN.SELECTED_TEMPLATES, 'deploy/test_node_chain_multiple_imported_native.py',
                     'deploy/test_node_chain_multiple_imported_native_runner.py'):
            self.assertIn(ROOT/path, inputs)
        required_wiring((ROOT/'deploy/build-native-runtime.py').read_text())

    def test_missing_duplicate_or_optional_build_invocation_is_refused(self):
        source = (ROOT/'deploy/build-native-runtime.py').read_text()
        self.assertEqual(source.count(CALL), 1)
        for changed in ('pass', '# '+CALL, CALL+'; '+CALL, CALL.replace('target,', "'windows/amd64',", 1),
                        'if False:\n                    '+CALL):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                required_wiring(source.replace(CALL, changed, 1))

    def test_required_workflow_keeps_actual_builder_and_validator(self):
        workflow = (ROOT/'.github/workflows/desktop-native-runtime.yml').read_text()
        self.assertEqual(workflow.count('python3 deploy/test_node_chain_multiple_imported_native_runner.py'), 1)
        self.assertEqual(workflow.count('python3 deploy/build-native-runtime.py "${runtime_args[@]}"'), 1)
        self.assertIn("timeout-minutes: ${{ startsWith(matrix.target, 'darwin/') && 60 || startsWith(matrix.target, 'linux/') && 310 || 220 }}", workflow)
        for architecture in ('amd64', 'arm64'):
            self.assertIn("('linux', '"+architecture+"',", workflow)

    def test_original_bounds_and_receipt_scope_are_explicit(self):
        source = (ROOT/'deploy/test_node_chain_multiple_imported_native.py').read_text()
        for anchor in ('timeout=300)', 'timeout=600)', 'root, leaf, 90, 105)', 'root, None, 120, 135)',
                       'communicate(timeout=135)', 'installed_host_acceptance=False', "controls=['equal-source']"):
            self.assertIn(anchor, source)
        peer = (ROOT/RUN.PEER_TEMPLATE).read_text()
        self.assertIn('85*time.Second', peer.replace(' ', ''))
        self.assertIn('RouterVPNNewNodeChainEngine', peer)
        self.assertIn('f.chain.Run(f.ctx, f.engine)', peer)
        self.assertIn('hopmeasure.PublicAddress', peer)
        self.assertNotIn('t.Skip(', peer)


if __name__ == '__main__': unittest.main()
