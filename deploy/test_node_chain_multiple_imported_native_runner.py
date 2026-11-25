#!/usr/bin/env python3
"""Validator-only transcripts and required native schema6 wiring controls."""
import ast
from contextlib import redirect_stdout
import io
import importlib.util
import json
from pathlib import Path
import re
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

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
        if root == RUN.SELECTED_ROOT and leaf not in RUN.PRIVATE_STREAM_CASES and leaf not in RUN.PRIVATE_DEPTH_CASES:
            rows.append(row('output',name,Output=RUN.selected_marker(leaf)))
            if leaf in RUN.PRIVATE_RESPONSE_CASES:
                count, _, fault = RUN.PRIVATE_RESPONSE_SOURCES[leaf]
                rows.append(row('output', name, Output=RUN.private_response_source_marker(leaf)))
                if fault == 'original':
                    position = RUN.response_position(leaf)
                    rows.append(row('output', name, Output=f'PRIVATE_RESPONSE_PREFIX nodes={count} position={position} prefixes={position+1} authenticated=50'))
                    rows.append(row('output',name,Output=RUN.reloaded_response_marker(leaf)))
                if RUN.suffix_refusal_marker(leaf):
                    rows.append(row('output', name, Output=RUN.suffix_refusal_marker(leaf)))
                rows.append(row('output',name,Output=f"SELECTED_PRIVATE_RESPONSE fault={fault} samples={50 if fault=='original' else 0} joined=true"))
            if leaf in RUN.AWG_SELECTED_CASES:
                entry = 'awg2-fast' if leaf in RUN.FAST_SELECTED_CASES else 'awg2-strong'
                rows.append(row('output', name, Output=f'QUALIFIED_SELECTED_CLIENT_AWG entry={entry} parameters_current=true other_mode_refused=true'))
            if leaf in RUN.AWG_SELECTED_CASES and leaf.endswith('-mtu'):
                entry = 'awg2-fast' if leaf in RUN.FAST_SELECTED_CASES else 'awg2-strong'
                count = leaf.split('-')[0]
                mtu_marker = 'STRONG_SELECTED_MTU' if entry == 'awg2-strong' else 'FAST_SELECTED_MTU'
                rows.append(row('output', name, Output=f'{mtu_marker} nodes={count} configured=1280 ceiling=1500 lease_paused=true missing_reader_refused=true'))
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
    def test_private_stream_release_proof_is_required_and_cannot_skip(self):
        path = ROOT/'deploy/native-artifact-workflow-parity-audit.py'
        tree = ast.parse(path.read_text())
        names = {'check_release_aggregate_gates', 'check_private_stream_release_workflow'}
        functions = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in names]
        self.assertEqual(len(functions), 2)
        scope = {}
        exec(compile(ast.Module(body=functions, type_ignores=[]), str(path), 'exec'), scope)
        release = (ROOT/'.github/workflows/release-candidate.yml').read_text()
        proof = (ROOT/'.github/workflows/diagnostic-selected-private-depth.yml').read_text()
        scope['check_release_aggregate_gates'](release)
        scope['check_private_stream_release_workflow'](proof)
        for changed in (release.replace('selected-private-stream-native, ', ''),
                        release.replace('  selected-private-stream-native:\n', '  selected-private-stream-native:\n    if: false\n')):
            with self.assertRaises(AssertionError):
                scope['check_release_aggregate_gates'](changed)
        for changed in (proof.replace('  workflow_call:\n', ''),
                        proof.replace('  native:\n', '  native:\n    if: false\n'),
                        proof.replace('encrypted "$RUNNER_TEMP" --depth', 'encrypted "$RUNNER_TEMP"'),
                        proof.replace('encrypted "$RUNNER_TEMP" --depth', 'encrypted "$RUNNER_TEMP" --depth || true'),
                        proof.replace('selected-private-depth.json', 'selected-private-stream.json')):
            with self.assertRaises(AssertionError):
                scope['check_private_stream_release_workflow'](changed)

    def test_private_stream_requires_the_compiled_worker_joined_proofs_and_original_route(self):
        image = 'c'*64
        owner = 'pid=7321 source='+'b'*64+' capture='+'1'*64+' image='+image
        self.assertEqual(len(RUN.PRIVATE_STREAM_CASES), 11)
        self.assertEqual(len(RUN.PRIVATE_DEPTH_CASES), 26)
        for leaf in (*RUN.PRIVATE_STREAM_CASES,*RUN.PRIVATE_DEPTH_CASES):
            count, position, mode, winner, action, first, last = RUN.private_case(leaf)
            root = RUN.SELECTED_ROOT
            rows = transcript(root, leaf)
            name = root+'/'+leaf
            event = next(row for row in rows if row.get('Test') == name and row['Action'] == 'run')
            negative = action.startswith('wrong-')
            witnesses = [
                'SEPARATE_NATIVE_CHILD '+owner, 'SEPARATE_NATIVE_JOINED '+owner,
                f'SELECTED_PRIVATE_STREAM_NATIVE nodes={count} private={position} mode={mode} winner={winner} operation={action} rejected={str(negative).lower()} '
                f'samples={6 if action=="response" else (last-first+1)*50 if action=="latency" else 0} bytes={count*(16<<20) if action=="throughput" else 0} first={first} last={last}',
            ]
            if (mode, winner) == ('auto', 'server'):
                second = owner.replace('7321', '7371').replace('1'*64, '2'*64)
                witnesses.extend(['SEPARATE_NATIVE_CHILD '+second, 'SEPARATE_NATIVE_JOINED '+second])
            if not negative:
                witnesses.append('PRIVATE_STREAM_OWNER foreign_peer_session_epoch_refused=true')
            if action == 'drain':
                witnesses.append('PRIVATE_STREAM_DRAIN cancelled_delete_retained=true replacement_refused=true original_joined=true')
            def check(lines, digest=image):
                recorded = [dict(event, Action='output', Output=line) for line in lines]
                pos = rows.index(event)+1
                return RUN.verdict(output(rows[:pos]+recorded+rows[pos:]), root, leaf, worker_digest=digest)
            self.assertEqual(check(witnesses), 2)
            for i in range(len(witnesses)):
                for changed in (witnesses[:i]+witnesses[i+1:], witnesses+[witnesses[i]], witnesses[:i]+[witnesses[i]+'x']+witnesses[i+1:]):
                    with self.assertRaises(ValueError):
                        check(changed)
            with self.assertRaises(ValueError):
                check(witnesses, '0'*64)
            if (mode, winner) == ('auto', 'server'):
                overlapped = witnesses.copy()
                overlapped[1], overlapped[3] = overlapped[3], overlapped[1]
                with self.assertRaises(ValueError):
                    check(overlapped)

    def test_private_depth_matrix_covers_each_physical_position_and_both_compare_winners(self):
        self.assertFalse(set(RUN.PRIVATE_STREAM_CASES) & set(RUN.PRIVATE_DEPTH_CASES))
        rows = list(RUN.PRIVATE_DEPTH_CASES.values())
        self.assertEqual({r[0] for r in rows}, {5, 9, 16})
        for count, placements in ((5, {2, 3}), (9, {4, 7}), (16, {2, 14})):
            selected = [r[1:] for r in rows if r[0] == count]
            self.assertEqual({r[0] for r in selected}, placements)
            self.assertEqual({(m, w) for _, m, w, action, _, _ in selected if action == 'response'},
                             {('server', 'server'), ('auto', 'local'), ('auto', 'server')})
            self.assertEqual(sorted(i for _, _, _, action, first, last in selected if action == 'latency'
                                    for i in range(first, last+1)), list(range(1, count+1)))
            for action in ('throughput', 'drain'):
                self.assertEqual(sum(r[3] == action for r in selected), 1)
        self.assertEqual(sorted(r[4] for r in rows if r[4].startswith('wrong-')),
                         ['wrong-dns', 'wrong-exit', 'wrong-identity', 'wrong-key', 'wrong-public'])

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
        self.assertEqual(len(set(RUN.MIXED_CANDIDATES)), 27)
        self.assertIn('5-1-2-wg-connected-original', RUN.MIXED_CANDIDATES)
        self.assertIn('5-1-3-wg-closed-wrong-private-id', RUN.MIXED_CANDIDATES)
        for leaf in RUN.MIXED_CANDIDATES:
            count, packets, pos = leaf.split('-')[:3]
            scope = 'closed' if '-closed-' in leaf else 'connected'
            outcome = leaf.split('-'+scope+'-')[1]
            n = 50 if outcome in ('original','hostname','later-hostname','later-hostname-last') else 0
            witness = f'MIXED_CANDIDATE_NATIVE nodes={count} packets={packets} position={pos} scope={scope} outcome={outcome} samples={n} joined=true'
            self.assertEqual(RUN.verdict(output(transcript(RUN.MIXED_CANDIDATE_ROOT,leaf,witness=witness)),RUN.MIXED_CANDIDATE_ROOT,leaf),2)
            for field in ('samples=', 'packets=', 'position=', 'scope=', 'joined='):
                with self.assertRaises(ValueError):
                    RUN.verdict(output(transcript(RUN.MIXED_CANDIDATE_ROOT,leaf,witness=witness.replace(field,field+'x'))),RUN.MIXED_CANDIDATE_ROOT,leaf)

    def test_later_hostname_requires_resolver_transfer_and_join_witnesses(self):
        self.assertEqual(len(set(RUN.LATER_HOSTNAME_CASES)), 22)
        self.assertEqual(len(set(RUN.LATER_HOSTNAME_CANDIDATES)), 8)
        for leaf in RUN.LATER_HOSTNAME_CASES:
            count, mode, position, outcome = re.fullmatch(r'(4|9|96)-(wg|awg2-fast|awg2-strong)-(?:p(2|7|94)-)?(.+)', leaf).groups()
            position = position or '2'
            query = 'false' if outcome in ('wrong-dns-route', 'wrong-predecessor') else 'true'
            size = 8 << 20 if outcome in ('traffic','rebind') else 0
            witness = f'LATER_HOSTNAME_NATIVE nodes={count} mode={mode} outcome={outcome} position={position} resolver_reached={query} down={size} up={size} joined=true'
            for field in ('nodes=', 'position=', 'resolver_reached=', 'down=', 'up=', 'joined='):
                with self.assertRaises(ValueError):
                    RUN.verdict(output(transcript(RUN.LATER_HOSTNAME_ROOT, leaf, witness=witness.replace(field, field+'x'))), RUN.LATER_HOSTNAME_ROOT, leaf)
            self.assertEqual(RUN.verdict(output(transcript(RUN.LATER_HOSTNAME_ROOT, leaf, witness=witness)), RUN.LATER_HOSTNAME_ROOT, leaf), 2)

    def test_mixed_sources_require_actual_bidirectional_bytes_or_rejected_late_key(self):
        self.assertEqual(len(set(RUN.MIXED)), 17)
        for count in (9, 16):
            for mode, packets in (('wg', 2), ('awg2-fast', 1), ('awg2-strong', 2)):
                outcomes = ('traffic', 'late-key')
                if count == 9 and mode == 'awg2-fast':
                    outcomes += ('hostname', 'hostname-collision', 'hostname-nxdomain','hostname-rebind','hostname-late-key')
                for outcome in outcomes:
                    leaf = f'{count}-{mode}-{packets}-{outcome}'
                    size = 8 << 20 if outcome in ('traffic','hostname','hostname-rebind') else 0
                    marker = f'MIXED_LOCAL_NATIVE nodes={count} packets={packets} mode={mode} outcome={outcome} down={size} up={size} joined=true'
                    rows = transcript(RUN.MIXED_ROOT, leaf, witness=marker)
                    self.assertEqual(RUN.verdict(output(rows), RUN.MIXED_ROOT, leaf), 2)
                    for altered in ('', marker.replace(f'up={size}', 'up=1'), marker.replace('joined=true', 'joined=false')):
                        with self.assertRaises(ValueError):
                            RUN.verdict(output(transcript(RUN.MIXED_ROOT, leaf, witness=altered)), RUN.MIXED_ROOT, leaf)

    def test_selected_evidence_requires_every_original_count_winner_and_transfer(self):
        self.assertEqual(len(RUN.SELECTED_CASES), 89)
        self.assertEqual(len(set(RUN.FAST_SELECTED_CASES)), 15)
        self.assertEqual(len(set(RUN.STRONG_SELECTED_CASES)), 15)
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

    def test_selected_private_response_requires_original_challenges_and_join(self):
        for leaf in RUN.PRIVATE_RESPONSE_CASES:
            rows = transcript(RUN.SELECTED_ROOT, leaf)
            witness = next(row for row in rows if 'SELECTED_PRIVATE_RESPONSE' in row.get('Output', ''))
            for changed in ('', witness['Output']+'0', witness['Output'].replace('joined=true', 'joined=false')):
                bad = [dict(row) for row in rows]
                bad[rows.index(witness)]['Output'] = changed
                with self.assertRaises(ValueError):
                    RUN.verdict(output(bad), RUN.SELECTED_ROOT, leaf)

    def test_private_response_source_roles_are_exact_and_independent(self):
        expected = {
            '3-local-private': (3, 0), '4-local-private': (4, 2), '9-local-private': (9, 7), '16-local-private': (16, 14),
            '4-imported-penultimate': (4, 0), '9-imported-penultimate': (9, 0), '16-imported-penultimate': (16, 0),
            '5-paired-2-imported-penultimate': (5, 2), '9-paired-4-imported-penultimate': (9, 4), '16-paired-7-imported-penultimate': (16, 7),
        }
        required = {name+'-'+fault: (count, paired, fault) for name,(count, paired) in expected.items()
                    for fault in (RUN.PRIVATE_RESPONSE_FAULTS if name in ('3-local-private', '4-local-private', '4-imported-penultimate') else ('original',))}
        earlier = {}
        for n,k in ((3,1),(4,1),(9,6),(16,8),(16,13)):
            for fault in (('original', 'wrong-candidate-key', 'forged-response', 'wrong-private-id', 'late-catalog', 'late-cancel',
                           'server-winner', 'suffix-alias', 'changed-original-suffix') if n == 4 else ('original',)):
                leaf = f'{n}-imported-stop-{k}-{fault}'
                earlier[leaf] = k
                required[leaf] = (n, 0, fault)
        self.assertEqual(RUN.INTERMEDIATE_POSITIONS, earlier)
        self.assertEqual(RUN.PRIVATE_RESPONSE_SOURCES, required)
        for leaf in required:
            rows = transcript(RUN.SELECTED_ROOT, leaf)
            source = next(row for row in rows if 'PRIVATE_RESPONSE_SOURCE' in row.get('Output', ''))
            for field in source['Output'].split()[1:]:
                bad = [dict(row, Output=row['Output'].replace(field, 'foreign')) if row is source else row for row in rows]
                with self.assertRaisesRegex(ValueError, 'response source roles'):
                    RUN.verdict(output(bad), RUN.SELECTED_ROOT, leaf)
            with self.assertRaisesRegex(ValueError, 'response source roles'):
                at = rows.index(source)
                RUN.verdict(output(rows[:at]+[source]+rows[at:]), RUN.SELECTED_ROOT, leaf)

    def test_private_response_reopen_requires_exact_dns_ingress_and_retirement(self):
        root,leaf=RUN.SELECTED_ROOT,'3-local-private-original'
        rows=transcript(root,leaf)
        original=next(r for r in rows if r.get('Output')==RUN.RELOADED_PRIVATE_FINAL)
        for part in ('requested=auto','winner=local','original_prefix=true','private=true','dns=true','application=true','joined=true'):
            bad=[dict(r,Output=r['Output'].replace(part,'foreign')) if r is original else r for r in rows]
            with self.assertRaisesRegex(ValueError,'Missing loaded Compare'):
                RUN.verdict(output(bad),root,leaf)
        self.assertEqual(len(set(RUN.PRIVATE_RESPONSE_CASES)), 41)
        for leaf,(count, _, fault) in RUN.PRIVATE_RESPONSE_SOURCES.items():
            if fault != 'original':
                continue
            rows = transcript(root, leaf)
            prefix = next(row for row in rows if row.get('Output', '').startswith('PRIVATE_RESPONSE_PREFIX'))
            position = RUN.response_position(leaf)
            for field in (f'nodes={count}', f'position={position}', f'prefixes={position+1}', 'authenticated=50'):
                corrupted = [dict(row, Output=row['Output'].replace(field, 'foreign')) if row is prefix else row for row in rows]
                with self.assertRaisesRegex(ValueError, 'prefix response witnesses'):
                    RUN.verdict(output(corrupted), root, leaf)
        for leaf in RUN.PRIVATE_RESPONSE_CASES:
            bad=transcript(root,leaf)
            bad.append(dict(original,Test=root+'/'+leaf))
            with self.assertRaises(ValueError):
                RUN.verdict(output(bad),root,leaf)

    def test_earlier_response_requires_its_original_suffix_and_loaded_intermediate(self):
        for leaf in RUN.INTERMEDIATE_POSITIONS:
            root = RUN.SELECTED_ROOT
            rows = transcript(root, leaf)
            marker = RUN.reloaded_response_marker(leaf) if leaf.endswith('-original') else RUN.suffix_refusal_marker(leaf)
            if not marker:
                continue
            witness = next(row for row in rows if row.get('Output') == marker)
            for forged in ('', RUN.RELOADED_PRIVATE_FINAL, *(marker.replace(field, 'foreign') for field in marker.split()[1:])):
                changed = [dict(row, Output=forged) if row is witness else row for row in rows]
                with self.assertRaises(ValueError):
                    RUN.verdict(output(changed), root, leaf)

    def test_three_node_draft_requires_its_schema_transition_without_a_named_save(self):
        root, leaf = RUN.SELECTED_ROOT, '3-imported-stop-1-original'
        rows = transcript(root, leaf)
        source = RUN.private_response_source_marker(leaf)
        self.assertEqual(source, 'PRIVATE_RESPONSE_SOURCE nodes=3 schema=2 position=1 role=imported paired=none')
        marker = RUN.reloaded_response_marker(leaf)
        witness = next(row for row in rows if row.get('Output') == marker)
        self.assertIn('nodes=4 schema=6 inserted=2 suffix=1 saved=false', marker)
        for changed in (marker.replace('saved=false', 'saved=true'), marker.replace('schema=6', 'schema=2'),
                        RUN.reloaded_response_marker('4-imported-stop-1-original'), RUN.RELOADED_PRIVATE_FINAL):
            bad = [dict(row, Output=changed) if row is witness else row for row in rows]
            with self.assertRaisesRegex(ValueError, 'Missing loaded Compare'):
                RUN.verdict(output(bad), root, leaf)

    def test_exact_box_inventory(self):
        self.assertEqual(sum(len(cases)+1 for cases in RUN.BOX_CASES.values()), 17)
        for root, cases in RUN.BOX_CASES.items():
            self.assertEqual(RUN.verdict(output(transcript(root)), root), len(cases)+1)
        self.assertIn('equal-source', RUN.BOX_CASES[RUN.BOX_NEGATIVE])

    def test_awg_selected_preserves_original_parameters_and_mtu_ownership(self):
        for leaf in RUN.AWG_SELECTED_CASES:
            entry = 'awg2-fast' if leaf in RUN.FAST_SELECTED_CASES else 'awg2-strong'
            rows = transcript(RUN.SELECTED_ROOT, leaf)
            marker = next(row for row in rows if 'QUALIFIED_SELECTED_NATIVE' in row.get('Output', ''))
            for before, after in ((f'entry_mode={entry}', 'entry_mode=wg'),
                                  ('parameters_current=true', 'parameters_current=false')):
                changed = [dict(row, Output=row['Output'].replace(before, after)) if row is marker else row for row in rows]
                with self.assertRaises(ValueError):
                    RUN.verdict(output(changed), RUN.SELECTED_ROOT, leaf)
            client = next(row for row in rows if 'QUALIFIED_SELECTED_CLIENT_AWG' in row.get('Output', ''))
            for changed in ([row for row in rows if row is not client], rows[:-2]+[client]+rows[-2:],
                            [dict(row, Output=row['Output'].replace('other_mode_refused=true', 'other_mode_refused=false')) if row is client else row for row in rows]):
                with self.assertRaises(ValueError):
                    RUN.verdict(output(changed), RUN.SELECTED_ROOT, leaf)
            if leaf.endswith('-mtu'):
                mtu = next(row for row in rows if '_SELECTED_MTU' in row.get('Output', ''))
                for changed in ([row for row in rows if row is not mtu],
                                rows[:-2]+[mtu]+rows[-2:],
                                *[[dict(row, Output=row['Output'].replace(before, after)) if row is mtu else row for row in rows]
                                  for before, after in (('configured=1280', 'configured=1501'),
                                                        ('ceiling=1500', 'ceiling=9000'),
                                                        ('lease_paused=true', 'lease_paused=false'),
                                                        ('missing_reader_refused=true', 'missing_reader_refused=false'))]):
                    with self.assertRaises(ValueError):
                        RUN.verdict(output(changed), RUN.SELECTED_ROOT, leaf)

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

    def test_later_hostname_diagnostic_requires_its_original_amd64_host(self):
        with self.assertRaisesRegex(ValueError, 'actual amd64 host'):
            RUN.execute(ROOT, 'linux/arm64', 'with_wireguard',
                        {'GOOS':'linux','GOARCH':'arm64','CGO_ENABLED':'1'},
                        lambda *a, **kw: self.fail('mismatched native host reached the build'),
                        later_hostname_diagnostic=True)

    def test_original_worker_overlay_retains_native_target_in_final_receipt(self):
        # Run original overlay, image identity, verdict and final receipt code.
        # Restrict peer families and use transcript doubles for Go processes.
        load_module = RUN.load
        workers = {name: raw for name, raw in load_module('prepare-server-node-chain.py').copies().items()
                   if name.startswith('cmd/sing-box/routervpn_server_chain_') and not name.endswith('_test.go')}
        self.assertTrue(workers)
        required = {f'{count}-awg2-strong-{case}' for count in (9,16)
                    for case in ('server-server','auto-local','auto-server','mtu','server-throughput')}
        required.add('9-awg2-strong-server-latency')
        required.update(f'16-awg2-strong-server-latency-{first}-{first+3}' for first in (1,5,9,13))
        self.assertTrue(required <= set(RUN.PEER_CASES[RUN.SELECTED_ROOT]), 'release inventory omitted an encrypted Strong case')
        peer_cases = {RUN.POSITIVE_ROOT: (RUN.POSITIVE[0],), RUN.SELECTED_ROOT:tuple(sorted(required))}
        control = RUN.CONTROL
        wrong_source = output(transcript(control['root'], control['leaf'], True, control['witness']))

        def modules(name):
            if name == 'test_node_chain_openvpn_execution_owner.py':
                return SimpleNamespace(verify=lambda core, desktop: None)
            return load_module(name)

        with tempfile.TemporaryDirectory() as tmp, patch.object(RUN, 'load', side_effect=modules), \
                patch.object(RUN, 'PEER_CASES', peer_cases), \
                patch.object(RUN, 'bounded_control', return_value=(1, wrong_source, '')):
            core = Path(tmp).resolve(strict=True)
            for relative, raw in workers.items():
                path = core/relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(raw)
            for name, relative in load_module('prepare-desktop-external.py').PEER_TEMPLATES.items():
                path = core/relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes((ROOT/'mobile/desktop'/name).read_bytes())
            (core/RUN.BOX_TARGET).write_bytes((ROOT/RUN.BOX_TEMPLATE).read_bytes())
            (core/control['target']).write_bytes((ROOT/'mobile/chain/box.go.tmpl').read_bytes())
            (core/'go.mod').write_text('module fixture.invalid/target-ownership\n')

            def run(command, *, cwd, env, timeout):
                if command[:2] == ['go', 'test']:
                    image = Path(command[command.index('-o')+1])
                    if image.name == 'peer.test':
                        overlay = Path(next(arg[9:] for arg in command if str(arg).startswith('-overlay=')))
                        entries = json.loads(overlay.read_bytes())['Replace']
                        for name, raw in workers.items():
                            source = core/'protocol/routervpnamnezia'/(Path(name).stem+'_test.go')
                            self.assertEqual(Path(entries[str(source)]).read_bytes(),
                                             raw.replace(b'package main\n', b'package routervpnamnezia_test\n', 1))
                    image.write_text('metadata-fixture-'+image.name)
                    return ''
                if len(command) == 2 and str(command[1]).startswith('-test.list='):
                    return '\n'.join(peer_cases if command[0].name == 'peer.test' else RUN.BOX_CASES)
                self.assertEqual(command[:3], ['go', 'tool', 'test2json'])
                for leaf in required:
                    if command[-1] == '-test.run='+RUN.selector(RUN.SELECTED_ROOT,leaf):
                        self.assertEqual(command[command.index('-t')+1].name, 'peer.test')
                        return output(transcript(RUN.SELECTED_ROOT,leaf))
                for root, leaf in [(RUN.POSITIVE_ROOT, RUN.POSITIVE[0]), *((root, None) for root in RUN.BOX_CASES)]:
                    if command[-1] == '-test.run='+RUN.selector(root, leaf):
                        return output(transcript(root, leaf))
                self.fail('Unexpected native selector '+str(command[-1]))

            for arch in ('amd64', 'arm64'):
                target = 'linux/'+arch
                with self.subTest(target=target), redirect_stdout(io.StringIO()):
                    receipt = RUN.execute(core, target, 'with_wireguard',
                                          {'GOOS':'linux','GOARCH':arch,'CGO_ENABLED':'1'}, run)
                    self.assertEqual(receipt['target'], target)
                    self.assertEqual({leaf for leaf in required if receipt['encrypted'].get(RUN.SELECTED_ROOT+'/'+leaf)==2}, required)
    def test_diagnostic_rejects_arm64_before_source_or_build(self):
        with self.assertRaisesRegex(ValueError, 'actual amd64 host'):
            RUN.execute(ROOT, 'linux/arm64', 'with_wireguard', {'GOOS':'linux', 'GOARCH':'arm64', 'CGO_ENABLED':'1'},
                        lambda *args, **kwargs: self.fail('wrong host compiled'), strong_diagnostic=True)

    def test_worker_overlay_preserves_diagnostic_host_in_receipt(self):
        # Exercise the original overlay loop and receipt with recorded-style
        # transcripts. Only the external source verifier and Go process are
        # doubles; this test cannot produce a qualifying encrypted artifact.
        load_module = RUN.load
        workers = {name: raw for name, raw in load_module('prepare-server-node-chain.py').copies().items()
                   if name.startswith('cmd/sing-box/routervpn_server_chain_') and not name.endswith('_test.go')}
        self.assertTrue(workers)
        def modules(name):
            if name == 'test_node_chain_openvpn_execution_owner.py':
                return SimpleNamespace(verify=lambda core, desktop: None)
            return load_module(name)

        with tempfile.TemporaryDirectory() as tmp, patch.object(RUN, 'load', side_effect=modules):
            core = Path(tmp).resolve(strict=True)
            for relative, raw in workers.items():
                path = core/relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(raw)
            for name, relative in load_module('prepare-desktop-external.py').PEER_TEMPLATES.items():
                path = core/relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes((ROOT/'mobile/desktop'/name).read_bytes())
            (core/RUN.BOX_TARGET).write_bytes((ROOT/RUN.BOX_TEMPLATE).read_bytes())
            (core/'go.mod').write_text('module fixture.invalid/target-ownership\n')
            def run(command, *, cwd, env, timeout):
                self.assertEqual((env['GOOS'], env['GOARCH']), ('linux', 'amd64'))
                if command[:2] == ['go', 'test']:
                    overlay = Path(next(arg[9:] for arg in command if str(arg).startswith('-overlay=')))
                    entries = json.loads(overlay.read_bytes())['Replace']
                    for name, original in workers.items():
                        destination = core/'protocol/routervpnamnezia'/(Path(name).stem+'_test.go')
                        self.assertEqual(Path(entries[str(destination)]).read_bytes(),
                                         original.replace(b'package main\n', b'package routervpnamnezia_test\n', 1))
                    Path(command[command.index('-o')+1]).write_bytes(b'validator-only')
                    return ''
                if len(command) == 2 and str(command[1]).startswith('-test.list='):
                    return '\n'.join(RUN.PEER_CASES)
                self.assertEqual(command[:3], ['go', 'tool', 'test2json'])
                leaf = next(leaf for leaf in RUN.STRONG_SELECTED_CASES
                            if command[-1] == '-test.run='+RUN.selector(RUN.SELECTED_ROOT, leaf))
                return output(transcript(RUN.SELECTED_ROOT, leaf))
            with redirect_stdout(io.StringIO()):
                receipt = RUN.execute(core, 'linux/amd64', 'with_wireguard',
                                      {'GOOS':'linux','GOARCH':'amd64','CGO_ENABLED':'1'}, run, strong_diagnostic=True)
        self.assertEqual(receipt['target'], 'linux/amd64')
        self.assertEqual(set(receipt['encrypted']), set(RUN.STRONG_SELECTED_CASES))

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
