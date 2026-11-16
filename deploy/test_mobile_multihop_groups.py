#!/usr/bin/env python3
"""Run every shared multihop root and prefix leaf in bounded, disjoint CI phases."""
from pathlib import Path
import argparse
import importlib.util
import json
import re
import subprocess
import sys
import unittest
from contextlib import redirect_stdout
from io import StringIO
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = './internal/mobilemultihop'
NAME = re.compile(r'(?:Test|Example|Fuzz)\w*')
PREFIX_ROOT = 'TestNodeChainImportedSSCompletePacketPrefixes'
PREFIX_PHASE = 'ordered imported SS complete prefixes'
PREFIX_MODES = ('wg', 'awg2-fast', 'awg2-strong')
PREFIX_FORMS = ('literal', 'hostname')
PREFIX_METHODS = ('2022-blake3-aes-128-gcm', '2022-blake3-aes-256-gcm',
                  '2022-blake3-chacha20-poly1305')


def prefix_inventory():
    return tuple((mode, form, '^' + PREFIX_ROOT + '$/^' + mode + '$/^' + form + '$',
                  frozenset((PREFIX_ROOT, *(PREFIX_ROOT + '/' + mode + '/' + form + '/' + method + '/' + str(count)
                            for method in PREFIX_METHODS for count in range(1, 7)))))
                 for mode in PREFIX_MODES for form in PREFIX_FORMS)


def load_clock_verdict():
    # Reuse the same exact run/pass/order/negative parser as the required
    # SS prefix source contract; only this group's original clocks differ.
    spec = importlib.util.spec_from_file_location('shared_prefix_clock_verdict',
        ROOT / 'deploy/test_focused_multihop_clocks.py')
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


EXECUTION_FIFTY_REQUIRED = frozenset((
    'TestNodeChainExecutionLatencyClosedCaptureRequiresFreshServerProof',
    'TestNodeChainExecutionLatencyClosedCaptureRejectsRetiredMeasurement',
    'TestNodeChainExecutionLatencyClosedCaptureRejectsChangedOwnerAndEpoch',
    'TestNodeChainExecutionLatencyClosedCaptureRequiresOriginalRequestAndCaller',
    'TestNodeChainExecutionLatencyRetainsSelectedProjectionAndFiftyResponses',
    'TestNodeChainExecutionLatencyShortCloseRetainsHeldReleaseAndHistory',
    'TestNodeChainExecutionLatencyInvalidateRetainsHeldReleaseAndHistory',
    'TestNodeChainExecutionLatencyRequiresFreshServerReceiptAfterRelease',
    'TestNodeChainExecutionLatencyRejectsUncapturedFactoryAndFacade',
    'TestNodeChainExecutionLatencyRejectsRequestReuseAndPreservesThroughputSuccessor',
))
PHASES = (
    # Fifty and held-release Retest have independent original 180s budgets.
    ('execution fifty selected projection', r'^TestNodeChainExecutionLatencyRetainsSelectedProjectionAndFiftyResponses$'),
    ('execution fifty held close', r'^TestNodeChainExecutionLatencyShortCloseRetainsHeldReleaseAndHistory$'),
    ('execution fifty held invalidation', r'^TestNodeChainExecutionLatencyInvalidateRetainsHeldReleaseAndHistory$'),
    ('execution fifty fresh server receipt', r'^TestNodeChainExecutionLatencyRequiresFreshServerReceiptAfterRelease$'),
    ('execution fifty original ownership', r'^TestNodeChainExecutionLatency(?!(?:RetainsSelectedProjectionAndFiftyResponses|ShortCloseRetainsHeldReleaseAndHistory|InvalidateRetainsHeldReleaseAndHistory|RequiresFreshServerReceiptAfterRelease|ClosedCaptureRequiresOriginalRequestAndCaller|ClosedCaptureRejectsChangedOwnerAndEpoch|ClosedCaptureRejectsRetiredMeasurement|ClosedCaptureRequiresFreshServerProof)$)'),
    ('execution fifty closed capture identity', r'^TestNodeChainExecutionLatencyClosedCaptureRequiresOriginalRequestAndCaller$'),
    ('execution fifty closed capture ownership', r'^TestNodeChainExecutionLatencyClosedCaptureRejectsChangedOwnerAndEpoch$'),
    ('execution fifty closed capture retirement', r'^TestNodeChainExecutionLatencyClosedCaptureRejectsRetiredMeasurement$'),
    ('execution fifty closed capture server proof', r'^TestNodeChainExecutionLatencyClosedCaptureRequiresFreshServerProof$'),
    # The complete ordered matrix exceeded one 180s phase. Partition by
    # authority boundary; future roots still enter one explicit fallback.
    ('ordered execution discovery and Last', r'^TestNodeChainExecution(?:Discovery|Last)'),
    ('ordered execution runtime and Stop', r'^TestNodeChainExecution(?:Runtime|Healthy|Stop)'),
    ('ordered execution MTU', r'^TestNodeChainExecutionMTU'),
    ('ordered execution measurements', r'^TestNodeChainExecutionMeasurement'),
    ('ordered execution capture and projection', r'^TestNodeChainExecution(?!(?:Discovery|Last|Runtime|Healthy|Stop|MTU|Measurement|Latency))'),
    ('ordered Server carrier and proof', r'^TestNodeChainServer'),
    ('ordered imported middle', r'^TestNodeChainImported(?!SSCompletePacketPrefixes$)'),
    ('ordered candidates and prefix measurements', r'^TestNodeChain(?:Candidate|Measurement)'),
    ('ordered original graphs and ownership', r'^TestNodeChain(?!(?:Execution|Server|Imported|Candidate|Measurement))'),
    ('node capture and packet identities', r'^Test(?:Node(?!Chain)|NativeNode|DesktopPredecessor|WireGuard|Amnezia|NativeAmnezia)'),
    ('proxy transports and native Xray', r'^Test(?:Proxy|Naive|Xray|NativeXray)'),
    ('mandatory PQ', r'^TestPQ'),
    ('Start Layers and composites', r'^Test(?:Composite|EntryStartLayer|EntryLayer|BothStartLayers|ExitLayer|NativeBaseStartLayer)'),
    ('complete MAX chains', r'^Test(?:CompleteMAX|MAX|ExportMAX|ExportPinnedCoreMAX)'),
    ('external paths and OpenVPN', r'^Test(?:External|OpenVPN|ImportedEntry)'),
    # Keep the growing fallback below the same 180s aggregate bound. Exclude
    # the roots already covered by the node and external phases explicitly.
    # Ordered replay and readiness have grown beyond the combined desktop
    # phase; keep their complete matrix under the same 180-second limit.
    # The complete physical graph matrix needs its own unchanged deadline;
    # its independent invalid-authority and readiness controls still all run.
    ('desktop ordered physical graph matrix', r'^TestDesktopNodeChainExecutionKeepsActualPhysicalGraph$'),
    ('desktop ordered execution authority', r'^TestDesktopNodeChainExecution(?!KeepsActualPhysicalGraph$)'),
    ('desktop ordered policies', r'^TestDesktopNodeChain(?!Execution|Ready)'),
    ('desktop ordered readiness', r'^TestDesktopNode(?:ChainReady|Ready)'),
    ('desktop node policies and ownership', r'^TestDesktop(?:Node(?!Chain|Ready)|LinuxNode|CompleteMAX)'),
    ('desktop execution and ownership', r'^TestDesktop(?!Predecessor|Node|LinuxNode|CompleteMAX)'),
    ('imported transports and ownership', r'^TestImported(?!Entry)'),
    # The typed mobile restore owns a fresh native/MTU join; keep its complete
    # matrix separate from the existing generic fallback at the same budget.
    ('mobile CONNECT execution restore', r'^TestMobileNodeChainCONNECTExecutionRestore'),
    (PREFIX_PHASE, '^' + PREFIX_ROOT + '$'),
)
# Explicit complete ownership keeps CI groups bounded without silently losing a
# newly introduced phase. The default invocation still runs every group.
CI_GROUPS = {
    'fifty': (
        'execution fifty selected projection',
        'execution fifty held close',
        'execution fifty held invalidation',
        'execution fifty fresh server receipt',
        'execution fifty original ownership',
    ),
    'fifty_closed': (
        'execution fifty closed capture identity',
        'execution fifty closed capture ownership',
        'execution fifty closed capture retirement',
        'execution fifty closed capture server proof',
    ),
    'core': (
        'ordered execution discovery and Last', 'ordered execution runtime and Stop',
        'ordered execution MTU', 'ordered execution measurements',
        'ordered execution capture and projection', 'ordered Server carrier and proof',
        'ordered imported middle', 'ordered candidates and prefix measurements',
        'ordered original graphs and ownership', 'node capture and packet identities',
        'proxy transports and native Xray', 'mandatory PQ',
        'Start Layers and composites', 'complete MAX chains',
        'external paths and OpenVPN',
    ),
    'imported_prefix': (PREFIX_PHASE,),
    'runtime': (
        'desktop ordered physical graph matrix', 'desktop ordered execution authority',
        'desktop ordered policies', 'desktop ordered readiness', 'desktop node policies and ownership',
        'desktop execution and ownership', 'imported transports and ownership',
        'mobile CONNECT execution restore',
        'controller, proof and remaining ownership',
    ),
}


REQUIRED = frozenset((
    'TestImportedEntryPacketFinalCompleteGraphs', 'TestImportedEntryPacketFinalOwnershipAndMTU',
    'TestImportedEntryPacketCompleteGraphs', 'TestImportedEntryPacketSourceAndMTUOwnership', 'TestImportedEntryHysteriaFinalCompleteGraphs',
    'TestImportedEntryHysteriaFinalRejectsUnownedLayerAndTrust',
    'TestImportedEntryHysteriaPairedFinalCompleteLayers',
    'TestImportedEntryHysteriaRejectsChangedSource',
    'TestImportedEntryPairedFinalCompleteLayers',
    'TestImportedEntryPairedFinalRejectsChangedAuthority',
    'TestImportedEntryRuntimeDistinctProofsAndSelectedDNS',
    'TestImportedEntryPairedFinalPolicyAndCipherOwnership',
    'TestImportedEntryLegacyPairedFinalKeepsOriginalSource',
    'TestImportedEntryRuntimeLocalSelectionRetiresWithOriginalOwner',
    'TestNodeMultihopEveryCompleteNativeEntryAndExit',
    'TestRealSharedControllerRequestsScoresSelectsAndCleans',
    'TestExternalExecutionRunsOwnedLeaseExactScoreRepeatAndPolicyProof',
    'TestCompleteMAXPrivateRelaysPreserveBothProofsAndEveryOwnedLayer',
    'TestPQEntriesPreserveAllExistingExitAndStartLayerPaths',
    'TestNaiveEveryExistingEntryExitLayerAndExecutionGraph',
    'TestNodeChainCompleteCapturedPaths',
    'TestNodeChainOrderSourceAndBounds',
    'TestNodeChainCanonicalIndependentPeers',
    'TestNodeChainProjectionReopensExactSystemTUN',
    'TestNodeChainMTURequiresEveryMiddleEnvelope',
    'TestNodeChainProjectionRetainsFixedAndSourcePolicy',
    'TestNodeChainRuntimeProvesEveryOriginalPrefix',
    'TestNodeChainRuntimeRejectsMiddleAndNativeChanges',
    'TestNodeChainRetainedObserverRetiresDeadMiddle',
    'TestNodeChainCancellationJoinsLateOriginalCallbacks',
    'TestDesktopNodeChainPolicyExactPhysicalProjection',
    'TestDesktopNodeChainPolicyCombinesProtectionAndKeepsFinalDNS',
    'TestDesktopNodeChainPolicyRejectsChangedOriginalAndPhysicalGraph',
    'TestDesktopNodeChainPolicyLaunchOwnerReceiptAndClosedConstructor',
    'TestDesktopNodeChainReadyRequiresCompletePhysicalAndProofIdentity',
    'TestMobileNodeChainCONNECTExecutionRestoreKeepsOriginalOwnerMTUAndChoice',
)) | EXECUTION_FIFTY_REQUIRED | {PREFIX_ROOT}


def inventory(output):
    names = []
    for line in output.splitlines():
        if line.startswith(('Test', 'Example', 'Fuzz')):
            if not NAME.fullmatch(line):
                raise ValueError('Malformed discovered Go test name: ' + repr(line))
            names.append(line)
    if not names or len(names) != len(set(names)):
        raise ValueError('Empty or duplicate shared multihop test inventory')
    if not REQUIRED.issubset(names):
        raise ValueError('Required shared multihop matrix is missing: ' + ', '.join(sorted(REQUIRED - set(names))))
    return names


def validate_partition(names, groups):
    counts = dict.fromkeys(names, 0)
    for label, selected in groups:
        if not selected:
            raise ValueError('Empty shared multihop phase: ' + label)
        for name in selected:
            if name not in counts:
                raise ValueError('Undiscovered test in shared multihop phase: ' + name)
            counts[name] += 1
    if any(count != 1 for count in counts.values()):
        raise ValueError('Shared multihop phases omit or duplicate a discovered test')


def partition(names, predicates=PHASES):
    groups = [(label, [name for name in names if re.match(pattern, name)])
              for label, pattern in predicates]
    assigned = {name for _, selected in groups for name in selected}
    groups.append(('controller, proof and remaining ownership',
                   [name for name in names if name not in assigned]))
    validate_partition(names, groups)
    return groups


def select_ci_group(groups, selected=None, assignment=CI_GROUPS):
    labels = [label for label, _ in groups]
    assigned = [label for members in assignment.values() for label in members]
    if (len(labels) != len(set(labels)) or len(assigned) != len(set(assigned))
            or set(labels) != set(assigned) or any(not members for members in assignment.values())):
        raise ValueError('CI groups must cover every discovered phase exactly once')
    if selected is None:
        return groups
    if selected not in assignment:
        raise ValueError('Unknown CI group')
    return [(label, names) for label, names in groups if label in assignment[selected]]


def exact_selector(names):
    # Go test does not support Python's noncapturing group syntax. These names
    # are compiler-discovered identifiers, so regex metacharacters cannot enter.
    return '^(' + '|'.join(names) + ')$'


def command(names):
    return ['go', 'test', '-race', '-count=1', '-timeout=180s',
            PACKAGE, '-run', exact_selector(names)]


def prefix_command(selection):
    return ['go', 'test', '-json', '-race', '-count=1', '-timeout=180s',
            PACKAGE, '-run', selection]


def imported_root_verdict(raw, root, code):
    # Execute the entire discovered root without a subtest filter. Require its
    # own run/pass plus every observed child and the original package terminal;
    # descendants can never stand in for an omitted or foreign root.
    expected = {root}
    for line in raw.splitlines():
        event = json.loads(line)
        if not isinstance(event, dict):
            raise ValueError('Malformed imported root verdict')
        name = event.get('Test')
        if 'Test' in event and not isinstance(name, str):
            raise ValueError('Malformed imported root test name')
        if name:
            if not isinstance(name, str) or not (name == root or name.startswith(root+'/')):
                raise ValueError('Foreign test in imported root verdict')
            expected.add(name)
    clock = load_clock_verdict()
    case = clock.Case(root, exact_selector([root]), frozenset(expected), 180, 240)
    receipt = clock.verdict(raw, case, code)
    if not receipt['accepted']:
        raise ValueError('Imported root refused: '+json.dumps(receipt, sort_keys=True))
    return receipt


def run_phase(label, selected, run=None):
    if run is None:
        run = subprocess.run
    if label == 'ordered imported middle':
        if (not selected or len(selected) != len(set(selected)) or
                any(not NAME.fullmatch(root) or not root.startswith('TestNodeChainImported') or root == PREFIX_ROOT for root in selected)):
            raise ValueError('Imported roots must retain their complete disjoint discovered inventory')
        # The combined runtime of the 32 remaining roots exceeded the old
        # 180s phase budget after Server/Compare coverage grew. Keep every
        # root's original complete cases under the same original deadline.
        for root in selected:
            print('Shared multihop: complete imported root '+root, flush=True)
            result = run(prefix_command(exact_selector([root])), cwd=ROOT, capture_output=True, timeout=240)
            raw = result.stdout + result.stderr
            print(raw.decode(errors='replace'), end='', flush=True)
            imported_root_verdict(raw, root, result.returncode)
        return
    if label != PREFIX_PHASE:
        run(command(selected), cwd=ROOT, check=True, timeout=240)
        return
    if selected != [PREFIX_ROOT]:
        raise ValueError('Complete prefix phase must own exactly its discovered root')
    clock = load_clock_verdict()
    for mode, form, selection, expected in prefix_inventory():
        print(f'Shared multihop: imported SS {mode}/{form}; 18 required leaves', flush=True)
        result = run(prefix_command(selection), cwd=ROOT, capture_output=True, timeout=240)
        raw = result.stdout + result.stderr
        print(raw.decode(errors='replace'), end='', flush=True)
        case = clock.Case(mode + '/' + form, selection, expected, 180, 240)
        receipt = clock.verdict(raw, case, result.returncode)
        if not receipt['accepted']:
            raise ValueError('Complete prefix phase refused: ' + json.dumps(receipt, sort_keys=True))


class PartitionTests(unittest.TestCase):
    def setUp(self):
        self.names = sorted(REQUIRED | {
            'TestEntryStartLayerPreservesAllNativeModesAndChoicePaths',
            'TestDesktopExecution', 'TestDesktopPredecessorOwnership',
            'TestDesktopNodeFuturePolicy', 'TestDesktopLinuxNodeFuturePolicy',
            'TestDesktopNodeChainFuturePolicy', 'TestDesktopNodeReadyFutureReceipt',
            'TestImportedTransport', 'TestNodeChainExecutionDiscoveryFuture',
            'TestNodeChainExecutionLastFuture', 'TestNodeChainExecutionRuntimeFuture',
            'TestNodeChainExecutionHealthyFuture', 'TestNodeChainExecutionStopFuture',
            'TestNodeChainExecutionMTUFuture', 'TestNodeChainExecutionMeasurementFuture',
            'TestNodeChainExecutionFuture', 'TestNodeChainExecutionLatencyFuture', 'TestNodeChainServerFuture',
            'TestNodeChainImportedFuture', 'TestNodeChainCandidateFuture',
            'TestNodeChainMeasurementFuture', 'TestNodeChainFuture',
            'TestDesktopNodeChainExecutionKeepsActualPhysicalGraph',
            'TestDesktopNodeChainExecutionFuture',
            'TestFutureController', 'Example', 'FuzzFutureSeed', 'TestÜnicode',
        })

    def test_complete_prefix_matrix_is_disjoint_exhaustive_and_separate(self):
        phases = prefix_inventory()
        self.assertEqual(len(phases), 6)
        self.assertEqual(len({row[2] for row in phases}), 6)
        leaves = [name for _, _, _, expected in phases for name in expected if name != PREFIX_ROOT]
        self.assertEqual(len(leaves), 108)
        self.assertEqual(len(set(leaves)), 108)
        for mode, form, selector, expected in phases:
            self.assertEqual(len(expected), 19)
            self.assertEqual(selector, '^' + PREFIX_ROOT + '$/^' + mode + '$/^' + form + '$')
            self.assertEqual(prefix_command(selector), ['go', 'test', '-json', '-race', '-count=1',
                '-timeout=180s', PACKAGE, '-run', selector])
        groups = partition(self.names)
        self.assertEqual(select_ci_group(groups, 'imported_prefix'), [(PREFIX_PHASE, [PREFIX_ROOT])])
        self.assertNotIn(PREFIX_ROOT, dict(groups)['ordered imported middle'])
        self.assertIn('TestNodeChainImportedFuture', dict(groups)['ordered imported middle'])
        with self.assertRaises(ValueError):
            inventory('\n'.join(name for name in self.names if name != PREFIX_ROOT))
        for fault in ('missing-job', 'duplicate', 'omitted'):
            assignment = {name: list(labels) for name, labels in CI_GROUPS.items()}
            if fault == 'missing-job':
                del assignment['imported_prefix']
            elif fault == 'duplicate':
                assignment['core'].append(PREFIX_PHASE)
            else:
                assignment['imported_prefix'].clear()
            with self.subTest(fault=fault), self.assertRaises(ValueError):
                select_ci_group(groups, None, assignment)

    def test_prefix_dispatch_requires_every_original_verdict_and_stops_on_failure(self):
        phases = prefix_inventory()
        def output(expected):
            rows = [{'Action': 'start', 'Package': 'router-vpn/internal/mobilemultihop'}]
            for name in sorted(expected):
                rows.extend({'Action': action, 'Package': 'router-vpn/internal/mobilemultihop', 'Test': name}
                            for action in ('run', 'pass'))
            rows.append({'Action': 'pass', 'Package': 'router-vpn/internal/mobilemultihop'})
            return rows
        def encode(rows):
            return ('\n'.join(json.dumps(row) for row in rows) + '\n').encode()
        calls = []
        def execute(args, **kwargs):
            index = len(calls)
            calls.append(args)
            self.assertEqual(args, prefix_command(phases[index][2]))
            self.assertEqual(kwargs, dict(cwd=ROOT, capture_output=True, timeout=240))
            return SimpleNamespace(returncode=0, stdout=encode(output(phases[index][3])), stderr=b'')
        with redirect_stdout(StringIO()):
            run_phase(PREFIX_PHASE, [PREFIX_ROOT], execute)
        self.assertEqual(len(calls), 6)
        clock = load_clock_verdict()
        for mode, form, selection, expected in phases:
            case = clock.Case(mode + '/' + form, selection, expected, 180, 240)
            rows = output(expected)
            for name in expected:
                for action in ('run', 'pass'):
                    omitted = [row for row in rows if not (row.get('Test') == name and row['Action'] == action)]
                    duplicated = rows[:-1] + [next(row for row in rows if row.get('Test') == name and row['Action'] == action)] + rows[-1:]
                    for altered in (omitted, duplicated):
                        self.assertFalse(clock.verdict(encode(altered), case, 0)['accepted'])
        for fault in ('failed', 'skipped', 'foreign', 'race', 'build-fail', 'exit', 'missing-terminal', 'late-run'):
            rows = output(phases[0][3]); code = 0
            if fault in ('failed', 'skipped'):
                rows[2]['Action'] = 'fail' if fault == 'failed' else 'skip'
            elif fault == 'foreign': rows[1]['Package'] = 'foreign/package'
            elif fault == 'race': rows.insert(1, {'Action': 'output', 'Output': 'WARNING: DATA RACE'})
            elif fault == 'build-fail': rows.insert(1, {'Action': 'build-fail'})
            elif fault == 'exit': code = 1
            elif fault == 'missing-terminal': rows.pop()
            else: rows.append(rows[1])
            calls = []
            def failed(args, **kwargs):
                calls.append(args)
                return SimpleNamespace(returncode=code, stdout=encode(rows), stderr=b'')
            with self.subTest(fault=fault), redirect_stdout(StringIO()), self.assertRaises(ValueError):
                run_phase(PREFIX_PHASE, [PREFIX_ROOT], failed)
            self.assertEqual(len(calls), 1)
        calls = []
        run_phase('ordinary unchanged phase', ['TestNodeChainImportedFuture'],
                  lambda args, **kwargs: calls.append((args, kwargs)))
        self.assertEqual(calls, [(command(['TestNodeChainImportedFuture']), dict(cwd=ROOT, check=True, timeout=240))])

    def test_imported_remainder_keeps_each_discovered_root_and_original_deadline(self):
        names = sorted(set(self.names) | {'TestNodeChainImportedServerFuture', 'TestNodeChainImportedPrefixExecutionFuture'})
        selected = dict(partition(names))['ordered imported middle']
        self.assertIn('TestNodeChainImportedFuture', selected)
        def output(root):
            package = 'router-vpn/internal/mobilemultihop'
            return [dict(Package=package, Action='start'), dict(Package=package, Action='run', Test=root),
                    dict(Package=package, Action='run', Test=root+'/original'),
                    dict(Package=package, Action='pass', Test=root+'/original'),
                    dict(Package=package, Action='pass', Test=root), dict(Package=package, Action='pass')]
        encode = lambda rows: ('\n'.join(json.dumps(row) for row in rows)+'\n').encode()
        calls = []
        def execute(args, **kwargs):
            root = selected[len(calls)]; calls.append(root)
            self.assertEqual(args, ['go', 'test', '-json', '-race', '-count=1', '-timeout=180s', PACKAGE, '-run', exact_selector([root])])
            self.assertEqual(kwargs, dict(cwd=ROOT, capture_output=True, timeout=240))
            return SimpleNamespace(returncode=0, stdout=encode(output(root)), stderr=b'')
        with redirect_stdout(StringIO()): run_phase('ordered imported middle', selected, execute)
        self.assertEqual(calls, selected)
        for invalid in ([], [selected[0], selected[0]], [PREFIX_ROOT], ['TestForeign'], ['TestNodeChainImportedFuture/partial']):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                run_phase('ordered imported middle', invalid, execute)
        root = selected[0]
        for fault in ('missing-root', 'missing-run', 'missing-child-pass', 'duplicate', 'foreign-root', 'foreign-package',
                      'skip', 'fail', 'race', 'panic', 'build-fail', 'exit', 'missing-terminal', 'duplicate-terminal', 'late-run',
                      'malformed-event', 'malformed-test-name'):
            rows = output(root); code = 0
            if fault == 'missing-root': rows = [row for row in rows if row.get('Test') != root]
            elif fault == 'missing-run': rows.pop(1)
            elif fault == 'missing-child-pass': rows.pop(3)
            elif fault == 'duplicate': rows.insert(2, rows[1])
            elif fault == 'foreign-root': rows[1]['Test'] = 'TestNodeChainImportedOther'
            elif fault == 'foreign-package': rows[1]['Package'] = 'foreign'
            elif fault in ('skip', 'fail'): rows[3]['Action'] = fault
            elif fault in ('race', 'panic'): rows.insert(2, dict(Action='output', Output='WARNING: DATA RACE' if fault == 'race' else 'panic: test timed out'))
            elif fault == 'build-fail': rows.insert(0, dict(Action='build-fail'))
            elif fault == 'exit': code = 1
            elif fault == 'missing-terminal': rows.pop()
            elif fault == 'duplicate-terminal': rows.append(rows[-1])
            elif fault == 'malformed-event': rows.insert(0, [])
            elif fault == 'malformed-test-name': rows.insert(1, dict(Action='output', Test=0))
            else: rows.append(rows[1])
            calls = []
            def fail(args, **kwargs):
                calls.append(args)
                return SimpleNamespace(returncode=code, stdout=encode(rows), stderr=b'')
            with self.subTest(fault=fault), redirect_stdout(StringIO()), self.assertRaises(ValueError):
                run_phase('ordered imported middle', [root, 'TestNodeChainImportedLater'], fail)
            self.assertEqual(len(calls), 1)

    def test_complete_future_coverage_and_exact_commands(self):
        actual = inventory('\n'.join(self.names) + '\nok\trouter-vpn/internal/mobilemultihop\t0.1s\n')
        groups = partition(actual)
        self.assertEqual(sorted(name for _, names in groups for name in names), self.names)
        for _, selected in groups:
            args = command(selected)
            self.assertEqual(args[:6], ['go', 'test', '-race', '-count=1', '-timeout=180s', PACKAGE])
            self.assertEqual([name for name in actual if re.fullmatch(args[-1], name)], selected)

    def test_ci_groups_retain_complete_disjoint_discovered_inventory(self):
        groups = partition(self.names)
        self.assertEqual(select_ci_group(groups), groups)
        selected = [entry for group in CI_GROUPS for entry in select_ci_group(groups, group)]
        self.assertEqual(sorted(selected), sorted(groups))
        validate_partition(self.names, selected)
        for mutation in ('omitted', 'overlap', 'unknown', 'empty'):
            assignment = {key: list(value) for key, value in CI_GROUPS.items()}
            if mutation == 'omitted':
                assignment['core'].pop()
            elif mutation == 'overlap':
                assignment['core'].append(assignment['runtime'][0])
            elif mutation == 'unknown':
                assignment['core'].append('not a discovered phase')
            else:
                assignment['runtime'] = []
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                select_ci_group(groups, 'core', assignment)
        with self.assertRaises(ValueError):
            select_ci_group(groups + [('new unassigned phase', ['TestNew'])], 'core')
        with self.assertRaises(ValueError):
            select_ci_group(groups, 'not a CI group')

    def test_empty_duplicate_malformed_and_missing_inventories(self):
        for output in ('', '\n'.join(self.names + [self.names[0]]),
                       '\n'.join(self.names + ['TestBroken/name']),
                       '\n'.join(name for name in self.names if name != sorted(REQUIRED)[0])):
            with self.subTest(output=output), self.assertRaises(ValueError):
                inventory(output)

    def test_growing_fallback_is_disjoint_and_future_names_still_run(self):
        groups = dict(partition(self.names))
        self.assertIn('TestDesktopExecution', groups['desktop execution and ownership'])
        self.assertIn('TestDesktopPredecessorOwnership', groups['node capture and packet identities'])
        for name in ('TestDesktopNodeFuturePolicy', 'TestDesktopLinuxNodeFuturePolicy'):
            self.assertIn(name, groups['desktop node policies and ownership'])
        self.assertIn('TestDesktopNodeChainFuturePolicy', groups['desktop ordered policies'])
        self.assertIn('TestDesktopNodeReadyFutureReceipt', groups['desktop ordered readiness'])
        self.assertIn('TestImportedTransport', groups['imported transports and ownership'])
        self.assertIn('TestImportedEntryPacketFinalCompleteGraphs', groups['external paths and OpenVPN'])
        for name in ('TestFutureController', 'Example', 'FuzzFutureSeed', 'TestÜnicode'):
            self.assertIn(name, groups['controller, proof and remaining ownership'])
        for label, pattern in (('overlap desktop', r'^TestDesktop'), ('overlap imported', r'^TestImported')):
            with self.subTest(label=label), self.assertRaises(ValueError):
                partition(self.names, PHASES + ((label, pattern),))

    def test_every_selected_node_chain_root_is_mandatory_and_runs_once(self):
        groups = dict(partition(self.names))
        for prefix, count, phase in (('TestNodeChain', 10, 'ordered original graphs and ownership'),
                                     ('TestDesktopNodeChainPolicy', 4, 'desktop ordered policies'),
                                     ('TestDesktopNodeChainReady', 1, 'desktop ordered readiness')):
            required = {name for name in REQUIRED if name.startswith(prefix) and name not in EXECUTION_FIFTY_REQUIRED and name != PREFIX_ROOT}
            self.assertEqual(len(required), count)
            self.assertTrue(required.issubset(groups[phase]))
            selected = [name for names in groups.values() for name in names if name in required]
            self.assertEqual(sorted(selected), sorted(required))
            for omitted in required:
                with self.subTest(omitted=omitted), self.assertRaisesRegex(ValueError, 'Required shared multihop matrix is missing'):
                    inventory('\n'.join(name for name in self.names if name != omitted))

    def test_execution_fifty_roots_have_disjoint_bounded_ci_phases(self):
        groups = partition(self.names)
        original = select_ci_group(groups, 'fifty')
        closed = select_ci_group(groups, 'fifty_closed')
        self.assertEqual(len(original), 5)
        self.assertEqual(len(closed), 4)
        closed_roots = {name for name in EXECUTION_FIFTY_REQUIRED
                        if name.startswith('TestNodeChainExecutionLatencyClosedCapture')}
        self.assertEqual(len(closed_roots), 4)
        original_roots = {name for _, names in original for name in names}
        actual_closed = {name for _, names in closed for name in names}
        self.assertEqual(actual_closed, closed_roots)
        self.assertEqual(original_roots, (EXECUTION_FIFTY_REQUIRED - closed_roots)
                         | {'TestNodeChainExecutionLatencyFuture'})
        self.assertFalse(original_roots.intersection(actual_closed))
        selected = original + closed
        actual = original_roots | actual_closed
        for label, names in selected:
            self.assertIn('-timeout=180s', command(names))
            if label != 'execution fifty original ownership':
                self.assertEqual(len(names), 1)
        for group in ('core', 'runtime'):
            self.assertFalse(actual.intersection(name for _, names in select_ci_group(groups, group) for name in names))
        for omitted in EXECUTION_FIFTY_REQUIRED:
            with self.subTest(omitted=omitted), self.assertRaisesRegex(ValueError, 'Required shared multihop matrix is missing'):
                inventory('\n'.join(name for name in self.names if name != omitted))
        for group in ('fifty', 'fifty_closed'):
            for omitted in CI_GROUPS[group]:
                assignment = {key: tuple(label for label in labels if label != omitted)
                              for key, labels in CI_GROUPS.items()}
                with self.subTest(group=group, phase=omitted), self.assertRaises(ValueError):
                    select_ci_group(groups, group, assignment)
        for label, names in selected:
            duplicate = groups + [(label + ' duplicate', names)]
            with self.subTest(duplicate=label), self.assertRaises(ValueError):
                validate_partition(self.names, duplicate)

    def test_closed_capture_job_cannot_lose_duplicate_or_steal_a_phase(self):
        names = self.names + ['TestNodeChainExecutionLatencyClosedCaptureFuture']
        groups = partition(names)
        # Future tests retain the original mandatory fallback; exactly the four
        # current closed-capture phases get the new bounded job.
        original = {name for _, found in select_ci_group(groups, 'fifty') for name in found}
        self.assertIn('TestNodeChainExecutionLatencyClosedCaptureFuture', original)
        for fault in ('missing-job', 'duplicate-phase', 'omitted-phase', 'foreign-phase'):
            assignment = {key: list(value) for key, value in CI_GROUPS.items()}
            if fault == 'missing-job':
                del assignment['fifty_closed']
            elif fault == 'duplicate-phase':
                assignment['fifty'].append(assignment['fifty_closed'][0])
            elif fault == 'omitted-phase':
                assignment['fifty_closed'].pop()
            else:
                assignment['fifty_closed'].append('unowned closed capture phase')
            with self.subTest(fault=fault), self.assertRaises(ValueError):
                select_ci_group(groups, 'fifty', assignment)

    def test_ordered_semantic_boundaries_keep_future_roots(self):
        groups = dict(partition(self.names))
        expected = {
            'ordered execution discovery and Last': ('Discovery', 'Last'),
            'ordered execution runtime and Stop': ('Runtime', 'Healthy', 'Stop'),
            'ordered execution MTU': ('MTU',),
            'ordered execution measurements': ('Measurement',),
            'ordered execution capture and projection': ('',),
        }
        for phase, suffixes in expected.items():
            for suffix in suffixes:
                self.assertIn('TestNodeChainExecution'+suffix+'Future', groups[phase])
        for phase, suffix in (
            ('ordered Server carrier and proof','Server'),
            ('ordered imported middle','Imported'),
            ('ordered candidates and prefix measurements','Candidate'),
            ('ordered candidates and prefix measurements','Measurement'),
            ('ordered original graphs and ownership','')):
            self.assertIn('TestNodeChain'+suffix+'Future',groups[phase])
        self.assertEqual(groups['desktop ordered physical graph matrix'],
            ['TestDesktopNodeChainExecutionKeepsActualPhysicalGraph'])
        self.assertEqual(groups['desktop ordered execution authority'],
            ['TestDesktopNodeChainExecutionFuture'])
        for prefix in ('^TestNodeChainExecution', '^TestNodeChainServer', '^TestDesktopNodeChainExecution'):
            with self.subTest(prefix=prefix), self.assertRaises(ValueError):
                partition(self.names, PHASES+(('overlapping ordered boundary',prefix),))

    def test_mobile_connect_restore_keeps_its_complete_bounded_phase(self):
        root = 'TestMobileNodeChainCONNECTExecutionRestoreKeepsOriginalOwnerMTUAndChoice'
        future = 'TestMobileNodeChainCONNECTExecutionRestoreFuture'
        ordinary = 'TestMobileNodeChainExecutionRestoreFuture'
        names = sorted(set(self.names) | {future, ordinary})
        groups = partition(names)
        selected = dict(groups)['mobile CONNECT execution restore']
        self.assertEqual(set(selected), {root, future})
        self.assertIn(ordinary, dict(groups)['controller, proof and remaining ownership'])
        self.assertIn('-timeout=180s', command(selected))
        self.assertIn(('mobile CONNECT execution restore', selected), select_ci_group(groups, 'runtime'))
        with self.assertRaisesRegex(ValueError, 'Required shared multihop matrix is missing'):
            inventory('\n'.join(name for name in names if name != root))
        with self.assertRaises(ValueError):
            partition(names, PHASES + (('duplicate mobile restore', r'^TestMobileNodeChainCONNECTExecutionRestore'),))
        for fault in ('missing', 'duplicate'):
            assignment = {key: list(value) for key, value in CI_GROUPS.items()}
            if fault == 'missing':
                assignment['runtime'].remove('mobile CONNECT execution restore')
            else:
                assignment['core'].append('mobile CONNECT execution restore')
            with self.subTest(fault=fault), self.assertRaises(ValueError):
                select_ci_group(groups, 'runtime', assignment)

    def test_overlapping_predicates_reject(self):
        with self.assertRaises(ValueError):
            partition(self.names, PHASES + (('duplicate PQ', r'^TestPQ'),))
        with self.assertRaises(ValueError):
            partition(self.names, PHASES + (('duplicate ordered nodes', r'^TestNode'),))

    def test_missing_duplicate_unknown_and_empty_phase_reject(self):
        for mutation in ('drop', 'duplicate', 'unknown', 'empty'):
            groups = [(label, list(names)) for label, names in partition(self.names)]
            if mutation == 'drop':
                groups[0][1].pop()
            elif mutation == 'duplicate':
                groups[0][1].append(groups[-1][1][0])
            elif mutation == 'unknown':
                groups[0][1].append('TestUndiscovered')
            else:
                groups[0][1].clear()
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                validate_partition(self.names, groups)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--self-test', action='store_true')
    parser.add_argument('--group', choices=tuple(CI_GROUPS), help='Run one fully inventoried CI group')
    args = parser.parse_args()
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(PartitionTests)
    if not unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful():
        return 1
    if args.self_test:
        return 0
    discovered = subprocess.check_output(['go', 'test', PACKAGE, '-list', '.'],
                                         cwd=ROOT, text=True, timeout=300)
    names = inventory(discovered)
    groups = partition(names)
    selected_groups = select_ci_group(groups, args.group)
    for label, selected in selected_groups:
        print(f'Shared multihop: {label}; {len(selected)} discovered tests', flush=True)
        run_phase(label, selected)
    count = sum(len(selected) for _, selected in selected_groups)
    print(f'All {count} selected shared multihop roots passed with disjoint leaf coverage in {len(selected_groups)} logical phases '
          f'(complete inventory: {len(names)} tests in {len(groups)} phases)', flush=True)
    return 0


if __name__ == '__main__':
    sys.exit(main())
