#!/usr/bin/env python3
"""Run every shared multihop test once in bounded, disjoint CI phases."""
from pathlib import Path
import argparse
import re
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = './internal/mobilemultihop'
NAME = re.compile(r'(?:Test|Example|Fuzz)\w*')
PHASES = (
    # The complete ordered matrix exceeded one 180s phase. Partition by
    # authority boundary; future roots still enter one explicit fallback.
    ('ordered execution discovery and Last', r'^TestNodeChainExecution(?:Discovery|Last)'),
    ('ordered execution runtime and Stop', r'^TestNodeChainExecution(?:Runtime|Healthy|Stop)'),
    ('ordered execution MTU', r'^TestNodeChainExecutionMTU'),
    ('ordered execution measurements', r'^TestNodeChainExecutionMeasurement'),
    ('ordered execution capture and projection', r'^TestNodeChainExecution(?!(?:Discovery|Last|Runtime|Healthy|Stop|MTU|Measurement))'),
    ('ordered Server carrier and proof', r'^TestNodeChainServer'),
    ('ordered imported middle', r'^TestNodeChainImported'),
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
)
# Explicit complete ownership keeps CI groups bounded without silently losing a
# newly introduced phase. The default invocation still runs every group.
CI_GROUPS = {
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
    'runtime': (
        'desktop ordered physical graph matrix', 'desktop ordered execution authority',
        'desktop ordered policies', 'desktop ordered readiness', 'desktop node policies and ownership',
        'desktop execution and ownership', 'imported transports and ownership',
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
))


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
            'TestNodeChainExecutionFuture', 'TestNodeChainServerFuture',
            'TestNodeChainImportedFuture', 'TestNodeChainCandidateFuture',
            'TestNodeChainMeasurementFuture', 'TestNodeChainFuture',
            'TestDesktopNodeChainExecutionKeepsActualPhysicalGraph',
            'TestDesktopNodeChainExecutionFuture',
            'TestFutureController', 'Example', 'FuzzFutureSeed', 'TestÜnicode',
        })

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
        self.assertEqual(selected, groups)
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
            required = {name for name in REQUIRED if name.startswith(prefix)}
            self.assertEqual(len(required), count)
            self.assertTrue(required.issubset(groups[phase]))
            selected = [name for names in groups.values() for name in names if name in required]
            self.assertEqual(sorted(selected), sorted(required))
            for omitted in required:
                with self.subTest(omitted=omitted), self.assertRaisesRegex(ValueError, 'Required shared multihop matrix is missing'):
                    inventory('\n'.join(name for name in self.names if name != omitted))

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
        subprocess.run(command(selected), cwd=ROOT, check=True, timeout=240)
    count = sum(len(selected) for _, selected in selected_groups)
    print(f'All {count} selected shared multihop tests passed exactly once in {len(selected_groups)} phases '
          f'(complete inventory: {len(names)} tests in {len(groups)} phases)', flush=True)
    return 0


if __name__ == '__main__':
    sys.exit(main())
