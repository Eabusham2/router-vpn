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
    ('node capture and packet identities', r'^Test(?:Node|NativeNode|DesktopPredecessor|WireGuard|Amnezia|NativeAmnezia)'),
    ('proxy transports and native Xray', r'^Test(?:Proxy|Naive|Xray|NativeXray)'),
    ('mandatory PQ', r'^TestPQ'),
    ('Start Layers and composites', r'^Test(?:Composite|EntryStartLayer|EntryLayer|BothStartLayers|ExitLayer|NativeBaseStartLayer)'),
    ('complete MAX chains', r'^Test(?:CompleteMAX|MAX|ExportMAX|ExportPinnedCoreMAX)'),
    ('external paths and OpenVPN', r'^Test(?:External|OpenVPN|ImportedEntry)'),
    # Keep the growing fallback below the same 180s aggregate bound. Exclude
    # the roots already covered by the node and external phases explicitly.
    ('desktop execution and ownership', r'^TestDesktop(?!Predecessor)'),
    ('imported transports and ownership', r'^TestImported(?!Entry)'),
)
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
            'TestImportedTransport',
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
        self.assertIn('TestImportedTransport', groups['imported transports and ownership'])
        self.assertIn('TestImportedEntryPacketFinalCompleteGraphs', groups['external paths and OpenVPN'])
        for name in ('TestFutureController', 'Example', 'FuzzFutureSeed', 'TestÜnicode'):
            self.assertIn(name, groups['controller, proof and remaining ownership'])
        for label, pattern in (('overlap desktop', r'^TestDesktop'), ('overlap imported', r'^TestImported')):
            with self.subTest(label=label), self.assertRaises(ValueError):
                partition(self.names, PHASES + ((label, pattern),))

    def test_every_selected_node_chain_root_is_mandatory_and_runs_once(self):
        groups = dict(partition(self.names))
        for prefix, count, phase in (('TestNodeChain', 10, 'node capture and packet identities'),
                                     ('TestDesktopNodeChainPolicy', 4, 'desktop execution and ownership')):
            required = {name for name in REQUIRED if name.startswith(prefix)}
            self.assertEqual(len(required), count)
            self.assertTrue(required.issubset(groups[phase]))
            selected = [name for names in groups.values() for name in names if name in required]
            self.assertEqual(sorted(selected), sorted(required))
            for omitted in required:
                with self.subTest(omitted=omitted), self.assertRaisesRegex(ValueError, 'Required shared multihop matrix is missing'):
                    inventory('\n'.join(name for name in self.names if name != omitted))

    def test_overlapping_predicates_reject(self):
        with self.assertRaises(ValueError):
            partition(self.names, PHASES + (('duplicate PQ', r'^TestPQ'),))

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
    for label, selected in groups:
        print(f'Shared multihop: {label}; {len(selected)} discovered tests', flush=True)
        subprocess.run(command(selected), cwd=ROOT, check=True, timeout=240)
    print(f'All {len(names)} discovered shared multihop tests passed exactly once in {len(groups)} phases', flush=True)
    return 0


if __name__ == '__main__':
    sys.exit(main())
