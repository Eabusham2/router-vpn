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
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = './internal/mobilemultihop'
NAME = re.compile(r'(?:Test|Example|Fuzz)\w*')
PREFIX_ROOT = 'TestNodeChainImportedSSCompletePacketPrefixes'
PREFIX_PHASE = 'ordered imported SS complete prefixes'
PREFIX_MODES = ('wg', 'awg2-fast', 'awg2-strong')
PREFIX_FORMS = ('literal', 'hostname')
PREFIX_METHODS = ('2022-blake3-aes-128-gcm', '2022-blake3-aes-256-gcm',
                  '2022-blake3-chacha20-poly1305')
DESKTOP_EXECUTION_PHASE = 'desktop execution and ownership'
ORIGINAL_GRAPHS_PHASE = 'ordered original graphs and ownership'
DESKTOP_EXECUTION_BATCH_ROOTS = 16


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
CONNECT_PREFIX_SOURCE = (
    'TestNodeChainCONNECTExecutionCompletePrefixes',
    'TestNodeChainCONNECTExecutionPrefixOwnershipRefusals',
    'TestNodeChainCONNECTExecutionProjectionSingleObservationOwnership',
)
CONNECT_PREFIX_LIFECYCLE = (
    'TestNodeChainCONNECTExecutionPrefixRuntimeAndStop',
    'TestNodeChainCONNECTExecutionPrefixRestoreKeepsWinner',
)
CONNECT_PREFIX_ROOTS = CONNECT_PREFIX_SOURCE + CONNECT_PREFIX_LIFECYCLE

SOCKS_PREFIX_ROOTS = (
    'TestNodeChainSOCKSExecutionPrefixesWG',
    'TestNodeChainSOCKSExecutionPrefixesFast',
    'TestNodeChainSOCKSExecutionPrefixesStrong',
    'TestNodeChainSOCKSExecutionPrefixRuntimeAndStop',
    'TestNodeChainSOCKSExecutionPrefixRestoreKeepsWinner',
    'TestNodeChainSOCKSExecutionPrefixOwnershipRefusals',
    'TestNodeChainSOCKSExecutionProjectionSingleObservationOwnership',
)
SOCKS_PREFIX_PHASES = tuple(('SOCKS prefix '+root.removeprefix('TestNodeChainSOCKSExecution'), '^'+root+'$')
                          for root in SOCKS_PREFIX_ROOTS)

OPENVPN_SERVER_ROOTS = (
    'TestNodeChainOpenVPNServerCompleteOriginalSuffix',
    'TestNodeChainOpenVPNServerRefusesForeignAuthority',
    'TestNodeChainOpenVPNServerRequiresConnectedNativeProof',
    'TestNodeChainOpenVPNServerPlanIndependentOriginalPair',
    'TestNodeChainOpenVPNServerPlanRefusesRoleSubstitution',
    'TestNodeChainOpenVPNPairingFieldCannotEnterOtherFamilies',
)

OPENVPN_EXECUTION_ROOTS = (
    'TestNodeChainOpenVPNExecutionRestoreFreshLocalReceipt',
    'TestNodeChainOpenVPNExecutionRestoreRefusesUnjoinedOrForeignOwner',
    'TestNodeChainOpenVPNExecutionRestoredLocalRetainsFreshReceipt',
    'TestNodeChainOpenVPNExecutionOrdinaryRuntimeCannotMintFreshLocalReceipt',
    'TestNodeChainOpenVPNExecutionRestoreMTUResumeRetainsFreshReceipt',
    'TestNodeChainOpenVPNExecutionIndependentCandidateConnection',
    'TestNodeChainOpenVPNExecutionDiscoveryRetainsOwnerWithoutLocalConnection',
    'TestNodeChainOpenVPNExecutionLocalWinnerRetainsConnectedReceipt',
    'TestMobileNodeChainOpenVPNExecutionRestoreKeepsOriginalOwnerMTUAndChoice',
    'TestNodeChainOpenVPNExecutionRuntimeServerOwnsOriginalLease',
    'TestNodeChainOpenVPNExecutionRestoreKeepsOriginalChoice',
    'TestNodeChainOpenVPNExecutionCompareKeepsSharedTargetAndFreshWinner',
    'TestNodeChainOpenVPNExecutionCompareTimeoutIsIneligible',
    'TestNodeChainOpenVPNExecutionPrefixRuntimeAndStop',
    'TestNodeChainOpenVPNExecutionDiscoveryKeepsTypedSourceAndRestoreProposal',
    'TestNodeChainOpenVPNExecutionLastReopensOnlyAfterFreshDiscovery',
    'TestNodeChainOpenVPNExecutionMissingObserverRefusedBeforeDiscovery',
    'TestNodeChainOpenVPNExecutionRuntimeRefusesChangedProofOrOwner',
    'TestNodeChainOpenVPNExecutionRetainsFailedOriginalStop',
    'TestNodeChainOpenVPNExecutionPrefixesWG',
    'TestNodeChainOpenVPNExecutionPrefixesFast',
    'TestNodeChainOpenVPNExecutionPrefixesStrong',
    'TestNodeChainOpenVPNExecutionRetainsSealedMobileProjection',
    'TestNodeChainOpenVPNExecutionRejectsForeignConnectedOwner',
    'TestNodeChainOpenVPNExecutionHeldReceiptRetainsCallerDeadline',
)
OPENVPN_EXECUTION_PHASES = tuple(("OpenVPN execution "+root, "^"+root+"$") for root in OPENVPN_EXECUTION_ROOTS)

OPENVPN_DESKTOP_EXECUTION_ROOTS = ('TestDesktopOpenVPNExecutionOriginalPhysicalLinux', 'TestDesktopOpenVPNExecutionOriginalPhysicalWindows', 'TestDesktopOpenVPNExecutionOriginalPhysicalDarwin', 'TestDesktopOpenVPNExecutionOriginalOwnerRefusals', 'TestDesktopOpenVPNExecutionCanonicalParserRefusals', 'TestDesktopOpenVPNExecutionConcretePhysicalAndCover', 'TestDesktopOpenVPNExecutionSavedChoiceBinding', 'TestDesktopOpenVPNExecutionLastRuntimeReproof', 'TestDesktopOpenVPNExecutionPrefixRuntimeAndStop', 'TestDesktopOpenVPNExecutionCanonicalRecords', 'TestDesktopOpenVPNExecutionMaximumRecords')
OPENVPN_DESKTOP_EXECUTION_PHASES = tuple(("desktop OpenVPN execution "+root,"^"+root+"$") for root in OPENVPN_DESKTOP_EXECUTION_ROOTS)

HYSTERIA_SERVER_ROOTS = (
    'TestNodeChainServerHysteriaRetainsOriginalFinalClosure',
    'TestNodeChainServerHysteriaExecutionRetainsBothOriginalPaths',
    'TestNodeChainServerHysteriaPlanRetainsIndependentIdentity',
    'TestNodeChainServerHysteriaRejectsChangedTransportAuthority',
    'TestNodeChainServerHysteriaRestoresProvedChoice',
    'TestNodeChainServerHysteriaLastFreshlyProvesCapturedWinner',
)
HYSTERIA_SERVER_PHASES = tuple(('paired Hysteria2 Server '+root, '^'+root+'$') for root in HYSTERIA_SERVER_ROOTS)

HYSTERIA_LAYER_ROOTS = (
    'TestNodeChainHysteriaFinalLayers2',
    'TestNodeChainHysteriaFinalLayers3',
    'TestNodeChainHysteriaFinalLayers4',
    'TestNodeChainHysteriaFinalLayers5',
    'TestNodeChainHysteriaFinalLayers6',
    'TestNodeChainHysteriaFinalLayers7',
    'TestNodeChainHysteriaFinalLayers8',
    'TestNodeChainHysteriaFinalLayersRejectChangedClosure',
    'TestNodeChainHysteriaFinalLayersRejectBorrowedSource',
    'TestNodeChainHysteriaFinalLayersRequireOriginalProofLifetime',
    'TestNodeChainServerHysteriaFinalLayers2',
    'TestNodeChainServerHysteriaFinalLayers3',
    'TestNodeChainServerHysteriaFinalLayers4',
    'TestNodeChainServerHysteriaFinalLayers5',
    'TestNodeChainServerHysteriaFinalLayers6',
    'TestNodeChainServerHysteriaFinalLayers7',
    'TestNodeChainServerHysteriaFinalLayers8',
    'TestNodeChainServerHysteriaFinalLayersPlan',
    'TestNodeChainServerHysteriaFinalLayersExecution',
    'TestNodeChainServerHysteriaFinalLayersRestore',
    'TestNodeChainServerHysteriaFinalLayersLast',
)
HYSTERIA_LAYER_PHASES = tuple(('paired Hysteria2 layers '+root, '^'+root+'$') for root in HYSTERIA_LAYER_ROOTS)

CANDIDATE_PREFIX_SOURCE_ROOTS = (
    'TestNodeChainCandidatePreparationImportedSavedPrefixes',
    'TestNodeChainCandidatePreparationOpenVPNKeepsOnlyPacketPrefixes',
)
CANDIDATE_PREFIX_REQUIRED_ROOTS = (*CANDIDATE_PREFIX_SOURCE_ROOTS,
    'TestNodeChainCandidatePreparationOpenVPNSuffixRemainsOnlyProvenance',
    'TestNodeChainCandidatePreparationOpenVPNRuntimeFiftyAndRetirement',
    'TestNodeChainCandidatePreparationImportedSuffixKeepsProvenance',
    'TestNodeChainCandidatePreparationImportedPrefixRunsFifty',
)
CANDIDATE_IMPORTED_SOURCE_ROOTS = (
    'TestNodeChainCandidatePreparationImportedSSKeepsOnlyPacketPrefixes',
    'TestNodeChainCandidatePreparationImportedSSDesktopLiteral',
    'TestNodeChainCandidatePreparationImportedSSDesktopHostname',
)
CANDIDATE_IMPORTED_REQUIRED_ROOTS = (*CANDIDATE_IMPORTED_SOURCE_ROOTS,
    'TestNodeChainCandidatePreparationIdentityReadIsFresh',
    'TestNodeChainCandidatePreparationImportedSSProvenanceAndOwners',
    'TestNodeChainCandidatePreparationImportedSSRuntimeFiftyAndRetirement',
)

CANDIDATE_LAYER_ROOTS = ('TestNodeChainCandidatePairedLayersUseOriginalTCPClosure', 'TestNodeChainCandidatePairedLayersRejectSourceSubstitution', 'TestNodeChainCandidatePairedLayersRunFiftyAndRetire')
CANDIDATE_LAYER_PHASES = tuple(('paired SS candidate layers '+root, '^'+root+'$') for root in CANDIDATE_LAYER_ROOTS)

CANDIDATE_TYPED_ROOTS = (
    'TestNodeChainCandidatePreparationTypedClosedSource',
    'TestNodeChainCandidatePreparationTypedRejectsSubstitution',
    'TestNodeChainCandidatePreparationTypedRuntimeFifty',
    'TestNodeChainCandidatePreparationTypedRuntimeAuthority',
)
CANDIDATE_TYPED_PHASES = tuple(('captured typed candidate '+root, '^'+root+'$') for root in CANDIDATE_TYPED_ROOTS)
CANDIDATE_CONNECTED_ROOTS = (
    'TestNodeChainTypedConnectedCandidateSource',
    'TestNodeChainTypedConnectedCandidateFifty',
    'TestNodeChainTypedConnectedCandidateRefusesOwners',
    'TestNodeChainTypedConnectedCandidateCancelDrain',
)
CANDIDATE_CONNECTED_PHASES = tuple(('connected typed candidate '+root, '^'+root+'$') for root in CANDIDATE_CONNECTED_ROOTS)
CANDIDATE_TYPED_DESKTOP_ROOTS = (
    'TestDesktopNodeCandidateTypedSavedPolicy',
    'TestDesktopNodeCandidateTypedPolicyRefusesOriginalChange',
)
CANDIDATE_TYPED_DESKTOP_PHASES = tuple(('desktop typed candidate '+root, '^'+root+'$') for root in CANDIDATE_TYPED_DESKTOP_ROOTS)
CONNECTED_IMPORTED_CANDIDATE_ROOTS = (
    'TestNodeChainCandidateConnectedImportedSources',
    'TestNodeChainCandidateConnectedImportedRequiresCompleteReady',
    'TestNodeChainCandidateConnectedImportedRunsOriginalFifty',
    'TestNodeChainCandidateConnectedImportedRejectsOwnerDrift',
)
CONNECTED_IMPORTED_CANDIDATE_PHASES = tuple(('connected imported candidate '+root, '^'+root+'$')
                                           for root in CONNECTED_IMPORTED_CANDIDATE_ROOTS)

MULTIPLE_IMPORTED_ROOTS = (
    'TestNodeChainMultipleIndependentImportedRequirement',
    'TestNodeChainMultipleImportedCompleteCapture',
    'TestNodeChainMultipleImportedProjectionAndDevicePolicy',
    'TestNodeChainMultipleImportedRejectsChangedOriginalOwners',
    'TestNodeChainMultipleImportedKeepsOlderCapabilitiesClosed',
    'TestNodeChainMultipleImportedProvesEachOriginalPublicIdentity',
    'TestNodeChainMultipleImportedMeasurementRoutesAndCancellation',
    'TestNodeChainMultipleImportedMTUConsecutiveAndLayeredPacket',
    'TestNodeChainMultipleImportedMTURetainsCipherAddressAndKeys',
    'TestNodeChainMultipleImportedMTURefusesFixedAndInsufficientBudget',
)
MULTIPLE_IMPORTED_PHASES = tuple(('Local independent imported nodes '+root, '^'+root+'$')
                                for root in MULTIPLE_IMPORTED_ROOTS)

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
    *HYSTERIA_SERVER_PHASES,
    *HYSTERIA_LAYER_PHASES,
    ('ordered Server carrier and proof', '^(?!(?:'+'|'.join(HYSTERIA_SERVER_ROOTS+HYSTERIA_LAYER_ROOTS)+')$)'+r'TestNodeChainServer'),
    ('ordered imported middle', r'^TestNodeChainImported(?!SSCompletePacketPrefixes$)'),
    ('ordered hostname Server and comparison', r'^TestNodeChainHostnameExecution'),
    # Complete saved-source matrices are separate from live measurements.
    # Preserve both entire source roots and every original/new runtime root,
    # each phase under the original 180s process bound.
    ('captured candidate prefix sources', '^(?:'+'|'.join(CANDIDATE_PREFIX_SOURCE_ROOTS)+')$'),
    ('captured imported candidate source ownership', '^(?:'+'|'.join(CANDIDATE_IMPORTED_SOURCE_ROOTS)+')$'),
    *CANDIDATE_TYPED_PHASES,
    *CANDIDATE_CONNECTED_PHASES,
    *CONNECTED_IMPORTED_CANDIDATE_PHASES,
    *CANDIDATE_LAYER_PHASES,
    *MULTIPLE_IMPORTED_PHASES,
    ('ordered candidates and prefix measurements', '^(?!(?:'+'|'.join(CANDIDATE_PREFIX_SOURCE_ROOTS+CANDIDATE_IMPORTED_SOURCE_ROOTS+CANDIDATE_TYPED_ROOTS+CONNECTED_IMPORTED_CANDIDATE_ROOTS+CANDIDATE_LAYER_ROOTS)+')$)'+r'TestNodeChain(?:Candidate|Measurement)'),
    ('CONNECT prefix execution source authority', '^(?:'+'|'.join(CONNECT_PREFIX_SOURCE)+')$'),
    ('CONNECT prefix execution lifecycle', '^(?:'+'|'.join(CONNECT_PREFIX_LIFECYCLE)+')$'),
    *SOCKS_PREFIX_PHASES,
    *OPENVPN_EXECUTION_PHASES,
    *OPENVPN_DESKTOP_EXECUTION_PHASES,
    ('OpenVPN Server original pair and proof', '^(?:'+'|'.join(OPENVPN_SERVER_ROOTS)+')$'),
    ('ordered original graphs and ownership', '^(?!(?:'+'|'.join(CONNECT_PREFIX_ROOTS+SOCKS_PREFIX_ROOTS+OPENVPN_SERVER_ROOTS+OPENVPN_EXECUTION_ROOTS+HYSTERIA_LAYER_ROOTS+CANDIDATE_CONNECTED_ROOTS+MULTIPLE_IMPORTED_ROOTS)+')$)'+r'TestNodeChain(?!(?:Execution|Server|Imported|Candidate|Measurement|HostnameExecution))'),
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
    *CANDIDATE_TYPED_DESKTOP_PHASES,
    ('desktop node policies and ownership', '^(?!(?:'+'|'.join(CANDIDATE_TYPED_DESKTOP_ROOTS)+')$)'+r'TestDesktop(?:Node(?!Chain|Ready)|LinuxNode|CompleteMAX)'),
    ('desktop execution and ownership', '^(?!(?:'+'|'.join(OPENVPN_DESKTOP_EXECUTION_ROOTS)+')$)'+r'TestDesktop(?!Predecessor|Node|LinuxNode|CompleteMAX)'),
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
        *(label for label, _ in HYSTERIA_SERVER_PHASES),
        *(label for label, _ in HYSTERIA_LAYER_PHASES),
        'ordered imported middle', 'ordered hostname Server and comparison', 'captured candidate prefix sources',
        'captured imported candidate source ownership', 'ordered candidates and prefix measurements',
        *(label for label, _ in CANDIDATE_TYPED_PHASES),
        *(label for label, _ in CANDIDATE_CONNECTED_PHASES),
        *(label for label, _ in CONNECTED_IMPORTED_CANDIDATE_PHASES),
        *(label for label, _ in CANDIDATE_LAYER_PHASES),
        *(label for label, _ in MULTIPLE_IMPORTED_PHASES),
        'CONNECT prefix execution source authority', 'CONNECT prefix execution lifecycle',
        *(label for label, _ in SOCKS_PREFIX_PHASES),
        *(label for label, _ in OPENVPN_EXECUTION_PHASES),
        'OpenVPN Server original pair and proof',
        'ordered original graphs and ownership', 'node capture and packet identities',
        'proxy transports and native Xray', 'mandatory PQ',
        'Start Layers and composites', 'complete MAX chains',
        'external paths and OpenVPN',
    ),
    'imported_prefix': (PREFIX_PHASE,),
    'runtime': (
        *(label for label, _ in OPENVPN_DESKTOP_EXECUTION_PHASES),
        'desktop ordered physical graph matrix', 'desktop ordered execution authority',
        'desktop ordered policies', 'desktop ordered readiness', 'desktop node policies and ownership',
        *(label for label, _ in CANDIDATE_TYPED_DESKTOP_PHASES),
        'desktop execution and ownership', 'imported transports and ownership',
        'mobile CONNECT execution restore',
        'controller, proof and remaining ownership',
    ),
}


REQUIRED = frozenset((*MULTIPLE_IMPORTED_ROOTS, *CANDIDATE_CONNECTED_ROOTS, *CANDIDATE_LAYER_ROOTS, *CANDIDATE_TYPED_ROOTS, *CANDIDATE_TYPED_DESKTOP_ROOTS,*CONNECT_PREFIX_ROOTS, *SOCKS_PREFIX_ROOTS, *OPENVPN_SERVER_ROOTS, *OPENVPN_EXECUTION_ROOTS, *OPENVPN_DESKTOP_EXECUTION_ROOTS, *HYSTERIA_SERVER_ROOTS, *HYSTERIA_LAYER_ROOTS, *CANDIDATE_PREFIX_REQUIRED_ROOTS, *CANDIDATE_IMPORTED_REQUIRED_ROOTS, *CONNECTED_IMPORTED_CANDIDATE_ROOTS,
    'TestNodeChainHostnameExecutionRetainsPacketPrefixDNS',
    'TestNodeChainHostnameExecutionRejectsUnownedDNS',
    'TestNodeChainHostnameExecutionComparesAndRestores',
    'TestNodeChainHostnameExecutionRejectsFailedOriginalPacketProof',
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


def complete_roots_verdict(raw, roots, code, label):
    # Execute entire discovered roots without a subtest filter. Require their
    # own run/pass plus every observed child and the original package terminal;
    # descendants can never stand in for an omitted or foreign root.
    if not roots or len(roots) != len(set(roots)) or any(not NAME.fullmatch(root) for root in roots):
        raise ValueError('Invalid '+label+' root inventory')
    expected = set(roots)
    for line in raw.splitlines():
        event = json.loads(line)
        if not isinstance(event, dict):
            raise ValueError('Malformed '+label+' root verdict')
        name = event.get('Test')
        if 'Test' in event and not isinstance(name, str):
            raise ValueError('Malformed '+label+' root test name')
        if name:
            if not any(name == root or name.startswith(root+'/') for root in roots):
                raise ValueError('Foreign test in '+label+' root verdict')
            expected.add(name)
    clock = load_clock_verdict()
    case = clock.Case(label, exact_selector(roots), frozenset(expected), 180, 240)
    receipt = clock.verdict(raw, case, code)
    if not receipt['accepted']:
        raise ValueError(label+' roots refused: '+json.dumps(receipt, sort_keys=True))
    return receipt


def imported_root_verdict(raw, root, code):
    return complete_roots_verdict(raw, [root], code, 'Imported')


def complete_phase_batches(label, selected):
    if label not in (DESKTOP_EXECUTION_PHASE, ORIGINAL_GRAPHS_PHASE):
        raise ValueError('Uncaptured complete-root phase')
    pattern = dict(PHASES)[label]
    if (not selected or len(selected) != len(set(selected)) or
            any(not NAME.fullmatch(root) or not re.match(pattern, root) for root in selected)):
        raise ValueError(label+' lost its complete disjoint discovered inventory')
    return tuple(tuple(selected[start:start+DESKTOP_EXECUTION_BATCH_ROOTS])
                 for start in range(0, len(selected), DESKTOP_EXECUTION_BATCH_ROOTS))


def desktop_execution_batches(selected):
    return complete_phase_batches(DESKTOP_EXECUTION_PHASE, selected)


def run_phase(label, selected, run=None):
    if run is None:
        run = subprocess.run
    if label in (DESKTOP_EXECUTION_PHASE, ORIGINAL_GRAPHS_PHASE):
        # The combined desktop and 129-root original-graph phases each exceeded
        # 180s. Whole-root batches keep that bound and every descendant;
        # the final receipt must cover the original discovery exactly once.
        completed = []
        batches = desktop_execution_batches(selected) if label == DESKTOP_EXECUTION_PHASE else complete_phase_batches(label, selected)
        for index, roots in enumerate(batches, 1):
            print('Shared multihop: '+label+' batch '+str(index)+'; '+str(len(roots))+' complete roots', flush=True)
            result = run(prefix_command(exact_selector(roots)), cwd=ROOT, capture_output=True, timeout=240)
            raw = result.stdout + result.stderr
            print(raw.decode(errors='replace'), end='', flush=True)
            complete_roots_verdict(raw, roots, result.returncode, label)
            completed.extend(roots)
        if completed != selected:
            raise ValueError(label+' omitted, duplicated or reordered a discovered root')
        return
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

    def test_new_connect_roots_are_disjoint_without_repartitioning_old_roots(self):
        groups = dict(partition(self.names))
        self.assertEqual(groups['CONNECT prefix execution source authority'], sorted(CONNECT_PREFIX_SOURCE))
        self.assertEqual(groups['CONNECT prefix execution lifecycle'], sorted(CONNECT_PREFIX_LIFECYCLE))
        self.assertIn('TestNodeChainFuture', groups['ordered original graphs and ownership'])
        self.assertFalse(set(CONNECT_PREFIX_ROOTS) & set(groups['ordered original graphs and ownership']))
        for root in CONNECT_PREFIX_ROOTS:
            self.assertIn(root, REQUIRED)
            self.assertEqual(sum(names.count(root) for names in groups.values()), 1)
            with self.assertRaisesRegex(ValueError, 'Required shared multihop matrix is missing'):
                inventory('\n'.join(name for name in self.names if name != root))
        self.assertIn('-timeout=180s', command(CONNECT_PREFIX_ROOTS))

    def test_connected_imported_candidates_keep_complete_bounded_roots(self):
        groups = partition(self.names)
        mapped = dict(groups)
        for root, (label, _) in zip(CONNECTED_IMPORTED_CANDIDATE_ROOTS, CONNECTED_IMPORTED_CANDIDATE_PHASES):
            self.assertEqual(mapped[label], [root])
            self.assertEqual(sum(names.count(root) for _, names in groups), 1)
            self.assertIn((label, [root]), select_ci_group(groups, 'core'))
            self.assertIn('-timeout=180s', command([root]))
            with self.assertRaisesRegex(ValueError, 'Required shared multihop matrix is missing'):
                inventory('\n'.join(name for name in self.names if name != root))

    def test_captured_candidate_prefix_sources_keep_all_runtime_roots(self):
        groups = partition(self.names)
        mapped = dict(groups)
        self.assertEqual(mapped['captured candidate prefix sources'], sorted(CANDIDATE_PREFIX_SOURCE_ROOTS))
        for root in CANDIDATE_PREFIX_REQUIRED_ROOTS:
            self.assertEqual(sum(names.count(root) for _, names in groups), 1)
            with self.assertRaisesRegex(ValueError, 'Required shared multihop matrix is missing'):
                inventory('\n'.join(name for name in self.names if name != root))
        for root in CANDIDATE_PREFIX_REQUIRED_ROOTS[2:]:
            self.assertIn(root, mapped['ordered candidates and prefix measurements'])
        for future in ('TestNodeChainCandidateFuture', 'TestNodeChainMeasurementFuture'):
            self.assertIn(future, mapped['ordered candidates and prefix measurements'])
        selected = mapped['captured candidate prefix sources']
        self.assertIn('-timeout=180s', command(selected))
        self.assertIn(('captured candidate prefix sources', selected), select_ci_group(groups, 'core'))
        for fault in ('missing', 'duplicate'):
            assignment = {key: list(value) for key, value in CI_GROUPS.items()}
            if fault == 'missing':
                assignment['core'].remove('captured candidate prefix sources')
            else:
                assignment['runtime'].append('captured candidate prefix sources')
            with self.subTest(fault=fault), self.assertRaises(ValueError):
                select_ci_group(groups, 'core', assignment)

    def test_imported_candidate_source_ownership_keeps_original_prefix_inventory(self):
        groups = partition(self.names)
        mapped = dict(groups)
        label = 'captured imported candidate source ownership'
        self.assertEqual(mapped[label], sorted(CANDIDATE_IMPORTED_SOURCE_ROOTS))
        self.assertEqual(mapped['captured candidate prefix sources'], sorted(CANDIDATE_PREFIX_SOURCE_ROOTS))
        for root in (*CANDIDATE_PREFIX_REQUIRED_ROOTS, *CANDIDATE_IMPORTED_REQUIRED_ROOTS):
            self.assertEqual(sum(names.count(root) for _, names in groups), 1)
            with self.subTest(omitted=root), self.assertRaisesRegex(ValueError, 'Required shared multihop matrix is missing'):
                inventory('\n'.join(name for name in self.names if name != root))
        for root in CANDIDATE_IMPORTED_REQUIRED_ROOTS[len(CANDIDATE_IMPORTED_SOURCE_ROOTS):]:
            self.assertIn(root, mapped['ordered candidates and prefix measurements'])
        self.assertIn('-timeout=180s', command(mapped[label]))
        self.assertIn((label, mapped[label]), select_ci_group(groups, 'core'))
        for fault in ('missing', 'duplicate'):
            assignment = {key: list(value) for key, value in CI_GROUPS.items()}
            if fault == 'missing':
                assignment['core'].remove(label)
            else:
                assignment['runtime'].append(label)
            with self.subTest(fault=fault), self.assertRaises(ValueError):
                select_ci_group(groups, 'core', assignment)

    def test_connected_typed_candidates_have_four_mandatory_disjoint_phases(self):
        mapped = dict(partition(self.names))
        self.assertEqual(len(CANDIDATE_CONNECTED_ROOTS), 4)
        for (label, selector), root in zip(CANDIDATE_CONNECTED_PHASES, CANDIDATE_CONNECTED_ROOTS):
            self.assertEqual(mapped[label], [root])
            self.assertEqual(selector, '^'+root+'$')
            self.assertIn(root, REQUIRED)
            self.assertIn(label, CI_GROUPS['core'])
            for other, names in mapped.items():
                if other != label: self.assertNotIn(root, names)
            with self.assertRaises(ValueError): inventory('\n'.join(name for name in self.names if name != root))
            assignment = {key: list(value) for key, value in CI_GROUPS.items()}
            assignment['core'].remove(label)
            with self.assertRaises(ValueError): select_ci_group(partition(self.names), assignment=assignment)
            assignment['core'].extend((label, label))
            with self.assertRaises(ValueError): select_ci_group(partition(self.names), assignment=assignment)
        self.assertIn('-timeout=180s', command(CANDIDATE_CONNECTED_ROOTS))

    def test_typed_candidate_capture_keeps_full_required_closed_union(self):
        groups = partition(self.names)
        mapped = dict(groups)
        for phases, owner in ((CANDIDATE_LAYER_PHASES, 'core'), (CANDIDATE_TYPED_PHASES, 'core'), (CANDIDATE_TYPED_DESKTOP_PHASES, 'runtime')):
            for label, selector in phases:
                root = selector[1:-1]
                self.assertEqual(mapped[label], [root])
                self.assertEqual(sum(names.count(root) for _, names in groups), 1)
                self.assertIn('-timeout=180s', command([root]))
                self.assertIn((label, [root]), select_ci_group(groups, owner))
                with self.assertRaisesRegex(ValueError, 'Required shared multihop matrix is missing'):
                    inventory('\n'.join(name for name in self.names if name != root))
                for fault in ('missing', 'duplicate'):
                    assignment = {key: list(value) for key, value in CI_GROUPS.items()}
                    if fault == 'missing':
                        assignment[owner].remove(label)
                    else:
                        assignment['fifty'].append(label)
                    with self.subTest(root=root, fault=fault), self.assertRaises(ValueError):
                        select_ci_group(groups, owner, assignment)

    def test_socks_prefix_roots_keep_independent_original_budgets(self):
        groups = dict(partition(self.names))
        for (label, selector), root in zip(SOCKS_PREFIX_PHASES, SOCKS_PREFIX_ROOTS):
            self.assertEqual(groups[label], [root])
            self.assertEqual(selector, '^'+root+'$')
            self.assertEqual(sum(names.count(root) for names in groups.values()), 1)
            self.assertIn('-timeout=180s', command([root]))
            with self.assertRaisesRegex(ValueError, 'Required shared multihop matrix is missing'):
                inventory('\n'.join(name for name in self.names if name != root))
        self.assertFalse(set(SOCKS_PREFIX_ROOTS) & set(groups['ordered original graphs and ownership']))

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

    def test_hostname_execution_keeps_all_original_roots_in_one_bounded_phase(self):
        names = sorted(set(self.names) | {'TestNodeChainHostnameExecutionFuture'})
        groups = partition(names)
        selected = dict(groups)['ordered hostname Server and comparison']
        expected = sorted(name for name in names if name.startswith('TestNodeChainHostnameExecution'))
        self.assertEqual(selected, expected)
        self.assertEqual(len(expected), 5)
        self.assertIn(('ordered hostname Server and comparison', selected), select_ci_group(groups, 'core'))
        self.assertEqual(command(selected)[2:5], ['-race', '-count=1', '-timeout=180s'])
        for omitted in set(expected).intersection(REQUIRED):
            with self.subTest(omitted=omitted), self.assertRaisesRegex(ValueError, 'Required shared multihop matrix is missing'):
                inventory('\n'.join(name for name in names if name != omitted))
        for mutation in ('omit', 'duplicate'):
            assignment = {key: list(value) for key, value in CI_GROUPS.items()}
            if mutation == 'omit':
                assignment['core'].remove('ordered hostname Server and comparison')
            else:
                assignment['runtime'].append('ordered hostname Server and comparison')
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                select_ci_group(groups, 'core', assignment)

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

    def test_desktop_execution_batches_keep_complete_discovery_and_original_deadlines(self):
        package = 'router-vpn/internal/mobilemultihop'
        for count in (1, 15, 16, 17, 96, 97):
            selected = ['TestDesktopFuture'+str(index) for index in range(count)]
            calls = []
            def execute(args, **kwargs):
                roots = [root for root in selected if re.fullmatch(args[-1], root)]
                self.assertTrue(1 <= len(roots) <= 16)
                self.assertEqual(args, ['go', 'test', '-json', '-race', '-count=1', '-timeout=180s', PACKAGE, '-run', exact_selector(roots)])
                self.assertEqual(kwargs, dict(cwd=ROOT, capture_output=True, timeout=240))
                calls.extend(roots)
                rows = [dict(Package=package, Action='start')]
                for root in roots:
                    rows.extend((dict(Package=package, Action='run', Test=root),
                                 dict(Package=package, Action='run', Test=root+'/original'),
                                 dict(Package=package, Action='pass', Test=root+'/original'),
                                 dict(Package=package, Action='pass', Test=root)))
                rows.append(dict(Package=package, Action='pass'))
                return SimpleNamespace(returncode=0, stdout=('\n'.join(json.dumps(row) for row in rows)+'\n').encode(), stderr=b'')
            with self.subTest(count=count), redirect_stdout(StringIO()):
                run_phase(DESKTOP_EXECUTION_PHASE, selected, execute)
            self.assertEqual(calls, selected)
            self.assertEqual([root for batch in desktop_execution_batches(selected) for root in batch], selected)
        names = sorted(set(self.names) | {'TestDesktopSOCKSExecutionRefusesSerializedDerivation', 'TestDesktopCONNECTFuture', 'TestDesktopImportedFuture'})
        groups = partition(names)
        selected = dict(groups)[DESKTOP_EXECUTION_PHASE]
        self.assertEqual([root for batch in desktop_execution_batches(selected) for root in batch], selected)
        self.assertIn(DESKTOP_EXECUTION_PHASE, dict(select_ci_group(groups, 'runtime')))
        for invalid in ([], ['TestDesktopFuture']*2, ['TestForeign'], ['TestDesktopNodeFuture'],
                        ['TestDesktopPredecessorFuture'], ['TestDesktopLinuxNodeFuture'],
                        ['TestDesktopCompleteMAXFuture'], ['TestDesktopFuture/partial']):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                run_phase(DESKTOP_EXECUTION_PHASE, invalid, lambda *args, **kwargs: self.fail('Invalid inventory was executed'))

    def test_desktop_execution_requires_all_roots_children_and_terminal_verdict(self):
        roots = ['TestDesktopOriginal', 'TestDesktopRetained']
        package = 'router-vpn/internal/mobilemultihop'
        def output():
            rows = [dict(Package=package, Action='start')]
            for root in roots:
                rows.extend((dict(Package=package, Action='run', Test=root),
                             dict(Package=package, Action='run', Test=root+'/original'),
                             dict(Package=package, Action='pass', Test=root+'/original'),
                             dict(Package=package, Action='pass', Test=root)))
            rows.append(dict(Package=package, Action='pass'))
            return rows
        encode = lambda rows: ('\n'.join(json.dumps(row) for row in rows)+'\n').encode()
        for fault in ('missing-root', 'missing-run', 'missing-child-pass', 'duplicate', 'foreign-root', 'foreign-package',
                      'skip', 'fail', 'race', 'panic', 'build-fail', 'exit', 'missing-terminal', 'duplicate-terminal',
                      'late-run', 'malformed-event', 'malformed-test-name', 'false-terminal'):
            rows, code = output(), 0
            if fault == 'missing-root': rows = [row for row in rows if not str(row.get('Test', '')).startswith(roots[1])]
            elif fault == 'missing-run': rows.pop(1)
            elif fault == 'missing-child-pass': rows.pop(3)
            elif fault == 'duplicate': rows.insert(2, rows[1])
            elif fault == 'foreign-root': rows[1]['Test'] = 'TestDesktopForeign'
            elif fault == 'foreign-package': rows[1]['Package'] = 'foreign'
            elif fault in ('skip', 'fail'): rows[3]['Action'] = fault
            elif fault in ('race', 'panic'): rows.insert(2, dict(Action='output', Output='WARNING: DATA RACE' if fault == 'race' else 'panic: test timed out'))
            elif fault == 'build-fail': rows.insert(0, dict(Action='build-fail'))
            elif fault == 'exit': code = 1
            elif fault == 'missing-terminal': rows.pop()
            elif fault == 'duplicate-terminal': rows.append(rows[-1])
            elif fault == 'false-terminal': rows[-1] = dict(Package=package, Action='output', Output='PASS\n')
            elif fault == 'malformed-event': rows.insert(0, [])
            elif fault == 'malformed-test-name': rows.insert(1, dict(Action='output', Test=0))
            else: rows.append(rows[1])
            calls = []
            def failed(args, **kwargs):
                calls.append(args)
                return SimpleNamespace(returncode=code, stdout=encode(rows), stderr=b'')
            with self.subTest(fault=fault), redirect_stdout(StringIO()), self.assertRaises(ValueError):
                run_phase(DESKTOP_EXECUTION_PHASE, roots, failed)
            self.assertEqual(len(calls), 1)

    def test_desktop_execution_final_inventory_rejects_dispatch_omission_or_replay(self):
        selected = ['TestDesktopOriginal'+str(index) for index in range(17)]
        batches = desktop_execution_batches(selected)
        package = 'router-vpn/internal/mobilemultihop'
        def execute(args, **kwargs):
            roots = [root for root in selected if re.fullmatch(args[-1], root)]
            rows = [dict(Package=package, Action='start')]
            for root in roots:
                rows.extend((dict(Package=package, Action='run', Test=root), dict(Package=package, Action='pass', Test=root)))
            rows.append(dict(Package=package, Action='pass'))
            return SimpleNamespace(returncode=0, stdout=('\n'.join(json.dumps(row) for row in rows)+'\n').encode(), stderr=b'')
        for changed in (batches[:-1], batches+batches[:1], tuple(reversed(batches))):
            with self.subTest(batches=changed), patch.dict(globals(), desktop_execution_batches=lambda selected: changed), \
                    redirect_stdout(StringIO()), self.assertRaisesRegex(ValueError, 'omitted, duplicated or reordered'):
                run_phase(DESKTOP_EXECUTION_PHASE, selected, execute)

    def test_desktop_openvpn_original_owners_have_required_bounded_phases(self):
        groups = dict(partition(self.names))
        for root, (label, expression) in zip(OPENVPN_DESKTOP_EXECUTION_ROOTS, OPENVPN_DESKTOP_EXECUTION_PHASES):
            self.assertEqual(groups[label], [root])
            self.assertEqual(expression, '^'+root+'$')
            self.assertIn(label, CI_GROUPS['runtime'])
            self.assertIn(root, REQUIRED)
            with self.assertRaises(ValueError):
                inventory('\n'.join(name for name in self.names if name != root))

    def test_openvpn_execution_roots_are_individually_bounded_and_required(self):
        groups = dict(partition(self.names))
        for root, (label, expression) in zip(OPENVPN_EXECUTION_ROOTS, OPENVPN_EXECUTION_PHASES):
            self.assertEqual(groups[label], [root])
            self.assertEqual(expression, '^'+root+'$')
            self.assertIn(root, REQUIRED)
            self.assertIn(label, CI_GROUPS['core'])
            with self.assertRaises(ValueError):
                inventory('\n'.join(name for name in self.names if name != root))

    def test_openvpn_server_original_authority_roots_are_required_and_disjoint(self):
        groups = dict(partition(self.names))
        self.assertEqual(set(groups['OpenVPN Server original pair and proof']), set(OPENVPN_SERVER_ROOTS))
        for root in OPENVPN_SERVER_ROOTS:
            self.assertIn(root, REQUIRED)
            self.assertNotIn(root, groups[ORIGINAL_GRAPHS_PHASE])
            with self.assertRaises(ValueError):
                inventory('\n'.join(name for name in self.names if name != root))
        self.assertIn('OpenVPN Server original pair and proof', CI_GROUPS['core'])

    def test_hysteria_server_original_authority_roots_are_required_and_disjoint(self):
        groups = dict(partition(self.names))
        for root, (label, expression) in zip(HYSTERIA_SERVER_ROOTS, HYSTERIA_SERVER_PHASES):
            self.assertEqual(groups[label], [root])
            self.assertEqual(expression, '^'+root+'$')
            self.assertIn(root, REQUIRED)
            self.assertIn(label, CI_GROUPS['core'])
            self.assertNotIn(root, groups['ordered Server carrier and proof'])
            self.assertIn('-timeout=180s', command(groups[label]))
            with self.assertRaises(ValueError):
                inventory('\n'.join(name for name in self.names if name != root))
            for mutation in ('omitted', 'duplicated'):
                assignment = {key: list(value) for key, value in CI_GROUPS.items()}
                if mutation == 'omitted':
                    assignment['core'].remove(label)
                else:
                    assignment['runtime'].append(label)
                with self.subTest(root=root, mutation=mutation), self.assertRaises(ValueError):
                    select_ci_group(list(groups.items()), 'core', assignment)
        future = 'TestNodeChainServerHysteriaFuture'
        self.assertIn(future, dict(partition(sorted(set(self.names) | {future})))['ordered Server carrier and proof'])

    def test_hysteria_final_layer_roots_are_complete_required_and_disjoint(self):
        groups = dict(partition(self.names))
        self.assertEqual(len(HYSTERIA_LAYER_ROOTS), 21)
        actual = set()
        for path in (ROOT/'internal/mobilemultihop').glob('node_chain*layers_test.go'):
            actual.update(re.findall(r'^func (TestNodeChain(?:Server)?Hysteria\w+)\(', path.read_text(), re.MULTILINE))
        self.assertEqual(set(HYSTERIA_LAYER_ROOTS), actual)
        for root, (label, expression) in zip(HYSTERIA_LAYER_ROOTS, HYSTERIA_LAYER_PHASES):
            self.assertEqual(groups[label], [root])
            self.assertEqual(expression, '^'+root+'$')
            self.assertIn(root, REQUIRED)
            self.assertIn(label, CI_GROUPS['core'])
            self.assertNotIn(root, groups['ordered Server carrier and proof'])
            self.assertNotIn(root, groups[ORIGINAL_GRAPHS_PHASE])
            self.assertIn('-timeout=180s', command(groups[label]))
            with self.assertRaises(ValueError):
                inventory('\n'.join(name for name in self.names if name != root))
            for mutation in ('omitted', 'duplicated'):
                assignment = {key: list(value) for key, value in CI_GROUPS.items()}
                if mutation == 'omitted':
                    assignment['core'].remove(label)
                else:
                    assignment['runtime'].append(label)
                with self.subTest(root=root, mutation=mutation), self.assertRaises(ValueError):
                    select_ci_group(list(groups.items()), 'core', assignment)

    def test_original_graph_batches_keep_whole_roots_order_and_existing_bounds(self):
        package = 'router-vpn/internal/mobilemultihop'
        for count in (1, 15, 16, 17, 129, 130):
            selected = ['TestNodeChainFuture'+str(index) for index in range(count)]
            calls = []
            def execute(args, **kwargs):
                roots = [root for root in selected if re.fullmatch(args[-1], root)]
                self.assertTrue(1 <= len(roots) <= 16)
                self.assertEqual(args, ['go', 'test', '-json', '-race', '-count=1', '-timeout=180s', PACKAGE, '-run', exact_selector(roots)])
                self.assertEqual(kwargs, dict(cwd=ROOT, capture_output=True, timeout=240))
                calls.extend(roots)
                rows = [dict(Package=package, Action='start')]
                for root in roots:
                    rows.extend((dict(Package=package, Action='run', Test=root),
                                 dict(Package=package, Action='run', Test=root+'/original'),
                                 dict(Package=package, Action='pass', Test=root+'/original'),
                                 dict(Package=package, Action='pass', Test=root)))
                rows.append(dict(Package=package, Action='pass'))
                return SimpleNamespace(returncode=0, stdout=('\n'.join(json.dumps(row) for row in rows)+'\n').encode(), stderr=b'')
            with self.subTest(count=count), redirect_stdout(StringIO()):
                run_phase(ORIGINAL_GRAPHS_PHASE, selected, execute)
            self.assertEqual(calls, selected)
            self.assertEqual([root for batch in complete_phase_batches(ORIGINAL_GRAPHS_PHASE, selected) for root in batch], selected)
        groups = partition(sorted(set(self.names) | {'TestNodeChainFuture'}))
        self.assertIn((ORIGINAL_GRAPHS_PHASE, dict(groups)[ORIGINAL_GRAPHS_PHASE]), select_ci_group(groups, 'core'))
        for invalid in ([], ['TestNodeChainFuture']*2, ['TestForeign'], ['TestDesktopFuture'],
                        ['TestNodeChainExecutionFuture'], ['TestNodeChainImportedFuture'],
                        ['TestNodeChainHostnameExecutionFuture'], [CONNECT_PREFIX_ROOTS[0]], ['TestNodeChainFuture/partial']):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                run_phase(ORIGINAL_GRAPHS_PHASE, invalid, lambda *args, **kwargs: self.fail('Invalid original inventory was executed'))
        with self.assertRaises(ValueError): complete_phase_batches('foreign', ['TestNodeChainFuture'])

    def test_original_graph_dispatch_keeps_descendants_and_strict_verdicts(self):
        roots = ['TestNodeChainOriginal', 'TestNodeChainRetained']
        package = 'router-vpn/internal/mobilemultihop'
        def output():
            rows = [dict(Package=package, Action='start')]
            for root in roots:
                rows.extend((dict(Package=package, Action='run', Test=root),
                             dict(Package=package, Action='run', Test=root+'/original'),
                             dict(Package=package, Action='pass', Test=root+'/original'),
                             dict(Package=package, Action='pass', Test=root)))
            rows.append(dict(Package=package, Action='pass'))
            return rows
        for fault in ('missing-root', 'missing-child', 'duplicate', 'foreign-root', 'skip', 'fail',
                      'race', 'panic', 'exit', 'missing-terminal', 'false-terminal'):
            rows, code = output(), 0
            if fault == 'missing-root': rows = [row for row in rows if not str(row.get('Test', '')).startswith(roots[1])]
            elif fault == 'missing-child': rows.pop(3)
            elif fault == 'duplicate': rows.insert(2, rows[1])
            elif fault == 'foreign-root': rows[1]['Test'] = 'TestNodeChainForeign'
            elif fault in ('skip', 'fail'): rows[3]['Action'] = fault
            elif fault in ('race', 'panic'): rows.insert(2, dict(Action='output', Output='WARNING: DATA RACE' if fault == 'race' else 'panic: test timed out'))
            elif fault == 'exit': code = 1
            elif fault == 'missing-terminal': rows.pop()
            else: rows[-1] = dict(Package=package, Action='output', Output='PASS\n')
            calls = []
            def failed(args, **kwargs):
                calls.append(args)
                return SimpleNamespace(returncode=code, stdout=('\n'.join(json.dumps(row) for row in rows)+'\n').encode(), stderr=b'')
            with self.subTest(fault=fault), redirect_stdout(StringIO()), self.assertRaises(ValueError):
                run_phase(ORIGINAL_GRAPHS_PHASE, roots, failed)
            self.assertEqual(len(calls), 1)

    def test_original_graph_final_inventory_rejects_omission_replay_and_reordering(self):
        selected = ['TestNodeChainOriginal'+str(index) for index in range(129)]
        batches = complete_phase_batches(ORIGINAL_GRAPHS_PHASE, selected)
        package = 'router-vpn/internal/mobilemultihop'
        def execute(args, **kwargs):
            roots = [root for root in selected if re.fullmatch(args[-1], root)]
            rows = [dict(Package=package, Action='start')]
            for root in roots:
                rows.extend((dict(Package=package, Action='run', Test=root), dict(Package=package, Action='pass', Test=root)))
            rows.append(dict(Package=package, Action='pass'))
            return SimpleNamespace(returncode=0, stdout=('\n'.join(json.dumps(row) for row in rows)+'\n').encode(), stderr=b'')
        for changed in (batches[:-1], batches+batches[:1], tuple(reversed(batches))):
            with self.subTest(batches=changed), patch.dict(globals(), complete_phase_batches=lambda label, selected: changed), \
                    redirect_stdout(StringIO()), self.assertRaisesRegex(ValueError, 'omitted, duplicated or reordered'):
                run_phase(ORIGINAL_GRAPHS_PHASE, selected, execute)

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

    def test_independent_imported_roots_remain_mandatory_disjoint_local_phases(self):
        groups = dict(partition(self.names))
        self.assertEqual(len(MULTIPLE_IMPORTED_ROOTS), 10)
        for root, (label, selector) in zip(MULTIPLE_IMPORTED_ROOTS, MULTIPLE_IMPORTED_PHASES):
            self.assertEqual(selector, '^' + root + '$')
            self.assertEqual(groups[label], [root])
            self.assertIn(label, CI_GROUPS['core'])
            self.assertIn('-timeout=180s', command([root]))
            self.assertEqual(sum(names.count(root) for names in groups.values()), 1)
            self.assertNotIn(root, groups['ordered original graphs and ownership'])
            with self.assertRaisesRegex(ValueError, 'Required shared multihop matrix is missing'):
                inventory('\n'.join(name for name in self.names if name != root))

    def test_every_selected_node_chain_root_is_mandatory_and_runs_once(self):
        groups = dict(partition(self.names))
        for prefix, count, phase in (('TestNodeChain', 10, 'ordered original graphs and ownership'),
                                     ('TestDesktopNodeChainPolicy', 4, 'desktop ordered policies'),
                                     ('TestDesktopNodeChainReady', 1, 'desktop ordered readiness')):
            required = {name for name in REQUIRED if name.startswith(prefix) and name not in EXECUTION_FIFTY_REQUIRED and name != PREFIX_ROOT and name not in CONNECT_PREFIX_ROOTS and name not in SOCKS_PREFIX_ROOTS and name not in OPENVPN_SERVER_ROOTS and name not in OPENVPN_EXECUTION_ROOTS and name not in HYSTERIA_SERVER_ROOTS and name not in HYSTERIA_LAYER_ROOTS and name not in CANDIDATE_PREFIX_REQUIRED_ROOTS and name not in CANDIDATE_IMPORTED_REQUIRED_ROOTS and name not in CANDIDATE_TYPED_ROOTS and name not in CANDIDATE_CONNECTED_ROOTS and name not in CONNECTED_IMPORTED_CANDIDATE_ROOTS and name not in CANDIDATE_LAYER_ROOTS and name not in MULTIPLE_IMPORTED_ROOTS and not name.startswith('TestNodeChainHostnameExecution')}
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
