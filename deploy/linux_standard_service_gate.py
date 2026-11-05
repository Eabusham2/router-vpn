"""Exact executable verdict inventory for the retained Linux standard service."""
from pathlib import Path
import re

PREFIX = 'TestLinuxStandardService'
MTU_PREFIX = 'TestLinuxStandardMTU'
CORE = {
    'TransferKeepsOriginalStartupBudget': ('earlier-startup', 'earlier-transfer', 'cancelled-startup'),
    'TransferResumesFinishedNativeCleanup': ('native-close', 'saved-close'),
    'TransferRequiresNativeAndDurableSettlement': ('reserved', 'entered', 'committed', 'aborted-before-native-finish', 'aborted-pending-write', 'settled-pending-write', 'aborted', 'settled'),
    'TransferSerializesOriginalRecovery': ('held-current', 'held-resolve', 'held-commit', 'concurrent-resolve'),
    'TransferRejectsUnadmittedReplay': ('history-full', 'cancelled-full-history', 'longer-inner-deadline', 'late-original-deadline'),
    'MTUPeerObservationExpiry': (),
    'OriginalPeerAndForeignPIDFD': (),
    'NetworkShippingDNSRepeatsRealOriginalExchange': (),
    'NetworkObservationCancellationPreservesOriginal': ('expired-before', 'cancelled-read', 'deadline-read', 'late-success', 'mixed-loss', 'replaced-owner', 'namespace-loss', 'lifetime-loss'),
    'NetworkProofArmsOnceAndLatchesABA': ('link', 'address', 'route', 'rule', 'overflow', 'reader-failure'),
    'NetworkInitializationAndProofFailuresStayRetained': ('initialization', 'missing-reader', 'second-proof', 'late-event', 'cancelled'),
    'NetworkRetirementPreservesUnjoinedAndReplacement': (),
    'RetainedPeerRejectsSameImageRoleReexec': (),
    'RetainsActualEngineAndAlwaysAcrossController': (),
    'StopRejectsDelayedStart': (),
    'DeadControllerKeepsOnConnectUntilSuccessorCreated': (),
    'JoinedHoldReleasesOnlyOriginalOnConnect': (),
    'ObservesActualEngineExitAfterRequest': ('on-connect', 'always'),
    'WatcherPreservesOnlyPureObservationExpiry': ('pure-expiry', 'mixed-reader-failure'),
    'OriginalChannelCancellationJoinsStartAndDNS': ('start', 'start-held', 'prove-dns'),
    'ShippingOwnershipGuardKeepsCallerLock': (),
    'StaleStopCannotCancelCurrentMonitor': (),
    'BootKeepsOriginalPartialCreator': (),
    'BootDispatchRequiresExplicitStandardSelection': ('unmarked-home-always', 'legacy-state', 'previous-standard', 'current-standard', 'corrupt-marker', 'corrupt-receipt', 'duplicate-marker'),
    'LegacyBootRetainsOriginalChildAcrossDeadline': (),
    'LegacyBootFailureCannotReportReady': (),
    'LegacyBootRejectsReplacementChildDescriptor': (),
    'AbsentEndpointRequiresIndependentNativeObservation': ('full', 'scoped-parent', 'listener', 'held-owner', 'saved-state', 'tun', 'native', 'lost-parent', 'late-socket', 'replaced-lock', 'replaced-directory', 'late-state', 'foreign-namespace', 'cancelled'),
    'ProtectionViewRejectsLiveForeignControllerAfterRevision': (),
    'PendingOffBlocksBootReassertUntilSave': (),
    'UIExplicitOffReleasesOriginalLiveOrBootCreator': ('joined', 'boot'),
    'UIOffRejectsChangedSourceOrNativeOwner': ('stale-profile', 'stale-selection', 'profile-path', 'foreign-table', 'foreign-state', 'replacement-controller', 'active'),
    'UIOffRetainsOriginalRetryAfterCancellationOrSaveFailure': ('cancel-after-native-delete', 'profile-save-failure'),
    'UIOwnedProtectionCannotBecomeSavedOnlyOff': (),
    'UIOffRejectsStaleCompletionAfterNativeRelease': ('profile', 'controller', 'local-adapter'),
    'UIParentAndServiceOwnershipPrecedence': ('parent-only', 'service-only', 'both', 'active-unowned', 'unknown-service', 'unknown-unowned-table', 'proved-empty'),
    'BootNeverAdoptsSavedOrExistingNativeOwner': ('current-boot', 'foreign-native', 'corrupt-state'),
    'BootWatcherRetriesOriginalCreatorWithoutClient': (),
    'BootWatcherCancellationJoinsOriginalAttempt': (),
    'BootNotificationUsesOriginalDeadline': (),
    'BootNotificationCancellationJoinsBlockedWrite': (),
    'IdleUpgradeRequiresJoinedNativeAbsence': ('idle', 'joined-off', 'closed-boot', 'unjoined', 'cleanup-pending', 'off-save-pending', 'engine-owner', 'always-owner', 'boot-owner', 'saved-state', 'tun-present', 'native-present', 'state-created-during-readback', 'foreign-namespace', 'cancelled'),
    'UpgradeAfterActualAlwaysToOffCleanup': (),
    'UpgradeJoinsActualPeerBeforeSuccess': ('complete', 'lost-reply', 'wrong-reply', 'listener-retained', 'cancelled'),
    'MonitorObservationExpiryKeepsProvedOwner': ('owner-lock', 'selection-lock', 'source-lock', 'probe-expiry', 'late-success', 'final-selection-lock', 'transaction-lock'),
    'MonitorMixedExpiryKeepsOriginalRetirement': ('mixed-probe', 'changed-source', 'replacement'),
    'MonitorActivationKeepsExactIntentAndDeadline': ('owner-lock', 'app-lock', 'derived-intent'),
    'MonitorBoundsApplicationMetadataLocks': ('observation', 'retained-watch', 'activation'),
    'MonitorObservesRealChildAfterRequestEnds': (),
    'MonitorRejectsLateFailureOverReplacement': (),
    'MonitorCancellationJoinsEnteredObservation': (),
    'MonitorRechecksUnderOriginalTransaction': (),
    'MonitorPreservesOnlyPureObservationExpiry': ('pure-expiry', 'mixed-runtime-failure'),
    'MonitorFailureRetainsRetryOwner': (),
    'MonitorSourceMutationRetiresOnlyOriginal': (),
    'MonitorRejectsUnprovedOrRepeatedActivation': ('dns', 'joined', 'unattempted', 'wrong-operation', 'foreign-runtime', 'foreign-tracker'),
    'MonitorShippingActivationOrderAndRefusal': ('active', 'monitor-refused', 'persistence-failed'),
}
NATIVE = {'NamespaceInstalledIdleUpgradeAndAlwaysRetention': ('off', 'on-connect', 'on-connect-mtu', 'on-connect-failure', 'on-connect-network-failure', 'on-connect-route-change', 'on-connect-pre-rpc-network-failure', 'always-off', 'always'), 'NamespaceNetworkEpochRejectsAwayAndBack': ('link', 'address', 'route', 'rule')}
STARTUP = {
    'RetirementRejectsUnboundFinalResult': ('absent', 'foreign-source', 'unknown-attempt', 'changed-deadline', 'foreign-tun', 'no-constructor', 'startup-extension'),
    'RetirementRetriesOriginalLiveChild': (),
    'RetirementBoundsOutstandingAttempts': ('unsettled', 'settled-failures', 'complete-retained', 'foreign-failure'),
    'RetirementRequiresOriginalResultAndRouting': ('complete', 'nonzero', 'signal', 'foreign-completion', 'routing-route', 'routing-rule', 'cancelled'),
    'ControllerEpochObservationCancellationPreservesOriginal': ('expired-before', 'cancelled-read', 'deadline-read', 'late-success', 'mixed-loss', 'replaced-source', 'held-app-lock', 'lifetime-loss'),
    'ControllerEpochStartupCancellationStillLatches': ('bind', 'begin', 'final-admit'),
    'ControllerEpochUsesOriginalWireAndChild': (),
    'ControllerEpochRejectsChangedStartup': ('pre-rpc-aba', 'during-rpc-aba', 'late-end', 'session', 'configuration', 'mode', 'deadline', 'expired', 'ready-source', 'missing', 'source-replaced', 'profile-replaced', 'operation-replaced', 'peer-replaced', 'cancelled'),
    'ControllerEpochCloseRetryPrecedesStop': (),
    'ControllerEpochPreparationPrecedesSources': ('before-source-event', 'source-failure', 'partial-open'),
    'ControllerEpochWireRejectsUnrelatedLedger': ('current', 'stop', 'failed-start', 'missing-start', 'foreign-session', 'wire-deadline'),
    'StartupPreparationFailureKeepsRetry': ('preparation-error', 'remote-error', 'replacement-workspace', 'adopted-owner'),
    'StartupVerificationKeepsOriginalSources': ('unchanged', 'catalog', 'image', 'library', 'in-place', 'foreign-result', 'cancelled'),
    'StartupUsesOriginalChildLedger': ('complete', 'wrong-source', 'wrong-mtu', 'malformed-ledger', 'late-network', 'cancelled'),
    'StartupExitObserverKeepsOriginalOwner': ('original-exit', 'cancelled', 'replacement'),
    'StartupNativeSOCKSDNSFrames': ('selected', 'foreign-resolver', 'foreign-auth'),
    'StartupInstalledRequestHasNoStockChild': ('installed-request', 'noninstalled-stock-required'),
    'StartupRequiresVerifiedRuntime': ('absent', 'corrupt'),
    'StartupRetainsRejectedPreparation': ('configuration', 'network', 'workspace-name', 'workspace-descriptor', 'preparation-error'),
    'StartupStockGraphs': tuple(protocol+'/'+policy for protocol in ('wireguard', 'socks5', 'http-connect', 'https-connect', 'shadowsocks', 'hysteria2') for policy in ('default', 'fixed', 'ipv6-off')),
}
CLEANUP = {
    'TestCleanupCompleteRetirementFitsOriginalFD10': ('large-attributes', 'many-objects'),
    'TestCleanupOperationWorkerStopRetainsUnjoinedNativeCall': ('held', 'within-budget'),
    'TestCleanupOperationWorkerObservationExpiryRetainsOriginal': ('command', 'cleanup'),
    'TestCleanupOperationWorkerObservationKeepsMixedFailure': ('expired', 'wrapped', 'identity', 'mixed', 'mixed-empty'),
    'TestCleanupOperationCommandRequiresBothOriginalAcknowledgements': (),
    'TestCleanupOperationWorkerCancellationJoinsOriginalMutation': (),
    'TestCleanupOperationExpiredCommandConsumesWithoutNativeMutation': (),
    'TestCleanupOperationPendingNativeEvidenceRetainsStopRetry': (),
    'TestCleanupOperationReportRejectsChangedNativeEvidence': ('bytes', 'current', 'deadline', 'mtu', 'revision', 'binding', 'unjoined'),
    'TestCleanupOperationPartialReadyCompletesOnlyOriginalEmptyBinding': (),
    'TestCleanupOperationCancelledAdmissionCannotConstructNativeReader': (),
    'TestCleanupOperationUnsubmittedAbortCannotHidePublishedWork': ('reserved', 'command-record', 'published', 'torn'),
    'TestCleanupOperationExplicitRetryPreservesWorkDeadlineAndReader': (),
    'TestCleanupOperationNoReaderKeepsActualOriginalRetirement': (),
    'TestCleanupOperationRawHistoryAndPartialReaders': (),
    'TestCleanupOperationRejectedAdmissionCannotBeRepaired': (),
    'TestCleanupOperationRejectsCorruptOrSubstitutedEvidence': ('torn-header', 'torn-payload', 'nonzero-tail', 'wrong-key', 'wrong-role', 'wrong-reader', 'oversized-ready', 'oversized-retirement', 'missing-binding', 'parent-writer'),
    'TestCleanupOperationCapacityAndOriginalKey': (),
    'TestCleanupOperationCancellationHasIndependentExpiredWorkSlot': (),
    'TestCleanupOperationBoundedLocksRetainOriginal': ('work', 'cancel', 'close'),
    'TestCleanupOperationCaptureRetainsRejectedDescriptors': ('wrong-inode', 'wrong-device', 'wrong-size', 'wrong-layout', 'wrong-capture', 'unsealed', 'replacement'),
    'TestCleanupOperationInheritedFD11': ('original', 'substituted'),
    'TestCleanupOperationRejectsReplayedPageHeader': (),
    'TestCleanupOperationProcessLockSeparatesCancellation': (),
    'TestCleanupRejectsOverlongSelfBudgetBeforeNativeCall': (),
    'TestCleanupOriginalDescriptorAndStableFrames': ('complete', 'wrong-source', 'torn', 'foreign-object', 'closed', 'replaced-descriptor', 'missing-result'),
    'TestCleanupRejectsMutableSizeAndUnsealedFiles': (),
    'TestCleanupOriginalAttemptsRetainOwnerAndDeadlines': ('expired-startup', 'failed-native', 'expired-request', 'wrong-source', 'torn-request'),
}


MTU = {
    'ReportKeepsExactRawHistory': ('unjoined', 'pending', 'different-digest', 'missing-retirement', 'changed-current-MTU', 'retirement-lost-address', 'retirement-wrong-incarnation'),
    'ControllerBindsOnlyOriginalAdmission': (),
    'ReportRetainsPartialFailedConstructor': (),
    'RejectionCannotAbandonAnotherAdmission': (),
    'OwnerDoesNotWaitPastCallerForLaunchLock': ('capture', 'change', 'rollback', 'dial', 'constructor'),
    'ExitCapturedBeforeStartIsDeepFrozen': (),
    'UsesActivationAfterActualConnectCompletion': (),
    'RecoveryCannotCrossOriginalIntents': (),
    'RetirementResponseDoesNotClaimSettlement': (),
    'EvidenceChunkKeepsRawBytesWithinPacket': (),
    'RetiredEvidencePreservesExplicitStop': ('status', 'cancel', 'evidence', 'unsubmitted', 'closed-observer', 'foreign-peer', 'foreign-session', 'changed-reservation', 'pending', 'unjoined', 'unvalidated', 'changed-digest', 'healthy-ack', 'cleanup-retry', 'new-candidate', 'ordinary-observation'),
    'CacheOriginalPathTTLAndBound': ('fresh', 'expired', 'future'),
    'CacheCanceledSaveRollsBackOnlyOwnBytes': ('restore-original', 'retain-newer'),
    'CacheDeadlineAndDirectoryReplacement': (),
    'UIPublicProgressAndCancelDuringNativeMutation': ('original', 'foreign-request', 'changed-profile', 'replacement-activation', 'replacement-during-status'),
    'UIStopJoinsOriginalAutomaticAdmission': ('join', 'deadline', 'replacement-owner'),
    'UILateResumeCannotRecreateStoppedOwner': ('stopped', 'replacement-ui'),
    'SocketCloseDoesNotWaitForLaunchGate': (),
    'CapacityPreservesWholeRetestAndRollback': ('fresh', 'whole-test', 'rollback-reserve', 'unsent-history', 'exhausted', 'full', 'sequence-overflow'),
}
MTU_NATIVE = {
    'StopRejectsHistoryBeforeGuardRelease': ('missing', 'changed-reservation', 'torn-page'),
    'StopHandsPendingCallToFD10': ('initial', 'retry-closed-observer'),
    'StopRetainsActualJoinedHistory': ('joined', 'missing', 'changed-reservation', 'torn-page', 'replacement-session', 'expired'),
    'ControllerStopSignalsBeforeHistory': ('joined-history', 'torn-cached-history'),
    'OrdinaryObservationUsesOriginalPhase': ('current', 'observe', 'dns-current'),
    'UnsubmittedRecoveryFencesDelayedCommand': ('cancel-before-begin', 'reserved-unsent', 'uncertain-unsent', 'uncertain-published'),
}
# These package gates are part of service MTU acceptance, not renamed client
# tests. Each is executed and checked before the captured service binary runs.
AUXILIARY = {
    'standard-node-journal': ('./internal/linuxprotection', {
        'TestLinuxStandardNodeTransferJournalKeepsOriginalIntent': ('original', 'changed-deadline', 'changed-source', 'changed-destination', 'new-idle-request', 'active-replacement'),
    }),
    'retirement-bound': ('./internal/desktopnetwork', {
        'TestDesktopNetworkRetirementKeepsSeparateBound': ('complete-history', 'oversized-writer', 'oversized-parser', 'ready-stays-bounded'),
    }),
    'routing-history': ('./internal/desktopnetwork', {
        'TestLinuxRoutingHistoryRetiresAllActualConstructors': ('complete', 'physical-change', 'missing-reader', 'missing-address', 'missing-object', 'missing-partial', 'changed-constructor', 'old-link-remains', 'old-object-remains', 'unjoined', 'cancelled'),
    }),
    'public-dns': ('./internal/dnsmeasure', {
        'TestPublicAddressExtractionKeepsOnlyExactQuestionChain': ('different-question', 'private-target', 'truncated', 'trailing', 'wrong-type'),
        'TestPublicAddressExtractionBoundsAndDeduplicates': (),
    }),
}
AUXILIARY_TESTS = {
    'internal/linuxprotection/standard_node_transfer_test.go': 'standard-node-journal',
    'internal/desktopnetwork/desktop_network_retirement_limit_test.go': 'retirement-bound',
    'internal/desktopnetwork/routing_history_retirement_linux_test.go': 'routing-history',
    'internal/dnsmeasure/addresses_test.go': 'public-dns',
}


def check_cleanup_verdict(output):
    if '--- SKIP:' in output or '--- FAIL:' in output:
        raise ValueError('Original cleanup descriptor gate skipped or failed')
    passed = re.findall(r'^\s*--- PASS: (\S+) \([0-9]+(?:\.[0-9]+)?s\)$', output, re.M)
    for parent, leaves in CLEANUP.items():
        for name in (parent, *(parent+'/'+leaf for leaf in leaves)):
            if passed.count(name) != 1:
                raise ValueError('Cleanup gate omitted or duplicated exact executable verdict: '+name)


GROUPS = {'core': CORE, 'startup': STARTUP, 'native': NATIVE, 'mtu': MTU, 'mtu-native': MTU_NATIVE}
GROUP_PREFIXES = {group: (MTU_PREFIX if group.startswith('mtu') else PREFIX) for group in GROUPS}
SOURCE = {'cmd/client/linux_standard_service_' + name for name in (
    'peer_linux.go', 'protocol_linux.go', 'runtime_linux.go', 'client_linux.go', 'dns_linux.go',
    'boot_linux.go', 'other.go', 'upgrade_linux.go', 'peer_native_test.go', 'runtime_native_test.go',
    'channel_native_test.go', 'client_test.go', 'boot_test.go', 'upgrade_native_test.go', 'namespace_test.go', 'route_native_test.go',
    'monitor_linux.go','monitor_linux_test.go','boot_retry_linux.go','boot_retry_linux_test.go','protection_linux.go','protection_native_test.go','absence_linux.go','absence_linux_test.go','legacy_boot_linux.go','legacy_boot_test.go','network_linux.go','network_native_test.go','network_namespace_test.go','startup_native_test.go','startup_config_test.go','startup_namespace_test.go','controller_epoch_linux.go','controller_epoch_native_test.go','observation_context_native_test.go','watcher_context_native_test.go','retirement_native_test.go')}
SOURCE.update({'internal/standardengine/operation.go', 'internal/standardengine/operation_linux.go', 'internal/standardengine/operation_linux_test.go', 'internal/standardengine/protocol.go', 'internal/standardengine/protocol_test.go', 'mobile/desktop/standard_owned_linux.go.tmpl', 'internal/standardengine/cleanup_linux.go', 'internal/standardengine/cleanup_loop_linux.go', 'internal/standardengine/cleanup_linux_test.go', 'internal/standardengine/cleanup_loop_linux_test.go', 'internal/desktopnetwork/desktop_network_retirement.go', 'mobile/desktop/standard_cleanup_linux.go.tmpl', 'cmd/client/linux_standard_engine_linux.go', 'cmd/client/linux_standard_engine_retirement_linux.go', 'cmd/client/legacy_standard_exit_preparation_linux.go', 'modes/kill-switch.py', 'modes/profile_id.py', 'cmd/client/profile_protection_standard_service_linux.go', 'cmd/client/profile_protection_standard_service_native_test.go', 'cmd/client/profile_protection_platform_linux.go'})
SOURCE.add('cmd/client/linux_standard_service_mtu_peer_native_test.go')
SOURCE.update({'internal/desktopnetwork/desktop_network_retirement_limit_test.go', 'internal/standardengine/cleanup_retirement_bound_linux_test.go'})
SOURCE.add('internal/standardengine/worker_stop_linux_test.go')
RUNNERS = ('test_standard_worker_stop.py', 'linux_standard_service_gate.py', 'test_linux_standard_service_runner.py', 'linux_standard_service_bundle.py', 'test_linux_standard_service_bundle.py')
SOURCE.update({'internal/standardengine/operation_command_linux.go', 'internal/standardengine/operation_command_linux_test.go',
               'internal/standardengine/worker_linux.go', 'mobile/desktop/standard_mtu_linux.go.tmpl',
               'mobile/desktop/standard_mtu_linux_test.go.tmpl'})

SOURCE.update({'cmd/client/linux_standard_service_mtu_' + name for name in (
    'linux.go', 'stop_linux.go', 'stop_native_test.go', 'protocol_linux.go', 'client_linux.go', 'client_linux_test.go',
    'controller_epoch_linux.go', 'controller_epoch_linux_test.go', 'probe_linux.go',
    'dns_linux.go', 'recovery_linux_test.go', 'admission_native_test.go', 'namespace_native_test.go',
    'cache_linux.go', 'cache_linux_test.go', 'capacity_linux.go', 'capacity_linux_test.go', 'ui_linux.go', 'ui_linux_test.go', 'ui_other.go')})
SOURCE.update({
    'cmd/client/standard_exit_platform_routes.go', 'cmd/client/standard_exit_dns_exchange.go',
    'cmd/client/mtu_retest.go', 'cmd/client/mtu_automatic.go', 'cmd/client/mtu_view_operation.go',
    'internal/desktopnetwork/desktop_network_transition.go',
    'internal/desktopnetwork/routing_history_retirement_linux.go',
    'internal/desktopnetwork/routing_history_retirement_linux_test.go',
    'internal/dnsmeasure/addresses.go', 'internal/dnsmeasure/addresses_test.go',
    'internal/dnsmeasure/wire.go', 'internal/dnsmeasure/response.go',
    'internal/mobilemtu/controller.go', 'internal/mobilemtu/context.go', 'internal/mobilemtu/external.go',
    'internal/mobilemtu/async.go', 'internal/mobilemtu/cache.go', 'internal/mobilemtu/policy.go',
    'internal/mobilemultihop/external_public_proof.go',
    'internal/hopmeasure/public.go', 'internal/hopmeasure/measure.go', 'internal/hopmeasure/activity.go',
})
SOURCE.update({'cmd/client/linux_standard_service_transfer_' + name for name in (
    'client_linux.go', 'linux_test.go', 'namespace_native_test.go', 'peer_native_test.go', 'protocol_linux.go', 'service_linux.go')})
SOURCE.update({'internal/linuxprotection/standard_node_transfer.go', 'internal/linuxprotection/standard_node_transfer_test.go',
    'internal/linuxprotection/journal_record.go', 'internal/mobiletor/desktop_standard_node_transfer_linux.go',
    'internal/mobiletor/desktop_standard_node_transfer_linux_test.go', 'internal/mobiletor/desktop_standard_node_transfer_native_linux_test.go',
    'internal/mobiletor/desktop_socket_linux_node_baseline.go', 'cmd/client/desktop_node_connection_linux.go',
    'cmd/client/desktop_node_connection_linux_tun_native_test.go', 'cmd/client/desktop_node_host_linux.go',
    'cmd/client/desktop_node_host_linux_tun_native_test.go', 'cmd/client/desktop_node_linux_journal.go',
    'cmd/client/desktop_node_linux_transaction.go', 'cmd/client/desktop_node_linux_transaction_retire.go',
    'cmd/client/desktop_node_session_linux.go', 'cmd/client/desktop_node_host_linux_transition.go', 'cmd/client/legacy_standard_exit_protection_linux.go'})
NATIVE_MTU_SOURCES = {'cmd/client/linux_standard_service_mtu_stop_native_test.go', 'cmd/client/linux_standard_service_mtu_admission_native_test.go',
                      'cmd/client/linux_standard_service_mtu_namespace_native_test.go'}


def case_names(group):
    prefix = GROUP_PREFIXES[group]
    return tuple(name for parent, leaves in GROUPS[group].items()
                 for name in (prefix + parent, *(prefix + parent + '/' + leaf for leaf in leaves)))


def auxiliary_pattern(group):
    return '^(' + '|'.join(AUXILIARY[group][1]) + ')$'


def check_auxiliary_verdict(output, group):
    cases = AUXILIARY[group][1]
    expected = tuple(name for parent, leaves in cases.items()
                     for name in (parent, *(parent + '/' + leaf for leaf in leaves)))
    _check_exact_verdict(output, expected, 'Service MTU ' + group, strict=True)


def _check_exact_verdict(output, expected, label, *, strict=False):
    if '--- SKIP:' in output or '--- FAIL:' in output:
        raise ValueError(label + ' skipped or failed')
    passed = re.findall(r'^\s*--- PASS: (\S+) \([0-9]+(?:\.[0-9]+)?s\)$', output, re.M)
    for name in expected:
        if passed.count(name) != 1:
            raise ValueError(label + ' omitted or duplicated exact executable verdict: ' + name)
    if strict and set(passed) != set(expected):
        raise ValueError(label + ' emitted an unregistered executable verdict: ' + repr(sorted(set(passed) - set(expected))))


def pattern(group):
    return '^' + GROUP_PREFIXES[group] + '(' + '|'.join(GROUPS[group]) + ')$'


def validate_inventory(root):
    root = Path(root)
    missing = [name for name in SOURCE if not (root / name).is_file() or (root / name).is_symlink()]
    if missing:
        raise ValueError('Standard service original source inventory is incomplete: ' + ', '.join(sorted(missing)))
    actual_mtu_sources = {path.relative_to(root).as_posix()
                          for path in (root / 'cmd/client').glob('linux_standard_service_*.go') if ('_mtu_' in path.name or '_transfer_' in path.name)}
    if actual_mtu_sources - SOURCE:
        raise ValueError('Service MTU source was not bound to the mandatory inventory: ' +
                         repr(sorted(actual_mtu_sources - SOURCE)))
    actual = []
    for path in (root / 'cmd/client').glob('*standard_service*test.go'):
        actual.extend(re.findall(r'^func (TestLinuxStandard(?:Service|MTU)\w+)\(t \*testing\.T\)', path.read_text(), re.M))
    actual = [name for name in actual if not name.endswith('Fixture') and name != 'TestLinuxStandardServiceMonitorChild']
    expected = [GROUP_PREFIXES[group] + name for group, cases in GROUPS.items() for name in cases]
    if sorted(actual) != sorted(expected):
        raise ValueError('Standard service runner omitted, renamed or duplicated a shipping case: ' + repr(sorted(set(actual) ^ set(expected))))

    for name in NATIVE_MTU_SOURCES:
        if not (root / name).read_text().startswith('//go:build linux && routervpn_controller_privileged\n'):
            raise ValueError('Native service MTU case lost its required privileged build tag: ' + name)
    for name, group in AUXILIARY_TESTS.items():
        actual = re.findall(r'^func (Test\w+)\(t \*testing\.T\)', (root / name).read_text(), re.M)
        if sorted(actual) != sorted(AUXILIARY[group][1]):
            raise ValueError('Service MTU package gate omitted or renamed an executable case: ' + name)


def check_verdict(output, group):
    _check_exact_verdict(output, case_names(group), 'Standard service ' + group,
                         strict=group.startswith('mtu'))
