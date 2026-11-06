"""Exact executable verdict inventory for the retained Linux standard service."""
from pathlib import Path
import re

PREFIX = 'TestLinuxStandardService'
MTU_PREFIX = 'TestLinuxStandardMTU'
CORE = {
    'BootBootstrapUnsentDestination': ('legacy', 'generation', 'missing-receipt', 'foreign-socket', 'missing-image', 'mixed-error', 'cancelled', 'wrong-network', 'wrong-operation', 'wrong-syscall', 'attempted', 'retained-peer'),
    'BootBootstrapParentJoin': ('cancelled-no-next-lookup', 'held-cleanup-retry', 'replacement', 'consumed-transfer', 'pending-failure-retry', 'consumed-detach-retry'),
    'BootTransferRetainsExactSource': ('original', 'replacement-boot', 'engine-not-joined', 'cleanup-pending', 'wrong-session', 'peer-close-pending', 'peer-closed'),
    'BootTransferUnsentAndCancelledCleanup': ('unsent', 'cancelled', 'replacement'),
    'BootTransferSourceKindsRemainDistinct': (),
    'ImageEnvelopeKeepsNativeOrdering': ('numeric-roundtrip', 'lexical-reorder', 'duplicate', 'mapped', 'cross-scope'),
    'ImageCleanupKeepsOriginalClock': ('lazy', 'once', 'expired-observation', 'same-cross-process-clock', 'outer-clamp'),
    'ImageControlKeepsExactDescriptors': ('three', 'ordinary-one'),
    'ImageSourceLeasePinsOriginalInode': (),
    'ImageControlKeepsOriginalSequence': (),
    'ImagePromotionRejectsExtraCode': ('exact', 'extra-tree', 'extra-helper', 'private-preserved'),
    'ImageReservationLookupKeepsOriginalPeer': ('lost-reply', 'foreign-peer', 'deadline', 'generation', 'scope', 'expired-observation'),
    'ImageSuccessorWaitKeepsOriginalConnect': ('actual-listener', 'source-disappearance', 'mixed-loss', 'captured-peer', 'cancelled'),
    "StartKeepsOriginalAdmission": ("application", "prior-owner", "post-reply"),
    'SpeedLabRestoreRejectsChangedSource': ('original', 'profile', 'exit', 'selection', 'intent', 'captured-profile', 'mtu', 'held-app', 'cancelled'),
    'SpeedLabPolicyCapture': ('original', 'profile', 'exit', 'hopped', 'late', 'duplicate', 'cancelled'),
    'SpeedLabHeldCaptureKeepsCaller': ('capture', 'current', 'dial', 'options'),
    'SpeedLabRestoreKeepsPolicySelection': (),
    'SpeedLabSessionKeepsCaller': ('held', 'cancelled', 'missing', 'replaced'),
    'ReverseRetainsPreparedOriginal': ('commit-start', 'abort', 'lost-prepare', 'wrong-peer', 'changed-intent', 'held-gate', 'held-app', 'held-owner', 'pending-release', 'foreign-scope', 'late-start', 'source-still-live', 'pending-native'),
    'ReverseAbortFencesUnsentPrepare': (),
    'ReverseClientKeepsOriginalPeer': ('original', 'lost-ack-retry', 'foreign-peer', 'changed-intent', 'transport-expiry', 'mixed-failure', 'late-response', 'replacement'),
    'ReverseStopKeepsBoundedOwner': (),
    'ReverseCaptureKeepsBoundedIntent': (),
    'GenerationRejectsChangedSource': ('current', 'legacy', 'bad-code', 'undeclared', 'linked-image', 'unsafe-mode', 'changed-manifest', 'foreign-lock', 'bad-activation', 'activation-link', 'activation-trailing', 'expired'),
    'GenerationExpiryKeepsOriginalLease': (),
    'GenerationBusyLeaseCannotAdopt': (),
    'GenerationRetainedPeerSocketPair': (),
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
NATIVE = {'NamespaceInstalledIdleUpgradeAndAlwaysRetention': ('off', 'on-connect', 'on-connect-generation', 'on-connect-mtu', 'on-connect-public', 'on-connect-public-restore', 'on-connect-failure', 'on-connect-network-failure', 'on-connect-route-change', 'on-connect-pre-rpc-network-failure', 'always-off', 'always'), 'NamespaceNetworkEpochRejectsAwayAndBack': ('link', 'address', 'route', 'rule')}
NATIVE.update({'GenerationRetainedPeerSurvivesActivation': (), 'GenerationListenerPreventsAbsence': ('present', 'created-during-readback')})
STARTUP = {
    'BootBootstrapDeadPeerCleanupClock': ('live','retired','cancelled-observer','expired-retirement','foreign-pidfd'),
    'BootBootstrapServiceKeepsOriginalAdmission': ('no-boot','image-reserved','image-frozen','image-settled','failed-boot','pending-transfer','cross-scope','cancel-before-admission','held-gate','cleanup-tombstone'),
    'BootBootstrapPeerCleanupRetainsAcknowledgedClose': ('cancel-before-close','partial-close'),
    'BootResolverCaptureUsesOnlyOriginalConfiguredUpstreams': (),
    'BootResolverCaptureRejectsChangedSources': ('contents','same-bytes-replacement','link','permissions','stub-contents'),
    'BootResolverRejectsUnownedStubAndImplicitFallback': (),
    'BootTransferRetriesReleasedOriginal': ('boot', 'active'),
    'BootTransferAdmissionKeepsOriginalPeer': ('no-boot', 'failed-boot', 'live-engine', 'pending-transfer', 'history-full', 'cancelled'),
    'BootTransferRetiredIntentRejectsReplay': ('original-result', 'renewed-deadline', 'other-session', 'other-selection', 'other-kind', 'late-reserve'),
    'PublicHTTPSPeer': ('latency', 'download', 'upload', 'foreign-auth', 'foreign-destination', 'tls-hostname'),
    'SpeedLabCapturesOriginalService': ('original', 'command', 'profile', 'dns', 'activation', 'pending', 'run', 'sockets', 'mtu', 'session', 'exit'),
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
    'TestCleanupOperationIdleOriginalParent': ('live', 'lost', 'expired', 'mixed', 'held-command-lock'),
    'TestCleanupSharedRunWorkerClosureKeepsOriginalDeadline': (),
    'TestCleanupSharedRunUnsubmittedRequiresBothOriginalObservers': (),
    'TestCleanupSharedRunWorkerClosesWithoutMutation': (),
    'TestCleanupSharedRunAdmissionHistoryIsBounded': (),
    'TestCleanupSharedRunClockIndependentAndSingle': (),
    'TestCleanupSharedRunClockCancellationAndHeldLock': (),
    'TestCleanupSharedRunClosureAndStaleClock': (),
    'TestCleanupSharedRunBindsCommandAndRestore': (),
    'TestCleanupSharedRunShortAdmissionAndOriginalBounds': (),
    'TestCleanupSharedRunPreviousLayoutRefused': (),
    'TestCleanupSharedRunClockInheritedProcess': (),
    'TestCleanupSharedRunSettlementKeepsClock': (),
    'TestCleanupSharedRunWorkerOneClockAndOriginalRestore': (),
    'TestCleanupSharedRunWorkerExpiredWorkRejectsConstructor': (),
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
    'RunPublicCancelKeepsCommit': ('before-commit', 'committed', 'expired-observation'),
    'RunOwnerUsesOriginalWireAndChild': ('original', 'lost-begin-ack', 'repeat-run', 'cancel-during-finalizer'),
    'RunServiceKeepsOriginalClock': ('original', 'changed-reader', 'changed-MTU', 'expired-admission', 'one-clock', 'cleanup-only', 'child-closure', 'lost-begin-fence', 'failed-admission-recovery'),
    'RunProviderRetainsOriginalAuthority': ('held-launch-lock', 'native-clock-first', 'foreign-token', 'changed-clock', 'cancelled-finalizer', 'expired-while-closing', 'unjoined-close', 'pending-observer'),
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
    'boot-bootstrap-context': ('./cmd/client', {
      'TestBootBootstrapFramesRejectCrossScope': ('start','image-prepare','mtu-start','reverse-prepare','transfer-reserve','protection-status'),
      'TestBootBootstrapOriginalParentAdmissionIsBounded': ('capture','shipping-prepare','retirement'),
      'TestBootBootstrapParentGenerationStillRejectsReplacement': (),
    }),
    'boot-bootstrap-dns': ('./internal/dnsmeasure', {
      'TestTransportBootstrapExactQuestionAndFamilies': (),
      'TestTransportBootstrapRejectsForeignOrMalformedAnswer': ('id','question','truncated','nxdomain','trailing','short-address','foreign-owner','mapped','too-many'),
      'TestTransportBootstrapBoundedAliasChain': (),
      'TestTransportBootstrapDoesNotExpandSearchNames': (),
    }),
    'speedlab-caller': ('./cmd/client', {
        'TestSpeedLabServiceCallerContextCapture': ('identity', 'expected', 'restore-plan'),
        'TestSpeedLabServiceObserverJoinsCaller': ('request-cancel', 'explicit-stop'),
        'TestSpeedLabServiceCallerContextAppGate': ('snapshot', 'temporary-admission', 'owner', 'expected-with-profiles', 'current-handler', 'public-validation'),
    }),
    'speedlab-transport': ('./cmd/client', {
        'TestSpeedLabCapturedTunnelUsesPublicTLSAndActualTransfer': (),
        'TestSpeedLabCapturedTunnelRejectsForeignTLSAndRedirect': ('foreign-certificate', 'redirect'),
        'TestSpeedLabCapturedTunnelCancellationJoinsLateDial': ('request-cancel', 'request-deadline', 'owner-cancel', 'late-connection', 'refused-no-fallback', 'missing-dialer'),
        'TestSpeedLabMeasurementConstructorsUseCapturedTunnel': (),
        'TestSpeedLabCapturedTunnelRejectsLateHTTPResponse': (),
        'TestSpeedLabCapturedTunnelSeparatesAdmissionAndSocketLifetime': ('request', 'factory'),
    }),
    'node-standard-journal': ('./internal/linuxprotection', {
        'TestLinuxNodeStandardTransferJournalRequiresOriginalClosedSource': ('original', 'engine-live', 'foreign-source', 'foreign-profile', 'foreign-config', 'foreign-request', 'no-transfer', 'candidate-widened'),
        'TestLinuxNodeStandardTransferJournalKeepsOutcomeAndIntent': ('commit', 'abort', 'changed-deadline', 'changed-destination', 'dropped-intent', 'foreign-outcome'),
    }),
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
    'cmd/client/linux_standard_service_boot_bootstrap_test.go': 'boot-bootstrap-context',
    'internal/dnsmeasure/transport_bootstrap_test.go': 'boot-bootstrap-dns',
    'cmd/client/speed_lab_service_caller_linux_test.go': 'speedlab-caller',
    'cmd/client/speed_lab_tunnel_transport_test.go': 'speedlab-transport',
    'internal/linuxprotection/node_standard_transfer_test.go': 'node-standard-journal',
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
# Each installed transaction keeps the existing per-process watchdog. Repeated
# upgrades exercise two transactions in one private namespace, not a longer
# timeout shared with all the other installed cases.
IMAGE_NATIVE = {
    'original': 'Original',
    'abort-prepared': 'AbortPrepared',
    'abort-promoted': 'AbortPromoted',
    'lost-freeze-reply': 'LostFreezeReply',
    'lost-commit-reply': 'LostCommitReply',
    'lost-ready-reply': 'LostReadyReply',
    'changed-sequence': 'ChangedSequence',
    'expired-prepare': 'ExpiredPrepare',
    'repeat-after-success': 'RepeatAfterSuccess',
    'repeat-after-abort': 'RepeatAfterAbort',
    'guard-lost-after-ready': 'GuardLostAfterReady',
}
GROUPS.update({'image-native-' + scenario: {'NamespaceImageUpgrade' + suffix: ()}
               for scenario, suffix in IMAGE_NATIVE.items()})
GROUP_PREFIXES = {group: (MTU_PREFIX if group.startswith('mtu') else PREFIX) for group in GROUPS}
SOURCE = {'cmd/client/linux_standard_service_' + name for name in (
    'peer_linux.go', 'protocol_linux.go', 'runtime_linux.go', 'client_linux.go', 'dns_linux.go',
    'boot_linux.go', 'other.go', 'upgrade_linux.go', 'generation_linux.go', 'generation_native_test.go', 'peer_native_test.go', 'runtime_native_test.go',
    'channel_native_test.go', 'client_test.go', 'boot_test.go', 'upgrade_native_test.go', 'namespace_test.go', 'route_native_test.go',
    'monitor_linux.go','monitor_linux_test.go','boot_retry_linux.go','boot_retry_linux_test.go','protection_linux.go','protection_native_test.go','absence_linux.go','absence_linux_test.go','legacy_boot_linux.go','legacy_boot_test.go','network_linux.go','network_native_test.go','network_namespace_test.go','startup_native_test.go','startup_config_test.go','startup_namespace_test.go','controller_epoch_linux.go','controller_epoch_native_test.go','observation_context_native_test.go','watcher_context_native_test.go','retirement_native_test.go')}
SOURCE.update({'internal/standardengine/operation.go', 'internal/standardengine/operation_linux.go', 'internal/standardengine/operation_linux_test.go', 'internal/standardengine/protocol.go', 'internal/standardengine/protocol_test.go', 'mobile/desktop/standard_owned_linux.go.tmpl', 'internal/standardengine/cleanup_linux.go', 'internal/standardengine/cleanup_loop_linux.go', 'internal/standardengine/cleanup_linux_test.go', 'internal/standardengine/cleanup_loop_linux_test.go', 'internal/desktopnetwork/desktop_network_retirement.go', 'mobile/desktop/standard_cleanup_linux.go.tmpl', 'cmd/client/linux_standard_engine_linux.go', 'cmd/client/linux_standard_engine_retirement_linux.go', 'cmd/client/legacy_standard_exit_preparation_linux.go', 'modes/kill-switch.py', 'modes/profile_id.py', 'cmd/client/profile_protection_standard_service_linux.go', 'cmd/client/profile_protection_standard_service_native_test.go', 'cmd/client/profile_protection_platform_linux.go'})
SOURCE.add('cmd/client/linux_standard_service_mtu_peer_native_test.go')
SOURCE.add('cmd/client/linux_standard_service_start_admission_native_test.go')
SOURCE.update({'cmd/client/linux_standard_service_image_' + name for name in (
    'upgrade_protocol_linux.go', 'upgrade_linux.go', 'dispatch_linux.go',
    'channel_linux.go', 'successor_linux.go', 'coordinator_linux.go', 'upgrade_test.go',
    'upgrade_namespace_test.go')})
SOURCE.update({'internal/desktopnetwork/desktop_network_retirement_limit_test.go', 'internal/standardengine/cleanup_retirement_bound_linux_test.go'})
SOURCE.add('internal/standardengine/worker_stop_linux_test.go')
RUNNERS = ('test_standard_run_clock.py', 'test_standard_worker_stop.py', 'linux_standard_service_gate.py', 'test_linux_standard_service_runner.py', 'linux_standard_service_bundle.py', 'test_linux_standard_service_bundle.py')
SOURCE.update({'internal/standardengine/operation_command_linux.go', 'internal/standardengine/operation_command_linux_test.go',
               'internal/standardengine/worker_linux.go', 'mobile/desktop/standard_mtu_linux.go.tmpl',
               'mobile/desktop/standard_mtu_linux_test.go.tmpl'})

SOURCE.update({'cmd/client/linux_standard_service_mtu_' + name for name in (
    'linux.go', 'run_linux.go', 'run_client_linux.go', 'run_native_test.go', 'stop_linux.go', 'stop_native_test.go', 'protocol_linux.go', 'client_linux.go', 'client_linux_test.go',
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
SOURCE.update({'cmd/client/' + name for name in (
    'linux_standard_service_speed_lab_linux.go', 'linux_standard_service_speed_lab_linux_test.go',
    'linux_standard_service_speed_lab_native_test.go', 'linux_standard_service_speed_lab_other.go',
    'speed_lab_standard_service.go', 'speed_lab.go', 'speed_lab_paths.go', 'speed_lab_expectation.go',
    'speed_lab_transaction.go', 'speed_lab_measure.go', 'speed_lab_tunnel_transport.go',
    'speed_lab_tunnel_transport_test.go', 'desktop_external_path.go', 'speed_lab_service_caller_linux_test.go',
    'speed_lab_path_context.go', 'connection_launch_order_test.go',
)})
SOURCE.update({'client/linux/routervpn-speed-lab-path-v19.inc', 'deploy/test_desktop_speed_lab_forms.py'})
SOURCE.update({'cmd/client/linux_standard_service_reverse_' + name for name in (
    'linux.go', 'native_test.go', 'client_linux.go', 'client_native_test.go', 'protocol_linux.go')})
SOURCE.update({'cmd/client/standard_exit_reverse.go', 'cmd/client/standard_exit_reverse_other.go',
    'internal/mobiletor/desktop_standard_node_reverse_transfer_linux.go',
    'internal/mobiletor/desktop_standard_node_reverse_transfer_linux_test.go',
    'internal/mobiletor/desktop_standard_node_reverse_transfer_native_linux_test.go',
    'internal/linuxprotection/node_standard_transfer.go', 'internal/linuxprotection/node_standard_transfer_test.go',
    'cmd/client/legacy_standard_exit_owner_linux.go'})
NATIVE_MTU_SOURCES = {'cmd/client/linux_standard_service_mtu_run_native_test.go', 'cmd/client/linux_standard_service_speed_lab_native_test.go', 'cmd/client/linux_standard_service_mtu_stop_native_test.go', 'cmd/client/linux_standard_service_mtu_admission_native_test.go',
                      'cmd/client/linux_standard_service_mtu_namespace_native_test.go'}
NATIVE_IMAGE_SOURCES = {'cmd/client/linux_standard_service_image_upgrade_namespace_test.go'}
# Installed image acceptance imports the actual generation builder and journal.
# Bind those Python bytes to the same before/after source identity as the Go
# service candidate, rather than silently reading an uncaptured implementation.
SOURCE.update({'client/install-linux-native.py', 'deploy/test_linux_native_install.py'})


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
    actual_image_sources = {path.relative_to(root).as_posix()
                            for path in (root / 'cmd/client').glob('linux_standard_service_image_*.go')}
    if actual_image_sources - SOURCE:
        raise ValueError('Service image source was not bound to the mandatory inventory: ' +
                         repr(sorted(actual_image_sources - SOURCE)))
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
    for name in NATIVE_IMAGE_SOURCES:
        if not (root / name).read_text().startswith('//go:build linux && routervpn_controller_privileged && routervpn_standard_service_native\n'):
            raise ValueError('Native service image case lost its required installed build tags: ' + name)
    for name, group in AUXILIARY_TESTS.items():
        actual = re.findall(r'^func (Test\w+)\(t \*testing\.T\)', (root / name).read_text(), re.M)
        if sorted(actual) != sorted(AUXILIARY[group][1]):
            raise ValueError('Service MTU package gate omitted or renamed an executable case: ' + name)


def check_verdict(output, group):
    _check_exact_verdict(output, case_names(group), 'Standard service ' + group,
                         strict=group.startswith(('mtu', 'image-native-')))

SOURCE.add('cmd/client/linux_standard_service_public_namespace_native_test.go')
NATIVE_MTU_SOURCES.add('cmd/client/linux_standard_service_public_namespace_native_test.go')
SOURCE.add('cmd/client/linux_standard_service_public_restore_namespace_native_test.go')
NATIVE_MTU_SOURCES.add('cmd/client/linux_standard_service_public_restore_namespace_native_test.go')
# Shared-clock provider and native admission are exact shipping dependencies.
SOURCE.update({
    'internal/standardengine/operation_run_clock.go',
    'internal/standardengine/operation_run_clock_linux.go',
    'internal/standardengine/operation_run_clock_linux_test.go',
    'internal/standardengine/worker_run_linux.go',
    'internal/standardengine/worker_run_linux_test.go',
    'internal/mobilemtu/cleanup_provider.go',
    'internal/mobilemtu/cleanup_provider_test.go',
})

SOURCE.update({'client/linux/routervpn-mtu-v20.inc', 'client/linux/test-mtu-v20.c', 'deploy/test_desktop_mtu.py'})

SOURCE.add('cmd/client/linux_standard_service_reverse_namespace_native_test.go')

SOURCE.update({'cmd/client/linux_standard_service_boot_transfer_' + name for name in ('linux.go', 'linux_test.go', 'namespace_native_test.go')})

# The hostname bootstrap is an owned outer transport operation. Its code and
# actual native witnesses are part of the same mandatory service source seal.
SOURCE.update({'cmd/client/' + name for name in (
 'linux_standard_service_boot_bootstrap_linux.go', 'linux_standard_service_boot_bootstrap_client_linux.go',
 'linux_standard_service_boot_bootstrap_test.go', 'linux_standard_service_boot_bootstrap_native_test.go',
 'linux_standard_service_boot_resolver_linux.go', 'linux_standard_service_boot_resolver_native_test.go',
 'linux_standard_service_boot_hostname_namespace_native_test.go', 'desktop_node_linux_parent.go',
 'desktop_node_linux_retirement.go', 'desktop_node_host_linux.go', 'desktop_node_host_linux_tun_native_test.go')})
SOURCE.update({'internal/dnsmeasure/transport_bootstrap.go','internal/dnsmeasure/transport_bootstrap_test.go',
 'internal/linuxprocess/bootstrap_cleanup_gate_linux_native_test.go',
 'internal/mobiletor/desktop_standard_linux_bootstrap.go','internal/mobiletor/desktop_standard_linux_bootstrap_test.go',
 'internal/mobiletor/desktop_standard_linux_bootstrap_native_test.go','internal/mobiletor/desktop_standard_linux_protection.go'})
SOURCE.update({'internal/mobiletor/desktop_standard_linux_bootstrap_netlink.go',
 'internal/mobiletor/desktop_standard_linux_bootstrap_netlink_test.go',
 'internal/mobiletor/desktop_standard_linux_bootstrap_netlink_native_test.go'})
NATIVE_MTU_SOURCES.update({'cmd/client/' + name for name in (
 'linux_standard_service_boot_bootstrap_native_test.go', 'linux_standard_service_boot_resolver_native_test.go',
 'linux_standard_service_boot_hostname_namespace_native_test.go')})

SOURCE.add('cmd/client/linux_standard_service_boot_bootstrap_client_linux_test.go')

# Original idle-child supervision and its actual parent/retirement witnesses.
SOURCE.update({'internal/standardengine/worker_parent_linux_test.go',
               'internal/linuxprocess/bootstrap_linux.go',
               'internal/linuxprocess/bootstrap_current_linux_native_test.go',
               'mobile/desktop/standard_parent_linux_test.go.tmpl',
               'mobile/desktop/standard_parent_native_linux_test.go.tmpl'})

CORE.update({'BootResolverHostsBeforeStub': ('hosts-stub',
                                 'hosts-missing',
                                 'dns-first-stub')})

SOURCE.update({'cmd/client/linux_standard_service_boot_resolver_adapter_linux.go',
 'internal/systembootstrap/config_linux.go',
 'internal/systembootstrap/config_linux_test.go',
 'internal/systembootstrap/resolve_linux.go'})

AUXILIARY.update({'system-bootstrap': ('./internal/systembootstrap',
                      {'TestSystemBootstrapCapturedDNSOptions': (),
                       'TestSystemBootstrapClosedCaptureCannotReturnHosts': (),
                       'TestSystemBootstrapDNSOwnerLabelAndNegativeAnswer': ('original',
                                                                             'embedded-dot',
                                                                             'nxdomain-address'),
                       'TestSystemBootstrapEarlierAnswerCannotHideOwnerLoss': (),
                       'TestSystemBootstrapHostsPrecedence': ('<missing>',
                                                              'nameserver',
                                                              'unrecognized',
                                                              'dns-first-retains-stub-authority',
                                                              'replacement'),
                       'TestSystemBootstrapWirePolicy': ('default',
                                                         'edns',
                                                         'tcp',
                                                         'truncated',
                                                         'search',
                                                         'retry-server',
                                                         'source-change')})})

AUXILIARY_TESTS.update({'internal/systembootstrap/config_linux_test.go': 'system-bootstrap'})

# Original bootstrap mutation receipts, finite kernel permits, and mandatory native proof.
SOURCE.update('internal/mobiletor/desktop_standard_linux_bootstrap_grant_'+suffix+'.go' for suffix in ('wire','receipt','transport','observe','wire_test','native_test'))

# Original read-only daemon authority, namespace provenance and fixed helper.
SOURCE.update('internal/standardengine/resolved_'+name+'.go' for name in ('policy','policy_test','protocol','protocol_test','local','local_test','command','command_test'))
SOURCE.update({'internal/desktopnetwork/observer_linux.go','internal/desktopnetwork/resolved_links_linux.go','internal/desktopnetwork/resolved_links_linux_test.go','mobile/desktop/sing_tun_resolver_linux.go.tmpl','mobile/desktop/sing_tun_resolver_linux_test.go.tmpl','mobile/desktop/sing_tun_resolved_authority_linux.go.tmpl','mobile/desktop/sing_tun_resolved_authority_linux_test.go.tmpl','mobile/desktop/standard_resolved_linux.go.tmpl','mobile/desktop/standard_resolved_linux_test.go.tmpl','deploy/prepare-desktop-mtu.py','deploy/test_desktop_network_cohort.py'})
AUXILIARY.update({
 'resolved-local':('./internal/standardengine',{'TestResolvedLocalOriginalDaemonVerdicts':()}),
 'resolved-command':('./internal/standardengine',{'TestResolvedFixedCommandCaptureAndRequests':(),'TestResolvedFixedCommandWholePolicyFrames':('missing','reorder','digest','capture','sequence','unknown','foreign-name')}),
 'resolved-namespace':('./internal/desktopnetwork',{'TestResolvedNamespaceDescriptorProvenance':()}),
})
AUXILIARY_TESTS.update({'internal/standardengine/resolved_local_test.go':'resolved-local','internal/standardengine/resolved_command_test.go':'resolved-command'})

# Exact captured upstream transport, independently guarded by native cases.
SOURCE.update('internal/mobiletor/desktop_standard_linux_bootstrap_upstream'+suffix+'.go' for suffix in ('','_test','_native_test'))
