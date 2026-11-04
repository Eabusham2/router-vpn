"""Exact executable verdict inventory for the retained Linux standard service."""
from pathlib import Path
import re

PREFIX = 'TestLinuxStandardService'
CORE = {
    'OriginalPeerAndForeignPIDFD': (),
    'NetworkShippingDNSRepeatsRealOriginalExchange': (),
    'NetworkProofArmsOnceAndLatchesABA': ('link', 'address', 'route', 'rule', 'overflow', 'reader-failure'),
    'NetworkInitializationAndProofFailuresStayRetained': ('initialization', 'missing-reader', 'second-proof', 'late-event', 'cancelled'),
    'NetworkRetirementPreservesUnjoinedAndReplacement': (),
    'RetainedPeerRejectsSameImageRoleReexec': (),
    'RetainsActualEngineAndAlwaysAcrossController': (),
    'StopRejectsDelayedStart': (),
    'DeadControllerKeepsOnConnectUntilSuccessorCreated': (),
    'JoinedHoldReleasesOnlyOriginalOnConnect': (),
    'ObservesActualEngineExitAfterRequest': ('on-connect', 'always'),
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
    'MonitorObservesRealChildAfterRequestEnds': (),
    'MonitorRejectsLateFailureOverReplacement': (),
    'MonitorCancellationJoinsEnteredObservation': (),
    'MonitorRechecksUnderOriginalTransaction': (),
    'MonitorFailureRetainsRetryOwner': (),
    'MonitorSourceMutationRetiresOnlyOriginal': (),
    'MonitorRejectsUnprovedOrRepeatedActivation': ('dns', 'joined', 'unattempted', 'wrong-operation', 'foreign-runtime', 'foreign-tracker'),
    'MonitorShippingActivationOrderAndRefusal': ('active', 'monitor-refused', 'persistence-failed'),
}
NATIVE = {'NamespaceInstalledIdleUpgradeAndAlwaysRetention': ('off', 'on-connect', 'on-connect-failure', 'on-connect-network-failure', 'on-connect-pre-rpc-network-failure', 'always-off', 'always'), 'NamespaceNetworkEpochRejectsAwayAndBack': ('link', 'address', 'route', 'rule')}
STARTUP = {
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
GROUPS = {'core': CORE, 'startup': STARTUP, 'native': NATIVE}
SOURCE = {'cmd/client/linux_standard_service_' + name for name in (
    'peer_linux.go', 'protocol_linux.go', 'runtime_linux.go', 'client_linux.go', 'dns_linux.go',
    'boot_linux.go', 'other.go', 'upgrade_linux.go', 'peer_native_test.go', 'runtime_native_test.go',
    'channel_native_test.go', 'client_test.go', 'boot_test.go', 'upgrade_native_test.go', 'namespace_test.go', 'route_native_test.go',
    'monitor_linux.go','monitor_linux_test.go','boot_retry_linux.go','boot_retry_linux_test.go','protection_linux.go','protection_native_test.go','absence_linux.go','absence_linux_test.go','legacy_boot_linux.go','legacy_boot_test.go','network_linux.go','network_native_test.go','network_namespace_test.go','startup_native_test.go','startup_config_test.go','startup_namespace_test.go','controller_epoch_linux.go','controller_epoch_native_test.go')}
SOURCE.update({'cmd/client/linux_standard_engine_linux.go', 'cmd/client/legacy_standard_exit_preparation_linux.go', 'modes/kill-switch.py', 'modes/profile_id.py', 'cmd/client/profile_protection_standard_service_linux.go', 'cmd/client/profile_protection_standard_service_native_test.go', 'cmd/client/profile_protection_platform_linux.go'})
RUNNERS = ('linux_standard_service_gate.py', 'test_linux_standard_service_runner.py', 'linux_standard_service_bundle.py', 'test_linux_standard_service_bundle.py')


def pattern(group):
    return '^' + PREFIX + '(' + '|'.join(GROUPS[group]) + ')$'


def validate_inventory(root):
    root = Path(root)
    missing = [name for name in SOURCE if not (root / name).is_file() or (root / name).is_symlink()]
    if missing:
        raise ValueError('Standard service original source inventory is incomplete: ' + ', '.join(sorted(missing)))
    actual = []
    for path in (root / 'cmd/client').glob('*standard_service*test.go'):
        actual.extend(re.findall(r'^func (TestLinuxStandardService\w+)\(t \*testing\.T\)', path.read_text(), re.M))
    actual = [name for name in actual if not name.endswith('Fixture') and name != 'TestLinuxStandardServiceMonitorChild']
    expected = [PREFIX + name for group in GROUPS.values() for name in group]
    if sorted(actual) != sorted(expected):
        raise ValueError('Standard service runner omitted, renamed or duplicated a shipping case: ' + repr(sorted(set(actual) ^ set(expected))))


def check_verdict(output, group):
    if '--- SKIP:' in output or '--- FAIL:' in output:
        raise ValueError('Standard service native boundary skipped or failed')
    passed = re.findall(r'^\s*--- PASS: (\S+) \([0-9]+(?:\.[0-9]+)?s\)$', output, re.M)
    for parent, leaves in GROUPS[group].items():
        for name in (PREFIX + parent, *(PREFIX + parent + '/' + leaf for leaf in leaves)):
            if passed.count(name) != 1:
                raise ValueError('Standard service omitted or duplicated exact executable verdict: ' + name)
