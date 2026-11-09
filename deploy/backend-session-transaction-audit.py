#!/usr/bin/env python3
"""Release-lock backend session mutation and durable-state transaction safety."""
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

_native_spec = importlib.util.spec_from_file_location(
    "routervpn_native_multihop_audit", Path(__file__).with_name("native_multihop_audit.py"))
_native_module = importlib.util.module_from_spec(_native_spec)
_native_spec.loader.exec_module(_native_module)
native_multihop_shipping_chain = _native_module.native_multihop_shipping_chain
native_multihop_proof_admission = _native_module.native_multihop_proof_admission
errors: list[str] = []


def read(rel: str) -> str:
    path = ROOT / rel
    if not path.is_file():
        errors.append(f"missing {rel}")
        return ""
    return path.read_text(encoding="utf-8")


def require(rel: str, *markers: str) -> str:
    body = read(rel)
    for marker in markers:
        if marker not in body:
            errors.append(f"{rel}: missing {marker!r}")
    return body


def function_block(body: str, signature: str) -> str:
    start = body.find(signature)
    if start < 0:
        return ""
    end = body.find("\nfunc ", start + len(signature))
    return body[start:] if end < 0 else body[start:end]


def require_native_multihop_shipping_chain() -> None:
    if not native_multihop_shipping_chain(read("cmd/client/multihop_native_routes.go")):
        errors.append("native multihop public shipping adapters or owned capture/preflight/stage/proof chain are incomplete")


require_native_multihop_shipping_chain()


def require_native_multihop_proof_admission() -> None:
    if not native_multihop_proof_admission(
            read("cmd/client/multihop_native_capture.go"),
            read("cmd/client/multihop_native_imported.go"),
            read("cmd/client/multihop_native_imported_dns.go")):
        errors.append("native multihop original caller/runtime, captured node proofs or selected DNS admission are incomplete")


require_native_multihop_proof_admission()


def standard_exit_captured_chain(source: str, restore_source: str) -> bool:
    """Check executable ownership/stage structure, not native execution evidence."""
    tokens = _native_module._tokens
    positions = _native_module._positions
    function = _native_module._function
    body = tokens(source)
    routes = function(body, "func registerPlatformStandardExitRoutes(h *http.ServeMux, a *app)")
    if routes is None or len(positions(routes, 'h.HandleFunc("/api/standard-exit/connect", a.platformStandardExitConnect)')) != 1:
        return False
    public = function(body, "func (a *app) platformStandardExitConnect(w http.ResponseWriter, r *http.Request)")
    if public != tokens("a.platformStandardExitConnectOwned(w, r, defaultPlatformStandardExitRuntime())"):
        return False
    owned = function(body, "func (a *app) platformStandardExitConnectOwned(w http.ResponseWriter, r *http.Request, adapter platformStandardExitRuntime)")
    if owned != tokens("""
        operation, finish, guardErr := a.beginConnectionOperation()
        if guardErr != nil {
            http.Error(w, guardErr.Error(), http.StatusConflict)
            return
        }
        defer finish()
        a.platformStandardExitConnectCaptured(w, r, adapter, operation)
    """):
        return False
    captured = function(body, "func (a *app) platformStandardExitConnectCaptured(w http.ResponseWriter, r *http.Request, adapter platformStandardExitRuntime, operation context.Context)")
    restore = function(tokens(restore_source), "func (s *linuxStandardServiceSpeedLabRestore) restart(ctx context.Context, a *app) error")
    if captured is None or restore is None:
        return False
    for block in (captured, restore):
        if any(positions(block, call) for call in ("beginConnectionOperation(", "checkConnectionOperation(", "connectionOperationContextOrBackground(")):
            return False
    for block, parameter in ((captured, "operation"), (restore, "ctx")):
        if positions(block, "var " + parameter):
            return False
        for index, token in enumerate(block):
            if token != parameter:
                continue
            index += 1
            while index + 1 < len(block) and block[index] == "," and block[index + 1].isidentifier():
                index += 2
            if ((block[index:index + 1] == ["="] and block[index:index + 2] != ["=", "="])
                    or block[index:index + 2] == [":", "="]):
                return False

    def depth_at(block, index):
        return block[:index].count("{") - block[:index].count("}")

    def single(block, fragment, depth):
        found = positions(block, fragment)
        return found[0] if len(found) == 1 and depth_at(block, found[0]) == depth else -1

    def rejects(block, start, fragment):
        if start < 0 or depth_at(block, start) != 0:
            return False
        opening = start + len(tokens(fragment))
        end = opening
        while end < len(block) and depth_at(block, end) > 0:
            end += 1
        return any(block[i] == "return" and depth_at(block, i) == 1 for i in range(opening, end))

    # Each rejection must execute at function scope and return before entering
    # the next stage; a comment, string, closure, or unchecked call is no guard.
    guards = (
        "if err := a.checkCapturedConnectionOperation(operation); err != nil {",
        "if err = a.checkCapturedConnectionOperation(operation); err != nil {",
        "if cancelErr := a.checkCapturedConnectionOperation(operation); cancelErr != nil {",
    )
    checks = []
    for fragment, count in zip(guards, (1, 2, 1)):
        found = positions(captured, fragment)
        if len(found) != count:
            return False
        for start in found:
            if not rejects(captured, start, fragment):
                return False
            checks.append(start)
    checks.sort()
    if checks[0] != 0 or len(positions(captured, "a.checkCapturedConnectionOperation(")) != 4:
        return False
    start = single(captured, "err = retained.Start(operation)", 1)
    command = single(captured, "err = cmd.Start()", 1)
    dns = single(captured, "proofErr = adapter.proveDNS(operation, retained)", 1)
    proof = single(captured, "proofErr = adapter.prove(a, exit.ExpectedPublicIP)", 1)
    current = single(captured, "proofErr = adapter.current(retained, operation)", 1)
    final_guard = "if a.cmd != cmd || a.checkCapturedConnectionOperationLocked(operation) != nil || a.connectionCancelIntent == operation || retained != nil && !legacyStandardExitFailureOwned(a, retained, false) {"
    adoption = single(captured, final_guard, 0)
    publish = single(captured, "a.state.Connected = true", 0)
    if not (checks[0] < checks[1] < start < command < checks[2] < dns < proof < current < checks[3] < adoption < publish) or not rejects(captured, adoption, final_guard):
        return False
    call = single(restore, "a.platformStandardExitConnectCaptured(response, request, defaultPlatformStandardExitRuntime(), ctx)", 0)
    request = single(restore, 'request, err := http.NewRequestWithContext(ctx, http.MethodPost, "/api/standard-exit/connect", bytes.NewReader(body))', 0)
    source_checks = positions(restore, "if err := s.sourceCurrent(ctx, a, ctx); err != nil {")
    if len(source_checks) != 2 or not (source_checks[0] == 0 < request < call < source_checks[1]):
        return False
    if not all(rejects(restore, at, "if err := s.sourceCurrent(ctx, a, ctx); err != nil {") for at in source_checks):
        return False
    return not positions(restore, "a.platformStandardExitConnectOwned(") and not positions(restore, "a.platformStandardExitConnect(")


def require_standard_exit_captured_chain() -> None:
    if not standard_exit_captured_chain(read("cmd/client/standard_exit_platform_routes.go"), read("cmd/client/linux_standard_service_speed_lab_linux.go")):
        errors.append("standard exit public admission, captured stage guards, or already-owned Speed Lab restoration chain is incomplete")


require_standard_exit_captured_chain()


guard = require(
    "cmd/client/operation_guard.go",
    "beginNodeBoundOperation", "beginMutationOperation", "beginConnectionOperation", "operationMu.TryLock()",
    "profileSettingsBusy(a.state.Connected, a.state.Phase)",
    "connection request was cancelled before it could adopt a runtime",
    "cancelPendingStartupPolicy(a)", "stopOwnedConnectionRuntime", "cloneRouterProfileStore",
    "a.guardSessionDNSStopPending(caller)",
)
require(
    "cmd/client/profile_settings.go",
    'case "", "off", "failed":', "return true",
    "beginMutationOperation(r)", "oldProfile := profile", "a.profiles.Profiles[i] = oldProfile", "a.state = oldState",
)
main = require(
    "cmd/client/main.go",
    "beginMutationOperation(r)", "beginConnectionOperation()", "cancelConnectionOperation()",
    "a.operationMu.Lock()", "checkCapturedConnectionOperation(startupCtx)", "a.ownsConnectionRuntime(cmd)",
    "publishStartedDesktopNode(startupCtx, native, cmd", "checkDesktopNodeStartupOwnerLocked(startupCtx, native, cmd)",
    "errConnectionOperationCancelled", "connectionOperationContextOrBackground()",
    "oldStore := a.profiles", "a.profiles = oldStore",
    "func (a *app) stopModeWithIntent(holdKillSwitch bool) (failure error)", "clearActiveMultihopGraph(a)",
    "a.drainSessionDNSForStop(ctx)", "failure = dnsStop.finish(ctx)",
)
require(
    "cmd/client/desktop_node_connection_host.go",
    "func (a *app) publishStartedDesktopNode", "a.mu.Lock()", "defer a.mu.Unlock()",
    "a.sameConnectionOperationLocked(operation)", "a.checkCapturedConnectionOperationLocked(operation)",
    "func (a *app) checkDesktopNodeStartupOwnerLocked", "a.cmd != command", "current != launch",
)
require(
    "cmd/client/desktop_node_connection_host_test.go",
    "TestDesktopNodePublicConnectRejectsReplacedRequest",
    "TestDesktopNodePublicConnectCancellationAndProofReplacement",
    "TestDesktopNodePublicOrdinaryCancellationRetainsCapturedCleanup",
)
require(
    "deploy/test_windows_node_process.py",
    '"TestDesktopNodePublicConnectRejectsReplacedRequest"',
    '"TestDesktopNodePublicConnectCancellationAndProofReplacement"',
    '"TestDesktopNodePublicOrdinaryCancellationRetainsCapturedCleanup"',
    '"public-node-adopts-replacement-request"', '"cancelled-ordinary-start-loses-cleanup"',
)
for handler in ("saveProfile", "selectProfile", "deleteProfile", "importProfileBundle", "options"):
    if f"func (a *app) {handler}" not in main:
        errors.append(f"cmd/client/main.go: missing handler {handler}")

strategy = require(
    "cmd/client/strategy_modes.go",
    "func (a *app) strategyAuto", "func (a *app) strategySmartAuto", "func (a *app) strategyCustom",
    "cancelPendingStartupPolicy", "applyStartupPolicyWithContext",
    "errors.Is(err, errConnectionOperationCancelled)", "finalizeCancelledFallback",
)
require(
    "cmd/client/controller_shutdown.go",
    "if closing.a.controllerClosing()", "scheduleStartupPolicy(closing.a)",
    "go closing.a.recordLastSuccessfulRuntime(closing.operations)",
)
require(
    "cmd/client/controller_startup_owner_test.go",
    "TestLocalControllerStartupRouteRegistrationIsPassive",
    "TestLocalControllerStartupCapturedBeforeEOFCannotLaunchAfterEOF",
    "TestLocalControllerStartupEOFDeniesHTTPWithoutCleanupScheduling",
    "TestLocalControllerStartupAlreadyRetiredClosesBeforeServing",
)
for name, next_name in (("strategyAuto", "strategySmartAuto"), ("strategySmartAuto", "strategyCustom"), ("strategyCustom", "writeStrategyResult")):
    start = strategy.find(f"func (a *app) {name}")
    end = strategy.find(f"func ", start + 1) if next_name == "writeStrategyResult" else strategy.find(f"func (a *app) {next_name}", start + 1)
    if start < 0 or end < 0 or "beginConnectionOperation()" not in strategy[start:end]:
        errors.append(f"cmd/client/strategy_modes.go: {name} is not individually serialized by beginConnectionOperation")

for rel, markers in {
    "cmd/client/strategy_modes.go": (
        "func (a *app) strategyAuto", "func (a *app) strategySmartAuto", "func (a *app) strategyCustom",
        "beginConnectionOperation()", "a.operationMu.Lock()", "current.RouterID == st.RouterID",
        "func (a *app) applyStartupPolicy()", "startup auto-connect skipped while another transaction is active",
        "errors.Is(restoreErr, errConnectionOperationCancelled)", "http.StatusConflict",
    ),
    "cmd/client/logical_modes.go": (
        "func (a *app) connectLogical", "beginConnectionOperation()",
        "previous := a.profiles.Profiles[i].BaseTunnel", "a.profiles.Profiles[i].BaseTunnel = previous",
        "connectionOperationContextOrBackground()", "finalizeCancelledFallback", "http.StatusConflict",
        "stageLogicalBasePreference(operation, q.Base)", "rollbackLogicalBasePreference(basePreference)",
        "preferred base could not be saved before connection preparation",
    ),
    "cmd/client/multihop.go": (
        "beginConnectionOperation()", "checkConnectionOperation()", "previousStore := cloneRouterProfileStore(a.profiles)",
        "a.rollbackProfilesLocked(previousStore)", "errConnectionOperationCancelled", "clearActiveMultihopGraph(a)",
    ),
    "cmd/client/multihop_native_routes.go": (
        "beginConnectionOperation()", "checkConnectionOperation()", "previousStore := cloneRouterProfileStore(a.profiles)",
        "a.rollbackProfilesLocked(previousStore)", "http.StatusConflict",
    ),
    "cmd/client/multihop_native_capture.go": (
        "func (a *app) proveNativeMultihop", "connectionOperationContextOrBackground()",
        "func proveNativeMultihopCapture", "a.nativeMultihopProofOwnerCurrentContext(ctx, sel, command)",
        "mobilemtu.LockContext(ctx, &a.mu)", "command != nil && a.cmd == command && !a.closing",
        "a.observeImportedOpenVPN(ctx, sel, command) == nil",
        "!owns() || sel.Native == nil || sel.Native.validate(sel) != nil",
        "prove(ctx, sel.Entry, multihopEntryProofProxy)",
        "prove(ctx, sel.Exit, multihopProofProxy)",
        "err == nil && ctx.Err() == nil && owns() && sel.Native.validate(sel) == nil",
    ),
    "cmd/client/external_profile_connect.go": (
        "a.beginConnectionOperationContext(r.Context())", "startedCmd", "checkConnectionOperation()",
        "previousStore := cloneRouterProfileStore(a.profiles)", "a.rollbackProfilesLocked(previousStore)",
        "proveOpenVPNStandardExitForOperation", "proveStandardExitForOperation",
    ),
    "cmd/client/standard_exit_platform_routes.go": (
        "beginConnectionOperation()", "checkCapturedConnectionOperation(operation)", "previousStore := cloneRouterProfileStore(a.profiles)",
        "a.rollbackProfilesLocked(previousStore)", "proofErr", "http.StatusConflict",
    ),
    "cmd/client/connection_profiles.go": (
        "func (a *app) saveConnectionProfile", "func (a *app) updateConnectionProfile",
        "func (a *app) loadConnectionProfile", "func (a *app) deleteConnectionProfile",
        "beginMutationOperation(r)", "oldState := a.state", "a.rollbackProfilesLocked(old)", "a.state = oldState",
    ),
    "cmd/client/connection_profile_setup.go": (
        "cloneConnectionProfileSetupMetaStore", "beginMutationOperation(r)", "withInternalMutationContext(innerReq)",
        "connection setup snapshot failed and rollback was incomplete",
        "connection profile delete failed and was rolled back",
    ),
    "cmd/client/dns_policy_api.go": (
        "beginMutationOperation(r)", "dnsPolicySelectionToken(current, currentEntry) != token",
        "current.ID != profile.ID", "copyDNSPolicy(&currentUpdate, updated)",
        "a.profiles.Profiles[i] = current", "cancelPendingStartupPolicy(a)",
    ),
    "cmd/client/home_summary.go": (
        "stateToken := mtuStateSnapshotToken(a.state)", "after.ActualMode != before.ActualMode",
        "previousStore := cloneRouterProfileStore(a.profiles)", "a.rollbackProfilesLocked(previousStore)",
        "homeExitProofs.Store", "profileSettingsBusy(a.state.Connected, a.state.Phase)", "targetID = liveID",
        "active Router VPN session has no node identity; refusing to substitute the mutable selected node",
    ),
    "cmd/client/session_state.go": (
        "profileSettingsBusy(s.Connected, s.Phase)", "profileID = liveID",
        "dnsProofObservationStillCurrentLocked", "proveDNSAsyncWithProbe", "proveSelectedDNSContext", "invalidateDNSProofBindingLocked",
        "t.dnsProofLastAttempt = time.Time{}", "asyncMeasurementProfileToken(profile) == asyncMeasurementProfileToken(s.Profile)",
    ),
    "cmd/client/dns_proof_path.go": (
        "asyncMeasurementPathContext", "beginAsyncMeasurementAdoption", "dns-proof-stale", "stale result discarded",
        "dnsProofBinding.validateLocked", "defer stop()", "defer release()",
    ),
    "cmd/client/extras.go": (
        "captureAsyncMeasurementSession", "sameAsyncMeasurementSession", "activeAsyncMeasurementProfile",
        "validateAsyncMeasurementProfile", "asyncMeasurementProfileToken",
        "VPN session/path changed while live proof was running",
        "active VPN node/mode/base/path changed while live proof was running",
        "active VPN profile or policy changed while live proof was running",
        "active VPN path or policy changed before public-exit persistence",
        "active node/path or DNS policy changed before DNS Retest persistence",
        "previousStore := cloneRouterProfileStore(a.profiles)", "a.rollbackProfilesLocked(previousStore)",
    ),
    "cmd/client/telemetry.go": (
        "previousStore := cloneRouterProfileStore(a.profiles)", "previousRouterID := a.state.RouterID",
        "a.rollbackProfilesLocked(previousStore)",
    ),
    "cmd/client/mtu_retest.go": (
        "captureMTULiveSnapshot", "validateMTUMeasurementAgainstLiveSnapshot",
        "failMTURetestWithLiveRollback", "restoreMTULiveSnapshot",
        "restoreMTUMeasurementFields", "rollback was incomplete",
    ),
}.items():
    require(rel, *markers)

logical_source = read("cmd/client/logical_modes.go")
logical_connect = function_block(logical_source, "func (a *app) connectLogical")
launch_at = logical_connect.find("used, err := a.startLogicalMode")
proof_at = logical_connect.find("if err := a.checkConnectionOperation()")
stage_at = logical_connect.find("basePreference, err := a.stageLogicalBasePreference(operation, q.Base)")
if min(launch_at, proof_at, stage_at) < 0 or not (stage_at < launch_at < proof_at) or "a.persistBasePreference(" in logical_connect:
    errors.append("cmd/client/logical_modes.go: explicit base preference must be saved before captured graph preparation and never mutate a proved source")
if logical_connect.count("a.rollbackLogicalBasePreference(basePreference)") != 2:
    errors.append("cmd/client/logical_modes.go: failed or cancelled logical launch must attempt its captured conditional preference rollback")
require("cmd/client/logical_base_preference.go",
        "a.connectionContext != capture.operation", "profileStartupSettingsToken(*profile) != capture.stagedRevision",
        "!capture.protectionUnchangedLocked(slot)", "profile.BaseTunnel = stagedBase",
        "slot.profileRevision != before.profileRevision", "*slot.target != *before.target")

legacy_openvpn = require(
    "cmd/client/openvpn_standard_exit_runtime.go",
    "func (a *app) standardExitConnectDispatch", "a.platformStandardExitConnect(w, r)",
    "openVPNStandardExitCommand", "prepareOpenVPNRuntime",
)
dispatch = function_block(legacy_openvpn, "func (a *app) standardExitConnectDispatch")
if "beginConnectionOperation()" in dispatch:
    errors.append("cmd/client/openvpn_standard_exit_runtime.go: compatibility dispatcher still acquires a nested connection transaction")
for retired in ("func proveOpenVPNStandardExit(", "func (a *app) openVPNStandardExitConnect"):
    if retired in legacy_openvpn:
        errors.append(f"cmd/client/openvpn_standard_exit_runtime.go: retired duplicate path remains: {retired}")

require(
    "cmd/client/connection_exit_proof.go",
    "proveExpectedPublicExit", "NewRequestWithContext", "connectionOperationContextOrBackground",
    "stopTimerWithoutBlocking", "CloseIdleConnections",
)
require(
    "cmd/client/connection_cancellation.go",
    "finalizeCancelledFallback", "releaseTransitionKillSwitch", "errConnectionOperationCancelled",
)
require(
    "cmd/client/connection_launch_order_test.go",
    "TestEveryShippingConnectionStartIsGuardedBeforeAndAfterLaunch",
    "TestFallbackLoopsRecognizeStableCancellationSentinel",
    "TestLegacyStandardExitDispatcherDelegatesWithoutNestedTransaction",
)
require(
    "cmd/client/connection_exit_proof_test.go",
    "TestProveExpectedPublicExitCancellationInterruptsRequest",
    "TestStopTimerWithoutBlockingAfterDelivery",
)
require(
    "cmd/client/multihop_native_capture_test.go",
    "TestNativeMultihopCaptureRejectsChangedBaseAssetsAndPolicies",
    "TestNativeMultihopProofCannotAdoptRetiredEntryOrExit",
)

require("cmd/client/forwarding_master.go", "beginNodeBoundOperation()", "active Router VPN graph changed while forwarding master was being verified")
require("cmd/client/main.go", "func proxyJSON", "beginNodeBoundOperation()")
require("cmd/client/operation_guard_test.go", "TestNodeBoundOperationSerializesWithoutRequiringDisconnect")

legacy = require("cmd/client/standard_exits.go", "Compatibility/read-only registration only")
legacy_register = legacy[legacy.find("func registerStandardExitRoutes"):legacy.find("func (a *app) guardedStandardExitSave")]
for forbidden in ('"/api/standard-exit/save"', '"/api/standard-exit/delete"'):
    if forbidden in legacy_register:
        errors.append(f"cmd/client/standard_exits.go: legacy registration still exposes mutating route {forbidden}")

require(
    "cmd/client/operation_guard_test.go",
    "TestProfileSettingsBusyFailsClosedForUnknownAndTransitionPhases",
    "TestOperationGuardSerializesConnectionAndMutationTransactions",
    "TestConnectionOperationCancellationBlocksAdoption",
    "TestCancelConnectionOperationSuppressesPendingStartupPolicy",
)
require(
    "cmd/client/connection_profiles_test.go",
    "TestConnectionProfileLoadPersistenceFailureRestoresRuntimeOptionState",
    "failed connection-profile load left option state changed",
)
require(
    "cmd/client/connection_profile_setup_test.go",
    "TestConnectionProfileSetupLoadPreflightsMetadataBeforeMutatingSelection",
    "failed setup load partially mutated selection",
)
require(
    "cmd/client/mtu_retest_test.go",
    "TestMTURetestPersistenceFailureRollsBackLiveAndInMemoryResult",
    "MTU persistence failure is no longer wired to exact live-MTU rollback",
)
require(
    "cmd/client/home_summary_test.go",
    "TestHomeSummaryUsesLiveRouterIDInsteadOfMutableSelection",
    "TestHomeExitProofRejectsMissingLiveRouterIdentity",
)
require(
    "cmd/client/session_state_test.go",
    "TestSessionCaptureUsesLiveProfileWhileActiveAndSelectedProfileWhenIdle",
    "TestDNSProofObservationFreshnessRejectsSameSessionPathChanges",
)

if errors:
    for error in errors:
        print("ERROR:", error)
    raise SystemExit(1)
print("Router VPN backend session/durable-state transaction audit: PASS")
