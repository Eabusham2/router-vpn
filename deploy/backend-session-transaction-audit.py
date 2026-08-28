#!/usr/bin/env python3
"""Release-lock backend session mutation and durable-state transaction safety."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
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

guard = require(
    "cmd/client/operation_guard.go",
    "beginNodeBoundOperation", "beginMutationOperation", "beginConnectionOperation", "operationMu.TryLock()",
    "profileSettingsBusy(a.state.Connected, a.state.Phase)",
    "connection request was cancelled before it could adopt a runtime",
    "stopOwnedConnectionRuntime", "cloneRouterProfileStore",
)
require(
    "cmd/client/profile_settings.go",
    'case "", "off", "failed":', "return true",
    "beginMutationOperation(r)", "oldProfile := profile", "a.state = oldState",
)
main = require(
    "cmd/client/main.go",
    "beginMutationOperation(r)", "beginConnectionOperation()", "cancelConnectionOperation()",
    "a.operationMu.Lock()", "checkConnectionOperation()", "a.ownsConnectionRuntime(cmd)",
    "oldStore := a.profiles", "a.profiles = oldStore",
)
for handler in ("saveProfile", "selectProfile", "deleteProfile", "importProfileBundle", "options"):
    if f"func (a *app) {handler}" not in main:
        errors.append(f"cmd/client/main.go: missing handler {handler}")

strategy = require("cmd/client/strategy_modes.go", "func (a *app) strategyAuto", "func (a *app) strategySmartAuto", "func (a *app) strategyCustom")
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
    ),
    "cmd/client/logical_modes.go": (
        "func (a *app) connectLogical", "beginConnectionOperation()",
        "previous := a.profiles.Profiles[i].BaseTunnel", "a.profiles.Profiles[i].BaseTunnel = previous",
    ),
    "cmd/client/multihop.go": (
        "beginConnectionOperation()", "checkConnectionOperation()", "previousStore := cloneRouterProfileStore(a.profiles)",
        "a.rollbackProfilesLocked(previousStore)",
    ),
    "cmd/client/multihop_native_routes.go": (
        "beginConnectionOperation()", "checkConnectionOperation()", "previousStore := cloneRouterProfileStore(a.profiles)",
        "a.rollbackProfilesLocked(previousStore)",
    ),
    "cmd/client/external_profile_connect.go": (
        "beginConnectionOperation()", "startedCmd", "checkConnectionOperation()",
        "previousStore := cloneRouterProfileStore(a.profiles)", "a.rollbackProfilesLocked(previousStore)",
    ),
    "cmd/client/standard_exit_platform_routes.go": (
        "beginConnectionOperation()", "checkConnectionOperation()", "previousStore := cloneRouterProfileStore(a.profiles)",
        "a.rollbackProfilesLocked(previousStore)",
    ),
    "cmd/client/openvpn_standard_exit_runtime.go": (
        "func (a *app) standardExitConnectDispatch", "beginConnectionOperation()", "checkConnectionOperation()",
        "previousStore := cloneRouterProfileStore(a.profiles)", "a.rollbackProfilesLocked(previousStore)",
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
        "beginMutationOperation(r)", "oldProfile := profile", "a.profiles.Profiles[i] = oldProfile",
    ),
    "cmd/client/home_summary.go": (
        "stateToken := mtuStateSnapshotToken(a.state)", "after.ActualMode != before.ActualMode",
        "previousStore := cloneRouterProfileStore(a.profiles)", "a.rollbackProfilesLocked(previousStore)",
        "homeExitProofs.Store",
    ),
    "cmd/client/extras.go": (
        "captureAsyncMeasurementSession", "sameAsyncMeasurementSession", "stateAtStart := mtuStateSnapshotToken(a.state)",
        "VPN session/path changed while public-exit lookup was running", "VPN session/path changed while DNS Retest was running",
        "previousStore := cloneRouterProfileStore(a.profiles)", "a.rollbackProfilesLocked(previousStore)",
    ),
    "cmd/client/telemetry.go": (
        "previousStore := cloneRouterProfileStore(a.profiles)", "previousRouterID := a.state.RouterID",
        "a.rollbackProfilesLocked(previousStore)",
    ),
    "cmd/client/mtu_retest.go": (
        "previous := *x", "*x = previous", "durable rollback was incomplete",
        "restoreMTUMeasurementFields", "rollbackMTULiveResult",
    ),
}.items():
    require(rel, *markers)

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
    "did not roll back the live interface",
)

if errors:
    for error in errors:
        print("ERROR:", error)
    raise SystemExit(1)
print("Router VPN backend session/durable-state transaction audit: PASS")
