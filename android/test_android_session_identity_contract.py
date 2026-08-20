#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parent
JAVA = ROOT / "app" / "src" / "main" / "java" / "com" / "eabusham" / "routervpn"


def read(name: str) -> str:
    text = (JAVA / name).read_text(encoding="utf-8")
    assert text.strip(), f"{name} is empty"
    return text


registry = read("AndroidRuntimeRegistry.java")
store = read("AndroidNodeStore.java")
exit_store = read("AndroidStandardExitStore.java")
home_state = read("AndroidHomeStateStore.java")
home = read("AndroidHomeSummary.java")
telemetry = read("AndroidTelemetry.java")
unified = read("AndroidUnifiedConnectionController.java")
product = read("ProductActivity.java")
forwarding = read("AndroidForwardingMaster.java")
revalidator = read("AndroidSessionRevalidator.java")
standard_activity = read("StandardExitActivity.java")
manifest = (ROOT / "app" / "src" / "main" / "AndroidManifest.xml").read_text(encoding="utf-8")

# One app-process engine owner. Activity recreation must not replace GoBackend,
# libbox, Xray, multihop or custom-exit runtime ownership.
for marker in (
    "static AndroidRuntimeRegistry instance",
    "final NativeWireGuardController wireGuard",
    "final NativeAmneziaWGController amneziaWG",
    "final NativeSingBoxController singBox",
    "final NativeXrayController xray",
    "final AndroidModeOrchestrator orchestrator",
    "final AndroidMultihopRuntime multihop",
    "final AndroidStandardExitRuntime standardExit",
    "final AndroidSessionRevalidator revalidator",
    "revalidator.start()",
):
    assert marker in registry, f"runtime registry lost ownership marker: {marker}"
assert 'android:name=".MainActivity" android:exported="false" android:enabled="false"' in manifest

# Node and external-profile identity cannot mutate underneath a live/transitioning
# tunnel. Public list/read operations remain available for rendering telemetry.
for marker in (
    "requireMutable(\"importing or replacing a Router VPN node\")",
    "requireSelectable(id)",
    "requireMutable(\"deleting a Router VPN node\")",
    "live session identity is frozen until disconnect",
    "engines.orchestrator.isRunning()",
    "engines.multihop.isActiveOrTransitioning()",
):
    assert marker in store, f"node mutation guard missing: {marker}"
for marker in (
    "requireMutable(\"saving or replacing a custom exit\")",
    "requireMutable(\"deleting a custom exit\")",
    "live external-exit identity and proof must remain immutable",
):
    assert marker in exit_store, f"external-store mutation guard missing: {marker}"

# Session and underlying-path generation are both proof identity. A path change
# must invalidate persisted proof before revalidation begins.
for marker in (
    "final String sessionId",
    "final long pathGeneration",
    "advancePathGeneration",
    'remove("actual_exit_ip")',
    'remove("actual_exit_session")',
):
    assert marker in home_state, f"Home state lost proof lifetime marker: {marker}"
for marker in (
    'String sessionId=""',
    "out.sessionId=home.sessionId",
    '"|session="+runtime.sessionId',
    '"|path="+runtime.pathGeneration',
    "AndroidHomeStateStore.actualExitForCurrentSession",
):
    assert marker in home, f"Home proof signature lost marker: {marker}"
for marker in (
    "AndroidHomeStateStore.advancePathGeneration(context)",
    "re-proving the frozen Router VPN session",
    "AndroidPathProbe.prove(bundle,10000)",
    "AndroidStandardExitRuntime.proveExpectedPublicIp",
):
    assert marker in revalidator, f"network-change revalidation lost marker: {marker}"

# Telemetry binds to frozen session IDs, never mutable selection or saved
# multihop preferences while a graph is actually running.
for marker in (
    "state.activeExitId",
    "state.activeNodeId",
    "validateRoutedHopIdentity(node)",
    "Requested hop is not part of the active Android multihop graph",
):
    assert marker in telemetry, f"telemetry session identity missing: {marker}"

# Android VPN consent can outlive an Activity instance. Persist only non-secret
# requested mode/layers/node IDs and rebind a new UI callback.
for marker in (
    "void savePending(Bundle out)",
    "void restorePending(Bundle in, Callback callback)",
    "STATE_ENTRY",
    "STATE_EXIT",
    "STATE_EXIT_MODE",
    "Activity destruction must not destroy app-process VPN engines",
):
    assert marker in unified, f"unified consent lifecycle missing: {marker}"
for marker in (
    "connection.restorePending(state,callback())",
    "connection.savePending(out)",
    "connection.isMultihopConnected()",
    "connection.activeMultihopEntryId()",
    "connection.activeMultihopExitId()",
    "connection.activeMultihopExitMode()",
    "Connect the actual Android multihop graph before testing routed hop speeds",
):
    assert marker in product, f"ProductActivity lost live-graph marker: {marker}"
assert 'prefs().getString(MULTI_ENTRY,"")' in product, "saved pre-connect multihop config should remain supported"
run_speed = product.split("private void runRoutedHopSpeeds()", 1)[1].split("private void refreshModeChoices", 1)[0]
assert "prefs().getString(MULTI_ENTRY" not in run_speed
assert "prefs().getString(MULTI_EXIT" not in run_speed

# Custom-exit UI/runtime ownership and permission metadata survive recreation.
for marker in (
    "engines.standardExit",
    "restorePending(state)",
    "onSaveInstanceState",
    "STATE_PENDING_ENTRY",
    "STATE_PENDING_EXIT",
):
    assert marker in standard_activity, f"standard-exit lifecycle missing: {marker}"
assert "runtime.close()" not in standard_activity

# Forwarding side control is a real authenticated tunnel operation, not local
# preference theater. It must be bound to the app-owned VPN Network and refuse
# public Router API hosts.
for marker in (
    'new URL(base+"/api/forwarding/master")',
    "vpn.openConnection",
    "getOwnerUid()==Process.myUid()",
    "isPrivate(address)",
    "state.sessionId.equals(after.sessionId)",
    "after.pathGeneration!=state.pathGeneration",
):
    assert marker in forwarding, f"Android forwarding-master safety marker missing: {marker}"
for marker in (
    "AndroidForwardingMaster forwardingMaster",
    "Forward ON",
    "Forward OFF",
    "setForwardingMaster",
    "Setup Center admin token never leaves the server",
):
    assert marker in product, f"Product forwarding control missing: {marker}"

print("Android session identity contract: PASS")
