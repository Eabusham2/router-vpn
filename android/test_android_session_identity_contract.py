#!/usr/bin/env python3
from pathlib import Path
import subprocess
import sys

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
numeric_address = read("AndroidNumericAddress.java")
revalidator = read("AndroidSessionRevalidator.java")
wireguard = read("NativeWireGuardController.java")
amnezia = read("NativeAmneziaWGController.java")
standard_activity = read("StandardExitActivity.java")
standard_runtime = read("AndroidStandardExitRuntime.java")
mutation_guard = read("AndroidVpnMutationGuard.java")
via_entry = read("AndroidViaEntryLatencyProbe.java")
map_view = read("RouterVpnNodeMapView.java")
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

# Location is an explicit map action only. Permission declarations may exist,
# but no first-launch/runtime owner may silently request them. The globe accepts
# only Android Location-provider fixes and renders a separately colored user pin.
for marker in (
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.ACCESS_FINE_LOCATION",
):
    assert marker in manifest, f"Android manifest missing opt-in location permission: {marker}"
for marker in (
    "LOCATE ME",
    "enableRealUserLocation()",
    "activity.requestPermissions",
    "requestSingleUpdate",
    "MAX_LAST_LOCATION_AGE_MS",
    "acceptRealLocation",
    "userPin",
    'canvas.drawText("YOU"',
    "Only real coordinates • device location appears only after LOCATE ME",
):
    assert marker in map_view, f"Android truthful-location globe marker missing: {marker}"
assert "requestPermissions" not in product, "Android ProductActivity must not silently request location on startup"
assert "getLastKnownLocation" in map_view and "getProviders(true)" in map_view
assert "Geocoder" not in map_view and "ip-api" not in map_view.lower() and "ipinfo" not in map_view.lower(), "Android map must not infer device location from network/IP"

# Persistent mutation fails closed for unknown/future phases and every
# app-process-owned transport, including raw WG/AWG and standard exits.
for marker in (
    "phaseBusy(home.connected, phase)",
    '"off".equals(phase)',
    '"disconnected".equals(phase)',
    '"failed".equals(phase)',
    "e.standardExit.isActiveOrTransitioning()",
    "tunnelBusy(e.wireGuard.getState())",
    "tunnelBusy(e.amneziaWG.getState())",
):
    assert marker in mutation_guard, f"Android mutation guard lost fail-closed ownership marker: {marker}"
assert 'phase.contains(' not in mutation_guard, "Android mutation guard regressed to allow unknown future phases"
for marker in (
    "synchronized boolean isActiveOrTransitioning()",
    "task!=null&&!task.isDone()",
    "if(state==null)return true",
    '!"external".equals(home.logicalMode)',
    "engines.wireGuard.getState()!=com.wireguard.android.backend.Tunnel.State.DOWN",
    "engines.amneziaWG.getState()!=org.amnezia.awg.backend.Tunnel.State.DOWN",
    "runtimeBusy(engines.xray.getState())",
    "exit.protocol",
):
    assert marker in standard_runtime, f"Android standard-exit ownership lost marker: {marker}"
assert "protocl" not in standard_runtime, "Android standard-exit source contains a misspelled protocol field"
assert "boolean isActiveOrTransitioning() { return AndroidVpnMutationGuard.isBusy(activity); }" in unified

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

# Native WG/AWG own their own handoff recovery, so they must independently
# invalidate public-exit proof/path generation before rebuilding the tunnel.
for name, source in (("WireGuard", wireguard), ("AmneziaWG", amnezia)):
    recovery = source.split("private void recoverAfterNetworkChange()", 1)
    assert len(recovery) == 2, f"{name} lost network-change recovery"
    recovery = recovery[1].split("void disconnect", 1)[0]
    invalidate = recovery.find("AndroidHomeStateStore.advancePathGeneration(appContext)")
    teardown = recovery.find("backend.setState(this, State.DOWN, null)")
    proof = recovery.find("AndroidPathProbe.prove(bundle, 10000)")
    assert invalidate >= 0, f"{name} must invalidate the old path/public-exit proof on underlay change"
    assert teardown >= 0 and invalidate < teardown, f"{name} must invalidate proof before tunnel rebuild"
    assert proof > teardown, f"{name} must re-prove selected node after tunnel rebuild"

# Telemetry binds to frozen session IDs, never mutable selection or saved
# multihop preferences while a graph is actually running.
for marker in (
    "state.activeExitId",
    "state.activeNodeId",
    "validateRoutedHopIdentity(node)",
    "Requested hop is not part of the active Android multihop graph",
):
    assert marker in telemetry, f"telemetry session identity missing: {marker}"

# Pre-connect X→Y/X→Z latency is a real temporary-entry routed measurement.
# The temporary WG entry must be proven, session/path identity must remain
# stable, results must never pollute direct RTT cache, and the entry must be
# fully DOWN before the picker sees any result.
for marker in (
    "wireGuard.connect(entry.file",
    "state != Tunnel.State.UP",
    "telemetry.measureNodesViaCurrentPath(entry.id",
    "wireGuard.disconnect",
    "Temporary entry did not fully disconnect; candidate results discarded.",
    "AtomicBoolean",
):
    assert marker in via_entry, f"via-entry probe missing: {marker}"
for marker in (
    "measureNodesViaCurrentPath",
    '"raw-tunnel".equals(before.logicalMode)',
    '"wg".equals(before.actualBase)',
    "String session=before.sessionId",
    "long generation=before.pathGeneration",
    "session.equals(now.sessionId)",
    "now.pathGeneration!=generation",
    "all results discarded",
):
    assert marker in telemetry, f"via-entry telemetry proof missing: {marker}"
via_method = telemetry.split("void measureNodesViaCurrentPath", 1)[1].split("void currentPath", 1)[0]
assert "cache(" not in via_method, "via-entry RTT must never overwrite direct-node RTT cache"

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
    "PREPARE_VIA_ENTRY_RTT",
    "VpnService.prepare(this)",
    "prepareViaEntryExitMeasurement",
    "runPendingViaEntryProbe",
    "showViaEntryExitPicker",
    "Values are not saved as direct-node RTTs.",
):
    assert marker in product, f"ProductActivity lost live-graph/via-entry marker: {marker}"
assert 'prefs().getString(MULTI_ENTRY,"")' in product, "saved pre-connect multihop config should remain supported"
run_speed = product.split("private void runRoutedHopSpeeds()", 1)[1].split("private void refreshModeChoices", 1)[0]
assert "prefs().getString(MULTI_ENTRY" not in run_speed
assert "prefs().getString(MULTI_EXIT" not in run_speed
picker = product.split("private void showViaEntryExitPicker", 1)[1].split("private void clearPendingProbe", 1)[0]
assert "cachedMedian" not in picker, "via-entry picker must not substitute direct cached RTT"
assert "medianMs" in picker and "unavailable" in picker

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
# preference theater. It must be bound to the app-owned VPN Network, refuse
# public Router API hosts, use a minSdk-24-compatible resolver-free literal-IP
# parser, and reject unspecified addresses before any token-bearing request.
for marker in (
    'new URL(base+"/api/forwarding/master")',
    "vpn.openConnection",
    "getOwnerUid()==Process.myUid()",
    "AndroidNumericAddress.parse(host)",
    "literal private Router API address",
    "isPrivate(address)",
    "isAnyLocalAddress())return false",
    "state.sessionId.equals(after.sessionId)",
    "after.pathGeneration!=state.pathGeneration",
):
    assert marker in forwarding, f"Android forwarding-master safety marker missing: {marker}"
for marker in (
    "InetAddress.getByAddress(raw)",
    "parseIPv4",
    "parseIPv6",
    "embedded IPv4 IPv6 literals are not accepted",
    "host.indexOf('%')>=0",
):
    assert marker in numeric_address, f"Android numeric-address parser lost marker: {marker}"
for forbidden in (
    "android.net.InetAddresses",
    "InetAddresses.isNumericAddress",
    "InetAddresses.parseNumericAddress",
    "InetAddress.getByName(uri.getHost())",
    "InetAddress.getByName(host)",
):
    assert forbidden not in forwarding + numeric_address, f"Android forwarding must not use resolver/API-29-only address path: {forbidden}"
for marker in (
    "AndroidForwardingMaster forwardingMaster",
    "Forward ON",
    "Forward OFF",
    "setForwardingMaster",
    "Setup Center admin token never leaves the server",
):
    assert marker in product, f"Product forwarding control missing: {marker}"

# Keep the standalone focused contract executable for local/CI use too.
standalone = ROOT / "test_android_via_entry_latency_contract.py"
assert standalone.is_file() and standalone.read_text(encoding="utf-8").strip()

mutation_audit = ROOT.parent / "deploy" / "android-session-mutation-audit.py"
subprocess.run([sys.executable, str(mutation_audit)], cwd=ROOT.parent, check=True)

print("Android session identity contract: PASS")
