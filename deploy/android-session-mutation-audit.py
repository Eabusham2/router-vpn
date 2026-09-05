#!/usr/bin/env python3
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def require(path: str, *markers: str) -> None:
    body = (ROOT / path).read_text(encoding="utf-8")
    missing = [marker for marker in markers if marker not in body]
    if missing:
        raise SystemExit(f"{path}: missing Android session-mutation marker(s): {missing}")


require(
    "android/app/src/main/java/com/eabusham/routervpn/AndroidVpnMutationGuard.java",
    "final class AndroidVpnMutationGuard",
    "static boolean isBusy(Context context)",
    "if (context == null) return true",
    "hasOwnedVpnTransport(context)",
    "phaseBusy(home.connected, phase)",
    "Unknown/future",
    '"off".equals(phase)',
    '"disconnected".equals(phase)',
    '"failed".equals(phase)',
    "e.orchestrator.isRunning()",
    "e.multihop.isActiveOrTransitioning()",
    "e.standardExit.isActiveOrTransitioning()",
    "tunnelBusy(e.wireGuard.getState())",
    "tunnelBusy(e.amneziaWG.getState())",
    "runtimeBusy(e.singBox.getState())",
    "runtimeBusy(e.xray.getState())",
    "return true;",
)

# A new process cannot inherit yesterday's process-owned Connected/UP proof.
require(
    "android/app/src/main/java/com/eabusham/routervpn/AndroidRuntimeRegistry.java",
    "AndroidProcessStateReconciler.reconcile(app)",
    "new NativeWireGuardController(app)",
)
registry = (ROOT / "android/app/src/main/java/com/eabusham/routervpn/AndroidRuntimeRegistry.java").read_text(encoding="utf-8")
if registry.index("AndroidProcessStateReconciler.reconcile(app)") > registry.index("new NativeWireGuardController(app)"):
    raise SystemExit("Android runtime registry restores engines before cold-process state invalidation")
require(
    "android/app/src/main/java/com/eabusham/routervpn/AndroidProcessStateReconciler.java",
    "previous process-owned VPN/path proof was invalidated",
    '"UP".equals(state)',
    '"STARTING".equals(state)',
    '"STOPPING".equals(state)',
    'putString(stateKey, "FAILED")',
    "AndroidHomeStateStore.advancePathGeneration(app)",
    "AndroidHomeStateStore.failed(app, RESTART_REASON)",
)
for service in (
    "android/app/src/main/java/com/eabusham/routervpn/LayeredVpnService.java",
    "android/app/src/main/java/com/eabusham/routervpn/XrayVpnService.java",
):
    body=(ROOT/service).read_text(encoding="utf-8")
    if body.count("Service.START_NOT_STICKY") < 2:
        raise SystemExit(f"{service}: became sticky; cold-process reconciliation contract must be revisited")

# One logical/session owner: raw WG/AWG may own Home state when launched directly,
# but AUTO/SMART/CUSTOM/logical candidate transports must be managed children.
for path in (
    "android/app/src/main/java/com/eabusham/routervpn/NativeWireGuardController.java",
    "android/app/src/main/java/com/eabusham/routervpn/NativeAmneziaWGController.java",
):
    require(
        path,
        "void connectManaged(File privateBundle, Callback callback)",
        "connectInternal(privateBundle, false, callback)",
        "if (publishHomeState) AndroidHomeStateStore.begin",
        "if (publishHomeState) AndroidHomeStateStore.connected",
        "void disconnectManaged(Callback callback)",
        "disconnectInternal(false, callback)",
        "if (publishHomeState) AndroidHomeStateStore.disconnected",
        "AndroidHomeStateStore.beginPathRevalidation",
        "AndroidHomeStateStore.completePathRevalidation",
    )
require(
    "android/app/src/main/java/com/eabusham/routervpn/AndroidModeOrchestrator.java",
    "wg.connectManaged(bundle",
    "awg.connectManaged(bundle",
    "wg.disconnectManaged",
    "awg.disconnectManaged",
    "stopCurrent(false)",
    "stopCurrent(true)",
    "if(clearHomeState)AndroidHomeStateStore.disconnected(context)",
)
orchestrator=(ROOT/"android/app/src/main/java/com/eabusham/routervpn/AndroidModeOrchestrator.java").read_text(encoding="utf-8")
for forbidden in ("wg.connect(bundle", "awg.connect(bundle"):
    if forbidden in orchestrator:
        raise SystemExit(f"Android logical orchestrator revived child Home-state ownership: {forbidden}")

# Every non-native underlay revalidation must visibly invalidate Connected proof
# and may re-adopt only the same session + exact next path generation.
require(
    "android/app/src/main/java/com/eabusham/routervpn/AndroidHomeStateStore.java",
    "beginPathRevalidation",
    "completePathRevalidation",
    'putString("path_proof", "pending")',
    'putBoolean("connected", false)',
    "currentGeneration != before.pathGeneration + 1L",
)
revalidator_path = "android/app/src/main/java/com/eabusham/routervpn/AndroidSessionRevalidator.java"
require(
    revalidator_path,
    "AndroidHomeStateStore.beginPathRevalidation",
    "requireSameRevalidation(token)",
    "AndroidHomeStateStore.completePathRevalidation(context,token)",
    '"pending".equals(now.pathProof)',
    "refusing to keep stale Connected proof",
    "failClosedOwnedRuntime(before,token,error)",
    "if(!isSameRevalidation(token))return;",
    "engines.multihop.failClosedForRevalidation()",
    "engines.standardExit.failClosedForRevalidation()",
    "engines.orchestrator.disconnect",
)
revalidator = (ROOT / revalidator_path).read_text(encoding="utf-8")
owned_cleanup = revalidator.split("private void failClosedOwnedRuntime", 1)[1].split(
    "private AndroidHomeStateStore.Snapshot requireSameRevalidation", 1
)[0]
if owned_cleanup.index("if(!isSameRevalidation(token))return;") > owned_cleanup.index("engines.multihop.failClosedForRevalidation()"):
    raise SystemExit("Android stale revalidation token is checked only after multihop teardown")
if owned_cleanup.index("if(!isSameRevalidation(token))return;") > owned_cleanup.index("engines.standardExit.failClosedForRevalidation()"):
    raise SystemExit("Android stale revalidation token is checked only after external-exit teardown")
for path in (
    "android/app/src/main/java/com/eabusham/routervpn/AndroidMultihopRuntime.java",
    "android/app/src/main/java/com/eabusham/routervpn/AndroidStandardExitRuntime.java",
):
    require(path, "failClosedForRevalidation()")
    body = (ROOT / path).read_text(encoding="utf-8")
    section = body.split("failClosedForRevalidation()", 1)[1].split("@Override", 1)[0]
    if "AndroidHomeStateStore." in section:
        raise SystemExit(f"{path}: revalidation teardown must not overwrite the transaction-owned Home state")

# Temporary pre-connect via-entry RTT owns only a short-lived managed WG child;
# it cannot create/overwrite a normal Home session and must be DOWN before the
# picker sees any routed values.
require(
    "android/app/src/main/java/com/eabusham/routervpn/AndroidViaEntryLatencyProbe.java",
    "wireGuard.connectManaged(entry.file",
    "AndroidViaEntryPathMeter.measure(entry, wireGuard",
    "wireGuard.disconnectManaged",
    "Temporary entry did not fully disconnect; candidate results discarded.",
)
require(
    "android/app/src/main/java/com/eabusham/routervpn/AndroidViaEntryPathMeter.java",
    "AndroidPathProbe.prove(entry.file, 8000)",
    "wireGuard.getState() != Tunnel.State.UP",
    "before candidate RTT measurement",
    "after candidate RTT measurement",
    "all results discarded",
)
via_meter=(ROOT/"android/app/src/main/java/com/eabusham/routervpn/AndroidViaEntryPathMeter.java").read_text(encoding="utf-8")
if "AndroidHomeStateStore" in via_meter or "cache(" in via_meter:
    raise SystemExit("Android temporary via-entry RTT must not depend on Home state or direct RTT cache")

standard_runtime_path = "android/app/src/main/java/com/eabusham/routervpn/AndroidStandardExitRuntime.java"
require(
    standard_runtime_path,
    "synchronized boolean isActiveOrTransitioning()",
    "task!=null&&!task.isDone()",
    "if(state==null)return true",
    '!"external".equals(home.logicalMode)',
    "engines.wireGuard.getState()!=com.wireguard.android.backend.Tunnel.State.DOWN",
    "engines.amneziaWG.getState()!=org.amnezia.awg.backend.Tunnel.State.DOWN",
    "runtimeBusy(engines.xray.getState())",
    "exit.protocol",
)
standard_runtime = (ROOT / standard_runtime_path).read_text(encoding="utf-8")
if "protocl" in standard_runtime:
    raise SystemExit(f"{standard_runtime_path}: misspelled protocol field would break Android compilation")

require(
    "android/app/src/main/java/com/eabusham/routervpn/AndroidUnifiedConnectionController.java",
    "boolean isActiveOrTransitioning() { return AndroidVpnMutationGuard.isBusy(activity); }",
)

product_path = "android/app/src/main/java/com/eabusham/routervpn/ProductActivity.java"
require(
    product_path,
    "private boolean mutationBusy()",
    "AndroidVpnMutationGuard.isBusy(this)",
    "nodeButton.setEnabled(!busy)",
    "fastestButton.setEnabled(!busy)",
    "killSwitch.setEnabled(!busy)",
    "multihopToggle.setEnabled(!busy)",
    "modeSpinner.setEnabled(!busy)",
    "dnsSpinner.setEnabled(!busy)",
    "VPN state changed while Fastest was measuring",
    "VPN state changed while permission was open",
    "before redeeming the one-time pairing code",
    "VPN state changed after pairing redemption",
    "before selecting another Router profile",
    "before deleting a Router profile",
    "before saving CUSTOM presets",
    "before deleting CUSTOM presets",
    "before saving multihop",
    "before changing persistent kill-switch policy",
    "before changing DNS",
    "Selecting a target does not connect",
    "values==null||values.isEmpty()",
    "Press Connect when ready.",
    "fastestButton.setText(chosen==null?\"⚡ Fastest ▾\":\"⚡ \"+chosen.name+\" ▾\")",
)
product = (ROOT / product_path).read_text(encoding="utf-8")
try:
    selector = product.split("private void showFastConnectMenu()", 1)[1].split(
        "private void refreshTelemetry", 1
    )[0]
except IndexError as exc:
    raise SystemExit(f"{product_path}: Fastest/node selector handler is missing") from exc
if "connectOrDisconnect()" in selector:
    raise SystemExit(
        f"{product_path}: Fastest/node selection must not auto-connect; Connect is a separate control"
    )
for marker in (
    "telemetry.measureAll(3",
    "if(mutationBusy())",
    "nodeStore.select(pick.id)",
    "prefs().edit().putString(SELECTED_KIND,\"router-vpn\")",
    "refreshAll()",
):
    if marker not in selector:
        raise SystemExit(f"{product_path}: Fastest/node selector missing {marker!r}")

require(
    "android/app/src/main/java/com/eabusham/routervpn/StandardExitActivity.java",
    "AndroidVpnMutationGuard.isBusy(this)",
    "addButton.setEnabled(!mutationBlocked)",
    "directButton.setEnabled(!mutationBlocked)",
    "hoppedButton.setEnabled(!mutationBlocked)",
    "before saving a custom exit",
    "before deleting a custom exit",
    "VPN state changed while permission was open",
)
require(
    "android/app/src/main/java/com/eabusham/routervpn/AndroidProductParity.java",
    "final boolean policyBusy=AndroidVpnMutationGuard.isBusy(activity)",
    "save.setEnabled(!AndroidVpnMutationGuard.isBusy(activity))",
    "Selected Router VPN profile changed while DNS settings were open",
    "persistBenchmark(nodeStore,openedProfileId,result)",
    "JSONObject bundle=activeBundle(store),profile=selectedProfile(bundle)",
    "measurement was not persisted",
)

# Benchmark persistence may update measured fastest metadata, but must never
# silently overwrite the selected dns_host from a stale captured bundle.
dns_body = (
    ROOT / "android/app/src/main/java/com/eabusham/routervpn/AndroidProductParity.java"
).read_text(encoding="utf-8")
persist = dns_body.split("private static void persistBenchmark", 1)[1].split(
    "private static String dnsResultsText", 1
)[0]
if 'profile.put("dns_host"' in persist:
    raise SystemExit(
        "AndroidProductParity.java: DNS benchmark persistence must not rewrite dns_host"
    )

for path in [
    "android/app/src/main/java/com/eabusham/routervpn/AndroidProfileSettingsDialog.java",
    "android/app/src/main/java/com/eabusham/routervpn/AndroidConnectionProfilesDialog.java",
    "android/app/src/main/java/com/eabusham/routervpn/AndroidConnectionProfileStore.java",
]:
    require(path, "AndroidVpnMutationGuard.isBusy")

# The private-control numeric parser is deliberately plain Java so this focused
# behavior test can run on the same JDK used for Android builds without an
# emulator. It proves IPv4/IPv6 parsing remains resolver-free on minSdk 24.
numeric_contract = ROOT / "android" / "test_android_numeric_address.py"
if not numeric_contract.is_file():
    raise SystemExit("missing Android resolver-free numeric-address contract")
subprocess.run([sys.executable, str(numeric_contract)], cwd=ROOT, check=True)

print("Android session mutation truth audit: PASS")
