#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def require(path: str, *markers: str) -> None:
    body = (ROOT / path).read_text(encoding="utf-8")
    missing = [marker for marker in markers if marker not in body]
    if missing:
        raise SystemExit(f"{path}: missing iOS session-mutation marker(s): {missing}")


require(
    "ios/RouterVPN/App/RouterVPNModel.swift",
    "@Published var tunnelTransitioning",
    "var profileMutationBlocked: Bool",
    "connected || tunnelTransitioning",
    "status == .connecting || status == .disconnecting || status == .reasserting",
)
require(
    "ios/RouterVPN/App/IOSUnifiedProductView.swift",
    "connectionStateTitle",
    "connectionButtonTitle",
    ".disabled(model.iosUserDisconnectInProgress)",
    ".disabled(model.profileMutationBlocked)",
    "if model.tunnelTransitioning || model.connected { model.disconnect(); return }",
    "Cancel & disconnect",
    "guard !parent.model.profileMutationBlocked",
    "setUnifiedQuickKillSwitch",
    "unifiedSetDNSMode",
    "Disconnect or let the active VPN transition finish before changing Mode or CUSTOM presets",
    "guard available, !model.profileMutationBlocked",
    "Save & Connect",
    "before saving a CUSTOM preset",
    "Toggle(\"Kill switch\"",
)
require(
    "ios/RouterVPN/App/IOSDNSPolicyView.swift",
    ".disabled(model.profileMutationBlocked)",
    "guard !model.profileMutationBlocked",
    "@StateObject private var nativeMeasurement = IOSDNSMeasurementClient.shared",
    "@State private var benchmarkSessionInvalidated = false",
    ".onChange(of: model.connected)",
    ".onChange(of: model.tunnelTransitioning)",
    ".onChange(of: model.activeEngine)",
    ".onChange(of: model.activeRawProfile)",
    "!benchmarkSessionInvalidated",
    "let captured = capture",
    "try captured.requireCurrent(model: model)",
    "try nativeMeasurement.captureForEditor(model: model, result: value)",
    "guard generation == legacyGeneration, !benchmarkSessionInvalidated",
    "legacyTask?.cancel()",
    "Use fastest \\(fastest.transportLabel) in editor",
    "Disconnect to save this DNS choice",
    "try measuredSource?.requireSources(model: model)",
    "DNS comparison discarded: the request failed or the captured VPN selection, session or network changed.",
)
# Comparison is an ephemeral captured transaction. The old audit expected the
# UDP loop to write unlabelled fastest fields into a freshly reloaded bundle;
# both native and retained Router comparisons now require an explicit Save.
dns_view = (ROOT / "ios/RouterVPN/App/IOSDNSPolicyView.swift").read_text()
for forbidden in (".fastestDNSHost =", ".fastestDNSLatencyMs =", ".dnsResults ="):
    assert forbidden not in dns_view, "DNS comparison cannot persist an unlabelled result: " + forbidden
comparison = dns_view.split("    private func retest(", 1)[1].split("    private func usePreset(", 1)[0]
assert "model.importBundle(" not in comparison and "savePolicy()" not in comparison
require(
    "ios/RouterVPN/App/IOSDNSMeasurementClient.swift",
    "model.activeSessionIdentity == identity", "model.iosConnectGeneration == decision",
    "model.selectedMode == mode", "model.selectedLogicalMode == logicalMode", "model.auto == auto",
    "try Self.encoded(bundle) == selection", "selected.id == nodeID",
    "IOSViaEntryNetwork.shared.current == network",
    "try model.externalTorEntryData(source: bundle) == identity.entryBundleData",
    "try Self.canonical(source) == Self.canonical(identity.bundleData)",
    "try model.iosSpeedLabOwnership.begin", "defer { model.iosSpeedLabOwnership.finish(owner) }",
    "try await IOSMTUControl.withHold(model: model)", "try await owned.run(current:",
    "IOSMTUControl.current(binding, model: model)",
    "IOSDNSRetirementReceipts.shared.drained(providerSession: information.session_id",
    "static let shared = IOSDNSMeasurementClient()", "self.cleanupPending = true",
)
require(
    "ios/RouterVPN/App/IOSDNSMeasurement.swift",
    "value.native_session_id == owner.native_session_id", "value.session_id == owner.session_id",
    "let cleanup = Task { @MainActor in await self.drain(pending: pending) }", "await cleanup.value",
    "value.complete && value.drained && value.results.isEmpty && value.failure?.isEmpty == false",
    'status("dns-measure-drain")', "samples == 3, failed == 0", "median_ms.isFinite, median_ms > 0",
)
require(
    "ios/RouterVPN/PacketTunnel/RouterVPNDNSMeasurementSession.swift",
    "reservations.insert(request)", "reservations.count < 128", "reservations.contains(request)",
    "try native.drain(request)", "try native.close()", "try persist(data, request: request)",
    "IOSDNSRetirementReceipts.shared.requireAvailable()",
    "scheduleRetirementRetry()", "repeating: .seconds(2)", "retirementRetry?.cancel()",
)
require("ios/RouterVPN/test_runtime_selection_contract.py",
        "deploy/test_ios_dns_measurement.py", "deploy/test_ios_dns_retirement_receipts.py")
require("deploy/test_ios_dns_measurement.py",
        "native workers retain host transaction and MTU hold",
        "new Connect waits for actual DNS drain", "lost Start is actually tombstoned and drained",
        "stopped provider recovery has exact native identity",
        "stale Fastest click leaves editor fields unchanged",
        "explicit Save rejects a changed linked entry without writes",
        "retained provider retry recovers transient storage without IPC",
        "lost Start reservation discarded", "native proof session not bound")
require(
    "ios/RouterVPN/App/IOSProfileSettingsView.swift",
    ".disabled(model.profileMutationBlocked)",
    "guard !model.profileMutationBlocked",
)
require(
    "ios/RouterVPN/App/IOSConnectionProfilesView.swift",
    "model.profileMutationBlocked",
    "delete(model: RouterVPNModel",
    "NetworkExtension is connecting/reasserting/disconnecting",
)
require(
    "ios/RouterVPN/App/RouterVPNModelExternal.swift",
    "guard !profileMutationBlocked",
    "tunnelTransitioning = true",
    "let generation = UUID(); iosConnectGeneration = generation",
    "try requireExternalPreparation(generation, source: bundle, entry: capturedEntry, manager: manager)",
    "guard try externalTorEntryData(source: source) == entry else { throw CancellationError() }",
    'saved.providerConfiguration?[entryBundleKey] as? Data == capturedEntry',
    'saved.providerConfiguration?[entryModeKey] as? String',
    'saved.providerConfiguration?[tor ? "external_entry_bundle" : "tor_entry_bundle"] == nil',
    "await refreshTunnelStatus()",
    "return IOSDNSRuntimePolicy.selectedProfile(in: bundle)",
    "before linking node data",
)

# Cancellation is an allowed transition; profile mutation is not. The prior
# blanket disabled-state marker prevented the user from stopping a trial and
# its unconditional defer unlocked unknown status after a failed readback.
model = (ROOT / "ios/RouterVPN/App/RouterVPNModel.swift").read_text()
disconnect = model.split("    func disconnect() {", 1)[1].split("    private func completeUserDisconnect()", 1)[0]
assert "guard !userDisconnectInProgress" in disconnect
assert "iosConnectGeneration = UUID()" in disconnect
assert "guard !tunnelTransitioning" not in disconnect
external = (ROOT / "ios/RouterVPN/App/RouterVPNModelExternal.swift").read_text()
assert "defer { tunnelTransitioning = false }" not in external
require("ios/RouterVPN/test_runtime_selection_contract.py", "deploy/test_ios_owned_strategy_app.py")
require("deploy/test_ios_owned_strategy_app.py",
        "cancel during external save cannot start later",
        "unknown external status keeps settings locked",
        "unknown multihop status keeps settings locked")
require(
    "ios/RouterVPN/App/RouterVPNModelNodeManagement.swift",
    "before removing a linked node",
    "before editing node metadata",
    "profileMutationBlocked",
)
require(
    "ios/RouterVPN/App/RouterVPNModelLinking.swift",
    "before pairing another node",
    "profileMutationBlocked",
)
require(
    "ios/RouterVPN/App/NodeManagerSheet.swift",
    "before pairing, importing, selecting, removing, or editing linked nodes",
    ".disabled(model.profileMutationBlocked)",
    "before importing node data",
    "before editing node metadata",
)

print("iOS/iPadOS session mutation truth audit: PASS")
