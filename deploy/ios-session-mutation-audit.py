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
    "let benchmarkNodeID = profile.id",
    "@State private var benchmarkSessionInvalidated = false",
    ".onChange(of: model.connected)",
    ".onChange(of: model.tunnelTransitioning)",
    ".onChange(of: model.activeEngine)",
    ".onChange(of: model.activeRawProfile)",
    "!benchmarkSessionInvalidated",
    "freshBundle.selectedRouterID == benchmarkNodeID",
    "freshBundle.routerProfiles.firstIndex(where: { $0.id == benchmarkNodeID })",
    "DNS Retest discarded: the VPN session changed during measurement.",
    "DNS Retest discarded: selected node or VPN session changed before results could be saved.",
)
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
