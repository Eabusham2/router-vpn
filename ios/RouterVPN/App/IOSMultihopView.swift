import Foundation
import SwiftUI

@MainActor
extension RouterVPNModel {
    /// Return the complete *entry's* private bundle, never the selected exit's
    /// raw files with a different display id. Capture before suspension/start.
    func iosMultihopEntryBundle(for exitBundle: ClientBundle) throws -> ClientBundle {
        guard let exit = exitBundle.routerProfiles.first(where: { $0.id == exitBundle.selectedRouterID }),
              exit.normalizedNodeKind == "router-vpn", exit.multihopEnabled == true,
              exit.multihopExitID == exit.id, let entryID = exit.multihopEntryID, entryID != exit.id,
              let mode = exit.multihopExitMode, ["shadowsocks", "hysteria2"].contains(mode),
              let data = IOSNodeBundleStore.shared.bundleData(containing: entryID, current: bundle),
              data.count <= 32 * 1024 * 1024 else {
            throw iosMultihopError("The saved multihop entry/exit is missing or no longer linked. Choose the graph again.")
        }
        var entry = try JSONDecoder().decode(ClientBundle.self, from: data)
        guard let profile = entry.routerProfiles.first(where: { $0.id == entryID }),
              profile.normalizedNodeKind == "router-vpn",
              let proof = profile.nodeProofID, !proof.isEmpty, proof != exit.nodeProofID,
              let raw = entry.profiles["wg"]?["wg.conf"],
              let config = Data(base64Encoded: raw), !config.isEmpty, config.count <= 1024 * 1024 else {
            throw iosMultihopError("Choose a different paired Router VPN entry with its own WireGuard profile.")
        }
        for node in [profile, exit] {
            guard ["", "off", "none", "disabled"].contains((node.startLayer ?? "off").lowercased()) else {
                throw iosMultihopError("Additional Start Layers are not yet composed by this multihop path; turn them off for the selected nodes.")
            }
        }
        entry.selectedRouterID = profile.id
        entry.nodeProofID = proof
        entry.endpoint = profile.endpoint
        // Readiness of the exit is checked separately from existence of entry
        // data. PacketTunnel validates WG keys/routes and proves both nodes.
        _ = try IOSRuntimeSelector.selectRaw(bundle: exitBundle, rawProfileID: mode)
        return entry
    }

    func saveIOSMultihop(enabled: Bool, entryID: String, exitID: String, exitMode: String) throws {
        guard !profileMutationBlocked else { throw iosMultihopError("Disconnect before changing the active graph.") }
        if !enabled {
            guard var value = bundle,
                  let index = value.routerProfiles.firstIndex(where: { $0.id == value.selectedRouterID }) else {
                throw iosMultihopError("Select a Router VPN node first.")
            }
            value.routerProfiles[index].multihopEnabled = false
            try importBundle(JSONEncoder().encode(value))
            message = "Multihop disabled. The next Connect uses the selected normal mode."
            return
        }
        guard ["shadowsocks", "hysteria2"].contains(exitMode), entryID != exitID,
              let data = IOSNodeBundleStore.shared.bundleData(containing: exitID, current: bundle) else {
            throw iosMultihopError("Choose two different linked Router VPN nodes and an exit transport.")
        }
        var value = try JSONDecoder().decode(ClientBundle.self, from: data)
        guard let index = value.routerProfiles.firstIndex(where: { $0.id == exitID }),
              value.routerProfiles[index].normalizedNodeKind == "router-vpn" else {
            throw iosMultihopError("This graph needs a Router VPN exit, not an unrelated external-only node.")
        }
        value.selectedRouterID = exitID
        value.routerProfiles[index].multihopEnabled = true
        value.routerProfiles[index].multihopEntryID = entryID
        value.routerProfiles[index].multihopExitID = exitID
        value.routerProfiles[index].multihopExitMode = exitMode
        let exit = value.routerProfiles[index]
        value.nodeProofID = exit.nodeProofID ?? value.nodeProofID
        value.endpoint = exit.endpoint
        value.routerAPI = exit.routerAPI
        value.apiToken = exit.apiToken
        value.adGuardIPv4 = exit.adGuardIPv4
        value.adGuardIPv6 = exit.adGuardIPv6
        value.socks5Host = exit.socksHost
        value.socks5Port = exit.socksPort
        value = try IOSDNSRuntimePolicy.patch(value)
        _ = try iosMultihopEntryBundle(for: value)
        // Store the old home before selecting the new exit. Node secrets remain
        // in the existing per-node store; connection profiles only reference ids.
        try linkNodeBundle(JSONEncoder().encode(value))
        message = "Saved WireGuard entry → \(exitMode) exit. Press Connect to start and prove both nodes."
    }

    private func iosMultihopError(_ text: String) -> NSError {
        NSError(domain: "RouterVPN.Multihop", code: 1, userInfo: [NSLocalizedDescriptionKey: text])
    }
}

struct IOSMultihopView: View {
    @EnvironmentObject var model: RouterVPNModel
    @Environment(\.dismiss) private var dismiss
    @State private var enabled = false
    @State private var entryID = ""
    @State private var exitID = ""
    @State private var exitMode = "shadowsocks"
    @State private var detail = ""
    private var nodes: [RouterProfile] { model.allNodeProfiles.filter { $0.normalizedNodeKind == "router-vpn" } }

    var body: some View {
        NavigationStack {
            Form {
                Section("Entry → exit") {
                    Toggle("Use multihop", isOn: $enabled)
                    Picker("WireGuard entry", selection: $entryID) {
                        Text("Choose entry").tag("")
                        ForEach(nodes) { node in Text(node.name.isEmpty ? node.id : node.name).tag(node.id) }
                    }
                    Picker("Exit node", selection: $exitID) {
                        Text("Choose exit").tag("")
                        ForEach(nodes) { node in Text(node.name.isEmpty ? node.id : node.name).tag(node.id) }
                    }
                    Picker("Exit transport", selection: $exitMode) {
                        Text("Shadowsocks 2022").tag("shadowsocks")
                        Text("Hysteria2").tag("hysteria2")
                    }
                    Text("One PacketTunnel owns both hops. Exit transport traffic goes through the entry, DNS goes through the exit, and each node is proved separately before Connected.")
                        .font(.caption).foregroundStyle(.secondary)
                }.disabled(model.profileMutationBlocked)
                Section("Connection requirements") {
                    Text("Link at least two Router VPN homes. This path uses a full-route raw WireGuard entry and a self-contained Shadowsocks or Hysteria2 exit. Both transport endpoints and the selected DNS resolver must be literal IP addresses; additional Start Layers, DAITA and Jumbo must be off. LAN-Off filtering is not yet supported by this graph and is rejected rather than ignored. Other graphs remain unfinished, not simulated.")
                        .font(.caption).foregroundStyle(.secondary)
                    Text("Saving selects the exit node without connecting. The stronger kill-switch requirement of either node is used for the connection. Saved graph choices do not prove a live path.")
                        .font(.caption).foregroundStyle(.secondary)
                    Button("Save graph") {
                        do { try model.saveIOSMultihop(enabled: enabled, entryID: entryID, exitID: exitID, exitMode: exitMode); dismiss() }
                        catch { detail = error.localizedDescription }
                    }.disabled(model.profileMutationBlocked || (enabled && (entryID.isEmpty || exitID.isEmpty || entryID == exitID)))
                    if !detail.isEmpty { Text(detail).font(.caption) }
                }
            }
            .navigationTitle("Multihop")
            .toolbar { ToolbarItem(placement: .confirmationAction) { Button("Done") { dismiss() } } }
            .onAppear {
                let profile = model.selectedNodeProfile
                enabled = profile?.multihopEnabled ?? false
                entryID = profile?.multihopEntryID ?? ""
                exitID = profile?.multihopExitID ?? (profile?.id ?? "")
                exitMode = profile?.multihopExitMode ?? "shadowsocks"
            }
        }
    }
}
