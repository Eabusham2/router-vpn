import Foundation
import SwiftUI

@MainActor
extension RouterVPNModel {
    /// Return the complete *entry's* private bundle, never the selected exit's
    /// raw files with a different display id. Capture before suspension/start.
    func iosMultihopEntryBundle(for exitBundle: ClientBundle) throws -> ClientBundle {
        guard let exit = IOSDNSRuntimePolicy.selectedProfile(in: exitBundle),
              exit.normalizedNodeKind == "router-vpn", exit.multihopEnabled == true,
              exit.multihopExitID == exit.id, let entryID = exit.multihopEntryID, entryID != exit.id,
              let mode = exit.multihopExitMode, ["wg", "awg2-fast", "awg2-strong", "wg-pq", "awg2-pq", "shadowsocks", "hysteria2", "reality-vision", "reality-pq-vision", "reality-xhttp", "max-tls-wg", "max-tls-awg", "max-quic-wg", "max-quic-awg", "naive-h2", "naive-h3"].contains(mode),
              let data = IOSNodeBundleStore.shared.bundleData(containing: entryID, current: bundle),
              data.count <= 32 * 1024 * 1024 else {
            throw iosMultihopError("The saved multihop entry/exit is missing or no longer linked. Choose the graph again.")
        }
        let entryMode = exit.multihopEntryMode ?? "wg"
        guard ["wg","awg2-fast","awg2-strong","wg-pq","awg2-pq","shadowsocks","hysteria2","reality-vision","reality-pq-vision","reality-xhttp","max-tls-wg","max-tls-awg","max-quic-wg","max-quic-awg","naive-h2","naive-h3"].contains(entryMode) else { throw iosMultihopError("Unknown saved entry transport.") }
        let entryAsset = IOSNativeMAXProfile.modeIDs.contains(entryMode) ? (entryMode.hasSuffix("-awg") ? "awg.conf" : "wg.conf") : ["wg", "wg-pq"].contains(entryMode) ? "wg.conf" : (["awg2-fast", "awg2-strong", "awg2-pq"].contains(entryMode) ? "awg.conf" : (["reality-vision", "reality-pq-vision", "reality-xhttp"].contains(entryMode) ? "xray.json" : "sing-box.json"))
        var entry = try JSONDecoder().decode(ClientBundle.self, from: data)
        guard entry.routerProfiles.filter({ $0.id == entryID }).count == 1,
              let profile = entry.routerProfiles.first(where: { $0.id == entryID }),
              profile.normalizedNodeKind == "router-vpn",
              let proof = profile.nodeProofID, !proof.isEmpty, proof != exit.nodeProofID,
              let raw = entry.profiles[entryMode]?[entryAsset],
              let config = Data(base64Encoded: raw), !config.isEmpty, config.count <= 4 * 1024 * 1024 else {
            throw iosMultihopError("Choose a different paired Router VPN entry with its own selected native entry profile.")
        }
        if IOSNativeMAXProfile.modeIDs.contains(entryMode) {
            _ = try IOSNativeMAXProfile.decode(mode: entryMode, encoded: entry.profiles[entryMode] ?? [:])
        } else if IOSNativePQProfile.modeIDs.contains(entryMode) {
            // Readiness inspects only this home's complete generated assets;
            // native protocol handles are created later inside PacketTunnel.
            _ = try IOSNativePQProfile.decode(mode: entryMode, encoded: entry.profiles[entryMode] ?? [:])
        }
        let capturedProfile = try JSONSerialization.jsonObject(with: JSONEncoder().encode(profile)) as! [String: Any]
        let capturedExit = try JSONSerialization.jsonObject(with: JSONEncoder().encode(exit)) as! [String: Any]
        if IOSNativeMAXProfile.modeIDs.contains(entryMode) { _ = try IOSMultihopStartLayer.selected(capturedProfile) }
        else { _ = try IOSMultihopStartLayer.capture(profile: capturedProfile, profiles: entry.profiles) }
        if IOSNativeMAXProfile.modeIDs.contains(mode) { _ = try IOSMultihopStartLayer.selected(capturedExit) }
        else { _ = try IOSMultihopStartLayer.capture(profile: capturedExit, profiles: exitBundle.profiles) }
        entry.selectedRouterID = profile.id
        entry.nodeProofID = proof
        entry.endpoint = profile.endpoint
        // Readiness of the exit is checked separately from existence of entry
        // data. PacketTunnel validates WG keys/routes and proves both nodes.
        _ = try IOSRuntimeSelector.selectRaw(bundle: exitBundle, rawProfileID: mode)
        return entry
    }

    func saveIOSMultihop(enabled: Bool, entryID: String, exitID: String, exitMode: String, execution: String = "local", entryMode: String = "wg") throws {
        guard ["wg","awg2-fast","awg2-strong","wg-pq","awg2-pq","shadowsocks","hysteria2","reality-vision","reality-pq-vision","reality-xhttp","max-tls-wg","max-tls-awg","max-quic-wg","max-quic-awg","naive-h2","naive-h3"].contains(entryMode) else { throw iosMultihopError("Choose an exact native entry transport.") }
        guard ["local", "server", "auto"].contains(execution) else { throw iosMultihopError("Choose Local, Server, or Compare both.") }
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
        guard ["wg", "awg2-fast", "awg2-strong", "wg-pq", "awg2-pq", "shadowsocks", "hysteria2", "reality-vision", "reality-pq-vision", "reality-xhttp", "max-tls-wg", "max-tls-awg", "max-quic-wg", "max-quic-awg", "naive-h2", "naive-h3"].contains(exitMode), entryID != exitID,
              let data = IOSNodeBundleStore.shared.bundleData(containing: exitID, current: bundle) else {
            throw iosMultihopError("Choose two different linked Router VPN nodes and an exit transport.")
        }
        var value = try JSONDecoder().decode(ClientBundle.self, from: data)
        guard value.routerProfiles.filter({ $0.id == exitID }).count == 1,
              let index = value.routerProfiles.firstIndex(where: { $0.id == exitID }),
              value.routerProfiles[index].normalizedNodeKind == "router-vpn" else {
            throw iosMultihopError("This graph needs a Router VPN exit, not an unrelated external-only node.")
        }
        value.selectedRouterID = exitID
        value.routerProfiles[index].multihopEnabled = true
        value.routerProfiles[index].multihopEntryID = entryID
        value.routerProfiles[index].multihopEntryMode = entryMode
        value.routerProfiles[index].multihopExitID = exitID
        value.routerProfiles[index].multihopExitMode = exitMode
        value.routerProfiles[index].multihopExecution = execution
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
        message = "Saved \(entryMode) entry → \(exitMode) exit. Press Connect to start and prove both nodes."
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
    @State private var entryMode = "wg"
    @State private var exitID = ""
    @State private var exitMode = "shadowsocks"
    @State private var execution = "local"
    @State private var detail = ""
    private var nodes: [RouterProfile] { model.allNodeProfiles.filter { $0.normalizedNodeKind == "router-vpn" } }

    var body: some View {
        NavigationStack {
            Form {
                Section("Entry → exit") {
                    Toggle("Use multihop", isOn: $enabled)
                    Picker("Entry node", selection: $entryID) {
                        Text("Choose entry").tag("")
                        ForEach(nodes) { node in Text(node.name.isEmpty ? node.id : node.name).tag(node.id) }
                    }
                    Picker("Entry transport", selection: $entryMode) {
                        Text("WireGuard").tag("wg")
                        Text("AmneziaWG Fast").tag("awg2-fast")
                        Text("AmneziaWG Strong").tag("awg2-strong")
                        Text("WireGuard + Rosenpass PQ").tag("wg-pq")
                        Text("AmneziaWG + Rosenpass PQ").tag("awg2-pq")
                        Text("Shadowsocks").tag("shadowsocks")
                        Text("Hysteria2").tag("hysteria2")
                        Text("Naive HTTP/2").tag("naive-h2")
                        Text("Naive HTTP/3").tag("naive-h3")
                        Text("REALITY Vision").tag("reality-vision")
                        Text("PQ REALITY Vision").tag("reality-pq-vision")
                        Text("REALITY XHTTP").tag("reality-xhttp")
                        Text("MAX TLS — WG + PQ").tag("max-tls-wg")
                        Text("MAX TLS — AWG + PQ").tag("max-tls-awg")
                        Text("MAX QUIC — WG + PQ").tag("max-quic-wg")
                        Text("MAX QUIC — AWG + PQ").tag("max-quic-awg")
                    }
                    Picker("Exit node", selection: $exitID) {
                        Text("Choose exit").tag("")
                        ForEach(nodes) { node in Text(node.name.isEmpty ? node.id : node.name).tag(node.id) }
                    }
                    Picker("Exit transport", selection: $exitMode) {
                        Text("WireGuard").tag("wg")
                        Text("AmneziaWG Fast").tag("awg2-fast")
                        Text("AmneziaWG Strong").tag("awg2-strong")
                        Text("WireGuard + Rosenpass PQ").tag("wg-pq")
                        Text("AmneziaWG + Rosenpass PQ").tag("awg2-pq")
                        Text("Shadowsocks 2022").tag("shadowsocks")
                        Text("Hysteria2").tag("hysteria2")
                        Text("Naive HTTP/2").tag("naive-h2")
                        Text("Naive HTTP/3").tag("naive-h3")
                        Text("REALITY Vision").tag("reality-vision")
                        Text("PQ REALITY Vision").tag("reality-pq-vision")
                        Text("REALITY XHTTP").tag("reality-xhttp")
                        Text("MAX TLS — WG + PQ").tag("max-tls-wg")
                        Text("MAX TLS — AWG + PQ").tag("max-tls-awg")
                        Text("MAX QUIC — WG + PQ").tag("max-quic-wg")
                        Text("MAX QUIC — AWG + PQ").tag("max-quic-awg")
                    }
                    Picker("Execution", selection: $execution) {
                        Text("Local — exit on this device").tag("local")
                        Text("Server — exit on entry node").tag("server")
                        Text("Compare both — lower valid average").tag("auto")
                    }
                    Text("Compare uses (last-node response time + one random external-server response time) / 2. Either timeout rejects the candidate. Server execution explicitly trusts the entry node with the exit tunnel; paired exit credentials must already be provisioned there.")
                        .font(.caption).foregroundStyle(.secondary)
                    Text("One PacketTunnel owns both hops. Exit transport traffic goes through the entry, DNS goes through the exit, and each node is proved separately before Connected.")
                        .font(.caption).foregroundStyle(.secondary)
                }.disabled(model.profileMutationBlocked)
                Section("Connection requirements") {
                    Text("Link at least two Router VPN homes. This path uses a full-route WireGuard, native AmneziaWG Fast/Strong, WireGuard/AmneziaWG with Rosenpass PQ, Shadowsocks, Hysteria2, Naive HTTP/2 or HTTP/3, or native REALITY/PQ/XHTTP entry and a WireGuard/AmneziaWG (with or without Rosenpass PQ), self-contained Shadowsocks, Hysteria2, Naive HTTP/2 or HTTP/3, or native REALITY/PQ/XHTTP exit. Transport endpoints are literal IP addresses. Custom UDP/TCP, DoT, DoH and DoH3 DNS stay inside the exit; resolver hostnames use a saved literal bootstrap over that same path. Both nodes' LAN-Off and IPv6-Off policies are enforced. An entry AES or AES+XOR Start Layer stays on the captured entry for Local, Server and Compare. Exit AES or AES+XOR uses the same captured exit in Local, Server and Compare; Server requires matching private relay provisioning. Bounded padding is available per node; Jumbo applies only to a compatible proxy exit, not a raw entry.")
                        .font(.caption).foregroundStyle(.secondary)
                    Text("Saving selects the exit node without connecting. The stronger kill-switch requirement of either node is used for the connection. Saved graph choices do not prove a live path.")
                        .font(.caption).foregroundStyle(.secondary)
                    Button("Save graph") {
                        do { try model.saveIOSMultihop(enabled: enabled, entryID: entryID, exitID: exitID, exitMode: exitMode, execution: execution, entryMode: entryMode); dismiss() }
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
                entryMode = profile?.multihopEntryMode ?? "wg"
                exitID = profile?.multihopExitID ?? (profile?.id ?? "")
                exitMode = profile?.multihopExitMode ?? "shadowsocks"
                execution = profile?.multihopExecution ?? "local"
            }
        }
    }
}
