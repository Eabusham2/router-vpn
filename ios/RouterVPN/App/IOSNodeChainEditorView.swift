import SwiftUI

struct IOSNodeChainEditorView: View {
    @EnvironmentObject private var model: RouterVPNModel
    @Environment(\.dismiss) private var dismiss
    @State private var draft = IOSNodeChainDraft()
    @State private var owner: IOSNodeChainEditorOwner?
    @State private var detail = ""
    @State private var execution = "local"

    private var available: [RouterProfile] {
        model.iosNodeChainEditorProfiles(owner: owner)
    }

    private var finalModes: [String] {
        IOSNodeChainEditorVisible.finalModes(available.first(where: { $0.id == draft.controlID }), nodes: draft.nodes)
    }

    var body: some View {
        Form {
            Section("Nodes in connection order") {
                ForEach(Array(draft.nodes.enumerated()), id: \.offset) { position, node in
                    VStack(alignment: .leading, spacing: 8) {
                        if position == draft.nodes.count - 1 {
                            LabeledContent("Selected final node", value: available.first(where: { $0.id == node.id })?.name ?? node.id)
                            Text("Choose a different final node from the main node selector before opening this editor.")
                                .font(.caption).foregroundStyle(.secondary)
                            Picker("Final transport", selection: Binding(
                                get: { draft.nodes[position].mode },
                                set: { mode in change {
                                    try IOSNodeChainEditorVisible.requireFinalMode(mode,
                                        profile: available.first(where: { $0.id == node.id }), nodes: draft.nodes)
                                    try draft.chooseFinalMode(mode)
                                } }
                            )) {
                                ForEach(finalModes, id: \.self) { mode in
                                    Text(IOSMultihopNodeSelection.transportName(mode)).tag(mode)
                                }
                                if !finalModes.contains(node.mode) {
                                    Text("Unavailable: \(IOSMultihopNodeSelection.transportName(node.mode))")
                                        .tag(node.mode).disabled(true)
                                }
                            }
                        } else {
                        Picker("Node \(position + 1)", selection: Binding(
                            get: { draft.nodes[position].id },
                            set: { id in change {
                                try draft.choose(id, at: position)
                                if let profile=available.first(where:{$0.id==id}) { try draft.chooseMode(profile.normalizedNodeKind=="external" ? (profile.external?.protocolName ?? "") : "wg", at:position) }
                            } }
                        )) {
                            Text("Choose linked node").tag("")
                            ForEach(IOSNodeChainEditorVisible.candidates(available, nodes: draft.nodes, position: position)) { candidate in
                                Text(candidate.name.isEmpty ? candidate.id : candidate.name).tag(candidate.id)
                            }
                            if !node.id.isEmpty && !available.contains(where: { $0.id == node.id }) {
                                Text("Missing linked node").tag(node.id)
                            }
                        }
                        Picker("Transport", selection: Binding(
                            get: { draft.nodes[position].mode },
                            set: { mode in change { try draft.chooseMode(mode, at: position) } }
                        )) {
                            ForEach(IOSNodeChainEditorVisible.modes(available.first(where:{$0.id==node.id})), id: \.self) { mode in
                                Text(IOSMultihopNodeSelection.transportName(mode)).tag(mode)
                            }
                            if !IOSMultihopNodeSelection.supportsNativePrefix(node.mode) && !["shadowsocks", "socks5", "http-connect", "https-connect", "openvpn"].contains(node.mode) {
                                Text(IOSMultihopNodeSelection.transportName(node.mode)).tag(node.mode)
                            }
                        }
                        }
                        Text(IOSMultihopNodeSelection.transportName(node.mode))
                            .font(.caption).foregroundStyle(.secondary)
                        if position < draft.nodes.count - 1 { HStack {
                            Button("Earlier") { change { try draft.move(from: position, to: position - 1) } }.disabled(position == 0)
                            Button("Later") { change { try draft.move(from: position, to: position + 1) } }.disabled(position >= draft.nodes.count - 2)
                            Spacer()
                            Button("Remove", role: .destructive) { change { try draft.remove(at: position) } }.disabled(draft.nodes.count <= 2)
                        }.buttonStyle(.borderless) }
                    }
                }
                Button("Add preceding node") { change { try draft.append() } }.disabled(draft.nodes.count >= IOSMultihopNodeSelection.maximumNodes)
            }
            Section("Execution") {
                Picker("Execution", selection: $execution) {
                    Text("Local").tag("local")
                    if IOSMultihopNodeSelection.supportsServerExecution(draft.nodes) {
                        Text("Server").tag("server")
                        Text("Compare").tag("auto")
                    } else if execution != "local" {
                        Text("Unavailable saved execution").tag(execution).disabled(true)
                    }
                }
                Text("Server and Compare support paired WireGuard or AWG2 preceding nodes and a paired Shadowsocks final. One custom Shadowsocks 2022 node can appear immediately before the final in a three-to-eight-node route. HTTP/HTTPS CONNECT requires exactly three nodes. Custom nodes retain their original literal server address. Compare proves both choices before retaining a winner.")
                Text("Traffic follows this order through one VPN connection. Paired preceding nodes use WireGuard or AWG2. The selected final Router node can use Shadowsocks 2022 or Hysteria2; Hysteria2 requires Start Layer Off on that final node. A route supports one saved Shadowsocks 2022, SOCKS5, HTTP/HTTPS CONNECT or OpenVPN node after one to six paired prefixes, with Start Layer Off on that custom node and a Shadowsocks 2022 final. An imported Shadowsocks hostname retains its saved Custom TCP transport resolver through the original preceding prefix; application DNS remains on the final node. OpenVPN retains its original single literal TCP or UDP remote and connected native owner. SOCKS5 and CONNECT retain their original literal server address and credentials; HTTPS CONNECT also retains verified TLS and SNI. CONNECT requires the paired final node’s captured SS UoT-v2 service declaration and preserves its selected DNS.")
                Text("Each node keeps its own saved credentials, Start Layer and protection settings. DNS uses the final node. Every node must pass verification before Connected.")
                    .font(.caption).foregroundStyle(.secondary)
                Button("Save ordered route") {
                    do { guard let owner else { return }; try model.saveIOSNodeChain(draft.nodes, owner: owner, execution: execution); dismiss() }
                    catch { detail = error.localizedDescription }
                }.disabled(!draft.canSave || owner == nil)
                if !detail.isEmpty { Text(detail).font(.caption) }
            }
        }
        .disabled(model.profileMutationBlocked)
        .navigationTitle("Ordered nodes")
        .onAppear {
            let selected = model.selectedNodeProfile
            execution = selected?.multihopExecution ?? "local"
            draft = IOSNodeChainDraft(saved: selected?.multihopNodes, finalID: selected?.normalizedNodeKind == "router-vpn" ? selected?.id ?? "" : "")
            do { owner = try model.captureIOSNodeChainEditorOwner(); detail = "" }
            catch { owner = nil; detail = error.localizedDescription }
        }
    }

    private func change(_ action: () throws -> Void) {
        do { try action(); detail = "" }
        catch { detail = error.localizedDescription }
    }
}
