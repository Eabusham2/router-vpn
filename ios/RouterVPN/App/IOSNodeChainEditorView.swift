import SwiftUI

struct IOSNodeChainEditorView: View {
    @EnvironmentObject private var model: RouterVPNModel
    @Environment(\.dismiss) private var dismiss
    @State private var draft = IOSNodeChainDraft()
    @State private var owner: IOSNodeChainEditorOwner?
    @State private var detail = ""

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
                            if !IOSMultihopNodeSelection.supportsNativePrefix(node.mode) && !["shadowsocks", "socks5", "http-connect", "https-connect"].contains(node.mode) {
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
            Section("Local execution") {
                Text("Traffic follows this order through one VPN connection. Paired preceding nodes use WireGuard or AWG2. The selected final Router node can use Shadowsocks 2022 or Hysteria2; Hysteria2 requires Start Layer Off on that final node. A three-node route supports one saved SOCKS5, HTTP/HTTPS CONNECT or Shadowsocks 2022 custom middle with Start Layer Off and a Shadowsocks 2022 final node. SOCKS5 and CONNECT retain their original literal server address and credentials; HTTPS CONNECT also retains verified TLS and SNI. CONNECT requires the paired final node’s captured SS UoT-v2 service declaration and preserves its selected DNS.")
                Text("Each node keeps its own saved credentials, Start Layer and protection settings. DNS uses the final node. Every node must pass verification before Connected.")
                    .font(.caption).foregroundStyle(.secondary)
                Button("Save ordered route") {
                    do { guard let owner else { return }; try model.saveIOSNodeChain(draft.nodes, owner: owner); dismiss() }
                    catch { detail = error.localizedDescription }
                }.disabled(!draft.canSave || owner == nil)
                if !detail.isEmpty { Text(detail).font(.caption) }
            }
        }
        .disabled(model.profileMutationBlocked)
        .navigationTitle("Ordered nodes")
        .onAppear {
            let selected = model.selectedNodeProfile
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
