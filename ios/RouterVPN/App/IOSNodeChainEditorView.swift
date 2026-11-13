import SwiftUI

struct IOSNodeChainEditorView: View {
    @EnvironmentObject private var model: RouterVPNModel
    @Environment(\.dismiss) private var dismiss
    @State private var draft = IOSNodeChainDraft()
    @State private var owner: IOSNodeChainEditorOwner?
    @State private var detail = ""

    private var available: [RouterProfile] {
        model.allNodeProfiles.filter { $0.normalizedNodeKind == "router-vpn" && $0.external == nil || IOSImportedShadowsocksSource.eligible($0) }
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
                                set: { mode in change { try draft.chooseFinalMode(mode) } }
                            )) {
                                ForEach(IOSMultihopNodeSelection.nativeFinalModes, id: \.self) { mode in
                                    Text(IOSMultihopNodeSelection.transportName(mode)).tag(mode)
                                }
                            }
                        } else {
                        Picker("Node \(position + 1)", selection: Binding(
                            get: { draft.nodes[position].id },
                            set: { id in change {
                                try draft.choose(id, at: position)
                                if let profile=available.first(where:{$0.id==id}) { try draft.chooseMode(profile.normalizedNodeKind=="external" ? "shadowsocks" : "wg", at:position) }
                            } }
                        )) {
                            Text("Choose linked node").tag("")
                            ForEach(available.filter { candidate in (candidate.normalizedNodeKind != "external" || draft.nodes.count == 3 && position == 1) && (candidate.id == node.id || !draft.nodes.contains(where: { $0.id == candidate.id })) }) { candidate in
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
                            ForEach(available.first(where:{$0.id==node.id})?.normalizedNodeKind == "external" ? ["shadowsocks"] : IOSMultihopNodeSelection.nativePrefixModes, id: \.self) { mode in
                                Text(IOSMultihopNodeSelection.transportName(mode)).tag(mode)
                            }
                            if !IOSMultihopNodeSelection.supportsNativePrefix(node.mode) && node.mode != "shadowsocks" {
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
                Text("Traffic follows this order through one VPN connection. Paired preceding nodes use WireGuard or AWG2. The selected final Router node can use Shadowsocks 2022 or Hysteria2; Hysteria2 requires Start Layer Off on that final node. A three-node route with one saved Shadowsocks 2022 custom middle (AES-128-GCM, AES-256-GCM or ChaCha20-Poly1305, Start Layer Off) still requires a Shadowsocks 2022 final node.")
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
