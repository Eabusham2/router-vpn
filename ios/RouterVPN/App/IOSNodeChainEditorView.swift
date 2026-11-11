import SwiftUI

struct IOSNodeChainEditorView: View {
    @EnvironmentObject private var model: RouterVPNModel
    @Environment(\.dismiss) private var dismiss
    @State private var draft = IOSNodeChainDraft()
    @State private var owner: IOSNodeChainEditorOwner?
    @State private var detail = ""

    private var available: [RouterProfile] {
        model.allNodeProfiles.filter { $0.normalizedNodeKind == "router-vpn" && $0.external == nil }
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
                        } else {
                        Picker("Node \(position + 1)", selection: Binding(
                            get: { draft.nodes[position].id },
                            set: { id in change { try draft.choose(id, at: position) } }
                        )) {
                            Text("Choose linked node").tag("")
                            ForEach(available.filter { candidate in candidate.id == node.id || !draft.nodes.contains(where: { $0.id == candidate.id }) }) { candidate in
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
                            ForEach(IOSMultihopNodeSelection.nativePrefixModes, id: \.self) { mode in
                                Text(IOSMultihopNodeSelection.transportName(mode)).tag(mode)
                            }
                            if !IOSMultihopNodeSelection.supportsNativePrefix(node.mode) {
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
                Text("Traffic follows this order through one VPN connection. Each preceding node uses its selected WireGuard or AWG2 transport; the selected final node uses Shadowsocks 2022.")
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
