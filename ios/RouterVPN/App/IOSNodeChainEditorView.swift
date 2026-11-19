import SwiftUI

struct IOSNodeChainEditorView: View {
    @EnvironmentObject private var model: RouterVPNModel
    @Environment(\.dismiss) private var dismiss
    @State private var draft = IOSNodeChainDraft()
    @State private var owner: IOSNodeChainEditorOwner?
    @State private var detail = ""
    @State private var execution = "local"
    @StateObject private var candidates = IOSNodeCandidates()
    private struct PrefixRequest: Equatable {
        let position: Int
        let id = UUID()
    }
    @State private var request: PrefixRequest?

    private var available: [RouterProfile] {
        model.iosNodeChainEditorProfiles(owner: owner)
    }

    private var finalModes: [String] {
        IOSNodeChainEditorVisible.finalModes(available.first(where: { $0.id == draft.controlID }), nodes: draft.nodes)
    }

    var body: some View {
        Form {
            Section("Nodes in connection order") {
                Text("Choosing a paired prefix in Local execution tests the next nodes through that prefix. Each score measures 50 TCP connections to the candidate’s saved proxy endpoint. Router candidates use their Shadowsocks endpoint.")
                    .font(.caption).foregroundStyle(.secondary)
                ForEach(Array(draft.nodes.enumerated()), id: \.offset) { position, node in
                    VStack(alignment: .leading, spacing: 8) {
                        if position == draft.nodes.count - 1 {
                            LabeledContent("Selected final node", value: available.first(where: { $0.id == node.id })?.name ?? node.id)
                            if let ms = candidates.editorScore(node: node.id, after: position - 1) {
                                Text(String(format: "Via selected prefix • %.1f ms (TCP)", ms)).font(.caption.monospacedDigit())
                            }
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
                            set: { id in change(measureAfter: position) {
                                try draft.choose(id, at: position)
                                if let profile=available.first(where:{$0.id==id}) { try draft.chooseMode(profile.normalizedNodeKind=="external" ? (profile.external?.protocolName ?? "") : "wg", at:position) }
                            } }
                        )) {
                            Text("Choose linked node").tag("")
                            ForEach(IOSNodeChainEditorVisible.candidates(available, nodes: draft.nodes, position: position)) { candidate in
                                let name = candidate.name.isEmpty ? candidate.id : candidate.name
                                let ms = candidates.editorScore(node: candidate.id, after: position - 1)
                                Text(ms.map { String(format: "%@ • %.1f ms via prefix (TCP)", name, $0) } ?? name).tag(candidate.id)
                            }
                            if !node.id.isEmpty && !available.contains(where: { $0.id == node.id }) {
                                Text("Missing linked node").tag(node.id)
                            }
                        }
                        Picker("Transport", selection: Binding(
                            get: { draft.nodes[position].mode },
                            set: { mode in change(measureAfter: position) { try draft.chooseMode(mode, at: position) } }
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
                        if execution == "local", position > 0, (try? draft.measurementPath(through: position - 1)) != nil {
                            Button("Measure candidates through node \(position)") { request = PrefixRequest(position: position - 1) }
                                .buttonStyle(.borderless)
                        }
                        if position < draft.nodes.count - 1 { HStack {
                            Button("Earlier") { change { try draft.move(from: position, to: position - 1) } }.disabled(position == 0)
                            Button("Later") { change { try draft.move(from: position, to: position + 1) } }.disabled(position >= draft.nodes.count - 2)
                            Spacer()
                            Button("Remove", role: .destructive) { change { try draft.remove(at: position) } }.disabled(draft.nodes.count <= 2)
                        }.buttonStyle(.borderless) }
                    }
                }
                Button("Add preceding node") {
                    change { try draft.append() }
                    if let added = draft.nodes.firstIndex(where: { $0.id.isEmpty }), added > 0 { schedule(after: added - 1) }
                }.disabled(draft.nodes.count >= IOSMultihopNodeSelection.maximumNodes)
            }.disabled(model.profileMutationBlocked || model.iosSpeedLabOwnership.active)
            if request != nil || candidates.running {
                Section("Prefix measurement") {
                    Text(candidates.text).font(.caption)
                    if candidates.running {
                        Button("Cancel measurement") { candidates.cancel(); request = nil }
                    }
                }
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
                Text("Server and Compare support paired WireGuard or AWG2 preceding nodes and a paired Shadowsocks or Hysteria2 final, with two to eight nodes total. Hysteria2 keeps an independent Off, AES or AES with XOR whitening layer on the final node and retains its saved TLS trust, password and Salamander settings. One custom Shadowsocks 2022 node can appear immediately before a Shadowsocks final: a literal IP address allows three to eight nodes, while a hostname requires four to eight nodes and its saved Custom TCP resolver with an explicit IP address and port. HTTP/HTTPS CONNECT can follow one to six paired nodes (three to eight nodes total). Its paired final node keeps its selected Off, AES or AES with XOR whitening layer. SOCKS5 and separately paired OpenVPN also support Server and Compare after one to six paired nodes before the Shadowsocks final. OpenVPN needs independent Local and Server provider credentials with the same captured transport policy. Compare proves both choices before retaining a winner.")
                Text("Traffic follows this order through one VPN connection. Paired preceding nodes use WireGuard or AWG2. The selected final Router node can use Shadowsocks 2022 or Hysteria2; Hysteria2 keeps an independent Off, AES or AES with XOR whitening layer on that final node. In Local execution, independently saved Shadowsocks 2022 nodes with literal server addresses can occupy any interior positions between a paired packet entry and a Shadowsocks final. Each keeps its original credentials and public proof. A three-node Local route can also start with two literal Shadowsocks 2022 imports, both with Start Layer Off, followed by a paired Shadowsocks 2022 final. A single saved Shadowsocks 2022, SOCKS5, HTTP/HTTPS CONNECT or OpenVPN node can also follow one to six paired prefixes (three to eight nodes total), with Start Layer Off on that custom node and a Shadowsocks 2022 final. An imported Shadowsocks hostname retains its saved Custom TCP transport resolver through the original preceding prefix; application DNS remains on the final node. OpenVPN retains its original single literal TCP or UDP remote and connected native owner. SOCKS5 and CONNECT retain their original literal server address and credentials; HTTPS CONNECT also retains verified TLS and SNI. CONNECT requires the paired final node’s captured SS UoT-v2 service declaration and preserves its selected DNS.")
                Text("Each node keeps its own saved credentials, Start Layer and protection settings. DNS uses the final node. Every node must pass verification before Connected.")
                    .font(.caption).foregroundStyle(.secondary)
                Button("Save ordered route") {
                    do { guard let owner else { return }; try model.saveIOSNodeChain(draft.nodes, owner: owner, execution: execution); dismiss() }
                    catch { detail = error.localizedDescription }
                }.disabled(!draft.canSave || owner == nil)
                if !detail.isEmpty { Text(detail).font(.caption) }
            }.disabled(model.profileMutationBlocked || model.iosSpeedLabOwnership.active)
        }
        .task(id: request) {
            guard let request else { return }
            await candidates.finishEditorComparison()
            guard !Task.isCancelled, self.request == request, execution == "local", let owner else { return }
            do {
                let source = try model.iosNodeChainMeasurementBundle(draft, through: request.position, owner: owner)
                try candidates.startEditorPrefix(model: model, bundle: source, position: request.position)
            } catch {
                self.request = nil
                detail = error.localizedDescription
            }
        }
        .onChange(of: execution) { _, _ in candidates.cancel(); request = nil }
        .onDisappear { candidates.cancel() }
        .navigationTitle("Ordered nodes")
        .onAppear {
            let selected = model.selectedNodeProfile
            execution = selected?.multihopExecution ?? "local"
            draft = IOSNodeChainDraft(saved: selected?.multihopNodes, finalID: selected?.normalizedNodeKind == "router-vpn" ? selected?.id ?? "" : "")
            do { owner = try model.captureIOSNodeChainEditorOwner(); detail = "" }
            catch { owner = nil; detail = error.localizedDescription }
        }
    }

    private func schedule(after position: Int) {
        if execution == "local", (try? draft.measurementPath(through: position)) != nil {
            request = PrefixRequest(position: position)
        }
    }

    private func change(measureAfter position: Int? = nil, _ action: () throws -> Void) {
        do {
            try action()
            candidates.cancel()
            request = nil
            detail = ""
            if let position { schedule(after: position) }
        }
        catch { detail = error.localizedDescription }
    }
}
