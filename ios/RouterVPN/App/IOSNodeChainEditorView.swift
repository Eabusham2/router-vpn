import SwiftUI

struct IOSNodeChainEditorView: View {
    @EnvironmentObject private var model: RouterVPNModel
    @Environment(\.dismiss) private var dismiss
    @State private var draft = IOSNodeChainDraft()
    @State private var owner: IOSNodeChainEditorOwner?
    @State private var detail = ""
    @State private var execution = "local"
    @State private var appendMode = "wg"
    @StateObject private var candidates = IOSNodeCandidates()
    @StateObject private var firstHop = IOSViaEntryLatency()

    private var needsFirstPublicHop: Bool {
        execution == "local" && draft.hasExternalFinal && draft.nodes.count >= 3 &&
            draft.nodes[1].id.isEmpty && IOSMultihopNodeSelection.supportsNativePrefix(draft.nodes[0].mode) &&
            available.contains { $0.id == draft.controlID && [nil, "", "off"].contains($0.startLayer) }
    }
    private var firstHopScores: [String: Double] {
        guard needsFirstPublicHop, let receipt = firstHop.receipt,
              (try? receipt.requireCurrent(model: model, entryID: draft.controlID, entryMode: draft.nodes[0].mode)) != nil else { return [:] }
        return receipt.values.reduce(into: [:]) { scores, value in
            if value.eligible, let time = value.trimmedMeanMS { scores[value.id] = time }
        }
    }
    private struct PrefixRequest: Equatable {
        let position: Int
        var nextMode: String? = nil
        var draftRevision: String? = nil
        var nodes: [IOSMultihopNodeSelection]? = nil
        let id = UUID()
    }
    @State private var request: PrefixRequest?

    private var available: [RouterProfile] {
        model.iosNodeChainEditorProfiles(owner: owner)
    }

    private var pairedAppendSources: [RouterProfile] {
        IOSNodeChainEditorVisible.unique(available).filter { $0.normalizedNodeKind == "router-vpn" && $0.external == nil }
    }
    private func visibleNodes(at position: Int) -> [RouterProfile] {
        if draft.unfinished {
            return IOSNodeChainEditorVisible.unique(available).filter { candidate in
                !IOSNodeCandidateAppendSource.prefixModes(candidate, position: position).isEmpty &&
                    !draft.nodes.enumerated().contains { $0.offset != position && $0.element.id == candidate.id }
            }
        }
        return IOSNodeChainEditorVisible.candidates(available, nodes: draft.nodes, position: position, execution: execution)
    }

    private var finalModes: [String] {
        let linked = available
        return IOSNodeChainEditorVisible.finalModes(linked.first(where: { $0.id == draft.nodes.last?.id }), nodes: draft.nodes,
                                                    execution: execution, linked: linked, bundle: model.bundle)
    }

    var body: some View {
        let firstScores = firstHopScores
        Form {
            Section("Nodes in connection order") {
                if !draft.unfinished {
                    Menu("Start a prefix-only draft") {
                        ForEach(pairedAppendSources) { profile in
                            Menu(profile.name.isEmpty ? profile.id : profile.name) {
                                ForEach(IOSMultihopNodeSelection.nativePrefixModes, id: \.self) { mode in
                                    Button(IOSMultihopNodeSelection.transportName(mode)) {
                                        change {
                                            try draft.beginPrefix(id: profile.id, mode: mode)
                                            execution = "local"
                                        }
                                    }
                                }
                            }
                        }
                    }.disabled(owner == nil || pairedAppendSources.isEmpty)
                }
                Text(draft.unfinished
                    ? "This draft contains only the real prefix nodes. Choose the next packet transport and measure candidates through the last prefix. A result can be appended only after the temporary test is disconnected. Choose a real final node before saving."
                    : "Each candidate needs 50 routed samples. A qualified paired successor returns authenticated responses using its captured transport. Other eligible packet prefixes measure TCP connections. A Local public-exit route can measure verified HTTPS responses. Use in draft replaces a measured intermediate packet hop or inserts a qualified stream hop. Save a final replacement as a named profile and Load it separately.")
                    .font(.caption).foregroundStyle(.secondary)
                ForEach(Array(draft.nodes.enumerated()), id: \.offset) { position, node in
                    VStack(alignment: .leading, spacing: 8) {
                        if !draft.unfinished && position == draft.nodes.count - 1 {
                            LabeledContent("Selected final node", value: available.first(where: { $0.id == node.id })?.name ?? node.id)
                            if let ms = candidates.editorScore(node: node.id, after: position - 1) {
                                Text(String(format: "Via selected prefix • %.1f ms (%@)", ms, candidates.editorMetricLabel)).font(.caption.monospacedDigit())
                            }
                            if ["local", "server", "auto"].contains(execution) {
                                if draft.hasExternalFinal {
                                    Button("Use paired router as final node") {
                                        change { try draft.restorePairedFinal() }
                                    }
                                }
                                let exits = available.filter { profile in
                                    var proposed = draft
                                    return (try? proposed.chooseExternalFinal(profile, profiles: available, execution: execution)) != nil &&
                                        !proposed.externalEntryModes(in: model.bundle).isEmpty
                                }
                                if !exits.isEmpty {
                                    Menu("Choose an imported exit") {
                                        ForEach(exits, id: \.id) { exit in
                                            Button(exit.name) { change(measureAfter: 0) { try draft.chooseExternalFinal(exit, profiles: available, execution: execution) } }
                                        }
                                    }
                                }
                            }
                            Picker("Final transport", selection: Binding(
                                get: { draft.nodes[position].mode },
                                set: { mode in change {
                                    try IOSNodeChainEditorVisible.requireFinalMode(mode,
                                        profile: available.first(where: { $0.id == node.id }), nodes: draft.nodes,
                                        execution: execution, linked: available, bundle: model.bundle)
                                    try draft.chooseFinalMode(mode, execution: execution)
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
                        } else if position < draft.firstEditablePrefix {
                            LabeledContent("Paired entry", value: available.first(where: { $0.id == node.id })?.name ?? node.id)
                            Picker("Entry transport", selection: Binding(
                                get: { node.mode },
                                set: { mode in change(measureAfter: position) { try draft.chooseExternalEntryMode(mode, in: model.bundle) } }
                            )) {
                                ForEach(draft.externalEntryModes(in: model.bundle), id: \.self) { mode in
                                    Text(IOSMultihopNodeSelection.transportName(mode)).tag(mode)
                                }
                                if !draft.externalEntryModes(in: model.bundle).contains(node.mode) {
                                    Text("Unavailable: \(IOSMultihopNodeSelection.transportName(node.mode))")
                                        .tag(node.mode).disabled(true)
                                }
                            }
                        } else {
                        Picker("Node \(position + 1)", selection: Binding(
                            get: { draft.nodes[position].id },
                            set: { id in change(measureAfter: position) {
                                guard id != draft.nodes[position].id else { return }
                                try draft.choose(id, at: position)
                                if let profile=available.first(where:{$0.id==id}) { try draft.chooseMode(profile.normalizedNodeKind=="external" ? (profile.external?.protocolName ?? "") : "wg", at:position) }
                            } }
                        )) {
                            Text("Choose linked node").tag("")
                            ForEach(visibleNodes(at: position)) { candidate in
                                let name = candidate.name.isEmpty ? candidate.id : candidate.name
                                let first = position == 1 ? firstScores[candidate.id] : nil
                                let ms = first ?? candidates.editorScore(node: candidate.id, after: position - 1)
                                Text(ms.map { String(format: "%@ • %.1f ms via prefix (%@)", name, $0, first != nil ? "TCP" : candidates.editorMetricLabel) } ?? name).tag(candidate.id)
                            }
                            if !node.id.isEmpty && !available.contains(where: { $0.id == node.id }) {
                                Text("Missing linked node").tag(node.id)
                            }
                        }
                        Picker("Transport", selection: Binding(
                            get: { draft.nodes[position].mode },
                            set: { mode in change(measureAfter: position) { try draft.chooseMode(mode, at: position) } }
                        )) {
                            if !draft.unfinished && IOSNodeChainEditorVisible.pairedStreamChoice(draft.nodes, at: position, execution: execution, profiles: available) {
                                Text("Paired Shadowsocks 2022").tag("shadowsocks")
                            }
                            ForEach(draft.unfinished ? IOSNodeCandidateAppendSource.prefixModes(available.first(where: { $0.id == node.id }), position: position) : IOSNodeChainEditorVisible.modes(available.first(where:{$0.id==node.id}), nodeCount: draft.nodes.count, mixedPacket: node.mode != "shadowsocks" && execution == "local" && draft.nodes.dropLast().contains(where: { $0.mode == "shadowsocks" }), selectedPacket: execution != "local" && position == 0 && IOSMultihopNodeSelection.extendedSelectedModeShape(draft.nodes.map(\.mode))), id: \.self) { mode in
                                Text(IOSMultihopNodeSelection.transportName(mode)).tag(mode)
                            }
                            if !IOSMultihopNodeSelection.supportsNativePrefix(node.mode) && !["shadowsocks", "socks5", "http-connect", "https-connect", "openvpn"].contains(node.mode) {
                                Text(IOSMultihopNodeSelection.transportName(node.mode)).tag(node.mode)
                            }
                        }
                        }
                        Text(IOSMultihopNodeSelection.transportName(node.mode))
                            .font(.caption).foregroundStyle(.secondary)
                        if position > 0, position == 1 && needsFirstPublicHop || (try? draft.measurementPath(through: position - 1, execution: execution, profiles: available)) != nil {
                            Button("Measure candidates through node \(position)") { request = PrefixRequest(position: position - 1) }
                                .buttonStyle(.borderless)
                        }
                        if position >= draft.firstEditablePrefix && position < draft.nodes.count - (draft.unfinished ? 0 : 1) { HStack {
                            Button("Earlier") { change { try draft.move(from: position, to: position - 1) } }.disabled(position == draft.firstEditablePrefix)
                            Button("Later") { change { try draft.move(from: position, to: position + 1) } }.disabled(position >= draft.nodes.count - (draft.unfinished ? 1 : 2))
                            Spacer()
                            Button("Remove", role: .destructive) { change { try draft.remove(at: position) } }.disabled(draft.nodes.count <= (draft.unfinished ? 1 : 2))
                        }.buttonStyle(.borderless) }
                    }
                }
                Button(draft.unfinished ? "Add prefix node" : "Add preceding node") {
                    change { try draft.append(execution: execution) }
                    if let added = draft.nodes.firstIndex(where: { $0.id.isEmpty }), added > 0 { schedule(after: added - 1) }
                }.disabled(!draft.canAppend(execution: execution))
                if draft.unfinished {
                    Picker("Next packet transport", selection: $appendMode) {
                        ForEach(IOSMultihopNodeSelection.nativePrefixModes, id: \.self) { mode in
                            Text(IOSMultihopNodeSelection.transportName(mode)).tag(mode)
                        }
                    }
                    Button("Measure next packet node") {
                        do {
                            let nodes = try draft.appendMeasurementPath(profiles: available)
                            request = PrefixRequest(position: nodes.count - 1, nextMode: appendMode,
                                draftRevision: draft.revision, nodes: nodes)
                        } catch { detail = error.localizedDescription }
                    }.disabled(owner == nil || (try? draft.appendMeasurementPath(profiles: available)) == nil)
                    Button("Choose selected router as the real final node") {
                        change { try draft.finishPrefixWithSelectedFinal() }
                    }.disabled(draft.nodes.contains(where: { $0.id == draft.controlID }) ||
                        draft.nodes.count >= IOSMultihopNodeSelection.physicalTraversalDepth)
                    if !detail.isEmpty { Text(detail).font(.caption) }
                }
            }.disabled(model.profileMutationBlocked || model.iosSpeedLabOwnership.active)
            if firstHop.running || !firstHop.progress.isEmpty && needsFirstPublicHop {
                Section("First hop measurement") {
                    Text(firstHop.error.isEmpty ? firstHop.progress : firstHop.error).font(.caption)
                    if firstHop.running { Button("Cancel measurement") { firstHop.cancel(); request = nil } }
                }
            }
            if candidates.running || request != nil && !firstHop.running && !needsFirstPublicHop {
                Section("Prefix measurement") {
                    if candidates.canPrepare || candidates.preparing || !candidates.proposalDescription.isEmpty || draft.unfinished && !candidates.scores.isEmpty {
                        IOSCandidateProfileChoices(probe: candidates, useInDraft: { score in
                            do {
                                guard let selected = request else { throw CancellationError() }
                                let position = selected.position
                                try candidates.useInDraft(score) { proposal in
                                    guard let compiled = proposal.orderedNodes else { throw CancellationError() }
                                    if proposal.appendsPacketNode {
                                        guard let nodes = selected.nodes, let revision = selected.draftRevision,
                                              let mode = selected.nextMode else { throw CancellationError() }
                                        try draft.appendMeasured(score.id, compiled: compiled, original: nodes, draftRevision: revision, mode: mode)
                                    } else {
                                        try draft.insertMeasured(score.id, after: position, compiled: compiled, replacingPacketSuccessor: proposal.replacesPacketSuccessor)
                                    }
                                }
                                request = nil
                                detail = "Applied the measured node to this draft."
                                schedule(after: position + 1)
                            } catch { detail = error.localizedDescription }
                        })
                    }
                    Text(candidates.text).font(.caption)
                    if candidates.running {
                        Button("Cancel measurement") { candidates.cancel(); request = nil }
                    }
                }
            }
            if !draft.unfinished {
            Section("Execution") {
                Picker("Execution", selection: $execution) {
                    Text("Local").tag("local")
                    if draft.externalExecutionEligible(profiles: available, bundle: model.bundle) ||
                        !draft.hasExternalFinal && IOSMultihopNodeSelection.supportsServerExecution(draft.nodes) &&
                        (IOSMultihopNodeSelection.pairedStreamPositions(draft.nodes, execution: "local", profiles: available).isEmpty ||
                         !IOSMultihopNodeSelection.pairedStreamPositions(draft.nodes, execution: "server", profiles: available).isEmpty) &&
                        !IOSMultihopNodeSelection.hasIndependentHostname(draft.nodes, profiles: available) {
                        Text("Server").tag("server")
                        Text("Compare").tag("auto")
                    } else if execution != "local" {
                        Text("Unavailable saved execution").tag(execution).disabled(true)
                    }
                }
                Text("Server and Compare support paired WireGuard or AWG2 preceding nodes and a paired Shadowsocks or Hysteria2 final, with two to eight nodes total. Hysteria2 keeps an independent Off, AES or AES with XOR whitening layer on the final node and retains its saved TLS trust, password and Salamander settings. Longer Server and Compare routes support one WireGuard, AWG2 Fast, or AWG2 Strong entry, literal Shadowsocks imports, and a paired Shadowsocks final, with Start Layer Off throughout. A single imported Shadowsocks hostname can go immediately before a paired Shadowsocks final on a four-to-eight-node route with its saved Custom TCP resolver and explicit resolver IP address and port. HTTP/HTTPS CONNECT can follow one to six paired nodes (three to eight nodes total). Its paired final node keeps its selected Off, AES or AES with XOR whitening layer. SOCKS5 and separately paired OpenVPN also support Server and Compare after one to six paired nodes before the Shadowsocks final. OpenVPN needs independent Local and Server provider credentials with the same captured transport policy. Compare proves both choices before retaining a winner.")
                Text("Traffic follows this order through one VPN connection. Paired packet nodes use WireGuard or AWG2. A Local route can also mix paired Shadowsocks 2022 nodes and imported streams when every node uses Start Layer Off. One imported stream can use its saved hostname and Custom TCP resolver immediately after the packet nodes. It can also follow a literal import when there is one packet entry and all interior streams are imports. When you measure through a stream node before the penultimate node, you can save the candidate in a named profile that keeps the remaining route and final. On a paired-final route, measuring through the penultimate node offers the candidate as the new final. A Local route with an imported exit keeps that exit when you save the candidate. The selected final Router node can use Shadowsocks 2022 or Hysteria2; Hysteria2 keeps an independent Off, AES or AES with XOR whitening layer on that final node. Local, Server and Compare both support independently saved Shadowsocks 2022 nodes at any interior position between a paired packet entry and a paired Shadowsocks 2022 final. With a WireGuard, AWG2 Fast, or AWG2 Strong entry and a literal import at the next position, Server and Compare can use independent paired Shadowsocks nodes and literal imports throughout the remaining middle positions. Keep every Start Layer Off. Each keeps its original credentials and public proof. A three-node Local route can also start with two literal Shadowsocks 2022 imports, both with Start Layer Off, followed by a paired Shadowsocks 2022 final. A single saved Shadowsocks 2022, SOCKS5, HTTP/HTTPS CONNECT or OpenVPN node can also follow one to six paired prefixes (three to eight nodes total), with Start Layer Off on that custom node and a Shadowsocks 2022 final. An imported Shadowsocks hostname retains its saved Custom TCP transport resolver through the original preceding prefix; application DNS remains on the final node. OpenVPN retains its original single literal TCP or UDP remote and connected native owner. SOCKS5 and CONNECT retain their original literal server address and credentials; HTTPS CONNECT also retains verified TLS and SNI. CONNECT requires the paired final node’s captured SS UoT-v2 service declaration and preserves its selected DNS.")
                Text("Each node keeps its saved credentials, Start Layer and protection settings. Server and Compare require a matching registration to use the server path. For an imported exit, only the paired entry can use AES or AES with XOR whitening. The imported exit keeps its saved DNS choice. Home DNS stays on the original paired packet entry. Every node must pass verification before Connected.")
                    .font(.caption).foregroundStyle(.secondary)
                Button("Save ordered route") {
                    do { guard let owner else { return }; try model.saveIOSNodeChain(draft.nodes, owner: owner, execution: execution); dismiss() }
                    catch { detail = error.localizedDescription }
                }.disabled(!draft.canSave || owner == nil)
                if !detail.isEmpty { Text(detail).font(.caption) }
            }.disabled(model.profileMutationBlocked || model.iosSpeedLabOwnership.active)
            }
        }
        .task(id: request) {
            guard let request else { return }
            await candidates.finishEditorComparison()
            guard !Task.isCancelled, self.request == request, let owner else { return }
            do {
                if let nextMode = request.nextMode {
                    guard draft.unfinished, execution == "local", let nodes = request.nodes,
                          let revision = request.draftRevision, draft.nodes == nodes, draft.revision == revision,
                          request.position == nodes.count - 1 else { throw CancellationError() }
                    try model.requireIOSNodeChainAppendSources(owner, nodes: nodes)
                    try candidates.startEditorAppend(model: model, nodes: nodes, editorOwner: owner, nextMode: nextMode,
                        draftRevision: revision) {
                        guard self.request == request, self.draft.unfinished, self.draft.nodes == nodes,
                              self.draft.revision == revision, self.execution == "local", self.appendMode == nextMode else { throw CancellationError() }
                        try model.requireIOSNodeChainAppendSources(owner, nodes: nodes)
                    }
                    return
                }
                guard !draft.unfinished else { throw CancellationError() }
                if request.position == 0 && needsFirstPublicHop {
                    let offered = IOSNodeChainEditorVisible.candidates(available, nodes: draft.nodes, position: 1, execution: execution)
                        .filter(IOSImportedShadowsocksSource.eligibleLiteral)
                    let mode = draft.nodes[0].mode
                    await firstHop.measure(model: model, entryID: owner.controlID, mode: mode, candidates: offered, exactImportedCandidates: true)
                    guard firstHop.receipt != nil else { detail = firstHop.error; return }
                    do { try await Task.sleep(for: .seconds(120)) } catch { return }
                    firstHop.invalidateIfStale(model: model, entryID: owner.controlID, mode: mode)
                    return
                }
                let source = try model.iosNodeChainMeasurementBundle(draft, through: request.position, owner: owner, execution: execution)
                try candidates.startEditorPrefix(model: model, bundle: source, nodes: draft.nodes, position: request.position)
            } catch {
                self.request = nil
                detail = error.localizedDescription
            }
        }
        .onChange(of: execution) { _, _ in candidates.cancel(); firstHop.cancel(); request = nil }
        .onChange(of: appendMode) { _, _ in candidates.cancel(); request = nil }
        .onDisappear { candidates.cancel(); firstHop.cancel() }
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
        guard !draft.unfinished else { return }
        if position == 0 && needsFirstPublicHop || (try? draft.measurementPath(through: position, execution: execution, profiles: available)) != nil {
            request = PrefixRequest(position: position)
        }
    }

    private func change(measureAfter position: Int? = nil, _ action: () throws -> Void) {
        do {
            try action()
            firstHop.cancel()
            candidates.cancel()
            request = nil
            detail = ""
            if let position { schedule(after: position) }
        }
        catch { detail = error.localizedDescription }
    }
}
