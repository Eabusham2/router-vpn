import Foundation

/// Only ordered references live in the editor. Credentials and transport
/// assets stay in each original linked node record.
struct IOSNodeChainDraft {
    private(set) var nodes: [IOSMultihopNodeSelection] { didSet { revision = UUID().uuidString } }
    private(set) var unfinished = false
    private(set) var revision = UUID().uuidString
    let controlID: String

    init(saved: [IOSMultihopNodeSelection]? = nil, finalID: String = "") {
        controlID = finalID
        nodes = saved ?? [.init(id: "", mode: "wg"), .init(id: finalID, mode: "shadowsocks")]
    }

    var hasExternalFinal: Bool { !unfinished && !controlID.isEmpty && nodes.last?.id != controlID && nodes.first?.id == controlID }
    var firstEditablePrefix: Int { hasExternalFinal ? 1 : 0 }

    mutating func beginPrefix(id: String, mode: String) throws {
        guard id.range(of: "\\A[A-Za-z0-9_-]{1,64}\\z", options: .regularExpression) != nil,
              IOSMultihopNodeSelection.supportsNativePrefix(mode) else { throw IOSNodeCandidateAppendSource.issue() }
        unfinished = true
        nodes = [.init(id: id, mode: mode)]
    }

    func appendMeasurementPath(profiles: [RouterProfile]) throws -> [IOSMultihopNodeSelection] {
        try appendSourcePath(profiles: profiles, maximum: IOSMultihopNodeSelection.physicalTraversalDepth - 1)
    }

    func appendCompletionPath(profiles: [RouterProfile]) throws -> [IOSMultihopNodeSelection] {
        try appendSourcePath(profiles: profiles, maximum: IOSMultihopNodeSelection.physicalTraversalDepth)
    }

    private func appendSourcePath(profiles: [RouterProfile], maximum: Int) throws -> [IOSMultihopNodeSelection] {
        guard unfinished, (1...maximum).contains(nodes.count),
              Set(nodes.map(\.id)).count == nodes.count, nodes.enumerated().allSatisfy({ position, node in
                  let originals = profiles.filter { $0.id == node.id }
                  return !node.id.isEmpty && originals.count == 1 &&
                      IOSNodeCandidateAppendSource.prefixModes(originals[0], position: position).contains(node.mode)
              }) else { throw IOSNodeCandidateAppendSource.issue() }
        return nodes
    }

    mutating func appendMeasured(_ candidate: String, compiled: [IOSMultihopNodeSelection],
                                original: [IOSMultihopNodeSelection], draftRevision: String, mode: String) throws {
        guard unfinished, revision == draftRevision, nodes == original, !candidate.isEmpty,
              nodes.count < IOSMultihopNodeSelection.physicalTraversalDepth,
              !nodes.contains(where: { $0.id == candidate }), IOSNodeCandidateAppendSource.supportsNextMode(mode),
              compiled == nodes + [.init(id: candidate, mode: mode)] else { throw IOSNodeCandidateAppendSource.issue() }
        nodes = compiled
    }

    mutating func finishPrefixWithSelectedFinal() throws {
        guard unfinished, !controlID.isEmpty, !nodes.isEmpty,
              nodes.count < IOSMultihopNodeSelection.physicalTraversalDepth,
              nodes.allSatisfy({ !$0.id.isEmpty }), !nodes.contains(where: { $0.id == controlID }) else {
            throw IOSMultihopNodeSelection.issue("Choose a distinct selected Router node as the final, and keep room for it after this prefix.")
        }
        nodes.append(.init(id: controlID, mode: "shadowsocks"))
        unfinished = false
    }

    mutating func chooseExternalFinal(_ exit: RouterProfile, profiles: [RouterProfile], execution: String) throws {
        guard !unfinished, ["local", "server", "auto"].contains(execution), IOSImportedShadowsocksSource.eligibleLiteral(exit), exit.id != controlID,
              let entry = profiles.first(where: { $0.id == controlID }),
              IOSMultihopNodeSelection.supportsExternalExitEntry(entry) else {
            throw IOSMultihopNodeSelection.issue("Choose a literal Shadowsocks 2022 exit and a paired WireGuard or AWG2 entry with its saved Start Layer.")
        }
        var middle = hasExternalFinal ? Array(nodes.dropFirst().dropLast()) : Array(nodes.dropLast())
        guard middle.allSatisfy({ node in node.id.isEmpty || node.id != exit.id && profiles.contains { $0.id == node.id && IOSImportedShadowsocksSource.eligibleLiteral($0) } }),
              middle.count <= IOSMultihopNodeSelection.physicalTraversalDepth-2 else {
            throw IOSMultihopNodeSelection.issue("Retain only distinct imported Shadowsocks 2022 intermediates before choosing the exit.")
        }
        if middle.isEmpty { middle = [.init(id: "", mode: "shadowsocks")] }
        let entryMode = hasExternalFinal ? nodes[0].mode : "wg"
        nodes = [.init(id: controlID, mode: entryMode)] + middle.map { .init(id: $0.id, mode: "shadowsocks") } + [.init(id: exit.id, mode: "shadowsocks")]
    }

    mutating func restorePairedFinal() throws {
        guard hasExternalFinal else {
            throw IOSMultihopNodeSelection.issue("Choose the imported exit route before changing its final node.")
        }
        let middle = nodes.dropFirst().dropLast()
        nodes = [.init(id: "", mode: "wg")] + Array(middle) + [.init(id: controlID, mode: "shadowsocks")]
    }

    var canSave: Bool {
        !unfinished && ((2...IOSMultihopNodeSelection.maximumNodes).contains(nodes.count) || IOSMultihopNodeSelection.extendedOriginalModes(nodes.map(\.mode), execution: "local")) &&
            nodes.allSatisfy({ $0.id.range(of: "\\A[A-Za-z0-9_-]{1,64}\\z", options: .regularExpression) != nil }) &&
            Set(nodes.map(\.id)).count == nodes.count && (nodes.last?.id == controlID || IOSMultihopNodeSelection.externalExitReferences(nodes, controlID: controlID, execution: "local")) &&
            (nodes.first?.mode != "shadowsocks" || IOSMultihopNodeSelection.usesLocalImportedEntry(nodes)) &&
            nodes.dropLast().enumerated().allSatisfy({ position, node in IOSMultihopNodeSelection.supportsNativePrefix(node.mode) || (IOSMultihopNodeSelection.supportsImportedMiddle(node.mode, position: position, count: nodes.count) || IOSMultihopNodeSelection.supportsLocalImportedNode(node.mode, position: position, count: nodes.count, importedEntry: IOSMultihopNodeSelection.usesLocalImportedEntry(nodes))) && nodes.last?.mode == "shadowsocks" }) &&
            (IOSMultihopNodeSelection.nativeFinalModes.contains(nodes.last?.mode ?? "") ||
             IOSMultihopNodeSelection.supportsLocalPacketRoute(nodes, execution: "local"))
    }

    mutating func insertMeasured(_ candidate: String, after position: Int, compiled: [IOSMultihopNodeSelection], replacingPacketSuccessor: Bool = false) throws {
        guard !unfinished else { throw IOSNodeCandidateAppendSource.issue() }
        var expected = nodes.filter { !$0.id.isEmpty }
        guard position >= 0, position < expected.count - 1,
              nodes.prefix(position + 1).allSatisfy({ !$0.id.isEmpty }), !expected.contains(where: { $0.id == candidate }) else {
            throw IOSMultihopNodeSelection.issue("Measure this draft again.")
        }
        if replacingPacketSuccessor {
            guard canSave, !hasExternalFinal, expected == nodes, position < expected.count - 2,
                  IOSMultihopNodeSelection.supportsNativePrefix(expected[position + 1].mode) else {
                throw IOSMultihopNodeSelection.issue("The original packet successor or full draft changed.")
            }
            expected[position + 1] = .init(id: candidate, mode: expected[position + 1].mode)
        } else {
            guard position > 0, expected.count < IOSMultihopNodeSelection.physicalTraversalDepth else {
                throw IOSMultihopNodeSelection.issue("Measure this draft again.")
            }
            expected.insert(.init(id: candidate, mode: "shadowsocks"), at: position + 1)
        }
        guard compiled == expected, compiled.last?.id == controlID || hasExternalFinal && IOSMultihopNodeSelection.externalExitReferences(compiled, controlID: controlID, execution: "local") else { throw IOSMultihopNodeSelection.issue("The measured path and the current draft differ.") }
        nodes = expected
    }

    /// The temporary provider receives a complete compilable Local source.
    /// Keep every chosen suffix node and its policy in the source. The
    /// provider only opens the prefix, and empty editor rows supply no node.
    func measurementPath(through position: Int, execution: String = "local", profiles: @autoclosure () -> [RouterProfile] = []) throws -> [IOSMultihopNodeSelection] {
        guard !unfinished, position >= 0, position < nodes.count - 1, let final = nodes.last,
              (final.id == controlID || hasExternalFinal), !final.id.isEmpty else {
            throw IOSMultihopNodeSelection.issue("Choose a linked final node and a preceding prefix.")
        }
        let prefix = nodes.prefix(position + 1)
        let selected = nodes.filter { !$0.id.isEmpty }
        let linked = profiles()
        if hasExternalFinal {
            guard IOSMultihopNodeSelection.externalExitReferences(nodes, controlID: controlID, execution: execution),
                  canSave, selected.count == nodes.count, nodes.enumerated().allSatisfy({ i, node in
                      let matches = linked.filter { $0.id == node.id }
                      guard matches.count == 1, let profile = matches.first else { return false }
                      return i == 0 ? IOSMultihopNodeSelection.supportsExternalExitEntry(profile) : IOSImportedShadowsocksSource.eligibleLiteral(profile)
                  }) else { throw IOSMultihopNodeSelection.issue("Select the complete route and its original literal Shadowsocks imports before measuring this prefix.") }
            return nodes
        }
        let hasIndependentHostname = IOSMultihopNodeSelection.hasIndependentHostname(nodes, profiles: linked)
        if ["server", "auto"].contains(execution) {
            if position == 1, nodes.count == 3, IOSMultihopNodeSelection.supportsNativePrefix(nodes[0].mode), nodes.dropFirst().allSatisfy({ $0.mode == "shadowsocks" }),
               Set(nodes.map(\.id)).count == 3, nodes.allSatisfy({ !$0.id.isEmpty }),
               nodes.enumerated().allSatisfy({ index, node in
                   let matches = linked.filter { $0.id == node.id }
                   guard matches.count == 1, let profile = matches.first, [nil, "", "off"].contains(profile.startLayer) else { return false }
                   return index == 1 ? IOSImportedShadowsocksSource.eligibleLiteral(profile) :
                        profile.normalizedNodeKind == "router-vpn" && profile.external == nil
               }) { return nodes }
            if selected == nodes,
               IOSMultihopNodeSelection.compareResponsePositions(nodes, profiles: linked).contains(position) { return nodes }
            let hasPairedStream = selected.dropFirst().dropLast().contains { node in
                node.mode == "shadowsocks" && linked.contains { $0.id == node.id && $0.normalizedNodeKind == "router-vpn" }
            }
            if hasPairedStream {
                let privateStops = IOSMultihopNodeSelection.pairedStreamPositions(nodes, execution: execution, profiles: linked)
                guard selected == nodes, !privateStops.isEmpty, position == 0 else {
                    throw IOSMultihopNodeSelection.issue("Choose the paired WireGuard or AWG2 entry, or a supported Shadowsocks hop in the selected route.")
                }
                return nodes
            }
            guard !hasIndependentHostname, prefix.allSatisfy({ !$0.id.isEmpty }),
                  IOSMultihopNodeSelection.supportsServerExecution(selected),
                  IOSMultihopNodeSelection.supportsNativePrefix(nodes[position].mode),
                  position == 0 || !IOSMultihopNodeSelection.supportsSOCKSExecution(selected) && !IOSMultihopNodeSelection.supportsCONNECTExecution(selected) else {
                throw IOSMultihopNodeSelection.issue("Select a supported complete Server or Compare path and a paired packet measurement position.")
            }
            return selected
        }
        let mixedPackets = IOSMultihopNodeSelection.extendedMixedPacketCount(nodes.map(\.mode), execution: execution)
        let packet = IOSMultihopNodeSelection.supportsNativePrefix(nodes[position].mode) && prefix.allSatisfy { node in
            if IOSMultihopNodeSelection.supportsNativePrefix(node.mode) { return true }
            let matches = linked.filter { $0.id == node.id }
            return node.mode == "shadowsocks" && matches.count == 1 && IOSImportedShadowsocksSource.eligibleLiteral(matches[0])
        }
        let extendedImport = (IOSMultihopNodeSelection.extendedLocalModes(nodes.map(\.mode), execution: execution) || mixedPackets > 0) && selected.count == nodes.count
        let packets = prefix.prefix(while: { IOSMultihopNodeSelection.supportsNativePrefix($0.mode) }).count
        let stream = packets > 0 && packets < prefix.count && final.mode == "shadowsocks" &&
            (nodes.count <= IOSMultihopNodeSelection.maximumNodes || extendedImport) &&
            prefix.dropFirst(packets).allSatisfy { $0.mode == "shadowsocks" }
        // The original native plan validates the credentials, literal addresses and layers before opening this test.
        guard execution == "local", prefix.allSatisfy({ !$0.id.isEmpty }), packet || stream else {
            throw IOSMultihopNodeSelection.issue("Choose a supported packet prefix or Local WireGuard or AWG2 nodes followed by linked Shadowsocks 2022 imports.")
        }
        if hasIndependentHostname {
            guard IOSMultihopNodeSelection.localStreamLayout(nodes, execution: execution, profiles: linked)?.hostname != nil else {
                throw IOSMultihopNodeSelection.issue("A Local hostname measurement needs the complete original route with its saved Custom TCP resolver immediately after the paired packet nodes.")
            }
            return nodes
        }
        if stream || mixedPackets > 0 {
            guard Set(selected.map(\.id)).count == selected.count else {
                throw IOSMultihopNodeSelection.issue("Choose a different linked node for every position.")
            }
            // The measured paired stream keeps its own private identity. Any
            // subsequent prefix must retain the complete qualified saved path.
            if !IOSMultihopNodeSelection.pairedStreamPositions(nodes, execution: execution, profiles: linked).isEmpty {
                return nodes
            }
            let required = position < 7 && mixedPackets == 0 ? Array(prefix) + [final] : nodes
            let requiredPackets = mixedPackets > 0 ? mixedPackets : packets
            for (index, node) in required.enumerated() {
                let matches = linked.filter { $0.id == node.id }
                guard matches.count == 1, let profile = matches.first,
                      (index < requiredPackets || index == required.count - 1) ?
                        profile.normalizedNodeKind == "router-vpn" && profile.external == nil && [nil, "", "off"].contains(profile.startLayer) :
                        IOSImportedShadowsocksSource.eligibleLiteral(profile) || (packets >= 1 && index == packets && position == packets && position == nodes.count - 2 && nodes.count <= IOSMultihopNodeSelection.maximumNodes && IOSImportedShadowsocksSource.eligible(profile)) else {
                    throw IOSMultihopNodeSelection.issue("Private response measurements require the original paired packet nodes, Shadowsocks 2022 imports and paired final with Start Layer Off. An imported hostname needs its original Custom TCP resolver through the paired prefix.")
                }
            }
        }
        return selected
    }

    mutating func choose(_ id: String, at position: Int) throws {
        guard position >= firstEditablePrefix else {
            throw IOSMultihopNodeSelection.issue("The imported exit uses the selected Router VPN node as its paired packet entry.")
        }
        guard nodes.indices.contains(position), position < nodes.count - (unfinished ? 0 : 1),
              id.isEmpty || !nodes.enumerated().contains(where: { $0.offset != position && $0.element.id == id }) else {
            throw IOSMultihopNodeSelection.issue("Choose a different linked node for each position.")
        }
        nodes[position].id = id
    }

    func externalExecutionEligible(profiles: [RouterProfile], bundle: ClientBundle?) -> Bool {
        guard hasExternalFinal, canSave, externalEntryModes(in: bundle).contains(nodes[0].mode) else { return false }
        return nodes.dropFirst().allSatisfy { node in
            let originals = profiles.filter { $0.id == node.id }
            return originals.count == 1 && IOSImportedShadowsocksSource.eligibleLiteral(originals[0])
        }
    }

    func externalEntryModes(in bundle: ClientBundle?) -> [String] {
        guard hasExternalFinal, let bundle, bundle.selectedRouterID == controlID,
              bundle.routerProfiles.filter({ $0.id == controlID }).count == 1,
              let entry = bundle.routerProfiles.first(where: { $0.id == controlID }),
              IOSMultihopNodeSelection.supportsExternalExitEntry(entry),
              bundle.profiles["wg"]?["wg.conf"]?.isEmpty == false else { return [] }
        if ![nil, "", "off"].contains(entry.startLayer),
           bundle.profiles["shadowsocks"]?["sing-box.json"]?.isEmpty != false { return [] }
        return IOSMultihopNodeSelection.nativePrefixModes.filter { mode in
            bundle.profiles[mode]?[mode == "wg" ? "wg.conf" : "awg.conf"]?.isEmpty == false
        }
    }

    mutating func chooseExternalEntryMode(_ mode: String, in bundle: ClientBundle?) throws {
        guard externalEntryModes(in: bundle).contains(mode) else {
            throw IOSMultihopNodeSelection.issue("The selected entry is missing the original files for this transport.")
        }
        nodes[0].mode = mode
    }

    mutating func chooseMode(_ mode: String, at position: Int) throws {
        if unfinished {
            guard nodes.indices.contains(position),
                  IOSMultihopNodeSelection.supportsNativePrefix(mode) || position > 0 && ["shadowsocks", "hysteria2"].contains(mode) else { throw IOSNodeCandidateAppendSource.issue() }
            nodes[position].mode = mode
            return
        }
        guard position >= firstEditablePrefix else {
            throw IOSMultihopNodeSelection.issue("Choose the entry transport from its paired source.")
        }
        guard nodes.indices.contains(position), position < nodes.count - 1,
              nodes.count <= IOSMultihopNodeSelection.maximumNodes || mode == "wg" || mode == "shadowsocks" || IOSMultihopNodeSelection.extendedMixedPacketCount(nodes.enumerated().map { $0.offset == position ? mode : $0.element.mode }, execution: "local") > 0,
              (IOSMultihopNodeSelection.supportsNativePrefix(mode) || IOSMultihopNodeSelection.supportsImportedMiddle(mode, position: position, count: nodes.count) || IOSMultihopNodeSelection.supportsLocalImportedNode(mode, position: position, count: nodes.count, importedEntry: position == 0 && nodes.count == 3 && nodes.last?.mode == "shadowsocks")) else {
            throw IOSMultihopNodeSelection.issue("Choose WireGuard or AWG2 for a paired packet node. Paired Shadowsocks 2022 stream nodes can share a Local route with imports when every node uses Start Layer Off. The first stream can use a hostname with its saved Custom TCP resolver. In Local execution, Shadowsocks 2022, SOCKS5, HTTP/HTTPS CONNECT or OpenVPN can follow one to six paired prefixes immediately before a Shadowsocks final (three to eight nodes total). Shadowsocks 2022 also supports Server and Compare with three to eight nodes for a literal IP address, or four to eight for a hostname using its saved Custom TCP resolver with an explicit IP address and port. HTTP/HTTPS CONNECT supports Server and Compare with three to eight nodes and an independent Off, AES or AES with XOR whitening layer on the paired final; SOCKS5 and separately paired OpenVPN also support Server and Compare after one to six paired nodes before the Shadowsocks final. OpenVPN retains independent Local and Server provider credentials.")
        }
        nodes[position].mode = mode
    }

    func canAppend(execution: String) -> Bool {
        if unfinished { return execution == "local" && nodes.count < IOSMultihopNodeSelection.physicalTraversalDepth - 1 }
        return nodes.count < IOSMultihopNodeSelection.maximumNodes ||
            IOSMultihopNodeSelection.extendedOriginalModes(nodes.map(\.mode) + ["shadowsocks"], execution: execution) ||
            IOSMultihopNodeSelection.extendedPairedModes(nodes.dropLast().map(\.mode) + ["wg", nodes.last?.mode ?? ""], execution: execution)
    }

    mutating func append(execution: String = "local") throws {
        guard canAppend(execution: execution) else {
            throw IOSMultihopNodeSelection.issue("This route cannot add another preceding node with its current transport and execution choices.")
        }
        if unfinished { nodes.append(.init(id: "", mode: "wg")); return }
        if hasExternalFinal {
            nodes.insert(.init(id: "", mode: "shadowsocks"), at: nodes.count - 1)
            return
        }
        if nodes.count >= IOSMultihopNodeSelection.maximumNodes {
            let paired = IOSMultihopNodeSelection.extendedPairedModes(nodes.dropLast().map(\.mode) + ["wg", nodes.last?.mode ?? ""], execution: execution)
            nodes.insert(.init(id: "", mode: paired ? "wg" : "shadowsocks"), at: nodes.count - 1)
            return
        }
        let beforeCONNECT = nodes.count >= 3 && ["shadowsocks", "socks5", "http-connect", "https-connect", "openvpn"].contains(nodes[nodes.count - 2].mode)
        nodes.insert(.init(id: "", mode: "wg"), at: nodes.count - (beforeCONNECT ? 2 : 1))
    }

    mutating func chooseFinalMode(_ mode: String, execution: String = "local") throws {
        guard !unfinished, !nodes.isEmpty, IOSMultihopNodeSelection.nativeFinalModes.contains(mode) || execution == "local" && IOSMultihopNodeSelection.supportsNativePrefix(mode),
              mode == "shadowsocks" || nodes.count <= IOSMultihopNodeSelection.maximumNodes && nodes.dropLast().allSatisfy({ IOSMultihopNodeSelection.supportsNativePrefix($0.mode) }) else {
            throw IOSMultihopNodeSelection.issue("Choose a final transport supported by the selected execution and paired packet prefix.")
        }
        nodes[nodes.count - 1].mode = mode
    }

    mutating func remove(at position: Int) throws {
        guard nodes.count > (unfinished ? 1 : 2), nodes.indices.contains(position),
              position < nodes.count - (unfinished ? 0 : 1), position >= firstEditablePrefix else {
            throw IOSMultihopNodeSelection.issue("Keep at least two nodes in the ordered route.")
        }
        nodes.remove(at: position)
    }

    mutating func move(from position: Int, to destination: Int) throws {
        guard nodes.indices.contains(position), nodes.indices.contains(destination),
              position < nodes.count - (unfinished ? 0 : 1), destination < nodes.count - (unfinished ? 0 : 1),
              position >= firstEditablePrefix, destination >= firstEditablePrefix else {
            throw IOSMultihopNodeSelection.issue("The selected node position changed.")
        }
        let node = nodes.remove(at: position); nodes.insert(node, at: destination)
    }
}

/// The editor captures opaque source identities when opened. Neither a newly
/// selected exit nor a relinked entry may inherit an older editor's Save.
struct IOSNodeChainEditorOwner {
    let controlID: String
    let fingerprints: [String: String]
}

/// An explicitly chosen complete future profile. The original device/control
/// remains selected; this value supplies no measured-final or runtime authority.
struct IOSNodeChainAppendCompletion {
    let id = UUID()
    let owner: IOSNodeChainEditorOwner
    let prefix: [IOSMultihopNodeSelection]
    let draftRevision: String
    let finalID: String
    let finalName: String
    let profiles: [RouterProfile]
    let launchInput: String
    let originalBundle: Data
    let records: [String: Data]
    let stamp: IOSCandidateCatalogPublication.Stamp
    let deviceMTU: IOSDeviceMTUPreference
    let idleGeneration: UUID
    var usesLastNodeAsFinal: Bool { prefix.last?.id == finalID && ["shadowsocks", "hysteria2"].contains(prefix.last?.mode ?? "") }
}

@MainActor
extension RouterVPNModel {
    private func iosNodeChainEditorFingerprint(_ id: String) throws -> String {
        guard let data = IOSNodeBundleStore.shared.bundleData(containing: id, current: bundle),
              !data.isEmpty, data.count <= 32 * 1024 * 1024 else {
            throw IOSMultihopNodeSelection.issue("A linked node source is no longer available. Reopen the ordered route editor.")
        }
        let source = try JSONDecoder().decode(ClientBundle.self, from: data)
        guard source.routerProfiles.filter({ $0.id == id }).count == 1,
              let profile = source.routerProfiles.first(where: { $0.id == id }),
              (profile.normalizedNodeKind == "router-vpn" && profile.external == nil || (IOSImportedShadowsocksSource.eligible(profile) || IOSImportedSOCKSSource.eligible(profile) || (IOSImportedCONNECTSource.eligible(profile) || IOSImportedOpenVPNSource.eligible(profile)))) else {
            throw IOSMultihopNodeSelection.issue("Choose independently linked Router nodes or the supported original custom intermediate.")
        }
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
        return Self.iosStrategyDigest(try encoder.encode(source))
    }

    func captureIOSNodeChainEditorOwner() throws -> IOSNodeChainEditorOwner {
        guard !profileMutationBlocked, !iosSpeedLabOwnership.active,
              let selected = selectedNodeProfile, selected.normalizedNodeKind == "router-vpn", selected.external == nil else {
            throw IOSMultihopNodeSelection.issue("Choose the final Router VPN node while the VPN and temporary tests are idle.")
        }
        var fingerprints: [String: String] = [:]
        for profile in allNodeProfiles where profile.normalizedNodeKind == "router-vpn" && profile.external == nil || (IOSImportedShadowsocksSource.eligible(profile) || IOSImportedSOCKSSource.eligible(profile) || (IOSImportedCONNECTSource.eligible(profile) || IOSImportedOpenVPNSource.eligible(profile))) {
            fingerprints[profile.id] = try? iosNodeChainEditorFingerprint(profile.id)
        }
        guard fingerprints[selected.id] != nil else {
            throw IOSMultihopNodeSelection.issue("The selected final node has no exact linked source.")
        }
        return IOSNodeChainEditorOwner(controlID: selected.id, fingerprints: fingerprints)
    }

    private func requireIOSNodeChainEditorOwner(_ owner: IOSNodeChainEditorOwner, nodes: [IOSMultihopNodeSelection]) throws {
        guard !profileMutationBlocked, !iosSpeedLabOwnership.active,
              bundle?.selectedRouterID == owner.controlID, nodes.last?.id == owner.controlID || IOSMultihopNodeSelection.externalExitReferences(nodes, controlID: owner.controlID, execution: "local") else {
            throw IOSMultihopNodeSelection.issue("The selected final node or connection owner changed. Reopen the ordered route editor.")
        }
        for node in nodes {
            guard let expected = owner.fingerprints[node.id], try iosNodeChainEditorFingerprint(node.id) == expected else {
                throw IOSMultihopNodeSelection.issue("An ordered node was removed or relinked. Reopen the editor to use its current source.")
            }
        }
    }

    /// Source equality only. The preparation owns activity admission separately,
    /// and calls this again through Start, measurement, retirement and adoption.
    func requireIOSNodeChainAppendSources(_ owner: IOSNodeChainEditorOwner, nodes: [IOSMultihopNodeSelection]) throws {
        guard bundle?.selectedRouterID == owner.controlID, let control = selectedNodeProfile,
              control.id == owner.controlID, control.normalizedNodeKind == "router-vpn", control.external == nil,
              !nodes.isEmpty, nodes.count <= IOSMultihopNodeSelection.physicalTraversalDepth,
              Set(nodes.map(\.id)).count == nodes.count, nodes.allSatisfy({ !$0.id.isEmpty }) else {
            throw IOSNodeCandidateAppendSource.issue()
        }
        for id in Set(nodes.map(\.id) + [owner.controlID]) {
            guard let expected = owner.fingerprints[id], try iosNodeChainEditorFingerprint(id) == expected,
                  allNodeProfiles.filter({ $0.id == id }).count == 1 else { throw IOSNodeCandidateAppendSource.issue() }
        }
        for (position, node) in nodes.enumerated() {
            guard IOSNodeCandidateAppendSource.prefixModes(allNodeProfiles.first(where: { $0.id == node.id }), position: position).contains(node.mode) else {
                throw IOSNodeCandidateAppendSource.issue()
            }
        }
    }

    func iosNodeChainAppendFinalChoices(owner: IOSNodeChainEditorOwner?, prefix: [IOSMultihopNodeSelection]) -> [RouterProfile] {
        guard let owner, !prefix.isEmpty, prefix.count < IOSMultihopNodeSelection.physicalTraversalDepth else { return [] }
        return iosNodeChainEditorProfiles(owner: owner).filter { profile in
            guard profile.normalizedNodeKind == "router-vpn", profile.external == nil,
                  !prefix.contains(where: { $0.id == profile.id }),
                  let raw = IOSNodeBundleStore.shared.bundleData(containing: profile.id, current: bundle),
                  let source = try? JSONDecoder().decode(ClientBundle.self, from: raw),
                  source.routerProfiles.filter({ $0.id == profile.id }).count == 1,
                  source.profiles["shadowsocks"]?["sing-box.json"]?.isEmpty == false else { return false }
            return true
        }
    }

    private func requireIOSNodeChainAppendCompletionIdle(_ owner: IOSNodeChainEditorOwner,
                                                         prefix: [IOSMultihopNodeSelection], finalID: String) throws {
        guard !connected, !tunnelTransitioning, !iosUserDisconnectInProgress, !profileMutationBlocked,
              !iosSpeedLabOwnership.active, !IOSMTUMeasurementGate.held,
              IOSNodeCandidatePreparation.retained == nil else { throw CancellationError() }
        try requireIOSNodeChainAppendSources(owner, nodes: prefix)
        let keepsLast = prefix.count >= 2 && prefix.last?.id == finalID && ["shadowsocks", "hysteria2"].contains(prefix.last?.mode ?? "")
        guard keepsLast || !prefix.contains(where: { $0.id == finalID }),
              let expected = owner.fingerprints[finalID], try iosNodeChainEditorFingerprint(finalID) == expected,
              allNodeProfiles.filter({ $0.id == finalID }).count == 1 else {
            throw IOSMultihopNodeSelection.issue("Use the actual last paired Shadowsocks or Hysteria2 node, or choose a distinct final from the original linked sources.")
        }
    }

    func prepareIOSNodeChainAppendCompletion(_ draft: IOSNodeChainDraft, owner: IOSNodeChainEditorOwner,
                                             finalID: String) throws -> IOSNodeChainAppendCompletion {
        guard draft.unfinished else { throw IOSNodeCandidateAppendSource.issue() }
        let prefix = try draft.appendCompletionPath(profiles: iosNodeChainEditorProfiles(owner: owner))
        try requireIOSNodeChainAppendCompletionIdle(owner, prefix: prefix, finalID: finalID)
        let originalBundle = try IOSNodeUsage.canonical(bundle)
        let snapshot = try IOSNodeBundleStore.shared.candidateSnapshot()
        let deviceMTU = try IOSDeviceMTUPreference.current(), idleGeneration = iosConnectGeneration
        let finalMode = prefix.last?.id == finalID ? (prefix.last?.mode ?? "") : "shadowsocks"
        guard ["shadowsocks", "hysteria2"].contains(finalMode), snapshot.stamp.ready,
              let raw = IOSNodeBundleStore.shared.bundleData(containing: finalID, current: bundle),
              var value = try? JSONDecoder().decode(ClientBundle.self, from: raw),
              value.routerProfiles.filter({ $0.id == finalID }).count == 1,
              let index = value.routerProfiles.firstIndex(where: { $0.id == finalID }),
              value.routerProfiles[index].normalizedNodeKind == "router-vpn", value.routerProfiles[index].external == nil,
              value.profiles[finalMode]?["sing-box.json"]?.isEmpty == false else {
            throw IOSMultihopNodeSelection.issue("The final node needs the original paired source for its chosen transport.")
        }
        let nodes = prefix.last?.id == finalID ? prefix : prefix + [IOSMultihopNodeSelection(id: finalID, mode: finalMode)]
        try IOSMultihopNodeSelection.validate(nodes, execution: "local", entryID: nil, entryMode: nil,
                                             exitID: nil, exitMode: nil, controlID: finalID)
        value.selectedRouterID = finalID
        value.routerProfiles[index].multihopEnabled = true
        value.routerProfiles[index].multihopExecution = "local"
        value.routerProfiles[index].multihopNodes = nodes
        value.routerProfiles[index].multihopEntryID = nil; value.routerProfiles[index].multihopEntryMode = nil
        value.routerProfiles[index].multihopExitID = nil; value.routerProfiles[index].multihopExitMode = nil
        let final = value.routerProfiles[index]
        value.nodeProofID = final.nodeProofID ?? ""
        value.endpoint = final.endpoint; value.routerAPI = final.routerAPI; value.apiToken = final.apiToken
        value.adGuardIPv4 = final.adGuardIPv4; value.adGuardIPv6 = final.adGuardIPv6
        value.socks5Host = final.socksHost; value.socks5Port = final.socksPort
        value = try IOSDNSRuntimePolicy.patch(value)
        let captured = try captureIOSOrderedRoute(value)
        defer { try? captured.close() }
        _ = try IOSRuntimeSelector.selectNodeChain(captured)
        guard captured.members.map({ IOSMultihopNodeSelection(id: $0.id, mode: $0.mode) }) == nodes else {
            throw IOSNodeCandidateAppendSource.issue()
        }
        let profiles = try captured.members.map { try JSONDecoder().decode(RouterProfile.self, from: Data($0.profileJSON.utf8)) }
        let proposal = IOSNodeChainAppendCompletion(owner: owner, prefix: prefix, draftRevision: draft.revision,
            finalID: finalID, finalName: final.name.isEmpty ? finalID : final.name, profiles: profiles,
            launchInput: captured.launchInput, originalBundle: originalBundle, records: snapshot.records, stamp: snapshot.stamp,
            deviceMTU: deviceMTU, idleGeneration: idleGeneration)
        try captured.close()
        try requireIOSNodeChainAppendCompletion(proposal, draft: draft, owner: owner)
        return proposal
    }

    private func requireIOSNodeChainAppendCompletion(_ proposal: IOSNodeChainAppendCompletion,
                                                     draft: IOSNodeChainDraft, owner: IOSNodeChainEditorOwner) throws {
        guard draft.unfinished, draft.revision == proposal.draftRevision, draft.nodes == proposal.prefix,
              owner.controlID == proposal.owner.controlID, owner.fingerprints == proposal.owner.fingerprints,
              iosConnectGeneration == proposal.idleGeneration,
              try IOSNodeUsage.canonical(bundle) == proposal.originalBundle else { throw CancellationError() }
        try requireIOSNodeChainAppendCompletionIdle(owner, prefix: proposal.prefix, finalID: proposal.finalID)
        try proposal.deviceMTU.requireCurrent()
        let snapshot = try IOSNodeBundleStore.shared.candidateSnapshot()
        guard snapshot.stamp == proposal.stamp, snapshot.records == proposal.records else { throw CancellationError() }
    }

    func saveIOSNodeChainAppendCompletion(_ proposal: IOSNodeChainAppendCompletion, draft: IOSNodeChainDraft,
                                          owner: IOSNodeChainEditorOwner, name: String,
                                          current: () throws -> Void) throws -> String {
        try current()
        try requireIOSNodeChainAppendCompletion(proposal, draft: draft, owner: owner)
        let replay = try prepareIOSNodeChainAppendCompletion(draft, owner: owner, finalID: proposal.finalID)
        guard replay.launchInput == proposal.launchInput else { throw IOSNodeCandidateAppendSource.issue() }
        return try IOSCandidateConnectionProfiles.save(name: name, profiles: replay.profiles) {
            try current()
            try self.requireIOSNodeChainAppendCompletion(proposal, draft: draft, owner: owner)
        }
    }

    func iosNodeChainEditorBundle(_ nodes: [IOSMultihopNodeSelection], owner: IOSNodeChainEditorOwner, execution: String) throws -> ClientBundle {
        try IOSMultihopNodeSelection.validate(nodes, execution: execution, entryID: nil, entryMode: nil,
                                             exitID: nil, exitMode: nil, controlID: owner.controlID)
        try requireIOSNodeChainEditorOwner(owner, nodes: nodes)
        guard let final = nodes.first(where: { $0.id == owner.controlID }), var value = bundle else {
            throw IOSMultihopNodeSelection.issue("The final node no longer has its linked private source.")
        }
        guard value.routerProfiles.filter({ $0.id == final.id }).count == 1,
              let index = value.routerProfiles.firstIndex(where: { $0.id == final.id }),
              value.routerProfiles[index].normalizedNodeKind == "router-vpn", value.routerProfiles[index].external == nil else {
            throw IOSMultihopNodeSelection.issue("Choose a paired Router VPN node as the final node.")
        }
        value.selectedRouterID = final.id
        value.routerProfiles[index].multihopEnabled = true
        value.routerProfiles[index].multihopExecution = execution
        value.routerProfiles[index].multihopNodes = nodes
        value.routerProfiles[index].multihopEntryID = nil; value.routerProfiles[index].multihopEntryMode = nil
        value.routerProfiles[index].multihopExitID = nil; value.routerProfiles[index].multihopExitMode = nil
        let profile = value.routerProfiles[index]
        value.nodeProofID = profile.nodeProofID ?? ""
        value.endpoint = profile.endpoint; value.routerAPI = profile.routerAPI; value.apiToken = profile.apiToken
        value.adGuardIPv4 = profile.adGuardIPv4; value.adGuardIPv6 = profile.adGuardIPv6
        value.socks5Host = profile.socksHost; value.socks5Port = profile.socksPort
        return try IOSDNSRuntimePolicy.patch(value)
    }

    func iosNodeChainMeasurementBundle(_ draft: IOSNodeChainDraft, through position: Int, owner: IOSNodeChainEditorOwner, execution: String = "local") throws -> ClientBundle {
        let nodes = try draft.measurementPath(through: position, execution: execution, profiles: iosNodeChainEditorProfiles(owner: owner))
        let preview = try iosNodeChainEditorBundle(nodes, owner: owner, execution: execution)
        try requireIOSNodeChainEditorOwner(owner, nodes: nodes)
        return preview
    }

    func saveIOSNodeChain(_ nodes: [IOSMultihopNodeSelection], owner: IOSNodeChainEditorOwner, execution: String = "local") throws {
        let value = try iosNodeChainEditorBundle(nodes, owner: owner, execution: execution)
        // Compile every independent original source before the existing atomic
        // node-store link. Saving supplies no native runtime/proof authority.
        let capture = try captureIOSOrderedRoute(value)
        defer { try? capture.close() }
        _ = try IOSRuntimeSelector.selectNodeChain(capture)
        try requireIOSNodeChainEditorOwner(owner, nodes: nodes)
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
        try linkNodeBundle(encoder.encode(value))
        message = "Saved \(nodes.count) nodes in order. Connect verifies every node and the final DNS path."
    }
}


/// The visible picker uses the same original source admission as Save. These
/// values describe eligible roles; they do not confer native path proof.
enum IOSNodeChainEditorVisible {
    static func eligible(_ profile: RouterProfile) -> Bool {
        profile.normalizedNodeKind == "router-vpn" && profile.external == nil ||
            IOSImportedShadowsocksSource.eligible(profile) || IOSImportedSOCKSSource.eligible(profile) || (IOSImportedCONNECTSource.eligible(profile) || IOSImportedOpenVPNSource.eligible(profile))
    }
    static func unique(_ profiles: [RouterProfile]) -> [RouterProfile] {
        profiles.filter { profile in profiles.filter({ $0.id == profile.id }).count == 1 }
    }
    static func pairedStreamChoice(_ nodes: [IOSMultihopNodeSelection], at position: Int, execution: String, profiles: [RouterProfile]) -> Bool {
        guard nodes.indices.contains(position), position > 0, position < nodes.count-1 else { return false }
        var proposed = nodes
        proposed[position].mode = "shadowsocks"
        return IOSMultihopNodeSelection.pairedStreamPositions(proposed, execution: execution, profiles: profiles).contains(position)
    }

    static func modes(_ profile: RouterProfile?, nodeCount: Int = 2, mixedPacket: Bool = false, selectedPacket: Bool = false) -> [String] {
        guard let profile, eligible(profile) else { return [] }
        if profile.normalizedNodeKind == "external" { return [profile.external?.protocolName ?? ""] }
        if selectedPacket && nodeCount > IOSMultihopNodeSelection.maximumNodes { return IOSMultihopNodeSelection.nativePrefixModes }
        return nodeCount > IOSMultihopNodeSelection.maximumNodes && !mixedPacket ? ["wg"] : IOSMultihopNodeSelection.nativePrefixModes
    }
    static func finalModes(_ profile: RouterProfile?, nodes: [IOSMultihopNodeSelection], execution: String = "local",
                           linked: [RouterProfile] = [], bundle: ClientBundle? = nil) -> [String] {
        guard let profile, nodes.last?.id == profile.id else { return [] }
        if IOSImportedShadowsocksSource.eligibleLiteral(profile) && IOSMultihopNodeSelection.supportsNativePrefix(nodes.first?.mode ?? "") { return ["shadowsocks"] }
        guard profile.normalizedNodeKind == "router-vpn", profile.external == nil else { return [] }
        var modes = ["shadowsocks"]
        if nodes.count <= IOSMultihopNodeSelection.maximumNodes, [nil, "", "off", "aes-256-gcm", "aes-256-gcm+xor-whitening"].contains(profile.startLayer) &&
            nodes.dropLast().allSatisfy({ IOSMultihopNodeSelection.supportsNativePrefix($0.mode) }) {
            modes.append("hysteria2")
        }
        if execution == "local", nodes.count <= IOSMultihopNodeSelection.maximumNodes,
           [nil, "", "off"].contains(profile.startLayer), let bundle, bundle.selectedRouterID == profile.id,
           bundle.profiles["wg"]?["wg.conf"]?.isEmpty == false,
           nodes.dropLast().allSatisfy({ node in
               IOSMultihopNodeSelection.supportsNativePrefix(node.mode) && (node.id.isEmpty || linked.contains { member in
                   member.id == node.id && member.normalizedNodeKind == "router-vpn" && member.external == nil && [nil, "", "off"].contains(member.startLayer)
               })
           }) {
            modes += IOSMultihopNodeSelection.nativePrefixModes.filter { mode in
                bundle.profiles[mode]?[mode == "wg" ? "wg.conf" : "awg.conf"]?.isEmpty == false
            }
        }
        return modes
    }
    static func requireFinalMode(_ mode: String, profile: RouterProfile?, nodes: [IOSMultihopNodeSelection], execution: String = "local",
                                 linked: [RouterProfile] = [], bundle: ClientBundle? = nil) throws {
        guard finalModes(profile, nodes: nodes, execution: execution, linked: linked, bundle: bundle).contains(mode) else {
            throw IOSMultihopNodeSelection.issue("Choose a final transport compatible with its original node, Start Layer and preceding nodes.")
        }
    }
    static func candidates(_ profiles: [RouterProfile], nodes: [IOSMultihopNodeSelection], position: Int, execution: String = "local") -> [RouterProfile] {
        guard nodes.indices.contains(position), position < nodes.count - 1 else { return [] }
        if let final = nodes.last, profiles.contains(where: { $0.id == final.id && IOSImportedShadowsocksSource.eligibleLiteral($0) }) {
            guard ["local", "server", "auto"].contains(execution) else { return [] }
            return unique(profiles).filter { profile in
                position == 0 ? profile.id == nodes.first?.id && profile.normalizedNodeKind == "router-vpn" :
                    IOSImportedShadowsocksSource.eligibleLiteral(profile) && !nodes.enumerated().contains { $0.offset != position && $0.element.id == profile.id }
            }
        }
        let customEntry = nodes.count == 3 && nodes.last?.mode == "shadowsocks" &&
            (position == 0 || nodes.first?.mode == "shadowsocks")
        let retainedStream = IOSMultihopNodeSelection.pairedStreamPositions(nodes, execution: "local", profiles: profiles).contains(position)
        return unique(profiles).filter { profile in
            var proposed = nodes
            proposed[position] = .init(id: profile.id, mode: profile.external?.protocolName ?? nodes[position].mode)
            let hostname = IOSImportedShadowsocksSource.hasHostnameTransport(profile)
            let independentHostname = hostname && (IOSMultihopNodeSelection.independentHostnamePosition(proposed, execution: execution) == position ||
                IOSMultihopNodeSelection.localStreamLayout(proposed, execution: execution, profiles: profiles)?.hostname == position)
            if hostname && IOSMultihopNodeSelection.requiresImportedNodesSource(proposed) && !independentHostname { return false }
            let pairedChoice = profile.normalizedNodeKind == "router-vpn" && pairedStreamChoice(proposed, at: position, execution: execution, profiles: profiles)
            let extendedPosition = pairedChoice || independentHostname || nodes.count <= IOSMultihopNodeSelection.maximumNodes ||
                retainedStream && profile.id == nodes[position].id ||
                (IOSMultihopNodeSelection.supportsNativePrefix(nodes[position].mode) ? profile.normalizedNodeKind == "router-vpn" && [nil, "", "off"].contains(profile.startLayer) : IOSImportedShadowsocksSource.eligibleLiteral(profile))
            return eligible(profile) && extendedPosition &&
            (profile.normalizedNodeKind != "external" || (customEntry ? IOSImportedShadowsocksSource.eligibleLiteral(profile) : IOSMultihopNodeSelection.supportsImportedMiddle(profile.external?.protocolName ?? "", position: position, count: nodes.count) || IOSMultihopNodeSelection.supportsLocalImportedNode(profile.external?.protocolName ?? "", position: position, count: nodes.count) && (IOSImportedShadowsocksSource.eligibleLiteral(profile) || independentHostname)) && nodes.last?.mode == "shadowsocks") &&
            !nodes.enumerated().contains(where: { $0.offset != position && $0.element.id == profile.id })
        }
    }
}

@MainActor extension RouterVPNModel {
    func iosNodeChainEditorProfiles(owner: IOSNodeChainEditorOwner?) -> [RouterProfile] {
        guard let owner, bundle?.selectedRouterID == owner.controlID, !profileMutationBlocked, !iosSpeedLabOwnership.active else { return [] }
        return IOSNodeChainEditorVisible.unique(allNodeProfiles).filter { profile in
            guard IOSNodeChainEditorVisible.eligible(profile), let expectedHash = owner.fingerprints[profile.id],
                  let actualHash = try? iosNodeChainEditorFingerprint(profile.id), actualHash == expectedHash else { return false }
            return true
        }
    }
}
