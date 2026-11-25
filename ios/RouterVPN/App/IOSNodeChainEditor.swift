import Foundation

/// Only ordered references live in the editor. Credentials and transport
/// assets stay in each original linked node record.
struct IOSNodeChainDraft {
    private(set) var nodes: [IOSMultihopNodeSelection]
    let controlID: String

    init(saved: [IOSMultihopNodeSelection]? = nil, finalID: String = "") {
        controlID = finalID
        nodes = saved ?? [.init(id: "", mode: "wg"), .init(id: finalID, mode: "shadowsocks")]
    }

    var canSave: Bool {
        ((2...IOSMultihopNodeSelection.maximumNodes).contains(nodes.count) || IOSMultihopNodeSelection.extendedOriginalModes(nodes.map(\.mode), execution: "local")) &&
            nodes.allSatisfy({ $0.id.range(of: "\\A[A-Za-z0-9_-]{1,64}\\z", options: .regularExpression) != nil }) &&
            Set(nodes.map(\.id)).count == nodes.count && nodes.last?.id == controlID &&
            (nodes.first?.mode != "shadowsocks" || IOSMultihopNodeSelection.usesLocalImportedEntry(nodes)) &&
            nodes.dropLast().enumerated().allSatisfy({ position, node in IOSMultihopNodeSelection.supportsNativePrefix(node.mode) || (IOSMultihopNodeSelection.supportsImportedMiddle(node.mode, position: position, count: nodes.count) || IOSMultihopNodeSelection.supportsLocalImportedNode(node.mode, position: position, count: nodes.count, importedEntry: IOSMultihopNodeSelection.usesLocalImportedEntry(nodes))) && nodes.last?.mode == "shadowsocks" }) &&
            IOSMultihopNodeSelection.nativeFinalModes.contains(nodes.last?.mode ?? "")
    }

    /// The temporary provider receives a complete compilable Local source.
    /// Keep every chosen suffix node and its policy in the source. The
    /// provider only opens the prefix, and empty editor rows supply no node.
    func measurementPath(through position: Int, execution: String = "local", profiles: @autoclosure () -> [RouterProfile] = []) throws -> [IOSMultihopNodeSelection] {
        guard position >= 0, position < nodes.count - 1, let final = nodes.last,
              final.id == controlID, !final.id.isEmpty else {
            throw IOSMultihopNodeSelection.issue("Choose a linked final node and a preceding prefix.")
        }
        let prefix = nodes.prefix(position + 1)
        let selected = nodes.filter { !$0.id.isEmpty }
        let linked = profiles()
        let hasIndependentHostname = IOSMultihopNodeSelection.hasIndependentHostname(nodes, profiles: linked)
        if ["server", "auto"].contains(execution) {
            if execution == "auto", position == 1, nodes.map(\.mode) == ["wg", "shadowsocks", "shadowsocks"],
               Set(nodes.map(\.id)).count == 3, nodes.allSatisfy({ !$0.id.isEmpty }),
               nodes.enumerated().allSatisfy({ index, node in
                   let matches = linked.filter { $0.id == node.id }
                   guard matches.count == 1, let profile = matches.first, [nil, "", "off"].contains(profile.startLayer) else { return false }
                   return index == 1 ? IOSImportedShadowsocksSource.eligibleLiteral(profile) :
                        profile.normalizedNodeKind == "router-vpn" && profile.external == nil
               }) { return nodes }
            let hasPairedStream = selected.dropFirst().dropLast().contains { node in
                node.mode == "shadowsocks" && linked.contains { $0.id == node.id && $0.normalizedNodeKind == "router-vpn" }
            }
            if hasPairedStream {
                guard position == 0, selected == nodes,
                      !IOSMultihopNodeSelection.pairedStreamPositions(nodes, execution: execution, profiles: linked).isEmpty else {
                    throw IOSMultihopNodeSelection.issue("Measure the original WireGuard entry of a qualified Server or Compare private-stream route.")
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
        let packet = prefix.allSatisfy { IOSMultihopNodeSelection.supportsNativePrefix($0.mode) }
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
        guard nodes.indices.contains(position), position < nodes.count - 1,
              id.isEmpty || !nodes.enumerated().contains(where: { $0.offset != position && $0.element.id == id }) else {
            throw IOSMultihopNodeSelection.issue("Choose a different linked node for each position.")
        }
        nodes[position].id = id
    }

    mutating func chooseMode(_ mode: String, at position: Int) throws {
        guard nodes.indices.contains(position), position < nodes.count - 1,
              nodes.count <= IOSMultihopNodeSelection.maximumNodes || mode == "wg" || mode == "shadowsocks" || IOSMultihopNodeSelection.extendedMixedPacketCount(nodes.enumerated().map { $0.offset == position ? mode : $0.element.mode }, execution: "local") > 0,
              (IOSMultihopNodeSelection.supportsNativePrefix(mode) || IOSMultihopNodeSelection.supportsImportedMiddle(mode, position: position, count: nodes.count) || IOSMultihopNodeSelection.supportsLocalImportedNode(mode, position: position, count: nodes.count, importedEntry: position == 0 && nodes.count == 3 && nodes.last?.mode == "shadowsocks")) else {
            throw IOSMultihopNodeSelection.issue("Choose WireGuard or AWG2 for a paired packet node. Paired Shadowsocks 2022 stream nodes can share a Local route with imports when every node uses Start Layer Off. The first stream can use a hostname with its saved Custom TCP resolver. In Local execution, Shadowsocks 2022, SOCKS5, HTTP/HTTPS CONNECT or OpenVPN can follow one to six paired prefixes immediately before a Shadowsocks final (three to eight nodes total). Shadowsocks 2022 also supports Server and Compare with three to eight nodes for a literal IP address, or four to eight for a hostname using its saved Custom TCP resolver with an explicit IP address and port. HTTP/HTTPS CONNECT supports Server and Compare with three to eight nodes and an independent Off, AES or AES with XOR whitening layer on the paired final; SOCKS5 and separately paired OpenVPN also support Server and Compare after one to six paired nodes before the Shadowsocks final. OpenVPN retains independent Local and Server provider credentials.")
        }
        nodes[position].mode = mode
    }

    func canAppend(execution: String) -> Bool {
        nodes.count < IOSMultihopNodeSelection.maximumNodes ||
            IOSMultihopNodeSelection.extendedOriginalModes(nodes.map(\.mode) + ["shadowsocks"], execution: execution) ||
            IOSMultihopNodeSelection.extendedPairedModes(nodes.dropLast().map(\.mode) + ["wg", nodes.last?.mode ?? ""], execution: execution)
    }

    mutating func append(execution: String = "local") throws {
        guard canAppend(execution: execution) else {
            throw IOSMultihopNodeSelection.issue("This route cannot add another preceding node with its current transport and execution choices.")
        }
        if nodes.count >= IOSMultihopNodeSelection.maximumNodes {
            let paired = IOSMultihopNodeSelection.extendedPairedModes(nodes.dropLast().map(\.mode) + ["wg", nodes.last?.mode ?? ""], execution: execution)
            nodes.insert(.init(id: "", mode: paired ? "wg" : "shadowsocks"), at: nodes.count - 1)
            return
        }
        let beforeCONNECT = nodes.count >= 3 && ["shadowsocks", "socks5", "http-connect", "https-connect", "openvpn"].contains(nodes[nodes.count - 2].mode)
        nodes.insert(.init(id: "", mode: "wg"), at: nodes.count - (beforeCONNECT ? 2 : 1))
    }

    mutating func chooseFinalMode(_ mode: String) throws {
        guard !nodes.isEmpty, IOSMultihopNodeSelection.nativeFinalModes.contains(mode),
              mode == "shadowsocks" || nodes.count <= IOSMultihopNodeSelection.maximumNodes && nodes.dropLast().allSatisfy({ IOSMultihopNodeSelection.supportsNativePrefix($0.mode) }) else {
            throw IOSMultihopNodeSelection.issue("Hysteria2 requires paired WireGuard or AWG2 preceding nodes and an independent Off, AES or AES with XOR whitening layer on the final node.")
        }
        nodes[nodes.count - 1].mode = mode
    }

    mutating func remove(at position: Int) throws {
        guard nodes.count > 2, nodes.indices.contains(position), position < nodes.count - 1 else {
            throw IOSMultihopNodeSelection.issue("Keep at least two nodes in the ordered route.")
        }
        nodes.remove(at: position)
    }

    mutating func move(from position: Int, to destination: Int) throws {
        guard nodes.indices.contains(position), nodes.indices.contains(destination),
              position < nodes.count - 1, destination < nodes.count - 1 else {
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
              bundle?.selectedRouterID == owner.controlID, nodes.last?.id == owner.controlID else {
            throw IOSMultihopNodeSelection.issue("The selected final node or connection owner changed. Reopen the ordered route editor.")
        }
        for node in nodes {
            guard let expected = owner.fingerprints[node.id], try iosNodeChainEditorFingerprint(node.id) == expected else {
                throw IOSMultihopNodeSelection.issue("An ordered node was removed or relinked. Reopen the editor to use its current source.")
            }
        }
    }

    func iosNodeChainEditorBundle(_ nodes: [IOSMultihopNodeSelection], owner: IOSNodeChainEditorOwner, execution: String) throws -> ClientBundle {
        try IOSMultihopNodeSelection.validate(nodes, execution: execution, entryID: nil, entryMode: nil,
                                             exitID: nil, exitMode: nil, controlID: owner.controlID)
        try requireIOSNodeChainEditorOwner(owner, nodes: nodes)
        guard let final = nodes.last, var value = bundle else {
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
    static func finalModes(_ profile: RouterProfile?, nodes: [IOSMultihopNodeSelection]) -> [String] {
        guard let profile, profile.normalizedNodeKind == "router-vpn", profile.external == nil,
              nodes.last?.id == profile.id else { return [] }
        var modes = ["shadowsocks"]
        if nodes.count <= IOSMultihopNodeSelection.maximumNodes, [nil, "", "off", "aes-256-gcm", "aes-256-gcm+xor-whitening"].contains(profile.startLayer) &&
            nodes.dropLast().allSatisfy({ IOSMultihopNodeSelection.supportsNativePrefix($0.mode) }) {
            modes.append("hysteria2")
        }
        return modes
    }
    static func requireFinalMode(_ mode: String, profile: RouterProfile?, nodes: [IOSMultihopNodeSelection]) throws {
        guard finalModes(profile, nodes: nodes).contains(mode) else {
            throw IOSMultihopNodeSelection.issue("Choose a final transport compatible with its original node, Start Layer and preceding nodes.")
        }
    }
    static func candidates(_ profiles: [RouterProfile], nodes: [IOSMultihopNodeSelection], position: Int, execution: String = "local") -> [RouterProfile] {
        guard nodes.indices.contains(position), position < nodes.count - 1 else { return [] }
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
