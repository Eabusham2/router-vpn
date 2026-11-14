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
        (2...IOSMultihopNodeSelection.maximumNodes).contains(nodes.count) &&
            nodes.allSatisfy({ $0.id.range(of: "\\A[A-Za-z0-9_-]{1,64}\\z", options: .regularExpression) != nil }) &&
            Set(nodes.map(\.id)).count == nodes.count && nodes.last?.id == controlID &&
            nodes.dropLast().enumerated().allSatisfy({ position, node in IOSMultihopNodeSelection.supportsNativePrefix(node.mode) || nodes.count == 3 && position == 1 && ["shadowsocks", "socks5", "http-connect", "https-connect"].contains(node.mode) && nodes.last?.mode == "shadowsocks" }) &&
            IOSMultihopNodeSelection.nativeFinalModes.contains(nodes.last?.mode ?? "")
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
              (IOSMultihopNodeSelection.supportsNativePrefix(mode) || nodes.count == 3 && position == 1 && ["shadowsocks", "socks5", "http-connect", "https-connect"].contains(mode)) else {
            throw IOSMultihopNodeSelection.issue("Choose WireGuard, AWG2 Fast or AWG2 Strong for a preceding node.")
        }
        nodes[position].mode = mode
    }

    mutating func append() throws {
        guard nodes.count < IOSMultihopNodeSelection.maximumNodes else {
            throw IOSMultihopNodeSelection.issue("An ordered route supports at most eight nodes.")
        }
        nodes.insert(.init(id: "", mode: "wg"), at: nodes.count - 1)
    }

    mutating func chooseFinalMode(_ mode: String) throws {
        guard !nodes.isEmpty, IOSMultihopNodeSelection.nativeFinalModes.contains(mode),
              mode == "shadowsocks" || nodes.dropLast().allSatisfy({ IOSMultihopNodeSelection.supportsNativePrefix($0.mode) }) else {
            throw IOSMultihopNodeSelection.issue("Hysteria2 requires paired WireGuard or AWG2 preceding nodes and Start Layer Off on the final node.")
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
              (profile.normalizedNodeKind == "router-vpn" && profile.external == nil || (IOSImportedShadowsocksSource.eligible(profile) || IOSImportedSOCKSSource.eligible(profile) || IOSImportedCONNECTSource.eligible(profile))) else {
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
        for profile in allNodeProfiles where profile.normalizedNodeKind == "router-vpn" && profile.external == nil || (IOSImportedShadowsocksSource.eligible(profile) || IOSImportedSOCKSSource.eligible(profile) || IOSImportedCONNECTSource.eligible(profile)) {
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

    func saveIOSNodeChain(_ nodes: [IOSMultihopNodeSelection], owner: IOSNodeChainEditorOwner) throws {
        try IOSMultihopNodeSelection.validate(nodes, execution: "local", entryID: nil, entryMode: nil,
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
        value.routerProfiles[index].multihopExecution = "local"
        value.routerProfiles[index].multihopNodes = nodes
        value.routerProfiles[index].multihopEntryID = nil; value.routerProfiles[index].multihopEntryMode = nil
        value.routerProfiles[index].multihopExitID = nil; value.routerProfiles[index].multihopExitMode = nil
        let profile = value.routerProfiles[index]
        value.nodeProofID = profile.nodeProofID ?? ""
        value.endpoint = profile.endpoint; value.routerAPI = profile.routerAPI; value.apiToken = profile.apiToken
        value.adGuardIPv4 = profile.adGuardIPv4; value.adGuardIPv6 = profile.adGuardIPv6
        value.socks5Host = profile.socksHost; value.socks5Port = profile.socksPort
        value = try IOSDNSRuntimePolicy.patch(value)
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
            IOSImportedShadowsocksSource.eligible(profile) || IOSImportedSOCKSSource.eligible(profile) || IOSImportedCONNECTSource.eligible(profile)
    }
    static func unique(_ profiles: [RouterProfile]) -> [RouterProfile] {
        profiles.filter { profile in profiles.filter({ $0.id == profile.id }).count == 1 }
    }
    static func modes(_ profile: RouterProfile?) -> [String] {
        guard let profile, eligible(profile) else { return [] }
        if profile.normalizedNodeKind == "external" { return [profile.external?.protocolName ?? ""] }
        return IOSMultihopNodeSelection.nativePrefixModes
    }
    static func candidates(_ profiles: [RouterProfile], nodes: [IOSMultihopNodeSelection], position: Int) -> [RouterProfile] {
        guard nodes.indices.contains(position), position < nodes.count - 1 else { return [] }
        return unique(profiles).filter { profile in
            eligible(profile) &&
            (profile.normalizedNodeKind != "external" || nodes.count == 3 && position == 1 && nodes.last?.mode == "shadowsocks") &&
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
