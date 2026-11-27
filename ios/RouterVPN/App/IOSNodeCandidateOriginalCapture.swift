import Foundation
import Libbox

struct IOSNodeCandidateResponseNode: Codable, Equatable {
    let id: String, mode: String, kind: String
    init(id: String, mode: String, kind: String = "router-vpn") { self.id = id; self.mode = mode; self.kind = kind }
    init(from decoder: Decoder) throws {
        let value = try decoder.singleValueContainer().decode([String: String].self)
        guard Set(value.keys) == ["id", "mode", "kind"],
              value["kind"] == "router-vpn" || value["kind"] == "external" && value["mode"] == "shadowsocks",
              let id = value["id"], !id.isEmpty, let mode = value["mode"],
              ["wg", "awg2-fast", "awg2-strong", "shadowsocks", "hysteria2"].contains(mode) else { throw IOSNodeCandidateOriginalCapture.issue() }
        self.init(id: id, mode: mode, kind: value["kind"]!)
    }
    var object: [String: String] { ["id": id, "mode": mode, "kind": kind] }
}

struct IOSNodeCandidatePrefix: Decodable, Equatable {
    let position: Int
    let profile_id: String
    let node_id: String
    let mode: String
    var measurement: String? = nil
    var candidate_mode: String? = nil
    var purpose: String? = nil
    var metric: String { measurement ?? "routed-tcp-connect" }
    var pairedFinalResponse: Bool {
        purpose == nil && (candidate_mode == "hysteria2" || IOSMultihopNodeSelection.supportsNativePrefix(candidate_mode ?? "")) &&
            metric == "routed-candidate-response" &&
            (IOSMultihopNodeSelection.supportsNativePrefix(mode) && !node_id.isEmpty ||
             IOSMultihopNodeSelection.supportsNativePrefix(candidate_mode ?? "") && mode == "shadowsocks" && node_id.isEmpty)
    }
    func packetSuccessorResponse(in proofs: [Self]) -> Bool {
        pairedFinalResponse && IOSMultihopNodeSelection.supportsNativePrefix(candidate_mode ?? "") &&
            position >= 0 && position < proofs.count - 2 && proofs[position] == self && candidate_mode == proofs[position + 1].mode
    }
    var typedImportedResponse: Bool {
        candidate_mode == nil && metric == "routed-candidate-response" && ["socks5", "http-connect", "https-connect", "openvpn"].contains(mode)
    }
    func appendResponse(in proofs: [Self]) -> Bool {
        guard purpose == "draft-prefix-append", metric == "routed-candidate-response",
              IOSNodeCandidateAppendSource.supportsNextMode(candidate_mode ?? ""),
              (1..<IOSMultihopNodeSelection.physicalTraversalDepth).contains(proofs.count),
              position == proofs.count - 1, proofs.last == self,
              Set(proofs.map(\.profile_id)).count == proofs.count else { return false }
        let pairedIDs = proofs.map(\.node_id).filter { !$0.isEmpty }
        guard Set(pairedIDs).count == pairedIDs.count,
              !proofs[0].node_id.isEmpty, IOSMultihopNodeSelection.supportsNativePrefix(proofs[0].mode) else { return false }
        return proofs.enumerated().allSatisfy { index, row in
            row.position == index && !row.profile_id.isEmpty &&
                (IOSMultihopNodeSelection.supportsNativePrefix(row.mode) && !row.node_id.isEmpty || index > 0 && row.mode == "shadowsocks") &&
                (index == position ? row == self : row.measurement == nil && row.candidate_mode == nil && row.purpose == nil)
        }
    }
    var supported: Bool {
        if purpose != nil {
            return purpose == "draft-prefix-append" && metric == "routed-candidate-response" &&
                IOSNodeCandidateAppendSource.supportsNextMode(candidate_mode ?? "") &&
                (IOSMultihopNodeSelection.supportsNativePrefix(mode) && !node_id.isEmpty || position > 0 && mode == "shadowsocks") &&
                (0..<(IOSMultihopNodeSelection.physicalTraversalDepth - 1)).contains(position)
        }
        if candidate_mode != nil {
            let limit = mode == "wg" && candidate_mode == "wg" ? IOSMultihopNodeSelection.physicalTraversalDepth - 2 : IOSMultihopNodeSelection.maximumNodes - 1
            return pairedFinalResponse && (0..<limit).contains(position)
        }
        switch metric {
        case "routed-tcp-connect": return ["wg", "awg2-fast", "awg2-strong"].contains(mode)
        case "routed-candidate-response": return (mode == "shadowsocks" || typedImportedResponse && node_id.isEmpty) && (1..<(IOSMultihopNodeSelection.physicalTraversalDepth - 1)).contains(position)
        case "routed-public-candidate-response": return mode == "shadowsocks" && node_id.isEmpty && (1..<(IOSMultihopNodeSelection.physicalTraversalDepth - 1)).contains(position)
        default: return false
        }
    }
    func selectedResponse(in proofs: [Self]) -> Bool {
        guard purpose == nil, proofs.allSatisfy({ $0.purpose == nil }) else { return false }
        if candidate_mode != nil {
            return packetSuccessorResponse(in: proofs) && supported(in: proofs)
        }
        guard proofs.allSatisfy({ $0.candidate_mode == nil }) else { return false }
        if metric == "routed-public-candidate-response" || typedImportedResponse { return supported(in: proofs) }
        guard (3...IOSMultihopNodeSelection.physicalTraversalDepth).contains(proofs.count), position > 0, position < proofs.count - 1,
              proofs[position] == self, metric == "routed-candidate-response",
              IOSMultihopNodeSelection.supportsNativePrefix(proofs.first?.mode ?? ""), proofs.dropFirst().allSatisfy({ $0.mode == "shadowsocks" }),
              Set(proofs.map(\.profile_id)).count == proofs.count else { return false }
        let privateIDs = proofs.map(\.node_id).filter { !$0.isEmpty }
        let privateStops = proofs.dropFirst().dropLast().filter { !$0.node_id.isEmpty }
        guard Set(privateIDs).count == privateIDs.count,
              !proofs[0].node_id.isEmpty, !proofs[proofs.count-1].node_id.isEmpty,
              privateStops.allSatisfy({ $0.position >= 2 }) else { return false }
        let finalPrefix = proofs.count - 2
        let first = proofs.count < IOSMultihopNodeSelection.physicalTraversalDepth ? 1 : finalPrefix
        let eligible = first...finalPrefix
        return eligible.contains(position) && proofs.enumerated().allSatisfy { index, row in
            row.position == index && row.measurement == (eligible.contains(index) ? "routed-candidate-response" : nil)
        }
    }
    func supported(in proofs: [Self]) -> Bool {
        if proofs.contains(where: { $0.purpose != nil }) { return supported && appendResponse(in: proofs) }
        guard supported, proofs.indices.contains(position), position < proofs.count - 1, proofs[position] == self else { return false }
        if pairedFinalResponse {
            let bounded = (2...IOSMultihopNodeSelection.maximumNodes).contains(proofs.count)
            let privateIDs = proofs.map(\.node_id).filter { !$0.isEmpty }
            guard bounded || IOSMultihopNodeSelection.extendedPairedModes(proofs.map(\.mode), execution: "local"),
                  Set(proofs.map(\.profile_id)).count == proofs.count, Set(privateIDs).count == privateIDs.count,
                  let final = proofs.last, !proofs[0].node_id.isEmpty, !final.node_id.isEmpty else { return false }
            return proofs.enumerated().allSatisfy { index, row in
                guard row.position == index, !row.profile_id.isEmpty, row.purpose == nil else { return false }
                if row.node_id.isEmpty {
                    guard bounded, (3...IOSMultihopNodeSelection.maximumNodes).contains(proofs.count),
                          index > 0, index < proofs.count - 1, row.mode == "shadowsocks", final.mode == "shadowsocks" else { return false }
                    return row.candidate_mode == nil
                        ? row.measurement == nil || row.measurement == "routed-candidate-response"
                        : row.packetSuccessorResponse(in: proofs)
                }
                if index == proofs.count - 1 {
                    return row.measurement == nil && row.candidate_mode == nil &&
                        (["shadowsocks", "hysteria2"].contains(row.mode) || bounded && IOSMultihopNodeSelection.supportsNativePrefix(row.mode))
                }
                guard IOSMultihopNodeSelection.supportsNativePrefix(row.mode) else { return false }
                if row.candidate_mode == nil { return row.measurement == nil }
                if index == proofs.count - 2 { return bounded && row.pairedFinalResponse && row.candidate_mode == final.mode }
                return ["shadowsocks", "hysteria2"].contains(final.mode) && row.packetSuccessorResponse(in: proofs)
            }
        }
        guard proofs.allSatisfy({ $0.candidate_mode == nil || $0.pairedFinalResponse }) else { return false }
        if metric == "routed-candidate-response", mode == "shadowsocks", proofs.first?.mode == "shadowsocks" {
            return importedEntryFinalResponse(in: proofs)
        }
        if typedImportedResponse {
            guard (3...IOSMultihopNodeSelection.maximumNodes).contains(proofs.count),
                  position == proofs.count - 2, proofs[position] == self,
                  Set(proofs.map(\.profile_id)).count == proofs.count else { return false }
            let privateIDs = proofs.map(\.node_id).filter { !$0.isEmpty }
            guard privateIDs.count == proofs.count - 1, Set(privateIDs).count == privateIDs.count else { return false }
            return proofs.enumerated().allSatisfy { index, row in
                guard row.position == index, !row.profile_id.isEmpty else { return false }
                if index == position { return row.node_id.isEmpty && row.typedImportedResponse }
                if index == proofs.count - 1 { return row.mode == "shadowsocks" && !row.node_id.isEmpty && row.measurement == nil }
                return IOSMultihopNodeSelection.supportsNativePrefix(row.mode) && !row.node_id.isEmpty && row.measurement == nil
            }
        }
        if metric == "routed-public-candidate-response" {
            guard (3...IOSMultihopNodeSelection.physicalTraversalDepth).contains(proofs.count),
                  proofs.indices.contains(position), position > 0, position < proofs.count - 1, proofs[position] == self,
                  Set(proofs.map(\.profile_id)).count == proofs.count else { return false }
            return proofs.enumerated().allSatisfy { index, row in
                guard row.position == index, !row.profile_id.isEmpty else { return false }
                if index == 0 { return IOSMultihopNodeSelection.supportsNativePrefix(row.mode) && !row.node_id.isEmpty && row.measurement == nil }
                return row.mode == "shadowsocks" && row.node_id.isEmpty &&
                    row.measurement == (index < proofs.count - 1 ? "routed-public-candidate-response" : nil)
            }
        }
        let modes = proofs.map(\.mode)
        let mixedPackets = IOSMultihopNodeSelection.extendedMixedPacketCount(modes, execution: "local")
        guard mixedPackets > 0 || position >= IOSMultihopNodeSelection.maximumNodes - 1 && metric == "routed-candidate-response" else { return true }
        guard mixedPackets > 0 || IOSMultihopNodeSelection.extendedLocalModes(modes, execution: "local"),
              proofs.indices.contains(position), position < proofs.count - 1, self == proofs[position],
              proofs.enumerated().allSatisfy({ $0.offset == $0.element.position }),
              Set(proofs.map(\.profile_id)).count == proofs.count else { return false }
        let packets = max(1, mixedPackets)
        let privateIDs = proofs.map(\.node_id).filter { !$0.isEmpty }
        guard Set(privateIDs).count == privateIDs.count, proofs.dropFirst(packets).dropLast().contains(where: { $0.node_id.isEmpty }) else { return false }
        return proofs.enumerated().allSatisfy { index, proof in
            if index < packets { return !proof.node_id.isEmpty && proof.metric == "routed-tcp-connect" }
            if index == proofs.count - 1 { return !proof.node_id.isEmpty && proof.measurement == nil }
            return proof.mode == "shadowsocks" && proof.metric == "routed-candidate-response"
        }
    }

    func connectedFinalResponse(in proofs: [Self]) -> Bool {
        guard purpose == nil else { return false }
        return (typedImportedResponse || pairedFinalResponse) ? position == proofs.count - 2 && supported(in: proofs) : importedEntryFinalResponse(in: proofs)
    }

    private func importedEntryFinalResponse(in proofs: [Self]) -> Bool {
        guard proofs.allSatisfy({ $0.purpose == nil }), proofs.count == 3, position == 1, proofs[1] == self,
              metric == "routed-candidate-response", Set(proofs.map(\.profile_id)).count == proofs.count else { return false }
        return proofs.enumerated().allSatisfy { index, row in
            row.position == index && !row.profile_id.isEmpty && row.mode == "shadowsocks" &&
                (index < 2 ? row.node_id.isEmpty : !row.node_id.isEmpty) &&
                row.measurement == (index == 1 ? "routed-candidate-response" : nil)
        }
    }
}

/// Complete saved Local source retained for independent prefix measurement
/// and future-profile proposals. This union grants no forwarding authority.
enum IOSNodeCandidateOriginalCapture {
    case ordinary(IOSNodeChainCapture)
    case socks(IOSNodeChainSOCKSCapture)
    case connect(IOSNodeChainCONNECTCapture)
    case append(IOSNodeCandidateAppendSource)

    var appendSource: IOSNodeCandidateAppendSource? { if case .append(let value) = self { return value }; return nil }
    var isAppend: Bool { appendSource != nil }

    var members: [IOSNodeChainCapture.Member] { switch self { case .ordinary(let v): return v.members; case .socks(let v): return v.members; case .connect(let v): return v.members; case .append(let v): return v.members } }
    var launchInput: String { switch self { case .ordinary(let v): return v.launchInput; case .socks(let v): return v.source; case .connect(let v): return v.source; case .append(let v): return v.source } }
    var originalSource: String? { switch self { case .ordinary(let v): return v.originalSource; case .socks(let v): return v.source; case .connect(let v): return v.source; case .append(let v): return v.source } }
    var sourceSHA256: String { switch self { case .ordinary(let v): return v.sourceSHA256; case .socks(let v): return v.sourceSHA256; case .connect(let v): return v.sourceSHA256; case .append(let v): return v.sourceSHA256 } }
    var configSHA256: String { switch self { case .ordinary(let v): return v.configSHA256; case .socks(let v): return v.plan.configSHA256(); case .connect(let v): return v.plan.configSHA256(); case .append(let v): return v.configSHA256 } }
    var selectionExecution: String { switch self { case .ordinary(let v): return v.selectionExecution; case .socks(let v): return v.selectionExecution; case .connect(let v): return v.selectionExecution; case .append: return "local" } }
    var strict: Bool { switch self { case .ordinary(let v): return v.strict; case .socks(let v): return v.strict; case .connect(let v): return v.strict; case .append(let v): return v.strict } }
    var homeLANAccess: Bool { switch self { case .ordinary(let v): return v.homeLANAccess; case .socks(let v): return v.homeLANAccess; case .connect(let v): return v.homeLANAccess; case .append(let v): return v.homeLANAccess } }
    var preparationKind: String {
        switch self {
        case .ordinary(let capture):
            if capture.sourceSchema == 6 || capture.sourceSchema == 8 {
                return "routervpn-node-chain-multiple-imported-candidate-preparation"
            }
            return "routervpn-node-chain-candidate-preparation"
        case .socks: return "routervpn-node-chain-socks-candidate-preparation"
        case .connect: return "routervpn-node-chain-connect-candidate-preparation"
        case .append: return "routervpn-node-chain-candidate-append-preparation"
        }
    }
    var requiresIndependentPrefix: Bool { if case .ordinary = self { return false }; return true }

    func canPreparePrefix(at position: Int) -> Bool {
        if case .append(let source) = self { return position == members.count - 1 && source.prefixes.last?.appendResponse(in: source.prefixes) == true }
        guard selectionExecution == "local", position >= 0, position < members.count - 1 else { return false }
        let prefix = members.prefix(position + 1)
        if prefix.allSatisfy({ IOSMultihopNodeSelection.supportsNativePrefix($0.mode) }) { return true }
        guard case .ordinary(let capture) = self else { return false }
        let metric = LibboxRouterNodeChainCandidatePrefixMeasurement(capture.plan, Int32(position))
        if ["routed-candidate-response", "routed-public-candidate-response"].contains(metric) { return true }
        guard capture.sourceSchema == 6, metric == "routed-tcp-connect" else { return false }
        return prefix.allSatisfy { member in
            if IOSMultihopNodeSelection.supportsNativePrefix(member.mode) { return true }
            guard member.mode == "shadowsocks", member.profile["node_kind"] as? String == "external",
                  let profile = try? JSONDecoder().decode(RouterProfile.self, from: Data(member.profileJSON.utf8)) else { return false }
            return IOSImportedShadowsocksSource.eligibleLiteral(profile)
        }
    }

    private enum Purpose { case ordinary, connected, prepared }
    var candidatePrefixes: [IOSNodeCandidatePrefix] { makeCandidatePrefixes(for: .ordinary) }
    var connectedCandidatePrefixes: [IOSNodeCandidatePrefix] { makeCandidatePrefixes(for: .connected) }
    var preparedCandidatePrefixes: [IOSNodeCandidatePrefix] { makeCandidatePrefixes(for: .prepared) }

    private func makeCandidatePrefixes(for purpose: Purpose) -> [IOSNodeCandidatePrefix] {
        if case .append(let source) = self { return purpose == .prepared ? source.prefixes : [] }
        return members.enumerated().map { position, member in
            var prefix = IOSNodeCandidatePrefix(position: position, profile_id: member.id,
                node_id: member.profile["node_proof_id"] as? String ?? "", mode: member.mode)
            if member.mode == "shadowsocks", case .ordinary(let capture) = self, selectionExecution == "local" {
                let metric = LibboxRouterNodeChainCandidatePrefixMeasurement(capture.plan, Int32(position))
                if metric == "routed-candidate-response" || capture.sourceSchema == 8 && metric == "routed-public-candidate-response" {
                    prefix.measurement = metric
                }
            }
            if purpose == .connected, selectionExecution == "local" {
                let metric: String
                switch self {
                case .ordinary(let capture): metric = LibboxRouterNodeChainConnectedCandidatePrefixMeasurement(capture.plan, Int32(position))
                case .socks(let capture): metric = capture.plan.candidatePrefixMeasurement(Int32(position))
                case .connect(let capture): metric = capture.plan.candidatePrefixMeasurement(Int32(position))
                case .append: metric = ""
                }
                if metric == "routed-candidate-response" { prefix.measurement = metric }
                if case .ordinary(let capture) = self, position < members.count - 2 {
                    let successor = LibboxRouterNodeChainConnectedPacketSuccessorCandidateMode(capture.plan, Int32(position))
                    if IOSMultihopNodeSelection.supportsNativePrefix(successor), successor == members[position + 1].mode {
                        prefix.measurement = "routed-candidate-response"; prefix.candidate_mode = successor
                    }
                }
            }
            if selectionExecution == "local", position < members.count - 1, case .ordinary(let capture) = self {
                let mode: String
                if purpose == .prepared {
                    mode = LibboxRouterNodeChainPreparedCandidateResponseMode(capture.plan, Int32(position))
                } else if purpose == .connected && position == members.count - 2 {
                    mode = LibboxRouterNodeChainConnectedFinalCandidateResponseMode(capture.plan, Int32(position))
                } else {
                    return prefix
                }
                if !mode.isEmpty, mode == members[position + 1].mode {
                    prefix.measurement = "routed-candidate-response"
                    prefix.candidate_mode = mode
                }
            }
            return prefix
        }
    }

    func close() throws { switch self { case .ordinary(let v): try v.plan.close(); case .socks(let v): try v.plan.close(); case .connect(let v): try v.plan.close(); case .append: return } }

    static func reopen(_ input: String, selectedProfile: [String: Any]) throws -> Self {
        guard !input.isEmpty, input.utf8.count <= IOSNodeChainCapture.maximumInputBytes,
              let source = try JSONSerialization.jsonObject(with: Data(input.utf8)) as? [String: Any] else { throw Self.issue() }
        let value: Self
        if source["kind"] as? String == "routervpn-node-chain-candidate-append-source" {
            value = .append(try IOSNodeCandidateAppendSource.reopen(input, selectedProfile: selectedProfile))
        } else if source["schema"] as? Int == 3 {
            value = .socks(try IOSNodeChainSOCKSCapture.reopen(input, selectedProfile: selectedProfile))
        } else if source["schema"] as? Int == 4 {
            value = .connect(try IOSNodeChainCONNECTCapture.reopen(input, selectedProfile: selectedProfile))
        } else {
            value = .ordinary(try IOSNodeChainCapture.reopen(input, selectedProfile: selectedProfile))
        }
        guard value.selectionExecution == "local", value.launchInput == input else { try? value.close(); throw Self.issue() }
        return value
    }
    /// Reopen only the complete Local source observed by the live measurement.
    /// This describes a future profile; it does not adopt the reopened native plan.
    static func reopenConnected(_ input: String, selectedProfile: [String: Any],
                                sourceSHA256: String, configSHA256: String) throws -> Self {
        let original = try reopen(input, selectedProfile: selectedProfile)
        guard !original.isAppend, original.sourceSHA256 == sourceSHA256, original.configSHA256 == configSHA256 else {
            try? original.close(); throw Self.issue()
        }
        return original
    }
    static func validateLocalResponseInfo(input: Data, bundle: Data, proofs: [IOSNodeCandidatePrefix],
                                             sourceSHA256: String, configSHA256: String) throws {
        guard let record = try JSONSerialization.jsonObject(with: bundle) as? [String: Any],
              let finalID = record["selectedRouterID"] as? String,
              let profiles = record["routerProfiles"] as? [[String: Any]],
              profiles.filter({ $0["id"] as? String == finalID }).count == 1,
              let final = profiles.first(where: { $0["id"] as? String == finalID }) else { throw issue() }
        let original = try reopenConnected(String(decoding: input, as: UTF8.self), selectedProfile: final,
                                           sourceSHA256: sourceSHA256, configSHA256: configSHA256)
        defer { try? original.close() }
        if case .ordinary(let source) = original {
            if proofs.contains(where: { $0.pairedFinalResponse }) {
                guard source.sourceSchema == 1 || source.sourceSchema == 6, proofs.filter(\.pairedFinalResponse).allSatisfy({ row in
                    guard row.supported(in: proofs) else { return false }
                    if row.packetSuccessorResponse(in: proofs) {
                        return LibboxRouterNodeChainConnectedPacketSuccessorCandidateMode(source.plan, Int32(row.position)) == row.candidate_mode
                    }
                    return row.position == proofs.count - 2 && LibboxRouterNodeChainConnectedFinalCandidateResponseMode(source.plan, Int32(row.position)) == row.candidate_mode
                }) else { throw issue() }
            } else if source.sourceSchema == 5 || source.sourceSchema == 7 {
                guard proofs.contains(where: { $0.connectedFinalResponse(in: proofs) }),
                      source.sourceSchema == 5 ? proofs[proofs.count - 2].mode == "openvpn" : proofs.count == 3 && proofs[0].mode == "shadowsocks" else { throw issue() }
            } else {
                guard source.sourceSchema == 6 || source.sourceSchema == 8,
                      source.sourceSchema == 8 || (4...IOSMultihopNodeSelection.maximumNodes).contains(proofs.count) || Int(source.plan.extendedLocalNodeCount()) == proofs.count else { throw issue() }
            }
        } else {
            guard proofs.contains(where: { $0.typedImportedResponse && $0.supported(in: proofs) }) else { throw issue() }
        }
        guard original.connectedCandidatePrefixes == proofs else { throw issue() }
    }
    static func issue() -> NSError {
        NSError(domain: "RouterVPN.CandidateOriginal", code: 1,
                userInfo: [NSLocalizedDescriptionKey: "The complete saved Local source could not be reproduced for this prefix test."])
    }

}
