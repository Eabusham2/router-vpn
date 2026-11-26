import Foundation
import Libbox

struct IOSNodeCandidatePrefix: Decodable, Equatable {
    let position: Int
    let profile_id: String
    let node_id: String
    let mode: String
    var measurement: String? = nil
    var candidate_mode: String? = nil
    var metric: String { measurement ?? "routed-tcp-connect" }
    var hysteria2Response: Bool {
        candidate_mode == "hysteria2" && metric == "routed-candidate-response" &&
            IOSMultihopNodeSelection.supportsNativePrefix(mode) && !node_id.isEmpty
    }
    var typedImportedResponse: Bool {
        candidate_mode == nil && metric == "routed-candidate-response" && ["socks5", "http-connect", "https-connect", "openvpn"].contains(mode)
    }
    var supported: Bool {
        if candidate_mode != nil { return hysteria2Response && (0..<(IOSMultihopNodeSelection.maximumNodes - 1)).contains(position) }
        switch metric {
        case "routed-tcp-connect": return ["wg", "awg2-fast", "awg2-strong"].contains(mode)
        case "routed-candidate-response": return (mode == "shadowsocks" || typedImportedResponse && node_id.isEmpty) && (1..<(IOSMultihopNodeSelection.physicalTraversalDepth - 1)).contains(position)
        case "routed-public-candidate-response": return mode == "shadowsocks" && node_id.isEmpty && (1..<(IOSMultihopNodeSelection.physicalTraversalDepth - 1)).contains(position)
        default: return false
        }
    }
    func selectedResponse(in proofs: [Self]) -> Bool {
        guard candidate_mode == nil, proofs.allSatisfy({ $0.candidate_mode == nil }) else { return false }
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
        guard supported else { return false }
        if hysteria2Response {
            guard (2...IOSMultihopNodeSelection.maximumNodes).contains(proofs.count), position == proofs.count - 2,
                  proofs[position] == self, Set(proofs.map(\.profile_id)).count == proofs.count,
                  Set(proofs.map(\.node_id)).count == proofs.count else { return false }
            return proofs.enumerated().allSatisfy { index, row in
                guard row.position == index, !row.profile_id.isEmpty, !row.node_id.isEmpty else { return false }
                if index == position { return row.hysteria2Response }
                guard row.measurement == nil, row.candidate_mode == nil else { return false }
                return index == proofs.count - 1 ? row.mode == "hysteria2" : IOSMultihopNodeSelection.supportsNativePrefix(row.mode)
            }
        }
        guard proofs.allSatisfy({ $0.candidate_mode == nil || $0.hysteria2Response }) else { return false }
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
        typedImportedResponse || hysteria2Response ? supported(in: proofs) : importedEntryFinalResponse(in: proofs)
    }

    private func importedEntryFinalResponse(in proofs: [Self]) -> Bool {
        guard proofs.count == 3, position == 1, proofs[1] == self,
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

    var members: [IOSNodeChainCapture.Member] { switch self { case .ordinary(let v): return v.members; case .socks(let v): return v.members; case .connect(let v): return v.members } }
    var launchInput: String { switch self { case .ordinary(let v): return v.launchInput; case .socks(let v): return v.source; case .connect(let v): return v.source } }
    var originalSource: String? { switch self { case .ordinary(let v): return v.originalSource; case .socks(let v): return v.source; case .connect(let v): return v.source } }
    var sourceSHA256: String { switch self { case .ordinary(let v): return v.sourceSHA256; case .socks(let v): return v.sourceSHA256; case .connect(let v): return v.sourceSHA256 } }
    var configSHA256: String { switch self { case .ordinary(let v): return v.configSHA256; case .socks(let v): return v.plan.configSHA256(); case .connect(let v): return v.plan.configSHA256() } }
    var selectionExecution: String { switch self { case .ordinary(let v): return v.selectionExecution; case .socks(let v): return v.selectionExecution; case .connect(let v): return v.selectionExecution } }
    var strict: Bool { switch self { case .ordinary(let v): return v.strict; case .socks(let v): return v.strict; case .connect(let v): return v.strict } }
    var homeLANAccess: Bool { switch self { case .ordinary(let v): return v.homeLANAccess; case .socks(let v): return v.homeLANAccess; case .connect(let v): return v.homeLANAccess } }
    var preparationKind: String {
        switch self {
        case .ordinary(let capture):
            if capture.sourceSchema == 6 || capture.sourceSchema == 8 {
                return "routervpn-node-chain-multiple-imported-candidate-preparation"
            }
            return "routervpn-node-chain-candidate-preparation"
        case .socks: return "routervpn-node-chain-socks-candidate-preparation"
        case .connect: return "routervpn-node-chain-connect-candidate-preparation"
        }
    }
    var requiresIndependentPrefix: Bool { if case .ordinary = self { return false }; return true }

    func canPreparePrefix(at position: Int) -> Bool {
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

    // Dormant preparations retain their original metrics. Only the connected
    // provider can describe an additional authenticated response carrier.
    var candidatePrefixes: [IOSNodeCandidatePrefix] { makeCandidatePrefixes(connected: false) }
    var connectedCandidatePrefixes: [IOSNodeCandidatePrefix] { makeCandidatePrefixes(connected: true) }

    private func makeCandidatePrefixes(connected: Bool) -> [IOSNodeCandidatePrefix] {
        members.enumerated().map { position, member in
            var prefix = IOSNodeCandidatePrefix(position: position, profile_id: member.id,
                node_id: member.profile["node_proof_id"] as? String ?? "", mode: member.mode)
            if member.mode == "shadowsocks", case .ordinary(let capture) = self, selectionExecution == "local" {
                let metric = LibboxRouterNodeChainCandidatePrefixMeasurement(capture.plan, Int32(position))
                if metric == "routed-candidate-response" || capture.sourceSchema == 8 && metric == "routed-public-candidate-response" {
                    prefix.measurement = metric
                }
            }
            if connected, selectionExecution == "local" {
                let metric: String
                switch self {
                case .ordinary(let capture): metric = LibboxRouterNodeChainConnectedCandidatePrefixMeasurement(capture.plan, Int32(position))
                case .socks(let capture): metric = capture.plan.candidatePrefixMeasurement(Int32(position))
                case .connect(let capture): metric = capture.plan.candidatePrefixMeasurement(Int32(position))
                }
                if metric == "routed-candidate-response" { prefix.measurement = metric }
                if case .ordinary(let capture) = self,
                   LibboxRouterNodeChainSupportsConnectedHysteria2FinalCandidate(capture.plan, Int32(position)) {
                    prefix.measurement = "routed-candidate-response"
                    prefix.candidate_mode = "hysteria2"
                }
            }
            return prefix
        }
    }

    func close() throws { switch self { case .ordinary(let v): try v.plan.close(); case .socks(let v): try v.plan.close(); case .connect(let v): try v.plan.close() } }

    static func reopen(_ input: String, selectedProfile: [String: Any]) throws -> Self {
        guard !input.isEmpty, input.utf8.count <= IOSNodeChainCapture.maximumInputBytes,
              let source = try JSONSerialization.jsonObject(with: Data(input.utf8)) as? [String: Any] else { throw Self.issue() }
        let value: Self
        if source["schema"] as? Int == 3 {
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
        guard original.sourceSHA256 == sourceSHA256, original.configSHA256 == configSHA256 else {
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
            if proofs.contains(where: { $0.hysteria2Response }) {
                guard source.sourceSchema == 1, let response = proofs.first(where: { $0.hysteria2Response }),
                      response.supported(in: proofs),
                      LibboxRouterNodeChainSupportsConnectedHysteria2FinalCandidate(source.plan, Int32(response.position)) else { throw issue() }
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
