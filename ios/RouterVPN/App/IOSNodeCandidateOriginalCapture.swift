import Foundation
import Libbox

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
    func preparationKind(at position: Int) -> String {
        switch self {
        case .ordinary(let capture):
            if capture.sourceSchema == 6, capture.selectionExecution == "local",
               Int(capture.plan.extendedLocalNodeCount()) == capture.members.count ||
                LibboxRouterNodeChainCandidatePrefixMeasurement(capture.plan, Int32(position)) == "routed-candidate-response" {
                return "routervpn-node-chain-multiple-imported-candidate-preparation"
            }
            return "routervpn-node-chain-candidate-preparation"
        case .socks: return "routervpn-node-chain-socks-candidate-preparation"
        case .connect: return "routervpn-node-chain-connect-candidate-preparation"
        }
    }
    var requiresIndependentPrefix: Bool { if case .ordinary = self { return false }; return true }

    var candidatePrefixes: [IOSNodeCandidatePrefix] {
        members.enumerated().map { position, member in
            var prefix = IOSNodeCandidatePrefix(position: position, profile_id: member.id,
                node_id: member.profile["node_proof_id"] as? String ?? "", mode: member.mode)
            if member.mode == "shadowsocks", case .ordinary(let capture) = self, selectionExecution == "local",
               LibboxRouterNodeChainCandidatePrefixMeasurement(capture.plan, Int32(position)) == "routed-candidate-response" {
                prefix.measurement = "routed-candidate-response"
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
    static func validateExtendedResponseInfo(input: Data, bundle: Data, proofs: [IOSNodeCandidatePrefix],
                                             sourceSHA256: String, configSHA256: String) throws {
        guard let record = try JSONSerialization.jsonObject(with: bundle) as? [String: Any],
              let finalID = record["selectedRouterID"] as? String,
              let profiles = record["routerProfiles"] as? [[String: Any]],
              profiles.filter({ $0["id"] as? String == finalID }).count == 1,
              let final = profiles.first(where: { $0["id"] as? String == finalID }) else { throw issue() }
        let original = try reopenConnected(String(decoding: input, as: UTF8.self), selectedProfile: final,
                                           sourceSHA256: sourceSHA256, configSHA256: configSHA256)
        defer { try? original.close() }
        guard case .ordinary(let source) = original, source.sourceSchema == 6,
              Int(source.plan.extendedLocalNodeCount()) == proofs.count,
              original.candidatePrefixes == proofs else { throw issue() }
    }
    static func issue() -> NSError {
        NSError(domain: "RouterVPN.CandidateOriginal", code: 1,
                userInfo: [NSLocalizedDescriptionKey: "The complete saved Local source could not be reproduced for this prefix test."])
    }

}
