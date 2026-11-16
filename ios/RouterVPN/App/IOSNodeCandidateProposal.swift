import Foundation
import Libbox

/// A future source graph only. Compilation does not run a VPN, alter the live
/// plan, or write a node record. The caller retains the measured receipt owner.
@MainActor struct IOSNodeCandidateProposal {
    let description: String
    let profiles: [RouterProfile]
    let launchInput: String

    static func compile(original: IOSNodeChainCapture, records: [String: Data], position: Int,
                        candidateID: String, measuredInput: String) throws -> Self {
        try compile(original: .ordinary(original), records: records, position: position,
                    candidateID: candidateID, measuredInput: measuredInput)
    }

    static func compile(original: IOSNodeCandidateOriginalCapture, records: [String: Data], position: Int,
                        candidateID: String, measuredInput: String) throws -> Self {
        try compileCaptured(original: original, records: records, position: position,
            candidateID: candidateID, measuredInput: measuredInput, selectedExecution: false)
    }

    /// Recompile only a future profile from the captured ordinary launch. The
    /// active Server/Compare controller is never run, restored or reselected.
    static func compileConnectedExecution(_ input: String, selectedProfile: [String: Any],
                        sourceSHA256: String, configSHA256: String, records: [String: Data], position: Int,
                        candidateID: String, measuredInput: String) throws -> Self {
        guard position == 0 else { throw IOSNodeCandidateCapture.issue() }
        let execution = try IOSNodeChainExecutionCapture.reopen(input, selectedProfile: selectedProfile)
        defer { try? execution.close() }
        guard execution.sourceSHA256 == sourceSHA256, execution.configSHA256 == configSHA256 else { throw IOSNodeCandidateCapture.issue() }
        let original: IOSNodeCandidateOriginalCapture
        switch execution.local {
        case .ordinary(let value), .openvpn(let value): original = .ordinary(value)
        case .socks(let value): original = .socks(value)
        case .connect(let value): original = .connect(value)
        }
        return try compileCaptured(original: original, records: records, position: position,
            candidateID: candidateID, measuredInput: measuredInput, selectedExecution: true)
    }

    private static func compileCaptured(original: IOSNodeCandidateOriginalCapture, records: [String: Data], position: Int,
                        candidateID: String, measuredInput: String, selectedExecution: Bool) throws -> Self {
        guard !selectedExecution || position == 0 && ["server", "auto"].contains(original.selectionExecution),
              selectedExecution || !original.requiresIndependentPrefix || original.selectionExecution == "local",
              original.members.indices.contains(position),
              position < original.members.count - (original.requiresIndependentPrefix && !selectedExecution ? 2 : 1),
              original.members.prefix(position + 1).allSatisfy({ ["wg", "awg2-fast", "awg2-strong"].contains($0.mode) }),
              !measuredInput.isEmpty else { throw IOSNodeCandidateCapture.issue() }
        func source(_ id: String) throws -> (root: [String: Any], profile: [String: Any], files: [String: [String: String]]) {
            var found: ([String: Any], [String: Any], [String: [String: String]])?
            for data in records.values {
                guard let root = try JSONSerialization.jsonObject(with: data) as? [String: Any],
                      let profiles = root["routerProfiles"] as? [[String: Any]], let files = root["profiles"] as? [String: [String: String]] else { throw IOSNodeCandidateCapture.issue() }
                for profile in profiles where profile["id"] as? String == id {
                    guard found == nil else { throw IOSNodeCandidateCapture.issue() }; found = (root, profile, files)
                }
            }
            guard let found else { throw IOSNodeCandidateCapture.issue() }; return found
        }
        let candidate = try source(candidateID)
        guard try IOSNodeCandidateCapture.member(profile: candidate.profile, files: candidate.files) == measuredInput else { throw IOSNodeCandidateCapture.issue() }
        let candidateMode: String
        if candidate.profile["node_kind"] as? String == "external" {
            let typed = try JSONDecoder().decode(RouterProfile.self, from: JSONSerialization.data(withJSONObject: candidate.profile))
            guard let mode = typed.external?.protocolName, ["shadowsocks", "socks5", "http-connect", "https-connect"].contains(mode) else { throw IOSNodeCandidateCapture.issue() }
            candidateMode = mode
        } else { candidateMode = "shadowsocks" }
        let replacement = position + 1
        let execution = original.selectionExecution
        guard original.members.indices.contains(replacement), ["local", "server", "auto"].contains(execution) else {
            throw IOSNodeCandidateCapture.issue()
        }
        // The measured target is the next hop reached through this prefix.
        // Preserve the rest of the complete saved path; its compiler decides
        // whether the replacement can occupy this exact role.
        var selected = original.members.map { (id: $0.id, mode: $0.mode) }
        selected[replacement] = (candidateID, candidateMode)
        guard (2...8).contains(selected.count), Set(selected.map(\.id)).count == selected.count else { throw IOSNodeCandidateCapture.issue() }
        let references = selected.map { ["id": $0.id, "mode": $0.mode] }
        var bundles: [Data] = [], savedProfiles: [RouterProfile] = []
        var proofs = Set<String>()
        for (index, member) in selected.enumerated() {
            var captured = try source(member.id)
            if let proof = captured.profile["node_proof_id"] as? String {
                guard proofs.insert(proof).inserted else { throw IOSNodeCandidateCapture.issue() }
            }
            if index == selected.count - 1 {
                captured.profile["multihop_enabled"] = true
                captured.profile["multihop_execution"] = execution
                captured.profile["multihop_nodes"] = references
                for key in ["multihop_entry_id", "multihop_entry_mode", "multihop_exit_id", "multihop_exit_mode"] { captured.profile.removeValue(forKey: key) }
            }
            savedProfiles.append(try JSONDecoder().decode(RouterProfile.self, from: JSONSerialization.data(withJSONObject: captured.profile)))
            let profiles = captured.root["routerProfiles"] as! [[String: Any]]
            captured.root["routerProfiles"] = profiles.map { $0["id"] as? String == member.id ? captured.profile : $0 }
            captured.root["selectedRouterID"] = member.id
            bundles.append(try JSONSerialization.data(withJSONObject: captured.root, options: [.sortedKeys]))
        }
        let preview: (members: [IOSNodeChainCapture.Member], launchInput: String, close: () throws -> Void)
        do {
            if execution != "local" {
                let captured = try IOSNodeChainExecutionCapture.compile(bundles: bundles, requested: execution)
                preview = (captured.members, captured.local.launchInput, { try captured.close() })
            } else if selected.contains(where: { $0.mode == "socks5" }) {
                let captured = try IOSNodeChainSOCKSCapture.compile(bundles: bundles)
                preview = (captured.members, captured.source, { try captured.plan.close() })
            } else if selected.contains(where: { ["http-connect", "https-connect"].contains($0.mode) }) {
                let captured = try IOSNodeChainCONNECTCapture.compile(bundles: bundles)
                preview = (captured.members, captured.source, { try captured.plan.close() })
            } else {
                let captured = try IOSNodeChainCapture.compile(bundles: bundles)
                preview = (captured.members, captured.launchInput, { try captured.plan.close() })
            }
        }
        catch {
            if candidate.profile["node_kind"] as? String == "router-vpn",
               let encoded = candidate.files["shadowsocks"]?["sing-box.json"], let data = Data(base64Encoded: encoded),
               let graph = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
               let outbounds = graph["outbounds"] as? [[String: Any]] {
                let ss = outbounds.filter { $0["type"] as? String == "shadowsocks" }
                if ss.count == 1, ss[0]["method"] as? String != "2022-blake3-aes-256-gcm" {
                    throw NSError(domain: "RouterVPN.CandidateProposal", code: 2, userInfo: [NSLocalizedDescriptionKey:
                        "This endpoint supports TCP timing, but the current complete ordered path requires an AES-256 Shadowsocks 2022 paired final node. Its measured score remains usable until expiry."])
                }
            }
            throw error
        }
        defer { try? preview.close() }
        guard let prior = try JSONSerialization.jsonObject(with: Data(original.launchInput.utf8)) as? [String: Any],
              let after = try JSONSerialization.jsonObject(with: Data(preview.launchInput.utf8)) as? [String: Any],
              let priorNodes = prior["nodes"] as? [String], let afterNodes = after["nodes"] as? [String],
              let priorIdentities = prior["identity_sources"] as? [String], let afterIdentities = after["identity_sources"] as? [String],
              priorNodes.count == selected.count, afterNodes.count == selected.count,
              priorIdentities.count == selected.count, afterIdentities.count == selected.count,
              Array(priorNodes.prefix(position + 1)) == Array(afterNodes.prefix(position + 1)),
              Array(priorIdentities.prefix(position + 1)) == Array(afterIdentities.prefix(position + 1)) else {
            throw IOSNodeCandidateCapture.issue()
        }
        for index in selected.indices where index > replacement {
            guard priorIdentities[index] == afterIdentities[index] else { throw IOSNodeCandidateCapture.issue() }
            if index == selected.count - 1 {
                // Only the control member's ordered references may change.
                // Its credentials, Start Layer, DNS and private transport stay exact.
                guard let before = try JSONSerialization.jsonObject(with: Data(priorNodes[index].utf8)) as? [String: Any],
                      let mode = before["mode"] as? String, let files = before["files"] as? String,
                      let start = before["start"] as? String, let bootstrap = before["dns_bootstrap"] as? String else {
                    throw IOSNodeCandidateCapture.issue()
                }
                var expected = original.members[index].profile
                expected["multihop_enabled"] = true; expected["multihop_execution"] = execution; expected["multihop_nodes"] = references
                for key in ["multihop_entry_id", "multihop_entry_mode", "multihop_exit_id", "multihop_exit_mode"] { expected.removeValue(forKey: key) }
                // Ordered references legitimately change the final member's
                // source/metadata receipts. Recompute through its real compiler
                // with the exact original transport, rather than ignoring hashes.
                let profileJSON = String(decoding: try JSONSerialization.data(withJSONObject: expected, options: [.sortedKeys]), as: UTF8.self)
                var failure: NSError?
                let expectedInput: String? = LibboxRouterNodeChainMemberInput(mode, files, profileJSON, start, bootstrap, &failure)
                guard failure == nil, let expectedInput, expectedInput == afterNodes[index] else {
                    throw failure ?? IOSNodeCandidateCapture.issue()
                }
            } else {
                guard priorNodes[index] == afterNodes[index] else { throw IOSNodeCandidateCapture.issue() }
            }
        }
        return Self(description: selected.map { "\($0.id) (\($0.mode))" }.joined(separator: " → "), profiles: savedProfiles, launchInput: preview.launchInput)
    }
}
