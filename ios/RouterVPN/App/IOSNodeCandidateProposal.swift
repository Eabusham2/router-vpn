import Foundation

/// A future source graph only. Compilation does not run a VPN, alter the live
/// plan, or write a node record. The caller retains the measured receipt owner.
@MainActor struct IOSNodeCandidateProposal {
    let description: String
    let profiles: [RouterProfile]
    let launchInput: String

    static func compile(original: IOSNodeChainCapture, records: [String: Data], position: Int,
                        candidateID: String, measuredInput: String) throws -> Self {
        guard original.members.indices.contains(position),
              ["wg", "awg2-fast", "awg2-strong"].contains(original.members[position].mode),
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
        var selected = original.members.prefix(position + 1).map { (id: $0.id, mode: $0.mode) }
        selected.append((candidateID, "shadowsocks"))
        if candidate.profile["node_kind"] as? String == "external" {
            guard position == 0, let final = original.members.last, final.profile["node_kind"] as? String == "router-vpn" else { throw IOSNodeCandidateCapture.issue() }
            let retained = try source(final.id)
            guard let originalAssets = try JSONSerialization.jsonObject(with: Data(final.filesJSON.utf8)) as? [String: String],
                  let launch = try JSONSerialization.jsonObject(with: Data(original.launchInput.utf8)) as? [String: Any],
                  let identities = launch["identity_sources"] as? [String], let identity = identities.last,
                  let originalIdentity = try JSONSerialization.jsonObject(with: Data(identity.utf8)) as? [String: String],
                  retained.files["shadowsocks"] == originalAssets, retained.files["wg"] == originalIdentity,
                  try JSONSerialization.data(withJSONObject: retained.profile, options: [.sortedKeys]) ==
                    JSONSerialization.data(withJSONObject: final.profile, options: [.sortedKeys]) else {
                throw NSError(domain: "RouterVPN.CandidateProposal", code: 3, userInfo: [NSLocalizedDescriptionKey:
                    "The original paired final node's policy or private assets changed. Reconnect its current source before preparing this custom middle."])
            }
            selected.append((final.id, "shadowsocks"))
        }
        guard (2...8).contains(selected.count), Set(selected.map(\.id)).count == selected.count else { throw IOSNodeCandidateCapture.issue() }
        let references = selected.map { ["id": $0.id, "mode": $0.mode] }
        var bundles: [Data] = []
        for (index, member) in selected.enumerated() {
            var captured = try source(member.id)
            if index == selected.count - 1 {
                captured.profile["multihop_enabled"] = true
                captured.profile["multihop_execution"] = "local"
                captured.profile["multihop_nodes"] = references
                for key in ["multihop_entry_id", "multihop_entry_mode", "multihop_exit_id", "multihop_exit_mode"] { captured.profile.removeValue(forKey: key) }
            }
            let profiles = captured.root["routerProfiles"] as! [[String: Any]]
            captured.root["routerProfiles"] = profiles.map { $0["id"] as? String == member.id ? captured.profile : $0 }
            captured.root["selectedRouterID"] = member.id
            bundles.append(try JSONSerialization.data(withJSONObject: captured.root, options: [.sortedKeys]))
        }
        let preview: IOSNodeChainCapture
        do { preview = try IOSNodeChainCapture.compile(bundles: bundles) }
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
        defer { try? preview.plan.close() }
        guard let prior = try JSONSerialization.jsonObject(with: Data(original.launchInput.utf8)) as? [String: Any],
              let after = try JSONSerialization.jsonObject(with: Data(preview.launchInput.utf8)) as? [String: Any],
              let priorNodes = prior["nodes"] as? [String], let afterNodes = after["nodes"] as? [String],
              let priorIdentities = prior["identity_sources"] as? [String], let afterIdentities = after["identity_sources"] as? [String],
              Array(priorNodes.prefix(position + 1)) == Array(afterNodes.prefix(position + 1)),
              Array(priorIdentities.prefix(position + 1)) == Array(afterIdentities.prefix(position + 1)) else {
            // Current saved labels or a re-linked credential cannot substitute
            // for the exact original prefix that supplied the timing.
            throw IOSNodeCandidateCapture.issue()
        }
        let profiles = try preview.members.map { try JSONDecoder().decode(RouterProfile.self, from: Data($0.profileJSON.utf8)) }
        return Self(description: selected.map { "\($0.id) (\($0.mode))" }.joined(separator: " → "), profiles: profiles, launchInput: preview.launchInput)
    }
}
