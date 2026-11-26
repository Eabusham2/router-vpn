import Foundation
import Libbox

/// Compile original saved sources once. The live callback observes their
/// publication and bytes; it never recompiles or guesses a candidate endpoint.
@MainActor struct IOSNodeCandidateCapture {
    struct Row { let id: String; let name: String; let input: String; let reason: String }
    let source: IOSCandidateCatalogPublication.Capture
    let records: [String: Data]
    let rows: [Row]
    let prefix: IOSNodeCandidatePrefix
    let chainSource: String
    let chainConfig: String

    static func make(request: String, prefixPosition: Int, proofs: [IOSNodeCandidatePrefix],
                     chainSource: String, chainConfig: String, selectedResponse: Bool = false, originalLaunch: Data? = nil) throws -> Self {
        let snapshot = try IOSNodeBundleStore.shared.candidateSnapshot()
        let compiled = try compile(records: snapshot.records, stamp: snapshot.stamp,
                                   prefixPosition: prefixPosition, proofs: proofs, selectedResponse: selectedResponse, originalLaunch: originalLaunch)
        guard IOSCandidateCatalogPublication.isDigest(chainSource), IOSCandidateCatalogPublication.isDigest(chainConfig) else { throw issue() }
        let published = try IOSCandidateCatalogPublication.shared.capture(request: request, inventory: compiled.inventory, expected: snapshot.stamp)
        let result = Self(source: published, records: snapshot.records, rows: compiled.rows,
            prefix: proofs[prefixPosition], chainSource: chainSource, chainConfig: chainConfig)
        do { try result.requireCurrent(); return result }
        catch { try? IOSCandidateCatalogPublication.shared.remove(published); throw error }
    }
    func requireCurrent() throws {
        let now = try IOSNodeBundleStore.shared.candidateSnapshot()
        guard now.records == records, now.stamp == source.stamp,
              IOSCandidateCatalogPublication.shared.current(source) else { throw Self.issue() }
    }
    static func compile(records: [String: Data], stamp: IOSCandidateCatalogPublication.Stamp,
                        prefixPosition: Int, proofs: [IOSNodeCandidatePrefix], selectedResponse: Bool = false, originalLaunch: Data? = nil) throws -> (inventory: Data, rows: [Row]) {
        guard stamp.ready, stamp.sources_sha256 == (try IOSCandidateCatalogPublication.sourcesDigest(records)),
              proofs.indices.contains(prefixPosition), selectedResponse ? proofs[prefixPosition].selectedResponse(in: proofs) : proofs[prefixPosition].supported(in: proofs),
              proofs.enumerated().allSatisfy({ $0.offset == $0.element.position }), (2...8).contains(proofs.count) || IOSMultihopNodeSelection.extendedOriginalModes(proofs.map(\.mode), execution: "local") else { throw issue() }
        let publicResponse = proofs[prefixPosition].metric == "routed-public-candidate-response"
        let completeSource = publicResponse || selectedResponse
        let excludedMembers = proofs.prefix(completeSource ? proofs.count : prefixPosition + 1)
        let excluded = Set(excludedMembers.map(\.profile_id))
        let paired = Set(excludedMembers.map(\.node_id).filter { !$0.isEmpty })
        var originals = completeSource ? Dictionary(uniqueKeysWithValues: proofs.map { ($0.profile_id, $0) }) : [:]
        var rows: [Row] = [], seen = Set<String>(), inputs: [String] = []
        for key in records.keys.sorted() {
            guard let data = records[key], data.count <= 32 * 1024 * 1024,
                  let root = try JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let profiles = root["routerProfiles"] as? [[String: Any]], let files = root["profiles"] as? [String: [String: String]] else { throw issue() }
            for profile in profiles.sorted(by: { ($0["id"] as? String ?? "") < ($1["id"] as? String ?? "") }) {
                guard let id = profile["id"] as? String, !id.isEmpty, seen.insert(id).inserted else { throw issue() }
                if let original = originals.removeValue(forKey: id) {
                    let saved = try JSONDecoder().decode(RouterProfile.self, from: JSONSerialization.data(withJSONObject: profile))
                    let layerAllowed = publicResponse && original.position == 0 ? IOSMultihopNodeSelection.supportsExternalExitEntry(saved) : [nil, "", "off"].contains(saved.startLayer)
                    guard (saved.nodeProofID ?? "") == original.node_id, layerAllowed,
                          original.node_id.isEmpty ? IOSImportedShadowsocksSource.eligibleLiteral(saved) :
                            saved.normalizedNodeKind == "router-vpn" && saved.external == nil else { throw issue() }
                }
                if excluded.contains(id) || (profile["node_proof_id"] as? String).map({ paired.contains($0) }) == true { continue }
                let name = profile["name"] as? String ?? id
                var input = "", reason = "This saved transport or Start Layer cannot supply this measurement"
                do {
                    input = try member(profile: profile, files: files)
                    guard LibboxRouterNodeChainCandidateInputSupported(input) else { throw issue() }
                    if publicResponse || proofs[prefixPosition].metric == "routed-candidate-response" {
                        guard LibboxRouterNodeChainCandidateInputSupportedForMeasurement(input, proofs[prefixPosition].metric) else { throw issue() }
                    }
                    reason = ""; inputs.append(input)
                } catch { input = "" }
                rows.append(Row(id: id, name: name, input: input, reason: reason))
            }
        }
        guard originals.isEmpty, !inputs.isEmpty else { throw issue() }
        let inventory = try JSONSerialization.data(withJSONObject: ["schema": 1, "revision": stamp.revision, "inputs": inputs], options: [.sortedKeys])
        guard inventory.count <= IOSCandidateCatalogPublication.maximumInventoryBytes else { throw issue() }
        guard publicResponse else { return (inventory, rows) }
        guard let launch = originalLaunch, launch.count <= IOSNodeChainCapture.maximumInputBytes,
              let record = try JSONSerialization.jsonObject(with: launch) as? [String: Any],
              record["kind"] as? String == "routervpn-node-chain-launch-input", record["schema"] as? Int == 8,
              record["execution"] as? String == "local" else { throw issue() }
        let original = record.filter { ["schema", "execution", "nodes", "identity_sources"].contains($0.key) }
        let source = try JSONSerialization.data(withJSONObject: original, options: [.sortedKeys])
        var failure: NSError?
        let filtered: String? = LibboxRouterNodeChainFilterPublicCandidateInventory(String(decoding: source, as: UTF8.self),
            Int32(prefixPosition), String(decoding: inventory, as: UTF8.self), &failure)
        guard failure == nil, let filtered, !filtered.isEmpty else { throw failure ?? issue() }
        let data = Data(filtered.utf8)
        guard data.count <= IOSCandidateCatalogPublication.maximumInventoryBytes,
              let filteredInventory = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              filteredInventory["schema"] as? Int == 1, filteredInventory["revision"] as? String == stamp.revision,
              let retained = filteredInventory["inputs"] as? [String], !retained.isEmpty else { throw issue() }
        let eligible = Set(retained)
        guard eligible.count == retained.count, inputs.filter({ eligible.contains($0) }) == retained else { throw issue() }
        return (data, rows.map { row in
            if row.input.isEmpty || eligible.contains(row.input) { return row }
            return Row(id: row.id, name: row.name, input: "", reason: "This source shares an endpoint or credentials with another route member or candidate")
        })
    }
    static func member(profile: [String: Any], files: [String: [String: String]]) throws -> String {
        guard profile["start_layer"] == nil || profile["start_layer"] is String else { throw issue() }
        let layer = profile["start_layer"] as? String ?? "off"
        guard ["", "off", "aes-256-gcm", "aes-256-gcm+xor-whitening"].contains(layer),
              profile["node_kind"] as? String != "external" || layer.isEmpty || layer == "off" else { throw issue() }
        var failure: NSError?
        let result: String?
        if profile["node_kind"] as? String == "external" {
            let typed = try JSONDecoder().decode(RouterProfile.self, from: JSONSerialization.data(withJSONObject: profile))
            if typed.external?.protocolName == "openvpn" {
                let original = try IOSImportedOpenVPNSource.capture(typed)
                result = LibboxRouterNodeChainImportedOpenVPNMemberInput(original.config, original.capture, &failure)
            } else if typed.external?.protocolName == "socks5" {
                let original = try IOSImportedSOCKSSource.capture(typed)
                result = LibboxRouterNodeChainImportedSOCKSMemberInput(original.config, original.capture, &failure)
            } else if ["http-connect", "https-connect"].contains(typed.external?.protocolName ?? "") {
                let original = try IOSImportedCONNECTSource.capture(typed)
                result = LibboxRouterNodeChainImportedCONNECTMemberInput(original.config, original.capture, &failure)
            } else {
                let original = try IOSImportedShadowsocksSource.capture(typed)
                result = LibboxRouterNodeChainImportedMemberInput(original.config, original.capture, &failure)
            }
        } else {
            guard profile["node_kind"] as? String == "router-vpn", profile["external"] == nil,
                  let original = files["shadowsocks"], !original.isEmpty else { throw issue() }
            func json(_ value: Any) throws -> String { String(decoding: try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys]), as: UTF8.self) }
            let bootstrap = try profile["dns_bootstrap"].map { try json($0) } ?? ""
            result = LibboxRouterNodeChainMemberInput("shadowsocks", try json(original), try json(profile), "", bootstrap, &failure)
        }
        guard let result, !result.isEmpty, failure == nil else { throw failure ?? issue() }; return result
    }
    static func issue() -> NSError { NSError(domain: "RouterVPN.CandidateCapture", code: 1, userInfo: [NSLocalizedDescriptionKey: "The saved sources or selected prefix cannot supply a current candidate inventory."]) }
}
