import Foundation
import Libbox

/// Private provider handoff for one ordered source. Its full Go compiler is
/// rerun before native service creation; this record is never a live receipt.
enum IOSNodeChainProviderCapture {
    static let key = "nodeChainSource"
    static let executionKey = "nodeChainExecutionSource"

    static func requested(_ configuration: [String: Any], profile: [String: Any]) -> Bool {
        configuration[key] != nil || configuration[executionKey] != nil || profile["multihop_nodes"] != nil
    }

    static func reopen(_ configuration: [String: Any]) throws -> IOSNodeChainCapture {
        guard configuration["nodeChainCONNECTSource"] == nil, configuration["nodeChainSOCKSSource"] == nil, configuration[executionKey] == nil,
              configuration["engine"] as? String == "multihop-libbox",
              ["entryBundle", "external_entry_bundle", "external_entry_mode", "tor_entry_bundle", "tor_entry_mode",
               "strategy", "strategy_catalog", "max_source_sha256"].allSatisfy({ configuration[$0] == nil }),
              let input = configuration[key] as? String, !input.isEmpty, input.utf8.count <= IOSNodeChainCapture.maximumInputBytes,
              let data = configuration["bundle"] as? Data, !data.isEmpty, data.count <= 32 * 1024 * 1024,
              let root = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let id = root["selectedRouterID"] as? String,
              let profiles = root["routerProfiles"] as? [[String: Any]],
              profiles.filter({ $0["id"] as? String == id }).count == 1,
              let selected = profiles.first(where: { $0["id"] as? String == id }) else {
            throw IOSNodeChainCapture.issue("The ordered provider source is missing or mixed with another graph owner.")
        }
        let capture = try IOSNodeChainCapture.reopen(input, selectedProfile: selected)
        var accepted = false
        defer { if !accepted { try? capture.plan.close() } }
        guard let final = capture.members.last, final.id == id,
              configuration["mode"] as? String == final.mode,
              configuration["rawProfileID"] as? String == final.mode,
              configuration["modeCandidates"] as? [String] == [final.mode],
              let assets = root["profiles"] as? [String: [String: String]], let selectedFiles = assets[final.mode],
              let originalFiles = try JSONSerialization.jsonObject(with: Data(final.filesJSON.utf8)) as? [String: String],
              selectedFiles == originalFiles else {
            throw IOSNodeChainCapture.issue("The ordered provider selection differs from its exact final source.")
        }
        accepted = true
        return capture
    }
}
