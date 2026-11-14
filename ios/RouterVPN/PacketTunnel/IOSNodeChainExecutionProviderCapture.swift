import Foundation

/// Provider-only native execution source validation.
extension IOSNodeChainProviderCapture {
    /// A separate preparation source and launch discriminator prevent a
    /// Server/Compare graph from borrowing Local or legacy pair receipts.
    static func reopenExecution(_ configuration: [String: Any], lastRecord: String? = nil) throws -> IOSNodeChainExecutionCapture {
        guard configuration["nodeChainSOCKSSource"] == nil, configuration[key] == nil,
              configuration["engine"] as? String == "multihop-libbox",
              ["entryBundle", "external_entry_bundle", "external_entry_mode", "tor_entry_bundle", "tor_entry_mode",
               "strategy", "strategy_catalog", "max_source_sha256"].allSatisfy({ configuration[$0] == nil }),
              let input = configuration[executionKey] as? String, !input.isEmpty, input.utf8.count <= IOSNodeChainCapture.maximumInputBytes,
              let data = configuration["bundle"] as? Data, !data.isEmpty, data.count <= 32 * 1024 * 1024,
              let root = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let id = root["selectedRouterID"] as? String,
              let profiles = root["routerProfiles"] as? [[String: Any]],
              profiles.filter({ $0["id"] as? String == id }).count == 1,
              let selected = profiles.first(where: { $0["id"] as? String == id }) else {
            throw IOSNodeChainCapture.issue("The ordered execution provider lost its original private source.")
        }
        let capture: IOSNodeChainExecutionCapture
        if let lastRecord { capture = try IOSNodeChainExecutionCapture.reopenLast(input, selectedProfile: selected, record: lastRecord) }
        else { capture = try IOSNodeChainExecutionCapture.reopen(input, selectedProfile: selected) }
        var accepted = false
        defer { if !accepted { try? capture.close() } }
        guard let final = capture.members.last, final.id == id,
              selected["multihop_execution"] as? String == capture.requested,
              configuration["mode"] as? String == final.mode,
              configuration["rawProfileID"] as? String == final.mode,
              configuration["modeCandidates"] as? [String] == [final.mode],
              let assets = root["profiles"] as? [String: [String: String]], let selectedFiles = assets[final.mode],
              let originalFiles = try JSONSerialization.jsonObject(with: Data(final.filesJSON.utf8)) as? [String: String],
              selectedFiles == originalFiles else {
            throw IOSNodeChainCapture.issue("The ordered execution final selection changed its captured policy or assets.")
        }
        accepted = true
        return capture
    }

}
