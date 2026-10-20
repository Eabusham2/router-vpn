import Foundation

/// A runtime-only restoration receipt. No node credential or selected policy
/// is copied into the launch option, and the saved Compare preference stays
/// unchanged. Both app and extension validate the exact original sources.
enum IOSMultihopExecution {
    static let launchKey = "routervpn_speed_lab_execution"

    struct Source: Codable, Equatable, Sendable {
        let bundleSHA256: String
        let entrySHA256: String
        let entryID: String
        let exitID: String
        let entryMode: String
        let exitMode: String
        let requested: String

        enum CodingKeys: String, CodingKey {
            case bundleSHA256 = "bundle_sha256", entrySHA256 = "entry_sha256"
            case entryID = "entry_id", exitID = "exit_id", entryMode = "entry_mode", exitMode = "exit_mode", requested
        }

        init(configuration: [String: Any], digest: (Data) -> String) throws {
            guard configuration["engine"] as? String == "multihop-libbox",
                  let bundle = configuration["bundle"] as? Data,
                  let entry = configuration["entryBundle"] as? Data,
                  let raw = configuration["rawProfileID"] as? String ?? configuration["mode"] as? String else { throw issue() }
            let exitProfile = try Self.profile(bundle), entryProfile = try Self.profile(entry)
            guard exitProfile["multihop_enabled"] as? Bool == true,
                  let exitID = exitProfile["id"] as? String, let entryID = entryProfile["id"] as? String,
                  exitID != entryID, exitProfile["multihop_exit_id"] as? String == exitID,
                  exitProfile["multihop_entry_id"] as? String == entryID,
                  let exitMode = exitProfile["multihop_exit_mode"] as? String, exitMode == raw else { throw issue() }
            self.bundleSHA256 = digest(bundle); self.entrySHA256 = digest(entry)
            self.entryID = entryID; self.exitID = exitID
            self.entryMode = exitProfile["multihop_entry_mode"] as? String ?? "wg"
            self.exitMode = exitMode; self.requested = exitProfile["multihop_execution"] as? String ?? "local"
            guard valid else { throw issue() }
        }

        var valid: Bool {
            [bundleSHA256, entrySHA256].allSatisfy { $0.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil } &&
            [entryID, exitID].allSatisfy { !$0.isEmpty && $0.utf8.count <= 128 && !$0.contains("\u{0}") } && entryID != exitID &&
            [entryMode, exitMode].allSatisfy { $0.range(of: "^[a-z0-9][a-z0-9-]{0,95}$", options: .regularExpression) != nil } &&
            ["local", "server", "auto"].contains(requested)
        }

        private static func profile(_ data: Data) throws -> [String: Any] {
            guard !data.isEmpty, data.count <= 32 * 1024 * 1024,
                  let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let profiles = object["routerProfiles"] as? [[String: Any]], !profiles.isEmpty else { throw issue() }
            let selected = object["selectedRouterID"] as? String ?? ""
            let matches = selected.isEmpty && profiles.count == 1 ? profiles : profiles.filter { $0["id"] as? String == selected }
            guard matches.count == 1 else { throw issue() }
            let kind = (matches[0]["node_kind"] as? String ?? "router-vpn").trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            guard kind.isEmpty || kind == "router-vpn" else { throw issue() }
            return matches[0]
        }
    }

    struct Capture: Codable, Equatable, Sendable {
        let schema: Int
        let requestID: String
        let sessionID: String
        let source: Source
        let execution: String
        let healthy: Bool

        enum CodingKeys: String, CodingKey {
            case schema, source, execution, healthy
            case requestID = "request_id", sessionID = "session_id"
        }

        init(source: Source, execution: String, session: String, request: String) throws {
            schema = 1; self.source = source; self.execution = execution
            sessionID = session; requestID = request; healthy = true
            guard valid else { throw issue() }
        }

        private var valid: Bool {
            schema == 1 && healthy && source.valid && UUID(uuidString: sessionID) != nil &&
            requestID.range(of: "^[0-9a-f]{32}$", options: .regularExpression) != nil &&
            ["local", "server"].contains(execution) && (source.requested == "auto" || source.requested == execution)
        }

        func encoded() throws -> Data {
            guard valid else { throw issue() }
            let data = try JSONEncoder().encode(self)
            guard data.count <= 4096 else { throw issue() }
            return data
        }

        static func decode(_ data: Data, source: Source, request: String? = nil) throws -> Capture {
            guard !data.isEmpty, data.count <= 4096,
                  let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
                  Set(object.keys) == Set(["schema", "request_id", "session_id", "source", "execution", "healthy"]),
                  let savedSource = object["source"] as? [String: Any],
                  Set(savedSource.keys) == Set(["bundle_sha256", "entry_sha256", "entry_id", "exit_id", "entry_mode", "exit_mode", "requested"]) else { throw issue() }
            let value = try JSONDecoder().decode(Capture.self, from: data)
            guard value.valid, value.source == source, request == nil || value.requestID == request else { throw issue() }
            return value
        }
    }

    static func restoredExecution(option: NSObject?, source: Source, mtuHold: String) throws -> String? {
        guard let option else { return nil }
        guard let text = option as? String, text.utf8.count <= 4096,
              mtuHold.range(of: "^[0-9a-f]{32}$", options: .regularExpression) != nil else { throw issue() }
        return try Capture.decode(Data(text.utf8), source: source).execution
    }

    static func issue() -> NSError {
        NSError(domain: "RouterVPN.MultihopExecution", code: 1,
                userInfo: [NSLocalizedDescriptionKey: "The previous multihop winner is missing, stale, or belongs to another frozen source."])
    }
}
