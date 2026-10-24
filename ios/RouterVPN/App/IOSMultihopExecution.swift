import Foundation

/// A runtime-only restoration receipt. No node credential or selected policy
/// is copied into the launch option, and the saved Compare preference stays
/// unchanged. Both app and extension validate the exact original sources.
enum IOSMultihopExecution {
    static let launchKey = "routervpn_speed_lab_execution"

    /// Plain external Local has no selector/lease owner. Only the saved
    /// Server/Compare family needs a proved runtime receipt for restoration.
    static func requiresCapture(configuration: [String: Any]) throws -> Bool {
        if configuration["engine"] as? String == "multihop-libbox" { return true }
        guard configuration["engine"] as? String == "external-libbox" else { return false }
        guard let data = configuration["bundle"] as? Data else { throw issue() }
        let selected = try Source.profile(data, kind: "external")
        return ["server", "auto"].contains(selected["multihop_execution"] as? String ?? "local")
    }

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
            let external = configuration["engine"] as? String == "external-libbox"
            let entryKey = external ? "external_entry_bundle" : "entryBundle"
            guard (external || configuration["engine"] as? String == "multihop-libbox"),
                  let bundle = configuration["bundle"] as? Data,
                  let entry = configuration[entryKey] as? Data,
                  let raw = external ? configuration["mode"] as? String : (configuration["rawProfileID"] as? String ?? configuration["mode"] as? String) else { throw issue() }
            let exitProfile = try Self.profile(bundle, kind: external ? "external" : "router-vpn")
            let entryProfile = try Self.profile(entry, kind: "router-vpn")
            guard exitProfile["multihop_enabled"] as? Bool == true,
                  let exitID = exitProfile["id"] as? String, let entryID = entryProfile["id"] as? String,
                  exitID != entryID, exitProfile["multihop_exit_id"] as? String == exitID,
                  exitProfile["multihop_entry_id"] as? String == entryID,
                  let exitMode = exitProfile["multihop_exit_mode"] as? String,
                  (external ? "external-" + exitMode : exitMode) == raw else { throw issue() }
            if external {
                guard configuration["rawProfileID"] == nil, configuration["entryBundle"] == nil, configuration["tor_entry_bundle"] == nil,
                      configuration["tor_entry_mode"] == nil,
                      configuration["external_entry_mode"] as? String == exitProfile["multihop_entry_mode"] as? String,
                      ["server", "auto"].contains(exitProfile["multihop_execution"] as? String ?? ""),
                      ["wireguard", "amneziawg", "shadowsocks", "hysteria2", "socks5", "http-connect", "https-connect"].contains(exitMode), let selected = exitProfile["external"] as? [String: Any],
                      selected["protocol"] as? String == exitMode, selected["response_probe"] is [String: Any] else { throw issue() }
                if ["wireguard", "amneziawg"].contains(exitMode) {
                    guard let peer = selected["server_peer"] as? [String: Any],
                          Set(["public_key", "addresses", "mtu"]).isSubset(of: Set(peer.keys)),
                          Set(peer.keys).isSubset(of: Set(["public_key", "addresses", "mtu", "persistent_keepalive_interval"])) else { throw issue() }
                }
            }
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

        fileprivate static func profile(_ data: Data, kind expected: String) throws -> [String: Any] {
            guard !data.isEmpty, data.count <= 32 * 1024 * 1024,
                  let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let profiles = object["routerProfiles"] as? [[String: Any]], !profiles.isEmpty else { throw issue() }
            let selected = object["selectedRouterID"] as? String ?? ""
            let matches = selected.isEmpty && profiles.count == 1 ? profiles : profiles.filter { $0["id"] as? String == selected }
            guard matches.count == 1 else { throw issue() }
            let kind = (matches[0]["node_kind"] as? String ?? "router-vpn").trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            guard kind == expected || (kind.isEmpty && expected == "router-vpn") else { throw issue() }
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
