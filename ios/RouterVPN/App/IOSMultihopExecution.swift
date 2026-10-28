import Foundation

/// A runtime-only restoration receipt. No node credential or selected policy
/// is copied into the launch option, and the saved Compare preference stays
/// unchanged. Both app and extension validate the exact original sources.
enum IOSMultihopExecution {
    static let launchKey = "routervpn_speed_lab_execution"
    static let startupLaunchKey = "routervpn_startup_execution"

    /// Tor entry paths preserve their proved Local/Server execution separately
    /// from a saved Compare preference. Ordinary
    /// external Local has no selector/lease owner; its Server/Compare family
    /// retains the separately proved runtime winner.
    static func requiresCapture(configuration: [String: Any]) throws -> Bool {
        if configuration["engine"] as? String == "multihop-libbox" { return true }
        guard configuration["engine"] as? String == "external-libbox" else { return false }
        guard let data = configuration["bundle"] as? Data else { throw issue() }
        let selected = try Source.profile(data, kind: "external")
        if let external = selected["external"] as? [String: Any], ["tor", "tor-bridge"].contains(external["protocol"] as? String ?? "") {
            guard ["local", "server", "auto"].contains(torSelection(selected)) else { throw issue() }
            return selected["multihop_enabled"] as? Bool == true
        }
        return ["server", "auto"].contains(selected["multihop_execution"] as? String ?? "local")
    }

    private static func torSelection(_ profile: [String: Any]) -> String {
        let execution = profile["multihop_execution"] as? String ?? "local"
        return execution.isEmpty ? "local" : execution
    }

    /// Lower only the execution selector of this immutable saved Tor profile.
    /// The native compiler still rejects unresolved auto; this copy is never
    /// written back to the node or used to replace a different saved source.
    static func torLeaf(_ profile: [String: Any], execution: String) throws -> [String: Any] {
        let requested = torSelection(profile)
        guard ["local", "server"].contains(execution), ["local", "server", "auto"].contains(requested),
              requested == "auto" || requested == execution,
              profile["node_kind"] as? String == "external",
              let external = profile["external"] as? [String: Any],
              ["tor", "tor-bridge"].contains(external["protocol"] as? String ?? ""),
              requested != "auto" || profile["multihop_enabled"] as? Bool == true else { throw issue() }
        var leaf = profile
        if requested == "auto" { leaf["multihop_execution"] = execution }
        return leaf
    }

    static func torLeafMatches(source: String, leaf: String, execution: String) -> Bool {
        guard !source.isEmpty, source.utf8.count <= 4 * 1024 * 1024,
              !leaf.isEmpty, leaf.utf8.count <= 4 * 1024 * 1024,
              let original = try? JSONSerialization.jsonObject(with: Data(source.utf8)) as? [String: Any],
              let actual = try? JSONSerialization.jsonObject(with: Data(leaf.utf8)) as? [String: Any],
              let expected = try? torLeaf(original, execution: execution),
              let before = try? JSONSerialization.data(withJSONObject: expected, options: [.sortedKeys]),
              let after = try? JSONSerialization.data(withJSONObject: actual, options: [.sortedKeys]) else { return false }
        return before == after
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
            guard (external || configuration["engine"] as? String == "multihop-libbox"),
                  let bundle = configuration["bundle"] as? Data,
                  let raw = external ? configuration["mode"] as? String : (configuration["rawProfileID"] as? String ?? configuration["mode"] as? String) else { throw issue() }
            let exitProfile = try Self.profile(bundle, kind: external ? "external" : "router-vpn")
            let tor = external && ["tor", "tor-bridge"].contains((exitProfile["external"] as? [String: Any])?["protocol"] as? String ?? "")
            let entryKey = tor ? "tor_entry_bundle" : (external ? "external_entry_bundle" : "entryBundle")
            guard let entry = configuration[entryKey] as? Data else { throw issue() }
            let ordinaryEntry = tor ? try? Self.profile(entry, kind: "external") : nil
            let entryProfile = try ordinaryEntry ?? Self.profile(entry, kind: "router-vpn")
            if let ordinaryEntry {
                guard IOSMultihopExecution.torSelection(exitProfile) == "local",
                      let transport = ordinaryEntry["external"] as? [String: Any],
                      let kind = transport["protocol"] as? String,
                      ["wireguard", "amneziawg", "socks5", "http-connect", "https-connect", "shadowsocks", "hysteria2", "openvpn"].contains(kind),
                      exitProfile["multihop_entry_mode"] as? String == kind,
                      let expected = transport["expected_public_ip"] as? String, !expected.isEmpty,
                      ["node_proof_id", "router_api", "api_token"].allSatisfy({ ordinaryEntry[$0] == nil || ordinaryEntry[$0] is NSNull || ordinaryEntry[$0] as? String == "" }) else { throw issue() }
            }
            guard exitProfile["multihop_enabled"] as? Bool == true,
                  let exitID = exitProfile["id"] as? String, let entryID = entryProfile["id"] as? String,
                  exitID != entryID, exitProfile["multihop_exit_id"] as? String == exitID,
                  exitProfile["multihop_entry_id"] as? String == entryID,
                  let exitMode = exitProfile["multihop_exit_mode"] as? String,
                  (external ? "external-" + exitMode : exitMode) == raw else { throw issue() }
            if external {
                guard configuration["rawProfileID"] == nil, configuration["entryBundle"] == nil else { throw issue() }
                if tor {
                    guard configuration["external_entry_bundle"] == nil, configuration["external_entry_mode"] == nil,
                          configuration["tor_entry_mode"] as? String == exitProfile["multihop_entry_mode"] as? String,
                          ["local", "server", "auto"].contains(IOSMultihopExecution.torSelection(exitProfile)),
                          ["tor", "tor-bridge"].contains(exitMode),
                          let selected = exitProfile["external"] as? [String: Any], selected["protocol"] as? String == exitMode,
                          selected["expected_public_ip"] as? String == "" else { throw issue() }
                } else {
                guard configuration["tor_entry_bundle"] == nil,
                      configuration["tor_entry_mode"] == nil,
                      configuration["external_entry_mode"] as? String == exitProfile["multihop_entry_mode"] as? String,
                      ["server", "auto"].contains(exitProfile["multihop_execution"] as? String ?? ""),
                      ["wireguard", "amneziawg", "shadowsocks", "hysteria2", "socks5", "http-connect", "https-connect", "openvpn"].contains(exitMode), let selected = exitProfile["external"] as? [String: Any],
                      selected["protocol"] as? String == exitMode else { throw issue() }
                if let probes = selected["openvpn_response_probes"] {
                    guard exitMode == "openvpn", selected["response_probe"] == nil,
                          selected["start_layer"] == nil,
                          let map = probes as? [String: Any], (2...16).contains(map.count),
                          map.values.allSatisfy({ $0 is [String: Any] }) else { throw issue() }
                    let mode = exitProfile["start_layer"] as? String ?? "off"
                    if let provision = selected["openvpn_start_layers"] {
                        guard ["aes-256-gcm", "aes-256-gcm+xor-whitening"].contains(mode),
                              let layers = provision as? [String: Any], Set(layers.keys) == Set(map.keys),
                              layers.values.allSatisfy({ value in
                                  guard let layer = value as? [String: Any] else { return false }
                                  return Set(layer.keys) == Set(["mode", "api", "transport"]) &&
                                      layer["mode"] as? String == mode && layer["api"] is String &&
                                      layer["transport"] is [String: Any]
                              }) else { throw issue() }
                    } else {
                        guard ["", "off"].contains(mode) else { throw issue() }
                    }
                } else {
                    guard selected["openvpn_start_layers"] == nil,
                          selected["response_probe"] is [String: Any] else { throw issue() }
                }
                if exitMode == "openvpn" {
                    guard let pairing = selected["openvpn_pairing"] as? [String: Any],
                          Set(pairing.keys) == ["private_key", "server"], pairing["private_key"] is String,
                          pairing["server"] is [String: Any] else { throw issue() }
                }
                if ["wireguard", "amneziawg"].contains(exitMode) {
                    guard let peer = selected["server_peer"] as? [String: Any],
                          Set(["public_key", "addresses", "mtu"]).isSubset(of: Set(peer.keys)),
                          Set(peer.keys).isSubset(of: Set(["public_key", "addresses", "mtu", "persistent_keepalive_interval"])) else { throw issue() }
                }
                }
            }
            self.bundleSHA256 = digest(bundle); self.entrySHA256 = digest(entry)
            self.entryID = entryID; self.exitID = exitID
            self.entryMode = exitProfile["multihop_entry_mode"] as? String ?? "wg"
            self.exitMode = exitMode
            self.requested = tor ? IOSMultihopExecution.torSelection(exitProfile) : (exitProfile["multihop_execution"] as? String ?? "local")
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

    /// Public Server identities accompany the exact source and proved winner.
    /// They are never resolver/transport configuration or new discovery input.
    struct ServerIdentityPins: Codable, Equatable, Sendable {
        let packetPublicKey: String?
        let pqClientIdentity: String?

        enum CodingKeys: String, CodingKey {
            case packetPublicKey = "expected_packet_public_key"
            case pqClientIdentity = "expected_pq_client_identity"
        }

        static let empty = ServerIdentityPins(packetPublicKey: nil, pqClientIdentity: nil)

        private init(packetPublicKey: String?, pqClientIdentity: String?) {
            self.packetPublicKey = packetPublicKey; self.pqClientIdentity = pqClientIdentity
        }

        init(json: String, source: Source, execution: String) throws {
            let data = Data(json.utf8)
            guard data.count <= 1024, let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
                  Self.exactObject(object) else { throw issue() }
            self = try JSONDecoder().decode(Self.self, from: data)
            guard valid(source: source, execution: execution) else { throw issue() }
        }

        static func exactObject(_ value: Any?) -> Bool {
            guard let object = value as? [String: Any],
                  Set(object.keys).isSubset(of: ["expected_packet_public_key", "expected_pq_client_identity"]),
                  object.values.allSatisfy({ $0 is String }) else { return false }
            return true
        }

        var structurallyValid: Bool {
            if let key = packetPublicKey {
                guard key.utf8.count == 44, let decoded = Data(base64Encoded: key), decoded.count == 32,
                      decoded.base64EncodedString() == key, decoded.contains(where: { $0 != 0 }) else { return false }
            }
            if let identity = pqClientIdentity {
                guard packetPublicKey != nil, identity.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil else { return false }
            }
            return true
        }

        func valid(source: Source, execution: String) -> Bool {
            guard source.valid, structurallyValid, ["local", "server"].contains(execution) else { return false }
            let pq = ["wg-pq", "awg2-pq", "max-tls-wg", "max-tls-awg", "max-quic-wg", "max-quic-awg"].contains(source.exitMode)
            let packet = pq || ["wg", "awg2-fast", "awg2-strong"].contains(source.exitMode)
            if execution != "server" || !packet { return self == .empty }
            return packetPublicKey != nil && (pq ? pqClientIdentity != nil : pqClientIdentity == nil)
        }

        func applying(to metadata: [String: String], source: Source) throws -> [String: String] {
            guard metadata["entry_id"] == source.entryID, metadata["exit_id"] == source.exitID,
                  metadata["entry_mode"] == source.entryMode, metadata["exit_mode"] == source.exitMode,
                  metadata["expected_packet_public_key"] == nil, metadata["expected_pq_client_identity"] == nil,
                  let execution = metadata["execution"], valid(source: source, execution: execution) else { throw issue() }
            var result = metadata
            if let packetPublicKey { result["expected_packet_public_key"] = packetPublicKey }
            if let pqClientIdentity { result["expected_pq_client_identity"] = pqClientIdentity }
            return result
        }
    }

    struct Capture: Codable, Equatable, Sendable {
        let schema: Int
        let requestID: String
        let sessionID: String
        let source: Source
        let execution: String
        let healthy: Bool
        let serverIdentityPins: ServerIdentityPins?

        var pins: ServerIdentityPins { serverIdentityPins ?? .empty }

        enum CodingKeys: String, CodingKey {
            case schema, source, execution, healthy
            case requestID = "request_id", sessionID = "session_id"
            case serverIdentityPins = "server_identity_pins"
        }

        init(source: Source, execution: String, session: String, request: String, pins: ServerIdentityPins = .empty) throws {
            schema = 2; self.source = source; self.execution = execution; serverIdentityPins = pins
            sessionID = session; requestID = request; healthy = true
            guard valid else { throw issue() }
        }

        private var valid: Bool {
            ((schema == 1 && serverIdentityPins == nil) || (schema == 2 && serverIdentityPins != nil)) &&
            healthy && source.valid && pins.valid(source: source, execution: execution) && UUID(uuidString: sessionID) != nil &&
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
                  (Set(object.keys) == Set(["schema", "request_id", "session_id", "source", "execution", "healthy"]) ||
                   Set(object.keys) == Set(["schema", "request_id", "session_id", "source", "execution", "healthy", "server_identity_pins"])),
                  object["server_identity_pins"] == nil || ServerIdentityPins.exactObject(object["server_identity_pins"]),
                  let savedSource = object["source"] as? [String: Any],
                  Set(savedSource.keys) == Set(["bundle_sha256", "entry_sha256", "entry_id", "exit_id", "entry_mode", "exit_mode", "requested"]) else { throw issue() }
            let value = try JSONDecoder().decode(Capture.self, from: data)
            guard value.valid, value.source == source, request == nil || value.requestID == request else { throw issue() }
            return value
        }
    }

    static func restoredCapture(option: NSObject?, source: Source, mtuHold: String) throws -> Capture? {
        guard let option else { return nil }
        guard let text = option as? String, text.utf8.count <= 4096,
              mtuHold.range(of: "^[0-9a-f]{32}$", options: .regularExpression) != nil else { throw issue() }
        return try Capture.decode(Data(text.utf8), source: source)
    }

    static func restoredExecution(option: NSObject?, source: Source, mtuHold: String) throws -> String? {
        try restoredCapture(option: option, source: source, mtuHold: mtuHold)?.execution
    }

    /// A cold-launch Last request chooses an already-recorded execution for
    /// this exact source. It does not claim a live proof or borrow Speed Lab's
    /// measurement lease. The new native runtime must prove the path normally.
    struct StartupChoice: Codable, Equatable, Sendable {
        let schema: Int
        let request: String
        let source: Source
        let execution: String
        let serverIdentityPins: ServerIdentityPins?

        var pins: ServerIdentityPins { serverIdentityPins ?? .empty }

        enum CodingKeys: String, CodingKey {
            case schema, request, source, execution
            case serverIdentityPins = "server_identity_pins"
        }

        init(source: Source, execution: String, pins: ServerIdentityPins = .empty) throws {
            schema = 2; request = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
            self.source = source; self.execution = execution; serverIdentityPins = pins
            guard valid else { throw issue() }
        }

        private var valid: Bool {
            ((schema == 1 && serverIdentityPins == nil) || (schema == 2 && serverIdentityPins != nil)) &&
                source.valid && pins.valid(source: source, execution: execution) &&
                request.range(of: "^[0-9a-f]{32}$", options: .regularExpression) != nil &&
                ["local", "server"].contains(execution) && (source.requested == "auto" || source.requested == execution)
        }

        func encoded() throws -> Data {
            guard valid else { throw issue() }
            let data = try JSONEncoder().encode(self)
            guard data.count <= 4096 else { throw issue() }
            return data
        }

        static func decode(_ data: Data, source: Source) throws -> StartupChoice {
            guard !data.isEmpty, data.count <= 4096,
                  let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
                  (Set(object.keys) == Set(["schema", "request", "source", "execution"]) ||
                   Set(object.keys) == Set(["schema", "request", "source", "execution", "server_identity_pins"])),
                  object["server_identity_pins"] == nil || ServerIdentityPins.exactObject(object["server_identity_pins"]),
                  let selected = object["source"] as? [String: Any],
                  Set(selected.keys) == Set(["bundle_sha256", "entry_sha256", "entry_id", "exit_id", "entry_mode", "exit_mode", "requested"]) else { throw issue() }
            let value = try JSONDecoder().decode(StartupChoice.self, from: data)
            guard value.valid, value.source == source else { throw issue() }
            return value
        }
    }

    static func restoredStartupChoice(option: NSObject?, source: Source) throws -> StartupChoice? {
        guard let option else { return nil }
        guard let text = option as? String, text.utf8.count <= 4096 else { throw issue() }
        return try StartupChoice.decode(Data(text.utf8), source: source)
    }

    static func restoredStartupExecution(option: NSObject?, source: Source) throws -> String? {
        try restoredStartupChoice(option: option, source: source)?.execution
    }

    static func issue() -> NSError {
        NSError(domain: "RouterVPN.MultihopExecution", code: 1,
                userInfo: [NSLocalizedDescriptionKey: "The previous multihop winner is missing, stale, or belongs to another frozen source."])
    }
}
