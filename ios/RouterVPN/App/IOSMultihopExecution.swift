import Foundation
import CoreFoundation
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

/// A runtime-only restoration receipt. No node credential or selected policy
/// is copied into the launch option, and the saved Compare preference stays
/// unchanged. Both app and extension validate the exact original sources.
enum IOSMultihopExecution {
    static let launchKey = "routervpn_speed_lab_execution"
    static let startupLaunchKey = "routervpn_startup_execution"

    /// The local native graph starts before the shared execution controller.
    /// Server creates a further native exit; Compare creates it a second time
    /// for the required final proof. Only captured Rosenpass-backed modes add
    /// their existing 30-second initial-key phase.
    static func startupTimeout(execution: String, entryMode: String, exitMode: String) throws -> TimeInterval {
        guard ["local", "server", "auto"].contains(execution) else { throw issue() }
        let initialKeyModes: Set<String> = ["wg-pq", "awg2-pq", "max-tls-wg", "max-tls-awg", "max-quic-wg", "max-quic-awg"]
        let entry: TimeInterval = initialKeyModes.contains(entryMode) ? 30 : 0
        let exit: TimeInterval = initialKeyModes.contains(exitMode) ? 30 : 0
        let remoteCount: TimeInterval = execution == "local" ? 0 : (execution == "auto" ? 2 : 1)
        return (execution == "local" ? 25 : 120) + entry + exit + remoteCount * exit
    }

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
            let ordinaryEntry = (tor || !external) ? try? Self.profile(entry, kind: "external") : nil
            let entryProfile = try ordinaryEntry ?? Self.profile(entry, kind: "router-vpn")
            if let ordinaryEntry, !external {
                guard let original = try JSONSerialization.jsonObject(with: bundle) as? [String: Any] else { throw issue() }
                var profiles: [String: [String: String]] = [:]
                if let value = original["profiles"] {
                    guard let captured = value as? [String: [String: String]] else { throw issue() }
                    profiles = captured
                }
                try IOSImportedEntryMultihop.validate(entry: ordinaryEntry, final: exitProfile, profiles: profiles)
            } else if let ordinaryEntry {
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


/// Validation of the two original saved roles. Native compilation and runtime
/// proof remain separate; this never grants a pairing identity to an import.
enum IOSImportedEntryMultihop {
    static func xrayFinal(_ mode: String) -> Bool {
        ["reality-vision", "reality-pq-vision", "reality-xhttp"].contains(mode)
    }
    static let methods: Set<String> = ["2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"]
    static func supports(entry: String, final: String) -> Bool {
        if ["http-connect", "https-connect"].contains(entry) { return final == "shadowsocks" || final == "naive-h2" || xrayFinal(final) }
        if ["socks5", "shadowsocks", "hysteria2", "wireguard", "amneziawg", "openvpn"].contains(entry) && (["naive-h2", "naive-h3"].contains(final) || xrayFinal(final)) { return true }
        if ["socks5", "openvpn"].contains(entry) { return ["shadowsocks", "hysteria2", "wg", "awg2-fast", "awg2-strong"].contains(final) }
        if ["shadowsocks", "hysteria2"].contains(final) {
            return ["wireguard", "amneziawg", "shadowsocks", "hysteria2"].contains(entry)
        }
        return ["wireguard", "amneziawg", "shadowsocks", "hysteria2"].contains(entry) && ["wg", "awg2-fast", "awg2-strong"].contains(final)
    }
    static func configuredCONNECTUoT(final: [String: Any], profiles: [String: [String: String]]) throws -> Bool {
        guard final["multihop_exit_mode"] as? String == "shadowsocks" else { return false }
        guard let files = profiles["shadowsocks"], files["routervpn-ss-service.json"] != nil else { return false }
        guard let node = final["node_proof_id"] as? String,
              node.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil else { throw issue() }
        try IOSMultihopStartLayer.validateCapturedSSService(files, node: node)
        return true
    }

    /// Picker/role validation of the original Naive source. The shared native
    /// compiler separately verifies the certificate, full wrapper and resolver
    /// closure before admission; this does not create a transport receipt.
    static func validateNaiveH2(final: [String: Any], profiles: [String: [String: String]], entry: String) throws {
        try validateNaive(final: final, profiles: profiles, entry: entry, mode: "naive-h2")
    }
    static func validateNaiveH3(final: [String: Any], profiles: [String: [String: String]], entry: String) throws {
        try validateNaive(final: final, profiles: profiles, entry: entry, mode: "naive-h3")
    }
    private static func validateNaive(final: [String: Any], profiles: [String: [String: String]], entry: String, mode: String) throws {
        guard ["naive-h2", "naive-h3"].contains(mode),
              mode != "naive-h3" || !["http-connect", "https-connect"].contains(entry),
              let files = profiles[mode], !files.isEmpty, files.count <= 2,
              files["routervpn-ss-service.json"] == nil,
              let encoded = files["sing-box.json"], let source = Data(base64Encoded: encoded),
              !source.isEmpty, source.count <= 4 * 1024 * 1024, source.base64EncodedString() == encoded,
              let root = try JSONSerialization.jsonObject(with: source) as? [String: Any],
              let rows = root["outbounds"] as? [[String: Any]], rows.filter({ $0["tag"] as? String == "proxy" }).count == 1,
              let out = rows.first(where: { $0["tag"] as? String == "proxy" }),
              Set(out.keys).isSubset(of: ["type", "tag", "server", "server_port", "username", "password", "quic", "udp_over_tcp", "tls"]),
              out["type"] as? String == "naive", exactBoolean(out["quic"]) == (mode == "naive-h3"),
              let host = out["server"] as? String, literalAddress(host),
              let port = out["server_port"] as? NSNumber, CFGetTypeID(port) != CFBooleanGetTypeID(),
              port.doubleValue == Double(port.intValue), (1...65535).contains(port.intValue),
              let username = out["username"] as? String, !username.contains(":"), let password = out["password"] as? String,
              [username, password].allSatisfy({ !$0.isEmpty && $0.utf8.count <= 4096 && !$0.utf8.contains(where: { [0, 10, 13].contains($0) }) }),
              let uot = out["udp_over_tcp"] as? [String: Any], Set(uot.keys) == Set(["enabled", "version"]),
              exactBoolean(uot["enabled"]) == true, let version = uot["version"] as? NSNumber,
              CFGetTypeID(version) != CFBooleanGetTypeID(), version.doubleValue == 2,
              let tls = out["tls"] as? [String: Any],
              Set(tls.keys).isSubset(of: ["enabled", "server_name", "insecure", "certificate", "certificate_path"]),
              exactBoolean(tls["enabled"]) == true, tls["insecure"] == nil || exactBoolean(tls["insecure"]) == false,
              let name = tls["server_name"] as? String, !name.isEmpty, name.utf8.count <= 253,
              name == name.trimmingCharacters(in: .whitespacesAndNewlines),
              name.unicodeScalars.allSatisfy({ $0.isASCII && $0.value > 32 && $0.value != 127 }) else { throw issue() }
        var used: Set<String> = ["sing-box.json"]
        if let raw = tls["certificate_path"] {
            guard let path = raw as? String, path != "sing-box.json", !path.contains(".."),
                  path.range(of: "^[A-Za-z0-9._-]+$", options: .regularExpression) != nil,
                  tls["certificate"] == nil, let text = files[path], let data = Data(base64Encoded: text),
                  data.base64EncodedString() == text, !data.isEmpty, data.count <= 256 * 1024,
                  let material = String(data: data, encoding: .utf8), capturedCertificate(material) else { throw issue() }
            used.insert(path)
        }
        if let raw = tls["certificate"] {
            let material = raw as? [String] ?? (raw as? String).map { [$0] }
            guard let material, !material.isEmpty, material.count <= 16,
                  material.reduce(0, { $0 + $1.utf8.count }) <= 256 * 1024,
                  material.allSatisfy(capturedCertificate) else { throw issue() }
        }
        guard used == Set(files.keys) else { throw issue() }
        if ["http-connect", "https-connect"].contains(entry) {
            // Naive's inner UoT does not authorize UDP below its own H2 dial.
            // Preserve the original selected DNS and bootstrap; refuse an
            // incompatible tree instead of replacing it with another policy.
            let selectedTransport = try selectedDNSTransport(final)
            let dnsMode = (final["dns_mode"] as? String ?? "home").lowercased()
            guard final["dns_host"] == nil || final["dns_host"] is String else { throw issue() }
            let configuredHost = final["dns_host"] as? String ?? ""
            let homeHost = [final["adguard_ipv4"] as? String ?? "", final["adguard_ipv6"] as? String ?? ""].first(where: { !$0.isEmpty }) ?? ""
            let resolverHost = dnsMode == "rescue" ? "1.1.1.1" :
                (["", "home"].contains(dnsMode) && configuredHost.isEmpty ? homeHost : configuredHost)
            guard !resolverHost.isEmpty else { throw issue() }
            // Literal H2 and independently captured AES layer endpoints need
            // no lower DNS query. Retain the resolver tree; this grants only
            // final-owned application UDP, not UDP below the H2 dial.
            let literalH2UDP = mode == "naive-h2" && selectedTransport == "udp"
                && ["", "off", "aes-256-gcm", "aes-256-gcm+xor-whitening"].contains(final["start_layer"] as? String ?? "")
                && literalAddress(resolverHost) && final["dns_bootstrap"] == nil
            guard literalH2UDP || ["tcp", "tls", "https"].contains(selectedTransport) else { throw issue() }
            if literalH2UDP && !["", "off"].contains(final["start_layer"] as? String ?? "") {
                // A hostname on the outer AES peer would need the unusable
                // lower UDP resolver even though Naive itself is literal.
                _ = try IOSMultihopStartLayer.capture(profile: final, profiles: profiles)
                guard let encoded = profiles["shadowsocks"]?["sing-box.json"],
                      let data = Data(base64Encoded: encoded),
                      let layer = try JSONSerialization.jsonObject(with: data) as? [String: Any],
                      let rows = layer["outbounds"] as? [[String: Any]] else { throw issue() }
                let transports = rows.filter { $0["type"] as? String == "shadowsocks" }
                guard transports.count == 1,
                      transports[0]["method"] as? String == "2022-blake3-aes-256-gcm",
                      let host = transports[0]["server"] as? String,
                      literalLayerAddress(host) else { throw issue() }
            }
            if let raw = final["dns_bootstrap"] {
                guard !literalAddress(resolverHost), let bootstrap = raw as? [String: Any],
                      Set(bootstrap.keys) == Set(["server", "query"]), let server = bootstrap["server"] as? [String: Any],
                      ["tcp", "tls", "https"].contains(server["type"] as? String ?? ""),
                      server["tag"] as? String == "external-dns-bootstrap",
                      ["proxy", "custom-exit"].contains(server["detour"] as? String ?? ""),
                      let host = server["server"] as? String, literalAddress(host),
                      let query = bootstrap["query"] as? [String: Any], query["server"] as? String == "external-dns-bootstrap" else { throw issue() }
            } else if !literalAddress(resolverHost) { throw issue() }
        }
    }

    private static func literalAddress(_ value: String) -> Bool {
        guard !value.isEmpty, !value.contains("%"), !value.utf8.contains(0) else { return false }
        var v4 = in_addr(), v6 = in6_addr()
        return inet_pton(AF_INET, value, &v4) == 1 || inet_pton(AF_INET6, value, &v6) == 1
    }

    private static func literalLayerAddress(_ value: String) -> Bool {
        guard literalAddress(value) else { return false }
        var v6 = in6_addr()
        guard inet_pton(AF_INET6, value, &v6) == 1 else { return true }
        return withUnsafeBytes(of: &v6) { bytes in
            !(bytes.prefix(10).allSatisfy { $0 == 0 } && bytes[10] == 255 && bytes[11] == 255)
        }
    }

    private static func exactBoolean(_ value: Any?) -> Bool? {
        guard let number = value as? NSNumber, CFGetTypeID(number) == CFBooleanGetTypeID() else { return nil }
        return number.boolValue
    }
    private static func capturedCertificate(_ value: String) -> Bool {
        let text = value.trimmingCharacters(in: .whitespacesAndNewlines)
        return text.hasPrefix("-----BEGIN CERTIFICATE-----") && text.hasSuffix("-----END CERTIFICATE-----")
    }
    private static func selectedDNSTransport(_ final: [String: Any]) throws -> String {
        guard ["dns_mode", "dns_protocol"].allSatisfy({ final[$0] == nil || final[$0] is String }) else { throw issue() }
        let mode = (final["dns_mode"] as? String ?? "").lowercased()
        let saved = (final["dns_protocol"] as? String ?? "").lowercased()
        let selected: String
        switch mode {
        case "", "home": selected = saved.isEmpty ? "udp" : saved
        case "custom": selected = saved
        case "dot": selected = "tls"
        case "doh", "rescue": selected = "https"
        case "doh3": selected = "h3"
        case "fastest": selected = "udp"
        default: throw issue()
        }
        return ["dot": "tls", "doh": "https", "doh3": "h3"][selected] ?? selected
    }
    static func validate(entry: [String: Any], final: [String: Any], profiles: [String: [String: String]] = [:]) throws {
        guard let imported = entry["external"] as? [String: Any],
              let kind = imported["protocol"] as? String, ["wireguard", "amneziawg", "shadowsocks", "hysteria2", "socks5", "http-connect", "https-connect", "openvpn"].contains(kind) else { throw issue() }
        let naiveH2 = final["multihop_exit_mode"] as? String == "naive-h2"
        if naiveH2 { try validateNaiveH2(final: final, profiles: profiles, entry: kind) }
        if final["multihop_exit_mode"] as? String == "naive-h3" { try validateNaiveH3(final: final, profiles: profiles, entry: kind) }
        if xrayFinal(final["multihop_exit_mode"] as? String ?? "") {
            guard ["socks5", "shadowsocks", "hysteria2", "http-connect", "https-connect", "wireguard", "amneziawg", "openvpn"].contains(kind),
                  [entry, final].allSatisfy({ profile in
                      (profile["start_layer"] == nil || profile["start_layer"] is String) &&
                      ["", "off", "aes-256-gcm", "aes-256-gcm+xor-whitening"].contains(profile["start_layer"] as? String ?? "")
                  }) else { throw issue() }
        }
        if ["http-connect", "https-connect"].contains(kind) {
            let mode = final["multihop_exit_mode"] as? String ?? ""
            let reality = xrayFinal(mode)
            if reality {
                guard let original = profiles[mode], original["xray.json"] != nil,
                      original["routervpn-ss-service.json"] == nil else { throw issue() }
            }
            let uot = try configuredCONNECTUoT(final: final, profiles: profiles)
            let datagrams = reality || uot || naiveH2
            let layers = datagrams ? ["", "off", "aes-256-gcm", "aes-256-gcm+xor-whitening"] : ["", "off"]
            // validateNaiveH2 above has already checked the narrow literal
            // UDP resolver tree before this common choice list. Captured
            // Start Layer authority is validated separately for each node.
            let transports = naiveH2 ? ["udp", "tcp", "tls", "https"] : datagrams ? ["udp", "tcp", "tls", "https", "h3"] : ["tcp", "tls", "https"]
            guard entry["start_layer"] == nil || entry["start_layer"] is String,
                  ["start_layer", "dns_mode", "dns_protocol"].allSatisfy({ final[$0] == nil || final[$0] is String }) else { throw issue() }
            let transport = try selectedDNSTransport(final)
            guard ["", "off", "aes-256-gcm", "aes-256-gcm+xor-whitening"].contains(entry["start_layer"] as? String ?? ""),
                  layers.contains(final["start_layer"] as? String ?? ""),
                  transports.contains(transport) else { throw issue() }
        }
        if kind == "shadowsocks" {
            guard let transport = imported[kind] as? [String: Any], methods.contains(transport["method"] as? String ?? "") else { throw issue() }
        } else if kind == "hysteria2" {
            guard let transport = imported[kind] as? [String: Any],
                  let password = transport["password"] as? String, !password.isEmpty,
                  let name = transport["tls_server_name"] as? String, !name.isEmpty, name.utf8.count <= 253,
                  name.range(of: "^[A-Za-z0-9.-]+$", options: .regularExpression) != nil,
                  !name.hasPrefix("."), !name.hasSuffix(".") else { throw issue() }
        }
        if ["wireguard", "amneziawg"].contains(kind) {
            guard let transport = imported[kind] as? [String: Any],
                  let privateKey = transport["private_key"] as? String, !privateKey.isEmpty,
                  let publicKey = transport["peer_public_key"] as? String, !publicKey.isEmpty,
                  let endpoint = transport["endpoint"] as? String, !endpoint.isEmpty,
                  let addresses = transport["addresses"] as? [String], !addresses.isEmpty,
                  let allowed = transport["allowed_ips"] as? [String], !allowed.isEmpty else { throw issue() }
            if kind == "amneziawg" {
                guard let parameters = transport["parameters"] as? [String: String], !parameters.isEmpty else { throw issue() }
            }
        }
        guard entry["node_kind"] as? String == "external",
              final["node_kind"] == nil || final["node_kind"] is String,
              ["", "router-vpn"].contains(final["node_kind"] as? String ?? ""),
              let entryID = entry["id"] as? String, !entryID.isEmpty,
              let finalID = final["id"] as? String, entryID != finalID,
              final["multihop_enabled"] as? Bool == true,
              final["multihop_entry_id"] as? String == entryID,
              final["multihop_exit_id"] as? String == finalID,
              final["multihop_entry_mode"] as? String == kind,
              supports(entry: kind, final: final["multihop_exit_mode"] as? String ?? ""),
              (final["multihop_execution"] as? String ?? "local") == "local",
              entry["multihop_enabled"] as? Bool != true,
              let expected = imported["expected_public_ip"] as? String, !expected.isEmpty,
              ["node_proof_id", "router_api", "api_token"].allSatisfy({
                  entry[$0] == nil || entry[$0] is NSNull || entry[$0] as? String == ""
              }),
              let proof = final["node_proof_id"] as? String,
              proof.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil,
              let api = final["router_api"] as? String, !api.isEmpty,
              let token = final["api_token"] as? String, !token.isEmpty else { throw issue() }
    }

    static func issue() -> NSError {
        NSError(domain: "RouterVPN.ImportedEntry", code: 1, userInfo: [NSLocalizedDescriptionKey:
            "Choose a Local imported entry and a different paired Router VPN final with their original settings. WireGuard, AmneziaWG, OpenVPN, SOCKS5, Shadowsocks 2022, Hysteria2 and HTTP/HTTPS CONNECT entries can use a paired REALITY Vision, PQ REALITY Vision or XHTTP final while retaining each node's independently provisioned Start Layer. Naive H2 retains its own authenticated H2 and UDP stream transport. Over HTTP/HTTPS CONNECT a captured literal Naive H2 final supports the original literal Home UDP resolver with its independently captured final Start Layer Off, AES or AES+XOR. Hostname resolver trees still require TCP-compatible bootstrap; saved DNS is never rewritten. REALITY carries TCP and UDP; Vision requires the final node's UDP 443 option for QUIC or DoH3 on port 443. HTTP/HTTPS CONNECT can also use SS2022 with selected TCP, DoT or DoH DNS. Its captured UoT-v2 service additionally permits UDP and final AES or AES+XOR; without it, SS2022 is TCP-only with the final layer Off. Resolver hostnames require their saved bootstrap through the same final. WireGuard and AmneziaWG finals require the captured entry capacity to fit their complete packet and handshake envelope. Auto may derive a smaller final endpoint MTU; Fixed overflow is refused. These configured bounds are not a measured path MTU."])
    }
}
