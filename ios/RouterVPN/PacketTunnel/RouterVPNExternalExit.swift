import Foundation
import CoreFoundation
import Network
import Libbox
#if canImport(CryptoKit)
import CryptoKit
#endif

/// The native compiler freezes both transport bytes and saved policy. This
/// record describes that configuration; it is never a successful live proof.
struct RouterVPNExternalPolicy: Sendable {
    let sourceConfig: String
    let capture: String
    let config: String
    let metadata: String
    let sourceSHA256: String

    var executionRequested: String? {
        (try? JSONSerialization.jsonObject(with: Data(metadata.utf8)) as? [String: Any])?["execution"] as? String
    }

    static func compile(config: String, profile: [String: Any], protocolName: String,
                        expectedPublicIP: String, entry: [String: Any]? = nil,
                        entryTag: String? = nil, predecessorConfig: String? = nil,
                        restoredExecution: String? = nil) throws -> RouterVPNExternalPolicy {
        guard let exitID = profile["id"] as? String, !exitID.isEmpty,
              (entry == nil) == (entryTag == nil) else { throw issue() }
        var frozenProfile = profile
        let bootstrap = frozenProfile.removeValue(forKey: "dns_bootstrap")
        var selected: [String: Any] = ["schema": 1, "exit_id": exitID, "protocol": protocolName,
            "expected_public_ip": expectedPublicIP, "profile": frozenProfile]
        if let bootstrap {
            guard let owned = bootstrap as? [String: Any], Set(owned.keys) == ["server", "query"] else { throw issue() }
            selected["dns_bootstrap"] = owned
        }
        if let entry, let entryTag { selected["entry"] = entry; selected["entry_tag"] = entryTag }
        if let predecessorConfig {
            guard entry != nil, entryTag == "external-entry", !predecessorConfig.isEmpty,
                  predecessorConfig.utf8.count <= 4 * 1024 * 1024 else { throw issue() }
            selected["predecessor_config"] = predecessorConfig
        }
        let selection = String(decoding: try JSONSerialization.data(withJSONObject: selected, options: [.sortedKeys]), as: UTF8.self)
        var failure: NSError?
        // Freeze the one lease proposal before graph compilation. Every proof,
        // measurement and MTU operation reuses these exact captured bytes.
        let capture = LibboxRouterPrepareExternalExecutionCapture(config, selection, restoredExecution ?? "", &failure)
        if let failure { throw failure }
        guard !capture.isEmpty, capture.utf8.count <= 8 * 1024 * 1024 else { throw issue() }
        let encoded = LibboxRouterCompileExternalPolicy(config, capture, &failure)
        if let failure { throw failure }
        return try adopt(encoded, source: config, capture: capture, exitID: exitID,
                         protocolName: protocolName, expectedPublicIP: expectedPublicIP,
                         entryID: entry?["id"] as? String, entryTag: entryTag)
    }

    static func adopt(_ encoded: String, source: String, capture: String, exitID: String,
                      protocolName: String, expectedPublicIP: String, entryID: String?, entryTag: String?) throws -> RouterVPNExternalPolicy {
        guard encoded.utf8.count <= 8 * 1024 * 1024,
              let envelope = try JSONSerialization.jsonObject(with: Data(encoded.utf8)) as? [String: Any],
              Set(envelope.keys) == ["schema", "source_sha256", "config_json", "metadata_json"],
              envelope["schema"] as? Int == 1,
              let config = envelope["config_json"] as? String, !config.isEmpty, config.utf8.count <= 4 * 1024 * 1024,
              let metadata = envelope["metadata_json"] as? String, metadata.utf8.count <= 65536,
              let values = try JSONSerialization.jsonObject(with: Data(metadata.utf8)) as? [String: Any],
              values["schema"] as? Int == 1,
              let sourceHash = envelope["source_sha256"] as? String,
              sourceHash == (try sourceDigest(source: source, capture: capture)),
              values["source_sha256"] as? String == sourceHash,
              values["config_sha256"] as? String == digest(Data(config.utf8)),
              values["exit_id"] as? String == exitID, values["policy_id"] as? String == exitID,
              values["protocol"] as? String == protocolName,
              values["expected_public_ip"] as? String == expectedPublicIP,
              values["entry_id"] as? String == entryID, values["entry_tag"] as? String == entryTag,
              values["final_tag"] as? String == "custom-exit",
              values["dns_proof"] as? String == "required", values["public_exit_proof"] as? String == "required",
              ["not-requested", "unmeasured"].contains(values["auto_mtu"] as? String ?? "") else { throw issue() }
        let selected = try JSONSerialization.jsonObject(with: Data(capture.utf8)) as? [String: Any]
        if let predecessor = selected?["predecessor_config"] as? String {
            guard values["predecessor_sha256"] as? String == digest(Data(predecessor.utf8)) else { throw issue() }
        } else { guard values["predecessor_sha256"] == nil else { throw issue() } }
        if let execution = selected?["execution"] as? [String: Any] {
            guard let requested = execution["selection"] as? String, ["local", "server", "auto"].contains(requested),
                  values["execution"] as? String == requested,
                  values["last_node_measurement"] as? String == "https-response-time",
                  ["wireguard", "amneziawg", "shadowsocks", "hysteria2", "socks5", "http-connect", "https-connect"].contains(protocolName), entryID != nil else { throw issue() }
        } else {
            guard selected?["execution"] == nil, values["execution"] == nil, values["last_node_measurement"] == nil else { throw issue() }
        }
        return RouterVPNExternalPolicy(sourceConfig: source, capture: capture, config: config,
                                       metadata: metadata, sourceSHA256: sourceHash)
    }

    func validateProof(_ result: String, sessionID: String, began: Date) throws {
        guard result.utf8.count <= 8192,
              let value = try JSONSerialization.jsonObject(with: Data(result.utf8)) as? [String: Any],
              let selected = try JSONSerialization.jsonObject(with: Data(capture.utf8)) as? [String: Any],
              let schema = value["schema"] as? NSNumber, CFGetTypeID(schema) != CFBooleanGetTypeID(), schema.intValue == 1, schema.doubleValue == 1,
              value["session_id"] as? String == sessionID,
              value["source_sha256"] as? String == sourceSHA256,
              value["config_sha256"] as? String == Self.digest(Data(config.utf8)),
              value["exit_id"] as? String == selected["exit_id"] as? String,
              let dns = value["dns_proven"] as? NSNumber, CFGetTypeID(dns) == CFBooleanGetTypeID(), dns.boolValue,
              let entryProven = value["entry_proven"] as? NSNumber, CFGetTypeID(entryProven) == CFBooleanGetTypeID(),
              let ip = value["ip"] as? String, let expected = selected["expected_public_ip"] as? String,
              Self.sameIP(ip, expected),
              let timestamp = value["checked_at"] as? NSNumber, CFGetTypeID(timestamp) != CFBooleanGetTypeID(),
              timestamp.doubleValue.isFinite, timestamp.doubleValue.rounded() == timestamp.doubleValue else { throw Self.issue() }
        let entry = selected["entry"] as? [String: Any]
        guard entryProven.boolValue == (entry != nil),
              (value["entry_id"] as? String ?? "") == (entry?["id"] as? String ?? ""),
              (value["entry_node_id"] as? String ?? "") == (entry?["node_proof_id"] as? String ?? "") else { throw Self.issue() }
        if let requested = executionRequested {
            guard let execution = value["execution"] as? String, ["local", "server"].contains(execution),
                  requested == "auto" || requested == execution else { throw Self.issue() }
        } else { guard value["execution"] == nil else { throw Self.issue() } }
        let checked = Date(timeIntervalSince1970: timestamp.doubleValue / 1000)
        guard checked >= began.addingTimeInterval(-2), checked <= Date().addingTimeInterval(5) else { throw Self.issue() }
    }

    private static func sameIP(_ lhs: String, _ rhs: String) -> Bool {
        guard lhs == lhs.trimmingCharacters(in: .whitespacesAndNewlines), !lhs.contains("%") else { return false }
        if let left = IPv4Address(lhs), let right = IPv4Address(rhs) { return left.rawValue == right.rawValue }
        if let left = IPv6Address(lhs), let right = IPv6Address(rhs) { return left.rawValue == right.rawValue }
        return false
    }

    private static func sourceDigest(source: String, capture: String) throws -> String {
        // encoding/json hashes the exact UTF-8 strings, including its HTML and
        // U+2028/U+2029 escaping. Do not hash a reserialized source dictionary.
        let data = try JSONSerialization.data(withJSONObject: ["routervpn-external-policy-v1", source, capture], options: [.withoutEscapingSlashes])
        let text = String(decoding: data, as: UTF8.self)
            .replacingOccurrences(of: "&", with: "\\u0026")
            .replacingOccurrences(of: "<", with: "\\u003c")
            .replacingOccurrences(of: ">", with: "\\u003e")
            .replacingOccurrences(of: "\u{2028}", with: "\\u2028")
            .replacingOccurrences(of: "\u{2029}", with: "\\u2029")
        return digest(Data(text.utf8))
    }
    private static func digest(_ data: Data) -> String { SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() }
    private static func issue() -> NSError { NSError(domain: "RouterVPN.ExternalPolicy", code: 1, userInfo: [NSLocalizedDescriptionKey: "External policy does not belong to the exact captured node, graph and preferences."]) }
}

struct RouterVPNExternalExitRuntime {
    let protocolName: String
    let expectedPublicIP: String
    let files: [String: Data]
    var torSessionID: String? = nil
    var torPredecessorProfile: String? = nil
    var torProfileJSON: String? = nil
    var policy: RouterVPNExternalPolicy? = nil
}

enum RouterVPNExternalExitBuilder {
    static let ordinaryProtocols: Set<String> = ["wireguard", "amneziawg", "socks5", "http-connect", "https-connect", "shadowsocks", "hysteria2", "openvpn"]
    static let torEntryModes: Set<String> = Set(RouterVPNMultihopGraph.supportedExitModes).union(IOSNativeMAXProfile.modeIDs)
    static func build(profile: [String: Any], predecessorFiles: [String: Data] = [:], predecessorProfile: [String: Any]? = nil,
                      restoredExecution: String? = nil) throws -> RouterVPNExternalExitRuntime {
        let kind = string(profile["node_kind"]).lowercased()
        guard kind == "external", let external = profile["external"] as? [String: Any] else {
            throw error("Selected profile is not an external custom node.")
        }
        let protocolName = string(external["protocol"]).lowercased()
        if protocolName == "tor" || protocolName == "tor-bridge" {
            guard restoredExecution == nil else { throw error("Tor cannot adopt an external execution receipt.") }
            let throughEntry = profile["multihop_enabled"] as? Bool ?? false
            guard throughEntry == (predecessorProfile != nil), throughEntry == !predecessorFiles.isEmpty else { throw error("Tor entry graph does not match the frozen node selection.") }
            var predecessor = ""
            var predecessorTag: String?
            var proofProfile: String?
            if let predecessorProfile {
                guard string(profile["multihop_exit_id"]) == string(profile["id"]),
                      string(profile["multihop_exit_mode"]) == protocolName,
                      ["", "local"].contains(string(profile["multihop_execution"])),
                      string(profile["multihop_entry_id"]) == string(predecessorProfile["id"]),
                      predecessorProfile["node_kind"] as? String == "router-vpn",
                      string(predecessorProfile["node_proof_id"]).range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil,
                      let source = predecessorFiles["sing-box.json"], let text = String(data: source, encoding: .utf8),
                      let config = try JSONSerialization.jsonObject(with: source) as? [String: Any],
                      let final = (config["route"] as? [String: Any])?["final"] as? String, !final.isEmpty else {
                    throw error("Tor requires the selected entry's complete graph and private node identity.")
                }
                // A single system TUN cannot obey two conflicting fixed sizes.
                // Preserve the entry's already validated MTU unless Tor explicitly
                // selects a compatible value; never reuse saved measurement history.
                let entryPolicy = string(predecessorProfile["mtu_policy"])
                let exitPolicy = string(profile["mtu_policy"])
                if ["manual", "fixed"].contains(entryPolicy), ["manual", "fixed"].contains(exitPolicy),
                   int(predecessorProfile["manual_mtu"]) != int(profile["manual_mtu"]) { throw error("Tor and its entry select different fixed sizes for the same VPN interface.") }
                predecessor = text; predecessorTag = final
                proofProfile = String(decoding: try JSONSerialization.data(withJSONObject: predecessorProfile, options: [.sortedKeys]), as: UTF8.self)
            }
            let sessionID = UUID().uuidString.lowercased()
            let source = try JSONSerialization.data(withJSONObject: profile, options: [.sortedKeys])
            var failure: NSError?
            let encoded = LibboxRouterCompileTorProfileWithPredecessor(String(decoding: source, as: UTF8.self), sessionID, predecessor, proofProfile ?? "", &failure)
            if let failure { throw failure }
            guard let data = encoded.data(using: .utf8), !data.isEmpty, data.count <= 4 * 1024 * 1024,
                  let config = try JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let inbounds = config["inbounds"] as? [[String: Any]], inbounds.count == 1, inbounds[0]["type"] as? String == "tun",
                  let outbounds = config["outbounds"] as? [[String: Any]],
                  outbounds.filter({ $0["type"] as? String == "routervpn-tor" }).count == 1,
                  let tor = outbounds.first(where: { $0["type"] as? String == "routervpn-tor" }),
                  tor["tag"] as? String == "routervpn-tor-exit",
                  tor["session_id"] as? String == sessionID,
                  tor["detour"] as? String == predecessorTag,
                  (config["route"] as? [String: Any])?["final"] as? String == "routervpn-tor-exit" else {
                throw error("Tor compiler lost the selected session or final route.")
            }
            var files = predecessorFiles; files["sing-box.json"] = data
            return RouterVPNExternalExitRuntime(protocolName: protocolName, expectedPublicIP: "", files: files, torSessionID: sessionID, torPredecessorProfile: proofProfile, torProfileJSON: String(decoding: source, as: UTF8.self))
        }
        guard ordinaryProtocols.contains(protocolName) else {
            throw error("Unsupported iOS external protocol \(protocolName).")
        }
        guard (profile["multihop_enabled"] as? Bool ?? false) == (predecessorProfile != nil) else {
            throw error("The external graph does not match the captured entry selection.")
        }
        let expected = try publicLiteralIP(string(external["expected_public_ip"]), label: "expected public exit IP")
        var custom = try customExit(external: external, protocolName: protocolName)

        var endpoints: [[String: Any]] = []
        var outbounds: [[String: Any]] = []
        var entryTag: String?
        var predecessorConfig: String?
        if let predecessorProfile {
            guard ordinaryProtocols.contains(protocolName),
                  profile["multihop_entry_id"] as? String == predecessorProfile["id"] as? String,
                  predecessorProfile["id"] as? String != profile["id"] as? String,
                  profile["multihop_exit_id"] as? String == profile["id"] as? String,
                  profile["multihop_exit_mode"] as? String == protocolName,
                  ["", "local", "server", "auto"].contains(string(profile["multihop_execution"])) else {
                throw error("The external graph belongs to another entry, exit or execution selection.")
            }
            let tag = "external-entry"
            if predecessorProfile["node_kind"] as? String == "external" {
                guard predecessorFiles.isEmpty, let imported = predecessorProfile["external"] as? [String: Any],
                      ["", "local"].contains(string(profile["multihop_execution"])), restoredExecution == nil,
                      let kind = imported["protocol"] as? String, ordinaryProtocols.contains(kind),
                      profile["multihop_entry_mode"] as? String == kind else {
                    throw error("The external entry must retain its exact native imported protocol.")
                }
                try IOSStartLayer.validateExternal(profile: predecessorProfile)
                _ = try publicLiteralIP(string(imported["expected_public_ip"]), label: "entry public proof IP")
                var entry = try customExit(external: imported, protocolName: kind); entry["tag"] = tag
                if ["wireguard", "amneziawg", "openvpn"].contains(kind) { endpoints.append(entry) } else { outbounds.append(entry) }
                custom["detour"] = tag
            } else {
                guard predecessorProfile["node_kind"] as? String == "router-vpn",
                      let mode = profile["multihop_entry_mode"] as? String, torEntryModes.contains(mode),
                      string(predecessorProfile["node_proof_id"]).range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil,
                      let data = predecessorFiles["sing-box.json"],
                      !data.isEmpty, data.count <= 4 * 1024 * 1024, let source = String(data: data, encoding: .utf8),
                      let graph = try JSONSerialization.jsonObject(with: data) as? [String: Any],
                      let inbounds = graph["inbounds"] as? [[String: Any]], inbounds.count == 1, inbounds[0]["type"] as? String == "tun",
                      let route = graph["route"] as? [String: Any], let final = route["final"] as? String, !final.isEmpty else {
                    throw error("The Router VPN entry requires its complete captured native graph.")
                }
                // The shared compiler imports and namespaces the whole graph.
                // Do not extract one endpoint and discard its Start Layer,
                // PQ handshake, transport lanes, DNS bootstrap or services.
                predecessorConfig = source
            }
            entryTag = tag
        } else if !predecessorFiles.isEmpty { throw error("External startup cannot discard an unowned predecessor graph.") }
        if ["wireguard", "amneziawg", "openvpn"].contains(protocolName) { endpoints.append(custom) } else { outbounds.append(custom) }

        let mtu = externalMTU(external: external, protocolName: protocolName)
        let tun: [String: Any] = [
            "type": "tun", "tag": "tun-in",
            "address": ["172.29.94.1/30", "fd29:94::1/126"],
            "mtu": mtu, "auto_route": true, "strict_route": true, "stack": "system"
        ]
        let route: [String: Any] = [
            "rules": [["protocol": "dns", "action": "hijack-dns"]],
            "final": "custom-exit", "auto_detect_interface": true
        ]
        let config: [String: Any] = [
            "log": ["level": "warn", "timestamp": true],
            "inbounds": [tun], "endpoints": endpoints, "outbounds": outbounds, "route": route
        ]
        let data = try JSONSerialization.data(withJSONObject: config, options: [.prettyPrinted, .sortedKeys])
        guard !data.isEmpty, data.count <= 4 * 1024 * 1024 else { throw error("iOS external Libbox config exceeds safety limit.") }
        let policy = try RouterVPNExternalPolicy.compile(config: String(decoding: data, as: UTF8.self), profile: profile,
                                                        protocolName: protocolName, expectedPublicIP: expected,
                                                        entry: predecessorProfile, entryTag: entryTag, predecessorConfig: predecessorConfig,
                                                        restoredExecution: restoredExecution)
        var files = predecessorFiles; files["sing-box.json"] = Data(policy.config.utf8)
        return RouterVPNExternalExitRuntime(protocolName: protocolName, expectedPublicIP: expected,
                                            files: files, policy: policy)
    }

    private static func customExit(external: [String: Any], protocolName: String) throws -> [String: Any] {
        switch protocolName {
        case "openvpn":
            guard let ovpn = external["openvpn"] as? [String: Any], let config = ovpn["config"] as? String else { throw error("OpenVPN inline configuration is missing.") }
            // Do not trim secrets or use a separate process/Go runtime. The
            // resulting endpoint still routes only through the owned Libbox TUN.
            var failure: NSError?
            let encoded = LibboxRouterOpenVPNEndpoint(config, ovpn["username"] as? String ?? "", ovpn["password"] as? String ?? "", "custom-exit", "", &failure)
            if let failure { throw failure }
            guard let data = encoded.data(using: .utf8),
                  let endpoint = try JSONSerialization.jsonObject(with: data) as? [String: Any],
                  endpoint["type"] as? String == "openvpn-client", endpoint["system"] as? Bool == false,
                  endpoint["tag"] as? String == "custom-exit", endpoint["detour"] == nil else { throw error("OpenVPN native compiler returned an invalid owned endpoint.") }
            return endpoint
        case "wireguard", "amneziawg":
            guard let wg = external[protocolName] as? [String: Any] else { throw error("External \(protocolName) block is missing.") }
            let endpoint = string(wg["endpoint"])
            let (server, port) = try literalEndpoint(endpoint, defaultPort: 51820)
            let addresses = strings(wg["addresses"]), allowed = strings(wg["allowed_ips"])
            let privateKey = string(wg["private_key"]), publicKey = string(wg["peer_public_key"])
            guard !addresses.isEmpty, !allowed.isEmpty, !privateKey.isEmpty, !publicKey.isEmpty else { throw error("External WireGuard credentials/routes are incomplete.") }
            var peer: [String: Any] = ["address": server, "port": port, "public_key": publicKey, "allowed_ips": allowed]
            let psk = string(wg["preshared_key"]); if !psk.isEmpty { peer["pre_shared_key"] = psk }
            if let keepalive = wg["persistent_keepalive_interval"] { peer["persistent_keepalive_interval"] = keepalive }
            var value: [String: Any] = ["type": protocolName == "amneziawg" ? "routervpn-amneziawg" : "wireguard", "tag": "custom-exit", "address": addresses, "private_key": privateKey, "peers": [peer]]
            let mtu = int(wg["mtu"]); if mtu >= 1280 && mtu <= 9000 { value["mtu"] = mtu }
            if protocolName == "amneziawg" {
                // The shared compiler validates all eleven exact strings,
                // including header ranges, S4 padding and imported keepalive.
                // Never turn an imported policy into a Fast/Strong preset.
                guard let parameters = wg["parameters"] as? [String: String] else { throw error("External AmneziaWG parameters are missing or not strings.") }
                value["amnezia"] = parameters
                if value["mtu"] == nil { value["mtu"] = 1280 }
            }
            return value
        case "socks5":
            guard let socks = external["socks5"] as? [String: Any] else { throw error("External SOCKS5 block is missing.") }
            let server = try literalServer(string(socks["host"]), label: "SOCKS5 server"), port = try port(socks["port"])
            var value: [String: Any] = ["type": "socks", "tag": "custom-exit", "server": server, "server_port": port, "version": "5"]
            let user = socks["username"] as? String ?? "", pass = socks["password"] as? String ?? ""
            guard user.isEmpty == pass.isEmpty else { throw error("External SOCKS5 username/password must be supplied together.") }
            if !user.isEmpty { value["username"] = user; value["password"] = pass }
            return value
        case "http-connect", "https-connect":
            let secure = protocolName == "https-connect"
            let key = secure ? "https_connect" : "http_connect"
            guard let proxy = external[key] as? [String: Any] else { throw error("External \(secure ? "HTTPS" : "HTTP") CONNECT block is missing.") }
            let server = try literalServer(string(proxy["host"]), label: "\(secure ? "HTTPS" : "HTTP") CONNECT server"), p = try port(proxy["port"])
            let user = proxy["username"] as? String ?? "", pass = proxy["password"] as? String ?? ""
            guard user.isEmpty == pass.isEmpty else { throw error("External CONNECT username/password must be supplied together.") }
            var value: [String: Any] = ["type": "http", "tag": "custom-exit", "server": server, "server_port": p]
            if !user.isEmpty { value["username"] = user; value["password"] = pass }
            let sni = string(proxy["tls_server_name"])
            if secure {
                guard safeHostname(sni) else { throw error("External HTTPS CONNECT requires a safe TLS server name for certificate verification.") }
                value["tls"] = ["enabled": true, "server_name": sni]
            } else if !sni.isEmpty {
                throw error("Plain HTTP CONNECT cannot carry TLS metadata; use HTTPS CONNECT instead.")
            }
            return value
        case "shadowsocks":
            guard let ss = external["shadowsocks"] as? [String: Any] else { throw error("External Shadowsocks block is missing.") }
            let server = try literalServer(string(ss["server"]), label: "Shadowsocks server"), p = try port(ss["port"])
            let method = string(ss["method"]).lowercased(), password = ss["password"] as? String ?? ""
            let allowed = ["2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305", "aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305"]
            guard allowed.contains(method), !password.isEmpty else { throw error("External Shadowsocks method/password is invalid.") }
            return ["type": "shadowsocks", "tag": "custom-exit", "server": server, "server_port": p, "method": method, "password": password]
        case "hysteria2":
            guard let hy = external["hysteria2"] as? [String: Any] else { throw error("External Hysteria2 block is missing.") }
            let server = try literalServer(string(hy["server"]), label: "Hysteria2 server"), p = try port(hy["port"])
            let password = hy["password"] as? String ?? "", sni = string(hy["tls_server_name"])
            guard !password.isEmpty, safeHostname(sni) else { throw error("External Hysteria2 password/TLS server name is invalid.") }
            return ["type": "hysteria2", "tag": "custom-exit", "server": server, "server_port": p, "password": password, "tls": ["enabled": true, "server_name": sni]]
        default: throw error("Unsupported external protocol.")
        }
    }

    private static func externalMTU(external: [String: Any], protocolName: String) -> Int {
        if ["wireguard", "amneziawg"].contains(protocolName), let wg = external[protocolName] as? [String: Any] { let value = int(wg["mtu"]); if value >= 1280 && value <= 9000 { return value } }
        return 1280
    }
    private static func literalEndpoint(_ value: String, defaultPort: Int) throws -> (String, Int) {
        let text = value.trimmingCharacters(in: .whitespacesAndNewlines)
        if text.hasPrefix("[") , let close = text.firstIndex(of: "]") {
            let host = String(text[text.index(after: text.startIndex)..<close]); let rest = text[text.index(after: close)...]
            let p = rest.hasPrefix(":") ? Int(rest.dropFirst()) ?? 0 : defaultPort
            return (try literalServer(host, label: "WireGuard server"), try port(p))
        }
        if let colon = text.lastIndex(of: ":"), !text[..<colon].contains(":") {
            let host = String(text[..<colon]), p = Int(text[text.index(after: colon)...]) ?? 0
            return (try literalServer(host, label: "WireGuard server"), try port(p))
        }
        return (try literalServer(text, label: "WireGuard server"), defaultPort)
    }
    private static func literalServer(_ value: String, label: String) throws -> String {
        let text = value.trimmingCharacters(in: CharacterSet(charactersIn: " []\t\r\n"))
        guard IPv4Address(text) != nil || IPv6Address(text) != nil else { throw error("\(label) must be a literal IP so setup cannot leak pre-tunnel DNS.") }
        return text
    }
    private static func publicLiteralIP(_ value: String, label: String) throws -> String {
        let text = try literalServer(value, label: label)
        if let ip = IPv4Address(text) { let b = [UInt8](ip.rawValue); guard b.count == 4 else { throw error("Invalid \(label).") }; let privateIP = b[0] == 10 || b[0] == 127 || (b[0] == 172 && b[1] >= 16 && b[1] <= 31) || (b[0] == 192 && b[1] == 168) || (b[0] == 169 && b[1] == 254) || b[0] >= 224 || b == [0,0,0,0]; guard !privateIP else { throw error("\(label) must be public.") }; return text }
        if let ip = IPv6Address(text) { let b = [UInt8](ip.rawValue); guard b.count == 16 else { throw error("Invalid \(label).") }; let allZero = b.allSatisfy { $0 == 0 }, loopback = b.dropLast().allSatisfy { $0 == 0 } && b.last == 1, ula = (b[0] & 0xfe) == 0xfc, linkLocal = b[0] == 0xfe && (b[1] & 0xc0) == 0x80, multicast = b[0] == 0xff; guard !(allZero || loopback || ula || linkLocal || multicast) else { throw error("\(label) must be public.") }; return text }
        throw error("Invalid \(label).")
    }
    private static func port(_ value: Any?) throws -> Int { let p = int(value); guard p >= 1 && p <= 65535 else { throw error("External server port is invalid.") }; return p }
    private static func int(_ value: Any?) -> Int { if let i = value as? Int { return i }; if let n = value as? NSNumber { return n.intValue }; if let s = value as? String { return Int(s) ?? 0 }; return 0 }
    private static func string(_ value: Any?) -> String { (value as? String ?? "").trimmingCharacters(in: .whitespacesAndNewlines) }
    private static func strings(_ value: Any?) -> [String] { (value as? [String] ?? []).map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }.filter { !$0.isEmpty } }
    private static func safeHostname(_ value: String) -> Bool { !value.isEmpty && value.count <= 253 && value.range(of: "^[A-Za-z0-9.-]+$", options: .regularExpression) != nil && !value.hasPrefix(".") && !value.hasSuffix(".") }
    private static func error(_ message: String) -> NSError { NSError(domain: "RouterVPN.ExternalExit", code: 1, userInfo: [NSLocalizedDescriptionKey: message]) }
}
