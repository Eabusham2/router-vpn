import Foundation
import Libbox

/// Pure readiness checks. Passing these checks never means that the entry's
/// private relay registry accepted this node or that a candidate was proved.
enum IOSExternalExecution {
    static func validatePrivateNodeJSON(_ data: Data) throws {
        guard !data.isEmpty, data.count <= 32 * 1024 * 1024,
              let source = String(data: data, encoding: .utf8) else { throw issue() }
        var failure: NSError?
        let valid = LibboxRouterValidatePrivateNodeJSON(source, &failure)
        if let failure { throw failure }
        guard valid else { throw issue() }
    }

    static func validateImported(_ bundle: ClientBundle) throws {
        for profile in bundle.routerProfiles {
            guard let external = profile.external else { continue }
            guard profile.normalizedNodeKind == "external", external.matchesStartLayer(profile.startLayer) else { throw issue() }
            if let probes = external.openVPNResponseProbes {
                guard external.protocolName == "openvpn", let original = external.openVPN,
                      external.responseProbe == nil, external.startLayer == nil else { throw issue() }
                _ = try openVPNResponseProbes(String(decoding: JSONEncoder().encode(probes), as: UTF8.self), profile: original)
            }
            if let layers = external.openVPNStartLayers, let original = external.openVPN {
                _ = try openVPNStartLayers(String(decoding: JSONEncoder().encode(layers), as: UTF8.self), profile: original, probes: external.openVPNResponseProbes, selectedMode: profile.startLayer ?? "off")
            }
            if external.startLayer != nil || external.openVPNStartLayers != nil || external.serverPeer != nil || external.openVPNPairing != nil || external.openVPNResponseProbes != nil || (external.protocolName == "openvpn" && external.responseProbe != nil) { try validateLayerDraft(profile) }
            guard let probe = external.responseProbe else { continue }
            let host = try host(external)
            try validate(probe, host: host)
        }
    }

    static func openVPNEndpoint(_ external: ExternalNodeConfig) throws -> [String: Any] {
        guard external.protocolName == "openvpn", let profile = external.openVPN,
              LibboxVersion().trimmingCharacters(in: .whitespacesAndNewlines) == "1.14.1" else { throw issue() }
        var failure: NSError?
        let source = LibboxRouterOpenVPNEndpoint(profile.config, profile.username ?? "", profile.password ?? "", "custom-exit", "", &failure)
        if let failure { throw failure }
        guard let result = try JSONSerialization.jsonObject(with: Data(source.utf8)) as? [String: Any],
              result["type"] as? String == "openvpn-client", result["system"] as? Bool == false,
              result["tag"] as? String == "custom-exit", result["detour"] == nil else { throw issue() }
        return result
    }

    static func host(_ external: ExternalNodeConfig) throws -> String {
        if external.protocolName == "openvpn" {
            let endpoint = try openVPNEndpoint(external)
            let primary = (endpoint["servers"] as? [[String: Any]])?.first ?? endpoint
            guard let host = primary["server"] as? String, !host.isEmpty else { throw issue() }
            return host
        }
        guard let host = external.serverExecutionHost else { throw issue() }
        return host
    }

    static func openVPNPairing(_ text: String, profile: ExternalOpenVPNConfig) throws -> ExternalOpenVPNPairing? {
        if text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty { return nil }
        guard text.utf8.count <= 512 * 1024 else { throw issue() }
        let source = String(decoding: try JSONEncoder().encode(profile), as: UTF8.self)
        var failure: NSError?
        let valid = LibboxRouterValidateExternalOpenVPNPairing(source, text, &failure)
        if let failure { throw failure }
        guard valid else { throw issue() }
        return try JSONDecoder().decode(ExternalOpenVPNPairing.self, from: Data(text.utf8))
    }

    static func openVPNPairingText(_ pairing: ExternalOpenVPNPairing?) -> String {
        guard let pairing else { return "" }
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .prettyPrinted]
        return (try? String(decoding: encoder.encode(pairing), as: UTF8.self)) ?? ""
    }

    static func openVPNResponseProbes(_ text: String, profile: ExternalOpenVPNConfig) throws -> [String: ExternalResponseProbe]? {
        if text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty { return nil }
        guard text.utf8.count <= 40 * 1024 else { throw issue() }
        let source = String(decoding: try JSONEncoder().encode(profile), as: UTF8.self)
        var failure: NSError?
        let valid = LibboxRouterValidateExternalOpenVPNResponseProbes(source, text, &failure)
        if let failure { throw failure }
        guard valid else { throw issue() }
        return try JSONDecoder().decode([String: ExternalResponseProbe].self, from: Data(text.utf8))
    }

    static func openVPNResponseProbesText(_ probes: [String: ExternalResponseProbe]?) -> String {
        guard let probes else { return "" }
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .prettyPrinted]
        return (try? String(decoding: encoder.encode(probes), as: UTF8.self)) ?? ""
    }

    static func openVPNStartLayers(_ text: String, profile: ExternalOpenVPNConfig,
                                   probes: [String: ExternalResponseProbe]?, selectedMode: String) throws -> [String: ExternalStartLayer]? {
        if text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty { return nil }
        guard text.utf8.count <= 128 * 1024, let probes else { throw issue() }
        let source = String(decoding: try JSONEncoder().encode(profile), as: UTF8.self)
        let responses = String(decoding: try JSONEncoder().encode(probes), as: UTF8.self)
        var failure: NSError?
        let valid = LibboxRouterValidateExternalOpenVPNStartLayers(source, responses, text, selectedMode, &failure)
        if let failure { throw failure }
        guard valid else { throw issue() }
        return try JSONDecoder().decode([String: ExternalStartLayer].self, from: Data(text.utf8))
    }

    static func openVPNStartLayersText(_ layers: [String: ExternalStartLayer]?) -> String {
        guard let layers else { return "" }
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .prettyPrinted]
        return (try? String(decoding: encoder.encode(layers), as: UTF8.self)) ?? ""
    }

    static func responseProbe(host: String, url: String, serverName: String) throws -> ExternalResponseProbe? {
        if url.isEmpty && serverName.isEmpty { return nil }
        let probe = ExternalResponseProbe(url: url, serverName: serverName.isEmpty ? nil : serverName)
        try validate(probe, host: host)
        return probe
    }

    static func serverPeer(_ text: String) throws -> ExternalServerPeer? {
        guard text.utf8.count <= 4096 else { throw issue() }
        if text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty { return nil }
        return try JSONDecoder().decode(ExternalServerPeer.self, from: Data(text.utf8))
    }

    static func serverPeerText(_ peer: ExternalServerPeer?) -> String {
        guard let peer else { return "" }
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .prettyPrinted]
        return (try? String(decoding: encoder.encode(peer), as: UTF8.self)) ?? ""
    }

    static func validate(_ probe: ExternalResponseProbe, host: String) throws {
        let data = try JSONEncoder().encode(probe)
        var failure: NSError?
        let valid = LibboxRouterValidateExternalResponseProbe(host, String(decoding: data, as: UTF8.self), &failure)
        if let failure { throw failure }
        guard valid else { throw issue() }
    }

    /// Saving an imported wrapper validates the real compiler contract while
    /// leaving Home DNS unresolved until its selected Router entry is captured.
    static func validateLayerDraft(_ profile: RouterProfile) throws {
        guard let external = profile.external,
              external.matchesStartLayer(profile.startLayer) else { throw issue() }
        let host = try host(external)
        var exit: [String: Any] = ["tag": "custom-exit", "server": host]
        let packet = ExternalNodeConfig.packetProtocols.contains(external.protocolName) || external.protocolName == "openvpn"
        switch external.protocolName {
        case "openvpn":
            exit = try openVPNEndpoint(external)
            if let pairing = external.openVPNPairing, let original = external.openVPN {
                _ = try openVPNPairing(String(decoding: JSONEncoder().encode(pairing), as: UTF8.self), profile: original)
            }
        case "wireguard", "amneziawg":
            guard let value = external.packetConfiguration, let endpoint = external.packetEndpoint else { throw issue() }
            var peer: [String: Any] = ["address": endpoint.host, "port": endpoint.port,
                "public_key": value.peerPublicKey, "allowed_ips": value.allowedIPs]
            if let key = value.presharedKey, !key.isEmpty { peer["pre_shared_key"] = key }
            if let keepalive = value.persistentKeepaliveInterval { peer["persistent_keepalive_interval"] = keepalive }
            exit = ["type": external.protocolName == "amneziawg" ? "routervpn-amneziawg" : "wireguard",
                "tag": "custom-exit", "address": value.addresses, "private_key": value.privateKey, "peers": [peer]]
            if let mtu = value.mtu { exit["mtu"] = mtu }
            if external.protocolName == "amneziawg" {
                guard let parameters = external.amneziaWG?.parameters else { throw issue() }
                exit["amnezia"] = parameters
                if exit["mtu"] == nil { exit["mtu"] = 1280 }
            }
        case "shadowsocks":
            guard let value = external.shadowsocks else { throw issue() }
            exit.merge(["type": "shadowsocks", "server_port": value.port, "method": value.method, "password": value.password]) { _, new in new }
        case "hysteria2":
            guard let value = external.hysteria2 else { throw issue() }
            exit.merge(["type": "hysteria2", "server_port": value.port, "password": value.password,
                "tls": ["enabled": true, "server_name": value.tlsServerName]]) { _, new in new }
        case "socks5":
            guard let value = external.socks5 else { throw issue() }
            exit.merge(["type": "socks", "version": "5", "server_port": value.port]) { _, new in new }
            if let user = value.username, !user.isEmpty { exit["username"] = user; exit["password"] = value.password ?? "" }
        case "http-connect", "https-connect":
            guard let value = external.protocolName == "http-connect" ? external.httpConnect : external.httpsConnect else { throw issue() }
            exit.merge(["type": "http", "server_port": value.port]) { _, new in new }
            if let user = value.username, !user.isEmpty { exit["username"] = user; exit["password"] = value.password ?? "" }
            if external.protocolName == "https-connect" { exit["tls"] = ["enabled": true, "server_name": value.tlsServerName ?? ""] }
        default: throw issue()
        }
        let native: [String: Any] = ["inbounds": [["type": "tun", "tag": "tun-in", "address": ["172.29.94.1/30", "fd29:94::1/126"],
            "mtu": 1280, "auto_route": true, "strict_route": true, "stack": "system"]], "endpoints": packet ? [exit] : [], "outbounds": packet ? [] : [exit],
            "route": ["final": "custom-exit", "auto_detect_interface": true]]
        let frozen = try JSONSerialization.jsonObject(with: JSONEncoder().encode(profile))
        let selected: [String: Any] = ["schema": 1, "exit_id": profile.id, "protocol": external.protocolName,
            "expected_public_ip": external.expectedPublicIP, "profile": frozen]
        let source = String(decoding: try JSONSerialization.data(withJSONObject: native), as: UTF8.self)
        let capture = String(decoding: try JSONSerialization.data(withJSONObject: selected), as: UTF8.self)
        var failure: NSError?
        let valid = LibboxRouterValidateExternalTransport(source, capture, &failure)
        if let failure { throw failure }
        guard valid else { throw issue() }
    }

    static func eligible(entry: RouterProfile, exit: RouterProfile) -> Bool {
        do { try validatePair(entry: entry, exit: exit); return true }
        catch { return false }
    }

    private static func validatePair(entry: RouterProfile, exit: RouterProfile) throws {
        guard entry.id != exit.id, entry.normalizedNodeKind == "router-vpn",
              entry.nodeProofID?.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil,
              !entry.routerAPI.isEmpty, !entry.apiToken.isEmpty,
              exit.normalizedNodeKind == "external", let external = exit.external,
              external.authenticatedServerExecution,
              external.matchesStartLayer(exit.startLayer) else { throw issue() }
        if let probes = external.openVPNResponseProbes {
            guard external.protocolName == "openvpn", let original = external.openVPN,
                  external.responseProbe == nil, external.startLayer == nil else { throw issue() }
            _ = try openVPNResponseProbes(String(decoding: JSONEncoder().encode(probes), as: UTF8.self), profile: original)
        } else {
            guard let probe = external.responseProbe else { throw issue() }
            try validate(probe, host: host(external))
        }
        if external.serverPeer != nil || external.openVPNPairing != nil { try validateLayerDraft(exit) }
    }

    static func require(selection: String, entry: RouterProfile, exit: RouterProfile) throws {
        guard ["local", "server", "auto"].contains(selection) else { throw issue() }
        if selection != "local" { try validatePair(entry: entry, exit: exit) }
    }

    static func issue() -> NSError {
        NSError(domain: "RouterVPN.ExternalExecution", code: 1,
            userInfo: [NSLocalizedDescriptionKey: "Server and Compare require a paired Router VPN entry and an authenticated external exit with an HTTPS response URL on its exact server IP. WireGuard and AmneziaWG require a separately provisioned server peer. OpenVPN requires private pairing with independent provider and authentication identities; different fallback hosts require a response URL for every host. Selecting an exit Start Layer also requires matching private layer settings for every host. Configure this exit in the entry's private relay registry before connecting."])
    }
}
