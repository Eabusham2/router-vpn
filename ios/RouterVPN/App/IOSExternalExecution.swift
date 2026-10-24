import Foundation
import Libbox

/// Pure readiness checks. Passing these checks never means that the entry's
/// private relay registry accepted this node or that a candidate was proved.
enum IOSExternalExecution {
    static func validateImported(_ bundle: ClientBundle) throws {
        for profile in bundle.routerProfiles {
            guard let external = profile.external else { continue }
            guard profile.normalizedNodeKind == "external", external.matchesStartLayer(profile.startLayer) else { throw issue() }
            if external.startLayer != nil || external.serverPeer != nil { try validateLayerDraft(profile) }
            guard let probe = external.responseProbe else { continue }
            guard let host = external.serverExecutionHost else { throw issue() }
            try validate(probe, host: host)
        }
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
        guard let external = profile.external, let host = external.serverExecutionHost,
              external.matchesStartLayer(profile.startLayer) else { throw issue() }
        var exit: [String: Any] = ["tag": "custom-exit", "server": host]
        let packet = ExternalNodeConfig.packetProtocols.contains(external.protocolName)
        switch external.protocolName {
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
              let host = external.serverExecutionHost, external.authenticatedServerExecution, let probe = external.responseProbe,
              external.matchesStartLayer(exit.startLayer) else { throw issue() }
        try validate(probe, host: host)
        if external.serverPeer != nil { try validateLayerDraft(exit) }
    }

    static func require(selection: String, entry: RouterProfile, exit: RouterProfile) throws {
        guard ["local", "server", "auto"].contains(selection) else { throw issue() }
        if selection != "local" { try validatePair(entry: entry, exit: exit) }
    }

    static func issue() -> NSError {
        NSError(domain: "RouterVPN.ExternalExecution", code: 1,
            userInfo: [NSLocalizedDescriptionKey: "Server and Compare require a paired Router VPN entry and an authenticated external exit with an HTTPS response URL on its exact server IP. WireGuard and AmneziaWG also require the public descriptor of a separately provisioned server peer, with distinct client identity and assigned addresses. Configure this exit in the entry's private relay registry before connecting."])
    }
}
