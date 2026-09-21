import Foundation
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

/// One Libbox TUN, not two competing system VPNs. The exit's transport sockets
/// are dialled by the entry WireGuard endpoint. Neither a saved graph nor a
/// successful engine start is connection proof; PacketTunnel proves both nodes.
enum RouterVPNMultihopGraph {
    static let entryProofPort = 1098
    static let entryTag = "routervpn-hop-entry"
    static let entryProofTag = "routervpn-hop-entry-proof"
    static let entryPrivateTag = "routervpn-hop-entry-private"
    static let supportedExitModes = ["shadowsocks", "hysteria2"]
    private static let maxBytes = 4 * 1024 * 1024

    static func build(entryEndpoint: [String: Any], entryProfile: [String: Any],
                      exitProfile: [String: Any], exitMode: String,
                      files: [String: Data]) throws -> [String: Data] {
        guard supportedExitModes.contains(exitMode),
              let entryID = entryProfile["id"] as? String, !entryID.isEmpty,
              let exitID = exitProfile["id"] as? String, !exitID.isEmpty,
              entryID != exitID,
              entryProfile["node_kind"] as? String ?? "router-vpn" == "router-vpn",
              exitProfile["node_kind"] as? String ?? "router-vpn" == "router-vpn",
              let entryProof = entryProfile["node_proof_id"] as? String,
              let exitProof = exitProfile["node_proof_id"] as? String,
              fullMatch(entryProof, "[0-9a-f]{64}"), fullMatch(exitProof, "[0-9a-f]{64}"),
              entryProof != exitProof else {
            throw issue("Multihop requires two different paired Router VPN nodes and a supported exit transport.")
        }
        // No saved setting is silently dropped when building the smaller graph.
        for profile in [entryProfile, exitProfile] {
            guard profile["home_lan_access"] as? Bool != false,
                  profile["daita_enabled"] as? Bool != true,
                  profile["jumbo_tun"] as? Bool != true else {
                throw issue("This graph does not yet own LAN-Off filtering, DAITA padding or Jumbo TUN. Those requested policies cannot be silently ignored.")
            }
            let start = (profile["start_layer"] as? String ?? "off").lowercased()
            guard ["", "off", "none", "disabled"].contains(start) else {
                throw issue("This multihop graph does not yet compose an additional Start Layer; turn it off before selecting this graph.")
            }
        }
        var entry = entryEndpoint
        let allowedEntry: Set<String> = ["type", "tag", "address", "private_key", "peers", "mtu", "system"]
        guard Set(entry.keys).isSubset(of: allowedEntry), entry["type"] as? String == "wireguard",
              entry["system"] == nil || entry["system"] as? Bool == false,
              let peers = entry["peers"] as? [[String: Any]], peers.count == 1,
              let peer = peers.first, let host = peer["address"] as? String, literalIP(host),
              let port = try integer(peer["port"]), (1...65535).contains(port),
              let addresses = entry["address"] as? [String], !addresses.isEmpty,
              let allowed = peer["allowed_ips"] as? [String],
              allowed.contains("0.0.0.0/0"), allowed.contains("::/0") else {
            throw issue("The entry needs a literal-IP, dual-stack full-route WireGuard profile. A split or hostname-only profile cannot certify this graph.")
        }
        entry["tag"] = entryTag
        entry["system"] = false
        let privateHost = entryProfile["socks_host"] as? String ?? ""
        guard privateIP(privateHost), let privatePort = try integer(entryProfile["socks_port"]),
              (1...65535).contains(privatePort) else {
            throw issue("Entry-node proof requires the paired node's literal private SOCKS endpoint.")
        }
        var privateProxy: [String: Any] = ["type": "socks", "tag": entryPrivateTag,
            "server": privateHost, "server_port": privatePort, "version": "5", "detour": entryTag]
        let username = entryProfile["socks_username"] as? String ?? ""
        let password = entryProfile["socks_password"] as? String ?? ""
        guard username.isEmpty == password.isEmpty, username.utf8.count <= 255, password.utf8.count <= 255 else {
            throw issue("Entry private SOCKS credentials are incomplete or oversized.")
        }
        if !username.isEmpty { privateProxy["username"] = username; privateProxy["password"] = password }

        let helpers: Set<String> = ["wg.conf", "awg.conf", "wg-socks.conf", "awg-socks.conf",
            "xray.json", "outer-xray.json", "sslocal.json", "middle-sing-box.json", "chain.env"]
        guard helpers.isDisjoint(with: files.keys), let data = files["sing-box.json"],
              !data.isEmpty, data.count <= maxBytes,
              let original = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              (original["endpoints"] as? [Any] ?? []).isEmpty,
              let inbounds = original["inbounds"] as? [[String: Any]], inbounds.count == 1,
              var tun = inbounds.first, tun["type"] as? String == "tun", tun["auto_route"] as? Bool == true,
              let route = original["route"] as? [String: Any], route["final"] as? String == "proxy",
              let outbounds = original["outbounds"] as? [[String: Any]] else {
            throw issue("The exit must contain one self-contained full-device Shadowsocks/Hysteria2 profile.")
        }
        // Only the generated full-device policy is transformed. A saved split
        // route, bypass or DNS rule must never disappear as a side effect.
        let rules = route["rules"] as? [[String: Any]] ?? []
        guard rules.allSatisfy({ Set($0.keys).isSubset(of: ["protocol", "action"]) &&
                  $0["protocol"] as? String == "dns" && $0["action"] as? String == "hijack-dns" }),
              route["rule_set"] == nil,
              tun["route_address"] == nil, tun["route_exclude_address"] == nil,
              tun["route_address_set"] == nil, tun["route_exclude_address_set"] == nil else {
            throw issue("Multihop cannot silently replace saved split/bypass routing policy.")
        }
        let proxies = outbounds.filter { $0["tag"] as? String == "proxy" }
        guard proxies.count == 1, var proxy = proxies.first,
              proxy["type"] as? String == exitMode,
              let server = proxy["server"] as? String, literalIP(server),
              let serverPort = try integer(proxy["server_port"]), (1...65535).contains(serverPort),
              outbounds.allSatisfy({ $0["tag"] as? String == "proxy" ||
                  (["direct", "block"].contains($0["type"] as? String ?? "")) }) else {
            throw issue("Exit transport must match its profile and use a literal endpoint; no unowned mixed helper graph is accepted.")
        }
        for key in ["detour", "bind_interface", "inet4_bind_address", "inet6_bind_address", "routing_mark", "network_strategy", "domain_resolver"] {
            guard proxy[key] == nil else { throw issue("Exit profile already owns dial policy; refusing to replace a pre-existing route.") }
        }
        guard let secret = proxy["password"] as? String, !secret.isEmpty else { throw issue("Exit transport has no credential.") }
        if exitMode == "hysteria2" {
            guard let tls = proxy["tls"] as? [String: Any], tls["enabled"] as? Bool == true,
                  tls["insecure"] == nil || tls["insecure"] as? Bool == false else {
                throw issue("Hysteria2 multihop requires verified TLS, not an insecure certificate bypass.")
            }
        }
        // Preserve the encrypted exit transport, TLS pin and obfuscation. Only
        // replace its upstream dialer; never fall back to a direct exit socket.
        proxy["detour"] = entryTag
        tun.removeValue(forKey: "interface_name")
        tun.removeValue(forKey: "route_exclude_address")
        tun.removeValue(forKey: "route_address")
        tun["strict_route"] = true
        tun["stack"] = "system"
        tun["address"] = ["172.29.94.1/30", "fd29:94::1/126"]
        // Initial MTU is conservative; a fixed policy is applied afterward by
        // the shared PacketTunnel MTU helper, not presented as Auto measurement.
        tun["mtu"] = 1280
        guard let dns = original["dns"] as? [String: Any], let dnsTag = dns["final"] as? String,
              let servers = dns["servers"] as? [[String: Any]],
              let selectedDNS = servers.first(where: { $0["tag"] as? String == dnsTag }),
              let dnsHost = selectedDNS["server"] as? String, literalIP(dnsHost),
              ["udp", "tcp", "tls", "https", "h3"].contains(selectedDNS["type"] as? String ?? "") else {
            throw issue("Multihop DNS needs a saved literal resolver that can be sent through the exit without bootstrap fallback.")
        }
        guard (dns["rules"] as? [Any] ?? []).isEmpty else {
            throw issue("Multihop cannot silently discard custom DNS routing rules.")
        }
        var finalDNS = selectedDNS
        finalDNS["detour"] = "proxy"
        finalDNS.removeValue(forKey: "domain_resolver")
        var dnsPolicy = dns
        dnsPolicy["servers"] = [finalDNS]
        var routeRules: [[String: Any]] = [
            ["inbound": [entryProofTag], "action": "route", "outbound": entryPrivateTag],
            ["protocol": "dns", "action": "hijack-dns"]
        ]
        if entryProfile["ipv6_mode"] as? String == "off" || exitProfile["ipv6_mode"] as? String == "off" {
            // Reject client IPv6 inside the owned TUN, not by omitting the v6
            // default route (which would leak it to the physical interface).
            routeRules.append(["ip_version": 6, "action": "reject"])
            dnsPolicy["strategy"] = "ipv4_only"
        }
        let config: [String: Any] = [
            "log": ["level": "warn"],
            "dns": dnsPolicy,
            "endpoints": [entry], "outbounds": [proxy, privateProxy],
            "inbounds": [tun, ["type": "mixed", "tag": entryProofTag,
                "listen": "127.0.0.1", "listen_port": entryProofPort]],
            "route": ["auto_detect_interface": true, "final": "proxy", "rules": routeRules]
        ]
        let encoded = try JSONSerialization.data(withJSONObject: config, options: [.sortedKeys])
        guard encoded.count <= maxBytes else { throw issue("Composed multihop configuration exceeds the safety limit.") }
        var result = files
        result["sing-box.json"] = encoded
        return result
    }

    static func privateIP(_ host: String) -> Bool {
        guard literalIP(host) else { return false }
        var v4 = in_addr(), v6 = in6_addr()
        if inet_pton(AF_INET, host, &v4) == 1 {
            return withUnsafeBytes(of: v4) { $0[0] == 10 || ($0[0] == 172 && (16...31).contains($0[1])) || ($0[0] == 192 && $0[1] == 168) }
        }
        if inet_pton(AF_INET6, host, &v6) == 1 { return withUnsafeBytes(of: v6) { $0[0] & 0xfe == 0xfc } }
        return false
    }
    static func literalIP(_ host: String) -> Bool {
        guard !host.isEmpty, !host.contains("%"), !host.utf8.contains(0),
              host.unicodeScalars.allSatisfy({ $0.isASCII }) else { return false }
        var v4 = in_addr(), v6 = in6_addr()
        return inet_pton(AF_INET, host, &v4) == 1 || inet_pton(AF_INET6, host, &v6) == 1
    }
    private static func integer(_ value: Any?) throws -> Int? {
        guard let value else { return nil }
        struct Number: Decodable { let value: Int }
        return try JSONDecoder().decode(Number.self, from: JSONSerialization.data(withJSONObject: ["value": value])).value
    }
    private static func fullMatch(_ value: String, _ pattern: String) -> Bool {
        value.range(of: "\\A(?:" + pattern + ")\\z", options: .regularExpression) != nil
    }
    static func issue(_ message: String) -> NSError {
        NSError(domain: "RouterVPN.Multihop", code: 1, userInfo: [NSLocalizedDescriptionKey: message])
    }
}
