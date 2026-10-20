import Foundation
import Network

/// Settings validation only. The captured native compiler and owned tunnel
/// prove the selected resolver again before connection completion.
enum IOSExternalDNSPolicy {
    static let protocols: Set<String> = ["wireguard", "socks5", "http-connect", "https-connect", "shadowsocks", "hysteria2", "openvpn"]

    static func validate(_ profile: RouterProfile, entry: RouterProfile? = nil) throws {
        guard profile.normalizedNodeKind == "external", protocols.contains(profile.external?.protocolName ?? "") else {
            throw issue("Select an ordinary external node for this DNS policy.")
        }
        let mode = profile.dnsMode ?? "rescue"
        var host = profile.dnsHost ?? "", type = profile.dnsProtocol ?? "", port = profile.dnsPort ?? 0
        var name = profile.dnsServerName ?? "", path = profile.dnsPath ?? ""
        var detour = "custom-exit"
        var udp = !["http-connect", "https-connect"].contains(profile.external?.protocolName ?? "")
        switch mode {
        case "rescue", "":
            host = "1.1.1.1"; type = "https"; port = 443; name = "cloudflare-dns.com"; path = "/dns-query"
        case "home":
            guard profile.multihopEnabled == true, let entry, entry.normalizedNodeKind == "router-vpn",
                  entry.id == profile.multihopEntryID,
                  entry.nodeProofID?.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil,
                  !entry.routerAPI.isEmpty, !entry.apiToken.isEmpty else { throw issue("Home AdGuard requires the selected paired Router VPN entry.") }
            let addresses = [entry.adGuardIPv4, entry.adGuardIPv6].filter { !$0.isEmpty }
            guard !addresses.isEmpty, addresses.allSatisfy(privateLiteral) else { throw issue("The paired entry must supply its private AdGuard address.") }
            if host.isEmpty { host = addresses[0] }
            guard addresses.contains(host) else { throw issue("The saved Home DNS address belongs to a different entry.") }
            if type.isEmpty { type = "udp" }
            detour = "external-entry"; udp = true
        case "fastest":
            host = profile.fastestDNSHost ?? ""; type = "udp"; port = 53; name = ""; path = ""
            let valid: Bool
            if let results = profile.dnsResults {
                valid = results.contains { $0.address == host && $0.working && ($0.latencyMs ?? 0).isFinite && ($0.latencyMs ?? 0) > 0 }
            } else { valid = (profile.fastestDNSLatencyMs ?? 0).isFinite && (profile.fastestDNSLatencyMs ?? 0) > 0 }
            guard !host.isEmpty, valid else { throw issue("Fastest DNS needs a saved successful resolver measurement.") }
        case "custom": guard !type.isEmpty else { throw issue("Choose the DNS transport.") }
        case "dot": type = "tls"
        case "doh": type = "https"
        case "doh3": type = "h3"
        default: throw issue("Choose a valid DNS policy.")
        }
        type = ["dot": "tls", "doh": "https", "doh3": "h3"][type] ?? type
        if port == 0 { port = type == "tls" ? 853 : (["https", "h3"].contains(type) ? 443 : 53) }
        if ["https", "h3"].contains(type), path.isEmpty { path = "/dns-query" }
        try transport(type: type, host: host, port: port, name: name, path: path, udp: udp)
        if literal(host) {
            guard profile.dnsBootstrap == nil else { throw issue("Remove the hostname lookup resolver when the selected DNS server is already an IP address.") }
        } else {
            guard let bootstrap = profile.dnsBootstrap else { throw issue("Choose an explicit IP resolver to look up the selected DNS hostname through this VPN path.") }
            let server = bootstrap.server
            guard server.tag == "external-dns-bootstrap", server.detour == detour,
                  literal(server.server), bootstrap.query.server == server.tag else { throw issue("The hostname lookup resolver must belong to this captured DNS path.") }
            try transport(type: server.type, host: server.server, port: server.serverPort,
                          name: server.tls?.serverName ?? "", path: server.path ?? "", udp: udp)
            if ["tls", "https", "h3"].contains(server.type) {
                guard server.tls?.enabled == true else { throw issue("Encrypted hostname lookup requires certificate verification.") }
            } else if server.tls != nil || server.path != nil { throw issue("The hostname lookup transport contains unrelated TLS or HTTP settings.") }
            if let strategy = bootstrap.query.strategy {
                guard ["", "prefer_ipv4", "prefer_ipv6", "ipv4_only", "ipv6_only"].contains(strategy) else { throw issue("Invalid hostname lookup address-family selection.") }
            }
            // Preserve every saved query option. Native compilation validates
            // duration/subnet syntax without replacing an imported choice.
            guard (bootstrap.query.timeout?.utf8.count ?? 0) <= 64, (bootstrap.query.clientSubnet?.utf8.count ?? 0) <= 64,
                  try JSONEncoder().encode(bootstrap).count <= 8192 else { throw issue("The hostname lookup configuration is oversized.") }
        }
    }

    static func literal(_ host: String) -> Bool { IPv4Address(host) != nil || IPv6Address(host) != nil }
    static func hostname(_ host: String) -> Bool {
        let labels = host.split(separator: ".", omittingEmptySubsequences: false)
        return host.utf8.count <= 253 && labels.count >= 2 && !host.lowercased().hasSuffix(".localhost") && labels.allSatisfy {
            !$0.isEmpty && $0.utf8.count <= 63 && $0.first != "-" && $0.last != "-" && $0.utf8.allSatisfy { (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) || $0 == 45 }
        }
    }
    private static func usableLiteral(_ host: String) -> Bool {
        if let address = IPv4Address(host) {
            let b = Array(address.rawValue)
            return b.count == 4 && b[0] != 0 && b[0] != 127 && b[0] < 224 && !(b[0] == 169 && b[1] == 254)
        }
        if let address = IPv6Address(host) {
            let b = Array(address.rawValue)
            return b.count == 16 && b[0] != 255 && !(b[0] == 254 && b[1] & 0xc0 == 0x80) &&
                !b.prefix(15).allSatisfy({ $0 == 0 }) && !(b.prefix(10).allSatisfy({ $0 == 0 }) && b[10] == 255 && b[11] == 255)
        }
        return false
    }
    private static func privateLiteral(_ host: String) -> Bool {
        if let address = IPv4Address(host) {
            let b = Array(address.rawValue)
            return b[0] == 10 || (b[0] == 172 && (16...31).contains(b[1])) || (b[0] == 192 && b[1] == 168)
        }
        if let address = IPv6Address(host) { return address.rawValue.first.map { $0 & 0xfe == 0xfc } ?? false }
        return false
    }
    private static func transport(type: String, host: String, port: Int, name: String, path: String, udp: Bool) throws {
        guard ["udp", "tcp", "tls", "https", "h3"].contains(type), (1...65535).contains(port),
              usableLiteral(host) || (!literal(host) && hostname(host)) else { throw issue("The selected resolver transport, host or port is invalid.") }
        guard udp || !["udp", "h3"].contains(type) else { throw issue("This TCP-only external path requires DNS over TCP, TLS or HTTPS.") }
        if ["tls", "https", "h3"].contains(type) {
            guard usableLiteral(name) || (!literal(name) && hostname(name)) else { throw issue("Encrypted DNS requires the selected TLS server name.") }
        }
        if ["https", "h3"].contains(type) {
            guard path.hasPrefix("/"), !path.hasPrefix("//"), path.utf8.count <= 2048,
                  !path.contains("?"), !path.contains("#"), !path.contains("\\"),
                  path.unicodeScalars.allSatisfy({ $0.value >= 0x21 && $0.value != 0x7f }) else { throw issue("The selected DNS HTTP path is invalid.") }
        }
    }
    private static func issue(_ text: String) -> NSError { NSError(domain: "RouterVPN.ExternalDNS", code: 1, userInfo: [NSLocalizedDescriptionKey: text]) }
}
