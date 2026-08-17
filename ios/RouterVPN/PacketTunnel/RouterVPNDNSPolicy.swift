import Foundation
import Network

struct RouterVPNResolvedDNSPolicy {
    let mode: String
    let type: String
    let host: String
    let port: Int
    let serverName: String
    let path: String

    var wireGuardCompatible: Bool {
        type == "udp" && (IPv4Address(host) != nil || IPv6Address(host) != nil)
    }
}

enum RouterVPNDNSPolicy {
    static func resolve(profile: [String: Any]) throws -> RouterVPNResolvedDNSPolicy? {
        let rawMode = string(profile, "dns_mode").lowercased()
        guard !rawMode.isEmpty else { return nil } // Old bundles preserve their embedded engine DNS.

        let mode = rawMode
        var type = "udp"
        var host = ""
        var port = 53
        var serverName = string(profile, "dns_server_name")
        var path = string(profile, "dns_path")

        switch mode {
        case "home":
            host = firstNonEmpty(string(profile, "adguard_ipv4"), string(profile, "adguard_ipv6"))
        case "fastest":
            host = fastestHost(profile)
            guard !host.isEmpty else { throw error("Fastest DNS is selected but this node has no measured working DNS result.") }
        case "custom":
            host = string(profile, "dns_host")
            type = string(profile, "dns_protocol").lowercased()
            if type.isEmpty { type = "udp" }
            guard ["udp", "tcp"].contains(type) else { throw error("Custom DNS on iOS accepts only explicit UDP or TCP transport.") }
            port = integer(profile, "dns_port") ?? 53
        case "dot":
            type = "tls"; host = string(profile, "dns_host"); port = integer(profile, "dns_port") ?? 853
        case "doh":
            type = "https"; host = string(profile, "dns_host"); port = integer(profile, "dns_port") ?? 443
            if path.isEmpty { path = "/dns-query" }
        case "doh3":
            type = "h3"; host = string(profile, "dns_host"); port = integer(profile, "dns_port") ?? 443
            if path.isEmpty { path = "/dns-query" }
        case "rescue":
            host = fastestHost(profile)
            if host.isEmpty { host = "1.1.1.1" }
        default:
            throw error("Unsupported iOS DNS policy \(mode).")
        }

        host = host.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !host.isEmpty else { throw error("DNS policy \(mode) has no resolver host.") }
        guard (1...65535).contains(port) else { throw error("DNS policy \(mode) has an invalid resolver port.") }

        if ["tls", "https", "h3"].contains(type) {
            if serverName.isEmpty, IPv4Address(host) == nil, IPv6Address(host) == nil { serverName = host }
            guard !serverName.isEmpty else {
                throw error("Encrypted DNS to an IP address requires a TLS server name; refusing an unverifiable encrypted resolver.")
            }
        }

        return RouterVPNResolvedDNSPolicy(mode: mode, type: type, host: host, port: port, serverName: serverName, path: path)
    }

    static func applyToWireGuard(_ text: String, profile: [String: Any]) throws -> String {
        guard let policy = try resolve(profile: profile) else { return text }
        guard policy.wireGuardCompatible else {
            throw error("DNS policy \(policy.mode) requires Libbox on iOS; WireGuardKit can only truthfully enforce plain IP DNS here.")
        }
        var lines = text.components(separatedBy: .newlines)
        var interfaceStart: Int?
        var interfaceEnd = lines.count
        for (index, line) in lines.enumerated() {
            let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
            if trimmed.caseInsensitiveCompare("[Interface]") == .orderedSame { interfaceStart = index; continue }
            if interfaceStart != nil, index > interfaceStart!, trimmed.hasPrefix("[") && trimmed.hasSuffix("]") {
                interfaceEnd = index; break
            }
        }
        guard let start = interfaceStart else { throw error("WireGuard profile has no [Interface] section for DNS policy application.") }
        var foundDNS = false
        if interfaceEnd > start + 1 {
            for index in (start + 1)..<interfaceEnd {
                let trimmed = lines[index].trimmingCharacters(in: .whitespacesAndNewlines)
                if trimmed.lowercased().hasPrefix("dns") && trimmed.contains("=") {
                    if !foundDNS { lines[index] = "DNS = \(policy.host)"; foundDNS = true }
                    else { lines[index] = "" }
                }
            }
        }
        if !foundDNS { lines.insert("DNS = \(policy.host)", at: interfaceEnd) }
        return lines.joined(separator: "\n")
    }

    static func applyToLibbox(_ files: [String: Data], profile: [String: Any]) throws -> [String: Data] {
        guard let policy = try resolve(profile: profile) else { return files }
        guard let data = files["sing-box.json"], var root = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw error("Libbox DNS policy requires a valid sing-box.json object.")
        }
        let detour = try selectedDetour(root)
        var server: [String: Any] = [
            "type": policy.type,
            "tag": "routervpn-selected-dns",
            "server": policy.host,
            "server_port": policy.port,
            "detour": detour
        ]
        if ["tls", "https", "h3"].contains(policy.type) {
            server["tls"] = ["enabled": true, "server_name": policy.serverName]
        }
        if ["https", "h3"].contains(policy.type) { server["path"] = policy.path }
        root["dns"] = ["servers": [server], "final": "routervpn-selected-dns"]

        var route = root["route"] as? [String: Any] ?? [:]
        var rules = route["rules"] as? [[String: Any]] ?? []
        rules.removeAll { ($0["action"] as? String) == "hijack-dns" || ($0["protocol"] as? String) == "dns" }
        rules.insert(["protocol": "dns", "action": "hijack-dns"], at: 0)
        route["rules"] = rules
        root["route"] = route

        let patched = try JSONSerialization.data(withJSONObject: root, options: [.prettyPrinted, .sortedKeys])
        guard patched.count <= 4 * 1024 * 1024 else { throw error("DNS-patched Libbox profile exceeds the 4 MiB safety limit.") }
        var result = files
        result["sing-box.json"] = patched
        return result
    }

    private static func selectedDetour(_ root: [String: Any]) throws -> String {
        if let route = root["route"] as? [String: Any], let final = route["final"] as? String, !final.isEmpty {
            guard final != "direct" else { throw error("Selected Libbox profile routes final traffic direct; refusing DNS policy that could bypass the intended VPN exit.") }
            return final
        }
        if let outbounds = root["outbounds"] as? [[String: Any]] {
            for outbound in outbounds {
                let tag = outbound["tag"] as? String ?? ""
                let type = outbound["type"] as? String ?? ""
                if !tag.isEmpty && type != "direct" { return tag }
            }
        }
        throw error("Selected Libbox profile has no non-direct outbound for DNS detour.")
    }

    private static func fastestHost(_ profile: [String: Any]) -> String {
        let saved = string(profile, "fastest_dns_host")
        if !saved.isEmpty { return saved }
        guard let results = profile["dns_results"] as? [[String: Any]] else { return "" }
        let working = results.compactMap { item -> (String, Double)? in
            guard item["working"] as? Bool == true,
                  let address = item["address"] as? String,
                  !address.isEmpty,
                  let latency = item["latency_ms"] as? Double,
                  latency >= 0 else { return nil }
            return (address, latency)
        }
        return working.min(by: { $0.1 < $1.1 })?.0 ?? ""
    }

    private static func string(_ profile: [String: Any], _ key: String) -> String {
        (profile[key] as? String ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
    }
    private static func integer(_ profile: [String: Any], _ key: String) -> Int? {
        if let value = profile[key] as? Int { return value }
        if let value = profile[key] as? NSNumber { return value.intValue }
        return nil
    }
    private static func firstNonEmpty(_ values: String...) -> String { values.first(where: { !$0.isEmpty }) ?? "" }
    private static func error(_ message: String) -> NSError {
        NSError(domain: "RouterVPN.DNSPolicy", code: 1, userInfo: [NSLocalizedDescriptionKey: message])
    }
}
