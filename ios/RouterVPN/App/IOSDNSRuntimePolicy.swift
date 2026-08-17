import Foundation
import Network

struct IOSResolvedDNSPolicy: Hashable {
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

enum IOSDNSRuntimePolicy {
    static let modeIDs = ["home", "fastest", "custom", "dot", "doh", "doh3", "rescue"]
    private static let helperAssets: Set<String> = [
        "xray.json", "outer-xray.json", "sslocal.json", "middle-sing-box.json", "chain.env",
        "wg.conf", "wg-socks.conf", "awg.conf", "awg-socks.conf"
    ]
    private static let loopbackHosts: Set<String> = ["127.0.0.1", "::1", "localhost"]

    static func selectedProfile(in bundle: ClientBundle) -> RouterProfile? {
        bundle.routerProfiles.first(where: { $0.id == bundle.selectedRouterID }) ?? bundle.routerProfiles.first
    }

    static func resolve(_ profile: RouterProfile) throws -> IOSResolvedDNSPolicy? {
        let mode = clean(profile.dnsMode).lowercased()
        guard !mode.isEmpty else { return nil }
        guard modeIDs.contains(mode) else { throw error("Unsupported iOS DNS policy \(mode).") }
        var type = "udp", host = "", port = 53, serverName = clean(profile.dnsServerName), path = clean(profile.dnsPath)
        switch mode {
        case "home": host = firstNonEmpty(profile.adGuardIPv4, profile.adGuardIPv6)
        case "fastest":
            host = fastestHost(profile)
            guard !host.isEmpty else { throw error("Fastest DNS is selected but this node has no measured working resolver.") }
        case "custom":
            host = clean(profile.dnsHost); type = clean(profile.dnsProtocol).lowercased()
            if type.isEmpty { type = "udp" }
            guard ["udp", "tcp"].contains(type) else { throw error("Custom DNS accepts explicit UDP or TCP only.") }
            port = profile.dnsPort ?? 53
        case "dot": type = "tls"; host = clean(profile.dnsHost); port = profile.dnsPort ?? 853
        case "doh": type = "https"; host = clean(profile.dnsHost); port = profile.dnsPort ?? 443; if path.isEmpty { path = "/dns-query" }
        case "doh3": type = "h3"; host = clean(profile.dnsHost); port = profile.dnsPort ?? 443; if path.isEmpty { path = "/dns-query" }
        case "rescue": host = fastestHost(profile); if host.isEmpty { host = "1.1.1.1" }
        default: break
        }
        guard !host.isEmpty else { throw error("DNS policy \(mode) has no resolver host.") }
        guard (1...65535).contains(port) else { throw error("DNS policy \(mode) has an invalid port.") }
        if ["tls", "https", "h3"].contains(type) {
            if serverName.isEmpty, IPv4Address(host) == nil, IPv6Address(host) == nil { serverName = host }
            guard !serverName.isEmpty else { throw error("Encrypted DNS to an IP requires its TLS server name.") }
        }
        return IOSResolvedDNSPolicy(mode: mode, type: type, host: host, port: port, serverName: serverName, path: path)
    }

    static func validate(selection: IOSRuntimeSelection, in bundle: ClientBundle) throws {
        guard let profile = selectedProfile(in: bundle), profile.normalizedNodeKind == "router-vpn", let policy = try resolve(profile) else { return }
        if selection.engine == .wireGuard && !policy.wireGuardCompatible {
            throw error("\(policy.mode.uppercased()) DNS requires Libbox on iOS. WireGuardKit can only enforce plain IP DNS without pretending to provide TCP/DoT/DoH/DoH3 transport.")
        }
    }

    static func patch(_ source: ClientBundle) throws -> ClientBundle {
        guard let profile = selectedProfile(in: source), profile.normalizedNodeKind == "router-vpn", let policy = try resolve(profile) else { return source }
        var bundle = source
        var profiles = bundle.profiles
        if policy.wireGuardCompatible, var wg = profiles["wg"], let encoded = wg["wg.conf"],
           let data = Data(base64Encoded: encoded, options: []), let text = String(data: data, encoding: .utf8) {
            wg["wg.conf"] = Data(try patchWireGuard(text, policy: policy).utf8).base64EncodedString()
            profiles["wg"] = wg
        }
        for rawID in Array(profiles.keys).filter({ $0 != "wg" }) {
            guard let encodedFiles = profiles[rawID], isSelfContainedLibbox(encodedFiles), let encoded = encodedFiles["sing-box.json"],
                  let data = Data(base64Encoded: encoded, options: []), data.count <= 4 * 1024 * 1024 else { continue }
            var next = encodedFiles
            next["sing-box.json"] = try patchLibbox(data, policy: policy).base64EncodedString()
            profiles[rawID] = next
        }
        bundle.profiles = profiles
        return bundle
    }

    private static func patchWireGuard(_ text: String, policy: IOSResolvedDNSPolicy) throws -> String {
        var lines = text.components(separatedBy: .newlines)
        guard let start = lines.firstIndex(where: { $0.trimmingCharacters(in: .whitespacesAndNewlines).caseInsensitiveCompare("[Interface]") == .orderedSame }) else { throw error("WireGuard profile has no [Interface] section for DNS policy application.") }
        let end = ((start + 1)..<lines.count).first(where: { let value = lines[$0].trimmingCharacters(in: .whitespacesAndNewlines); return value.hasPrefix("[") && value.hasSuffix("]") }) ?? lines.count
        var dnsIndexes: [Int] = []
        if end > start + 1 { for index in (start + 1)..<end { let value = lines[index].trimmingCharacters(in: .whitespacesAndNewlines).lowercased(); if value.hasPrefix("dns") && value.contains("=") { dnsIndexes.append(index) } } }
        if let first = dnsIndexes.first { lines[first] = "DNS = \(policy.host)"; for index in dnsIndexes.dropFirst().reversed() { lines.remove(at: index) } }
        else { lines.insert("DNS = \(policy.host)", at: end) }
        return lines.joined(separator: "\n")
    }

    private static func patchLibbox(_ data: Data, policy: IOSResolvedDNSPolicy) throws -> Data {
        guard var root = try JSONSerialization.jsonObject(with: data) as? [String: Any] else { throw error("Libbox DNS patch requires a JSON object.") }
        let detour = try selectedDetour(root)
        var server: [String: Any] = ["type": policy.type, "tag": "routervpn-selected-dns", "server": policy.host, "server_port": policy.port, "detour": detour]
        if ["tls", "https", "h3"].contains(policy.type) { server["tls"] = ["enabled": true, "server_name": policy.serverName] }
        if ["https", "h3"].contains(policy.type) { server["path"] = policy.path }
        root["dns"] = ["servers": [server], "final": "routervpn-selected-dns"]
        var route = root["route"] as? [String: Any] ?? [:]
        var rules = route["rules"] as? [[String: Any]] ?? []
        rules.removeAll { ($0["action"] as? String) == "hijack-dns" || ($0["protocol"] as? String) == "dns" }
        rules.insert(["protocol": "dns", "action": "hijack-dns"], at: 0)
        route["rules"] = rules; root["route"] = route
        let patched = try JSONSerialization.data(withJSONObject: root, options: [.prettyPrinted, .sortedKeys])
        guard patched.count <= 4 * 1024 * 1024 else { throw error("DNS-patched Libbox profile exceeds 4 MiB.") }
        return patched
    }

    private static func selectedDetour(_ root: [String: Any]) throws -> String {
        if let route = root["route"] as? [String: Any], let final = route["final"] as? String, !final.isEmpty {
            guard final != "direct" else { throw error("Libbox final route is direct; refusing DNS that could bypass the selected VPN exit.") }
            return final
        }
        for outbound in root["outbounds"] as? [[String: Any]] ?? [] { let tag = outbound["tag"] as? String ?? "", type = outbound["type"] as? String ?? ""; if !tag.isEmpty && type != "direct" { return tag } }
        throw error("Libbox profile has no non-direct outbound for selected DNS.")
    }

    private static func isSelfContainedLibbox(_ encoded: [String: String]) -> Bool {
        if helperAssets.contains(where: { encoded[$0] != nil }) { return false }
        guard let value = encoded["sing-box.json"], let data = Data(base64Encoded: value, options: []), let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return false }
        for outbound in root["outbounds"] as? [[String: Any]] ?? [] { guard let server = outbound["server"] as? String else { continue }; if loopbackHosts.contains(server.trimmingCharacters(in: CharacterSet(charactersIn: "[]")).lowercased()) { return false } }
        return true
    }

    private static func fastestHost(_ profile: RouterProfile) -> String {
        let saved = clean(profile.fastestDNSHost)
        if !saved.isEmpty { return saved }
        return (profile.dnsResults ?? []).filter { $0.working && ($0.latencyMs ?? -1) >= 0 }
            .min(by: { ($0.latencyMs ?? .greatestFiniteMagnitude) < ($1.latencyMs ?? .greatestFiniteMagnitude) })?.address ?? ""
    }
    private static func clean(_ value: String?) -> String { (value ?? "").trimmingCharacters(in: .whitespacesAndNewlines) }
    private static func firstNonEmpty(_ values: String...) -> String { values.map { clean($0) }.first(where: { !$0.isEmpty }) ?? "" }
    private static func error(_ message: String) -> NSError { NSError(domain: "RouterVPN.IOSDNS", code: 1, userInfo: [NSLocalizedDescriptionKey: message]) }
}
