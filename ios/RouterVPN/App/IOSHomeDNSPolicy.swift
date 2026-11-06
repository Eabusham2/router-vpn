import Foundation
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

/// The app and PacketTunnel must retain the same captured Home AdGuard policy.
/// This validates ownership and syntax, not live service availability or proof.
struct IOSHomeDNSPolicy: Equatable {
    let type: String
    let host: String
    let port: Int
    let serverName: String
    let path: String

    static func resolve(adGuardIPv4: String, adGuardIPv6: String, ipv6Mode: String,
                        protocolName: String, host: String, port: Int,
                        serverName: String, path: String) throws -> Self {
        var addresses: [String] = []
        for (address, version) in [(adGuardIPv4, 4), (adGuardIPv6, 6)] where !address.isEmpty {
            guard privateAddress(address, version: version) else { throw issue("Home DNS requires this node's canonical private AdGuard addresses.") }
            addresses.append(address)
        }
        guard let fallback = addresses.first else { throw issue("Home AdGuard address is missing from this captured node.") }
        let selected = host.trimmingCharacters(in: .whitespacesAndNewlines)
        let result = try normalize(protocolName: protocolName, host: selected.isEmpty ? fallback : selected,
                                   port: port, serverName: serverName, path: path)
        guard addresses.contains(result.host) else { throw issue("Home DNS belongs to a different node. Select this node's saved AdGuard address.") }
        guard ipv6Mode.lowercased() != "off" || !result.host.contains(":") else { throw issue("The selected IPv6 Home resolver cannot be used while IPv6 is Off.") }
        return result
    }

    /// Saved snapshots validate syntax before they can revalidate their linked
    /// node at Load. This never invents a node or public resolver.
    static func normalize(protocolName: String, host: String, port: Int,
                          serverName: String, path: String) throws -> Self {
        let host = host.trimmingCharacters(in: .whitespacesAndNewlines).trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
        guard privateAddress(host, version: host.contains(":") ? 6 : 4) else { throw issue("Home DNS requires a canonical private AdGuard IP address.") }
        var type = protocolName.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        type = ["": "udp", "dot": "tls", "doh": "https", "doh3": "h3"][type] ?? type
        guard ["udp", "tcp", "tls", "https", "h3"].contains(type) else { throw issue("Home DNS transport must be UDP, TCP, DoT, DoH or DoH3.") }
        guard (0...65535).contains(port) else { throw issue("Home DNS port must be between 1 and 65535, or zero for the selected transport default.") }
        let port = port == 0 ? (type == "tls" ? 853 : ["https", "h3"].contains(type) ? 443 : 53) : port
        var name = serverName.trimmingCharacters(in: .whitespacesAndNewlines)
        var path = path.trimmingCharacters(in: .whitespacesAndNewlines)
        if ["udp", "tcp"].contains(type) { name = ""; path = "" }
        else {
            guard hostname(name) else { throw issue("Encrypted Home DNS requires its exact TLS certificate hostname.") }
            if type == "tls" { path = "" }
            else {
                if path.isEmpty { path = "/dns-query" }
                guard path.utf8.count <= 2048, path.hasPrefix("/"), !path.hasPrefix("//"),
                      !path.unicodeScalars.contains(where: { $0.value <= 32 || $0.value >= 127 }),
                      !path.contains(where: { "\\?#".contains($0) }),
                      path.range(of: "%(?![0-9A-Fa-f]{2})", options: .regularExpression) == nil,
                      let url = URLComponents(string: path), url.scheme == nil, url.host == nil, url.query == nil, url.fragment == nil else {
                    throw issue("Home DoH requires its exact local resolver path without a host, query or fragment.")
                }
            }
        }
        return Self(type: type, host: host, port: port, serverName: name, path: path)
    }

    private static func hostname(_ value: String) -> Bool {
        guard value.utf8.count <= 253, value.contains("."), value.unicodeScalars.allSatisfy({ $0.isASCII }),
              value.unicodeScalars.contains(where: { CharacterSet.letters.contains($0) }),
              value.range(of: "\\A(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\\.)+[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\\z", options: .regularExpression) != nil else { return false }
        var v4 = in_addr(), v6 = in6_addr()
        return inet_pton(AF_INET, value, &v4) != 1 && inet_pton(AF_INET6, value, &v6) != 1
    }

    private static func privateAddress(_ value: String, version: Int) -> Bool {
        guard !value.isEmpty, !value.contains("%"), !value.utf8.contains(0), value.unicodeScalars.allSatisfy({ $0.isASCII }) else { return false }
        var bytes = [UInt8](repeating: 0, count: version == 4 ? 4 : 16)
        let family = version == 4 ? AF_INET : AF_INET6
        guard inet_pton(family, value, &bytes) == 1 else { return false }
        let isPrivate = version == 4 ? (bytes[0] == 10 || bytes[0] == 172 && (16...31).contains(bytes[1]) || bytes[0] == 192 && bytes[1] == 168) : bytes[0] & 0xfe == 0xfc
        var text = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        guard isPrivate, inet_ntop(family, &bytes, &text, socklen_t(text.count)) != nil else { return false }
        return String(decoding: text.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self) == value
    }

    private static func issue(_ text: String) -> NSError {
        NSError(domain: "RouterVPN.HomeDNS", code: 1, userInfo: [NSLocalizedDescriptionKey: text])
    }
}
