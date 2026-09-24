import Foundation

/// Applies the frozen node's fixed TUN MTU to the configuration actually started
/// by PacketTunnel. Saved/effective values are not evidence of a measured path.
enum RouterVPNMTUPolicy {
    static let minimum = 1280  // Every shipped iOS TUN is IPv4/IPv6 capable.
    static let maximum = 9000
    private static let maxConfigBytes = 4 * 1024 * 1024

    static func fixedMTU(profile: [String: Any]) throws -> Int? {
        struct Settings: Decodable {
            let mtu_policy: String?
            let manual_mtu: Int?
        }
        let settings = try JSONDecoder().decode(Settings.self, from: JSONSerialization.data(withJSONObject: profile))
        switch (settings.mtu_policy ?? "auto").trimmingCharacters(in: .whitespacesAndNewlines).lowercased() {
        case "", "auto", "default":
            // Do not reuse a saved effective_mtu without current path identity.
            return nil
        case "manual", "fixed":
            guard let mtu = settings.manual_mtu, (minimum...maximum).contains(mtu) else {
                throw issue("Fixed iOS TUN MTU must be 1280–9000 for the dual-stack PacketTunnel.")
            }
            return mtu
        default:
            throw issue("Unknown iOS MTU policy; refusing to silently ignore it.")
        }
    }

    static func wireGuard(_ text: String, profile: [String: Any]) throws -> String {
        guard let mtu = try fixedMTU(profile: profile) else { return text }
        guard text.utf8.count <= maxConfigBytes else { throw issue("WireGuard MTU input exceeds its safety limit.") }
        // CRLF is one Swift grapheme; splitting on the LF string alone does
        // not split CRLF input on every Foundation implementation.
        let newline = text.contains("\r\n") ? "\r\n" : "\n"
        var lines = text.replacingOccurrences(of: "\r\n", with: "\n")
            .replacingOccurrences(of: "\r", with: "\n").components(separatedBy: "\n")
        var inInterface = false
        var interfaceLine: Int?
        var mtuLine: Int?
        for index in lines.indices {
            let statement = lines[index].split(separator: "#", maxSplits: 1, omittingEmptySubsequences: false)[0]
                .split(separator: ";", maxSplits: 1, omittingEmptySubsequences: false)[0]
                .trimmingCharacters(in: .whitespacesAndNewlines)
            if statement.hasPrefix("[") && statement.hasSuffix("]") {
                inInterface = statement.lowercased() == "[interface]"
                if inInterface {
                    guard interfaceLine == nil else { throw issue("Multiple WireGuard interfaces make MTU ownership ambiguous.") }
                    interfaceLine = index
                }
                continue
            }
            guard inInterface, let equals = statement.firstIndex(of: "="),
                  statement[..<equals].trimmingCharacters(in: .whitespaces).lowercased() == "mtu" else { continue }
            guard mtuLine == nil else { throw issue("Duplicate WireGuard MTU fields are not a verifiable configuration.") }
            mtuLine = index
        }
        guard let interfaceLine else { throw issue("WireGuard has no interface for fixed MTU application.") }
        if let mtuLine { lines[mtuLine] = "MTU = \(mtu)" }
        else { lines.insert("MTU = \(mtu)", at: interfaceLine + 1) }
        return lines.joined(separator: newline)
    }

    static func libbox(_ files: [String: Data], profile: [String: Any]) throws -> [String: Data] {
        guard let mtu = try fixedMTU(profile: profile) else { return files }
        guard let data = files["sing-box.json"], !data.isEmpty, data.count <= maxConfigBytes,
              var root = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              var inbounds = root["inbounds"] as? [[String: Any]] else {
            throw issue("Libbox has no bounded native TUN configuration for fixed MTU application.")
        }
        let tunIndexes = inbounds.indices.filter { inbounds[$0]["type"] as? String == "tun" }
        guard tunIndexes.count == 1, let index = tunIndexes.first else {
            throw issue("Fixed iOS MTU requires exactly one owned Libbox TUN.")
        }
        inbounds[index]["mtu"] = mtu
        root["inbounds"] = inbounds
        // A native WireGuard endpoint has its own userspace TUN. Keep a fixed
        // manual policy consistent there instead of only changing the OS TUN.
        if var endpoints = root["endpoints"] as? [[String: Any]] {
            for i in endpoints.indices where endpoints[i]["type"] as? String == "wireguard" { endpoints[i]["mtu"] = mtu }
            root["endpoints"] = endpoints
        }
        var output = files
        let encoded = try JSONSerialization.data(withJSONObject: root, options: [.sortedKeys])
        guard encoded.count <= maxConfigBytes else { throw issue("MTU-patched Libbox configuration exceeds its safety limit.") }
        output["sing-box.json"] = encoded
        return output
    }

    /// Keep each frozen hop's policy separate. A nested WG transport must fit
    /// inside the entry endpoint's IP MTU, including UDP/IP headers, the 32-byte
    /// WG transport header/tag and 16-byte plaintext padding. This is a bound
    /// from configured interfaces, NOT a claim that the live path was measured.
    static func multihop(_ files: [String: Data], entryProfile: [String: Any], exitProfile: [String: Any]) throws -> [String: Data] {
        guard let data = files["sing-box.json"], !data.isEmpty, data.count <= maxConfigBytes,
              var root = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              var inbounds = root["inbounds"] as? [[String: Any]],
              var endpoints = root["endpoints"] as? [[String: Any]] else {
            throw issue("Multihop MTU requires the owned bounded native graph.")
        }
        let tun = inbounds.indices.filter { inbounds[$0]["type"] as? String == "tun" }
        let entry = endpoints.indices.filter { endpoints[$0]["tag"] as? String == "routervpn-hop-entry" }
        let exit = endpoints.indices.filter { endpoints[$0]["tag"] as? String == "proxy" }
        guard tun.count == 1, entry.count == 1, exit.count <= 1,
              endpoints.count == entry.count + exit.count,
              endpoints.allSatisfy({ $0["type"] as? String == "wireguard" }) else {
            throw issue("Multihop MTU ownership is ambiguous; no hop policy was replaced.")
        }
        let tunIndex = tun[0], entryIndex = entry[0]
        let entryMTU = try fixedMTU(profile: entryProfile) ?? mtuValue(endpoints[entryIndex]["mtu"])
        guard (minimum...maximum).contains(entryMTU) else { throw issue("Entry MTU is outside the supported dual-stack range.") }
        let fixedExit = try fixedMTU(profile: exitProfile)
        var tunMTU = try fixedExit ?? mtuValue(inbounds[tunIndex]["mtu"])
        endpoints[entryIndex]["mtu"] = entryMTU
        if let exitIndex = exit.first {
            guard endpoints[exitIndex]["detour"] as? String == "routervpn-hop-entry",
                  let peers = endpoints[exitIndex]["peers"] as? [[String: Any]], peers.count == 1,
                  let host = peers[0]["address"] as? String, !host.isEmpty else {
                throw issue("Nested WireGuard MTU requires the owned exit-through-entry dialer.")
            }
            let overhead = host.contains(":") ? 80 : 60
            let payloadLimit = ((entryMTU - overhead) / 16) * 16
            guard payloadLimit >= minimum else {
                throw issue("The configured entry MTU cannot carry a dual-stack nested WireGuard packet. Increase the entry MTU or select another exit transport.")
            }
            let importedExit = try mtuValue(endpoints[exitIndex]["mtu"])
            let exitMTU = fixedExit ?? min(importedExit, payloadLimit)
            guard (minimum...maximum).contains(exitMTU), exitMTU <= payloadLimit else {
                throw issue("The requested fixed exit MTU does not fit inside the configured entry. It was not silently clamped or applied to the wrong hop.")
            }
            endpoints[exitIndex]["mtu"] = exitMTU
            tunMTU = fixedExit ?? min(tunMTU, exitMTU)
        }
        guard (minimum...maximum).contains(tunMTU) else { throw issue("Multihop TUN MTU is outside the supported dual-stack range.") }
        inbounds[tunIndex]["mtu"] = tunMTU
        root["inbounds"] = inbounds; root["endpoints"] = endpoints
        let encoded = try JSONSerialization.data(withJSONObject: root, options: [.sortedKeys])
        guard encoded.count <= maxConfigBytes else { throw issue("Multihop MTU configuration exceeds the safety limit.") }
        var output = files; output["sing-box.json"] = encoded
        return output
    }

    private static func mtuValue(_ value: Any?) throws -> Int {
        guard let value else { throw issue("The owned graph is missing an explicit interface MTU.") }
        struct Value: Decodable { let mtu: Int }
        return try JSONDecoder().decode(Value.self, from: JSONSerialization.data(withJSONObject: ["mtu": value])).mtu
    }

    private static func issue(_ message: String) -> NSError {
        NSError(domain: "RouterVPN.MTU", code: 1, userInfo: [NSLocalizedDescriptionKey: message])
    }
}
