import Foundation
import CoreFoundation

enum IOSStartLayer {
    static let off = "off"
    static let aes = "aes-256-gcm"
    static let aesXOR = "aes-256-gcm+xor-whitening"
    static let aesMethod = "2022-blake3-aes-256-gcm"
    static let aesTag = "start-layer-aes"
    static let nativeWhiteningType = "routervpn-aes-xor"
    static let whiteningPort = 8389

    private static let supportedRawModes: Set<String> = ["shadowsocks", "hysteria2", "naive-h2", "naive-h3"]
    private static let maxJSONBytes = 4 * 1024 * 1024

    static func selectedMode(profile: [String: Any]) throws -> String {
        try normalize(profile["start_layer"] as? String ?? off)
    }

    static func validateWireGuard(profile: [String: Any]) throws {
        let mode = try selectedMode(profile: profile)
        guard mode == off else {
            throw error("Start Layer \(mode) has no proved iOS WireGuard composition path; Router VPN refuses to ignore it.")
        }
    }

    static func validateExternal(profile: [String: Any]) throws {
        let mode = try selectedMode(profile: profile)
        guard mode == off else {
            throw error("External nodes own their own transport security; iOS refuses to apply or silently ignore Router VPN Start Layer \(mode).")
        }
    }

    static func apply(
        root: [String: Any],
        selectedProfile: [String: Any],
        files: [String: Data],
        rawProfileID: String
    ) throws -> [String: Data] {
        let start = try selectedMode(profile: selectedProfile)
        guard start != off else { return files }

        var kind = (selectedProfile["node_kind"] as? String ?? "router-vpn").trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if kind.isEmpty { kind = "router-vpn" }
        guard kind == "router-vpn" else {
            throw error("Start Layer is owned by Router VPN home-node profiles; external nodes keep their own transport security.")
        }

        let rawMode = rawProfileID.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard supportedRawModes.contains(rawMode) else {
            throw error("\(rawMode) has no proved iOS Start Layer composition path.")
        }
        guard start == aes || start == aesXOR else { throw error("Unsupported iOS Start Layer \(start).") }
        // XOR is obfuscation only; the native outbound always uses authenticated
        // Shadowsocks 2022 AES. No local listener, second VPN, or helper process.
        let whitening = start == aesXOR

        guard let targetData = files["sing-box.json"], !targetData.isEmpty, targetData.count <= maxJSONBytes,
              var target = try JSONSerialization.jsonObject(with: targetData) as? [String: Any],
              var outbounds = target["outbounds"] as? [[String: Any]] else {
            throw error("Selected iOS raw profile has no valid bounded sing-box outbounds for Start Layer composition.")
        }

        try requireUniqueTags(outbounds)
        if rawMode == "shadowsocks" {
            let index = try exactlyOneIndex(type: "shadowsocks", in: outbounds, label: "selected Shadowsocks mode")
            try requireAESOutbound(outbounds[index])
            guard whitening else { return files }
            outbounds[index] = try nativeWhitening(outbounds[index])
            target["outbounds"] = outbounds
            return try replacingConfig(target, in: files)
        }
        guard !outbounds.contains(where: { ($0["tag"] as? String) == aesTag }) else {
            throw error("Start Layer route tag already belongs to an outbound; refusing to replace its owner.")
        }

        guard let profiles = root["profiles"] as? [String: Any],
              let shadowsocks = profiles["shadowsocks"] as? [String: Any],
              let encoded = shadowsocks["sing-box.json"] as? String,
              !encoded.isEmpty,
              let sourceData = Data(base64Encoded: encoded, options: []),
              !sourceData.isEmpty, sourceData.count <= maxJSONBytes,
              let source = try JSONSerialization.jsonObject(with: sourceData) as? [String: Any],
              let sourceOutbounds = source["outbounds"] as? [[String: Any]] else {
            throw error("Generated Shadowsocks 2022 profile is missing or invalid for iOS Start Layer.")
        }

        let aesIndex = try exactlyOneIndex(type: "shadowsocks", in: sourceOutbounds, label: "generated Shadowsocks profile")
        var aesOutbound = sourceOutbounds[aesIndex]
        try requireAESOutbound(aesOutbound)
        if whitening { aesOutbound = try nativeWhitening(aesOutbound) }
        aesOutbound["tag"] = aesTag

        let proxyIndexes = outbounds.indices.filter { (outbounds[$0]["tag"] as? String ?? "") == "proxy" }
        guard proxyIndexes.count == 1, let proxyIndex = proxyIndexes.first else {
            throw error("\(rawMode) must expose exactly one proxy outbound for iOS Start Layer composition.")
        }
        let existingDetour = outbounds[proxyIndex]["detour"] as? String
        guard outbounds[proxyIndex]["detour"] == nil || existingDetour == "" else {
            throw error("\(rawMode) proxy outbound already owns a detour; Start Layer will not overwrite it.")
        }

        // The inner service is on the same Router VPN node. The authenticated
        // Shadowsocks-2022 outbound reaches that node first, then the node dials
        // this loopback destination after decrypting the outer Start Layer.
        outbounds[proxyIndex]["server"] = "127.0.0.1"
        outbounds[proxyIndex]["detour"] = aesTag
        outbounds.append(aesOutbound)
        target["outbounds"] = outbounds

        return try replacingConfig(target, in: files)
    }

    private static func replacingConfig(_ target: [String: Any], in files: [String: Data]) throws -> [String: Data] {
        let composed = try JSONSerialization.data(withJSONObject: target, options: [.sortedKeys])
        guard !composed.isEmpty, composed.count <= maxJSONBytes else {
            throw error("Composed iOS Start Layer profile exceeds the bounded sing-box config size.")
        }
        var result = files
        result["sing-box.json"] = composed
        return result
    }

    private static func requireUniqueTags(_ outbounds: [[String: Any]]) throws {
        var tags = Set<String>()
        for outbound in outbounds {
            guard let tag = outbound["tag"] as? String, !tag.isEmpty, tags.insert(tag).inserted else {
                throw error("Start Layer requires unique, nonempty outbound ownership tags.")
            }
        }
    }

    private static func nativeWhitening(_ outbound: [String: Any]) throws -> [String: Any] {
        try requireAESOutbound(outbound)
        let allowed: Set<String> = ["type", "tag", "method", "password", "server", "server_port"]
        guard Set(outbound.keys).isSubset(of: allowed), outbound["type"] as? String == "shadowsocks",
              outbound["method"] as? String == aesMethod,
              let password = outbound["password"] as? String, (16...4096).contains(password.utf8.count),
              !password.contains("\0"), let server = outbound["server"] as? String,
              !server.isEmpty, server == server.trimmingCharacters(in: .whitespacesAndNewlines) else {
            throw error("Native AES+XOR cannot silently discard a plugin, detour, socket policy, or invalid key.")
        }
        var native = outbound
        native["type"] = nativeWhiteningType
        native["server_port"] = whiteningPort
        return native
    }

    private static func exactlyOneIndex(type: String, in outbounds: [[String: Any]], label: String) throws -> Int {
        let indexes = outbounds.indices.filter {
            (outbounds[$0]["type"] as? String ?? "").trimmingCharacters(in: .whitespacesAndNewlines).lowercased() == type
        }
        guard indexes.count == 1, let index = indexes.first else {
            throw error("\(label) must contain exactly one \(type) outbound.")
        }
        return index
    }

    private static func requireAESOutbound(_ outbound: [String: Any]) throws {
        let method = (outbound["method"] as? String ?? "").trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        let password = outbound["password"] as? String ?? ""
        let server = (outbound["server"] as? String ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        let number = outbound["server_port"] as? NSNumber
        let port = number?.intValue ?? 0
        guard let number, CFGetTypeID(number) != CFBooleanGetTypeID(),
              number.doubleValue.isFinite, number.doubleValue == Double(port) else {
            throw error("Start Layer AES port must be an exact integer, not a Boolean or fraction.")
        }
        guard method == aesMethod, !password.isEmpty else {
            throw error("Start Layer requires authenticated Shadowsocks 2022 BLAKE3 AES-256-GCM.")
        }
        guard !server.isEmpty, !server.contains("\n"), !server.contains("\r"), port >= 1, port <= 65535 else {
            throw error("Start Layer AES outbound has an invalid server/port.")
        }
    }

    private static func normalize(_ value: String) throws -> String {
        let raw = value.trimmingCharacters(in: .whitespacesAndNewlines).lowercased().replacingOccurrences(of: "_", with: "-").replacingOccurrences(of: " ", with: "")
        switch raw {
        case "", "off", "none", "disabled": return off
        case "aes", "aes256", "aes-256", "aes-gcm", "aes256-gcm", aes: return aes
        case "aes+xor", "xor+aes", "aes-256-gcm+xor", "xor+aes-256-gcm", aesXOR: return aesXOR
        case "xor", "xor-only", "xor-whitening":
            throw error("XOR whitening is obfuscation only and requires authenticated AES-256-GCM.")
        default: throw error("Unsupported iOS Start Layer \(raw).")
        }
    }

    private static func error(_ message: String) -> NSError {
        NSError(domain: "RouterVPN.IOSStartLayer", code: 1, userInfo: [NSLocalizedDescriptionKey: message])
    }
}
