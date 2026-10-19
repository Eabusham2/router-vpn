import CoreFoundation
import Foundation

/// This catalog is captured from providerConfiguration once. IPC may select
/// references in it, but can never provide replacement profiles or policies.
struct RouterVPNStrategyCandidate: Codable, Hashable, Sendable {
    let raw: String
    let logical: String
}

struct RouterVPNStrategyPlan: Sendable {
    enum Kind: String, Sendable { case manual, logical, auto, smart, custom, all }
    let requestID: String
    let kind: Kind
    let candidates: [RouterVPNStrategyCandidate]
    let preferredRaw: String?
}

struct RouterVPNStrategyPolicy: Sendable {
    let candidates: [RouterVPNStrategyCandidate]
    private let logicalOrders: [String: [String]]
    private let allOrder: [String]
    private let customLayers: Set<String>
    private let requireEncrypted: Bool
    private let requireObfuscation: Bool

    static func error(_ message: String) -> NSError {
        NSError(domain: "RouterVPN.Strategy", code: 1, userInfo: [NSLocalizedDescriptionKey: message])
    }

    static func validID(_ value: String) -> Bool {
        value.range(of: "^[A-Za-z0-9._-]{1,96}$", options: .regularExpression) != nil && !value.contains("..")
    }

    static func validUUID(_ value: String) -> Bool {
        UUID(uuidString: value)?.uuidString.lowercased() == value.lowercased()
    }

    private static func versionOne(_ value: Any?) -> Bool {
        guard let number = value as? NSNumber, CFGetTypeID(number) != CFBooleanGetTypeID() else { return false }
        return number.doubleValue == 1
    }

    private static func boolean(_ profile: [String: Any], _ key: String) throws -> Bool {
        guard let value = profile[key] else { return false }
        guard let number = value as? NSNumber, CFGetTypeID(number) == CFBooleanGetTypeID() else {
            throw error("The captured strategy has an invalid \(key) policy.")
        }
        return number.boolValue
    }

    private static func references(_ value: Any?) throws -> [RouterVPNStrategyCandidate] {
        guard let values = value as? [[String: Any]], (1...32).contains(values.count) else {
            throw error("A provider strategy requires 1–32 captured candidate references.")
        }
        var result: [RouterVPNStrategyCandidate] = []
        var seen = Set<String>()
        for item in values {
            guard Set(item.keys) == ["raw", "logical"], let raw = item["raw"] as? String,
                  let logical = item["logical"] as? String, validID(raw), validID(logical),
                  layers[raw] != nil, seen.insert(raw).inserted else {
                throw error("The provider strategy contains an unknown, duplicate or unsafe candidate.")
            }
            result.append(RouterVPNStrategyCandidate(raw: raw, logical: logical))
        }
        return result
    }

    init(catalog: [String: Any], root: [String: Any], profile: [String: Any]) throws {
        guard Set(catalog.keys) == ["version", "candidates"], Self.versionOne(catalog["version"]),
              profile["node_kind"] == nil || profile["node_kind"] is String,
              profile["node_kind"] as? String ?? "router-vpn" == "router-vpn",
              try !Self.boolean(profile, "multihop_enabled"),
              let profileID = profile["id"] as? String, root["selectedRouterID"] as? String == profileID,
              let assets = root["profiles"] as? [String: Any] else {
            throw Self.error("Owned strategies require a captured single Router VPN node and version 1 catalog.")
        }
        candidates = try Self.references(catalog["candidates"])
        guard root["logicalModes"] == nil || root["logicalModes"] is [[String: Any]],
              profile["base_tunnel"] == nil || profile["base_tunnel"] is String else {
            throw Self.error("The captured mode or base policy has an invalid type.")
        }
        let logical = root["logicalModes"] as? [[String: Any]] ?? []
        var orders: [String: [String]] = [:]
        let base = (profile["base_tunnel"] as? String ?? "auto").trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        let preferred: String
        switch base {
        case "", "auto", "wg", "wireguard": preferred = "wg"
        case "awg", "awg2", "amneziawg": preferred = "awg"
        default: throw Self.error("The captured strategy has an unknown tunnel base.")
        }
        let baseFallback = try Self.boolean(profile, "base_fallback")
        for item in logical {
            guard let id = item["id"] as? String, Self.validID(id), orders[id] == nil,
                  let variants = item["variants"] as? [String: String] else {
                throw Self.error("The captured logical mode catalog is invalid.")
            }
            let keys: [String]
            if try Self.boolean(item, "base_selector") {
                let logicalFallback = try Self.boolean(item, "fallback")
                let fallback = base.isEmpty || base == "auto" || (logicalFallback && baseFallback)
                keys = fallback ? [preferred, preferred == "wg" ? "awg" : "wg"] : [preferred]
            } else {
                keys = ["native", "default", "auto", "wg", "awg", "awg2"] + variants.keys.sorted()
            }
            var values: [String] = []
            for key in keys {
                if let raw = variants[key], !raw.isEmpty, !values.contains(raw) { values.append(raw) }
            }
            orders[id] = values
        }
        for candidate in candidates {
            guard let files = assets[candidate.raw] as? [String: String], !files.isEmpty else {
                throw Self.error("Strategy candidate \(candidate.raw) has no captured assets.")
            }
            var total = 0
            for (name, encoded) in files {
                guard name.range(of: "^[A-Za-z0-9._-]{1,128}$", options: .regularExpression) != nil,
                      name != ".", !name.contains(".."), let data = Data(base64Encoded: encoded),
                      data.count <= 4 * 1024 * 1024 else {
                    throw Self.error("A captured strategy asset is unsafe or exceeds its size bound.")
                }
                total += data.count
                guard total <= 12 * 1024 * 1024 else { throw Self.error("A strategy candidate exceeds the asset budget.") }
            }
            let matched = logical.contains { item in
                item["id"] as? String == candidate.logical &&
                    (item["variants"] as? [String: String])?.values.contains(candidate.raw) == true
            }
            guard matched || (candidate.logical == candidate.raw && !logical.contains {
                ($0["variants"] as? [String: String])?.values.contains(candidate.raw) == true
            }) else { throw Self.error("A strategy raw/logical reference does not match the captured bundle.") }
        }
        logicalOrders = orders
        let all = logical.first { $0["id"] as? String == "all" }
        let allFallback = try all.map { try Self.boolean($0, "fallback") } ?? false
        let otherBase = base.isEmpty || base == "auto" || (allFallback && baseFallback)
        let preferredBase = preferred == "awg" ? "awg" : "wg"
        let bases = otherBase ? [preferredBase, preferredBase == "wg" ? "awg" : "wg"] : [preferredBase]
        allOrder = all == nil ? [] : ["tls", "quic"].flatMap { family in bases.map { "max-\(family)-\($0)" } }
        if let requested = profile["custom_layers"] {
            guard let values = requested as? [String], values.count <= 64 else { throw Self.error("The captured CUSTOM layer list is invalid.") }
            let normalized = values.map { $0.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() }
            guard normalized.allSatisfy({ !$0.isEmpty && $0.utf8.count <= 96 }) else { throw Self.error("The captured CUSTOM layer list is invalid.") }
            customLayers = Set(normalized)
        } else { customLayers = [] }
        requireEncrypted = try Self.boolean(profile, "auto_require_encrypted")
        requireObfuscation = try Self.boolean(profile, "auto_require_obfuscation")
    }

    func plan(_ value: [String: Any], initial: Bool) throws -> RouterVPNStrategyPlan {
        let keys = Set(value.keys)
        guard keys.isSubset(of: ["version", "request_id", "kind", "candidates", "preferred_raw"]),
              ["version", "request_id", "kind", "candidates"].allSatisfy(keys.contains),
              Self.versionOne(value["version"]), let request = value["request_id"] as? String,
              Self.validUUID(request), let rawKind = value["kind"] as? String,
              let kind = RouterVPNStrategyPlan.Kind(rawValue: rawKind),
              initial || [.auto, .smart, .custom, .all].contains(kind) else {
            throw Self.error("The provider strategy request has an invalid schema or kind.")
        }
        let refs = try Self.references(value["candidates"])
        let allowed = Set(candidates)
        guard refs.allSatisfy(allowed.contains) else { throw Self.error("A strategy request refers to assets outside its captured catalog.") }
        if kind == .manual, refs.count != 1 { throw Self.error("Manual selection must name exactly one raw runtime.") }
        if kind == .logical {
            guard let logical = refs.first?.logical, refs.allSatisfy({ $0.logical == logical }),
                  let order = logicalOrders[logical] else { throw Self.error("Logical selection changed its captured mode.") }
            let captured = Set(candidates.filter { $0.logical == logical }.map(\.raw))
            guard order.filter(captured.contains) == refs.map(\.raw) else {
                throw Self.error("Logical selection violates the captured tunnel base or fallback order.")
            }
        }
        if kind == .all {
            let captured = Set(candidates.map(\.raw))
            guard !allOrder.isEmpty, allOrder.filter(captured.contains) == refs.map(\.raw) else {
                throw Self.error("ALL requires complete MAX TLS/QUIC branches in the captured base/fallback order.")
            }
        }
        if kind == .auto || kind == .smart {
            for candidate in refs {
                let layers = Self.layers[candidate.raw] ?? []
                if requireEncrypted && layers.isDisjoint(with: Self.encryptedLayers) {
                    throw Self.error("AUTO candidate violates Require encrypted.")
                }
                if requireObfuscation && layers.isDisjoint(with: Self.obfuscationLayers) {
                    throw Self.error("AUTO candidate violates Require obfuscation.")
                }
            }
        }
        if kind == .custom {
            guard !customLayers.isEmpty, refs.allSatisfy({ customLayers.isSubset(of: Self.layers[$0.raw] ?? []) }) else {
                throw Self.error("CUSTOM candidates must contain every captured requested layer.")
            }
        }
        let preferred = value["preferred_raw"] as? String
        if value["preferred_raw"] != nil {
            guard kind == .smart, let preferred, refs.contains(where: { $0.raw == preferred }) else {
                throw Self.error("SMART's remembered runtime must be a captured allowed candidate.")
            }
        }
        return RouterVPNStrategyPlan(requestID: request, kind: kind, candidates: refs, preferredRaw: preferred)
    }

    private static let encryptedLayers: Set<String> = ["wireguard", "amneziawg", "amneziawg2", "shadowsocks2022", "reality", "hysteria2", "tls", "https", "xtls-vision", "naive", "vless-pq", "rosenpass-pq"]
    private static let obfuscationLayers: Set<String> = ["light-obfuscation", "strong-obfuscation", "reality", "salamander", "v2ray-plugin", "websocket", "utls-chrome", "finalmask", "xhttp", "naive", "https", "protocol-split"]

    // The provider checks its own reduction edges; IPC ordering is not proof
    // that an arbitrary transport is a compatible simplification.
    static let layers: [String: Set<String>] = [
        "wg": ["wireguard"],
        "awg2-fast": ["amneziawg2", "light-obfuscation"],
        "wg-pq": ["wireguard", "rosenpass-pq"],
        "shadowsocks": ["shadowsocks2022"],
        "awg2-strong": ["amneziawg2", "strong-obfuscation"],
        "awg2-pq": ["amneziawg2", "strong-obfuscation", "rosenpass-pq"],
        "reality-vision": ["vless", "tcp", "reality", "xtls-vision", "utls-chrome"],
        "hysteria2": ["hysteria2", "quic", "salamander"],
        "reality-pq-vision": ["vless-pq", "reality", "xtls-vision", "tcp"],
        "ss-v2ray": ["shadowsocks2022", "v2ray-plugin", "websocket", "tls", "hysteria2", "quic-udp-fallback"],
        "naive-h2": ["naive", "https", "http2", "udp-over-tcp"],
        "naive-h3": ["naive", "https", "http3", "quic"],
        "split": ["vless", "reality", "xtls-vision", "utls-chrome", "tcp", "hysteria2", "quic", "protocol-split"],
        "reality-xhttp": ["vless-pq", "reality", "xhttp", "finalmask", "utls-chrome"],
        "max": ["vless-pq", "reality", "xtls-vision", "utls-chrome", "tcp", "hysteria2", "quic", "protocol-split"],
        "max-quic-wg": ["wireguard", "rosenpass-pq", "shadowsocks2022", "hysteria2", "quic"],
        "max-quic-awg": ["amneziawg2", "strong-obfuscation", "rosenpass-pq", "shadowsocks2022", "hysteria2", "quic"],
        "max-tls-wg": ["wireguard", "rosenpass-pq", "shadowsocks2022", "vless-pq", "reality", "xhttp", "finalmask", "utls-chrome"],
        "max-tls-awg": ["amneziawg2", "strong-obfuscation", "rosenpass-pq", "shadowsocks2022", "vless-pq", "reality", "xhttp", "finalmask", "utls-chrome"]
    ]
    static let simplify: [String: [String]] = [
        "wg": [], "awg2-fast": ["wg"], "wg-pq": ["wg"],
        "shadowsocks": ["wg", "awg2-fast"], "awg2-strong": ["awg2-fast", "wg"],
        "awg2-pq": ["wg-pq", "awg2-strong", "awg2-fast", "wg"],
        "reality-vision": ["wg", "awg2-fast", "shadowsocks"],
        "hysteria2": ["wg", "awg2-fast", "reality-vision"],
        "reality-pq-vision": ["wg-pq", "reality-vision", "awg2-pq"],
        "ss-v2ray": ["shadowsocks", "reality-vision", "hysteria2"],
        "naive-h2": ["reality-vision", "ss-v2ray"],
        "naive-h3": ["hysteria2", "naive-h2", "reality-vision"],
        "split": ["reality-vision", "hysteria2"], "reality-xhttp": ["reality-pq-vision", "reality-vision"],
        "max": ["split", "reality-pq-vision", "hysteria2"],
        "max-quic-wg": ["wg-pq", "hysteria2", "shadowsocks", "max"],
        "max-quic-awg": ["awg2-pq", "wg-pq", "hysteria2", "max-quic-wg"],
        "max-tls-wg": ["reality-xhttp", "reality-pq-vision", "wg-pq", "max-quic-wg"],
        "max-tls-awg": ["max-tls-wg", "reality-xhttp", "awg2-pq", "max-quic-awg"]
    ]
}
