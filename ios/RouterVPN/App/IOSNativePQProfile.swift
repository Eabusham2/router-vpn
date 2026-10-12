import Foundation

/// Frozen generated assets for a single native Rosenpass-protected WG/AWG peer.
/// The app validates the asset envelope; the extension calls the shared pinned
/// compiler before creating any protocol handle, session directory or interface.
enum IOSNativePQProfile {
    static let modeIDs: Set<String> = ["wg-pq", "awg2-pq"]
    static let maxGraphBytes = 4 * 1024 * 1024

    static func decode(mode: String, encoded: [String: String]) throws -> [String: Data] {
        guard modeIDs.contains(mode) else { throw issue("Unknown native PQ mode.") }
        let raw = mode == "wg-pq" ? "wg.conf" : "awg.conf"
        let keys: Set<String> = ["rosenpass-client-secret", "rosenpass-client-public", "rosenpass-server-public"]
        let required = keys.union([raw, "rosenpass.env", "rosenpass.toml"])
        guard required.isSubset(of: Set(encoded.keys)), Set(encoded.keys).isSubset(of: required.union(["stack.json"])) else {
            throw issue("Native PQ requires exactly its captured keys and generated profile assets.")
        }
        var files: [String: Data] = [:]
        var total = 0
        for (name, value) in encoded {
            let limit = keys.contains(name) ? 2 * 1024 * 1024 : (name == "rosenpass.env" || name == "rosenpass.toml" ? 16384 : 1024 * 1024)
            guard value.utf8.count <= ((limit + 2) / 3) * 4,
                  let data = Data(base64Encoded: value, options: []), !data.isEmpty,
                  data.count <= limit, data.base64EncodedString() == value else {
                throw issue("Native PQ contains a missing, oversized or noncanonical asset.")
            }
            total += data.count
            guard total <= 8 * 1024 * 1024 else { throw issue("Native PQ assets exceed their combined bound.") }
            if keys.contains(name) {
                guard data.count >= 32, data.contains(where: { $0 != 0 }) else { throw issue("Native PQ key material is invalid.") }
            } else {
                guard String(data: data, encoding: .utf8) != nil else { throw issue("Native PQ configuration is not UTF-8.") }
            }
            files[name] = data
        }
        guard let own = files["rosenpass-client-public"], let peer = files["rosenpass-server-public"],
              own.count == peer.count, own != peer else { throw issue("Native PQ requires distinct complete peer identities.") }
        return files
    }

    static func compile(mode: String, encoded: [String: String], nodeID: String,
                        compiler: (String, String, String) throws -> String) throws -> [String: Data] {
        let assets = try decode(mode: mode, encoded: encoded)
        guard nodeID.utf8.count == 64, nodeID.allSatisfy({ "0123456789abcdef".contains($0) }) else {
            throw issue("Native PQ requires the exact captured Router VPN node identity.")
        }
        let input = try JSONSerialization.data(withJSONObject: encoded, options: [.sortedKeys])
        guard input.count <= 12 * 1024 * 1024 else { throw issue("Native PQ asset map exceeds its bound.") }
        let result = try compiler(mode, String(decoding: input, as: UTF8.self), nodeID)
        guard !result.isEmpty, result.utf8.count <= maxGraphBytes,
              let graph = try JSONSerialization.jsonObject(with: Data(result.utf8)) as? [String: Any],
              let endpoints = graph["endpoints"] as? [[String: Any]], endpoints.count == 1,
              let inbounds = graph["inbounds"] as? [[String: Any]], inbounds.count == 1,
              inbounds[0]["type"] as? String == "tun", inbounds[0]["tag"] as? String == "tun-in",
              inbounds[0]["auto_route"] as? Bool == true, inbounds[0]["strict_route"] as? Bool == true,
              let outbounds = graph["outbounds"] as? [Any], outbounds.isEmpty,
              let route = graph["route"] as? [String: Any], route["final"] as? String == "proxy",
              let pq = endpoints[0]["pq"] as? [String: Any],
              endpoints[0]["type"] as? String == "routervpn-pq", endpoints[0]["tag"] as? String == "proxy",
              endpoints[0]["mode"] as? String == mode, endpoints[0]["node_id"] as? String == nodeID,
              endpoints[0]["system"] as? Bool == false, endpoints[0]["detour"] == nil else {
            throw issue("Native PQ compiler did not preserve its one-interface, one-peer ownership.")
        }
        for (asset, field) in [("rosenpass-client-secret", "secret"), ("rosenpass-client-public", "public"), ("rosenpass-server-public", "peer")] {
            guard pq[field] as? String == assets[asset]?.base64EncodedString() else { throw issue("Native PQ compiler changed a captured key.") }
        }
        // Raw profiles and helper documents must never become executable or
        // separately staged artifacts; their validated data is inside the graph.
        return ["sing-box.json": Data(result.utf8)]
    }

    private static func issue(_ text: String) -> NSError {
        NSError(domain: "RouterVPN.NativePQProfile", code: 1, userInfo: [NSLocalizedDescriptionKey: text])
    }
}
