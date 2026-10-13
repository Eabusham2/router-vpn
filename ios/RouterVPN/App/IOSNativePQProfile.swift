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

    /// Use exactly the single-node compiler's captured assets for an entry.
    /// The graph builder then revalidates mode/node ownership before nesting.
    static func entryEndpoint(mode: String, encoded: [String: String], nodeID: String,
                              compiler: (String, String, String) throws -> String) throws -> [String: Any] {
        let files = try compile(mode: mode, encoded: encoded, nodeID: nodeID, compiler: compiler)
        guard let data = files["sing-box.json"],
              let graph = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let endpoints = graph["endpoints"] as? [[String: Any]], endpoints.count == 1 else {
            throw issue("The captured PQ entry has no unique native endpoint.")
        }
        return endpoints[0]
    }

    private static func issue(_ text: String) -> NSError {
        NSError(domain: "RouterVPN.NativePQProfile", code: 1, userInfo: [NSLocalizedDescriptionKey: text])
    }
}

/// A complete MAX profile is not the older raw Xray "max" mode. The captured
/// mandatory PQ base, SS2022 middle and XHTTP/Hysteria2 outer all belong to one
/// PacketTunnel; generated helper documents are data, never executable files.
enum IOSNativeMAXProfile {
    static let modeIDs: Set<String> = ["max-tls-wg", "max-tls-awg", "max-quic-wg", "max-quic-awg"]
    static let maxGraphBytes = 4 * 1024 * 1024

    static func decode(mode: String, encoded: [String: String]) throws -> [String: Data] {
        guard modeIDs.contains(mode) else { throw issue("Unknown complete MAX mode.") }
        let awg = mode.hasSuffix("-awg"), tls = mode.hasPrefix("max-tls-")
        let raw = awg ? "awg.conf" : "wg.conf"
        let keys: Set<String> = ["rosenpass-client-secret", "rosenpass-client-public", "rosenpass-server-public"]
        let required = keys.union([raw, "middle-sing-box.json", "chain.env", "rosenpass.env", "rosenpass.toml", tls ? "outer-xray.json" : "cert.pem"])
        let allowed = required.union(["stack.json", awg ? "awg-socks.conf" : "wg-socks.conf"])
        guard required.isSubset(of: Set(encoded.keys)), Set(encoded.keys).isSubset(of: allowed) else {
            throw issue("Complete MAX requires its exact generated chain and post-quantum assets.")
        }
        var result: [String: Data] = [:]
        var total = 0
        for (name, value) in encoded {
            let limit = 4 * 1024 * 1024
            guard value.utf8.count <= ((limit + 2) / 3) * 4,
                  let data = Data(base64Encoded: value, options: []), !data.isEmpty,
                  data.count <= limit, data.base64EncodedString() == value else {
                throw issue("Complete MAX contains a missing, oversized or noncanonical asset.")
            }
            total += data.count
            guard total <= 12 * 1024 * 1024 else { throw issue("Complete MAX assets exceed their combined bound.") }
            if keys.contains(name) {
                guard data.count >= 32, data.contains(where: { $0 != 0 }) else { throw issue("Complete MAX lost mandatory PQ key material.") }
            } else {
                guard String(data: data, encoding: .utf8) != nil else { throw issue("Complete MAX configuration is not UTF-8.") }
            }
            result[name] = data
        }
        guard let own = result["rosenpass-client-public"], let peer = result["rosenpass-server-public"],
              own.count == peer.count, own != peer else { throw issue("Complete MAX requires distinct PQ peer identities.") }
        return result
    }

    static func compile(mode: String, encoded: [String: String], nodeID: String, profile: [String: Any], startLayer: String,
                        compiler: (String, String, String) throws -> String) throws -> [String: Data] {
        let assets = try decode(mode: mode, encoded: encoded)
        guard nodeID.utf8.count == 64, nodeID.allSatisfy({ "0123456789abcdef".contains($0) }),
              profile["node_kind"] as? String == "router-vpn", profile["node_proof_id"] as? String == nodeID,
              let endpoint = profile["endpoint"] as? String, let api = profile["router_api"] as? String,
              ["off", "aes-256-gcm", "aes-256-gcm+xor-whitening"].contains(startLayer) else {
            throw issue("Complete MAX requires the exact selected node and Start Layer policy.")
        }
        let metadata = try JSONSerialization.data(withJSONObject: ["node_id": nodeID, "node_kind": "router-vpn", "router_api": api, "endpoint": endpoint, "start_layer": startLayer], options: [.sortedKeys])
        let input = try JSONSerialization.data(withJSONObject: encoded, options: [.sortedKeys])
        guard input.count <= 16 * 1024 * 1024 else { throw issue("Complete MAX input exceeds its bound.") }
        let result = try compiler(mode, String(decoding: input, as: UTF8.self), String(decoding: metadata, as: UTF8.self))
        let extra = startLayer != "off"
        guard !result.isEmpty, result.utf8.count <= maxGraphBytes,
              let graph = try JSONSerialization.jsonObject(with: Data(result.utf8)) as? [String: Any],
              let endpoints = graph["endpoints"] as? [[String: Any]], endpoints.count == 1,
              let inbounds = graph["inbounds"] as? [[String: Any]], inbounds.count == 1,
              inbounds[0]["type"] as? String == "tun", inbounds[0]["tag"] as? String == "tun-in",
              inbounds[0]["auto_route"] as? Bool == true, inbounds[0]["strict_route"] as? Bool == true,
              let route = graph["route"] as? [String: Any], route["final"] as? String == "proxy",
              let outbounds = graph["outbounds"] as? [[String: Any]], outbounds.count == (extra ? 3 : 2),
              endpoints[0]["type"] as? String == "routervpn-pq", endpoints[0]["tag"] as? String == "proxy",
              endpoints[0]["mode"] as? String == (mode.hasSuffix("-awg") ? "awg2-pq" : "wg-pq"),
              endpoints[0]["node_id"] as? String == nodeID, endpoints[0]["system"] as? Bool == false,
              endpoints[0]["detour"] as? String == "routervpn-max-ss", let pq = endpoints[0]["pq"] as? [String: Any],
              outbounds[0]["type"] as? String == "shadowsocks", outbounds[0]["tag"] as? String == "routervpn-max-ss",
              outbounds[0]["method"] as? String == "2022-blake3-aes-256-gcm", outbounds[0]["detour"] as? String == "routervpn-max-outer",
              outbounds[1]["tag"] as? String == "routervpn-max-outer",
              outbounds[1]["type"] as? String == (mode.hasPrefix("max-tls-") ? "routervpn-xray" : "hysteria2"),
              extra ? outbounds[1]["detour"] as? String == "routervpn-max-start-layer" : outbounds[1]["detour"] == nil else {
            throw issue("Complete MAX lost its one-interface ordered encryption chain.")
        }
        if extra {
            guard outbounds[2]["tag"] as? String == "routervpn-max-start-layer", outbounds[2]["detour"] == nil,
                  outbounds[2]["type"] as? String == (startLayer == "aes-256-gcm" ? "shadowsocks" : "routervpn-aes-xor") else {
                throw issue("Complete MAX lost the selected outermost Start Layer.")
            }
        }
        for (asset, field) in [("rosenpass-client-secret", "secret"), ("rosenpass-client-public", "public"), ("rosenpass-server-public", "peer")] {
            guard pq[field] as? String == assets[asset]?.base64EncodedString() else { throw issue("Complete MAX changed a captured PQ key.") }
        }
        return ["sing-box.json": Data(result.utf8)]
    }

    private static func issue(_ text: String) -> NSError {
        NSError(domain: "RouterVPN.NativeMAXProfile", code: 1, userInfo: [NSLocalizedDescriptionKey: text])
    }
}
