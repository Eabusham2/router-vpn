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


/// Captures complete MAX encryption before reusing the existing two-node graph
/// builder. Temporary PQ-only values are construction inputs, never runnable
/// selections; all captured layers must be restored before native validation.
enum IOSNativeMAXMultihop {
    struct Capture {
        let mode: String
        let nodeID: String
        let startLayer: String
        let source: String
        let baseFiles: [String: Data]

        var baseMode: String { mode.hasSuffix("-awg") ? "awg2-pq" : "wg-pq" }
        func endpoint() throws -> [String: Any] {
            let graph = try IOSNativeMAXMultihop.object(baseFiles["sing-box.json"])
            guard let values = graph["endpoints"] as? [[String: Any]], values.count == 1 else {
                throw IOSNativeMAXMultihop.issue("MAX construction lost its packet owner.")
            }
            return values[0]
        }
    }

    static func capture(mode: String, encoded: [String: String], nodeID: String,
                        profile: [String: Any], startLayer: String,
                        compiler: (String, String, String) throws -> String,
                        baseCompiler: (String, String, String, String) throws -> String) throws -> Capture {
        let files = try IOSNativeMAXProfile.compile(mode: mode, encoded: encoded, nodeID: nodeID,
            profile: profile, startLayer: startLayer, compiler: compiler)
        guard let original = files["sing-box.json"], let source = String(data: original, encoding: .utf8) else {
            throw issue("MAX source did not compile to its complete owned graph.")
        }
        let temporary = try baseCompiler(source, mode, nodeID, startLayer)
        let base = try object(Data(temporary.utf8))
        var expected = try object(original)
        guard var endpoints = expected["endpoints"] as? [[String: Any]], endpoints.count == 1 else {
            throw issue("Complete MAX has no unique packet endpoint.")
        }
        endpoints[0].removeValue(forKey: "detour")
        expected["endpoints"] = endpoints
        expected["outbounds"] = [[String: Any]]()
        guard try same(expected, base) else {
            throw issue("MAX construction changed captured keys, node, DNS or native policy.")
        }
        return Capture(mode: mode, nodeID: nodeID, startLayer: startLayer, source: source,
                       baseFiles: ["sing-box.json": Data(temporary.utf8)])
    }

    static func compose(files: [String: Data], metadata: String,
                        entry: Capture?, exit: Capture?,
                        compiler: (String, String, String, String) throws -> String) throws -> [String: Data] {
        guard entry != nil || exit != nil, metadata.utf8.count <= 16384,
              let captured = try JSONSerialization.jsonObject(with: Data(metadata.utf8)) as? [String: String],
              let entryTag = captured["entry_tag"], entryTag == "routervpn-hop-entry",
              let input = files["sing-box.json"], let config = String(data: input, encoding: .utf8) else {
            throw issue("MAX multihop requires complete captured node and source ownership.")
        }
        var expected = try object(input)
        guard var endpoints = expected["endpoints"] as? [[String: Any]],
              var outbounds = expected["outbounds"] as? [[String: Any]] else {
            throw issue("MAX multihop has no owned native managers.")
        }
        for (side, capture) in [("entry", entry), ("exit", exit)] {
            guard let mode = captured[side + "_mode"], IOSNativeMAXProfile.modeIDs.contains(mode) == (capture != nil) else {
                throw issue("MAX multihop source does not match its selected transport.")
            }
            guard let capture else { continue }
            let selectedLayer = captured[side + "_start_layer"] ?? ""
            guard mode == capture.mode, captured[side + "_node_id"] == capture.nodeID,
                  selectedLayer == (capture.startLayer == "off" ? "" : capture.startLayer) else {
                throw issue("MAX source belongs to a different node, protocol or outer layer.")
            }
            let source = try object(Data(capture.source.utf8))
            guard let originals = source["endpoints"] as? [[String: Any]], originals.count == 1,
                  let layers = source["outbounds"] as? [[String: Any]] else {
                throw issue("Captured MAX source lost an encryption layer.")
            }
            let tag = side == "entry" ? entryTag : "proxy"
            let prefix = "routervpn-" + side + "-max-"
            let tags = ["proxy": tag, "routervpn-max-ss": prefix + "ss",
                        "routervpn-max-outer": prefix + "outer", "routervpn-max-start-layer": prefix + "start"]
            let positions = endpoints.indices.filter { endpoints[$0]["tag"] as? String == tag }
            guard positions.count == 1 else { throw issue("MAX packet endpoint is missing or duplicated.") }
            var placeholder = originals[0]
            placeholder["tag"] = tag
            if side == "entry" { placeholder.removeValue(forKey: "detour") }
            else { placeholder["detour"] = entryTag }
            guard try same(placeholder, endpoints[positions[0]]) else {
                throw issue("MAX base changed before complete encryption could be restored.")
            }
            var restored = originals[0]
            restored["tag"] = tag; restored["detour"] = prefix + "ss"
            endpoints[positions[0]] = restored
            for var layer in layers {
                guard let originalTag = layer["tag"] as? String, let ownedTag = tags[originalTag],
                      originalTag != "proxy",
                      !endpoints.contains(where: { $0["tag"] as? String == ownedTag }),
                      !outbounds.contains(where: { $0["tag"] as? String == ownedTag }) else {
                    throw issue("MAX encryption layer names already have an owner.")
                }
                layer["tag"] = ownedTag
                if let detour = layer["detour"] {
                    guard let old = detour as? String, let owned = tags[old] else {
                        throw issue("MAX contains a route outside its captured chain.")
                    }
                    layer["detour"] = owned
                } else if side == "exit" { layer["detour"] = entryTag }
                outbounds.append(layer)
            }
        }
        expected["endpoints"] = endpoints; expected["outbounds"] = outbounds
        let compiled = try compiler(config, metadata, entry?.source ?? "", exit?.source ?? "")
        let result = try object(Data(compiled.utf8))
        guard try same(expected, result) else {
            throw issue("MAX composition changed a captured layer, proof path or exit policy.")
        }
        var output = files
        output["sing-box.json"] = Data(compiled.utf8)
        return output
    }

    private static func object(_ data: Data?) throws -> [String: Any] {
        guard let data, !data.isEmpty, data.count <= IOSNativeMAXProfile.maxGraphBytes,
              let value = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw issue("Missing or oversized MAX graph.")
        }
        return value
    }
    private static func same(_ a: [String: Any], _ b: [String: Any]) throws -> Bool {
        try JSONSerialization.data(withJSONObject: a, options: [.sortedKeys]) ==
            JSONSerialization.data(withJSONObject: b, options: [.sortedKeys])
    }
    private static func issue(_ message: String) -> NSError {
        NSError(domain: "RouterVPN.MAXMultihop", code: 1, userInfo: [NSLocalizedDescriptionKey: message])
    }
}
