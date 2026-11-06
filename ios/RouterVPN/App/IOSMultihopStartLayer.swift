import Foundation
import CoreFoundation
#if canImport(CryptoKit)
import CryptoKit
#endif

/// Captures a selected entry's Start Layer before any asynchronous work. The
/// native compiler validates its encryption, peer identity and graph ownership.
enum IOSMultihopStartLayer {
    static let maximumBytes = 16384
    struct Capture {
        let mode: String
        let source: String?
        let graphProfile: [String: Any]
    }

    static func selected(_ profile: [String: Any]) throws -> String {
        guard let raw = profile["start_layer"] else { return "off" }
        guard let text = raw as? String else { throw issue("Start Layer must be a string.") }
        switch text.trimmingCharacters(in: .whitespacesAndNewlines).lowercased().replacingOccurrences(of: "_", with: "-").replacingOccurrences(of: " ", with: "") {
        case "", "off", "none", "disabled": return "off"
        case "aes", "aes256", "aes-256", "aes-gcm", "aes256-gcm", "aes-256-gcm": return "aes-256-gcm"
        case "aes+xor", "aes-xor", "xor+aes", "aes-256-gcm+xor", "xor+aes-256-gcm", "aes-256-gcm+xor-whitening": return "aes-256-gcm+xor-whitening"
        default: throw issue("Select authenticated AES or AES with XOR whitening; standalone XOR is not encryption.")
        }
    }

    /// Configured service authority is passive here. It never establishes live
    /// readiness or enables UoT on an ordinary captured Start Layer.
    static func validateCapturedSSService(_ files: [String: String], node: String? = nil) throws {
        let bad = "Captured SS service declaration must match its original paired source."
        guard Set(files.keys) == Set(["sing-box.json", "routervpn-ss-service.json"]),
              let encoded = files["sing-box.json"], let encodedClaim = files["routervpn-ss-service.json"],
              let base = Data(base64Encoded: encoded), let data = Data(base64Encoded: encodedClaim),
              base.count <= 4 * 1024 * 1024, data.count <= 16384,
              base.base64EncodedString() == encoded, data.base64EncodedString() == encodedClaim,
              let original = try JSONSerialization.jsonObject(with: base) as? [String: Any],
              let claim = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              Set(claim.keys) == Set(["schema","node_id","configured_image","uot_version","endpoint","port","method","key_sha256","source_sha256"]),
              let schema = claim["schema"] as? NSNumber, CFGetTypeID(schema) != CFBooleanGetTypeID(), schema.doubleValue == 1,
              let version = claim["uot_version"] as? NSNumber, CFGetTypeID(version) != CFBooleanGetTypeID(), version.doubleValue == 2,
              claim["configured_image"] as? String == "ghcr.io/sagernet/sing-box:v1.13.12",
              let owner = claim["node_id"] as? String, owner.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil,
              node == nil || node == owner,
              let rows = original["outbounds"] as? [[String: Any]], rows.filter({$0["tag"] as? String == "proxy"}).count == 1,
              let out = rows.first(where: {$0["tag"] as? String == "proxy"}),
              Set(out.keys) == Set(["type","tag","server","server_port","method","password"]),
              out["type"] as? String == "shadowsocks", out["method"] as? String == "2022-blake3-aes-256-gcm",
              let endpoint = out["server"] as? String, !endpoint.isEmpty, claim["endpoint"] as? String == endpoint,
              let port = out["server_port"] as? NSNumber, CFGetTypeID(port) != CFBooleanGetTypeID(), port.doubleValue >= 1, port.doubleValue <= 65535, port.doubleValue == Double(port.intValue),
              let capturedPort = claim["port"] as? NSNumber, CFGetTypeID(capturedPort) != CFBooleanGetTypeID(), capturedPort == port,
              claim["method"] as? String == out["method"] as? String,
              let key = out["password"] as? String, !key.isEmpty else { throw issue(bad) }
        #if canImport(CryptoKit)
        let sourceHash = CryptoKit.SHA256.hash(data: base).map { String(format: "%02x", $0) }.joined()
        let keyHash = CryptoKit.SHA256.hash(data: Data(key.utf8)).map { String(format: "%02x", $0) }.joined()
        guard claim["source_sha256"] as? String == sourceHash, claim["key_sha256"] as? String == keyHash else { throw issue(bad) }
        #else
        throw issue("Captured SS service validation requires the platform SHA-256 provider.")
        #endif
    }
    static func capture(profile: [String: Any], profiles: [String: [String: String]]) throws -> Capture {
        let mode = try selected(profile)
        if mode == "off" { return Capture(mode: mode, source: nil, graphProfile: profile) }
        let rawKind = profile["node_kind"] ?? "router-vpn"
        guard let kind = rawKind as? String else { throw issue("Invalid captured node kind.") }
        guard kind == "router-vpn", let assets = profiles["shadowsocks"], (assets.count == 1 || assets.count == 2),
              let encoded = assets["sing-box.json"], !encoded.isEmpty, encoded.utf8.count < maximumBytes,
              let raw = Data(base64Encoded: encoded, options: []), !raw.isEmpty,
              raw.base64EncodedString() == encoded, String(data: raw, encoding: .utf8) != nil else {
            throw issue("Entry Start Layer requires the exact bounded AES assets of the captured home node.")
        }
        if assets.count == 2 {
            guard let node = profile["node_proof_id"] as? String,
                  node.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil else {
                throw issue("Captured SS service requires its original paired node identity.")
            }
            try validateCapturedSSService(assets, node: node)
        }
        let bytes = try JSONSerialization.data(withJSONObject: ["mode": mode, "profile": assets], options: [.sortedKeys])
        guard bytes.count <= maximumBytes else { throw issue("Captured entry layer exceeds its private input bound.") }
        var graph = profile
        // Only base composition sees Off. The original source and required-mode
        // marker are passed together to the native factory; neither is optional
        // once requested. All DNS, MTU, LAN and privacy settings remain unchanged.
        graph["start_layer"] = "off"
        return Capture(mode: mode, source: String(decoding: bytes, as: UTF8.self), graphProfile: graph)
    }

    /// Convert only the exit-owned certificate file to its exact inline bytes.
    /// All route, DNS, TUN, credential and non-certificate transport data survive.
    static func inlineExitTLS(files: [String: Data], assets: [String: String], mode: String = "hysteria2",
                              compiler: (String, String) throws -> String) throws -> [String: Data] {
        guard ["hysteria2", "naive-h2", "naive-h3"].contains(mode) else { throw issue("Unknown captured TLS transport.") }
        let naive = mode == "naive-h2" || mode == "naive-h3"
        guard let data = files["sing-box.json"], data.count <= 4 * 1024 * 1024,
              var graph = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              var outbounds = graph["outbounds"] as? [[String: Any]],
              outbounds.filter({ $0["tag"] as? String == "proxy" }).count == 1,
              let index = outbounds.firstIndex(where: { $0["tag"] as? String == "proxy" }),
              outbounds[index]["type"] as? String == (naive ? "naive" : "hysteria2") else { throw issue("Exit trust has no unique captured transport.") }
        let payload = try JSONSerialization.data(withJSONObject: assets, options: [.sortedKeys])
        guard payload.count <= 8 * 1024 * 1024 else { throw issue("Exit trust source exceeds its bound.") }
        let output = try compiler(String(decoding: payload, as: UTF8.self), mode)
        guard output.utf8.count <= 4 * 1024 * 1024,
              var normalized = try JSONSerialization.jsonObject(with: Data(output.utf8)) as? [String: Any],
              let tls = normalized["tls"] as? [String: Any], tls["enabled"] as? Bool == true,
              tls["certificate_path"] == nil else { throw issue("Exit trust did not compile to its owned inline policy.") }
        normalized["tag"] = "proxy"
        var expected = outbounds[index]
        guard var originalTLS = expected["tls"] as? [String: Any] else { throw issue("Exit TLS is missing.") }
        if let file = originalTLS["certificate_path"] as? String {
            guard !file.contains("/"), !file.contains("\\"), !file.contains(".."),
                  let bytes = files[file], bytes.count <= 128 * 1024,
                  let text = String(data: bytes, encoding: .utf8),
                  tls["certificate"] as? [String] == [text] else { throw issue("Inline trust differs from the captured exit certificate.") }
            originalTLS.removeValue(forKey: "certificate_path")
            originalTLS["certificate"] = [text]
        }
        expected["tls"] = originalTLS
        guard try JSONSerialization.data(withJSONObject: normalized, options: [.sortedKeys]) == JSONSerialization.data(withJSONObject: expected, options: [.sortedKeys]) else {
            throw issue("Inlining exit trust changed another transport setting.")
        }
        outbounds[index] = normalized; graph["outbounds"] = outbounds
        // Naive's exact compiler already rejects extra helper assets. Retain
        // only the inlined graph; it has no native certificate-file owner.
        var result: [String: Data] = naive ? [:] : files
        result["sing-box.json"] = try JSONSerialization.data(withJSONObject: graph, options: [.sortedKeys])
        return result
    }

    static func validateExit(_ profile: [String: Any]) throws {
        guard try selected(profile) == "off" else {
            throw issue("An exit Start Layer requires its own paired execution policy.")
        }
    }

    /// A missing or changed layer must not select the old bare-entry factory.
    /// The existing native controller revalidates the complete metadata/source.
    static func requiredExitSource(metadata: String?, source: String?) throws -> String? {
        guard let metadata else {
            if source != nil { throw issue("Exit layer source has no captured multihop owner.") }
            return nil
        }
        guard metadata.utf8.count <= maximumBytes,
              var selected = try JSONSerialization.jsonObject(with: Data(metadata.utf8)) as? [String: Any] else {
            throw issue("Malformed captured exit-layer metadata.")
        }
        selected.removeValue(forKey: "entry_start_layer")
        selected.removeValue(forKey: "entry_mode")
        if let mode = selected["exit_mode"] { selected["entry_mode"] = mode }
        if let required = selected["exit_start_layer"] { selected["entry_start_layer"] = required }
        let translated = String(decoding: try JSONSerialization.data(withJSONObject: selected), as: UTF8.self)
        return try requiredSource(metadata: translated, source: source)
    }

    static func requiredSource(metadata: String?, source: String?) throws -> String? {
        guard let metadata else {
            guard source == nil else { throw issue("Entry layer has no captured multihop owner.") }
            return nil
        }
        guard metadata.utf8.count <= maximumBytes,
              let captured = try JSONSerialization.jsonObject(with: Data(metadata.utf8)) as? [String: Any] else {
            throw issue("Invalid captured multihop metadata.")
        }
        let required: String
        if let value = captured["entry_start_layer"] {
            guard let text = value as? String else { throw issue("Invalid requested entry layer.") }
            required = text
        } else { required = "" }
        if ["max-tls-wg", "max-tls-awg", "max-quic-wg", "max-quic-awg", "ss-v2ray", "split", "max"].contains(captured["entry_mode"] as? String ?? "") {
            // MAX's exact chain compiler already embedded the selected layer.
            // The native multihop factory must still validate that full chain;
            // a second source could wrap a different node or double-encrypt it.
            guard source == nil, required.isEmpty || ["aes-256-gcm", "aes-256-gcm+xor-whitening"].contains(required) else {
                throw issue("Complete MAX owns its one captured Start Layer inside the graph.")
            }
            return nil
        }
        guard let source else {
            guard required.isEmpty else { throw issue("Requested entry layer source is missing.") }
            return nil
        }
        guard ["aes-256-gcm", "aes-256-gcm+xor-whitening"].contains(required),
              !source.isEmpty, source.utf8.count <= maximumBytes,
              let capturedSource = try JSONSerialization.jsonObject(with: Data(source.utf8)) as? [String: Any],
              Set(capturedSource.keys) == Set(["mode", "profile"]),
              capturedSource["mode"] as? String == required,
              capturedSource["profile"] is [String: String] else {
            throw issue("Entry layer source is missing, unrequested or different from the captured selection.")
        }
        return source
    }

    private static func issue(_ message: String) -> NSError {
        NSError(domain: "RouterVPN.EntryStartLayer", code: 1, userInfo: [NSLocalizedDescriptionKey: message])
    }
}
