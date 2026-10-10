import Foundation

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
        switch text.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() {
        case "", "off", "none", "disabled": return "off"
        case "aes", "aes-256-gcm": return "aes-256-gcm"
        case "aes+xor", "aes-xor", "aes-256-gcm+xor-whitening": return "aes-256-gcm+xor-whitening"
        default: throw issue("Select authenticated AES or AES with XOR whitening; standalone XOR is not encryption.")
        }
    }

    static func capture(profile: [String: Any], profiles: [String: [String: String]]) throws -> Capture {
        let mode = try selected(profile)
        if mode == "off" { return Capture(mode: mode, source: nil, graphProfile: profile) }
        let kind = profile["node_kind"] as? String ?? "router-vpn"
        guard kind == "router-vpn", let assets = profiles["shadowsocks"], assets.count == 1,
              let encoded = assets["sing-box.json"], !encoded.isEmpty, encoded.utf8.count < maximumBytes,
              let raw = Data(base64Encoded: encoded, options: []), !raw.isEmpty,
              raw.base64EncodedString() == encoded, String(data: raw, encoding: .utf8) != nil else {
            throw issue("Entry Start Layer requires the exact bounded AES assets of the captured home node.")
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

    static func validateExit(_ profile: [String: Any]) throws {
        guard try selected(profile) == "off" else {
            throw issue("An exit Start Layer requires its own paired execution policy.")
        }
    }

    /// A missing or changed layer must not select the old bare-entry factory.
    /// The existing native controller revalidates the complete metadata/source.
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
