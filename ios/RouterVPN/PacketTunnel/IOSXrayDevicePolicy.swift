import Foundation
#if canImport(Libbox)
import Libbox
#endif

/// Applies the captured node's LAN/IPv6 policy to its validated native Xray
/// graph. This is separate from optional Start Layer selection: LAN-Off and
/// IPv6-Off must still be enforced when the outer AES layer is disabled.
enum IOSXrayDevicePolicy {
    private static let maximum = 4 * 1024 * 1024

    static func apply(
        files: [String: Data],
        profile: [String: Any],
        compiler: ((String, String) throws -> String)? = nil
    ) throws -> [String: Data] {
        guard let data = files["sing-box.json"], !data.isEmpty, data.count <= maximum,
              String(data: data, encoding: .utf8) != nil,
              var graph = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              var inbounds = graph["inbounds"] as? [[String: Any]], inbounds.count == 1,
              inbounds[0]["type"] as? String == "tun" else {
            throw issue("Native Xray device policy requires one bounded owned TUN graph.")
        }
        // Historical generated wrappers may omit the virtual address/tag.
        // Supply only the product's fixed TUN identity, never a second tunnel.
        if inbounds[0]["tag"] == nil { inbounds[0]["tag"] = "tun-in" }
        if inbounds[0]["address"] == nil {
            inbounds[0]["address"] = ["172.19.0.1/30", "fdfe:dcba:9876::1/126"]
        }
        graph["inbounds"] = inbounds
        let input = try JSONSerialization.data(withJSONObject: graph, options: [.sortedKeys])
        let policy = try JSONSerialization.data(withJSONObject: profile, options: [.sortedKeys])
        guard input.count <= maximum, policy.count <= 256 * 1024 else {
            throw issue("Native Xray device-policy input exceeds its bound.")
        }
        let text = String(decoding: input, as: UTF8.self)
        let captured = String(decoding: policy, as: UTF8.self)
        let output: String
        if let compiler {
            output = try compiler(text, captured)
        } else {
            #if canImport(Libbox)
            var failure: NSError?
            let result: String? = LibboxRouterApplyNativeXrayDevicePolicy(text, captured, &failure)
            if let failure { throw failure }
            guard let result else { throw issue("Native Xray device policy returned no graph.") }
            output = result
            #else
            throw issue("Native Xray device policy requires the pinned Libbox compiler.")
            #endif
        }
        guard !output.isEmpty, output.utf8.count <= maximum,
              let result = try JSONSerialization.jsonObject(with: Data(output.utf8)) as? [String: Any],
              let incoming = result["inbounds"] as? [[String: Any]], incoming.count == 1,
              incoming[0]["type"] as? String == "tun", result["outbounds"] is [[String: Any]] else {
            throw issue("Native Xray device policy returned an invalid graph.")
        }
        var protected = files
        protected["sing-box.json"] = Data(output.utf8)
        return protected
    }

    private static func issue(_ message: String) -> NSError {
        NSError(domain: "RouterVPN.XrayDevicePolicy", code: 1,
                userInfo: [NSLocalizedDescriptionKey: message])
    }
}
