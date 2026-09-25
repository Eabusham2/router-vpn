import Foundation
import CoreFoundation

/// Host-side graph composition only. The PacketTunnel's native Go compiler
/// independently validates the exact original Xray JSON before any engine starts.
/// Protocol fields are carried as the original bytes, never translated to a
/// weaker approximate protocol or accepted solely because a mode label exists.
enum IOSNativeXrayProfile {
    static let modeIDs: Set<String> = ["reality-vision", "reality-pq-vision", "reality-xhttp", "split", "max"]
    static let nativeType = "routervpn-xray"
    private static let allowedAssets: Set<String> = ["sing-box.json", "xray.json", "cert.pem", "stack.json"]

    static func compose(mode: String, files: [String: Data], homeDNS: String) throws -> [String: Data] {
        guard modeIDs.contains(mode), files.keys.allSatisfy({ allowedAssets.contains($0) }),
              let raw = files["xray.json"], !raw.isEmpty, raw.count <= 4 * 1024 * 1024,
              let text = String(data: raw, encoding: .utf8),
              let xray = try JSONSerialization.jsonObject(with: raw) as? [String: Any],
              let incoming = xray["inbounds"] as? [[String: Any]], incoming.count == 1,
              incoming[0]["listen"] as? String == "127.0.0.1", incoming[0]["protocol"] as? String == "socks",
              let listener = integer(incoming[0]["port"]), (1...65535).contains(listener),
              let outgoing = xray["outbounds"] as? [[String: Any]], outgoing.count == 1,
              outgoing[0]["protocol"] as? String == "vless",
              let settings = outgoing[0]["settings"] as? [String: Any],
              let remotes = settings["vnext"] as? [[String: Any]], remotes.count == 1,
              let users = remotes[0]["users"] as? [[String: Any]], users.count == 1,
              let stream = outgoing[0]["streamSettings"] as? [String: Any], stream["security"] as? String == "reality" else {
            throw issue("Native Xray requires one intact generated VLESS/REALITY profile and its owned wrapper.")
        }
        let encryption = users[0]["encryption"] as? String ?? ""
        let pq = ["reality-pq-vision", "reality-xhttp", "max"].contains(mode)
        guard pq ? encryption.hasPrefix("mlkem768x25519plus.") : encryption == "none" else {
            throw issue("The selected Xray mode does not retain its required encryption settings.")
        }
        let network = stream["network"] as? String ?? ""
        if mode == "reality-xhttp" {
            guard ["xhttp", "splithttp"].contains(network), (users[0]["flow"] as? String ?? "").isEmpty else {
                throw issue("XHTTP must retain its native transport rather than a substituted Vision flow.")
            }
        } else {
            guard ["raw", "tcp"].contains(network), users[0]["flow"] as? String == "xtls-rprx-vision" else {
                throw issue("REALITY/Vision must retain its native XTLS flow.")
            }
        }
        var graph: [String: Any]
        if let wrapper = files["sing-box.json"] {
            guard wrapper.count <= 4 * 1024 * 1024, let decoded = try JSONSerialization.jsonObject(with: wrapper) as? [String: Any] else {
                throw issue("Invalid native Xray TUN wrapper.")
            }
            graph = decoded
        } else {
            guard mode == "reality-xhttp", !homeDNS.isEmpty else {
                throw issue("The imported Xray mode lacks its generated TUN wrapper or selected-node DNS.")
            }
            graph = [
                "log": ["level": "warn"],
                "inbounds": [["type": "tun", "tag": "tun-in", "address": ["172.19.0.1/30", "fdfe:dcba:9876::1/126"], "mtu": 1280, "auto_route": true, "strict_route": true, "stack": "gvisor"]],
                "outbounds": [["type": "socks", "tag": "proxy", "server": "127.0.0.1", "server_port": listener, "version": "5"]],
                "dns": ["servers": [["type": "udp", "tag": "home", "server": homeDNS, "detour": "proxy"]], "final": "home"],
                "route": ["rules": [["protocol": "dns", "action": "hijack-dns"]], "final": "proxy", "auto_detect_interface": true],
            ]
        }
        guard var outbounds = graph["outbounds"] as? [[String: Any]] else { throw issue("Missing Xray wrapper routes.") }
        var changed = 0
        for index in outbounds.indices {
            let outbound = outbounds[index]
            if outbound["type"] as? String == nativeType {
                guard Set(outbound.keys) == Set(["type", "tag", "mode", "config_json"]),
                      outbound["config_json"] as? String == text, outbound["mode"] as? String == mode,
                      let tag = outbound["tag"] as? String, !tag.isEmpty else {
                    throw issue("Saved native Xray wrapper no longer matches its exact imported configuration.")
                }
                changed += 1
                continue
            }
            let server = outbound["server"] as? String ?? ""
            if ["127.0.0.1", "::1", "localhost"].contains(server) {
                guard server == "127.0.0.1", outbound["type"] as? String == "socks", outbound["version"] as? String == "5",
                      integer(outbound["server_port"]) == listener,
                      Set(outbound.keys) == Set(["type", "tag", "server", "server_port", "version"]),
                      let tag = outbound["tag"] as? String, !tag.isEmpty else { throw issue("Unowned local helper in the imported Xray graph.") }
                outbounds[index] = ["type": nativeType, "tag": tag, "mode": mode, "config_json": text]
                changed += 1
            }
        }
        guard changed == 1 else { throw issue("Exactly one native Xray route must replace the imported local wrapper.") }
        graph["outbounds"] = outbounds
        guard let native = outbounds.first(where: { $0["type"] as? String == nativeType }),
              let nativeTag = native["tag"] as? String, let route = graph["route"] as? [String: Any],
              route["final"] as? String == nativeTag else { throw issue("The native Xray final route must remain authenticated.") }
        if ["split", "max"].contains(mode) {
            let udp = outbounds.filter { $0["type"] as? String == "hysteria2" }
            let rules = route["rules"] as? [[String: Any]] ?? []
            guard udp.count == 1, let udpTag = udp[0]["tag"] as? String,
                  rules.contains(where: { $0["network"] as? String == "tcp" && $0["outbound"] as? String == nativeTag }),
                  rules.contains(where: { $0["network"] as? String == "udp" && $0["outbound"] as? String == udpTag }) else {
                throw issue("Dual Transport must retain independent Xray TCP and Hysteria2 UDP routes.")
            }
        }
        let encoded = try JSONSerialization.data(withJSONObject: graph, options: [.sortedKeys])
        guard encoded.count <= 4 * 1024 * 1024 else { throw issue("Compiled Xray graph exceeds the native size limit.") }
        var result = files
        result["sing-box.json"] = encoded
        return result
    }
    private static func integer(_ value: Any?) -> Int? {
        guard let number = value as? NSNumber, CFGetTypeID(number) != CFBooleanGetTypeID(), number.doubleValue.isFinite,
              number.doubleValue == Double(number.intValue) else { return nil }
        return number.intValue
    }
    private static func issue(_ message: String) -> NSError { NSError(domain: "RouterVPN.NativeXray", code: 1, userInfo: [NSLocalizedDescriptionKey: message]) }
}
