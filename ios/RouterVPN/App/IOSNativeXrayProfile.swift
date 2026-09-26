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


/// The host only composes the generated graph. PacketTunnel independently runs
/// the strict shared Go compiler before creating any socket or reporting a path.
/// The original helper bytes remain available for exact credential comparison.
enum IOSNativeSIP003Profile {
    static let modeID = "ss-v2ray"
    private static let allowedAssets: Set<String> = ["sing-box.json", "sslocal.json", "cert.pem", "stack.json"]
    private static let helperKeys: Set<String> = ["server", "server_port", "password", "method", "local_address", "local_port", "mode", "plugin", "plugin_opts"]

    static func compose(files: [String: Data]) throws -> [String: Data] {
        guard files.keys.allSatisfy({ allowedAssets.contains($0) }),
              let original = files["sslocal.json"], !original.isEmpty, original.count <= 4 * 1024 * 1024,
              String(data: original, encoding: .utf8) != nil,
              let helper = try JSONSerialization.jsonObject(with: original) as? [String: Any],
              Set(helper.keys) == helperKeys,
              helper["method"] as? String == "2022-blake3-aes-256-gcm",
              helper["plugin"] as? String == "v2ray-plugin", helper["mode"] as? String == "tcp_only",
              helper["local_address"] as? String == "127.0.0.1",
              let localPort = port(helper["local_port"]), let remotePort = port(helper["server_port"]),
              let host = helper["server"] as? String, safeHost(host),
              let password = helper["password"] as? String,
              let key = Data(base64Encoded: password, options: []), key.count == 32, key.base64EncodedString() == password,
              let options = helper["plugin_opts"] as? String else { throw issue() }
        try validateOptions(options)
        guard let wrapper = files["sing-box.json"], !wrapper.isEmpty, wrapper.count <= 4 * 1024 * 1024,
              String(data: wrapper, encoding: .utf8) != nil,
              var graph = try JSONSerialization.jsonObject(with: wrapper) as? [String: Any],
              Set(graph.keys).isSubset(of: ["log", "dns", "inbounds", "outbounds", "route"]),
              let inbounds = graph["inbounds"] as? [[String: Any]], inbounds.count == 1,
              inbounds[0]["type"] as? String == "tun", inbounds[0]["auto_route"] as? Bool == true,
              inbounds[0]["strict_route"] as? Bool == true,
              var outbounds = graph["outbounds"] as? [[String: Any]], (2...3).contains(outbounds.count) else { throw issue() }
        var tcpTag = "", udpTag = "", seen: Set<String> = []
        for index in outbounds.indices {
            let outbound = outbounds[index]
            guard let tag = outbound["tag"] as? String, safeTag(tag), seen.insert(tag).inserted else { throw issue() }
            switch outbound["type"] as? String {
            case "socks", "shadowsocks":
                guard tcpTag.isEmpty else { throw issue() }; tcpTag = tag
                let expected: [String: Any] = ["type": "shadowsocks", "tag": tag, "server": host, "server_port": remotePort,
                    "method": "2022-blake3-aes-256-gcm", "password": password,
                    "plugin": "v2ray-plugin", "plugin_opts": options, "network": "tcp"]
                if outbound["type"] as? String == "socks" {
                    guard Set(outbound.keys) == ["type", "tag", "server", "server_port", "version"],
                          outbound["server"] as? String == "127.0.0.1", port(outbound["server_port"]) == localPort,
                          outbound["version"] as? String == "5" else { throw issue() }
                } else {
                    guard NSDictionary(dictionary: outbound).isEqual(to: expected) else { throw issue() }
                }
                outbounds[index] = expected
            case "hysteria2":
                guard udpTag.isEmpty, let server = outbound["server"] as? String, safeHost(server),
                      port(outbound["server_port"]) != nil, (outbound["detour"] as? String ?? "").isEmpty,
                      let secret = outbound["password"] as? String, !secret.isEmpty,
                      let tls = outbound["tls"] as? [String: Any], tls["enabled"] as? Bool == true,
                      tls["insecure"] as? Bool != true else { throw issue() }
                udpTag = tag
            case "direct":
                guard Set(outbound.keys) == ["type", "tag"] else { throw issue() }
            default: throw issue()
            }
        }
        guard !tcpTag.isEmpty, !udpTag.isEmpty, let route = graph["route"] as? [String: Any],
              route["final"] as? String == tcpTag, let rules = route["rules"] as? [[String: Any]] else { throw issue() }
        var tcp = false, udp = false, dnsRule = false
        for rule in rules {
            if rule["protocol"] as? String == "dns", rule["action"] as? String == "hijack-dns" { dnsRule = true; continue }
            guard Set(rule.keys).isSubset(of: ["network", "action", "outbound"]), rule["action"] as? String == "route" else { throw issue() }
            switch rule["network"] as? String {
            case "tcp": guard !tcp, rule["outbound"] as? String == tcpTag else { throw issue() }; tcp = true
            case "udp": guard !udp, rule["outbound"] as? String == udpTag else { throw issue() }; udp = true
            default: throw issue()
            }
        }
        guard tcp, udp, dnsRule, var dns = graph["dns"] as? [String: Any],
              var servers = dns["servers"] as? [[String: Any]], !servers.isEmpty else { throw issue() }
        for index in servers.indices {
            guard let detour = servers[index]["detour"] as? String, [tcpTag, udpTag].contains(detour) else { throw issue() }
            switch servers[index]["type"] as? String {
            case "udp", "h3", "quic": servers[index]["detour"] = udpTag
            case "tcp", "tls", "https": servers[index]["detour"] = tcpTag
            default: throw issue()
            }
        }
        dns["servers"] = servers; graph["dns"] = dns; graph["outbounds"] = outbounds
        let encoded = try JSONSerialization.data(withJSONObject: graph, options: [.sortedKeys])
        guard encoded.count <= 4 * 1024 * 1024 else { throw issue() }
        var result = files; result["sing-box.json"] = encoded; return result
    }

    private static func port(_ value: Any?) -> Int? {
        guard let n = value as? NSNumber, CFGetTypeID(n) != CFBooleanGetTypeID(), n.doubleValue.isFinite,
              n.doubleValue == Double(n.intValue), (1...65535).contains(n.intValue) else { return nil }
        return n.intValue
    }
    private static func safeTag(_ value: String) -> Bool {
        !value.isEmpty && value.utf8.count <= 96 && value.range(of: "^[A-Za-z0-9_.-]+$", options: .regularExpression) != nil
    }
    private static func safeHost(_ value: String) -> Bool {
        guard !value.isEmpty, value.utf8.count <= 253, !value.contains("%"),
              value.rangeOfCharacter(from: .whitespacesAndNewlines) == nil,
              value.range(of: "^[A-Za-z0-9.:-]+$", options: .regularExpression) != nil else { return false }
        let lower = value.lowercased()
        return !["localhost", "::1", "::", "0.0.0.0"].contains(lower) && !lower.hasPrefix("127.") && !lower.hasPrefix("::ffff:127.") && !lower.contains("..")
    }
    private static func validateOptions(_ value: String) throws {
        guard !value.isEmpty, value.utf8.count <= 16384, !value.contains("\\"),
              value.unicodeScalars.allSatisfy({ $0.value >= 0x20 && $0.value <= 0x7e }) else { throw issue() }
        var seen: Set<String> = [], host = false, path = false, tls = false
        for part in value.split(separator: ";", omittingEmptySubsequences: false) {
            let fields = part.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
            guard let first = fields.first, !first.isEmpty, seen.insert(String(first)).inserted else { throw issue() }
            let option = fields.count == 2 ? String(fields[1]) : ""
            switch first {
            case "tls": guard fields.count == 1 else { throw issue() }; tls = true
            case "host": guard safeHost(option) else { throw issue() }; host = true
            case "path": guard option.hasPrefix("/"), option.utf8.count <= 2048, !option.contains(" ") else { throw issue() }; path = true
            case "mode": guard option == "websocket" else { throw issue() }
            case "mux": guard let count = Int(option), (0...64).contains(count), String(count) == option else { throw issue() }
            case "certRaw": guard let certificate = Data(base64Encoded: option), !certificate.isEmpty, certificate.count <= 8192 else { throw issue() }
            default: throw issue()
            }
        }
        guard host, path, tls else { throw issue() }
    }
    private static func issue() -> NSError {
        NSError(domain: "RouterVPN.NativeSIP003", code: 1, userInfo: [NSLocalizedDescriptionKey:
            "The Shadowsocks/V2Ray mode must retain its exact authenticated TLS/WebSocket TCP graph and independent Hysteria2 UDP route; unowned helpers and substitutions are rejected."])
    }
}
