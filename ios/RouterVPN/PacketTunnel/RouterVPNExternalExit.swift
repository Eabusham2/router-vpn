import Foundation
import Network

struct RouterVPNExternalExitRuntime {
    let protocolName: String
    let expectedPublicIP: String
    let files: [String: Data]
}

enum RouterVPNExternalExitBuilder {
    static func build(profile: [String: Any]) throws -> RouterVPNExternalExitRuntime {
        let kind = string(profile["node_kind"]).lowercased()
        guard kind == "external", let external = profile["external"] as? [String: Any] else {
            throw error("Selected profile is not an external custom node.")
        }
        let protocolName = string(external["protocol"]).lowercased()
        guard ["wireguard", "socks5", "http-connect", "https-connect", "shadowsocks", "hysteria2"].contains(protocolName) else {
            if protocolName == "openvpn" {
                throw error("OpenVPN external exits are unavailable on iOS until Router VPN ships a pinned native Apple OpenVPN dataplane; this build will not fake support through Libbox 1.13.12.")
            }
            if protocolName == "tor-bridge" {
                throw error("Tor bridges are unavailable on iOS until Router VPN ships a native Tor + pluggable-transport PacketTunnel dataplane with dynamic Tor-exit proof.")
            }
            throw error("Unsupported iOS external protocol \(protocolName).")
        }
        let expected = try publicLiteralIP(string(external["expected_public_ip"]), label: "expected public exit IP")
        let custom = try customExit(external: external, protocolName: protocolName)

        var endpoints: [[String: Any]] = []
        var outbounds: [[String: Any]] = []
        if protocolName == "wireguard" { endpoints.append(custom) } else { outbounds.append(custom) }

        let mtu = externalMTU(external: external, protocolName: protocolName)
        let tun: [String: Any] = [
            "type": "tun", "tag": "tun-in",
            "address": ["172.29.94.1/30", "fd29:94::1/126"],
            "mtu": mtu, "auto_route": true, "strict_route": true, "stack": "system"
        ]
        let dns = try selectedDNS(profile)
        let route: [String: Any] = [
            "rules": [["protocol": "dns", "action": "hijack-dns"]],
            "final": "custom-exit", "auto_detect_interface": true
        ]
        let config: [String: Any] = [
            "log": ["level": "warn", "timestamp": true],
            "dns": ["servers": [dns], "final": "selected-dns"],
            "inbounds": [tun], "endpoints": endpoints, "outbounds": outbounds, "route": route
        ]
        let data = try JSONSerialization.data(withJSONObject: config, options: [.prettyPrinted, .sortedKeys])
        guard !data.isEmpty, data.count <= 4 * 1024 * 1024 else { throw error("iOS external Libbox config exceeds safety limit.") }
        return RouterVPNExternalExitRuntime(protocolName: protocolName, expectedPublicIP: expected, files: ["sing-box.json": data])
    }

    private static func customExit(external: [String: Any], protocolName: String) throws -> [String: Any] {
        switch protocolName {
        case "wireguard":
            guard let wg = external["wireguard"] as? [String: Any] else { throw error("External WireGuard block is missing.") }
            let endpoint = string(wg["endpoint"])
            let (server, port) = try literalEndpoint(endpoint, defaultPort: 51820)
            let addresses = strings(wg["addresses"]), allowed = strings(wg["allowed_ips"])
            let privateKey = string(wg["private_key"]), publicKey = string(wg["peer_public_key"])
            guard !addresses.isEmpty, !allowed.isEmpty, !privateKey.isEmpty, !publicKey.isEmpty else { throw error("External WireGuard credentials/routes are incomplete.") }
            var peer: [String: Any] = ["address": server, "port": port, "public_key": publicKey, "allowed_ips": allowed]
            let psk = string(wg["preshared_key"]); if !psk.isEmpty { peer["pre_shared_key"] = psk }
            var value: [String: Any] = ["type": "wireguard", "tag": "custom-exit", "address": addresses, "private_key": privateKey, "peers": [peer]]
            let mtu = int(wg["mtu"]); if mtu >= 1280 && mtu <= 9000 { value["mtu"] = mtu }
            return value
        case "socks5":
            guard let socks = external["socks5"] as? [String: Any] else { throw error("External SOCKS5 block is missing.") }
            let server = try literalServer(string(socks["host"]), label: "SOCKS5 server"), port = try port(socks["port"])
            var value: [String: Any] = ["type": "socks", "tag": "custom-exit", "server": server, "server_port": port, "version": "5"]
            let user = string(socks["username"]), pass = string(socks["password"])
            guard user.isEmpty == pass.isEmpty else { throw error("External SOCKS5 username/password must be supplied together.") }
            if !user.isEmpty { value["username"] = user; value["password"] = pass }
            return value
        case "http-connect", "https-connect":
            let secure = protocolName == "https-connect"
            let key = secure ? "https_connect" : "http_connect"
            guard let proxy = external[key] as? [String: Any] else { throw error("External \(secure ? "HTTPS" : "HTTP") CONNECT block is missing.") }
            let server = try literalServer(string(proxy["host"]), label: "\(secure ? "HTTPS" : "HTTP") CONNECT server"), p = try port(proxy["port"])
            let user = string(proxy["username"]), pass = string(proxy["password"])
            guard user.isEmpty == pass.isEmpty else { throw error("External CONNECT username/password must be supplied together.") }
            var value: [String: Any] = ["type": "http", "tag": "custom-exit", "server": server, "server_port": p]
            if !user.isEmpty { value["username"] = user; value["password"] = pass }
            let sni = string(proxy["tls_server_name"])
            if secure {
                guard safeHostname(sni) else { throw error("External HTTPS CONNECT requires a safe TLS server name for certificate verification.") }
                value["tls"] = ["enabled": true, "server_name": sni]
            } else if !sni.isEmpty {
                throw error("Plain HTTP CONNECT cannot carry TLS metadata; use HTTPS CONNECT instead.")
            }
            return value
        case "shadowsocks":
            guard let ss = external["shadowsocks"] as? [String: Any] else { throw error("External Shadowsocks block is missing.") }
            let server = try literalServer(string(ss["server"]), label: "Shadowsocks server"), p = try port(ss["port"])
            let method = string(ss["method"]).lowercased(), password = string(ss["password"])
            let allowed = ["2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305", "aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305"]
            guard allowed.contains(method), !password.isEmpty else { throw error("External Shadowsocks method/password is invalid.") }
            return ["type": "shadowsocks", "tag": "custom-exit", "server": server, "server_port": p, "method": method, "password": password]
        case "hysteria2":
            guard let hy = external["hysteria2"] as? [String: Any] else { throw error("External Hysteria2 block is missing.") }
            let server = try literalServer(string(hy["server"]), label: "Hysteria2 server"), p = try port(hy["port"])
            let password = string(hy["password"]), sni = string(hy["tls_server_name"])
            guard !password.isEmpty, safeHostname(sni) else { throw error("External Hysteria2 password/TLS server name is invalid.") }
            return ["type": "hysteria2", "tag": "custom-exit", "server": server, "server_port": p, "password": password, "tls": ["enabled": true, "server_name": sni]]
        default: throw error("Unsupported external protocol.")
        }
    }

    private static func selectedDNS(_ profile: [String: Any]) throws -> [String: Any] {
        let mode = string(profile["dns_mode"]).lowercased()
        if mode.isEmpty || mode == "rescue" {
            return ["type": "https", "tag": "selected-dns", "server": "1.1.1.1", "server_port": 443, "path": "/dns-query", "detour": "custom-exit", "tls": ["enabled": true, "server_name": "cloudflare-dns.com"]]
        }
        guard mode != "home" else { throw error("Home AdGuard cannot be claimed for a direct unrelated external iOS exit. Choose Rescue, Fastest, Custom, DoH, DoT or DoH3.") }
        var protocolName = string(profile["dns_protocol"]).lowercased()
        var host = string(profile["dns_host"])
        if mode == "fastest" { host = string(profile["fastest_dns_host"]); protocolName = "udp" }
        if protocolName == "doh" || mode == "doh" { protocolName = "https" }
        if protocolName == "dot" || mode == "dot" { protocolName = "tls" }
        if protocolName == "doh3" || mode == "doh3" { protocolName = "h3" }
        if protocolName.isEmpty { protocolName = "udp" }
        guard ["udp", "tcp", "tls", "https", "h3"].contains(protocolName) else { throw error("Unsupported external iOS DNS protocol \(protocolName).") }
        host = try literalServer(host, label: "DNS server")
        var p = int(profile["dns_port"]); if p <= 0 { p = protocolName == "tls" ? 853 : (protocolName == "https" || protocolName == "h3" ? 443 : 53) }
        var server: [String: Any] = ["type": protocolName, "tag": "selected-dns", "server": host, "server_port": p, "detour": "custom-exit"]
        if ["tls", "https", "h3"].contains(protocolName) {
            let sni = string(profile["dns_server_name"]); guard safeHostname(sni) else { throw error("Encrypted external iOS DNS requires a safe TLS server name.") }
            server["tls"] = ["enabled": true, "server_name": sni]
        }
        if protocolName == "https" || protocolName == "h3" { let path = string(profile["dns_path"]); server["path"] = path.isEmpty ? "/dns-query" : path }
        return server
    }

    private static func externalMTU(external: [String: Any], protocolName: String) -> Int {
        if protocolName == "wireguard", let wg = external["wireguard"] as? [String: Any] { let value = int(wg["mtu"]); if value >= 1280 && value <= 9000 { return value } }
        return 1280
    }
    private static func literalEndpoint(_ value: String, defaultPort: Int) throws -> (String, Int) {
        let text = value.trimmingCharacters(in: .whitespacesAndNewlines)
        if text.hasPrefix("[") , let close = text.firstIndex(of: "]") {
            let host = String(text[text.index(after: text.startIndex)..<close]); let rest = text[text.index(after: close)...]
            let p = rest.hasPrefix(":") ? Int(rest.dropFirst()) ?? 0 : defaultPort
            return (try literalServer(host, label: "WireGuard server"), try port(p))
        }
        if let colon = text.lastIndex(of: ":"), !text[..<colon].contains(":") {
            let host = String(text[..<colon]), p = Int(text[text.index(after: colon)...]) ?? 0
            return (try literalServer(host, label: "WireGuard server"), try port(p))
        }
        return (try literalServer(text, label: "WireGuard server"), defaultPort)
    }
    private static func literalServer(_ value: String, label: String) throws -> String {
        let text = value.trimmingCharacters(in: CharacterSet(charactersIn: " []\t\r\n"))
        guard IPv4Address(text) != nil || IPv6Address(text) != nil else { throw error("\(label) must be a literal IP so setup cannot leak pre-tunnel DNS.") }
        return text
    }
    private static func publicLiteralIP(_ value: String, label: String) throws -> String {
        let text = try literalServer(value, label: label)
        if let ip = IPv4Address(text) { let b = [UInt8](ip.rawValue); guard b.count == 4 else { throw error("Invalid \(label).") }; let privateIP = b[0] == 10 || b[0] == 127 || (b[0] == 172 && b[1] >= 16 && b[1] <= 31) || (b[0] == 192 && b[1] == 168) || (b[0] == 169 && b[1] == 254) || b[0] >= 224 || b == [0,0,0,0]; guard !privateIP else { throw error("\(label) must be public.") }; return text }
        if let ip = IPv6Address(text) { let b = [UInt8](ip.rawValue); guard b.count == 16 else { throw error("Invalid \(label).") }; let allZero = b.allSatisfy { $0 == 0 }, loopback = b.dropLast().allSatisfy { $0 == 0 } && b.last == 1, ula = (b[0] & 0xfe) == 0xfc, linkLocal = b[0] == 0xfe && (b[1] & 0xc0) == 0x80, multicast = b[0] == 0xff; guard !(allZero || loopback || ula || linkLocal || multicast) else { throw error("\(label) must be public.") }; return text }
        throw error("Invalid \(label).")
    }
    private static func port(_ value: Any?) throws -> Int { let p = int(value); guard p >= 1 && p <= 65535 else { throw error("External server port is invalid.") }; return p }
    private static func int(_ value: Any?) -> Int { if let i = value as? Int { return i }; if let n = value as? NSNumber { return n.intValue }; if let s = value as? String { return Int(s) ?? 0 }; return 0 }
    private static func string(_ value: Any?) -> String { (value as? String ?? "").trimmingCharacters(in: .whitespacesAndNewlines) }
    private static func strings(_ value: Any?) -> [String] { (value as? [String] ?? []).map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }.filter { !$0.isEmpty } }
    private static func safeHostname(_ value: String) -> Bool { !value.isEmpty && value.count <= 253 && value.range(of: "^[A-Za-z0-9.-]+$", options: .regularExpression) != nil && !value.hasPrefix(".") && !value.hasSuffix(".") }
    private static func error(_ message: String) -> NSError { NSError(domain: "RouterVPN.ExternalExit", code: 1, userInfo: [NSLocalizedDescriptionKey: message]) }
}
