import Foundation
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

/// One Libbox TUN, not two competing system VPNs. The exit's transport sockets
/// are dialled by the selected packet endpoint or authenticated proxy outbound. Neither a saved graph nor a
/// successful engine start is connection proof; PacketTunnel proves both nodes.
enum RouterVPNMultihopGraph {
    static let entryProofPort = 1098
    static let entryTag = "routervpn-hop-entry"
    static let entryProofTag = "routervpn-hop-entry-proof"
    static let entryPrivateTag = "routervpn-hop-entry-private"
    static let nativeXrayModes = ["reality-vision", "reality-pq-vision", "reality-xhttp"]
    static let supportedExitModes = ["wg", "awg2-fast", "awg2-strong", "shadowsocks", "hysteria2"] + nativeXrayModes
    private static let maxBytes = 4 * 1024 * 1024

    static func build(entryEndpoint: [String: Any], entryProfile: [String: Any],
                      exitProfile: [String: Any], exitMode: String,
                      files: [String: Data]) throws -> [String: Data] {
        guard supportedExitModes.contains(exitMode),
              let entryID = entryProfile["id"] as? String, !entryID.isEmpty,
              let exitID = exitProfile["id"] as? String, !exitID.isEmpty,
              entryID != exitID,
              entryProfile["node_kind"] as? String ?? "router-vpn" == "router-vpn",
              exitProfile["node_kind"] as? String ?? "router-vpn" == "router-vpn",
              let entryProof = entryProfile["node_proof_id"] as? String,
              let exitProof = exitProfile["node_proof_id"] as? String,
              fullMatch(entryProof, "[0-9a-f]{64}"), fullMatch(exitProof, "[0-9a-f]{64}"),
              entryProof != exitProof else {
            throw issue("Multihop requires two different paired Router VPN nodes and a supported exit transport.")
        }
        // No saved setting is silently dropped when building the smaller graph.
        for profile in [entryProfile, exitProfile] {
            struct Performance: Decodable { let daita_enabled: Bool?; let jumbo_tun: Bool? }
            _ = try JSONDecoder().decode(Performance.self, from: JSONSerialization.data(withJSONObject: profile))
            // Both policies are applied after the final MTU/LAN graph is built.
            // The shared native compiler rejects unsafe Jumbo compositions.
            let start = (profile["start_layer"] as? String ?? "off").lowercased()
            guard ["", "off", "none", "disabled"].contains(start) else {
                throw issue("This multihop graph does not yet compose an additional Start Layer; turn it off before selecting this graph.")
            }
        }
        let packetEntry = ["wireguard", "routervpn-amneziawg"].contains(entryEndpoint["type"] as? String ?? "")
        let entry = try packetEntry ? wireGuardEndpoint(entryEndpoint, tag: entryTag) : proxyEntry(entryEndpoint, tag: entryTag)
        let privateHost = entryProfile["socks_host"] as? String ?? ""
        guard privateIP(privateHost), let privatePort = try integer(entryProfile["socks_port"]),
              (1...65535).contains(privatePort) else {
            throw issue("Entry-node proof requires the paired node's literal private SOCKS endpoint.")
        }
        var privateProxy: [String: Any] = ["type": "socks", "tag": entryPrivateTag,
            "server": privateHost, "server_port": privatePort, "version": "5", "detour": entryTag]
        let username = entryProfile["socks_username"] as? String ?? ""
        let password = entryProfile["socks_password"] as? String ?? ""
        guard username.isEmpty == password.isEmpty, username.utf8.count <= 255, password.utf8.count <= 255 else {
            throw issue("Entry private SOCKS credentials are incomplete or oversized.")
        }
        if !username.isEmpty { privateProxy["username"] = username; privateProxy["password"] = password }

        let helpers: Set<String> = ["wg.conf", "awg.conf", "wg-socks.conf", "awg-socks.conf",
            "xray.json", "outer-xray.json", "sslocal.json", "middle-sing-box.json", "chain.env"]
        guard helpers.isDisjoint(with: files.keys), let data = files["sing-box.json"],
              !data.isEmpty, data.count <= maxBytes,
              let original = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let inbounds = original["inbounds"] as? [[String: Any]], inbounds.count == 1,
              var tun = inbounds.first, tun["type"] as? String == "tun", tun["auto_route"] as? Bool == true,
              let route = original["route"] as? [String: Any], route["final"] as? String == "proxy",
              let outbounds = original["outbounds"] as? [[String: Any]] else {
            throw issue("The exit must contain one self-contained full-device native packet or encrypted proxy profile.")
        }
        // Only the generated full-device policy is transformed. A saved split
        // route, bypass or DNS rule must never disappear as a side effect.
        let rules = route["rules"] as? [[String: Any]] ?? []
        guard rules.allSatisfy({ Set($0.keys).isSubset(of: ["protocol", "action"]) &&
                  $0["protocol"] as? String == "dns" && $0["action"] as? String == "hijack-dns" }),
              route["rule_set"] == nil,
              tun["route_address"] == nil, tun["route_exclude_address"] == nil,
              tun["route_address_set"] == nil, tun["route_exclude_address_set"] == nil else {
            throw issue("Multihop cannot silently replace saved split/bypass routing policy.")
        }
        let originalEndpoints = original["endpoints"] as? [[String: Any]] ?? []
        guard original["endpoints"] == nil || original["endpoints"] is [[String: Any]] else {
            throw issue("Exit endpoints must be an explicit array, not an ignored malformed field.")
        }
        var proxy: [String: Any]
        if ["wg", "awg2-fast", "awg2-strong"].contains(exitMode) {
            guard originalEndpoints.count == 1, let exitEndpoint = originalEndpoints.first,
                  outbounds.isEmpty else {
                throw issue("WireGuard exit must contain exactly one owned endpoint and no alternate outbound.")
            }
            proxy = try wireGuardEndpoint(exitEndpoint, tag: "proxy")
            let expectedType = exitMode == "wg" ? "wireguard" : "routervpn-amneziawg"
            guard proxy["type"] as? String == expectedType else { throw issue("Exit transport label does not match its native endpoint.") }
            if packetEntry {
                guard let entryPeer = (entry["peers"] as? [[String: Any]])?.first,
                      let exitPeer = (proxy["peers"] as? [[String: Any]])?.first,
                      entryPeer["public_key"] as? String != exitPeer["public_key"] as? String else {
                    throw issue("Two WireGuard hops cannot use the same server key under different node labels.")
                }
            }
        } else if nativeXrayModes.contains(exitMode) {
            let proxies = outbounds.filter { $0["tag"] as? String == "proxy" }
            guard originalEndpoints.isEmpty, proxies.count == 1, let native = proxies.first,
                  native["mode"] as? String == exitMode,
                  outbounds.allSatisfy({ $0["tag"] as? String == "proxy" ||
                      ($0["type"] as? String == "direct" && Set($0.keys) == Set(["type", "tag"])) }) else {
                throw issue("Native Xray exit lost its exact protocol or contains another routing owner.")
            }
            // xrayFiles already ran the shared strict native compiler. Keep its
            // original authentication bytes; add only this graph's entry detour.
            proxy = try proxyEntry(native, tag: "proxy")
        } else {
            let proxies = outbounds.filter { $0["tag"] as? String == "proxy" }
            guard originalEndpoints.isEmpty, proxies.count == 1, let exitProxy = proxies.first,
                  exitProxy["type"] as? String == exitMode,
                  let server = exitProxy["server"] as? String, serverIP(server),
                  let serverPort = try integer(exitProxy["server_port"]), (1...65535).contains(serverPort),
                  outbounds.allSatisfy({ $0["tag"] as? String == "proxy" ||
                      (["direct", "block"].contains($0["type"] as? String ?? "")) }) else {
                throw issue("Exit transport must match its profile and use a literal endpoint; no unowned mixed helper graph is accepted.")
            }
            proxy = exitProxy
            guard let secret = proxy["password"] as? String, !secret.isEmpty else { throw issue("Exit transport has no credential.") }
            if exitMode == "hysteria2" {
                guard let tls = proxy["tls"] as? [String: Any], tls["enabled"] as? Bool == true,
                      tls["insecure"] == nil || tls["insecure"] as? Bool == false else {
                    throw issue("Hysteria2 multihop requires verified TLS, not an insecure certificate bypass.")
                }
            }
        }
        for key in ["detour", "bind_interface", "inet4_bind_address", "inet6_bind_address", "routing_mark", "network_strategy", "domain_resolver"] {
            guard proxy[key] == nil else { throw issue("Exit profile already owns dial policy; refusing to replace a pre-existing route.") }
        }
        // Preserve the encrypted exit transport, TLS pin and obfuscation. Only
        // replace its upstream dialer; never fall back to a direct exit socket.
        proxy["detour"] = entryTag
        tun.removeValue(forKey: "interface_name")
        tun.removeValue(forKey: "route_exclude_address")
        tun.removeValue(forKey: "route_address")
        if tun["tag"] == nil { tun["tag"] = "tun-in" }
        tun["strict_route"] = true
        tun["stack"] = "system"
        tun["address"] = ["172.29.94.1/30", "fd29:94::1/126"]
        // Initial MTU is conservative; a fixed policy is applied afterward by
        // the shared PacketTunnel MTU helper, not presented as Auto measurement.
        tun["mtu"] = 1280
        guard let dns = original["dns"] as? [String: Any] else { throw issue("Missing exit DNS policy.") }
        // Preserve a hostname resolver and its bounded literal bootstrap. Both
        // are re-owned by the same encrypted exit; no direct/system lookup.
        var dnsPolicy = try exitDNS(dns)
        var routeRules: [[String: Any]] = [
            ["inbound": [entryProofTag], "action": "route", "outbound": entryPrivateTag],
            ["protocol": "dns", "action": "hijack-dns"]
        ]
        if entryProfile["ipv6_mode"] as? String == "off" || exitProfile["ipv6_mode"] as? String == "off" {
            // Reject client IPv6 inside the owned TUN, not by omitting the v6
            // default route (which would leak it to the physical interface).
            routeRules.append(["inbound": [tun["tag"] as? String ?? "tun-in"], "ip_version": 6, "action": "reject"])
            dnsPolicy["strategy"] = "ipv4_only"
        }
        let packetExit = ["wg", "awg2-fast", "awg2-strong"].contains(exitMode)
        let endpoints = (packetEntry ? [entry] : []) + (packetExit ? [proxy] : [])
        let proxyOutbounds = (packetExit ? [] : [proxy]) + [privateProxy] + (packetEntry ? [] : [entry])
        let config: [String: Any] = [
            "log": ["level": "warn"],
            "dns": dnsPolicy,
            "endpoints": endpoints,
            "outbounds": proxyOutbounds,
            "inbounds": [tun, ["type": "mixed", "tag": entryProofTag,
                "listen": "127.0.0.1", "listen_port": entryProofPort]],
            "route": ["auto_detect_interface": true, "final": "proxy", "rules": routeRules]
        ]
        let encoded = try JSONSerialization.data(withJSONObject: config, options: [.sortedKeys])
        guard encoded.count <= maxBytes else { throw issue("Composed multihop configuration exceeds the safety limit.") }
        var result = files
        result["sing-box.json"] = encoded
        return result
    }

    /// The same native WG endpoint supports direct and nested packet graphs.
    /// DNS is a separate Libbox transport, never an address-only OS DNS claim.
    static func wireGuardFiles(endpoint: [String: Any], profile: [String: Any], dnsServers: [String]) throws -> [String: Data] {
        guard dnsServers.count == 1, let importedDNS = dnsServers.first, serverIP(importedDNS) else {
            throw issue("WireGuard requires exactly one bounded literal imported DNS resolver.")
        }
        let dns = try selectedDNS(profile, importedDNS: importedDNS, requireImportedMatch: true)
        let exit = try wireGuardEndpoint(endpoint, tag: "proxy")
        let config: [String: Any] = [
            "log": ["level": "warn"],
            "inbounds": [["type": "tun", "tag": "tun-in", "auto_route": true, "strict_route": true,
                "stack": "system", "address": ["172.29.94.1/30", "fd29:94::1/126"], "mtu": 1280]],
            "endpoints": [exit], "outbounds": [[String: Any]](),
            "dns": dns,
            "route": ["auto_detect_interface": true, "final": "proxy", "rules": [["protocol": "dns", "action": "hijack-dns"]]]
        ]
        return ["sing-box.json": try JSONSerialization.data(withJSONObject: config, options: [.sortedKeys])]
    }

    /// Compile before any engine or private session is created. The closure is
    /// the pinned native compiler in production, not a host-side approximation.
    static func xrayFiles(assets: [String: String], mode: String, profile: [String: Any],
                          compiler: (String, String) throws -> String) throws -> [String: Data] {
        guard nativeXrayModes.contains(mode), (1...2).contains(assets.count),
              Set(assets.keys).isSubset(of: ["sing-box.json", "xray.json"]),
              let encoded = assets["xray.json"], encoded.utf8.count <= 6 * 1024 * 1024,
              let original = Data(base64Encoded: encoded, options: []),
              !original.isEmpty, original.count <= maxBytes,
              original.base64EncodedString() == encoded,
              let originalText = String(data: original, encoding: .utf8) else {
            throw issue("The exact selected Xray exit assets are missing, ambiguous or oversized.")
        }
        let payload = try JSONSerialization.data(withJSONObject: assets, options: [.sortedKeys])
        guard payload.count <= 8 * 1024 * 1024 else { throw issue("Native exit input exceeds its bound.") }
        let compiled = try compiler(String(decoding: payload, as: UTF8.self), mode)
        guard !compiled.isEmpty, compiled.utf8.count <= maxBytes,
              var graph = try JSONSerialization.jsonObject(with: Data(compiled.utf8)) as? [String: Any],
              let ins = graph["inbounds"] as? [[String: Any]], ins.count == 1,
              ins[0]["type"] as? String == "tun", ins[0]["auto_route"] as? Bool == true,
              ins[0]["strict_route"] as? Bool == true,
              let outs = graph["outbounds"] as? [[String: Any]],
              let route = graph["route"] as? [String: Any], route["final"] as? String == "proxy" else {
            throw issue("Native exit compilation lost its one-TUN graph.")
        }
        let native = outs.filter { $0["type"] as? String == "routervpn-xray" }
        guard native.count == 1, native[0]["tag"] as? String == "proxy",
              native[0]["mode"] as? String == mode,
              native[0]["config_json"] as? String == originalText else {
            throw issue("Native exit compilation changed the captured protocol or authentication.")
        }
        _ = try proxyEntry(native[0], tag: "proxy")
        // An explicit saved DNS policy wins. Otherwise retain valid imported
        // DNS, falling back only to this node's own AdGuard for legacy raw XHTTP.
        let savedMode = try setting(profile, "dns_mode", "").lowercased()
        if !savedMode.isEmpty || graph["dns"] == nil {
            let v4 = try setting(profile, "adguard_ipv4", "")
            let home = try v4.isEmpty ? setting(profile, "adguard_ipv6", "") : v4
            var captured = profile
            if savedMode.isEmpty { captured["dns_mode"] = "home" }
            graph["dns"] = try selectedDNS(captured, importedDNS: home, requireImportedMatch: false)
        } else {
            guard let dns = graph["dns"] as? [String: Any] else { throw issue("Malformed imported exit DNS.") }
            graph["dns"] = try exitDNS(dns)
        }
        let result = try JSONSerialization.data(withJSONObject: graph, options: [.sortedKeys])
        guard result.count <= maxBytes else { throw issue("Native exit graph exceeds its bound.") }
        // Original xray.json is carried INSIDE the native outbound, never as a
        // separately launchable file, process or second system VPN.
        return ["sing-box.json": result]
    }

    private static func selectedDNS(_ profile: [String: Any], importedDNS: String,
                                    requireImportedMatch: Bool) throws -> [String: Any] {
        let mode = try setting(profile, "dns_mode", "").lowercased()
        var host = "", type = "udp", port = 53
        let requestedPort = try integer(profile["dns_port"])
        var name = try setting(profile, "dns_server_name", "")
        var path = try setting(profile, "dns_path", "/dns-query")
        switch mode {
        case "": host = importedDNS
        case "home":
            let v4 = try setting(profile, "adguard_ipv4", "")
            host = try v4.isEmpty ? setting(profile, "adguard_ipv6", "") : v4
        case "custom":
            host = try setting(profile, "dns_host", "")
            type = try setting(profile, "dns_protocol", "udp").lowercased()
            if type.isEmpty { type = "udp" }
            guard ["udp", "tcp"].contains(type) else { throw issue("Custom DNS requires explicit UDP or TCP.") }
            port = requestedPort ?? 53
        case "dot", "doh", "doh3":
            host = try setting(profile, "dns_host", "")
            type = ["dot": "tls", "doh": "https", "doh3": "h3"][mode]!
            port = requestedPort ?? (mode == "dot" ? 853 : 443)
        case "fastest", "rescue":
            let saved = try setting(profile, "fastest_dns_host", "")
            let results = (profile["dns_results"] as? [[String: Any]] ?? []).filter {
                $0["working"] as? Bool == true && ($0["latency_ms"] as? Double ?? -1).isFinite && ($0["latency_ms"] as? Double ?? -1) >= 0
            }.sorted { ($0["latency_ms"] as? Double ?? .greatestFiniteMagnitude) < ($1["latency_ms"] as? Double ?? .greatestFiniteMagnitude) }
            host = saved.isEmpty ? results.first?["address"] as? String ?? "" : saved
            if host.isEmpty && mode == "rescue" { host = "1.1.1.1" }
        default: throw issue("Unknown saved native DNS policy.")
        }
        guard (1...65535).contains(port), serverIP(host) || hostname(host) else { throw issue("The selected DNS host or port is invalid.") }
        if requireImportedMatch && type == "udp", port == 53, serverIP(host) {
            guard host == importedDNS else { throw issue("WireGuard DNS does not match the frozen exit-node DNS selection.") }
        }
        var server: [String: Any] = ["type": type, "tag": "selected-dns", "server": host, "server_port": port, "detour": "proxy"]
        if ["tls", "https", "h3"].contains(type) {
            if name.isEmpty && hostname(host) { name = host }
            guard hostname(name) else { throw issue("Encrypted DNS requires its explicit TLS server name.") }
            server["tls"] = ["enabled": true, "server_name": name]
        }
        if ["https", "h3"].contains(type) {
            if path.isEmpty { path = "/dns-query" }
            guard path.hasPrefix("/"), path.utf8.count <= 2048, path.unicodeScalars.allSatisfy({ $0.value > 0x20 && $0.value < 0x7f }) else { throw issue("Invalid encrypted DNS request path.") }
            server["path"] = path
        }
        var servers: [[String: Any]] = []
        if !literalIP(host) {
            let choices = ["fastest_dns_host", "adguard_ipv4", "adguard_ipv6"]
            var bootstrap = ""
            for key in choices {
                let candidate = try setting(profile, key, "")
                if serverIP(candidate) { bootstrap = candidate; break }
            }
            guard !bootstrap.isEmpty else { throw issue("Resolver hostname requires a literal saved bootstrap inside the encrypted exit.") }
            servers.append(["type": "udp", "tag": "routervpn-bootstrap-dns", "server": bootstrap, "server_port": 53, "detour": "proxy"])
            server["domain_resolver"] = "routervpn-bootstrap-dns"
        }
        servers.append(server)
        return try exitDNS(["servers": servers, "final": "selected-dns"])
    }

    /// Apply a saved IPv6 preference to the existing single-node WG graph.
    static func singleWireGuardPolicy(_ files: [String: Data], profile: [String: Any]) throws -> [String: Data] {
        struct Policy: Decodable { let ipv6_mode: String?; let daita_enabled: Bool?; let jumbo_tun: Bool? }
        let policy = try JSONDecoder().decode(Policy.self, from: JSONSerialization.data(withJSONObject: profile))
        guard policy.jumbo_tun != true else { throw issue("Jumbo requires a compatible proxy TUN, not a raw WG/AWG endpoint.") }
        let ipv6 = (policy.ipv6_mode ?? "on").trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard ["", "on", "auto", "off"].contains(ipv6) else { throw issue("Unknown saved IPv6 policy.") }
        guard ipv6 == "off" else { return files }
        guard let data = files["sing-box.json"], data.count <= maxBytes,
              var root = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let inbounds = root["inbounds"] as? [[String: Any]], inbounds.count == 1,
              inbounds[0]["tag"] as? String == "tun-in", inbounds[0]["type"] as? String == "tun",
              var route = root["route"] as? [String: Any], route["final"] as? String == "proxy",
              let rules = route["rules"] as? [[String: Any]], var dns = root["dns"] as? [String: Any] else { throw issue("Native WG lost its one-TUN graph.") }
        route["rules"] = [["inbound": ["tun-in"], "ip_version": 6, "action": "reject"]] + rules
        dns["strategy"] = "ipv4_only"; root["route"] = route; root["dns"] = dns
        var result = files; result["sing-box.json"] = try JSONSerialization.data(withJSONObject: root, options: [.sortedKeys]); return result
    }

    /// The host and extension both validate the same no-fallback DNS graph.
    private static func exitDNS(_ source: [String: Any]) throws -> [String: Any] {
        guard let final = source["final"] as? String, fullMatch(final, "[A-Za-z0-9._-]{1,96}"),
              var servers = source["servers"] as? [[String: Any]], (1...2).contains(servers.count),
              source["rules"] == nil || (source["rules"] as? [Any])?.isEmpty == true,
              let selected = servers.firstIndex(where: { $0["tag"] as? String == final }) else { throw issue("DNS needs an exact owned final resolver and no custom routing rules.") }
        var tags: Set<String> = []
        for index in servers.indices {
            guard let tag = servers[index]["tag"] as? String, fullMatch(tag,"[A-Za-z0-9._-]{1,96}"), tags.insert(tag).inserted,
                  let host = servers[index]["server"] as? String, serverIP(host) || hostname(host),
                  let type = servers[index]["type"] as? String, ["udp", "tcp", "tls", "https", "h3"].contains(type),
                  (1...65535).contains(try integer(servers[index]["server_port"]) ?? 53),
                  (servers[index]["detour"] as? String) == "proxy" else { throw issue("DNS has an invalid or unowned encrypted route.") }
            for field in ["bind_interface", "inet4_bind_address", "inet6_bind_address", "routing_mark", "network_strategy", "network_type", "fallback_network_type"] {
                guard servers[index][field] == nil else { throw issue("DNS cannot replace a pre-existing underlay dial policy.") }
            }
            if ["tls", "https", "h3"].contains(type) {
                guard let tls = servers[index]["tls"] as? [String: Any], tls["enabled"] as? Bool == true,
                      tls["insecure"] == nil || tls["insecure"] as? Bool == false,
                      let name = tls["server_name"] as? String, hostname(name) else { throw issue("DNS requires verified TLS with the saved server name.") }
            }
            servers[index]["detour"] = "proxy"
        }
        let host = servers[selected]["server"] as! String
        if literalIP(host) {
            guard servers.count == 1, servers[selected]["domain_resolver"] == nil else { throw issue("Literal DNS must not retain an unowned bootstrap resolver.") }
        } else {
            guard servers.count == 2, let bootstrapTag = servers[selected]["domain_resolver"] as? String, bootstrapTag != final,
                  let bootstrap = servers.first(where: { $0["tag"] as? String == bootstrapTag }),
                  let address = bootstrap["server"] as? String, serverIP(address), bootstrap["type"] as? String == "udp",
                  (try integer(bootstrap["server_port"]) ?? 53) == 53, bootstrap["domain_resolver"] == nil else { throw issue("DNS hostname bootstrap must be literal, nonrecursive and owned by the same exit.") }
        }
        var result = source; result["servers"] = servers; return result
    }
    private static func setting(_ profile: [String: Any], _ key: String, _ fallback: String) throws -> String {
        guard let value = profile[key] else { return fallback }
        guard let value = value as? String else { throw issue("Invalid saved \(key) type.") }
        return value.trimmingCharacters(in: .whitespacesAndNewlines)
    }
    private static func hostname(_ value: String) -> Bool {
        guard !value.isEmpty, value.utf8.count <= 253, !literalIP(value), value.contains("."),
              value.unicodeScalars.allSatisfy({ $0.isASCII }), !value.hasSuffix(".") else { return false }
        return value.split(separator: ".", omittingEmptySubsequences: false).allSatisfy {
            fullMatch(String($0), "[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?")
        } && value.unicodeScalars.contains { CharacterSet.letters.contains($0) }
    }

    /// Both hops have independent userspace WG devices. Only the final graph
    /// composer adds the exit detour; imported bind/detour policy is forbidden.
    private static func wireGuardEndpoint(_ value: [String: Any], tag: String) throws -> [String: Any] {
        let keys: Set<String> = ["type", "tag", "address", "private_key", "peers", "mtu", "system", "amnezia"]
        let peerKeys: Set<String> = ["address", "port", "public_key", "pre_shared_key", "allowed_ips", "persistent_keepalive_interval"]
        guard Set(value.keys).isSubset(of: keys), ["wireguard", "routervpn-amneziawg"].contains(value["type"] as? String ?? ""),
              value["system"] == nil || value["system"] as? Bool == false,
              validKey(value["private_key"]),
              let peers = value["peers"] as? [[String: Any]], peers.count == 1, let peer = peers.first,
              Set(peer.keys).isSubset(of: peerKeys), validKey(peer["public_key"]),
              peer["pre_shared_key"] == nil || validKey(peer["pre_shared_key"]),
              let host = peer["address"] as? String, serverIP(host),
              let port = try integer(peer["port"]), (1...65535).contains(port),
              let addresses = value["address"] as? [String], !addresses.isEmpty, addresses.allSatisfy(validPrefix),
              let allowed = peer["allowed_ips"] as? [String], Set(allowed) == Set(["0.0.0.0/0", "::/0"]), allowed.count == 2,
              (1280...9000).contains(try integer(value["mtu"]) ?? 1280),
              (0...65535).contains(try integer(peer["persistent_keepalive_interval"]) ?? 0) else {
            throw issue("Each WireGuard hop needs one valid, literal-IP, dual-stack full-route peer with no unowned dial policy.")
        }
        if value["type"] as? String == "routervpn-amneziawg" {
            guard let parameters = value["amnezia"] as? [String: String], Set(parameters.keys) == Set(["jc","jmin","jmax","s1","s2","s3","s4","h1","h2","h3","h4"]) else { throw issue("Native AWG lost its exact obfuscation parameters.") }
            for key in ["jc","jmin","jmax","s1","s2","s3","s4"] {
                guard let text = parameters[key], fullMatch(text,"[0-9]+"), let n = Int(text), (0...(key == "jc" ? 128 : 1280)).contains(n) else { throw issue("Native AWG obfuscation exceeds its bounded policy.") }
            }
            guard Int(parameters["jmin"]!)! <= Int(parameters["jmax"]!)!, Int(parameters["s1"]!)! + 148 != Int(parameters["s2"]!)! + 92 else { throw issue("Inconsistent native AWG padding policy.") }
            var ranges: [ClosedRange<UInt32>] = []
            for key in ["h1","h2","h3","h4"] {
                let parts = parameters[key]!.split(separator:"-",omittingEmptySubsequences:false)
                guard (1...2).contains(parts.count), parts.allSatisfy({ fullMatch(String($0),"[0-9]+") }),
                      let low = UInt32(parts[0]), let high = UInt32(parts.last!), low > 4, high >= low else { throw issue("Invalid native AWG header range.") }
                let range = low...high
                guard !ranges.contains(where: { $0.overlaps(range) }) else { throw issue("Overlapping native AWG header ranges.") }; ranges.append(range)
            }
        } else if value["amnezia"] != nil { throw issue("Standard WireGuard cannot discard AWG parameters.") }
        var endpoint = value
        endpoint["tag"] = tag; endpoint["system"] = false
        return endpoint
    }
    /// The shared native compiler resolves entry-owned certificate assets
    /// before this point. The host graph keeps the self-contained outbound
    /// intact and refuses any attempt to replace its physical dial ownership.
    private static func proxyEntry(_ value: [String: Any], tag: String) throws -> [String: Any] {
        let mode = value["type"] as? String ?? ""
        if mode == "routervpn-xray" {
            guard Set(value.keys) == Set(["type", "tag", "mode", "config_json"]),
                  let rawMode = value["mode"] as? String,
                  ["reality-vision", "reality-pq-vision", "reality-xhttp"].contains(rawMode),
                  let text = value["config_json"] as? String, !text.isEmpty, text.utf8.count <= maxBytes,
                  let native = try JSONSerialization.jsonObject(with: Data(text.utf8)) as? [String: Any],
                  Set(native.keys).isSubset(of: ["log", "inbounds", "outbounds"]),
                  let outs = native["outbounds"] as? [[String: Any]], outs.count == 1,
                  outs[0]["protocol"] as? String == "vless",
                  let settings = outs[0]["settings"] as? [String: Any],
                  let peers = settings["vnext"] as? [[String: Any]], peers.count == 1,
                  let host = peers[0]["address"] as? String, serverIP(host),
                  let port = try integer(peers[0]["port"]), (1...65535).contains(port) else {
                throw issue("Native Xray entry must retain its exact compiled protocol and literal owned server.")
            }
            // LibboxRouterCompileProxyEntry has verified raw REALITY/PQ fields.
            // The mandatory shared MTU/controller checks revalidate these bytes
            // before startup; this graph operation cannot substitute credentials.
            var result = value; result["tag"] = tag
            return result
        }
        var allowed: Set<String> = ["type", "tag", "server", "server_port", "password", "network"]
        if mode == "shadowsocks" { allowed.formUnion(["method", "udp_over_tcp"]) }
        else if mode == "hysteria2" { allowed.formUnion(["tls", "obfs", "up_mbps", "down_mbps"]) }
        else { throw issue("This entry has no authenticated native TCP/UDP proxy implementation.") }
        guard Set(value.keys).isSubset(of: allowed),
              let host = value["server"] as? String, serverIP(host),
              let port = try integer(value["server_port"]), (1...65535).contains(port),
              let password = value["password"] as? String, !password.isEmpty, password.utf8.count <= 4096,
              !password.utf8.contains(0), value["network"] == nil || value["network"] as? String == "",
              !hasHostPath(value) else {
            throw issue("Proxy entry lost its own bounded credentials, literal server or TCP/UDP path.")
        }
        if mode == "shadowsocks" {
            guard ["2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305", "aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305"].contains(value["method"] as? String ?? "") else {
                throw issue("Shadowsocks entry requires an authenticated cipher.")
            }
        } else {
            guard let tls = value["tls"] as? [String: Any], tls["enabled"] as? Bool == true,
                  tls["insecure"] == nil || tls["insecure"] as? Bool == false else {
                throw issue("Hysteria2 entry requires its own verified TLS identity.")
            }
        }
        var result = value; result["tag"] = tag
        return result
    }
    private static func hasHostPath(_ value: Any) -> Bool {
        if let object = value as? [String: Any] {
            return object.contains { key, value in key == "path" || key.hasSuffix("_path") || hasHostPath(value) }
        }
        if let array = value as? [Any] { return array.contains(where: hasHostPath) }
        return false
    }

    private static func validKey(_ value: Any?) -> Bool {
        guard let key = value as? String, let data = Data(base64Encoded: key, options: []), data.count == 32 else { return false }
        return data.contains { $0 != 0 }
    }
    private static func validPrefix(_ value: String) -> Bool {
        let parts = value.split(separator: "/", omittingEmptySubsequences: false)
        guard parts.count == 2, let length = Int(parts[1]), literalIP(String(parts[0])) else { return false }
        return (0...(parts[0].contains(":") ? 128 : 32)).contains(length)
    }
    static func serverIP(_ host: String) -> Bool {
        guard literalIP(host) else { return false }
        var v4 = in_addr(), v6 = in6_addr()
        if inet_pton(AF_INET, host, &v4) == 1 {
            return withUnsafeBytes(of: v4) { $0[0] != 0 && $0[0] != 127 && $0[0] < 224 && !($0[0] == 169 && $0[1] == 254) }
        }
        guard inet_pton(AF_INET6, host, &v6) == 1 else { return false }
        return withUnsafeBytes(of: v6) { bytes in
            let data = Array(bytes)
            guard data.contains(where: { $0 != 0 }), data != Array(repeating: UInt8(0), count: 15) + [1],
                  data[0] != 0xff, !(data[0] == 0xfe && data[1] & 0xc0 == 0x80) else { return false }
            // Reject mapped IPv4 literals rather than bypassing the v4 checks.
            return !(data.prefix(10).allSatisfy { $0 == 0 } && data[10] == 0xff && data[11] == 0xff)
        }
    }

    static func privateIP(_ host: String) -> Bool {
        guard literalIP(host) else { return false }
        var v4 = in_addr(), v6 = in6_addr()
        if inet_pton(AF_INET, host, &v4) == 1 {
            return withUnsafeBytes(of: v4) { $0[0] == 10 || ($0[0] == 172 && (16...31).contains($0[1])) || ($0[0] == 192 && $0[1] == 168) }
        }
        if inet_pton(AF_INET6, host, &v6) == 1 { return withUnsafeBytes(of: v6) { $0[0] & 0xfe == 0xfc } }
        return false
    }
    static func literalIP(_ host: String) -> Bool {
        guard !host.isEmpty, !host.contains("%"), !host.utf8.contains(0),
              host.unicodeScalars.allSatisfy({ $0.isASCII }) else { return false }
        var v4 = in_addr(), v6 = in6_addr()
        return inet_pton(AF_INET, host, &v4) == 1 || inet_pton(AF_INET6, host, &v6) == 1
    }
    private static func integer(_ value: Any?) throws -> Int? {
        guard let value else { return nil }
        struct Number: Decodable { let value: Int }
        return try JSONDecoder().decode(Number.self, from: JSONSerialization.data(withJSONObject: ["value": value])).value
    }
    private static func fullMatch(_ value: String, _ pattern: String) -> Bool {
        value.range(of: "\\A(?:" + pattern + ")\\z", options: .regularExpression) != nil
    }
    static func issue(_ message: String) -> NSError {
        NSError(domain: "RouterVPN.Multihop", code: 1, userInfo: [NSLocalizedDescriptionKey: message])
    }
}
