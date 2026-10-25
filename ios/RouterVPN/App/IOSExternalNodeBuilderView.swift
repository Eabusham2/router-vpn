import Network
import Libbox
import SwiftUI

private enum IOSExternalNodeProtocol: String, CaseIterable, Identifiable {
    case wireguard
    case amneziawg
    case socks5
    case httpConnect = "http-connect"
    case httpsConnect = "https-connect"
    case shadowsocks
    case hysteria2
    case openvpn
    case tor
    case torBridge = "tor-bridge"
    var isTor: Bool { self == .tor || self == .torBridge }
    var isWireGuardFamily: Bool { self == .wireguard || self == .amneziawg }
    var id: String { rawValue }
    var title: String {
        switch self {
        case .wireguard: return "WireGuard"
        case .amneziawg: return "AmneziaWG"
        case .socks5: return "SOCKS5"
        case .httpConnect: return "HTTP CONNECT"
        case .httpsConnect: return "HTTPS CONNECT"
        case .shadowsocks: return "Shadowsocks"
        case .hysteria2: return "Hysteria2"
        case .openvpn: return "OpenVPN"
        case .tor: return "Tor"
        case .torBridge: return "Tor with bridges"
        }
    }
}

@MainActor
extension RouterVPNModel {
    func createIOSExternalNode(
        protocolName: String,
        name rawName: String,
        server rawServer: String,
        port: Int,
        expectedPublicIP rawExpected: String,
        username: String,
        password: String,
        method: String,
        secret: String,
        tlsServerName: String,
        wgPrivateKey: String,
        wgPeerPublicKey: String,
        wgPresharedKey: String,
        wgAddresses: [String],
        wgAllowedIPs: [String],
        wgDNS: [String],
        wgMTU: Int?,
        openVPNConfig: String = "",
        torTransport: String = "custom",
        torBridges: [String] = [],
        wgKeepalive: Int? = nil,
        awgParameters: [String: String] = [:],
        responseProbeURL: String = "",
        responseProbeServerName: String = "",
        exitStartLayer: String = "off",
        exitLayerAPI: String = "",
        exitLayerPort: Int = 0,
        exitLayerKey: String = "",
        serverPeerJSON: String = "",
        openVPNPairingJSON: String = "",
        openVPNResponseProbesJSON: String = "",
        openVPNStartLayersJSON: String = ""
    ) throws {
        guard !profileMutationBlocked else {
            throw NSError(domain: "RouterVPN.ExternalNode", code: 1, userInfo: [NSLocalizedDescriptionKey: "Disconnect or let the active VPN transition finish before adding an external node."])
        }
        let tor = protocolName == "tor" || protocolName == "tor-bridge"
        let supported = Set(["wireguard", "amneziawg", "socks5", "http-connect", "https-connect", "shadowsocks", "hysteria2", "openvpn", "tor", "tor-bridge"])
        guard supported.contains(protocolName) else {
            throw NSError(domain: "RouterVPN.ExternalNode", code: 2, userInfo: [NSLocalizedDescriptionKey: "This external protocol has no proven iOS PacketTunnel dataplane."])
        }
        let compiledOpenVPN: [String: Any]?
        if protocolName == "openvpn" {
            guard LibboxVersion().trimmingCharacters(in: .whitespacesAndNewlines) == "1.14.1" else {
                throw NSError(domain: "RouterVPN.ExternalNode", code: 32, userInfo: [NSLocalizedDescriptionKey: "Native OpenVPN core pin mismatch."])
            }
            var failure: NSError?
            let encoded = LibboxRouterOpenVPNEndpoint(openVPNConfig, username, password, "custom-exit", "", &failure)
            if let failure { throw failure }
            guard let data = encoded.data(using: .utf8),
                  let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
                  object["type"] as? String == "openvpn-client", object["system"] as? Bool == false,
                  object["tag"] as? String == "custom-exit", object["detour"] == nil else {
                throw NSError(domain: "RouterVPN.ExternalNode", code: 33, userInfo: [NSLocalizedDescriptionKey: "Native OpenVPN compiler returned an invalid endpoint."])
            }
            compiledOpenVPN = object
        } else { compiledOpenVPN = nil }
        // This address identifies the saved node in the UI. Native startup
        // compiles the complete inline profile and preserves every remote.
        let primaryOpenVPN = (compiledOpenVPN?["servers"] as? [[String: Any]])?.first ?? compiledOpenVPN
        if compiledOpenVPN != nil && (primaryOpenVPN?["server"] as? String == nil || primaryOpenVPN?["server_port"] as? Int == nil) {
            throw NSError(domain: "RouterVPN.ExternalNode", code: 33, userInfo: [NSLocalizedDescriptionKey: "Native OpenVPN compiler returned no valid primary remote."])
        }
        let server = tor ? "tor" : try iosExternalLiteralIP(primaryOpenVPN?["server"] as? String ?? rawServer, label: "External server")
        let port = primaryOpenVPN?["server_port"] as? Int ?? port
        let expected = tor ? "" : try iosExternalPublicIP(rawExpected, label: "Expected public exit IP")
        guard tor || (1...65535).contains(port) else {
            throw NSError(domain: "RouterVPN.ExternalNode", code: 3, userInfo: [NSLocalizedDescriptionKey: "External server port must be 1..65535."])
        }
        let name = rawName.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? "Custom \(protocolName)" : rawName.trimmingCharacters(in: .whitespacesAndNewlines)
        guard name.count <= 120, name.rangeOfCharacter(from: .newlines) == nil else {
            throw NSError(domain: "RouterVPN.ExternalNode", code: 4, userInfo: [NSLocalizedDescriptionKey: "External node name is unsafe or too long."])
        }

        var external: [String: Any] = ["protocol": protocolName, "expected_public_ip": expected]
        switch protocolName {
        case "tor":
            guard torBridges.isEmpty else { throw NSError(domain: "RouterVPN.ExternalNode", code: 34, userInfo: [NSLocalizedDescriptionKey: "Choose Tor with bridges to retain the bridge lines."]) }
        case "tor-bridge":
            external["tor_bridge"] = ["transport": torTransport, "bridges": torBridges]
        case "openvpn":
            // Persist the private source profile, not a second set of generated
            // credentials. PacketTunnel recompiles the frozen profile before use.
            external["openvpn"] = ["config": openVPNConfig, "username": username, "password": password]
        case "wireguard", "amneziawg":
            guard !wgPrivateKey.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
                  !wgPeerPublicKey.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
                  !wgAddresses.isEmpty, !wgAllowedIPs.isEmpty else {
                throw NSError(domain: "RouterVPN.ExternalNode", code: 5, userInfo: [NSLocalizedDescriptionKey: "WireGuard requires private key, peer public key, interface address and AllowedIPs."])
            }
            var block: [String: Any] = [
                "private_key": wgPrivateKey.trimmingCharacters(in: .whitespacesAndNewlines),
                "addresses": wgAddresses,
                "peer_public_key": wgPeerPublicKey.trimmingCharacters(in: .whitespacesAndNewlines),
                "endpoint": iosExternalEndpoint(server: server, port: port),
                "allowed_ips": wgAllowedIPs,
            ]
            let psk = wgPresharedKey.trimmingCharacters(in: .whitespacesAndNewlines)
            if !psk.isEmpty { block["preshared_key"] = psk }
            if !wgDNS.isEmpty { block["dns"] = wgDNS }
            if let mtu = wgMTU {
                guard (1280...9000).contains(mtu) else {
                    throw NSError(domain: "RouterVPN.ExternalNode", code: 6, userInfo: [NSLocalizedDescriptionKey: "WireGuard MTU must be 1280..9000 when set."])
                }
                block["mtu"] = mtu
            }
            if let wgKeepalive {
                guard (0...65535).contains(wgKeepalive) else { throw NSError(domain: "RouterVPN.ExternalNode", code: 36, userInfo: [NSLocalizedDescriptionKey: "Persistent keepalive must be 0..65535 seconds."]) }
                block["persistent_keepalive_interval"] = wgKeepalive
            }
            if protocolName == "amneziawg" { block["parameters"] = awgParameters }
            else if !awgParameters.isEmpty { throw NSError(domain: "RouterVPN.ExternalNode", code: 37, userInfo: [NSLocalizedDescriptionKey: "Choose AmneziaWG to retain obfuscation parameters."]) }
            external[protocolName] = block
        case "socks5":
            let user = username
            guard user.isEmpty == password.isEmpty else {
                throw NSError(domain: "RouterVPN.ExternalNode", code: 7, userInfo: [NSLocalizedDescriptionKey: "SOCKS5 username/password must both be set or both be empty."])
            }
            var block: [String: Any] = ["host": server, "port": port]
            if !user.isEmpty { block["username"] = user; block["password"] = password }
            external["socks5"] = block
        case "http-connect", "https-connect":
            let secure = protocolName == "https-connect"
            let user = username
            guard user.isEmpty == password.isEmpty else {
                throw NSError(domain: "RouterVPN.ExternalNode", code: 8, userInfo: [NSLocalizedDescriptionKey: "CONNECT proxy username/password must both be set or both be empty."])
            }
            var block: [String: Any] = ["host": server, "port": port]
            if !user.isEmpty { block["username"] = user; block["password"] = password }
            let sni = tlsServerName.trimmingCharacters(in: .whitespacesAndNewlines)
            if secure {
                guard iosExternalSafeHostname(sni) else {
                    throw NSError(domain: "RouterVPN.ExternalNode", code: 9, userInfo: [NSLocalizedDescriptionKey: "HTTPS CONNECT requires a safe TLS server name/SNI for certificate verification."])
                }
                block["tls_server_name"] = sni
                external["https_connect"] = block
            } else {
                guard sni.isEmpty else {
                    throw NSError(domain: "RouterVPN.ExternalNode", code: 10, userInfo: [NSLocalizedDescriptionKey: "Plain HTTP CONNECT cannot carry TLS metadata; choose HTTPS CONNECT instead."])
                }
                external["http_connect"] = block
            }
        case "shadowsocks":
            let normalizedMethod = method.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            let allowed = Set(["2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305", "aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305"])
            guard allowed.contains(normalizedMethod), !secret.isEmpty else {
                throw NSError(domain: "RouterVPN.ExternalNode", code: 11, userInfo: [NSLocalizedDescriptionKey: "Choose a supported Shadowsocks method and password/PSK."])
            }
            external["shadowsocks"] = ["server": server, "port": port, "method": normalizedMethod, "password": secret]
        case "hysteria2":
            let sni = tlsServerName.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !secret.isEmpty, iosExternalSafeHostname(sni) else {
                throw NSError(domain: "RouterVPN.ExternalNode", code: 12, userInfo: [NSLocalizedDescriptionKey: "Hysteria2 requires a password and safe TLS server name/SNI."])
            }
            external["hysteria2"] = ["server": server, "port": port, "password": secret, "tls_server_name": sni]
        default: fatalError("guarded protocol")
        }
        if let serverPeer = try IOSExternalExecution.serverPeer(serverPeerJSON) {
            guard ExternalNodeConfig.packetProtocols.contains(protocolName) else { throw IOSExternalExecution.issue() }
            external["server_peer"] = try JSONSerialization.jsonObject(with: JSONEncoder().encode(serverPeer))
        }
        if !openVPNPairingJSON.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            guard protocolName == "openvpn" else { throw IOSExternalExecution.issue() }
            let original = ExternalOpenVPNConfig(config: openVPNConfig, username: username, password: password)
            if let pairing = try IOSExternalExecution.openVPNPairing(openVPNPairingJSON, profile: original) {
                external["openvpn_pairing"] = try JSONSerialization.jsonObject(with: JSONEncoder().encode(pairing))
            }
        }
        if !openVPNResponseProbesJSON.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            guard protocolName == "openvpn", responseProbeURL.isEmpty, responseProbeServerName.isEmpty else { throw IOSExternalExecution.issue() }
            let original = ExternalOpenVPNConfig(config: openVPNConfig, username: username, password: password)
            if let probes = try IOSExternalExecution.openVPNResponseProbes(openVPNResponseProbesJSON, profile: original) {
                external["openvpn_response_probes"] = try JSONSerialization.jsonObject(with: JSONEncoder().encode(probes))
            }
        }
        if !openVPNStartLayersJSON.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            guard protocolName == "openvpn", let rawProbes = external["openvpn_response_probes"] else { throw IOSExternalExecution.issue() }
            let original = ExternalOpenVPNConfig(config: openVPNConfig, username: username, password: password)
            let probes = try JSONDecoder().decode([String: ExternalResponseProbe].self, from: JSONSerialization.data(withJSONObject: rawProbes))
            if let layers = try IOSExternalExecution.openVPNStartLayers(openVPNStartLayersJSON, profile: original, probes: probes, selectedMode: exitStartLayer) {
                external["openvpn_start_layers"] = try JSONSerialization.jsonObject(with: JSONEncoder().encode(layers))
            }
        }
        if ExternalNodeConfig.serverExecutionProtocols.contains(protocolName) {
            if let probe = try IOSExternalExecution.responseProbe(host: server, url: responseProbeURL, serverName: responseProbeServerName) {
                external["response_probe"] = try JSONSerialization.jsonObject(with: JSONEncoder().encode(probe))
            }
        } else {
            guard responseProbeURL.isEmpty && responseProbeServerName.isEmpty else { throw IOSExternalExecution.issue() }
        }
        if exitStartLayer != "off" {
            guard ExternalNodeConfig.serverExecutionProtocols.contains(protocolName),
                  ["aes-256-gcm", "aes-256-gcm+xor-whitening"].contains(exitStartLayer) else { throw IOSExternalExecution.issue() }
            if external["openvpn_start_layers"] != nil {
                guard exitLayerAPI.isEmpty, exitLayerPort == 0, exitLayerKey.isEmpty else { throw IOSExternalExecution.issue() }
            } else {
                guard external["openvpn_response_probes"] == nil else { throw IOSExternalExecution.issue() }
                external["start_layer"] = ["mode": exitStartLayer, "api": exitLayerAPI,
                    "transport": ["type": "shadowsocks", "tag": "provisioned-exit-layer", "server": server,
                        "server_port": exitLayerPort, "method": "2022-blake3-aes-256-gcm", "password": exitLayerKey]]
            }
        } else {
            guard exitLayerAPI.isEmpty, exitLayerPort == 0, exitLayerKey.isEmpty else { throw IOSExternalExecution.issue() }
        }

        let profileID = "ios-ext-" + UUID().uuidString.lowercased()
        let endpoint = tor ? "tor" : iosExternalEndpoint(server: server, port: port)
        let profile: [String: Any] = [
            "schema_version": 4,
            "id": profileID,
            "name": name,
            "node_kind": "external",
            "external": external,
            "endpoint": endpoint,
            "router_api": "",
            "api_token": "",
            "adguard_ipv4": "",
            "adguard_ipv6": "",
            "socks_host": "",
            "socks_port": 0,
            "socks_username": "",
            "socks_password": "",
            "ipv6_mode": "on",
            "mtu_policy": "auto",
            "startup_mode": "manual",
            "kill_switch_policy": "off",
            "dns_mode": "home",
            "start_layer": exitStartLayer,
        ]
        if tor {
            let captured = try JSONSerialization.data(withJSONObject: profile, options: [.sortedKeys])
            var failure: NSError?
            let valid = LibboxRouterValidateTorProfile(String(decoding: captured, as: UTF8.self), &failure)
            if let failure { throw failure }
            guard valid else { throw NSError(domain: "RouterVPN.ExternalNode", code: 35, userInfo: [NSLocalizedDescriptionKey: "Tor profile validation did not complete."]) }
        }
        if protocolName == "amneziawg", let block = external[protocolName] as? [String: Any] {
            // Validate the exact imported transport before storage. Home DNS
            // remains an unresolved draft until its paired entry is captured
            // during connection; saving must not substitute a public resolver.
            var peer: [String: Any] = ["address": server, "port": port, "public_key": block["peer_public_key"]!, "allowed_ips": block["allowed_ips"]!]
            if let psk = block["preshared_key"] { peer["pre_shared_key"] = psk }
            if let keepalive = block["persistent_keepalive_interval"] { peer["persistent_keepalive_interval"] = keepalive }
            let native: [String: Any] = ["type": "routervpn-amneziawg", "tag": "custom-exit", "address": block["addresses"]!,
                "private_key": block["private_key"]!, "peers": [peer], "amnezia": awgParameters, "mtu": wgMTU ?? 1280]
            let graph: [String: Any] = ["inbounds": [["type": "tun", "tag": "tun-in", "address": ["172.29.94.1/30", "fd29:94::1/126"], "mtu": wgMTU ?? 1280,
                "auto_route": true, "strict_route": true, "stack": "system"]], "endpoints": [native], "outbounds": [], "route": ["final": "custom-exit", "auto_detect_interface": true]]
            let selection: [String: Any] = ["schema": 1, "exit_id": profileID, "protocol": protocolName, "expected_public_ip": expected, "profile": profile]
            let source = String(decoding: try JSONSerialization.data(withJSONObject: graph, options: [.sortedKeys]), as: UTF8.self)
            let capture = String(decoding: try JSONSerialization.data(withJSONObject: selection, options: [.sortedKeys]), as: UTF8.self)
            var failure: NSError?
            let valid = LibboxRouterValidateExternalTransport(source, capture, &failure)
            if let failure { throw failure }
            guard valid else { throw NSError(domain: "RouterVPN.ExternalNode", code: 38, userInfo: [NSLocalizedDescriptionKey: "AmneziaWG profile validation did not complete."]) }
        }
        let bundleJSON: [String: Any] = [
            "bundleVersion": 4,
            "profileSchemaVersion": 4,
            "nodeProofId": "",
            "endpoint": endpoint,
            "apiToken": "",
            "routerAPI": "",
            "adGuardIPv4": "",
            "adGuardIPv6": "",
            "socks5Host": "",
            "socks5Port": 0,
            "socks5Username": "",
            "socks5Password": "",
            "routerProfiles": [profile],
            "selectedRouterID": profileID,
            "logicalModes": [],
            "modes": [],
            "profiles": [:],
        ]
        let data = try JSONSerialization.data(withJSONObject: bundleJSON, options: [.sortedKeys])
        try IOSExternalExecution.validateImported(JSONDecoder().decode(ClientBundle.self, from: data))
        try linkNodeBundle(data)
        message = "Added and selected \(name) • external \(protocolName)."
    }

    private func iosExternalLiteralIP(_ raw: String, label: String) throws -> String {
        let value = raw.trimmingCharacters(in: CharacterSet(charactersIn: " []\t\r\n"))
        guard IPv4Address(value) != nil || IPv6Address(value) != nil else {
            throw NSError(domain: "RouterVPN.ExternalNode", code: 20, userInfo: [NSLocalizedDescriptionKey: "\(label) must be a literal IP so setup cannot leak pre-tunnel DNS."])
        }
        return value
    }

    private func iosExternalPublicIP(_ raw: String, label: String) throws -> String {
        let value = try iosExternalLiteralIP(raw, label: label)
        if let ip = IPv4Address(value) {
            let b = [UInt8](ip.rawValue)
            let invalid = b.count != 4 || b[0] == 10 || b[0] == 127 || (b[0] == 172 && (16...31).contains(b[1])) || (b[0] == 192 && b[1] == 168) || (b[0] == 169 && b[1] == 254) || b[0] >= 224 || b == [0,0,0,0]
            guard !invalid else { throw NSError(domain: "RouterVPN.ExternalNode", code: 21, userInfo: [NSLocalizedDescriptionKey: "\(label) must be public."]) }
            return value
        }
        if let ip = IPv6Address(value) {
            let b = [UInt8](ip.rawValue)
            let invalid = b.count != 16 || b.allSatisfy { $0 == 0 } || (b.dropLast().allSatisfy { $0 == 0 } && b.last == 1) || (b[0] & 0xfe) == 0xfc || (b[0] == 0xfe && (b[1] & 0xc0) == 0x80) || b[0] == 0xff
            guard !invalid else { throw NSError(domain: "RouterVPN.ExternalNode", code: 22, userInfo: [NSLocalizedDescriptionKey: "\(label) must be public."]) }
            return value
        }
        throw NSError(domain: "RouterVPN.ExternalNode", code: 23, userInfo: [NSLocalizedDescriptionKey: "Invalid \(label)."])
    }

    private func iosExternalEndpoint(server: String, port: Int) -> String {
        server.contains(":") ? "[\(server)]:\(port)" : "\(server):\(port)"
    }

    private func iosExternalSafeHostname(_ value: String) -> Bool {
        !value.isEmpty && value.count <= 253 && value.range(of: "^[A-Za-z0-9.-]+$", options: .regularExpression) != nil && !value.hasPrefix(".") && !value.hasSuffix(".")
    }
}

struct IOSExternalNodeBuilderView: View {
    @EnvironmentObject var model: RouterVPNModel
    @Environment(\.dismiss) private var dismiss
    @State private var selected: IOSExternalNodeProtocol = .wireguard
    @State private var name = ""
    @State private var server = ""
    @State private var port = ""
    @State private var expectedPublicIP = ""
    @State private var username = ""
    @State private var password = ""
    @State private var method = "2022-blake3-aes-256-gcm"
    @State private var secret = ""
    @State private var tlsName = ""
    @State private var responseProbeURL = ""
    @State private var responseProbeServerName = ""
    @State private var exitStartLayer = "off"
    @State private var exitLayerAPI = ""
    @State private var exitLayerPort = ""
    @State private var exitLayerKey = ""
    @State private var serverPeerJSON = ""
    @State private var openVPNPairingJSON = ""
    @State private var openVPNResponseProbesJSON = ""
    @State private var openVPNStartLayersJSON = ""
    @State private var wgPrivate = ""
    @State private var wgPeer = ""
    @State private var wgPSK = ""
    @State private var wgAddresses = ""
    @State private var wgAllowed = "0.0.0.0/0, ::/0"
    @State private var wgDNS = ""
    @State private var wgMTU = ""
    @State private var wgKeepalive = ""
    @State private var awgParameters: [String: String] = [:]
    @State private var openVPNConfig = ""
    @State private var torTransport = "custom"
    @State private var torBridges = ""
    @State private var errorText = ""

    var body: some View {
        NavigationStack {
            Form {
                Section("Protocol") {
                    Picker("External node type", selection: $selected) {
                        ForEach(IOSExternalNodeProtocol.allCases) { item in Text(item.title).tag(item) }
                    }
                    Text("Choose a saved VPN or proxy endpoint, ordinary Tor, or Tor with your bridge settings.")
                        .font(.caption).foregroundStyle(.secondary)
                }
                Section("Identity") {
                    TextField("Display name", text: $name)
                    if selected != .openvpn && !selected.isTor {
                        TextField("Server literal IP", text: $server).textInputAutocapitalization(.never).autocorrectionDisabled()
                        TextField("Port", text: $port).keyboardType(.numberPad)
                    }
                    if !selected.isTor {
                        TextField("Expected public exit IP", text: $expectedPublicIP).textInputAutocapitalization(.never).autocorrectionDisabled()
                    }
                }
                if selected.isTor {
                    Section("Tor connection") {
                        Text("The app builds a circuit and verifies its current Tor exit before showing Connected. Home AdGuard is the default and uses your paired Router VPN entry. For Tor without an entry, choose a public TCP, DoT, DoH or Rescue resolver in DNS settings.")
                            .font(.caption).foregroundStyle(.secondary)
                        if selected == .torBridge {
                            Picker("Bridge transport", selection: $torTransport) {
                                Text("Mixed / Custom").tag("custom")
                                Text("obfs4").tag("obfs4")
                                Text("meek").tag("meek_lite")
                                Text("Snowflake").tag("snowflake")
                                Text("WebTunnel").tag("webtunnel")
                            }
                            TextEditor(text: $torBridges).frame(minHeight: 150)
                                .textInputAutocapitalization(.never).autocorrectionDisabled()
                            Text("Paste complete bridge lines, one per line. Bridge credentials stay with this private saved node.")
                                .font(.caption).foregroundStyle(.secondary)
                        }
                    }
                } else {
                    Section("DNS") {
                        Text("Home AdGuard is the default and uses your paired Router VPN entry. You can save this node now, then choose its entry in Multihop. To connect directly, select a reachable resolver in DNS settings.")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                }
                if selected == .socks5 || selected == .httpConnect || selected == .httpsConnect {
                    Section(selected == .socks5 ? "SOCKS5" : (selected == .httpsConnect ? "HTTPS CONNECT" : "HTTP CONNECT")) {
                        TextField("Username (optional)", text: $username)
                        SecureField("Password (optional)", text: $password)
                        if selected == .httpsConnect {
                            TextField("TLS server name / SNI", text: $tlsName).textInputAutocapitalization(.never).autocorrectionDisabled()
                            Text("HTTPS CONNECT verifies the proxy certificate against this SNI. Plain HTTP CONNECT intentionally has no TLS field.")
                                .font(.caption).foregroundStyle(.secondary)
                        }
                    }
                }
                if selected == .shadowsocks {
                    Section("Shadowsocks") { TextField("Method", text: $method).textInputAutocapitalization(.never); SecureField("Password / PSK", text: $secret) }
                }
                if selected.isWireGuardFamily {
                    Section("Server / Compare peer") {
                        TextEditor(text: $serverPeerJSON).font(.system(.caption, design: .monospaced)).frame(minHeight: 110)
                            .textInputAutocapitalization(.never).autocorrectionDisabled()
                            .accessibilityLabel("Provisioned server peer public descriptor JSON")
                        Text("Paste the public descriptor supplied when a separate client peer is provisioned on the Router VPN entry: public_key, addresses, mtu and optional persistent_keepalive_interval. Its client public key and assigned addresses must differ from this device's peer. Keep the server private key and preshared key on the entry. Leave this blank for Local only.")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                }
                if ExternalNodeConfig.serverExecutionProtocols.contains(selected.rawValue) {
                    Section("Exit Start Layer") {
                        Picker("Encryption and whitening", selection: $exitStartLayer) {
                            Text("Off").tag("off")
                            Text("AES-256-GCM").tag("aes-256-gcm")
                            Text("AES-256-GCM + XOR whitening").tag("aes-256-gcm+xor-whitening")
                        }
                        if exitStartLayer != "off" {
                            TextField("Provisioned private service API URL", text: $exitLayerAPI).textInputAutocapitalization(.never).autocorrectionDisabled()
                            TextField("Provisioned AES port", text: $exitLayerPort).keyboardType(.numberPad)
                            SecureField("Provisioned AES-256-GCM key", text: $exitLayerKey)
                            Text("Use the layer already provisioned on this same server. Its private service address and key stay with the saved node. XOR whitening uses authenticated AES and the provisioned listener on port 8389.")
                                .font(.caption).foregroundStyle(.secondary)
                        }
                    }
                    Section("Server / Compare response measurement") {
                        TextField("HTTPS URL on this server IP (optional)", text: $responseProbeURL).textInputAutocapitalization(.never).autocorrectionDisabled()
                        TextField("Certificate server name (optional)", text: $responseProbeServerName).textInputAutocapitalization(.never).autocorrectionDisabled()
                        Text("Use an HTTPS response endpoint hosted on the exact server IP above. Its certificate must verify against this name or the IP. Server and Compare also require this exit to be paired in the Router VPN entry's private relay settings. Local remains available without this endpoint.")
                            .font(.caption).foregroundStyle(.secondary)
                        if selected == .openvpn {
                            TextEditor(text: $openVPNResponseProbesJSON).font(.system(.caption, design: .monospaced)).frame(minHeight: 120)
                                .textInputAutocapitalization(.never).autocorrectionDisabled()
                                .accessibilityLabel("Private OpenVPN remote response endpoints JSON")
                            Text("For a profile with multiple remote IPs, paste one HTTPS response endpoint for each of its 2–16 IPs. Use an object keyed by remote IP, with url and optional server_name for each endpoint. Leave the single URL and certificate fields blank. Exit encryption uses the per-remote layer map below. This response map stays in the private node.")
                                .font(.caption).foregroundStyle(.secondary)
                            TextEditor(text: $openVPNStartLayersJSON).font(.system(.caption, design: .monospaced)).frame(minHeight: 140)
                                .textInputAutocapitalization(.never).autocorrectionDisabled()
                                .accessibilityLabel("Private OpenVPN per-remote Start Layer map JSON")
                            Text("For AES or AES + XOR, provide every original remote IP's provisioned mode, api and transport. Each record must match the selected exit mode. Keep the single-service API, port and key fields empty. Leave this map empty when Exit Start Layer is Off.")
                                .font(.caption).foregroundStyle(.secondary)
                        }
                    }
                }
                if selected == .hysteria2 {
                    Section("Hysteria2") { SecureField("Password", text: $secret); TextField("TLS server name / SNI", text: $tlsName).textInputAutocapitalization(.never).autocorrectionDisabled() }
                }
                if selected == .openvpn {
                    Section("Private OpenVPN Server pairing") {
                        TextEditor(text: $openVPNPairingJSON).font(.system(.caption, design: .monospaced)).frame(minHeight: 140)
                            .textInputAutocapitalization(.never).autocorrectionDisabled()
                            .accessibilityLabel("Private OpenVPN pairing JSON")
                        Text("Paste the private client pairing package supplied by your Router entry. It includes a dedicated local authentication key and the separate server's descriptor. Provider credentials and authentication keys must differ between Local and Server. Server secrets stay on the entry. Leave blank for Local only.")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                    Section("Private OpenVPN profile") {
                        TextEditor(text: $openVPNConfig).frame(minHeight: 150)
                            .textInputAutocapitalization(.never).autocorrectionDisabled()
                        TextField("Username (when required)", text: $username).textInputAutocapitalization(.never).autocorrectionDisabled()
                        SecureField("Password (when required)", text: $password)
                        Text("Paste a complete inline .ovpn profile. Its remote list, TLS verification and authentication are compiled by the same native core used by PacketTunnel. Scripts, plugins and external file references are rejected.")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                }
                if selected.isWireGuardFamily {
                    Section(selected.title) {
                        SecureField("Private key", text: $wgPrivate)
                        TextField("Peer public key", text: $wgPeer).textInputAutocapitalization(.never).autocorrectionDisabled()
                        SecureField("Preshared key (optional)", text: $wgPSK)
                        TextField("Interface addresses, comma-separated CIDRs", text: $wgAddresses).textInputAutocapitalization(.never).autocorrectionDisabled()
                        TextField("AllowedIPs, comma-separated CIDRs", text: $wgAllowed).textInputAutocapitalization(.never).autocorrectionDisabled()
                        TextField("DNS IPs, comma-separated (optional)", text: $wgDNS).textInputAutocapitalization(.never).autocorrectionDisabled()
                        TextField("MTU (optional)", text: $wgMTU).keyboardType(.numberPad)
                        TextField("Persistent keepalive seconds (optional)", text: $wgKeepalive).keyboardType(.numberPad)
                    }
                    if selected == .amneziawg {
                        Section("AmneziaWG parameters") {
                            ForEach(["jc", "jmin", "jmax", "s1", "s2", "s3", "s4", "h1", "h2", "h3", "h4"], id: \.self) { key in
                                TextField(key.uppercased(), text: Binding(get: { awgParameters[key] ?? "" }, set: { awgParameters[key] = $0 }))
                                    .textInputAutocapitalization(.never).autocorrectionDisabled()
                            }
                            Text("Copy all eleven values from this node’s configuration. Header ranges such as 10000000-19999999 are preserved exactly. These values must match the server.")
                                .font(.caption).foregroundStyle(.secondary)
                        }
                    }
                }
                Section("Saved node") {
                    Text(selected.isTor ? "Tor exit addresses are verified live and may change between circuits." : "Enter literal IP addresses for the server and expected exit. Credentials stay in the private saved node.")
                        .font(.caption).foregroundStyle(.secondary)
                    if !errorText.isEmpty { Text(errorText).font(.caption).foregroundStyle(.orange) }
                }
            }
            .navigationTitle("Add External Node")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save") { save() }.disabled(model.profileMutationBlocked)
                }
            }
        }
    }

    private func csv(_ value: String) -> [String] {
        value.split(separator: ",").map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }.filter { !$0.isEmpty }
    }

    private func save() {
        guard !model.profileMutationBlocked else { errorText = "Disconnect or let the active VPN transition finish before adding an external node."; return }
        do {
            guard let numericPort = (selected.isTor ? 0 : selected == .openvpn ? 1194 : Int(port)) else { throw NSError(domain: "RouterVPN.ExternalNode", code: 30, userInfo: [NSLocalizedDescriptionKey: "Enter a valid port."]) }
            let mtu = wgMTU.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? nil : Int(wgMTU)
            if selected.isWireGuardFamily && mtu == nil && !wgMTU.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty { throw NSError(domain: "RouterVPN.ExternalNode", code: 31, userInfo: [NSLocalizedDescriptionKey: "Enter a valid WireGuard-family MTU."]) }
            let keepalive = wgKeepalive.isEmpty ? nil : Int(wgKeepalive)
            if selected.isWireGuardFamily && !wgKeepalive.isEmpty && keepalive == nil { throw NSError(domain: "RouterVPN.ExternalNode", code: 36, userInfo: [NSLocalizedDescriptionKey: "Enter a valid persistent keepalive interval."]) }
            try model.createIOSExternalNode(
                protocolName: selected.rawValue, name: name, server: server, port: numericPort, expectedPublicIP: expectedPublicIP,
                username: username, password: password, method: method, secret: secret, tlsServerName: tlsName,
                wgPrivateKey: wgPrivate, wgPeerPublicKey: wgPeer, wgPresharedKey: wgPSK,
                wgAddresses: csv(wgAddresses), wgAllowedIPs: csv(wgAllowed), wgDNS: csv(wgDNS), wgMTU: mtu, openVPNConfig: openVPNConfig,
                torTransport: torTransport, torBridges: selected == .torBridge ? torBridges.split(whereSeparator: \.isNewline).map { String($0) } : [],
                wgKeepalive: selected.isWireGuardFamily ? keepalive : nil, awgParameters: selected == .amneziawg ? awgParameters : [:],
                responseProbeURL: ExternalNodeConfig.serverExecutionProtocols.contains(selected.rawValue) ? responseProbeURL : "",
                responseProbeServerName: ExternalNodeConfig.serverExecutionProtocols.contains(selected.rawValue) ? responseProbeServerName : "",
                exitStartLayer: ExternalNodeConfig.serverExecutionProtocols.contains(selected.rawValue) ? exitStartLayer : "off",
                exitLayerAPI: ExternalNodeConfig.serverExecutionProtocols.contains(selected.rawValue) && exitStartLayer != "off" ? exitLayerAPI : "",
                exitLayerPort: ExternalNodeConfig.serverExecutionProtocols.contains(selected.rawValue) && exitStartLayer != "off" ? (Int(exitLayerPort) ?? 0) : 0,
                exitLayerKey: ExternalNodeConfig.serverExecutionProtocols.contains(selected.rawValue) && exitStartLayer != "off" ? exitLayerKey : "",
                serverPeerJSON: selected.isWireGuardFamily ? serverPeerJSON : "",
                openVPNPairingJSON: selected == .openvpn ? openVPNPairingJSON : "",
                openVPNResponseProbesJSON: selected == .openvpn ? openVPNResponseProbesJSON : "",
                openVPNStartLayersJSON: selected == .openvpn ? openVPNStartLayersJSON : ""
            )
            dismiss()
        } catch { errorText = error.localizedDescription }
    }
}
