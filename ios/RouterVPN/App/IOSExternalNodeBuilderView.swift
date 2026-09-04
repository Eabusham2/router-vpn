import Network
import SwiftUI

private enum IOSExternalNodeProtocol: String, CaseIterable, Identifiable {
    case wireguard
    case socks5
    case httpConnect = "http-connect"
    case httpsConnect = "https-connect"
    case shadowsocks
    case hysteria2
    var id: String { rawValue }
    var title: String {
        switch self {
        case .wireguard: return "WireGuard"
        case .socks5: return "SOCKS5"
        case .httpConnect: return "HTTP CONNECT"
        case .httpsConnect: return "HTTPS CONNECT"
        case .shadowsocks: return "Shadowsocks"
        case .hysteria2: return "Hysteria2"
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
        wgMTU: Int?
    ) throws {
        guard !profileMutationBlocked else {
            throw NSError(domain: "RouterVPN.ExternalNode", code: 1, userInfo: [NSLocalizedDescriptionKey: "Disconnect or let the active VPN transition finish before adding an external node."])
        }
        let supported = Set(["wireguard", "socks5", "http-connect", "https-connect", "shadowsocks", "hysteria2"])
        guard supported.contains(protocolName) else {
            throw NSError(domain: "RouterVPN.ExternalNode", code: 2, userInfo: [NSLocalizedDescriptionKey: "This external protocol has no proven iOS PacketTunnel dataplane."])
        }
        let server = try iosExternalLiteralIP(rawServer, label: "External server")
        let expected = try iosExternalPublicIP(rawExpected, label: "Expected public exit IP")
        guard (1...65535).contains(port) else {
            throw NSError(domain: "RouterVPN.ExternalNode", code: 3, userInfo: [NSLocalizedDescriptionKey: "External server port must be 1..65535."])
        }
        let name = rawName.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? "Custom \(protocolName)" : rawName.trimmingCharacters(in: .whitespacesAndNewlines)
        guard name.count <= 120, name.rangeOfCharacter(from: .newlines) == nil else {
            throw NSError(domain: "RouterVPN.ExternalNode", code: 4, userInfo: [NSLocalizedDescriptionKey: "External node name is unsafe or too long."])
        }

        var external: [String: Any] = ["protocol": protocolName, "expected_public_ip": expected]
        switch protocolName {
        case "wireguard":
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
            external["wireguard"] = block
        case "socks5":
            let user = username.trimmingCharacters(in: .whitespacesAndNewlines)
            guard user.isEmpty == password.isEmpty else {
                throw NSError(domain: "RouterVPN.ExternalNode", code: 7, userInfo: [NSLocalizedDescriptionKey: "SOCKS5 username/password must both be set or both be empty."])
            }
            var block: [String: Any] = ["host": server, "port": port]
            if !user.isEmpty { block["username"] = user; block["password"] = password }
            external["socks5"] = block
        case "http-connect", "https-connect":
            let secure = protocolName == "https-connect"
            let user = username.trimmingCharacters(in: .whitespacesAndNewlines)
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

        let profileID = "ios-ext-" + UUID().uuidString.lowercased()
        let endpoint = iosExternalEndpoint(server: server, port: port)
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
            "dns_mode": "rescue",
        ]
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
        _ = try JSONDecoder().decode(ClientBundle.self, from: data)
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
    @State private var wgPrivate = ""
    @State private var wgPeer = ""
    @State private var wgPSK = ""
    @State private var wgAddresses = ""
    @State private var wgAllowed = "0.0.0.0/0, ::/0"
    @State private var wgDNS = ""
    @State private var wgMTU = ""
    @State private var errorText = ""

    var body: some View {
        NavigationStack {
            Form {
                Section("Protocol") {
                    Picker("External node type", selection: $selected) {
                        ForEach(IOSExternalNodeProtocol.allCases) { item in Text(item.title).tag(item) }
                    }
                    Text("iOS exposes only external protocols with a real pinned PacketTunnel dataplane. OpenVPN and Tor are not presented here until their Apple runtime paths are proven.")
                        .font(.caption).foregroundStyle(.secondary)
                }
                Section("Identity") {
                    TextField("Display name", text: $name)
                    TextField("Server literal IP", text: $server).textInputAutocapitalization(.never).autocorrectionDisabled()
                    TextField("Port", text: $port).keyboardType(.numberPad)
                    TextField("Expected public exit IP", text: $expectedPublicIP).textInputAutocapitalization(.never).autocorrectionDisabled()
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
                if selected == .hysteria2 {
                    Section("Hysteria2") { SecureField("Password", text: $secret); TextField("TLS server name / SNI", text: $tlsName).textInputAutocapitalization(.never).autocorrectionDisabled() }
                }
                if selected == .wireguard {
                    Section("WireGuard") {
                        SecureField("Private key", text: $wgPrivate)
                        TextField("Peer public key", text: $wgPeer).textInputAutocapitalization(.never).autocorrectionDisabled()
                        SecureField("Preshared key (optional)", text: $wgPSK)
                        TextField("Interface addresses, comma-separated CIDRs", text: $wgAddresses).textInputAutocapitalization(.never).autocorrectionDisabled()
                        TextField("AllowedIPs, comma-separated CIDRs", text: $wgAllowed).textInputAutocapitalization(.never).autocorrectionDisabled()
                        TextField("DNS IPs, comma-separated (optional)", text: $wgDNS).textInputAutocapitalization(.never).autocorrectionDisabled()
                        TextField("MTU (optional)", text: $wgMTU).keyboardType(.numberPad)
                    }
                }
                Section("Safety") {
                    Text("Servers and expected exits require literal IPs so profile creation cannot leak DNS before the tunnel. Security-critical fields stay in the existing app-private linked-node bundle store and are never copied into connection-profile snapshots.")
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
            guard let numericPort = Int(port) else { throw NSError(domain: "RouterVPN.ExternalNode", code: 30, userInfo: [NSLocalizedDescriptionKey: "Enter a valid port."]) }
            let mtu = wgMTU.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? nil : Int(wgMTU)
            if selected == .wireguard && mtu == nil && !wgMTU.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty { throw NSError(domain: "RouterVPN.ExternalNode", code: 31, userInfo: [NSLocalizedDescriptionKey: "Enter a valid WireGuard MTU."]) }
            try model.createIOSExternalNode(
                protocolName: selected.rawValue, name: name, server: server, port: numericPort, expectedPublicIP: expectedPublicIP,
                username: username, password: password, method: method, secret: secret, tlsServerName: tlsName,
                wgPrivateKey: wgPrivate, wgPeerPublicKey: wgPeer, wgPresharedKey: wgPSK,
                wgAddresses: csv(wgAddresses), wgAllowedIPs: csv(wgAllowed), wgDNS: csv(wgDNS), wgMTU: mtu
            )
            dismiss()
        } catch { errorText = error.localizedDescription }
    }
}
