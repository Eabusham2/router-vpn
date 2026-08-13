import Foundation
import WireGuardKit

/// Narrow wg-quick parser for the Router VPN generated client profile.
/// It accepts only keys the native iOS WireGuard engine can faithfully apply.
enum RouterVPNWireGuardConfig {
    enum ParseError: LocalizedError {
        case malformed(String)
        var errorDescription: String? {
            switch self {
            case .malformed(let message): return message
            }
        }
    }

    static func parse(_ text: String, name: String = "Router VPN") throws -> TunnelConfiguration {
        guard text.utf8.count <= 1024 * 1024 else { throw ParseError.malformed("WireGuard profile exceeds the 1 MiB safety limit.") }

        var interfaceValues: [String: [String]] = [:]
        var peerSections: [[String: [String]]] = []
        var currentSection = ""

        for (index, rawLine) in text.split(whereSeparator: { $0.isNewline }).enumerated() {
            var line = String(rawLine)
            if let hash = line.firstIndex(of: "#") { line = String(line[..<hash]) }
            if let semi = line.firstIndex(of: ";") { line = String(line[..<semi]) }
            line = line.trimmingCharacters(in: .whitespacesAndNewlines)
            if line.isEmpty { continue }
            if line.hasPrefix("[") && line.hasSuffix("]") {
                let section = String(line.dropFirst().dropLast()).lowercased()
                guard section == "interface" || section == "peer" else {
                    throw ParseError.malformed("Unsupported WireGuard section [\(section)] at line \(index + 1).")
                }
                currentSection = section
                if section == "peer" { peerSections.append([:]) }
                continue
            }
            guard let equals = line.firstIndex(of: "=") else {
                throw ParseError.malformed("Malformed WireGuard line \(index + 1).")
            }
            guard !currentSection.isEmpty else {
                throw ParseError.malformed("WireGuard key appears before a section at line \(index + 1).")
            }
            let key = line[..<equals].trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            let value = line[line.index(after: equals)...].trimmingCharacters(in: .whitespacesAndNewlines)
            guard !key.isEmpty && !value.isEmpty else { throw ParseError.malformed("Empty WireGuard key/value at line \(index + 1).") }
            if currentSection == "interface" {
                interfaceValues[key, default: []].append(value)
            } else {
                guard !peerSections.isEmpty else { throw ParseError.malformed("Peer key appears without [Peer].") }
                peerSections[peerSections.count - 1][key, default: []].append(value)
            }
        }

        let allowedInterfaceKeys: Set<String> = ["privatekey", "address", "listenport", "mtu", "dns"]
        for key in interfaceValues.keys where !allowedInterfaceKeys.contains(key) {
            throw ParseError.malformed("Unsupported WireGuard interface key \(key); scripts/hooks are never executed by Router VPN.")
        }
        guard let privateKeyText = one(interfaceValues, "privatekey"), let privateKey = PrivateKey(base64Key: privateKeyText) else {
            throw ParseError.malformed("WireGuard PrivateKey is missing or invalid.")
        }
        var interface = InterfaceConfiguration(privateKey: privateKey)
        interface.addresses = try csv(interfaceValues["address"]).map {
            guard let range = IPAddressRange(from: $0) else { throw ParseError.malformed("Invalid WireGuard Address: \($0)") }
            return range
        }
        guard !interface.addresses.isEmpty else { throw ParseError.malformed("WireGuard Address is required.") }
        if let listen = one(interfaceValues, "listenport") {
            guard let port = UInt16(listen), port > 0 else { throw ParseError.malformed("Invalid WireGuard ListenPort.") }
            interface.listenPort = port
        }
        if let mtuText = one(interfaceValues, "mtu") {
            guard let mtu = UInt16(mtuText), mtu >= 1280 && mtu <= 9000 else { throw ParseError.malformed("WireGuard MTU must be 1280…9000.") }
            interface.mtu = mtu
        }
        interface.dns = try csv(interfaceValues["dns"]).map {
            guard let dns = DNSServer(from: $0) else { throw ParseError.malformed("Only literal IPv4/IPv6 DNS servers are supported in native iOS WireGuard: \($0)") }
            return dns
        }

        guard !peerSections.isEmpty else { throw ParseError.malformed("WireGuard profile has no peers.") }
        guard peerSections.count <= 16 else { throw ParseError.malformed("WireGuard profile has too many peers.") }
        let allowedPeerKeys: Set<String> = ["publickey", "presharedkey", "allowedips", "endpoint", "persistentkeepalive"]
        var peers: [PeerConfiguration] = []
        for values in peerSections {
            for key in values.keys where !allowedPeerKeys.contains(key) {
                throw ParseError.malformed("Unsupported WireGuard peer key \(key).")
            }
            guard let publicKeyText = one(values, "publickey"), let publicKey = PublicKey(base64Key: publicKeyText) else {
                throw ParseError.malformed("WireGuard peer PublicKey is missing or invalid.")
            }
            var peer = PeerConfiguration(publicKey: publicKey)
            if let pskText = one(values, "presharedkey") {
                guard let psk = PreSharedKey(base64Key: pskText) else { throw ParseError.malformed("WireGuard PresharedKey is invalid.") }
                peer.preSharedKey = psk
            }
            peer.allowedIPs = try csv(values["allowedips"]).map {
                guard let range = IPAddressRange(from: $0) else { throw ParseError.malformed("Invalid WireGuard AllowedIPs entry: \($0)") }
                return range
            }
            guard !peer.allowedIPs.isEmpty else { throw ParseError.malformed("WireGuard peer AllowedIPs is required.") }
            if let endpointText = one(values, "endpoint") {
                guard let endpoint = Endpoint(from: endpointText) else { throw ParseError.malformed("WireGuard peer Endpoint is invalid.") }
                peer.endpoint = endpoint
            }
            if let keepaliveText = one(values, "persistentkeepalive") {
                guard let keepalive = UInt16(keepaliveText) else { throw ParseError.malformed("WireGuard PersistentKeepalive is invalid.") }
                peer.persistentKeepAlive = keepalive
            }
            peers.append(peer)
        }
        return TunnelConfiguration(name: name, interface: interface, peers: peers)
    }

    private static func one(_ values: [String: [String]], _ key: String) -> String? {
        guard let entries = values[key], entries.count == 1 else { return nil }
        return entries[0]
    }

    private static func csv(_ entries: [String]?) throws -> [String] {
        guard let entries else { return [] }
        var output: [String] = []
        for entry in entries {
            for item in entry.split(separator: ",", omittingEmptySubsequences: false) {
                let value = item.trimmingCharacters(in: .whitespacesAndNewlines)
                guard !value.isEmpty else { throw ParseError.malformed("WireGuard list contains an empty item.") }
                output.append(value)
                if output.count > 256 { throw ParseError.malformed("WireGuard list exceeds the 256-item safety limit.") }
            }
        }
        return output
    }
}
