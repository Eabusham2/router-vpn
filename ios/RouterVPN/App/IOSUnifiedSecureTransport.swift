import Foundation

enum IOSUnifiedSecureTransport {
    // This is an iOS/iPadOS product-truth view, not a copy of the cross-platform
    // transport catalog. Only transports with a real Apple PacketTunnel path may
    // appear as runnable here.
    static let alwaysOn = true

    // Secure final transports the current iOS PacketTunnel can actually enforce.
    // Shadowsocks uses the profile protocol name "shadowsocks" while the shared
    // product vocabulary also calls the modern family "shadowsocks-2022".
    static let allowedFinalNodeTypes = Set([
        "router-vpn",
        "wireguard",
        "amneziawg",
        "openvpn",
        "shadowsocks",
        "shadowsocks-2022",
        "hysteria2",
        "tor",
        "tor-bridge",
    ])

    // Node-builder/bridge catalog. Hysteria2 and Shadowsocks are also valid
    // encrypted final transports. Plain SOCKS5 / HTTP(S) CONNECT remain outer
    // bridge/proxy choices and are not relabeled as authenticated secure finals.
    static let bridgeTypes = [
        "socks5",
        "http-connect",
        "https-connect",
        "shadowsocks-2022",
        "hysteria2",
    ]

    // Tor bridges use the owned native Tor runtime and dynamic exit proof.
    // Connection readiness still validates the complete selected native graph.

    static let suites = [
        "WireGuard Noise_IK + ChaCha20-Poly1305",
        "AmneziaWG authenticated encryption + captured packet obfuscation",
        "OpenVPN verified TLS + negotiated data cipher",
        "HTTPS CONNECT TLS 1.3 with certificate verification",
        "Shadowsocks 2022 BLAKE3 + AEAD",
        "Hysteria2 QUIC + TLS 1.3",
        "Tor encrypted relay circuits + owned bridge transports",
    ]

    static func protectionLabel(protocolName: String) -> String {
        switch protocolName.lowercased() {
        case "socks5", "http-connect": return "No transport encryption"
        case "https-connect": return "TLS to the selected proxy"
        case "tor", "tor-bridge": return "Tor encrypted relay path"
        case "router-vpn", "wireguard", "amneziawg", "openvpn", "shadowsocks", "shadowsocks-2022", "hysteria2":
            return "Authenticated encryption"
        default: return "Check the selected runtime"
        }
    }

    // `connected` means PacketTunnel startup returned only after exact private
    // node proof or exact external public-exit proof. Do not call that generic
    // proof an "authenticated handshake": plain SOCKS5/HTTP CONNECT can be real
    // full-device external paths while providing no transport encryption.
    static func handshakeLabel(connected: Bool) -> String {
        connected ? "Selected-path proof ✓" : "Selected-path proof required"
    }
}
