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
        "shadowsocks",
        "shadowsocks-2022",
        "hysteria2",
    ])

    // These proxy families have real Libbox adapters on iOS, but plain SOCKS5 /
    // HTTP CONNECT are not advertised as authenticated secure final transports.
    static let bridgeTypes = [
        "socks5",
        "http-connect",
        "https-connect",
        "shadowsocks-2022",
    ]

    // Keep unsupported shared-product families visible as explicit unavailable
    // truth instead of accidentally presenting desktop capability on iOS.
    static let unavailableNodeTypes: [String: String] = [
        "amneziawg": "AmneziaWG is unavailable on iOS until a pinned Apple PacketTunnel dataplane can enforce and prove it.",
        "openvpn": "OpenVPN is unavailable on iOS until a pinned native Apple OpenVPN PacketTunnel dataplane ships.",
        "tor-bridge": "Tor bridges are unavailable on iOS until a native Tor + pluggable-transport PacketTunnel can prove the dynamic Tor exit.",
    ]

    static let suites = [
        "WireGuard Noise_IK + ChaCha20-Poly1305",
        "HTTPS CONNECT TLS 1.3 with certificate verification",
        "Shadowsocks 2022 BLAKE3 + AEAD",
        "Hysteria2 QUIC + TLS 1.3",
    ]

    static func handshakeLabel(connected: Bool) -> String {
        connected ? "Authenticated handshake ✓" : "Authenticated handshake required"
    }
}
