
import Foundation

enum IOSUnifiedSecureTransport {
    static let alwaysOn = true
    static let allowedFinalNodeTypes = Set(["router-vpn", "wireguard", "amneziawg", "openvpn", "shadowsocks-2022"])
    static let bridgeTypes = ["socks5", "http-connect", "https-connect", "shadowsocks-2022", "tor-bridge"]
    static let suites = [
        "WireGuard Noise_IK + ChaCha20-Poly1305",
        "AmneziaWG Noise_IK + ChaCha20-Poly1305",
        "OpenVPN TLS 1.3 + AEAD",
        "Shadowsocks 2022 BLAKE3 + AEAD",
        "Tor ntor-v3 outer bridge",
    ]

    static func handshakeLabel(connected: Bool) -> String {
        connected ? "Authenticated handshake ✓" : "Authenticated handshake required"
    }
}
