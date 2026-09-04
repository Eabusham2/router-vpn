import Foundation

enum UnifiedControlCenterPolicy {
    static let experience = "Unified Map Control Center"
    static let defaultMode = "smart-auto"
    static let defaultNodeCount = 1
    static let defaultIPv6 = true
    static let defaultMTUPolicy = "auto"
    static let requireEncryptedAuto = false
    static let requireObfuscationAuto = false
    static let authenticatedTransportAlwaysOn = true
    static let bottomSheetOrder = ["connection", "multihop", "settings", "mode", "dns"]
    static let profileActions = ["create", "load", "update", "delete", "import-router-bundle"]
    static let bridgeTypes = ["socks5", "http-connect", "https-connect", "shadowsocks-2022", "tor-bridge"]
    static let secureSuites = [
        "WireGuard Noise_IK + ChaCha20-Poly1305",
        "AmneziaWG Noise_IK + ChaCha20-Poly1305",
        "OpenVPN TLS 1.3 + AEAD",
        "Shadowsocks 2022 BLAKE3 + AEAD",
        "Tor pluggable transport + proven ntor-v3 circuit",
    ]

    // A tor-bridge profile represents Router VPN's complete owned PT -> Tor
    // circuit runtime. The PT provides censorship circumvention; the proved Tor
    // circuit is the encrypted final path. Raw proxy/bridge types remain outer
    // transports unless followed by an authenticated encrypted tunnel.
    static let finalEncryptedTypes = Set(["router-vpn", "wireguard", "amneziawg", "openvpn", "shadowsocks-2022", "tor-bridge"])
}
