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
        "Tor ntor-v3 outer bridge",
    ]
}
