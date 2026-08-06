import Foundation

struct VPNMode: Identifiable, Codable, Hashable {
    let id: String
    let name: String
    let protection: String
    let pingMinMs: Double
    let pingMaxMs: Double
    let trafficMinPct: Double
    let trafficMaxPct: Double
    let speedLossMinPct: Double
    let speedLossMaxPct: Double
    let daitaSupported: Bool?
    let jumboSupported: Bool?
    enum CodingKeys: String, CodingKey {
        case id, name, protection
        case pingMinMs = "ping_min_ms", pingMaxMs = "ping_max_ms"
        case trafficMinPct = "traffic_min_pct", trafficMaxPct = "traffic_max_pct"
        case speedLossMinPct = "speed_loss_min_pct", speedLossMaxPct = "speed_loss_max_pct"
        case daitaSupported = "daita_supported", jumboSupported = "jumbo_supported"
    }
}

struct RouterProfile: Identifiable, Codable, Hashable {
    var id: String
    var name: String
    var endpoint: String
    var routerAPI: String
    var apiToken: String
    var adGuardIPv4: String
    var adGuardIPv6: String
    var socksHost: String
    var socksPort: Int
    var socksUsername: String
    var socksPassword: String

    enum CodingKeys: String, CodingKey {
        case id, name, endpoint
        case routerAPI = "router_api"
        case apiToken = "api_token"
        case adGuardIPv4 = "adguard_ipv4"
        case adGuardIPv6 = "adguard_ipv6"
        case socksHost = "socks_host"
        case socksPort = "socks_port"
        case socksUsername = "socks_username"
        case socksPassword = "socks_password"
    }
}

struct ClientBundle: Codable {
    var endpoint: String?
    var apiToken: String?
    var routerAPI: String?
    var adGuardIPv4: String?
    var adGuardIPv6: String?
    var socks5Host: String?
    var socks5Port: Int?
    var socks5Username: String?
    var socks5Password: String?
    var routerProfiles: [RouterProfile]?
    var selectedRouterID: String?
    var modes: [VPNMode]
    var profiles: [String: [String: String]]
}
