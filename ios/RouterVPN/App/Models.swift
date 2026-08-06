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

struct ClientBundle: Codable {
    var endpoint: String
    var apiToken: String
    var routerAPI: String
    var socks5Host: String
    var socks5Port: Int
    var socks5Username: String
    var socks5Password: String
    var modes: [VPNMode]
    var profiles: [String: [String: String]]
}
