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
    var endpoint: String
    var apiToken: String
    var routerAPI: String
    var adGuardIPv4: String
    var adGuardIPv6: String
    var socks5Host: String
    var socks5Port: Int
    var socks5Username: String
    var socks5Password: String
    var routerProfiles: [RouterProfile]
    var selectedRouterID: String
    var modes: [VPNMode]
    var profiles: [String: [String: String]]

    static let empty = ClientBundle(
        endpoint: "",
        apiToken: "",
        routerAPI: "http://10.77.0.1:8787",
        adGuardIPv4: "10.77.0.1",
        adGuardIPv6: "fd77:77::1",
        socks5Host: "10.77.0.1",
        socks5Port: 1080,
        socks5Username: "",
        socks5Password: "",
        routerProfiles: [],
        selectedRouterID: "",
        modes: [],
        profiles: [:]
    )

    enum CodingKeys: String, CodingKey {
        case endpoint, apiToken, routerAPI, adGuardIPv4, adGuardIPv6
        case socks5Host, socks5Port, socks5Username, socks5Password
        case routerProfiles, selectedRouterID, modes, profiles
    }

    init(
        endpoint: String,
        apiToken: String,
        routerAPI: String,
        adGuardIPv4: String,
        adGuardIPv6: String,
        socks5Host: String,
        socks5Port: Int,
        socks5Username: String,
        socks5Password: String,
        routerProfiles: [RouterProfile],
        selectedRouterID: String,
        modes: [VPNMode],
        profiles: [String: [String: String]]
    ) {
        self.endpoint = endpoint
        self.apiToken = apiToken
        self.routerAPI = routerAPI
        self.adGuardIPv4 = adGuardIPv4
        self.adGuardIPv6 = adGuardIPv6
        self.socks5Host = socks5Host
        self.socks5Port = socks5Port
        self.socks5Username = socks5Username
        self.socks5Password = socks5Password
        self.routerProfiles = routerProfiles
        self.selectedRouterID = selectedRouterID
        self.modes = modes
        self.profiles = profiles
    }

    init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        endpoint = try values.decodeIfPresent(String.self, forKey: .endpoint) ?? ""
        apiToken = try values.decodeIfPresent(String.self, forKey: .apiToken) ?? ""
        routerAPI = try values.decodeIfPresent(String.self, forKey: .routerAPI) ?? "http://10.77.0.1:8787"
        adGuardIPv4 = try values.decodeIfPresent(String.self, forKey: .adGuardIPv4) ?? "10.77.0.1"
        adGuardIPv6 = try values.decodeIfPresent(String.self, forKey: .adGuardIPv6) ?? "fd77:77::1"
        socks5Host = try values.decodeIfPresent(String.self, forKey: .socks5Host) ?? "10.77.0.1"
        socks5Port = try values.decodeIfPresent(Int.self, forKey: .socks5Port) ?? 1080
        socks5Username = try values.decodeIfPresent(String.self, forKey: .socks5Username) ?? ""
        socks5Password = try values.decodeIfPresent(String.self, forKey: .socks5Password) ?? ""
        routerProfiles = try values.decodeIfPresent([RouterProfile].self, forKey: .routerProfiles) ?? []
        selectedRouterID = try values.decodeIfPresent(String.self, forKey: .selectedRouterID) ?? ""
        modes = try values.decodeIfPresent([VPNMode].self, forKey: .modes) ?? []
        profiles = try values.decodeIfPresent([String: [String: String]].self, forKey: .profiles) ?? [:]

        if endpoint.isEmpty, let selected = routerProfiles.first(where: { $0.id == selectedRouterID }) ?? routerProfiles.first {
            endpoint = selected.endpoint
            routerAPI = selected.routerAPI
            apiToken = selected.apiToken
            adGuardIPv4 = selected.adGuardIPv4
            adGuardIPv6 = selected.adGuardIPv6
            socks5Host = selected.socksHost
            socks5Port = selected.socksPort
        }
        socks5Username = ""
        socks5Password = ""
    }
}
