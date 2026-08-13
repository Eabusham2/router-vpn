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

struct LogicalMode: Identifiable, Codable, Hashable {
    let id: String
    let name: String
    let description: String
    let baseSelector: Bool
    let fallback: Bool
    let variants: [String: String]

    enum CodingKeys: String, CodingKey {
        case id, name, description, fallback, variants
        case baseSelector = "base_selector"
    }
}

struct DNSBenchmarkResult: Codable, Hashable {
    var name: String
    var address: String
    var family: String?
    var latencyMs: Double?
    var working: Bool

    enum CodingKeys: String, CodingKey {
        case name, address, family, working
        case latencyMs = "latency_ms"
    }
}

struct RouterProfile: Identifiable, Codable, Hashable {
    var schemaVersion: Int?
    var id: String
    var name: String
    var nodeProofID: String?
    var endpoint: String
    var routerAPI: String
    var apiToken: String
    var adGuardIPv4: String
    var adGuardIPv6: String
    var socksHost: String
    var socksPort: Int
    var socksUsername: String
    var socksPassword: String
    var daitaHost: String?
    var daitaPort: Int?
    var daitaRateKbps: Int?
    var baseTunnel: String?
    var baseFallback: Bool?
    var customLayers: [String]?
    var homeLANAccess: Bool?
    var homeLANCIDRs: [String]?
    var killSwitch: Bool?
    var killSwitchPolicy: String?
    var ipv6Mode: String?
    var startupMode: String?
    var autoConnect: Bool?
    var multihopEnabled: Bool?
    var multihopEntryID: String?
    var multihopExitID: String?
    var mtuPolicy: String?
    var manualMTU: Int?
    var effectiveMTU: Int?
    var diagnosticsEnabled: Bool?
    var diagnosticsRetentionDays: Int?
    var shareDiagnostics: Bool?
    var telemetryEnabled: Bool?
    var pathProbeURL: String?
    var location: String?
    var latitude: Double?
    var longitude: Double?
    var useCount: Int?
    var lastUsedAt: String?
    var latencySamples: Int?
    var latencyMinMs: Double?
    var latencyMedianMs: Double?
    var latencyTrimmedMeanMs: Double?
    var latencyAverageMs: Double?
    var latencyP90Ms: Double?
    var latencyMaxMs: Double?
    var latencyLastTest: String?
    var publicIP: String?
    var dnsMode: String?
    var dnsProtocol: String?
    var dnsHost: String?
    var dnsPort: Int?
    var dnsServerName: String?
    var dnsPath: String?
    var fastestDNSHost: String?
    var fastestDNSName: String?
    var fastestDNSLatencyMs: Double?
    var dnsResults: [DNSBenchmarkResult]?

    enum CodingKeys: String, CodingKey {
        case id, name, endpoint, location, latitude, longitude
        case schemaVersion = "schema_version"
        case nodeProofID = "node_proof_id"
        case routerAPI = "router_api"
        case apiToken = "api_token"
        case adGuardIPv4 = "adguard_ipv4"
        case adGuardIPv6 = "adguard_ipv6"
        case socksHost = "socks_host"
        case socksPort = "socks_port"
        case socksUsername = "socks_username"
        case socksPassword = "socks_password"
        case daitaHost = "daita_host"
        case daitaPort = "daita_port"
        case daitaRateKbps = "daita_rate_kbps"
        case baseTunnel = "base_tunnel"
        case baseFallback = "base_fallback"
        case customLayers = "custom_layers"
        case homeLANAccess = "home_lan_access"
        case homeLANCIDRs = "home_lan_cidrs"
        case killSwitch = "kill_switch"
        case killSwitchPolicy = "kill_switch_policy"
        case ipv6Mode = "ipv6_mode"
        case startupMode = "startup_mode"
        case autoConnect = "auto_connect"
        case multihopEnabled = "multihop_enabled"
        case multihopEntryID = "multihop_entry_id"
        case multihopExitID = "multihop_exit_id"
        case mtuPolicy = "mtu_policy"
        case manualMTU = "manual_mtu"
        case effectiveMTU = "effective_mtu"
        case diagnosticsEnabled = "diagnostics_enabled"
        case diagnosticsRetentionDays = "diagnostics_retention_days"
        case shareDiagnostics = "share_diagnostics"
        case telemetryEnabled = "telemetry_enabled"
        case pathProbeURL = "path_probe_url"
        case useCount = "use_count"
        case lastUsedAt = "last_used_at"
        case latencySamples = "latency_samples"
        case latencyMinMs = "latency_min_ms"
        case latencyMedianMs = "latency_median_ms"
        case latencyTrimmedMeanMs = "latency_trimmed_mean_ms"
        case latencyAverageMs = "latency_average_ms"
        case latencyP90Ms = "latency_p90_ms"
        case latencyMaxMs = "latency_max_ms"
        case latencyLastTest = "latency_last_test"
        case publicIP = "public_ip"
        case dnsMode = "dns_mode"
        case dnsProtocol = "dns_protocol"
        case dnsHost = "dns_host"
        case dnsPort = "dns_port"
        case dnsServerName = "dns_server_name"
        case dnsPath = "dns_path"
        case fastestDNSHost = "fastest_dns_host"
        case fastestDNSName = "fastest_dns_name"
        case fastestDNSLatencyMs = "fastest_dns_latency_ms"
        case dnsResults = "dns_results"
    }
}

struct ClientBundle: Codable {
    var bundleVersion: Int
    var profileSchemaVersion: Int
    var nodeProofID: String
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
    var logicalModes: [LogicalMode]
    var modes: [VPNMode]
    var profiles: [String: [String: String]]

    static let empty = ClientBundle(
        bundleVersion: 4,
        profileSchemaVersion: 2,
        nodeProofID: "",
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
        logicalModes: [],
        modes: [],
        profiles: [:]
    )

    enum CodingKeys: String, CodingKey {
        case bundleVersion, profileSchemaVersion, endpoint, apiToken, routerAPI, adGuardIPv4, adGuardIPv6
        case nodeProofID = "nodeProofId"
        case socks5Host, socks5Port, socks5Username, socks5Password
        case routerProfiles, selectedRouterID, logicalModes, modes, profiles
    }

    init(
        bundleVersion: Int,
        profileSchemaVersion: Int,
        nodeProofID: String,
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
        logicalModes: [LogicalMode],
        modes: [VPNMode],
        profiles: [String: [String: String]]
    ) {
        self.bundleVersion = bundleVersion
        self.profileSchemaVersion = profileSchemaVersion
        self.nodeProofID = nodeProofID
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
        self.logicalModes = logicalModes
        self.modes = modes
        self.profiles = profiles
    }

    init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        bundleVersion = try values.decodeIfPresent(Int.self, forKey: .bundleVersion) ?? 1
        profileSchemaVersion = try values.decodeIfPresent(Int.self, forKey: .profileSchemaVersion) ?? 1
        guard profileSchemaVersion <= 2 else {
            throw DecodingError.dataCorruptedError(forKey: .profileSchemaVersion, in: values, debugDescription: "Router profile schema is newer than this app supports")
        }
        nodeProofID = try values.decodeIfPresent(String.self, forKey: .nodeProofID) ?? ""
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
        logicalModes = try values.decodeIfPresent([LogicalMode].self, forKey: .logicalModes) ?? []
        modes = try values.decodeIfPresent([VPNMode].self, forKey: .modes) ?? []
        profiles = try values.decodeIfPresent([String: [String: String]].self, forKey: .profiles) ?? [:]

        let selected = routerProfiles.first(where: { $0.id == selectedRouterID }) ?? routerProfiles.first
        if let selected {
            if endpoint.isEmpty {
                endpoint = selected.endpoint
                routerAPI = selected.routerAPI
                apiToken = selected.apiToken
                adGuardIPv4 = selected.adGuardIPv4
                adGuardIPv6 = selected.adGuardIPv6
                socks5Host = selected.socksHost
                socks5Port = selected.socksPort
            }
            let nested = (selected.nodeProofID ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
            if !nested.isEmpty && nested.range(of: "^[0-9a-f]{64}$", options: .regularExpression) == nil {
                throw DecodingError.dataCorruptedError(forKey: .nodeProofID, in: values, debugDescription: "Router profile node proof id is invalid")
            }
            if nodeProofID.isEmpty {
                nodeProofID = nested
            } else if !nested.isEmpty && nested != nodeProofID {
                throw DecodingError.dataCorruptedError(forKey: .nodeProofID, in: values, debugDescription: "Router bundle node proof ids disagree")
            }
        }
        nodeProofID = nodeProofID.trimmingCharacters(in: .whitespacesAndNewlines)
        if !nodeProofID.isEmpty && nodeProofID.range(of: "^[0-9a-f]{64}$", options: .regularExpression) == nil {
            throw DecodingError.dataCorruptedError(forKey: .nodeProofID, in: values, debugDescription: "Router node proof id is invalid")
        }
        socks5Username = ""
        socks5Password = ""
    }
}
