import Combine
import Foundation
@preconcurrency import NetworkExtension

@MainActor
final class RouterVPNModel: ObservableObject {
    @Published var modes: [VPNMode] = []
    @Published var logicalModes: [LogicalMode] = []
    @Published var selectedMode = "wg"
    @Published var selectedLogicalMode = "base-raw"
    @Published var basePreference = "wg"
    @Published var baseFallback = false
    @Published var homeLANAccess = true
    @Published var homeLANCIDRs = ["192.168.50.0/24"]
    @Published var lanImportHost = "192.168.50.133"
    @Published var auto = true
    @Published var daita = false
    @Published var jumbo = false
    @Published var connected = false
    @Published var message = "Import a router bundle from Files or directly from your home LAN"
    @Published var forwardProtocol = "both"
    @Published var forwardFrom = "25565"
    @Published var forwardTo = "25565"
    @Published var forwardTarget = "25565"
    @Published var routerName = "Home Router"
    @Published var endpoint = ""
    @Published var routerAPI = "http://10.77.0.1:8787"
    @Published var apiToken = ""
    @Published var socksHost = "10.77.0.1"
    @Published var socksPort = "1080"
    @Published var socksUsername = ""
    @Published var socksPassword = ""

    private(set) var bundle: ClientBundle?
    private let bundleKey = "router-vpn.bundle"
    private let lanImportKey = "router-vpn.lan-import-host"

    init() {
        let defaults = UserDefaults.standard
        lanImportHost = defaults.string(forKey: lanImportKey) ?? "192.168.50.133"
        if let data = defaults.data(forKey: bundleKey),
           let saved = try? JSONDecoder().decode(ClientBundle.self, from: data) {
            apply(saved)
            message = "Saved router profile loaded"
        }
        Task { await refreshTunnelStatus() }
    }

    var socksSummary: String {
        guard !socksHost.isEmpty else { return "Configure your home router first" }
        return "\(socksHost):\(socksPort) • no authentication • tunnel/LAN only"
    }

    var currentLogicalMode: LogicalMode? {
        logicalModes.first(where: { $0.id == selectedLogicalMode })
    }

    var iosRunnableLogicalModes: [LogicalMode] {
        logicalModes.filter { $0.id == "base-raw" && $0.variants["wg"] == "wg" }
    }

    var iosManualModeSupported: Bool {
        selectedLogicalMode == "base-raw" && currentLogicalMode?.variants["wg"] == "wg"
    }

    var baseSelectorEnabled: Bool { false }

    private var selectedRouterProfile: RouterProfile? {
        guard let bundle else { return nil }
        return bundle.routerProfiles.first(where: { $0.id == bundle.selectedRouterID }) ?? bundle.routerProfiles.first
    }

    private var strictKillSwitchEnabled: Bool {
        guard let profile = selectedRouterProfile else { return false }
        if profile.killSwitch == true { return true }
        let policy = (profile.killSwitchPolicy ?? "").trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        return ["strict", "always", "enabled", "on", "lockdown"].contains(policy)
    }

    func importBundle(_ data: Data) throws {
        guard data.count <= 32 * 1024 * 1024 else { throw URLError(.dataLengthExceedsMaximum) }
        let decoded = try JSONDecoder().decode(ClientBundle.self, from: data)
        apply(decoded)
        saveRouter()
        message = "Router bundle imported"
    }

    func importFromLAN() async {
        let raw = lanImportHost.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !raw.isEmpty else { message = "Enter the AI Board LAN IP or hostname"; return }
        let host = raw.replacingOccurrences(of: "http://", with: "").replacingOccurrences(of: "https://", with: "").trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        guard let url = URL(string: "http://\(host):8786/router-vpn-bundle.json") else {
            message = "Invalid LAN host"
            return
        }
        do {
            var req = URLRequest(url: url)
            req.timeoutInterval = 12
            req.cachePolicy = .reloadIgnoringLocalAndRemoteCacheData
            let (data, response) = try await URLSession.shared.data(for: req)
            guard let http = response as? HTTPURLResponse, http.statusCode == 200 else { throw URLError(.badServerResponse) }
            try importBundle(data)
            UserDefaults.standard.set(raw, forKey: lanImportKey)
            message = "Imported directly from \(host) over the home LAN"
        } catch {
            message = "LAN import failed: \(error.localizedDescription)"
        }
    }

    func saveRouter() {
        guard !endpoint.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            message = "Enter the home router public IP or hostname"
            return
        }
        var current = bundle ?? ClientBundle.empty
        current.endpoint = endpoint.trimmingCharacters(in: .whitespacesAndNewlines)
        current.apiToken = apiToken
        current.routerAPI = routerAPI
        current.socks5Host = socksHost
        current.socks5Port = Int(socksPort) ?? 1080
        current.socks5Username = ""
        current.socks5Password = ""
        current.modes = modes
        current.logicalModes = logicalModes
        bundle = current
        if let data = try? JSONEncoder().encode(current) { UserDefaults.standard.set(data, forKey: bundleKey) }
        UserDefaults.standard.set(lanImportHost, forKey: lanImportKey)
        message = "Router profile saved on this device"
    }

    private func apply(_ decoded: ClientBundle) {
        bundle = decoded
        modes = decoded.modes
        logicalModes = decoded.logicalModes.isEmpty ? legacyLogicalModes(decoded.modes) : decoded.logicalModes
        endpoint = decoded.endpoint
        routerAPI = decoded.routerAPI
        apiToken = decoded.apiToken
        socksHost = decoded.socks5Host
        socksPort = String(decoded.socks5Port)
        socksUsername = ""
        socksPassword = ""
        basePreference = "wg"
        baseFallback = false
        if let selected = decoded.routerProfiles.first(where: { $0.id == decoded.selectedRouterID }) ?? decoded.routerProfiles.first {
            if let access = selected.homeLANAccess { homeLANAccess = access }
            if let cidrs = selected.homeLANCIDRs, !cidrs.isEmpty { homeLANCIDRs = cidrs }
        }
        if !iosRunnableLogicalModes.contains(where: { $0.id == selectedLogicalMode }) {
            selectedLogicalMode = iosRunnableLogicalModes.first?.id ?? "base-raw"
        }
        selectedMode = "wg"
    }

    private func legacyLogicalModes(_ oldModes: [VPNMode]) -> [LogicalMode] {
        oldModes.map {
            LogicalMode(id: $0.id, name: $0.name, description: $0.protection, baseSelector: false, fallback: false, variants: ["native": $0.id])
        }
    }

    func modeCandidates() -> [String] {
        iosManualModeSupported ? ["wg"] : []
    }

    func connect() async {
        saveRouter()
        guard let bundle else { message = "Configure your home router first"; return }
        let candidates = modeCandidates()
        if !auto && candidates.isEmpty {
            connected = false
            message = "This iOS build currently supports manual Raw WireGuard only. Other modes remain visible as unavailable until their native engines are linked and proven."
            return
        }
        do {
            let managers = try await NETunnelProviderManager.loadAllFromPreferences()
            let manager = managers.first ?? NETunnelProviderManager()
            let proto = NETunnelProviderProtocol()
            proto.providerBundleIdentifier = "com.eabusham.routervpn.PacketTunnel"
            proto.serverAddress = bundle.endpoint
            proto.providerConfiguration = [
                "mode": auto ? "auto" : "wg",
                "modeCandidates": auto ? [] : ["wg"],
                "logicalMode": auto ? "auto" : "base-raw",
                "basePreference": "wg",
                "baseFallback": false,
                "bundle": try JSONEncoder().encode(bundle)
            ]

            // NetworkExtension owns the route-lockdown boundary on Apple
            // platforms. For a strict Router VPN policy, include all routable
            // traffic, make tunnel routes authoritative, and only exclude local
            // networks when the imported node policy says LAN access is off.
            let strict = strictKillSwitchEnabled
            proto.includeAllNetworks = strict
            proto.enforceRoutes = strict
            proto.excludeLocalNetworks = strict ? !homeLANAccess : false
            proto.excludeAPNs = false
            proto.excludeCellularServices = false

            manager.protocolConfiguration = proto
            manager.localizedDescription = routerName
            manager.isEnabled = true
            if strict {
                manager.onDemandRules = [NEOnDemandRuleConnect()]
                manager.isOnDemandEnabled = true
            } else {
                manager.isOnDemandEnabled = false
                manager.onDemandRules = []
            }
            try await manager.saveToPreferences()
            try await manager.loadFromPreferences()
            try manager.connection.startVPNTunnel()
            connected = false
            message = strict
                ? (auto ? "Connecting with AUTO → native WireGuard • strict route lockdown…" : "Connecting native WireGuard • strict route lockdown…")
                : (auto ? "Connecting with AUTO → native WireGuard…" : "Connecting native WireGuard…")
            await watchConnection(manager, attempts: 32)
        } catch {
            connected = false
            message = error.localizedDescription
        }
    }

    private func watchConnection(_ manager: NETunnelProviderManager, attempts: Int) async {
        for _ in 0..<attempts {
            switch manager.connection.status {
            case .connected:
                connected = true
                message = strictKillSwitchEnabled
                    ? "Connected • native WireGuard • strict route lockdown • selected-node proof passed"
                    : "Connected • native WireGuard • selected-node proof passed"
                return
            case .invalid:
                connected = false
                message = "Tunnel configuration is invalid"
                return
            case .disconnected:
                try? await Task.sleep(for: .milliseconds(250))
            case .disconnecting:
                connected = false
                message = "Disconnecting…"
                return
            case .connecting, .reasserting:
                connected = false
                try? await Task.sleep(for: .milliseconds(250))
            @unknown default:
                connected = false
                try? await Task.sleep(for: .milliseconds(250))
            }
        }
        connected = manager.connection.status == .connected
        if !connected {
            message = "Tunnel did not reach connected state. Check the Packet Tunnel/engine error."
        }
    }

    func refreshTunnelStatus() async {
        let managers = (try? await NETunnelProviderManager.loadAllFromPreferences()) ?? []
        guard let manager = managers.first else { connected = false; return }
        connected = manager.connection.status == .connected
    }

    func disconnect() {
        Task {
            let managers = (try? await NETunnelProviderManager.loadAllFromPreferences()) ?? []
            guard let manager = managers.first else {
                connected = false
                message = "Disconnected"
                return
            }
            // An explicit user disconnect is an intentional emergency-off
            // action. Disable on-demand first so NetworkExtension does not
            // immediately reconnect a strict profile behind the user's back.
            manager.isOnDemandEnabled = false
            manager.onDemandRules = []
            try? await manager.saveToPreferences()
            manager.connection.stopVPNTunnel()
            connected = false
            message = "Disconnected"
        }
    }

    func applyForward(dmz: Bool) async {
        saveRouter()
        guard let b = bundle, let url = URL(string: b.routerAPI + "/api/forward") else { message = "Configure your home router first"; return }
        guard let from = Int(forwardFrom), let to = Int(forwardTo), let target = Int(forwardTarget) else { message = "Enter valid ports"; return }
        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.setValue("Bearer \(b.apiToken)", forHTTPHeaderField: "Authorization")
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.httpBody = try? JSONSerialization.data(withJSONObject: ["protocol": forwardProtocol, "from": from, "to": to, "target_port": target, "dmz": dmz])
        do {
            let (_, response) = try await URLSession.shared.data(for: req)
            guard (response as? HTTPURLResponse)?.statusCode == 200 else { throw URLError(.badServerResponse) }
            message = dmz ? "Protected DMZ applied" : "Port forwarding applied"
        } catch { message = "Port forwarding requires a connected WireGuard/AWG peer path: \(error.localizedDescription)" }
    }

    func clearForward() async {
        saveRouter()
        guard let b = bundle, let url = URL(string: b.routerAPI + "/api/forward/clear") else { return }
        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.setValue("Bearer \(b.apiToken)", forHTTPHeaderField: "Authorization")
        do { _ = try await URLSession.shared.data(for: req); message = "Port forwarding cleared" }
        catch { message = error.localizedDescription }
    }
}