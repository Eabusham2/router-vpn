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
    @Published var homeLANCIDRs: [String] = []
    @Published var lanImportHost = ""
    @Published var lanPairingCode = ""
    @Published var auto = true
    @Published var daita = false
    @Published var jumbo = false
    @Published var connected = false
    @Published var message = "Import a router bundle from Files or pair from your home LAN"
    @Published var activeEngine = "none"
    @Published var activeRawProfile = ""
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
        lanImportHost = defaults.string(forKey: lanImportKey) ?? ""
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
        guard let bundle else { return [] }
        return IOSRuntimeSelector.runnableModes(in: bundle)
    }

    var iosManualModeSupported: Bool {
        guard let bundle else { return false }
        return (try? IOSRuntimeSelector.select(bundle: bundle, logicalModeID: selectedLogicalMode)) != nil
    }

    var baseSelectorEnabled: Bool { false }

    func runtimeLabel(for mode: LogicalMode) -> String {
        guard let bundle,
              let selection = try? IOSRuntimeSelector.select(bundle: bundle, logicalModeID: mode.id)
        else { return "Unavailable" }
        switch selection.engine {
        case .wireGuard: return "WireGuardKit"
        case .libbox: return "Libbox • \(selection.rawProfileID)"
        }
    }

    func runtimeReason(for mode: LogicalMode) -> String {
        guard let bundle else { return "Import a node bundle first." }
        do {
            let selection = try IOSRuntimeSelector.select(bundle: bundle, logicalModeID: mode.id)
            return selection.engine == .wireGuard
                ? "Native WireGuardKit PacketTunnel with exact selected-node proof."
                : "Pinned Libbox 1.13.12 PacketTunnel using imported raw profile \(selection.rawProfileID), with exact selected-node proof forced through the engine."
        } catch {
            return error.localizedDescription
        }
    }

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
        let prepared = try IOSDNSRuntimePolicy.patch(decoded)
        apply(prepared)
        guard saveRouter() else { throw NSError(domain: "RouterVPN.ProfileSave", code: 1, userInfo: [NSLocalizedDescriptionKey: message]) }
        message = "Router bundle imported • \(iosRunnableLogicalModes.count) iOS runtime mode(s) available"
    }

    func importFromLAN() async {
        let raw = lanImportHost.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !raw.isEmpty else { message = "Enter the AI Board LAN IP or hostname"; return }
        let code = lanPairingCode.trimmingCharacters(in: .whitespacesAndNewlines)
        guard code.count == 6, code.allSatisfy(\.isNumber) else {
            message = "Enter the 6-digit one-time pairing code shown by the authenticated Setup Center"
            return
        }
        let host = raw.replacingOccurrences(of: "http://", with: "").replacingOccurrences(of: "https://", with: "").trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        guard !host.contains("/"), let url = URL(string: "http://\(host):8786/api/pairing/redeem") else { message = "Invalid LAN host"; return }
        do {
            var req = URLRequest(url: url)
            req.httpMethod = "POST"
            req.timeoutInterval = 12
            req.cachePolicy = .reloadIgnoringLocalAndRemoteCacheData
            req.setValue("application/json", forHTTPHeaderField: "Content-Type")
            req.httpBody = try JSONSerialization.data(withJSONObject: ["code": code])
            let (data, response) = try await URLSession.shared.data(for: req)
            guard let http = response as? HTTPURLResponse else { throw URLError(.badServerResponse) }
            guard http.statusCode == 200 else {
                if http.statusCode == 401 || http.statusCode == 403 { throw NSError(domain: "RouterVPN.Pairing", code: http.statusCode, userInfo: [NSLocalizedDescriptionKey: "Pairing code is invalid, expired, already used, or this request is not from the home LAN"]) }
                throw URLError(.badServerResponse)
            }
            try importBundle(data)
            lanPairingCode = ""
            UserDefaults.standard.set(raw, forKey: lanImportKey)
            message = "Paired securely with \(host) over the home LAN • \(iosRunnableLogicalModes.count) iOS runtime mode(s) available"
        } catch { message = "LAN pairing failed: \(error.localizedDescription)" }
    }

    @discardableResult
    func saveRouter() -> Bool {
        guard !endpoint.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { message = "Enter the home router public IP or hostname"; return false }
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
        do { current = try IOSDNSRuntimePolicy.patch(current) }
        catch { message = "DNS policy is not runnable on this iOS node: \(error.localizedDescription)"; return false }
        bundle = current
        guard let data = try? JSONEncoder().encode(current) else { message = "Router profile could not be encoded"; return false }
        UserDefaults.standard.set(data, forKey: bundleKey)
        UserDefaults.standard.set(lanImportHost, forKey: lanImportKey)
        message = "Router profile saved on this device"
        return true
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
        let runnable = IOSRuntimeSelector.runnableModes(in: decoded)
        if !runnable.contains(where: { $0.id == selectedLogicalMode }) { selectedLogicalMode = runnable.first?.id ?? "base-raw" }
        selectedMode = selectedLogicalMode
    }

    private func legacyLogicalModes(_ oldModes: [VPNMode]) -> [LogicalMode] {
        oldModes.map { LogicalMode(id: $0.id, name: $0.name, description: $0.protection, baseSelector: false, fallback: false, variants: ["native": $0.id]) }
    }

    func modeCandidates() -> [String] {
        guard let bundle,
              let selection = try? IOSRuntimeSelector.select(bundle: bundle, logicalModeID: selectedLogicalMode)
        else { return [] }
        return [selection.rawProfileID]
    }

    func connect() async {
        guard saveRouter() else { connected = false; return }
        guard let bundle else { message = "Configure your home router first"; return }
        let selections: [IOSRuntimeSelection]
        do {
            if auto {
                let runnable = IOSRuntimeSelector.runnableModes(in: bundle)
                var values = try runnable.map { try IOSRuntimeSelector.select(bundle: bundle, logicalModeID: $0.id) }
                values.sort { lhs, rhs in
                    if lhs.engine != rhs.engine { return lhs.engine == .wireGuard }
                    return lhs.logicalModeID < rhs.logicalModeID
                }
                guard !values.isEmpty else { throw IOSRuntimeSelectionError.unsupportedMode("This imported node has no iOS-runnable WireGuardKit or Libbox mode for the selected DNS policy.") }
                selections = strictKillSwitchEnabled ? [values[0]] : values
            } else {
                selections = [try IOSRuntimeSelector.select(bundle: bundle, logicalModeID: selectedLogicalMode)]
            }
        } catch {
            connected = false
            message = error.localizedDescription
            return
        }

        do {
            let managers = try await NETunnelProviderManager.loadAllFromPreferences()
            let manager = managers.first ?? NETunnelProviderManager()
            var failures: [String] = []
            for (index, selection) in selections.enumerated() {
                if auto { message = "AUTO \(index + 1)/\(selections.count) • trying \(modeName(selection.logicalModeID)) • \(engineName(selection.engine))…" }
                let success = try await start(manager: manager, bundle: bundle, selection: selection)
                if success {
                    connected = true
                    activeEngine = selection.engine.rawValue
                    activeRawProfile = selection.rawProfileID
                    selectedLogicalMode = selection.logicalModeID
                    selectedMode = selection.rawProfileID
                    let strictText = strictKillSwitchEnabled ? " • strict route lockdown" : ""
                    message = "Connected • \(modeName(selection.logicalModeID)) • \(engineName(selection.engine))\(strictText) • selected-node proof passed"
                    return
                }
                failures.append("\(modeName(selection.logicalModeID)) / \(engineName(selection.engine))")
                if strictKillSwitchEnabled {
                    connected = false
                    message = "Strict AUTO failed closed on \(failures[0]). iOS will not cycle to another engine after a failed strict tunnel because that transition could create a route-lockdown gap; choose another mode manually."
                    return
                }
                await stopTrial(manager)
            }
            connected = false
            activeEngine = "none"
            activeRawProfile = ""
            message = "AUTO: no iOS runtime passed PacketTunnel + selected-node proof. Tried: \(failures.joined(separator: ", "))."
        } catch {
            connected = false
            activeEngine = "none"
            activeRawProfile = ""
            message = error.localizedDescription
        }
    }

    private func start(manager: NETunnelProviderManager, bundle: ClientBundle, selection: IOSRuntimeSelection) async throws -> Bool {
        let proto = NETunnelProviderProtocol()
        proto.providerBundleIdentifier = "com.eabusham.routervpn.PacketTunnel"
        proto.serverAddress = bundle.endpoint
        var configuration: [String: Any] = [
            "engine": selection.engine.rawValue,
            "mode": selection.rawProfileID,
            "modeCandidates": [selection.rawProfileID],
            "logicalMode": selection.logicalModeID,
            "basePreference": "wg",
            "baseFallback": false,
            "bundle": try JSONEncoder().encode(bundle)
        ]
        if selection.engine == .libbox { configuration["rawProfileID"] = selection.rawProfileID }
        proto.providerConfiguration = configuration

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
        activeEngine = selection.engine.rawValue
        activeRawProfile = selection.rawProfileID
        return await waitForConnection(manager, attempts: 40)
    }

    private func waitForConnection(_ manager: NETunnelProviderManager, attempts: Int) async -> Bool {
        var sawConnecting = false
        for _ in 0..<attempts {
            switch manager.connection.status {
            case .connected: return true
            case .invalid: return false
            case .disconnected:
                if sawConnecting { return false }
                try? await Task.sleep(for: .milliseconds(250))
            case .disconnecting: return false
            case .connecting, .reasserting:
                sawConnecting = true
                try? await Task.sleep(for: .milliseconds(250))
            @unknown default:
                try? await Task.sleep(for: .milliseconds(250))
            }
        }
        return manager.connection.status == .connected
    }

    private func stopTrial(_ manager: NETunnelProviderManager) async {
        manager.isOnDemandEnabled = false
        manager.onDemandRules = []
        try? await manager.saveToPreferences()
        manager.connection.stopVPNTunnel()
        for _ in 0..<12 {
            if manager.connection.status == .disconnected || manager.connection.status == .invalid { return }
            try? await Task.sleep(for: .milliseconds(150))
        }
    }

    private func modeName(_ id: String) -> String { logicalModes.first(where: { $0.id == id })?.name ?? id }
    private func engineName(_ engine: IOSRuntimeEngine) -> String { engine == .wireGuard ? "WireGuardKit" : "Libbox 1.13.12" }

    func refreshTunnelStatus() async {
        let managers = (try? await NETunnelProviderManager.loadAllFromPreferences()) ?? []
        guard let manager = managers.first else { connected = false; return }
        connected = manager.connection.status == .connected
        if connected, let proto = manager.protocolConfiguration as? NETunnelProviderProtocol {
            activeEngine = (proto.providerConfiguration?["engine"] as? String) ?? "wireguard"
            activeRawProfile = (proto.providerConfiguration?["rawProfileID"] as? String) ?? (proto.providerConfiguration?["mode"] as? String) ?? "wg"
        }
    }

    func disconnect() {
        Task {
            let managers = (try? await NETunnelProviderManager.loadAllFromPreferences()) ?? []
            guard let manager = managers.first else {
                connected = false; activeEngine = "none"; activeRawProfile = ""; message = "Disconnected"; return
            }
            manager.isOnDemandEnabled = false
            manager.onDemandRules = []
            try? await manager.saveToPreferences()
            manager.connection.stopVPNTunnel()
            connected = false
            activeEngine = "none"
            activeRawProfile = ""
            message = "Disconnected"
        }
    }

    func applyForward(dmz: Bool) async {
        guard saveRouter() else { return }
        if dmz {
            message = "Protected DMZ is a broad server/admin action. Manage it in the authenticated home Setup Center; this app creates only explicit forwarding owned by this tunnel peer."
            return
        }
        guard let b = bundle, let url = URL(string: b.routerAPI + "/api/forward") else { message = "Configure your home router first"; return }
        guard let from = Int(forwardFrom), let to = Int(forwardTo), let target = Int(forwardTarget) else { message = "Enter valid ports"; return }
        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.setValue("Bearer \(b.apiToken)", forHTTPHeaderField: "Authorization")
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.httpBody = try? JSONSerialization.data(withJSONObject: ["protocol": forwardProtocol, "from": from, "to": to, "target_port": target, "dmz": false])
        do {
            let (_, response) = try await URLSession.shared.data(for: req)
            guard (response as? HTTPURLResponse)?.statusCode == 200 else { throw URLError(.badServerResponse) }
            message = "Port forwarding applied for this tunnel peer"
        } catch { message = "Port forwarding requires a connected Router VPN peer path: \(error.localizedDescription)" }
    }

    func clearForward() async {
        guard saveRouter() else { return }
        guard let b = bundle, let url = URL(string: b.routerAPI + "/api/forward/clear") else { return }
        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.setValue("Bearer \(b.apiToken)", forHTTPHeaderField: "Authorization")
        do {
            let (_, response) = try await URLSession.shared.data(for: req)
            guard (response as? HTTPURLResponse)?.statusCode == 200 else { throw URLError(.badServerResponse) }
            message = "This tunnel peer's forwarding cleared"
        }
        catch { message = error.localizedDescription }
    }
}
