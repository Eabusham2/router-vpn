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
    @Published var tunnelTransitioning = false
    @Published var message = "Import a router bundle from Files or pair from your home LAN"
    @Published var multihopProgressText = ""
    var multihopProgressGeneration = UUID()
    var multihopProgressInFlight: UUID?
    var multihopProgressDeadline = Date.distantPast
    @Published var activeEngine = "none"
    @Published var activeRawProfile = ""
    private(set) var activeSessionIdentity: IOSSessionIdentity?
    private var userDisconnectInProgress = false
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

    var baseSelectorEnabled: Bool { currentLogicalMode?.baseSelector == true }
    var profileMutationBlocked: Bool { connected || tunnelTransitioning || userDisconnectInProgress }

    func runtimeLabel(for mode: LogicalMode) -> String {
        guard let bundle,
              let selection = try? IOSRuntimeSelector.select(bundle: bundle, logicalModeID: mode.id)
        else { return "Unavailable" }
        switch selection.engine {
        case .wireGuard:
            return selection.rawProfileID.hasPrefix("awg2") ? "AmneziaWG • native" : "WireGuardKit"
        case .libbox: return "Libbox • \(selection.rawProfileID)"
        case .multihop: return "Multihop • WireGuard → \(selection.rawProfileID)"
        }
    }

    func runtimeReason(for mode: LogicalMode) -> String {
        guard let bundle else { return "Import a node bundle first." }
        do {
            let selection = try IOSRuntimeSelector.select(bundle: bundle, logicalModeID: mode.id)
            if selection.engine == .wireGuard {
                return selection.rawProfileID.hasPrefix("awg2")
                    ? "Pinned native Apple AmneziaWG PacketTunnel with exact private selected-node proof."
                    : "Native WireGuardKit PacketTunnel with exact selected-node proof."
            }
            return "Pinned Libbox 1.14.1 PacketTunnel using imported raw profile \(selection.rawProfileID), with exact selected-node proof forced through the engine."
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
        multihopProgressGeneration = UUID(); multihopProgressText = ""
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
        basePreference = "auto"
        baseFallback = false
        if let selected = decoded.routerProfiles.first(where: { $0.id == decoded.selectedRouterID }) ?? decoded.routerProfiles.first {
            basePreference = selected.baseTunnel ?? "auto"
            baseFallback = selected.baseFallback ?? false
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

    func connect() async { await connect(rawProfileID: nil) }

    // Exact raw attempts are used by CUSTOM, SMART reductions and last-good
    // rollback. Resolving them through the logical picker would silently turn
    // an AWG Fast attempt into the preferred WG variant of the same mode.
    func connect(rawProfileID: String?) async {
        multihopProgressGeneration = UUID(); multihopProgressText = ""
        if connected { message = "Disconnect before starting another VPN session"; return }
        if tunnelTransitioning { message = "VPN transition already in progress"; return }
        tunnelTransitioning = true
        defer { tunnelTransitioning = false }
        guard saveRouter() else { connected = false; return }
        guard let bundle else { message = "Configure your home router first"; return }
        let selections: [IOSRuntimeSelection]
        do {
            if selectedRouterProfile?.multihopEnabled == true {
                guard rawProfileID == nil, let profile = selectedRouterProfile,
                      profile.multihopExitID == profile.id,
                      let mode = profile.multihopExitMode, ["wg", "shadowsocks", "hysteria2"].contains(mode) else {
                    throw IOSRuntimeSelectionError.unsupportedMode("Choose a valid multihop graph or disable multihop before selecting an individual raw mode.")
                }
                _ = try IOSRuntimeSelector.selectRaw(bundle: bundle, rawProfileID: mode)
                selections = [IOSRuntimeSelection(engine: .multihop, logicalModeID: "multihop", rawProfileID: mode, files: [:])]
            } else if let rawProfileID {
                selections = [try IOSRuntimeSelector.selectRaw(bundle: bundle, rawProfileID: rawProfileID)]
            } else if auto {
                let runnable = IOSRuntimeSelector.runnableModes(in: bundle)
                var values = try runnable.flatMap { try IOSRuntimeSelector.candidates(bundle: bundle, logicalModeID: $0.id) }
                if let profile = selectedRouterProfile {
                    let filtered = values.compactMap { selection -> (IOSRuntimeSelection, String?) in
                        (selection, IOSStrategyCatalog.autoRequirementFailure(rawID: selection.rawProfileID, profile: profile))
                    }
                    let rejected = filtered.compactMap { pair in pair.1 }
                    values = filtered.compactMap { pair in pair.1 == nil ? pair.0 : nil }
                    if values.isEmpty && !rejected.isEmpty {
                        throw IOSRuntimeSelectionError.unsupportedMode("AUTO failed closed: no iOS-runnable candidate satisfies the saved requirements. " + rejected.joined(separator: " • "))
                    }
                }
                let catalog = bundle.logicalModes.map(\.id)
                values = values.enumerated().sorted { lhs, rhs in
                    let a = lhs.element, b = rhs.element
                    if a.engine != b.engine { return a.engine == .wireGuard }
                    let left = catalog.firstIndex(of: a.logicalModeID) ?? Int.max
                    let right = catalog.firstIndex(of: b.logicalModeID) ?? Int.max
                    return left == right ? lhs.offset < rhs.offset : left < right
                }.map(\.element)
                guard !values.isEmpty else { throw IOSRuntimeSelectionError.unsupportedMode("This imported node has no iOS-runnable WireGuardKit or Libbox mode for the selected DNS policy.") }
                selections = strictKillSwitchEnabled ? [values[0]] : values
            } else {
                let candidates = try IOSRuntimeSelector.candidates(bundle: bundle, logicalModeID: selectedLogicalMode)
                selections = strictKillSwitchEnabled ? Array(candidates.prefix(1)) : candidates
            }
        } catch {
            connected = false
            message = error.localizedDescription
            return
        }

        do {
            let managers = try await NETunnelProviderManager.loadAllFromPreferences().filter {
                ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == "com.eabusham.routervpn.PacketTunnel"
            }
            guard managers.count <= 1 else {
                message = "Multiple Router VPN tunnel configurations exist; resolve them before connecting."
                return
            }
            let manager = managers.first ?? NETunnelProviderManager()
            guard manager.connection.status == .disconnected || manager.connection.status == .invalid else {
                message = "An existing Router VPN tunnel is still active or transitioning; disconnect it before replacement."
                return
            }
            guard self.bundle?.selectedRouterID == bundle.selectedRouterID,
                  self.bundle?.routerProfiles == bundle.routerProfiles,
                  self.bundle?.profiles == bundle.profiles else {
                message = "Node configuration changed while preparing the connection; no runtime was started."
                return
            }
            var failures: [String] = []
            for (index, selection) in selections.enumerated() {
                if auto { message = "AUTO \(index + 1)/\(selections.count) • trying \(modeName(selection.logicalModeID)) • \(engineName(selection))…" }
                let success = try await start(manager: manager, bundle: bundle, selection: selection)
                if success {
                    connected = true
                    activeEngine = selection.engine.rawValue
                    activeRawProfile = selection.rawProfileID
                    selectedLogicalMode = selection.logicalModeID
                    selectedMode = selection.rawProfileID
                    let strictText = strictKillSwitchEnabled ? " • strict route lockdown" : ""
                    message = "Connected • \(modeName(selection.logicalModeID)) • \(engineName(selection))\(strictText) • selected-node proof passed"
                    return
                }
                failures.append("\(modeName(selection.logicalModeID)) / \(engineName(selection))")
                if strictKillSwitchEnabled {
                    connected = false
                    message = "Strict AUTO failed closed on \(failures[0]). iOS will not cycle to another engine after a failed strict tunnel because that transition could create a route-lockdown gap; choose another mode manually."
                    return
                }
                guard await stopTrial(manager) else {
                    message = "Previous VPN teardown is unverified; fallback was stopped rather than overlapping runtimes."
                    return
                }
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
            "basePreference": selection.rawProfileID.hasPrefix("awg2") ? "awg" : "wg",
            "baseFallback": baseFallback,
            "bundle": try JSONEncoder().encode(bundle)
        ]
        configuration["rawProfileID"] = selection.rawProfileID
        var entryStrict = false
        if selection.engine == .multihop {
            let entry = try iosMultihopEntryBundle(for: bundle)
            configuration["entryBundle"] = try JSONEncoder().encode(entry)
            if let profile = entry.routerProfiles.first(where: { $0.id == entry.selectedRouterID }) {
                entryStrict = profile.killSwitch == true || ["always", "strict", "on", "enabled", "lockdown"].contains(profile.killSwitchPolicy ?? "off")
            }
        }
        proto.providerConfiguration = configuration

        let strict = strictKillSwitchEnabled || entryStrict
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
        return await waitForConnection(manager, attempts: selection.engine == .multihop ? ((selectedRouterProfile?.multihopExecution ?? "local") == "local" ? 100 : 480) : 40)
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

    private func stopTrial(_ manager: NETunnelProviderManager) async -> Bool {
        manager.isOnDemandEnabled = false
        manager.onDemandRules = []
        do { try await manager.saveToPreferences() }
        catch { manager.connection.stopVPNTunnel(); return false }
        manager.connection.stopVPNTunnel()
        for _ in 0..<12 {
            if manager.connection.status == .disconnected || manager.connection.status == .invalid { return true }
            try? await Task.sleep(for: .milliseconds(150))
        }
        return manager.connection.status == .disconnected || manager.connection.status == .invalid
    }

    private func modeName(_ id: String) -> String { logicalModes.first(where: { $0.id == id })?.name ?? id }
    private func engineName(_ selection: IOSRuntimeSelection) -> String {
        if selection.engine == .multihop { return "WireGuard entry → \(selection.rawProfileID) exit" }
        if selection.engine == .libbox { return "Libbox 1.14.1" }
        return selection.rawProfileID.hasPrefix("awg2") ? "AmneziaWG native" : "WireGuardKit"
    }

    func refreshTunnelStatus() async {
        guard !userDisconnectInProgress else { return }
        do {
            let managers = try await NETunnelProviderManager.loadAllFromPreferences().filter {
                ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == "com.eabusham.routervpn.PacketTunnel"
            }
            guard !userDisconnectInProgress else { return }
            guard managers.count <= 1 else { throw IOSRuntimeSelectionError.unsupportedMode("Multiple Router VPN sessions make status ownership ambiguous.") }
            guard let manager = managers.first else {
                connected = false; tunnelTransitioning = false; activeSessionIdentity = nil
                activeEngine = "none"; activeRawProfile = ""; return
            }
            let status = manager.connection.status
            tunnelTransitioning = status == .connecting || status == .disconnecting || status == .reasserting
            connected = status == .connected
            activeSessionIdentity = nil
            if connected {
                guard let proto = manager.protocolConfiguration as? NETunnelProviderProtocol,
                      let configuration = proto.providerConfiguration,
                      let data = configuration["bundle"] as? Data,
                      let connectedAt = manager.connection.connectedDate else {
                    throw IOSRuntimeSelectionError.unsupportedMode("The connected tunnel did not provide its frozen session identity.")
                }
                let engine = configuration["engine"] as? String ?? "wireguard"
                let raw = configuration["rawProfileID"] as? String ?? configuration["mode"] as? String ?? "wg"
                let identity = try IOSSessionIdentity(connectedAt: connectedAt, engine: engine, rawProfile: raw,
                    bundleData: data, entryBundleData: configuration["entryBundle"] as? Data)
                activeEngine = engine; activeRawProfile = raw; activeSessionIdentity = identity
            }
        } catch {
            guard !userDisconnectInProgress else { return }
            // Failure to read preferences is UNKNOWN, not proof that the VPN is
            // down. Lock mutations and invalidate measurements until readback.
            activeSessionIdentity = nil
            tunnelTransitioning = true
            message = "Tunnel status is unverified: \(error.localizedDescription)"
        }
    }

    func disconnect() {
        multihopProgressGeneration = UUID(); multihopProgressText = ""
        guard !tunnelTransitioning, !userDisconnectInProgress else { return }
        userDisconnectInProgress = true
        tunnelTransitioning = true
        activeSessionIdentity = nil
        message = "Disconnecting…"
        Task { await completeUserDisconnect() }
    }

    private func completeUserDisconnect() async {
        defer { userDisconnectInProgress = false }
        do {
            let managers = try await NETunnelProviderManager.loadAllFromPreferences().filter {
                ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == "com.eabusham.routervpn.PacketTunnel"
            }
            guard managers.count <= 1 else {
                throw IOSRuntimeSelectionError.unsupportedMode("Multiple Router VPN managers make disconnect ownership ambiguous.")
            }
            if let manager = managers.first {
                manager.isOnDemandEnabled = false
                manager.onDemandRules = []
                var persistenceError: Error?
                do {
                    try await manager.saveToPreferences()
                    try await manager.loadFromPreferences()
                    guard !manager.isOnDemandEnabled, (manager.onDemandRules ?? []).isEmpty else {
                        throw IOSRuntimeSelectionError.unsupportedMode("On-demand reconnect was not disabled by preference readback.")
                    }
                } catch { persistenceError = error }
                // Even when persistence fails, attempt to stop our own current
                // connection. Never stop a different provider or report success
                // while a saved on-demand policy could immediately reconnect.
                guard (manager.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == "com.eabusham.routervpn.PacketTunnel" else {
                    throw IOSRuntimeSelectionError.unsupportedMode("VPN manager ownership changed during disconnect.")
                }
                manager.connection.stopVPNTunnel()
                for _ in 0..<24 {
                    if manager.connection.status == .disconnected || manager.connection.status == .invalid { break }
                    try await Task.sleep(for: .milliseconds(150))
                }
                if let persistenceError { throw persistenceError }
                try await manager.loadFromPreferences()
                guard (manager.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == "com.eabusham.routervpn.PacketTunnel",
                      !manager.isOnDemandEnabled, (manager.onDemandRules ?? []).isEmpty,
                      manager.connection.status == .disconnected || manager.connection.status == .invalid else {
                    throw IOSRuntimeSelectionError.unsupportedMode("The owned VPN session did not finish a verified stop.")
                }
            }
            connected = false
            activeSessionIdentity = nil
            activeEngine = "none"
            activeRawProfile = ""
            tunnelTransitioning = false
            message = "Disconnected"
        } catch {
            // Unknown teardown is not Disconnected. Keep mutations locked and
            // invalidate Speed Lab/forwarding identity until fresh system status.
            activeSessionIdentity = nil
            tunnelTransitioning = true
            message = "Disconnect is unverified: \(error.localizedDescription)"
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
