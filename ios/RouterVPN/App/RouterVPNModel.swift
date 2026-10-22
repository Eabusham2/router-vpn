import Libbox
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
    var iosConnectGeneration = UUID()
    let iosSpeedLabOwnership = IOSSpeedLabOwnership()
    var iosStrategyTaskActive = false
    private(set) var iosStrategyStatus: IOSStrategyStatus?
    var iosUserDisconnectInProgress: Bool { userDisconnectInProgress }
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

    /// Linking another node may preserve the durable selection, never the
    /// temporary bundle currently installed by a Speed Lab transaction.
    var persistedNodeBundle: ClientBundle? {
        guard let data = UserDefaults.standard.data(forKey: bundleKey) else { return nil }
        return try? JSONDecoder().decode(ClientBundle.self, from: data)
    }

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
        case .libbox: return selection.files["xray.json"] != nil ? "Xray + Libbox • \(selection.rawProfileID)" : "Libbox • \(selection.rawProfileID)"
        case .multihop: return "Multihop • \(selection.displayName)"
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
        return IOSDNSRuntimePolicy.selectedProfile(in: bundle)
    }

    private var strictKillSwitchEnabled: Bool {
        guard let profile = selectedRouterProfile else { return false }
        if profile.killSwitch == true { return true }
        let policy = (profile.killSwitchPolicy ?? "").trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        return ["strict", "always", "enabled", "on", "lockdown"].contains(policy)
    }

    func importBundle(_ data: Data) throws {
        guard iosSpeedLabOwnership.admit(.profile) else { throw CancellationError() }
        multihopProgressGeneration = UUID(); multihopProgressText = ""
        guard data.count <= 32 * 1024 * 1024 else { throw URLError(.dataLengthExceedsMaximum) }
        let decoded = try JSONDecoder().decode(ClientBundle.self, from: data)
        try IOSExternalExecution.validateImported(decoded)
        let prepared = try IOSDNSRuntimePolicy.patch(decoded)
        let previous = bundle
        apply(prepared)
        guard saveRouter() else {
            let failure = message
            apply(previous ?? ClientBundle.empty)
            if previous == nil { bundle = nil }
            throw NSError(domain: "RouterVPN.ProfileSave", code: 1, userInfo: [NSLocalizedDescriptionKey: failure])
        }
        message = "Router bundle imported • \(iosRunnableLogicalModes.count) iOS runtime mode(s) available"
    }

    /// A link validates its normalized source before one atomic private-store
    /// commit. Adopting those exact bytes must not perform a second, fallible
    /// private save after the first has already made the node durable.
    func commitLinkedNodeBundle(_ data: Data) throws {
        guard IOSSpeedLabContext.owner == nil else { throw CancellationError() }
        guard data.count <= 32 * 1024 * 1024 else { throw URLError(.dataLengthExceedsMaximum) }
        let linked = try IOSNodeBundleStore.shared.link(data, preserving: persistedNodeBundle) { normalized in
            try IOSExternalExecution.validateImported(normalized)
            var prepared = normalized
            prepared.endpoint = prepared.endpoint.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !prepared.endpoint.isEmpty else {
                throw NSError(domain: "RouterVPN.ProfileSave", code: 1,
                    userInfo: [NSLocalizedDescriptionKey: "Enter the home router public IP or hostname"])
            }
            prepared.socks5Username = ""; prepared.socks5Password = ""
            if prepared.logicalModes.isEmpty { prepared.logicalModes = legacyLogicalModes(prepared.modes) }
            return try IOSDNSRuntimePolicy.patch(prepared)
        }
        apply(linked.bundle)
        UserDefaults.standard.set(linked.data, forKey: bundleKey)
        UserDefaults.standard.set(lanImportHost, forKey: lanImportKey)
        multihopProgressGeneration = UUID(); multihopProgressText = ""
    }

    func restoreIOSSpeedLabBundle(_ data: Data?) throws {
        guard let owner = IOSSpeedLabContext.owner,
              iosSpeedLabOwnership.mayRestoreSelection(owner), !profileMutationBlocked else { throw CancellationError() }
        if let data { try importBundle(data) }
        else {
            apply(ClientBundle.empty)
            bundle = nil
        }
    }

    /// Measurement commits use the same atomic node store as explicit edits.
    /// Never call import/save again after the durable commit already succeeded.
    func commitNodeLatency(_ result: IOSLatencyResult, expectedRecord: Data,
                           expectedSelection: Data, owner: UUID) throws {
        try iosSpeedLabOwnership.require(owner)
        guard !profileMutationBlocked, let bundle, bundle.selectedRouterID == result.id else { throw CancellationError() }
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
        guard try encoder.encode(bundle) == expectedSelection,
              try encoder.encode(JSONDecoder().decode(ClientBundle.self, from: expectedRecord)) == expectedSelection else { throw CancellationError() }
        let committed = try IOSNodeBundleStore.shared.recordLatency(result, expectedRecord: expectedRecord, current: persistedNodeBundle)
        self.bundle = committed.bundle
        UserDefaults.standard.set(committed.data, forKey: bundleKey)
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
        guard iosSpeedLabOwnership.admit(.profile) else { return false }
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
        guard let data = try? JSONEncoder().encode(current) else { message = "Router profile could not be encoded"; return false }
        if IOSSpeedLabContext.owner == nil {
            do {
                if !current.routerProfiles.isEmpty { try IOSNodeBundleStore.shared.save(current) }
            } catch {
                message = "Private node profile could not be saved: \(error.localizedDescription)"
                return false
            }
            UserDefaults.standard.set(data, forKey: bundleKey)
            UserDefaults.standard.set(lanImportHost, forKey: lanImportKey)
        }
        bundle = current
        message = IOSSpeedLabContext.owner == nil ? "Router profile saved on this device" : "Temporary test profile prepared"
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
        guard await iosSpeedLabOwnership.admitConnection() else { return }
        multihopProgressGeneration = UUID(); multihopProgressText = ""
        if selectedRouterProfile?.multihopEnabled != true {
            do {
                if !connected && !tunnelTransitioning { guard saveRouter() else { return } }
                let kind: IOSStrategyPlan.Kind = rawProfileID != nil ? .manual :
                    (auto ? .automatic : (selectedLogicalMode == "all" ? .all : .logical))
                let candidates = try iosStrategySelections(kind: kind, rawProfileID: rawProfileID)
                _ = await runIOSOwnedStrategy(kind: kind, selections: candidates)
            } catch { message = error.localizedDescription }
            return
        }
        guard !connected, !tunnelTransitioning, !userDisconnectInProgress else {
            message = "Disconnect the current VPN before replacing its multihop graph."; return
        }
        let generation = UUID(); iosConnectGeneration = generation
        guard saveRouter(), let bundle else { return }
        tunnelTransitioning = true
        do {
            let selection = try IOSRuntimeSelector.selectMultihop(bundle: bundle, rawProfileID: rawProfileID)
            let managers = try await NETunnelProviderManager.loadAllFromPreferences().filter {
                ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == "com.eabusham.routervpn.PacketTunnel"
            }
            guard iosConnectGeneration == generation, !userDisconnectInProgress else { return }
            guard managers.count <= 1 else {
                throw IOSRuntimeSelectionError.unsupportedMode("Multiple Router VPN managers make connection ownership ambiguous.")
            }
            let manager = managers.first ?? NETunnelProviderManager()
            guard manager.connection.status == .disconnected || manager.connection.status == .invalid,
                  self.bundle?.selectedRouterID == bundle.selectedRouterID,
                  self.bundle?.routerProfiles == bundle.routerProfiles, self.bundle?.profiles == bundle.profiles else {
                throw IOSRuntimeSelectionError.unsupportedMode("The selected node or VPN owner changed before multihop startup.")
            }
            let success = try await start(manager: manager, bundle: bundle, selection: selection)
            guard iosConnectGeneration == generation, !userDisconnectInProgress else { return }
            if success {
                connected = true; activeEngine = selection.engine.rawValue; activeRawProfile = selection.rawProfileID
                selectedLogicalMode = selection.logicalModeID; selectedMode = selection.rawProfileID
                message = "Connected • \(engineName(selection)) • selected-node proof passed"
                await refreshTunnelStatus()
            } else {
                connected = false
                message = "The captured multihop graph did not complete both node proofs."
                await refreshTunnelStatus()
            }
        } catch {
            guard iosConnectGeneration == generation, !userDisconnectInProgress else { return }
            connected = false; activeSessionIdentity = nil
            let failure = error.localizedDescription
            await refreshTunnelStatus()
            guard iosConnectGeneration == generation, !userDisconnectInProgress else { return }
            message = "Multihop startup was not completed: \(failure)"
        }
    }

    private func start(manager: NETunnelProviderManager, bundle: ClientBundle, selection: IOSRuntimeSelection) async throws -> Bool {
        let generation = iosConnectGeneration
        var launchBundle = bundle
        if selection.engine == .libbox && selection.files["xray.json"] != nil {
            // Carry the exact compiled wrapper, including legacy XHTTP imports,
            // into the extension. Do not merely update a host readiness label.
            guard let wrapperData = selection.files["sing-box.json"], let originalData = selection.files["xray.json"],
                  let wrapper = String(data: wrapperData, encoding: .utf8), let original = String(data: originalData, encoding: .utf8) else {
                throw IOSRuntimeSelectionError.unsupportedMode("The native Xray selection lost its owned graph.")
            }
            let mode = selection.rawProfileID
            let startLayer = try IOSRuntimeSelector.normalizedStartLayer(in: bundle)
            var aesInput: String?
            var startPolicy: String?
            if startLayer != "off" {
                guard let selected = IOSDNSRuntimePolicy.selectedProfile(in: bundle),
                      let encoded = bundle.profiles["shadowsocks"]?["sing-box.json"],
                      !encoded.isEmpty, encoded.utf8.count <= 6 * 1024 * 1024,
                      let bytes = Data(base64Encoded: encoded, options: []),
                      !bytes.isEmpty, bytes.count <= 4 * 1024 * 1024,
                      bytes.base64EncodedString() == encoded,
                      let text = String(data: bytes, encoding: .utf8) else {
                    throw IOSRuntimeSelectionError.unsupportedMode("Xray Start Layer requires its exact AES node profile.")
                }
                aesInput = text
                let metadata = ["mode": startLayer, "raw_mode": mode,
                                "node_kind": selected.nodeKind ?? "router-vpn", "router_api": selected.routerAPI]
                startPolicy = String(decoding: try JSONSerialization.data(withJSONObject: metadata), as: UTF8.self)
            }
            // Immutable captured strings may cross the asynchronous boundary;
            // live settings/credentials must be rechecked before publication.
            let capturedAES = aesInput, capturedPolicy = startPolicy
            let resolved = try await Task.detached(priority: .userInitiated) {
                var failure: NSError?
                let output: String?
                if let capturedAES, let capturedPolicy {
                    output = LibboxRouterResolveXrayStartLayerProfile(mode, wrapper, original, capturedAES, capturedPolicy, &failure)
                } else {
                    output = LibboxRouterResolveXrayProfile(mode, wrapper, original, &failure)
                }
                if let failure { throw failure }
                guard let output, output.utf8.count <= 12 * 1024 * 1024 else {
                    throw IOSRuntimeSelectionError.unsupportedMode("Native Xray endpoint preparation failed.")
                }
                return output
            }.value
            guard !Task.isCancelled, iosConnectGeneration == generation, !userDisconnectInProgress,
                  self.bundle?.selectedRouterID == bundle.selectedRouterID,
                  self.bundle?.routerProfiles == bundle.routerProfiles,
                  self.bundle?.profiles == bundle.profiles,
                  manager.connection.status == .disconnected || manager.connection.status == .invalid else {
                throw IOSRuntimeSelectionError.unsupportedMode("The selected node or VPN ownership changed during endpoint preparation.")
            }
            let replacements = try JSONDecoder().decode([String: Data].self, from: Data(resolved.utf8))
            let expectedFiles: Set<String> = startLayer == "off" ? ["sing-box.json", "xray.json"] : ["sing-box.json", "xray.json", "start-layer-source.json"]
            guard Set(replacements.keys) == expectedFiles, replacements.values.allSatisfy({ !$0.isEmpty && $0.count <= 4 * 1024 * 1024 }) else {
                throw IOSRuntimeSelectionError.unsupportedMode("Native Xray preparation returned an invalid asset set.")
            }
            var launchFiles = selection.files
            for (name, data) in replacements where name != "start-layer-source.json" { launchFiles[name] = data }
            if let aes = replacements["start-layer-source.json"] {
                // Launch-only address alignment; do not mutate bundle/self.bundle.
                guard launchBundle.profiles["shadowsocks"] != nil else { throw IOSRuntimeSelectionError.invalidSingBoxConfig }
                launchBundle.profiles["shadowsocks"]?["sing-box.json"] = aes.base64EncodedString()
            }
            launchBundle.profiles[selection.rawProfileID] = launchFiles.mapValues { $0.base64EncodedString() }
            launchBundle = try IOSDNSRuntimePolicy.patch(launchBundle)
        }
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
            "bundle": try JSONEncoder().encode(launchBundle)
        ]
        configuration["rawProfileID"] = selection.rawProfileID
        var entryStrict = false
        var entryAllowsLAN = true
        if selection.engine == .multihop {
            let entry = try iosMultihopEntryBundle(for: bundle)
            let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
            configuration["entryBundle"] = try encoder.encode(entry)
            if let profile = entry.routerProfiles.first(where: { $0.id == entry.selectedRouterID }) {
                entryAllowsLAN = profile.homeLANAccess ?? true
                entryStrict = profile.killSwitch == true || ["always", "strict", "on", "enabled", "lockdown"].contains(profile.killSwitchPolicy ?? "off")
            }
        }
        let maxSources = try IOSMAXSourceSelection.sourceHashes(provider: configuration) { mode, assets, metadata in
            var failure: NSError?
            let digest: String? = LibboxRouterCheckMAXProfile(mode, assets, metadata, &failure)
            if let failure { throw failure }
            guard let digest else { throw IOSMAXSourceSelection.issue() }
            return digest
        }
        if !maxSources.isEmpty { configuration["max_source_sha256"] = maxSources }
        IOSSpeedLabContext.mark(&configuration)
        proto.providerConfiguration = configuration

        let strict = strictKillSwitchEnabled || entryStrict
        proto.includeAllNetworks = strict
        proto.enforceRoutes = strict
        // Excluding local networks sends them OUTSIDE the tunnel. LAN-Off must
        // never enable that bypass; either hop can request the stricter policy.
        let capturedLANExclusion = strict && homeLANAccess && entryAllowsLAN
        proto.excludeLocalNetworks = capturedLANExclusion
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
        guard iosConnectGeneration == generation, !userDisconnectInProgress else { throw CancellationError() }
        try await manager.saveToPreferences()
        guard iosConnectGeneration == generation, !userDisconnectInProgress else { throw CancellationError() }
        try await manager.loadFromPreferences()
        guard iosConnectGeneration == generation, !userDisconnectInProgress else { throw CancellationError() }
        if !maxSources.isEmpty {
            if let capturedEntry = configuration["entryBundle"] as? Data {
                let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
                guard try encoder.encode(iosMultihopEntryBundle(for: bundle)) == capturedEntry else { throw IOSMAXSourceSelection.issue() }
            }
            guard !Task.isCancelled,
                  self.bundle?.selectedRouterID == bundle.selectedRouterID,
                  self.bundle?.routerProfiles == bundle.routerProfiles, self.bundle?.profiles == bundle.profiles,
                  let saved = manager.protocolConfiguration as? NETunnelProviderProtocol,
                  saved.providerConfiguration?["bundle"] as? Data == configuration["bundle"] as? Data,
                  saved.providerConfiguration?["entryBundle"] as? Data == configuration["entryBundle"] as? Data,
                  saved.providerConfiguration?["max_source_sha256"] as? [String: String] == maxSources,
                  saved.providerConfiguration?["rawProfileID"] as? String == selection.rawProfileID,
                  saved.providerConfiguration?["engine"] as? String == selection.engine.rawValue,
                  saved.includeAllNetworks == strict, saved.enforceRoutes == strict,
                  saved.excludeLocalNetworks == capturedLANExclusion,
                  manager.connection.status == .disconnected || manager.connection.status == .invalid else {
                throw IOSMAXSourceSelection.issue()
            }
        }
        let mtuHold = IOSMTUMeasurementGate.current
        let options: [String: NSObject]? = mtuHold.isEmpty ? nil : ["routervpn_mtu_hold": mtuHold as NSString]
        try manager.connection.startVPNTunnel(options: options)
        connected = false
        activeEngine = selection.engine.rawValue
        activeRawProfile = selection.rawProfileID
        return await waitForConnection(manager, attempts: selection.engine == .multihop ? ((selectedRouterProfile?.multihopExecution ?? "local") == "local" ? 100 : 480) : 40)
    }

    private func waitForConnection(_ manager: NETunnelProviderManager, attempts: Int) async -> Bool {
        let generation = iosConnectGeneration
        var sawConnecting = false
        for _ in 0..<attempts {
            guard iosConnectGeneration == generation, !userDisconnectInProgress, !Task.isCancelled else { return false }
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

    func iosInvalidateStrategyIdentity() {
        connected = false; activeSessionIdentity = nil
        tunnelTransitioning = true
    }

    func iosAdoptStrategyStatus(_ status: IOSStrategyStatus, manager: NETunnelProviderManager, bundleData: Data) throws {
        guard !userDisconnectInProgress, manager.connection.status == .connected,
              let connectedAt = manager.connection.connectedDate else { throw CancellationError() }
        iosStrategyStatus = status
        connected = status.isProven
        tunnelTransitioning = !status.isProven
        activeSessionIdentity = nil
        activeEngine = status.isProven ? "libbox" : "none"
        activeRawProfile = status.currentRaw
        message = status.message
        if status.isProven {
            let identity = try IOSSessionIdentity(connectedAt: connectedAt, engine: "libbox", rawProfile: status.provenRaw,
                bundleData: bundleData, entryBundleData: nil, providerSession: status.providerSession, runtimeEpoch: status.runtimeEpoch)
            activeSessionIdentity = identity
            selectedMode = status.provenRaw
            selectedLogicalMode = status.kind == .all ? "all" : status.provenLogical
        }
    }

    private func modeName(_ id: String) -> String { logicalModes.first(where: { $0.id == id })?.name ?? id }
    private func engineName(_ selection: IOSRuntimeSelection) -> String {
        selection.displayName
    }

    func refreshTunnelStatus() async {
        guard !userDisconnectInProgress else { return }
        let generation = iosConnectGeneration
        do {
            let managers = try await NETunnelProviderManager.loadAllFromPreferences().filter {
                ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == "com.eabusham.routervpn.PacketTunnel"
            }
            guard !userDisconnectInProgress else { return }
            guard iosConnectGeneration == generation else { return }
            guard managers.count <= 1 else { throw IOSRuntimeSelectionError.unsupportedMode("Multiple Router VPN sessions make status ownership ambiguous.") }
            guard let manager = managers.first else {
                connected = false; tunnelTransitioning = false; activeSessionIdentity = nil
                activeEngine = "none"; activeRawProfile = ""; iosStrategyStatus = nil; return
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
                if configuration["strategy_catalog"] != nil {
                    connected = false
                    guard let session = manager.connection as? NETunnelProviderSession else {
                        throw IOSStrategyWire.failure("The strategy tunnel has no owned provider session.")
                    }
                    let catalog = try IOSStrategyWire.catalog(configuration)
                    let digest = Self.iosStrategyDigest(data)
                    let reply = try await IOSStrategyTransport.send(session, request: ["operation": "strategy-status", "bundle_digest": digest])
                    guard iosConnectGeneration == generation, !userDisconnectInProgress,
                          session.status == .connected, session.connectedDate == connectedAt,
                          (manager.protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration?["bundle"] as? Data == data else { return }
                    let strategy = try IOSStrategyWire.status(reply, bundleDigest: digest, catalog: catalog)
                    try iosAdoptStrategyStatus(strategy, manager: manager, bundleData: data)
                    return
                }
                iosStrategyStatus = nil
                let engine = configuration["engine"] as? String ?? "wireguard"
                let raw = configuration["rawProfileID"] as? String ?? configuration["mode"] as? String ?? "wg"
                let identity = try IOSSessionIdentity(connectedAt: connectedAt, engine: engine, rawProfile: raw,
                    bundleData: data, configuration: configuration)
                activeEngine = engine; activeRawProfile = raw; activeSessionIdentity = identity
            }
        } catch {
            guard !userDisconnectInProgress else { return }
            guard iosConnectGeneration == generation else { return }
            // Failure to read preferences is UNKNOWN, not proof that the VPN is
            // down. Lock mutations and invalidate measurements until readback.
            activeSessionIdentity = nil
            connected = false
            tunnelTransitioning = true
            message = "Tunnel status is unverified: \(error.localizedDescription)"
        }
    }

    func disconnect() {
        guard iosSpeedLabOwnership.admit(.disconnect) else { return }
        multihopProgressGeneration = UUID(); multihopProgressText = ""
        guard !userDisconnectInProgress else { return }
        iosConnectGeneration = UUID(); iosStrategyTaskActive = false; iosStrategyStatus = nil
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
