import Foundation
import Libbox
@preconcurrency import NetworkExtension

extension RouterVPNModel {
    var allNodeProfiles: [RouterProfile] {
        IOSNodeBundleStore.shared.profiles(current: bundle)
    }

    var selectedNodeProfile: RouterProfile? {
        guard let bundle else { return nil }
        return IOSDNSRuntimePolicy.selectedProfile(in: bundle)
    }

    var selectedNodeIsExternal: Bool { selectedNodeProfile?.normalizedNodeKind == "external" }
    var selectedExternalProtocol: String { selectedNodeProfile?.external?.protocolName.lowercased() ?? "" }

    var selectedExternalSupportedOnIOS: Bool {
        selectedNodeIsExternal && ["wireguard", "amneziawg", "socks5", "http-connect", "https-connect", "shadowsocks", "hysteria2", "openvpn", "tor", "tor-bridge"].contains(selectedExternalProtocol)
    }

    func nodeRuntimeSummary(_ profile: RouterProfile) -> String {
        if profile.normalizedNodeKind == "external" {
            let protocolName = profile.external?.protocolName.lowercased() ?? "unknown"
            if protocolName == "openvpn" { return "External OpenVPN — selected native DNS and exact public-exit proof" }
            if protocolName == "tor" { return "Tor • current circuit exit verified before connection completes" }
            if protocolName == "tor-bridge" { return "Tor bridges • obfs4 / meek / Snowflake / WebTunnel • current circuit exit verification" }
            if ["wireguard", "amneziawg", "socks5", "http-connect", "https-connect", "shadowsocks", "hysteria2", "openvpn"].contains(protocolName) { return "External \(protocolName) — selected DNS and exact exit proved by the native tunnel" }
            return "External \(protocolName) — unsupported"
        }
        return "Router VPN node — WireGuardKit / Libbox modes + exact private node proof"
    }

    /// Selects a linked node together with the exact full bundle that owns its
    /// raw runtime profiles. This is what makes multiple Router VPN homes real
    /// on iOS instead of merely keeping several metadata rows beside one set of
    /// node-specific wg/sing-box files.
    func selectNode(_ id: String) {
        guard iosSpeedLabOwnership.admit(.profile) else { return }
        guard !profileMutationBlocked else { message = "Disconnect or let the active VPN transition finish before selecting another node."; return }
        guard let data = IOSNodeBundleStore.shared.bundleData(containing: id, current: bundle),
              var value = try? JSONDecoder().decode(ClientBundle.self, from: data),
              let selected = value.routerProfiles.first(where: { $0.id == id })
        else { message = "Node not found in the linked iOS bundle store"; return }
        value.selectedRouterID = selected.id
        value.endpoint = selected.endpoint
        if selected.normalizedNodeKind == "router-vpn" {
            value.nodeProofID = selected.nodeProofID ?? value.nodeProofID
            value.apiToken = selected.apiToken
            value.routerAPI = selected.routerAPI
            value.adGuardIPv4 = selected.adGuardIPv4
            value.adGuardIPv6 = selected.adGuardIPv6
            value.socks5Host = selected.socksHost
            value.socks5Port = selected.socksPort
            value.socks5Username = ""
            value.socks5Password = ""
        } else {
            value.nodeProofID = ""
            value.apiToken = ""; value.routerAPI = ""; value.adGuardIPv4 = ""; value.adGuardIPv6 = ""
            value.socks5Host = ""; value.socks5Port = 0; value.socks5Username = ""; value.socks5Password = ""
        }
        do {
            let selectedData = try JSONEncoder().encode(value)
            try importBundle(selectedData)
            message = "Selected \(selected.name) • \(nodeRuntimeSummary(selected))"
        } catch { message = "Could not select node: \(error.localizedDescription)" }
    }

    /// Add/link a complete node bundle while preserving the current bundle in
    /// the per-node store first. Router VPN bundles get a deterministic id from
    /// their 64-hex selected-node proof so every home keeps its own raw profile
    /// assets. External-only bundles retain their validated profile ids.
    func linkNodeBundle(_ data: Data) throws {
        guard iosSpeedLabOwnership.admit(.profile) else { throw CancellationError() }
        guard !profileMutationBlocked else {
            throw NSError(domain: "RouterVPN.NodeMutation", code: 1, userInfo: [NSLocalizedDescriptionKey: "Disconnect or let the active VPN transition finish before linking node data."])
        }
        try commitLinkedNodeBundle(data)
        message = "Linked node bundle • \(allNodeProfiles.count) node(s) available without reinstalling Router VPN"
    }

    func connectSelectedExternal() async {
        guard await iosSpeedLabOwnership.admitConnection() else { return }
        await connectSelectedExternal(startupAdmission: nil)
    }

    func connectSelectedExternal(startupAdmission: (() -> Bool)?, restoreLast: Bool = false) async {
        // Startup has no right to supersede a temporary test. Its captured
        // admission proves idle ownership synchronously before preparation.
        // Explicit Connect has already joined the normal owner above.
        if let startupAdmission { guard startupAdmission() else { return } }
        guard !profileMutationBlocked else { message = "Disconnect or let the active VPN transition finish before starting another external connection."; return }
        guard let bundle, let profile = selectedNodeProfile, profile.normalizedNodeKind == "external" else {
            message = "Choose an external custom node first"; return
        }
        guard selectedExternalSupportedOnIOS else {
            connected = false
            if selectedExternalProtocol == "openvpn" {
                message = "OpenVPN native capability is unavailable in this build."
            } else {
                message = "This external protocol is unavailable on iOS."
            }
            return
        }
        let tor = selectedExternalProtocol == "tor" || selectedExternalProtocol == "tor-bridge"
        let ordinary = ["wireguard", "amneziawg", "socks5", "http-connect", "https-connect", "shadowsocks", "hysteria2", "openvpn"].contains(selectedExternalProtocol)
        let entryBundleKey = tor ? "tor_entry_bundle" : "external_entry_bundle"
        let entryModeKey = tor ? "tor_entry_mode" : "external_entry_mode"
        let expected = profile.external?.expectedPublicIP ?? ""
        guard tor ? expected.isEmpty : !expected.isEmpty else {
            connected = false; message = "External node is missing its expected public exit IP."; return
        }
        let encodedBundle: Data
        let capturedEntry: Data?
        let capturedEntryProfile: RouterProfile?
        do {
            encodedBundle = try externalRuntimeBundleData(source: bundle, profile: profile)
            capturedEntry = try externalTorEntryData(source: bundle)
            capturedEntryProfile = try capturedEntry.map { data in
                let entry = try JSONDecoder().decode(ClientBundle.self, from: data)
                guard let selected = IOSDNSRuntimePolicy.selectedProfile(in: entry) else { throw CancellationError() }
                return selected
            }
        } catch {
            connected = false; message = "Could not prepare the selected external runtime bundle: \(error.localizedDescription)"; return
        }
        let generation = UUID(); iosConnectGeneration = generation
        let protocolName = profile.external?.protocolName.lowercased() ?? ""
        tunnelTransitioning = true
        do {
            let managers = try await NETunnelProviderManager.loadAllFromPreferences().filter {
                ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == "com.eabusham.routervpn.PacketTunnel"
            }
            guard iosConnectGeneration == generation, !iosUserDisconnectInProgress, !Task.isCancelled else { return }
            guard managers.count <= 1 else {
                throw IOSRuntimeSelectionError.unsupportedMode("Multiple Router VPN tunnel configurations make external connection ownership ambiguous.")
            }
            let manager = managers.first ?? NETunnelProviderManager()
            try requireExternalPreparation(generation, source: bundle, entry: capturedEntry, manager: manager)
            let proto = NETunnelProviderProtocol()
            proto.providerBundleIdentifier = "com.eabusham.routervpn.PacketTunnel"
            proto.serverAddress = profile.endpoint
            proto.providerConfiguration = [
                "engine": "external-libbox",
                "mode": "external-\(protocolName)",
                "modeCandidates": ["external-\(protocolName)"],
                "logicalMode": "external-node",
                "bundle": encodedBundle
            ]
            if let capturedEntry {
                proto.providerConfiguration?[entryBundleKey] = capturedEntry
                proto.providerConfiguration?[entryModeKey] = profile.multihopEntryMode ?? "wg"
            }
            let maxSources = try IOSMAXSourceSelection.sourceHashes(provider: proto.providerConfiguration ?? [:]) { mode, assets, metadata in
                var failure: NSError?
                let digest: String? = LibboxRouterCheckMAXProfile(mode, assets, metadata, &failure)
                if let failure { throw failure }
                guard let digest else { throw IOSMAXSourceSelection.issue() }
                return digest
            }
            if !maxSources.isEmpty { proto.providerConfiguration?["max_source_sha256"] = maxSources }
            var ownedConfiguration = proto.providerConfiguration ?? [:]
            IOSSpeedLabContext.mark(&ownedConfiguration)
            proto.providerConfiguration = ownedConfiguration
            let strict = externalStrict(profile) || capturedEntryProfile.map(externalStrict) == true
            proto.includeAllNetworks = strict
            proto.enforceRoutes = strict
            proto.excludeLocalNetworks = strict && (profile.homeLANAccess ?? true) && (capturedEntryProfile?.homeLANAccess ?? true)
            proto.excludeAPNs = false
            proto.excludeCellularServices = false
            manager.protocolConfiguration = proto
            manager.localizedDescription = profile.name.isEmpty ? "Router VPN External" : profile.name
            manager.isEnabled = true
            if strict { manager.onDemandRules = [NEOnDemandRuleConnect()]; manager.isOnDemandEnabled = true }
            else { manager.onDemandRules = []; manager.isOnDemandEnabled = false }
            try await manager.saveToPreferences()
            try requireExternalPreparation(generation, source: bundle, entry: capturedEntry, manager: manager)
            try await manager.loadFromPreferences()
            try requireExternalPreparation(generation, source: bundle, entry: capturedEntry, manager: manager)
            if startupAdmission != nil {
                let available = try await NETunnelProviderManager.loadAllFromPreferences()
                try requireExternalPreparation(generation, source: bundle, entry: capturedEntry, manager: manager)
                guard available.allSatisfy({
                    $0.connection.status == .disconnected || $0.connection.status == .invalid
                }) else {
                    throw IOSStartupPolicy.issue("A VPN became active during startup permission. No new connection was started.")
                }
            }
            guard let saved = manager.protocolConfiguration as? NETunnelProviderProtocol,
                  saved.providerConfiguration?["bundle"] as? Data == encodedBundle,
                  saved.providerConfiguration?["engine"] as? String == "external-libbox",
                  saved.providerConfiguration?[entryBundleKey] as? Data == capturedEntry,
                  saved.providerConfiguration?[entryModeKey] as? String == (capturedEntry == nil ? nil : (profile.multihopEntryMode ?? "wg")),
                  saved.providerConfiguration?[tor ? "external_entry_bundle" : "tor_entry_bundle"] == nil,
                  saved.providerConfiguration?[tor ? "external_entry_mode" : "tor_entry_mode"] == nil,
                  saved.providerConfiguration?["max_source_sha256"] as? [String: String] == (maxSources.isEmpty ? nil : maxSources),
                  saved.includeAllNetworks == strict, saved.enforceRoutes == strict,
                  saved.excludeLocalNetworks == proto.excludeLocalNetworks,
                  manager.isEnabled, manager.isOnDemandEnabled == strict else {
                throw IOSRuntimeSelectionError.unsupportedMode("External runtime preferences did not preserve the captured owner.")
            }
            message = tor ? "Connecting to Tor • building the circuit and verifying its current exit…" : "Starting external \(protocolName) PacketTunnel • proving \(ordinary ? "selected DNS and " : "")exit \(expected)…"
            let hold = IOSMTUMeasurementGate.current
            var launchOptions: [String: NSObject] = hold.isEmpty ? [:] : ["routervpn_mtu_hold": hold as NSString]
            if restoreLast, let configuration = saved.providerConfiguration,
               (try? IOSMultihopExecution.requiresCapture(configuration: configuration)) == true,
               let previous = try? IOSStartupLastChoice.restored(configuration: configuration, digest: Self.iosStrategyDigest),
               let encoded = try? previous.encoded() {
                launchOptions[IOSMultihopExecution.startupLaunchKey] = String(decoding: encoded, as: UTF8.self) as NSString
            }
            let options: [String: NSObject]? = launchOptions.isEmpty ? nil : launchOptions
            try manager.connection.startVPNTunnel(options: options)
            let selectingExecution = ordinary && profile.multihopEnabled == true && ["server", "auto"].contains(profile.multihopExecution ?? "local")
            let ok = await waitExternalConnection(manager, attempts: tor ? 720 : (selectingExecution ? 480 : 48), generation: generation)
            guard iosConnectGeneration == generation, !iosUserDisconnectInProgress, !Task.isCancelled else { return }
            guard ok else {
                await refreshTunnelStatus()
                guard iosConnectGeneration == generation, !iosUserDisconnectInProgress else { return }
                message = tor ? "Tor has not finished verifying its current circuit exit. You can disconnect while it is connecting." : "External \(protocolName) has not completed \(ordinary ? "selected DNS and node" : "public-exit") proof. Check its protected status or Disconnect."
                return
            }
            await refreshTunnelStatus()
            guard iosConnectGeneration == generation, !iosUserDisconnectInProgress else { return }
            if connected {
                message = (tor ? "Connected • Tor • current circuit exit verified" : "Connected • external \(protocolName) • \(ordinary ? "selected DNS and " : "")exact exit verified: \(expected)") + (capturedEntry == nil ? "" : " • captured entry verified") + (strict ? " • strict route lockdown" : "")
                if selectingExecution, IOSSpeedLabContext.owner == nil, !iosSpeedLabOwnership.active {
                    do { try await rememberIOSExternalExecution(manager: manager, source: bundle, entry: capturedEntry, generation: generation) }
                    catch {
                        guard iosConnectGeneration == generation, connected, !iosUserDisconnectInProgress else { return }
                        message += " • previous execution could not be saved for Last"
                    }
                }
            }
        } catch {
            guard iosConnectGeneration == generation, !iosUserDisconnectInProgress else { return }
            let failure = error.localizedDescription
            await refreshTunnelStatus()
            guard iosConnectGeneration == generation, !iosUserDisconnectInProgress else { return }
            message = "External startup was not completed: \(failure)"
        }
    }

    private func rememberIOSExternalExecution(manager: NETunnelProviderManager, source: ClientBundle,
                                              entry: Data?, generation: UUID) async throws {
        guard let connection = manager.connection as? NETunnelProviderSession,
              let connectedDate = connection.connectedDate,
              let proto = manager.protocolConfiguration as? NETunnelProviderProtocol,
              let configuration = proto.providerConfiguration else { throw CancellationError() }
        let captured = try IOSStartupCapture(bundle: source, entry: entry, generation: generation)
        let executionSource = try IOSMultihopExecution.Source(configuration: configuration, digest: Self.iosStrategyDigest)
        let strict = proto.includeAllNetworks, enforced = proto.enforceRoutes, lan = proto.excludeLocalNetworks
        func requireCurrent() throws {
            try Task.checkCancellation()
            guard connected, iosConnectGeneration == generation, !iosUserDisconnectInProgress,
                  IOSSpeedLabContext.owner == nil, !iosSpeedLabOwnership.active,
                  connection.status == .connected, connection.connectedDate == connectedDate,
                  let current = bundle, let saved = manager.protocolConfiguration as? NETunnelProviderProtocol,
                  saved.providerBundleIdentifier == "com.eabusham.routervpn.PacketTunnel",
                  saved.includeAllNetworks == strict, saved.enforceRoutes == enforced, saved.excludeLocalNetworks == lan,
                  let now = saved.providerConfiguration,
                  try IOSMultihopExecution.Source(configuration: now, digest: Self.iosStrategyDigest) == executionSource,
                  try IOSStartupCapture(bundle: current, entry: externalTorEntryData(source: current), generation: iosConnectGeneration) == captured else {
                throw CancellationError()
            }
        }
        try requireCurrent()
        let request = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
        let data = try await IOSMTUControl.send(connection, operation: "speed-lab-execution", request: request, session: "")
        try requireCurrent()
        let receipt = try IOSMultihopExecution.Capture.decode(data, source: executionSource, request: request)
        try IOSStartupLastChoice.record(configuration: configuration, receipt: receipt, digest: Self.iosStrategyDigest)
    }

    private func requireExternalPreparation(_ generation: UUID, source: ClientBundle, entry: Data?, manager: NETunnelProviderManager) throws {
        try Task.checkCancellation()
        guard iosConnectGeneration == generation, !iosUserDisconnectInProgress,
              let current = bundle, current.selectedRouterID == source.selectedRouterID,
              current.routerProfiles == source.routerProfiles, current.profiles == source.profiles,
              manager.protocolConfiguration == nil || (manager.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == "com.eabusham.routervpn.PacketTunnel" else {
            throw CancellationError()
        }
        guard try externalTorEntryData(source: source) == entry else { throw CancellationError() }
        guard manager.connection.status == .disconnected || manager.connection.status == .invalid else {
            throw IOSRuntimeSelectionError.unsupportedMode("The external VPN owner changed during startup; disconnect before replacing it.")
        }
    }

    func externalTorEntryData(source: ClientBundle) throws -> Data? {
        guard let selected = IOSDNSRuntimePolicy.selectedProfile(in: source) else { throw CancellationError() }
        guard selected.multihopEnabled == true else { return nil }
        guard selected.normalizedNodeKind == "external", ["tor", "tor-bridge", "wireguard", "amneziawg", "socks5", "http-connect", "https-connect", "shadowsocks", "hysteria2", "openvpn"].contains(selected.external?.protocolName ?? "") else {
            throw IOSRuntimeSelectionError.unsupportedMode("This external node has no saved native entry composition.")
        }
        let entry = try iosMultihopEntryBundle(for: source)
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
        let data = try encoder.encode(entry)
        guard data.count <= 32 * 1024 * 1024 else { throw IOSRuntimeSelectionError.unsupportedMode("The captured external entry bundle exceeds its 32 MiB limit.") }
        return data
    }

    func externalRuntimeBundleData(source: ClientBundle, profile: RouterProfile) throws -> Data {
        var runtimeProfile = profile
        guard runtimeProfile.normalizedNodeKind == "external" else {
            throw NSError(domain: "RouterVPN.ExternalNode", code: 40, userInfo: [NSLocalizedDescriptionKey: "External runtime handoff requires an external profile"])
        }
        runtimeProfile.nodeProofID = nil
        runtimeProfile.routerAPI = ""
        runtimeProfile.apiToken = ""
        runtimeProfile.adGuardIPv4 = ""
        runtimeProfile.adGuardIPv6 = ""
        runtimeProfile.socksHost = ""
        runtimeProfile.socksPort = 0
        runtimeProfile.socksUsername = ""
        runtimeProfile.socksPassword = ""
        runtimeProfile.daitaHost = nil
        runtimeProfile.daitaPort = nil
        runtimeProfile.daitaRateKbps = nil
        runtimeProfile.baseTunnel = nil
        runtimeProfile.baseFallback = nil
        runtimeProfile.pathProbeURL = nil

        var runtime = source
        runtime.nodeProofID = ""
        runtime.endpoint = runtimeProfile.endpoint
        runtime.apiToken = ""
        runtime.routerAPI = ""
        runtime.adGuardIPv4 = ""
        runtime.adGuardIPv6 = ""
        runtime.socks5Host = ""
        runtime.socks5Port = 0
        runtime.socks5Username = ""
        runtime.socks5Password = ""
        runtime.routerProfiles = [runtimeProfile]
        runtime.selectedRouterID = runtimeProfile.id
        runtime.logicalModes = []
        runtime.modes = []
        runtime.profiles = [:]
        let data = try JSONEncoder().encode(runtime)
        guard data.count <= 4 * 1024 * 1024 else {
            throw NSError(domain: "RouterVPN.ExternalNode", code: 41, userInfo: [NSLocalizedDescriptionKey: "Selected external runtime profile exceeds the 4 MiB PacketTunnel handoff limit"])
        }
        return data
    }

    private func externalStrict(_ profile: RouterProfile) -> Bool {
        if profile.killSwitch == true { return true }
        let value = (profile.killSwitchPolicy ?? "").trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        return ["strict", "always", "enabled", "on", "lockdown"].contains(value)
    }

    private func waitExternalConnection(_ manager: NETunnelProviderManager, attempts: Int, generation: UUID) async -> Bool {
        var sawConnecting = false
        for _ in 0..<attempts {
            guard iosConnectGeneration == generation, !iosUserDisconnectInProgress, !Task.isCancelled else { return false }
            switch manager.connection.status {
            case .connected: return true
            case .invalid, .disconnecting: return false
            case .disconnected:
                if sawConnecting { return false }
                try? await Task.sleep(for: .milliseconds(250))
            case .connecting, .reasserting:
                sawConnecting = true
                try? await Task.sleep(for: .milliseconds(250))
            @unknown default: try? await Task.sleep(for: .milliseconds(250))
            }
        }
        return iosConnectGeneration == generation && !iosUserDisconnectInProgress && !Task.isCancelled && manager.connection.status == .connected
    }
}
