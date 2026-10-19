import Foundation
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
        selectedNodeIsExternal && ["wireguard", "socks5", "http-connect", "https-connect", "shadowsocks", "hysteria2", "openvpn"].contains(selectedExternalProtocol)
    }

    func nodeRuntimeSummary(_ profile: RouterProfile) -> String {
        if profile.normalizedNodeKind == "external" {
            let protocolName = profile.external?.protocolName.lowercased() ?? "unknown"
            if protocolName == "openvpn" { return "External OpenVPN — native pinned client with exact public-exit proof" }
            if protocolName == "tor-bridge" { return "Tor bridges — obfs4 / meek / Snowflake / WebTunnel / Custom — unavailable on iOS until Router VPN ships a real native Tor + pluggable-transport PacketTunnel dataplane with dynamic Tor-exit proof" }
            if ["wireguard", "socks5", "http-connect", "https-connect", "shadowsocks", "hysteria2", "openvpn"].contains(protocolName) { return "External \(protocolName) — native Libbox PacketTunnel + exact public-exit proof" }
            return "External \(protocolName) — unsupported"
        }
        return "Router VPN node — WireGuardKit / Libbox modes + exact private node proof"
    }

    /// Selects a linked node together with the exact full bundle that owns its
    /// raw runtime profiles. This is what makes multiple Router VPN homes real
    /// on iOS instead of merely keeping several metadata rows beside one set of
    /// node-specific wg/sing-box files.
    func selectNode(_ id: String) {
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
        guard !profileMutationBlocked else {
            throw NSError(domain: "RouterVPN.NodeMutation", code: 1, userInfo: [NSLocalizedDescriptionKey: "Disconnect or let the active VPN transition finish before linking node data."])
        }
        let normalized = try IOSNodeBundleStore.shared.link(data, preserving: bundle)
        try importBundle(normalized)
        message = "Linked node bundle • \(allNodeProfiles.count) node(s) available without reinstalling Router VPN"
    }

    func connectSelectedExternal() async {
        guard !profileMutationBlocked else { message = "Disconnect or let the active VPN transition finish before starting another external connection."; return }
        guard let bundle, let profile = selectedNodeProfile, profile.normalizedNodeKind == "external" else {
            message = "Choose an external custom node first"; return
        }
        guard selectedExternalSupportedOnIOS else {
            connected = false
            if selectedExternalProtocol == "openvpn" {
                message = "OpenVPN native capability is unavailable in this build."
            } else if selectedExternalProtocol == "tor-bridge" {
                message = "Tor bridges (obfs4 / meek / Snowflake / WebTunnel / Custom) are unavailable on iOS until Router VPN ships a real native Tor + pluggable-transport PacketTunnel dataplane. A fixed expected-exit IP cannot substitute for Tor's dynamic circuit-exit proof."
            } else {
                message = "This external protocol is unavailable on iOS."
            }
            return
        }
        guard let expected = profile.external?.expectedPublicIP, !expected.isEmpty else {
            connected = false; message = "External node is missing its expected public exit IP."; return
        }
        let encodedBundle: Data
        do {
            encodedBundle = try externalRuntimeBundleData(source: bundle, profile: profile)
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
            try requireExternalPreparation(generation, source: bundle, manager: manager)
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
            let strict = externalStrict(profile)
            proto.includeAllNetworks = strict
            proto.enforceRoutes = strict
            proto.excludeLocalNetworks = strict && (profile.homeLANAccess ?? true)
            proto.excludeAPNs = false
            proto.excludeCellularServices = false
            manager.protocolConfiguration = proto
            manager.localizedDescription = profile.name.isEmpty ? "Router VPN External" : profile.name
            manager.isEnabled = true
            if strict { manager.onDemandRules = [NEOnDemandRuleConnect()]; manager.isOnDemandEnabled = true }
            else { manager.onDemandRules = []; manager.isOnDemandEnabled = false }
            try await manager.saveToPreferences()
            try requireExternalPreparation(generation, source: bundle, manager: manager)
            try await manager.loadFromPreferences()
            try requireExternalPreparation(generation, source: bundle, manager: manager)
            guard let saved = manager.protocolConfiguration as? NETunnelProviderProtocol,
                  saved.providerConfiguration?["bundle"] as? Data == encodedBundle,
                  saved.providerConfiguration?["engine"] as? String == "external-libbox",
                  manager.isEnabled, manager.isOnDemandEnabled == strict else {
                throw IOSRuntimeSelectionError.unsupportedMode("External runtime preferences did not preserve the captured owner.")
            }
            message = "Starting external \(protocolName) PacketTunnel • proving exit \(expected)…"
            try manager.connection.startVPNTunnel()
            let ok = await waitExternalConnection(manager, attempts: 48, generation: generation)
            guard iosConnectGeneration == generation, !iosUserDisconnectInProgress, !Task.isCancelled else { return }
            guard ok else {
                await refreshTunnelStatus()
                guard iosConnectGeneration == generation, !iosUserDisconnectInProgress else { return }
                message = "External \(protocolName) has not completed exact public-exit proof. Check its protected status or Disconnect."
                return
            }
            await refreshTunnelStatus()
            guard iosConnectGeneration == generation, !iosUserDisconnectInProgress else { return }
            if connected {
                message = "Connected • external \(protocolName) • exact public-exit proof passed: \(expected)" + (strict ? " • strict route lockdown" : "")
            }
        } catch {
            guard iosConnectGeneration == generation, !iosUserDisconnectInProgress else { return }
            let failure = error.localizedDescription
            await refreshTunnelStatus()
            guard iosConnectGeneration == generation, !iosUserDisconnectInProgress else { return }
            message = "External startup was not completed: \(failure)"
        }
    }

    private func requireExternalPreparation(_ generation: UUID, source: ClientBundle, manager: NETunnelProviderManager) throws {
        try Task.checkCancellation()
        guard iosConnectGeneration == generation, !iosUserDisconnectInProgress,
              let current = bundle, current.selectedRouterID == source.selectedRouterID,
              current.routerProfiles == source.routerProfiles, current.profiles == source.profiles,
              manager.protocolConfiguration == nil || (manager.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == "com.eabusham.routervpn.PacketTunnel" else {
            throw CancellationError()
        }
        guard manager.connection.status == .disconnected || manager.connection.status == .invalid else {
            throw IOSRuntimeSelectionError.unsupportedMode("The external VPN owner changed during startup; disconnect before replacing it.")
        }
    }

    private func externalRuntimeBundleData(source: ClientBundle, profile: RouterProfile) throws -> Data {
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
