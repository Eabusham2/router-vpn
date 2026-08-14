import Foundation
@preconcurrency import NetworkExtension

extension RouterVPNModel {
    var allNodeProfiles: [RouterProfile] {
        IOSNodeBundleStore.shared.profiles(current: bundle)
    }

    var selectedNodeProfile: RouterProfile? {
        guard let bundle else { return nil }
        return bundle.routerProfiles.first(where: { $0.id == bundle.selectedRouterID }) ?? bundle.routerProfiles.first
    }

    var selectedNodeIsExternal: Bool { selectedNodeProfile?.normalizedNodeKind == "external" }
    var selectedExternalProtocol: String { selectedNodeProfile?.external?.protocolName.lowercased() ?? "" }

    var selectedExternalSupportedOnIOS: Bool {
        selectedNodeIsExternal && ["wireguard", "socks5", "shadowsocks", "hysteria2"].contains(selectedExternalProtocol)
    }

    func nodeRuntimeSummary(_ profile: RouterProfile) -> String {
        if profile.normalizedNodeKind == "external" {
            let protocolName = profile.external?.protocolName.lowercased() ?? "unknown"
            if protocolName == "openvpn" { return "External OpenVPN — unavailable on iOS until a pinned native Apple OpenVPN dataplane exists" }
            if ["wireguard", "socks5", "shadowsocks", "hysteria2"].contains(protocolName) { return "External \(protocolName) — native Libbox PacketTunnel + exact public-exit proof" }
            return "External \(protocolName) — unsupported"
        }
        return "Router VPN node — WireGuardKit / Libbox modes + exact private node proof"
    }

    /// Selects a linked node together with the exact full bundle that owns its
    /// raw runtime profiles. This is what makes multiple Router VPN homes real
    /// on iOS instead of merely keeping several metadata rows beside one set of
    /// node-specific wg/sing-box files.
    func selectNode(_ id: String) {
        guard let data = IOSNodeBundleStore.shared.bundleData(containing: id, current: bundle),
              var value = try? JSONDecoder().decode(ClientBundle.self, from: data),
              let selected = value.routerProfiles.first(where: { $0.id == id })
        else { message = "Node not found in the linked iOS bundle store"; return }
        value.selectedRouterID = selected.id
        value.endpoint = selected.endpoint
        if selected.normalizedNodeKind == "router-vpn" {
            value.apiToken = selected.apiToken
            value.routerAPI = selected.routerAPI
            value.adGuardIPv4 = selected.adGuardIPv4
            value.adGuardIPv6 = selected.adGuardIPv6
            value.socks5Host = selected.socksHost
            value.socks5Port = selected.socksPort
            value.socks5Username = ""
            value.socks5Password = ""
        } else {
            value.apiToken = ""; value.routerAPI = ""; value.adGuardIPv4 = ""; value.adGuardIPv6 = ""
            value.socks5Host = ""; value.socks5Port = 1080; value.socks5Username = ""; value.socks5Password = ""
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
        let normalized = try IOSNodeBundleStore.shared.link(data, preserving: bundle)
        try importBundle(normalized)
        message = "Linked node bundle • \(allNodeProfiles.count) node(s) available without reinstalling Router VPN"
    }

    func connectSelectedExternal() async {
        guard let bundle, let profile = selectedNodeProfile, profile.normalizedNodeKind == "external" else {
            message = "Choose an external custom node first"; return
        }
        guard selectedExternalSupportedOnIOS else {
            connected = false
            message = selectedExternalProtocol == "openvpn"
                ? "OpenVPN external exits are unavailable on iOS until Router VPN ships a pinned native Apple OpenVPN dataplane."
                : "This external protocol is unavailable on iOS."
            return
        }
        guard let expected = profile.external?.expectedPublicIP, !expected.isEmpty else {
            connected = false; message = "External node is missing its expected public exit IP."; return
        }
        do {
            let managers = try await NETunnelProviderManager.loadAllFromPreferences()
            let manager = managers.first ?? NETunnelProviderManager()
            let proto = NETunnelProviderProtocol()
            proto.providerBundleIdentifier = "com.eabusham.routervpn.PacketTunnel"
            proto.serverAddress = profile.endpoint
            proto.providerConfiguration = [
                "engine": "external-libbox",
                "mode": "external-\(selectedExternalProtocol)",
                "modeCandidates": ["external-\(selectedExternalProtocol)"],
                "logicalMode": "external-node",
                "bundle": try JSONEncoder().encode(bundle)
            ]
            let strict = externalStrict(profile)
            proto.includeAllNetworks = strict
            proto.enforceRoutes = strict
            proto.excludeLocalNetworks = strict ? !(profile.homeLANAccess ?? false) : false
            proto.excludeAPNs = false
            proto.excludeCellularServices = false
            manager.protocolConfiguration = proto
            manager.localizedDescription = profile.name.isEmpty ? "Router VPN External" : profile.name
            manager.isEnabled = true
            if strict { manager.onDemandRules = [NEOnDemandRuleConnect()]; manager.isOnDemandEnabled = true }
            else { manager.onDemandRules = []; manager.isOnDemandEnabled = false }
            try await manager.saveToPreferences(); try await manager.loadFromPreferences()
            message = "Starting external \(selectedExternalProtocol) PacketTunnel • proving exit \(expected)…"
            try manager.connection.startVPNTunnel()
            let ok = await waitExternalConnection(manager, attempts: 48)
            guard ok else {
                manager.isOnDemandEnabled = false; manager.onDemandRules = []; try? await manager.saveToPreferences(); manager.connection.stopVPNTunnel()
                connected = false; activeEngine = "none"; activeRawProfile = ""
                message = "External \(selectedExternalProtocol) failed closed before exact public-exit proof passed."
                return
            }
            connected = true; activeEngine = "external-libbox"; activeRawProfile = "external-\(selectedExternalProtocol)"
            message = "Connected • external \(selectedExternalProtocol) • exact public-exit proof passed: \(expected)" + (strict ? " • strict route lockdown" : "")
        } catch {
            connected = false; activeEngine = "none"; activeRawProfile = ""; message = error.localizedDescription
        }
    }

    private func externalStrict(_ profile: RouterProfile) -> Bool {
        if profile.killSwitch == true { return true }
        let value = (profile.killSwitchPolicy ?? "").trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        return ["strict", "always", "enabled", "on", "lockdown"].contains(value)
    }

    private func waitExternalConnection(_ manager: NETunnelProviderManager, attempts: Int) async -> Bool {
        var sawConnecting = false
        for _ in 0..<attempts {
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
        return manager.connection.status == .connected
    }
}
