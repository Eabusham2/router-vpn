import Foundation
@preconcurrency import NetworkExtension

extension RouterVPNModel {
    var allNodeProfiles: [RouterProfile] { bundle?.routerProfiles ?? [] }

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

    func selectNode(_ id: String) {
        guard var value = bundle,
              let selected = value.routerProfiles.first(where: { $0.id == id })
        else { message = "Node not found"; return }
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
            let data = try JSONEncoder().encode(value)
            try importBundle(data)
            message = "Selected \(selected.name) • \(nodeRuntimeSummary(selected))"
        } catch { message = "Could not select node: \(error.localizedDescription)" }
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
