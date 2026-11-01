import Foundation
@preconcurrency import NetworkExtension

struct IOSNodeUsageOwner {
    let identity: IOSSessionIdentity
    let strict: Bool, enforced: Bool, lan: Bool, apns: Bool, cellular: Bool
    let enabled: Bool, onDemand: Bool
}

@MainActor extension RouterVPNModel {
    /// Freeze the actual native connection before the final asynchronous status
    /// refresh. An on-demand reconnect during that refresh is a different owner.
    func captureIOSNodeUsageIdentity(_ manager: NETunnelProviderManager) -> IOSSessionIdentity? {
        guard manager.connection.status == .connected, let date = manager.connection.connectedDate,
              let proto = manager.protocolConfiguration as? NETunnelProviderProtocol,
              proto.providerBundleIdentifier == "com.eabusham.routervpn.PacketTunnel",
              let configuration = proto.providerConfiguration,
              let data = configuration["bundle"] as? Data,
              let engine = configuration["engine"] as? String,
              let raw = configuration["rawProfileID"] as? String ?? configuration["mode"] as? String else { return nil }
        return try? IOSSessionIdentity(connectedAt: date, engine: engine, rawProfile: raw,
                                       bundleData: data, configuration: configuration)
    }

    func captureIOSNodeUsageOwner(_ manager: NETunnelProviderManager, strategy: IOSSessionIdentity? = nil) -> IOSNodeUsageOwner? {
        guard let identity = strategy ?? captureIOSNodeUsageIdentity(manager),
              manager.connection.status == .connected, manager.connection.connectedDate == identity.connectedAt,
              let proto = manager.protocolConfiguration as? NETunnelProviderProtocol,
              proto.providerBundleIdentifier == "com.eabusham.routervpn.PacketTunnel",
              proto.providerConfiguration?["bundle"] as? Data == identity.bundleData,
              proto.providerConfiguration?["engine"] as? String == identity.engine else { return nil }
        return IOSNodeUsageOwner(identity: identity, strict: proto.includeAllNetworks, enforced: proto.enforceRoutes,
                                 lan: proto.excludeLocalNetworks, apns: proto.excludeAPNs, cellular: proto.excludeCellularServices,
                                 enabled: manager.isEnabled, onDemand: manager.isOnDemandEnabled)
    }

    /// Called only by the final successful user Connect/strategy path. Status
    /// refresh, provider adoption, temporary candidates, restoration and startup
    /// have no authority to increment usage. The sidecar stores hashes only.
    func recordIOSNodeUsage(manager: NETunnelProviderManager, source: ClientBundle, generation: UUID,
                            expected owner: IOSNodeUsageOwner?, terminal: IOSStrategyStatus? = nil,
                            startup: Bool = false) {
        guard let owner else { return }
        let expected = owner.identity
        guard !startup, IOSSpeedLabContext.startupAdmission == nil,
              IOSSpeedLabContext.owner == nil, !IOSSpeedLabContext.restoringSelection,
              !iosSpeedLabOwnership.active, !Task.isCancelled,
              connected, !iosUserDisconnectInProgress, iosConnectGeneration == generation,
              activeSessionIdentity == expected,
              manager.connection.status == .connected, manager.connection.connectedDate == expected.connectedAt,
              let current = bundle,
              let proto = manager.protocolConfiguration as? NETunnelProviderProtocol,
              proto.providerBundleIdentifier == "com.eabusham.routervpn.PacketTunnel",
              proto.includeAllNetworks == owner.strict, proto.enforceRoutes == owner.enforced,
              proto.excludeLocalNetworks == owner.lan, proto.excludeAPNs == owner.apns,
              proto.excludeCellularServices == owner.cellular,
              manager.isEnabled == owner.enabled, manager.isOnDemandEnabled == owner.onDemand,
              let configuration = proto.providerConfiguration,
              configuration[IOSSpeedLabContext.ownerKey] == nil,
              configuration["engine"] as? String == expected.engine,
              configuration["bundle"] as? Data == expected.bundleData,
              let selected = IOSDNSRuntimePolicy.selectedProfile(in: source) else { return }
        do {
            // Credentials and generated transport source remain exact at final
            // adoption even though later client-key refresh retains the metric.
            guard try IOSNodeUsage.canonical(current) == IOSNodeUsage.canonical(source) else { return }
            let entry: Data?
            if expected.engine == "multihop-libbox" {
                entry = try IOSNodeUsage.canonical(iosMultihopEntryBundle(for: current))
            } else if expected.engine == "external-libbox" {
                entry = try externalTorEntryData(source: current)
            } else { entry = nil }
            guard entry == expected.entryBundleData else { return }

            if let terminal {
                guard expected.engine == "libbox", selected.normalizedNodeKind == "router-vpn",
                      terminal.phase == .connected, terminal.outcome == .success,
                      terminal.isProven, !terminal.isRunning, iosStrategyStatus == terminal,
                      expected.providerSession == terminal.providerSession,
                      expected.runtimeEpoch == terminal.runtimeEpoch,
                      expected.rawProfile == terminal.provenRaw,
                      terminal.bundleDigest == IOSNodeUsage.digest(expected.bundleData),
                      configuration["strategy_source_digest"] as? String == IOSNodeUsage.digest(try IOSNodeUsage.canonical(source)) else { return }
            } else {
                guard configuration["strategy_catalog"] == nil,
                      captureIOSNodeUsageIdentity(manager) == expected else { return }
                if expected.engine == "multihop-libbox" {
                    guard selected.normalizedNodeKind == "router-vpn",
                          try IOSNodeUsage.canonicalJSON(expected.bundleData) == IOSNodeUsage.canonicalJSON(IOSNodeUsage.canonical(source)) else { return }
                } else if expected.engine == "external-libbox" {
                    let projected = try externalRuntimeBundleData(source: source, profile: selected)
                    guard selected.normalizedNodeKind == "external",
                          try IOSNodeUsage.canonicalJSON(expected.bundleData) == IOSNodeUsage.canonicalJSON(projected) else { return }
                } else { return }
            }

            var nodes = [selected]
            if let entry {
                let captured = try JSONDecoder().decode(ClientBundle.self, from: entry)
                guard let entryNode = IOSDNSRuntimePolicy.selectedProfile(in: captured),
                      selected.multihopEnabled == true, selected.multihopEntryID == entryNode.id else { return }
                nodes.append(entryNode)
            } else if selected.multihopEnabled == true { return }
            let adoption: [String: String] = [
                "generation": generation.uuidString, "date": String(expected.connectedAt.timeIntervalSince1970),
                "engine": expected.engine, "raw": expected.rawProfile,
                "source": IOSNodeUsage.digest(expected.bundleData),
                "entry": expected.entryBundleData.map(IOSNodeUsage.digest) ?? "",
                "provider": expected.providerSession ?? "", "epoch": expected.runtimeEpoch ?? "",
                "request": terminal?.requestID ?? ""
            ]
            try IOSNodeUsage.record(profiles: nodes, adoption: IOSNodeUsage.digest(try IOSNodeUsage.canonical(adoption)))
        } catch {
            // Optional history can fail without tearing down an already proved
            // VPN. Node Manager also retains a truthful storage warning.
            IOSNodeUsage.reportFailure()
            message += " • usage history could not be saved"
        }
    }
}
