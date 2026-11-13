import Foundation
@preconcurrency import NetworkExtension

/// A prepared prefix connection has its own immutable identity. It never
/// becomes IOSSessionIdentity or grants ordinary Connected/usage authority.
@MainActor struct IOSNodeCandidatePrefixBinding {
    let manager: NETunnelProviderManager
    let connection: NETunnelProviderSession
    let configuration: [String: Any]
    let connectedAt: Date
    let generation: UUID
    let owner: UUID
    let strict: Bool, homeLANAccess: Bool

    func require(_ model: RouterVPNModel) throws {
        try model.iosSpeedLabOwnership.require(owner)
        guard model.iosConnectGeneration == generation, !model.iosUserDisconnectInProgress,
              !model.connected, !model.tunnelTransitioning, model.activeSessionIdentity == nil,
              connection.status == .connected, connection.connectedDate == connectedAt,
              manager.connection === connection,
              let proto = manager.protocolConfiguration as? NETunnelProviderProtocol,
              proto.providerBundleIdentifier == "com.eabusham.routervpn.PacketTunnel",
              let now = proto.providerConfiguration, NSDictionary(dictionary: now).isEqual(to: configuration),
              proto.includeAllNetworks == strict, proto.enforceRoutes == strict,
              proto.excludeLocalNetworks == (strict && homeLANAccess),
              !proto.excludeAPNs, !proto.excludeCellularServices, manager.isEnabled,
              !manager.isOnDemandEnabled, (manager.onDemandRules ?? []).isEmpty else { throw CancellationError() }
    }
}

@MainActor extension RouterVPNModel {
    func connectCandidatePrefix(_ capture: IOSNodeCandidatePrefixCapture, bundle: ClientBundle,
                                owner: UUID, epoch: UUID, request: String,
                                current: @escaping @MainActor @Sendable () throws -> Void) async throws -> IOSNodeCandidatePrefixBinding {
        try current(); try iosSpeedLabOwnership.require(owner)
        guard IOSSpeedLabContext.owner == owner, !connected, !tunnelTransitioning,
              activeSessionIdentity == nil, !iosUserDisconnectInProgress,
              !IOSMTUMeasurementGate.current.isEmpty else { throw CancellationError() }
        let config = try IOSNodeCandidatePrefixProviderCapture.configuration(capture: capture,
            bundle: JSONEncoder().encode(bundle), owner: owner, epoch: epoch, request: request)
        let generation = UUID(); iosConnectGeneration = generation; tunnelTransitioning = true
        defer { if iosConnectGeneration == generation { tunnelTransitioning = false } }
        func require() throws {
            try current(); try iosSpeedLabOwnership.require(owner)
            guard iosConnectGeneration == generation, !iosUserDisconnectInProgress, !Task.isCancelled,
                  activeSessionIdentity == nil, !connected else { throw CancellationError() }
        }
        let managers = try await NETunnelProviderManager.loadAllFromPreferences().filter {
            ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == "com.eabusham.routervpn.PacketTunnel"
        }
        try require()
        guard managers.count <= 1 else { throw CancellationError() }
        let manager = managers.first ?? NETunnelProviderManager()
        guard manager.connection.status == .disconnected || manager.connection.status == .invalid,
              !manager.isOnDemandEnabled else { throw CancellationError() }
        let proto = NETunnelProviderProtocol()
        proto.providerBundleIdentifier = "com.eabusham.routervpn.PacketTunnel"
        proto.serverAddress = bundle.endpoint; proto.providerConfiguration = config
        proto.includeAllNetworks = capture.strict; proto.enforceRoutes = capture.strict
        proto.excludeLocalNetworks = capture.strict && capture.homeLANAccess
        proto.excludeAPNs = false; proto.excludeCellularServices = false
        manager.protocolConfiguration = proto; manager.localizedDescription = routerName
        manager.isEnabled = true; manager.isOnDemandEnabled = false; manager.onDemandRules = []
        try require()
        try await manager.saveToPreferences()
        try require()
        try await manager.loadFromPreferences()
        try require()
        func requireProtocol() throws {
            guard let actual = manager.protocolConfiguration as? NETunnelProviderProtocol,
                  actual.providerBundleIdentifier == proto.providerBundleIdentifier,
                  let source = actual.providerConfiguration, NSDictionary(dictionary: source).isEqual(to: config),
                  actual.includeAllNetworks == capture.strict, actual.enforceRoutes == capture.strict,
                  actual.excludeLocalNetworks == (capture.strict && capture.homeLANAccess),
                  !actual.excludeAPNs, !actual.excludeCellularServices, manager.isEnabled,
                  !manager.isOnDemandEnabled, (manager.onDemandRules ?? []).isEmpty else { throw CancellationError() }
        }
        try requireProtocol()
        guard manager.connection.status == .disconnected || manager.connection.status == .invalid,
              let connection = manager.connection as? NETunnelProviderSession else { throw CancellationError() }
        let hold = IOSMTUMeasurementGate.current
        guard !hold.isEmpty else { throw CancellationError() }
        try require()
        try connection.startVPNTunnel(options: ["routervpn_mtu_hold": hold as NSString])
        activeEngine = IOSNodeCandidatePrefixProviderCapture.engine; activeRawProfile = ""
        let deadline = ProcessInfo.processInfo.systemUptime + TimeInterval(25 + 10 * capture.metadata.prefixes.count)
        var entered = false
        while ProcessInfo.processInfo.systemUptime < deadline {
            try require(); try requireProtocol()
            switch connection.status {
            case .connected:
                guard let date = connection.connectedDate else { throw CancellationError() }
                tunnelTransitioning = false
                let binding = IOSNodeCandidatePrefixBinding(manager: manager, connection: connection, configuration: config,
                    connectedAt: date, generation: generation, owner: owner, strict: capture.strict, homeLANAccess: capture.homeLANAccess)
                try binding.require(self); try current()
                message = "Testing selected packet prefix"
                return binding
            case .connecting, .reasserting: entered = true
            case .disconnected: if entered { throw CancellationError() }
            case .disconnecting, .invalid: throw CancellationError()
            @unknown default: throw CancellationError()
            }
            try await Task.sleep(for: .milliseconds(100))
        }
        throw CancellationError()
    }
}
