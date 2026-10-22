import Foundation
@preconcurrency import NetworkExtension

/// Captures the actual proved native source, including compiled strategy assets
/// and both predecessor bundles. Restoration never reruns AUTO selection or
/// reloads a node from a mutable linked-node store.
@MainActor final class IOSSpeedLabTunnel {
    private static let provider = "com.eabusham.routervpn.PacketTunnel"
    static let ownerKey = IOSSpeedLabContext.ownerKey
    let identity: IOSSessionIdentity?
    private let savedProtocol: NETunnelProviderProtocol?
    private let savedRules: [NEOnDemandRule]
    private let savedOnDemand: Bool
    private let savedEnabled: Bool
    private let savedDescription: String?
    private let multihopExecution: IOSMultihopExecution.Capture?

    private init(identity: IOSSessionIdentity?, proto: NETunnelProviderProtocol?, manager: NETunnelProviderManager?, execution: IOSMultihopExecution.Capture? = nil) throws {
        self.identity = identity
        multihopExecution = execution
        savedProtocol = proto.map { $0.copy() as! NETunnelProviderProtocol }
        savedRules = (manager?.onDemandRules ?? []).map { $0.copy() as! NEOnDemandRule }
        // The app owns simple Connect rules. Do not silently flatten an unknown
        // system-edited evaluation rule into an unrestricted Connect rule.
        guard savedRules.allSatisfy({ $0 is NEOnDemandRuleConnect }) else {
            throw Self.issue("The saved native reconnect rule could not be captured exactly.")
        }
        savedOnDemand = manager?.isOnDemandEnabled ?? false
        savedEnabled = manager?.isEnabled ?? false
        savedDescription = manager?.localizedDescription
    }

    static func capture(model: RouterVPNModel, owner: UUID) async throws -> IOSSpeedLabTunnel {
        try model.iosSpeedLabOwnership.require(owner)
        guard !model.tunnelTransitioning else { throw issue("Wait for the active VPN transition before testing a temporary path.") }
        let identity = model.activeSessionIdentity
        guard !model.connected || identity != nil else { throw issue("The original VPN runtime is not proved.") }
        let manager = try await ownedManager()
        try model.iosSpeedLabOwnership.require(owner)
        guard model.activeSessionIdentity == identity, !model.tunnelTransitioning else { throw CancellationError() }
        if let manager {
            guard let proto = manager.protocolConfiguration as? NETunnelProviderProtocol,
                  proto.providerBundleIdentifier == provider else { throw CancellationError() }
            if let identity {
                guard manager.connection.status == .connected,
                      manager.connection.connectedDate == identity.connectedAt,
                      proto.providerConfiguration?["bundle"] as? Data == identity.bundleData else { throw CancellationError() }
                let captured = try IOSSessionIdentity(connectedAt: identity.connectedAt, engine: identity.engine,
                    rawProfile: identity.rawProfile, bundleData: identity.bundleData,
                    configuration: proto.providerConfiguration ?? [:])
                guard captured.entryBundleData == identity.entryBundleData, captured.entryMode == identity.entryMode else { throw CancellationError() }
            } else {
                guard idle(manager), !model.connected, !manager.isOnDemandEnabled else { throw CancellationError() }
            }
            var execution: IOSMultihopExecution.Capture?
            if let identity, try IOSMultihopExecution.requiresCapture(configuration: proto.providerConfiguration ?? [:]) {
                execution = try await readExecution(manager, model: model, identity: identity, owner: owner)
            }
            return try IOSSpeedLabTunnel(identity: identity, proto: proto, manager: manager, execution: execution)
        }
        guard identity == nil, !model.connected else { throw CancellationError() }
        return try IOSSpeedLabTunnel(identity: nil, proto: nil, manager: nil)
    }

    func stopOriginal(model: RouterVPNModel, owner: UUID) async throws {
        guard let identity else { return }
        try model.iosSpeedLabOwnership.require(owner)
        guard model.activeSessionIdentity == identity,
              let manager = try await Self.ownedManager(),
              let expected = savedProtocol else { throw CancellationError() }
        try model.iosSpeedLabOwnership.require(owner)
        guard manager.connection.status == .connected,
              manager.connection.connectedDate == identity.connectedAt,
              Self.sameProtocol(manager.protocolConfiguration, expected) else { throw CancellationError() }
        if let multihopExecution {
            let current = try await Self.readExecution(manager, model: model, identity: identity, owner: owner)
            guard current.source == multihopExecution.source, current.sessionID == multihopExecution.sessionID,
                  current.execution == multihopExecution.execution else { throw IOSMultihopExecution.issue() }
        }
        try await Self.stop(manager, expected: expected, model: model, owner: owner)
    }

    static func stopTemporary(model: RouterVPNModel, owner: UUID) async throws {
        guard model.iosSpeedLabOwnership.owns(owner) else { throw CancellationError() }
        guard let manager = try await ownedManager() else { return }
        guard model.iosSpeedLabOwnership.owns(owner) else { throw CancellationError() }
        if idle(manager), !manager.isOnDemandEnabled { await model.refreshTunnelStatus(); return }
        guard let proto = manager.protocolConfiguration as? NETunnelProviderProtocol,
              proto.providerConfiguration?[ownerKey] as? String == owner.uuidString else {
            throw issue("A newer VPN owner replaced the temporary Speed Lab path.")
        }
        let expected = proto.copy() as! NETunnelProviderProtocol
        do { try await stop(manager, expected: expected, model: model, owner: owner, retiring: true) }
        catch is CancellationError { throw CancellationError() }
        catch {
            // The last captured manager still belongs to this transaction.
            // A timed-out stop or unavailable preferences is not retirement.
            // Its caller retains the MTU hold and retries the same owner.
            guard sameProtocol(manager.protocolConfiguration, expected) else { throw CancellationError() }
            throw NSError(domain: "RouterVPN.SpeedLab", code: 62,
                userInfo: [NSLocalizedDescriptionKey: "The captured temporary VPN has not finished shutdown: \(error.localizedDescription)"])
        }
    }

    static func retirementPending(_ error: Error) -> Bool {
        let error = error as NSError
        return error.domain == "RouterVPN.SpeedLab" && error.code == 62
    }

    static func recoverTemporary(model: RouterVPNModel, owner: UUID) async throws {
        let token = try model.iosSpeedLabOwnership.begin(owner: owner) {
            model.iosConnectGeneration = UUID()
        }
        defer { model.iosSpeedLabOwnership.finish(token) }
        try await IOSSpeedLabContext.$owner.withValue(token) {
            try await stopTemporary(model: model, owner: token)
        }
    }

    private static func stop(_ manager: NETunnelProviderManager, expected: NETunnelProviderProtocol,
                             model: RouterVPNModel, owner: UUID, retiring: Bool = false) async throws {
        func requireOwner() throws {
            if retiring {
                guard model.iosSpeedLabOwnership.owns(owner), !model.iosUserDisconnectInProgress,
                      !model.iosSpeedLabOwnership.userDisconnected(owner),
                      (manager.protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration?[ownerKey] as? String == owner.uuidString else { throw CancellationError() }
            } else { try model.iosSpeedLabOwnership.require(owner) }
        }
        try requireOwner()
        guard sameProtocol(manager.protocolConfiguration, expected) else { throw CancellationError() }
        let date = manager.connection.connectedDate
        manager.isOnDemandEnabled = false; manager.onDemandRules = []
        try await manager.saveToPreferences()
        try requireOwner()
        try await manager.loadFromPreferences()
        try requireOwner()
        guard sameProtocol(manager.protocolConfiguration, expected), !manager.isOnDemandEnabled,
              (manager.onDemandRules ?? []).isEmpty,
              manager.connection.connectedDate == date else { throw CancellationError() }
        model.iosConnectGeneration = UUID()
        manager.connection.stopVPNTunnel()
        let deadline = ProcessInfo.processInfo.systemUptime + 20
        while !idle(manager), ProcessInfo.processInfo.systemUptime < deadline {
            try requireOwner()
            try await Task.sleep(for: .milliseconds(100))
        }
        try requireOwner()
        try await manager.loadFromPreferences()
        try requireOwner()
        guard idle(manager), sameProtocol(manager.protocolConfiguration, expected),
              !manager.isOnDemandEnabled, (manager.onDemandRules ?? []).isEmpty else {
            throw issue("Temporary Speed Lab tunnel did not fully stop.")
        }
        await model.refreshTunnelStatus()
        try requireOwner()
        guard !model.connected, !model.tunnelTransitioning else { throw issue("The captured native stop is not verified.") }
    }

    func restore(model: RouterVPNModel, owner: UUID, reconnect: Bool) async throws {
        func requireOwner() throws {
            guard reconnect ? model.iosSpeedLabOwnership.current(owner) : model.iosSpeedLabOwnership.mayRestoreSelection(owner) else { throw CancellationError() }
        }
        try requireOwner()
        guard let savedProtocol else { return }
        guard let manager = try await Self.ownedManager() else { throw Self.issue("The original native VPN manager was removed.") }
        try requireOwner()
        guard Self.idle(manager), !model.connected, !model.tunnelTransitioning else { throw CancellationError() }
        let proto = savedProtocol.copy() as! NETunnelProviderProtocol
        if let identity, var configuration = proto.providerConfiguration, configuration["strategy_catalog"] != nil {
            let candidates = try IOSStrategyWire.catalog(configuration).filter { $0.raw == identity.rawProfile }
            guard candidates.count == 1 else { throw Self.issue("The exact original raw runtime is absent from its frozen catalog.") }
            let plan = try IOSStrategyPlan(kind: .manual, candidates: candidates)
            configuration["strategy"] = try plan.object()
            configuration["mode"] = identity.rawProfile
            configuration["rawProfileID"] = identity.rawProfile
            configuration["modeCandidates"] = [identity.rawProfile]
            configuration["logicalMode"] = candidates[0].logical
            proto.providerConfiguration = configuration
        }
        manager.protocolConfiguration = proto
        manager.localizedDescription = savedDescription
        manager.isEnabled = savedEnabled
        let onDemand = reconnect ? savedOnDemand : false
        let rules = reconnect ? savedRules : []
        // Re-enabling On Demand while idle may start the VPN before its
        // captured MTU lease reaches startVPNTunnel. Restore it only after the
        // explicit held start has passed fresh proof.
        manager.isOnDemandEnabled = false
        manager.onDemandRules = rules.map { $0.copy() as! NEOnDemandRule }
        try await manager.saveToPreferences()
        try requireOwner()
        try await manager.loadFromPreferences()
        try requireOwner()
        guard Self.sameProtocol(manager.protocolConfiguration, proto), manager.isEnabled == savedEnabled,
              !manager.isOnDemandEnabled,
              Self.sameRules(manager.onDemandRules ?? [], rules), Self.idle(manager) else {
            throw Self.issue("The original native VPN source did not survive preference readback.")
        }
        guard reconnect, let identity else { return }
        model.iosConnectGeneration = UUID()
        let generation = model.iosConnectGeneration
        let hold = IOSMTUMeasurementGate.current
        guard !hold.isEmpty else { throw Self.issue("Original-path restoration lost its MTU measurement lease.") }
        var options: [String: NSObject] = ["routervpn_mtu_hold": hold as NSString]
        if let multihopExecution {
            options[IOSMultihopExecution.launchKey] = String(decoding: try multihopExecution.encoded(), as: UTF8.self) as NSString
        }
        try manager.connection.startVPNTunnel(options: options)
        let tor = ["external-tor", "external-tor-bridge"].contains(identity.rawProfile)
        let deadline = ProcessInfo.processInfo.systemUptime + (tor ? 210 : 130)
        var sawTransition = false
        while ProcessInfo.processInfo.systemUptime < deadline {
            try model.iosSpeedLabOwnership.require(owner)
            guard model.iosConnectGeneration == generation, Self.sameProtocol(manager.protocolConfiguration, proto) else { throw CancellationError() }
            if [.connecting, .reasserting, .connected].contains(manager.connection.status) { sawTransition = true }
            if manager.connection.status == .disconnecting || sawTransition && Self.idle(manager) {
                throw Self.issue("The original VPN stopped before its fresh path proof completed.")
            }
            await model.refreshTunnelStatus()
            try model.iosSpeedLabOwnership.require(owner)
            if let restored = model.activeSessionIdentity, model.connected, !model.tunnelTransitioning {
                guard restored.engine == identity.engine, restored.rawProfile == identity.rawProfile,
                      restored.bundleData == identity.bundleData, restored.entryBundleData == identity.entryBundleData,
                      restored.entryMode == identity.entryMode else {
                    throw Self.issue("Restoration proved a different runtime or predecessor source.")
                }
                if let multihopExecution {
                    let current = try await Self.readExecution(manager, model: model, identity: restored, owner: owner)
                    guard current.source == multihopExecution.source, current.execution == multihopExecution.execution,
                          current.sessionID != multihopExecution.sessionID else { throw IOSMultihopExecution.issue() }
                }
                if onDemand {
                    manager.isOnDemandEnabled = true
                    try await manager.saveToPreferences()
                    try requireOwner()
                    try await manager.loadFromPreferences()
                    try requireOwner()
                    guard model.activeSessionIdentity == restored, manager.connection.status == .connected,
                          manager.connection.connectedDate == restored.connectedAt,
                          Self.sameProtocol(manager.protocolConfiguration, proto), manager.isOnDemandEnabled,
                          Self.sameRules(manager.onDemandRules ?? [], rules) else {
                        throw Self.issue("The restored reconnect policy belongs to another native session.")
                    }
                }
                return
            }
            try await Task.sleep(for: .milliseconds(150))
        }
        throw Self.issue("The original VPN has not completed its fresh path proof; inspect its status or Disconnect.")
    }

    private static func readExecution(_ manager: NETunnelProviderManager, model: RouterVPNModel,
                                      identity: IOSSessionIdentity, owner: UUID) async throws -> IOSMultihopExecution.Capture {
        try model.iosSpeedLabOwnership.require(owner)
        let entryKey = identity.engine == "external-libbox" ? "external_entry_bundle" : "entryBundle"
        guard model.activeSessionIdentity == identity, model.connected,
              let connection = manager.connection as? NETunnelProviderSession,
              connection.status == .connected, connection.connectedDate == identity.connectedAt,
              let config = (manager.protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration,
              config["bundle"] as? Data == identity.bundleData, config[entryKey] as? Data == identity.entryBundleData else { throw CancellationError() }
        let source = try IOSMultihopExecution.Source(configuration: config, digest: RouterVPNModel.iosStrategyDigest)
        let request = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
        let data = try await IOSMTUControl.send(connection, operation: "speed-lab-execution", request: request, session: "")
        try model.iosSpeedLabOwnership.require(owner)
        guard model.activeSessionIdentity == identity, model.connected,
              connection.status == .connected, connection.connectedDate == identity.connectedAt,
              let after = (manager.protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration,
              after["bundle"] as? Data == identity.bundleData, after[entryKey] as? Data == identity.entryBundleData else { throw CancellationError() }
        guard try IOSMultihopExecution.Source(configuration: after, digest: RouterVPNModel.iosStrategyDigest) == source else { throw CancellationError() }
        return try IOSMultihopExecution.Capture.decode(data, source: source, request: request)
    }

    private static func ownedManager() async throws -> NETunnelProviderManager? {
        let managers = try await NETunnelProviderManager.loadAllFromPreferences().filter {
            ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == provider
        }
        guard managers.count <= 1 else { throw issue("Multiple Router VPN managers make Speed Lab ownership ambiguous.") }
        return managers.first
    }

    private static func idle(_ manager: NETunnelProviderManager) -> Bool {
        manager.connection.status == .disconnected || manager.connection.status == .invalid
    }

    private static func sameProtocol(_ actual: NEVPNProtocol?, _ expected: NETunnelProviderProtocol) -> Bool {
        guard let actual = actual as? NETunnelProviderProtocol,
              actual.providerBundleIdentifier == expected.providerBundleIdentifier,
              actual.serverAddress == expected.serverAddress,
              actual.includeAllNetworks == expected.includeAllNetworks, actual.enforceRoutes == expected.enforceRoutes,
              actual.excludeLocalNetworks == expected.excludeLocalNetworks,
              actual.excludeAPNs == expected.excludeAPNs, actual.excludeCellularServices == expected.excludeCellularServices else { return false }
        return NSDictionary(dictionary: actual.providerConfiguration ?? [:]).isEqual(to: expected.providerConfiguration ?? [:])
    }

    private static func sameRules(_ actual: [NEOnDemandRule], _ expected: [NEOnDemandRule]) -> Bool {
        guard actual.count == expected.count else { return false }
        return zip(actual, expected).allSatisfy { a, b in
            a is NEOnDemandRuleConnect && b is NEOnDemandRuleConnect && a.action == b.action &&
            a.interfaceTypeMatch == b.interfaceTypeMatch && a.dnsSearchDomainMatch == b.dnsSearchDomainMatch &&
            a.dnsServerAddressMatch == b.dnsServerAddressMatch && a.ssidMatch == b.ssidMatch && a.probeURL == b.probeURL
        }
    }

    private static func issue(_ text: String) -> NSError {
        NSError(domain: "RouterVPN.SpeedLab", code: 61, userInfo: [NSLocalizedDescriptionKey: text])
    }
}
