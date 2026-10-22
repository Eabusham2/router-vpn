import Foundation
@preconcurrency import NetworkExtension

/// Reuse the source/session capture used by proved DNS, and additionally bind
/// the complete paired entry for Router-to-Router multihop measurements.
@MainActor struct IOSCurrentTelemetryCapture {
    let source: IOSDNSMeasurementCapture
    private let entry: Data?
    init(model: RouterVPNModel, network: UInt64) throws {
        guard model.connected, let bundle = model.bundle,
              IOSDNSRuntimePolicy.selectedProfile(in: bundle)?.normalizedNodeKind == "router-vpn" else {
            throw IOSTelemetryProtocol.issue("Connect a proved Router VPN node before measuring its private path.")
        }
        var source = try IOSDNSMeasurementCapture(model: model)
        source.network = network; self.source = source
        if let captured = source.identity.entryBundleData {
            let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
            let actual = try encoder.encode(model.iosMultihopEntryBundle(for: bundle))
            guard try encoder.encode(JSONDecoder().decode(ClientBundle.self, from: captured)) == actual else { throw CancellationError() }
            entry = actual
        } else { entry = nil }
        try requireCurrent(model)
    }
    func requireCurrent(_ model: RouterVPNModel) throws {
        try source.requireCurrent(model: model)
        if let entry {
            guard let bundle = model.bundle else { throw CancellationError() }
            let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
            guard try encoder.encode(model.iosMultihopEntryBundle(for: bundle)) == entry else { throw CancellationError() }
        }
    }
    func connection(_ model: RouterVPNModel) async throws -> NETunnelProviderSession {
        try requireCurrent(model)
        let managers = try await NETunnelProviderManager.loadAllFromPreferences().filter {
            ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == "com.eabusham.routervpn.PacketTunnel"
        }
        try requireCurrent(model)
        guard managers.count == 1, let connection = managers[0].connection as? NETunnelProviderSession,
              connection.status == .connected, connection.connectedDate == source.identity.connectedAt else { throw CancellationError() }
        return connection
    }
    func current(_ model: RouterVPNModel, connection: NETunnelProviderSession) -> Bool {
        guard connection.status == .connected, connection.connectedDate == source.identity.connectedAt else { return false }
        return (try? requireCurrent(model)) != nil
    }
}

/// The exact stored record and current selection are captured before any await.
/// A public endpoint benchmark is always direct while Router VPN is idle.
@MainActor struct IOSDirectTelemetryCapture {
    let selection: Data
    let records: [String: Data]
    let profiles: [RouterProfile]
    private let decision: UUID
    private let selectedMode: String, logicalMode: String
    private let auto: Bool
    var network: UInt64?
    init(model: RouterVPNModel, profiles: [RouterProfile]) throws {
        guard !model.profileMutationBlocked, !model.iosSpeedLabOwnership.active,
              let bundle = model.bundle else { throw IOSTelemetryProtocol.issue("Disconnect before measuring direct node latency.") }
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
        selection = try encoder.encode(bundle); decision = model.iosConnectGeneration
        selectedMode = model.selectedMode; logicalMode = model.selectedLogicalMode; auto = model.auto
        self.profiles = profiles
        var captured: [String: Data] = [:]
        for profile in profiles {
            guard captured[profile.id] == nil,
                  let record = IOSNodeBundleStore.shared.bundleData(containing: profile.id, current: model.bundle),
                  let stored = try JSONDecoder().decode(ClientBundle.self, from: record).routerProfiles.first(where: { $0.id == profile.id }),
                  stored == profile else { throw CancellationError() }
            captured[profile.id] = record
        }
        records = captured
    }
    func requireCurrent(_ model: RouterVPNModel) throws {
        guard !model.profileMutationBlocked, model.iosConnectGeneration == decision,
              model.selectedMode == selectedMode, model.selectedLogicalMode == logicalMode, model.auto == auto,
              network == nil || IOSViaEntryNetwork.shared.current == network, let bundle = model.bundle else { throw CancellationError() }
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
        guard try encoder.encode(bundle) == selection else { throw CancellationError() }
        for (id, data) in records {
            guard IOSNodeBundleStore.shared.bundleData(containing: id, current: model.bundle) == data else { throw CancellationError() }
        }
    }
}
