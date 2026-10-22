import Combine
import Foundation
@preconcurrency import NetworkExtension

/// Both the selected editor source and the independently proved native source
/// are frozen. A same-name reconnect or linked-entry edit is a different path.
@MainActor struct IOSDNSMeasurementCapture {
    let identity: IOSSessionIdentity
    let nodeID: String
    let tor: Bool
    private let selection: Data
    private let decision: UUID
    private let mode: String
    private let logicalMode: String
    private let auto: Bool
    var network: UInt64?

    init(model: RouterVPNModel) throws {
        guard model.connected, !model.tunnelTransitioning, let identity = model.activeSessionIdentity,
              let bundle = model.bundle, let selected = IOSDNSRuntimePolicy.selectedProfile(in: bundle) else {
            throw IOSDNSMeasurementStatus.issue("Connect the selected node and wait for its live path proof before measuring DNS.")
        }
        self.identity = identity; nodeID = selected.id
        tor = ["external-tor", "external-tor-bridge"].contains(identity.rawProfile)
        selection = try Self.encoded(bundle); decision = model.iosConnectGeneration
        mode = model.selectedMode; logicalMode = model.selectedLogicalMode; auto = model.auto
        try requireCurrent(model: model)
    }

    func requireCurrent(model: RouterVPNModel) throws {
        guard model.connected, !model.tunnelTransitioning, !model.iosUserDisconnectInProgress,
              model.activeSessionIdentity == identity, model.iosConnectGeneration == decision,
              network == nil || IOSViaEntryNetwork.shared.current == network else { throw CancellationError() }
        try requireSources(model: model)
    }

    /// An explicit DNS draft may survive Disconnect. Its saved source and
    /// paired entry still must be the ones on which the user chose the row.
    func requireSources(model: RouterVPNModel) throws {
        guard
              model.selectedMode == mode, model.selectedLogicalMode == logicalMode, model.auto == auto,
              let bundle = model.bundle, try Self.encoded(bundle) == selection,
              let selected = IOSDNSRuntimePolicy.selectedProfile(in: bundle), selected.id == nodeID else { throw CancellationError() }
        if identity.engine == "external-libbox" {
            let source = try model.externalRuntimeBundleData(source: bundle, profile: selected)
            guard try Self.canonical(source) == Self.canonical(identity.bundleData),
                  try model.externalTorEntryData(source: bundle) == identity.entryBundleData else { throw CancellationError() }
        } else {
            guard try Self.canonical(identity.bundleData) == selection else { throw CancellationError() }
        }
    }

    private static func encoded(_ bundle: ClientBundle) throws -> Data {
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
        return try encoder.encode(bundle)
    }
    private static func canonical(_ data: Data) throws -> Data {
        try encoded(JSONDecoder().decode(ClientBundle.self, from: data))
    }
}

private final class IOSDNSMeasurementReply: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<Data, Error>?
    init(_ value: CheckedContinuation<Data, Error>) { continuation = value }
    func finish(_ data: Data?) {
        lock.lock(); let pending = continuation; continuation = nil; lock.unlock()
        guard let pending else { return }
        guard let data, !data.isEmpty, data.count <= 65536 else {
            pending.resume(throwing: IOSDNSMeasurementStatus.issue("The captured VPN extension did not return its DNS acknowledgement.")); return
        }
        pending.resume(returning: data)
    }
}

@MainActor final class IOSDNSMeasurementClient: ObservableObject {
    // The app owns one VPN. Reopening the sheet must reveal an outstanding
    // cleanup transaction instead of hiding its retained native/MTU owner.
    static let shared = IOSDNSMeasurementClient()
    @Published private(set) var running = false
    @Published private(set) var cleanupPending = false
    @Published private(set) var progress = ""
    @Published private(set) var error = ""
    @Published private(set) var results: [IOSDNSMeasurementResult] = []
    private var task: Task<Void, Never>?
    private var transaction: IOSDNSMeasurementTransaction?
    private var cancellationGeneration: UInt64 = 0
    private var receiptCapture: IOSDNSMeasurementCapture?
    private var receiptTime: TimeInterval = 0

    static func supported(_ model: RouterVPNModel) -> Bool {
        model.connected && !model.tunnelTransitioning && model.activeEngine == "external-libbox"
    }

    func start(model: RouterVPNModel, transport: String) {
        guard !running, Self.supported(model), !model.iosSpeedLabOwnership.active, !IOSMTUMeasurementGate.held else { return }
        let generation = cancellationGeneration
        running = true; cleanupPending = false; error = ""; results = []; receiptCapture = nil
        progress = "Capturing the proved DNS path…"
        task = Task { @MainActor [self] in
            defer { running = false; cleanupPending = false; task = nil; transaction = nil }
            do {
                var initial = try IOSDNSMeasurementCapture(model: model)
                initial.network = try await IOSViaEntryNetwork.shared.snapshot()
                try Task.checkCancellation()
                guard generation == cancellationGeneration, !model.iosSpeedLabOwnership.active,
                      !IOSMTUMeasurementGate.held else { throw CancellationError() }
                let captured = initial
                try captured.requireCurrent(model: model)
                try IOSDNSRetirementReceipts.shared.requireAvailable()
                let owner = try model.iosSpeedLabOwnership.begin { [weak self] in self?.cancel() }
                defer { model.iosSpeedLabOwnership.finish(owner) }
                let values = try await IOSSpeedLabContext.$owner.withValue(owner) {
                    try await IOSMTUControl.withHold(model: model) {
                        try Task.checkCancellation(); try captured.requireCurrent(model: model)
                        try model.iosSpeedLabOwnership.require(owner)
                        let binding = try await IOSMTUControl.capture(model)
                        try captured.requireCurrent(model: model)
                        guard binding.identity == captured.identity else { throw CancellationError() }
                        let id = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
                        let infoData = try await send(binding.connection, operation: "dns-measure-info", id: id,
                            session: "", nativeSession: "", transport: "")
                        let information = try IOSDNSMeasurementInfo.decode(infoData, request: id, node: captured.nodeID)
                        let owned = try IOSDNSMeasurementTransaction(id: id, owner: information, transport: transport,
                            tor: captured.tor, send: { [self] operation in
                                try await send(binding.connection, operation: operation, id: id,
                                    session: information.session_id, nativeSession: information.native_session_id,
                                    transport: operation == "dns-measure-start" ? transport : "")
                            }, recovered: {
                                IOSDNSRetirementReceipts.shared.drained(providerSession: information.session_id,
                                    nativeSession: information.native_session_id, request: id, nodeID: captured.nodeID)
                            })
                        transaction = owned
                        return try await owned.run(current: {
                            await model.refreshTunnelStatus()
                            do { try captured.requireCurrent(model: model); try model.iosSpeedLabOwnership.require(owner) }
                            catch { return false }
                            return generation == self.cancellationGeneration && IOSMTUControl.current(binding, model: model)
                        }, pending: {
                            self.cleanupPending = true
                            self.progress = "Cleanup pending. Retrying the captured extension until its DNS workers confirm drain; the measurement hold remains active."
                        }, update: { stage in
                            self.progress = "DNS comparison: \(stage) · three answers per resolver"
                        })
                    }
                }
                try Task.checkCancellation(); try captured.requireCurrent(model: model)
                guard generation == cancellationGeneration else { throw CancellationError() }
                receiptCapture = captured; receiptTime = ProcessInfo.processInfo.systemUptime
                results = values
                progress = "DNS responses complete and drained. Choose a public row to fill the editor, then explicitly Save."
            } catch is CancellationError {
                results = []; receiptCapture = nil
                error = "DNS comparison cancelled or its captured session, selection or network changed."
            } catch {
                results = []; receiptCapture = nil; self.error = error.localizedDescription
            }
        }
    }

    func cancel() {
        cancellationGeneration &+= 1; results = []; receiptCapture = nil
        guard running else { return }
        transaction?.cancel(); task?.cancel()
        progress = "Cancelling DNS queries and joining their native cleanup…"
    }

    func requireCurrent(model: RouterVPNModel, result: IOSDNSMeasurementResult) throws {
        guard !running, let captured = receiptCapture,
              ProcessInfo.processInfo.systemUptime - receiptTime < 120,
              result.kind == "public", result.ready, results.contains(result) else {
            throw IOSDNSMeasurementStatus.issue("Retest this path before choosing a measured DNS result.")
        }
        try captured.requireCurrent(model: model)
    }

    func captureForEditor(model: RouterVPNModel, result: IOSDNSMeasurementResult) throws -> IOSDNSMeasurementCapture {
        try requireCurrent(model: model, result: result)
        guard let receiptCapture else { throw CancellationError() }
        return receiptCapture
    }

    func invalidateIfStale(model: RouterVPNModel) {
        guard !running, let captured = receiptCapture else { return }
        do {
            guard ProcessInfo.processInfo.systemUptime - receiptTime < 120 else { throw CancellationError() }
            try captured.requireCurrent(model: model)
        } catch {
            results = []; receiptCapture = nil
            self.error = "The measured DNS path changed or expired. Retest before using a result."
        }
    }

    private func send(_ connection: NETunnelProviderSession, operation: String, id: String,
                      session: String, nativeSession: String, transport: String) async throws -> Data {
        let data = try JSONSerialization.data(withJSONObject: ["operation": operation, "request_id": id,
            "session_id": session, "native_session_id": nativeSession, "transport": transport])
        guard data.count <= 512 else { throw CancellationError() }
        return try await withCheckedThrowingContinuation { continuation in
            let reply = IOSDNSMeasurementReply(continuation)
            DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + 8) { reply.finish(nil) }
            do { try connection.sendProviderMessage(data) { reply.finish($0) } }
            catch { reply.finish(nil) }
        }
    }
}
