import Combine
import Foundation
@preconcurrency import NetworkExtension

/// Read-only live responses on the captured external path. This owner survives
/// sheet dismissal through native drain; it never changes or reconnects a node.
@MainActor final class IOSExternalLiveTelemetry: ObservableObject {
    static let shared = IOSExternalLiveTelemetry()
    @Published private(set) var milliseconds: Double?
    @Published private(set) var running = false
    @Published private(set) var progress = ""
    private var transaction: IOSHopMeasurementTransaction?
    private var worker: Task<Double, Error>?
    private var generation: UInt64 = 0
    private var receipt: IOSDNSMeasurementCapture?
    private var receiptSource: Data?
    private var receiptAt: TimeInterval = 0
    private var lastRefresh: TimeInterval = -.infinity
    private var performanceVisible = false
    private var backgroundRefresh = false

    static func supported(_ model: RouterVPNModel) -> Bool {
        model.connected && !model.tunnelTransitioning && !model.iosCandidateTesting &&
            (model.activeSessionIdentity?.hasPublicFinalResponse == true ||
             (model.activeEngine == "external-libbox" && model.unifiedSelectedProfile?.normalizedNodeKind == "external"))
    }

    func showPerformance(_ visible: Bool) {
        performanceVisible = visible
        if !visible || backgroundRefresh { cancel() }
    }

    func cancel() {
        generation &+= 1
        transaction?.cancel(); worker?.cancel()
        if running { progress = "Cancelling live responses and waiting for the original native workers…" }
    }

    private func clear() { milliseconds = nil; receipt = nil; receiptSource = nil; receiptAt = 0 }

    func currentMilliseconds(model: RouterVPNModel) -> Double? {
        guard let receipt, let source = receiptSource, Self.supported(model),
              ProcessInfo.processInfo.systemUptime - receiptAt < 15,
              (try? receipt.requireCurrent(model: model)) != nil,
              Self.storedCurrent(node: receipt.nodeID, source: source, model: model) else { return nil }
        return milliseconds
    }

    func invalidate(model: RouterVPNModel) {
        if currentMilliseconds(model: model) == nil { clear() }
    }

    func refresh(model: RouterVPNModel) async {
        invalidate(model: model)
        let now = ProcessInfo.processInfo.systemUptime
        guard !performanceVisible, !running, Self.supported(model), !model.iosSpeedLabOwnership.active,
              !IOSMTUMeasurementGate.held, now - lastRefresh >= 5 else { return }
        lastRefresh = now; backgroundRefresh = true
        defer { backgroundRefresh = false }
        do { _ = try await measure(model: model) }
        catch { clear() }
    }

    func measure(model: RouterVPNModel) async throws -> Double {
        try Task.checkCancellation()
        guard !running, Self.supported(model), !model.iosSpeedLabOwnership.active, !IOSMTUMeasurementGate.held else {
            throw IOSTelemetryProtocol.issue("Wait for the current measurement and its native cleanup before measuring the external path.")
        }
        let round = generation
        var capture = try IOSDNSMeasurementCapture(model: model)
        guard let stored = IOSNodeBundleStore.shared.bundleData(containing: capture.nodeID, current: model.persistedNodeBundle) else {
            throw CancellationError()
        }
        let ordered = capture.identity.selectedMeasurementSource.flatMap { $0.externalFinal ? $0 : nil }
        let local = capture.identity.localPublicResponseSource
        let publicIDs = local?.ids ?? ordered?.ids
        let requested = try (local == nil ? ordered?.requested : "local") ?? IOSExternalNodeStatistics.requestedExecution(node: capture.nodeID, bundle: capture.identity.bundleData)
        running = true; progress = "Measuring three HTTPS responses through the proved external path…"
        defer { running = false; transaction = nil; worker = nil }
        let task = Task { @MainActor [self] in
            capture.network = try await IOSViaEntryNetwork.shared.snapshot()
            try Task.checkCancellation(); try capture.requireCurrent(model: model)
            guard generation == round, !model.iosSpeedLabOwnership.active, !IOSMTUMeasurementGate.held,
                  Self.storedCurrent(node: capture.nodeID, source: stored, model: model) else { throw CancellationError() }
            let captured = capture
            let owner = try model.iosSpeedLabOwnership.begin { [weak self] in self?.cancel() }
            defer { model.iosSpeedLabOwnership.finish(owner) }
            let value = try await IOSSpeedLabContext.$owner.withValue(owner) {
                try await IOSMTUControl.withHold(model: model, idleOnly: true) {
                    try Task.checkCancellation(); try captured.requireCurrent(model: model)
                    try model.iosSpeedLabOwnership.require(owner)
                    let binding = try await IOSMTUControl.capture(model)
                    try captured.requireCurrent(model: model)
                    guard binding.identity == captured.identity, let network = captured.network else { throw CancellationError() }
                    let id = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
                    let data = try await IOSMTUControl.send(binding.connection, operation: "hop-measure-info", request: id, session: "")
                    let initial = try IOSHopMeasurementBinding.decode(data, request: id, mtuSession: binding.session)
                    let path: IOSExternalNodeStatistics.PathReceipt?
                    if let local {
                        guard initial.node_id == nil, initial.execution == nil, initial.ordered_execution == nil, let binding = initial.local_public_final,
                              binding.source_sha256 == local.source, binding.config_sha256 == local.config else { throw CancellationError() }
                        path = nil
                    } else if let ordered {
                        guard initial.node_id == nil, initial.execution == nil, initial.local_public_final == nil, let execution = initial.ordered_execution, execution.source_sha256 == ordered.source,
                              execution.config_sha256 == ordered.config, execution.requested == requested,
                              execution.nodes == ordered.ids.count, ["local", "server"].contains(execution.selected),
                              requested == "auto" || requested == execution.selected else { throw CancellationError() }
                        path = nil
                    } else {
                        guard initial.node_id == captured.nodeID else { throw CancellationError() }
                        path = try IOSExternalNodeStatistics.PathReceipt(binding: initial, requested: requested, network: network)
                    }
                    let owned = try IOSHopMeasurementTransaction(id: id, session: initial.session_id,
                        startOperation: "hop-measure-response-start", send: { operation in
                            try await IOSMTUControl.send(binding.connection, operation: operation, request: id, session: initial.session_id)
                        })
                    transaction = owned
                    var completed: IOSHopMeasurementStatus?
                    try await owned.run(current: {
                        await model.refreshTunnelStatus()
                        guard self.generation == round,
                              Self.storedCurrent(node: captured.nodeID, source: stored, model: model) else { return false }
                        do { try captured.requireCurrent(model: model); try model.iosSpeedLabOwnership.require(owner) }
                        catch { return false }
                        return IOSMTUControl.current(binding, model: model)
                    }, update: { completed = $0; self.progress = $0.stage })
                    let finalData = try await IOSMTUControl.send(binding.connection, operation: "hop-measure-info", request: id, session: "")
                    let final = try IOSHopMeasurementBinding.decode(finalData, request: id, mtuSession: binding.session)
                    try Task.checkCancellation(); try captured.requireCurrent(model: model)
                    try model.iosSpeedLabOwnership.require(owner)
                    guard generation == round, IOSMTUControl.current(binding, model: model),
                          Self.storedCurrent(node: captured.nodeID, source: stored, model: model),
                          final.session_id == initial.session_id,
                          let status = completed, status.complete, status.drained, status.stage == "complete", status.failure == nil,
                          let result = status.results.last,
                          result.role == "exit", result.kind == "public-path", result.ready,
                          result.failure == nil, result.idle == nil, result.download == nil, result.upload == nil, result.benchmark == nil,
                          let response = result.response, response.valid else { throw CancellationError() }
                    if let publicIDs {
                        guard final.ordered_execution == initial.ordered_execution, final.local_public_final == initial.local_public_final,
                              status.results.count == 2, status.results.first?.node_id == publicIDs.first,
                              status.results.first?.role == "entry", status.results.first?.kind == "private-node",
                              status.results.first?.ready == true, result.node_id == publicIDs.last else { throw CancellationError() }
                    } else {
                        guard status.results.count == 1, result.node_id == captured.nodeID, final.node_id == captured.nodeID,
                              try IOSExternalNodeStatistics.PathReceipt(binding: final, requested: requested, network: network) == path else { throw CancellationError() }
                    }
                    return response.distribution.median_ms
                }
            }
            try Task.checkCancellation(); try captured.requireCurrent(model: model)
            try model.iosSpeedLabOwnership.require(owner)
            guard generation == round, Self.storedCurrent(node: captured.nodeID, source: stored, model: model) else { throw CancellationError() }
            receipt = captured; receiptSource = stored; receiptAt = ProcessInfo.processInfo.systemUptime
            milliseconds = value; progress = "Live HTTPS response through the captured external path."
            return value
        }
        worker = task
        do { return try await withTaskCancellationHandler { try await task.value } onCancel: { task.cancel() } }
        catch { clear(); throw error }
    }

    private static func storedCurrent(node: String, source: Data, model: RouterVPNModel) -> Bool {
        guard let actual = IOSNodeBundleStore.shared.bundleData(containing: node, current: model.persistedNodeBundle) else { return false }
        if actual == source { return true }
        guard let expected = try? IOSNodeUsage.canonicalJSON(source), let current = try? IOSNodeUsage.canonicalJSON(actual) else { return false }
        return expected == current
    }
}
