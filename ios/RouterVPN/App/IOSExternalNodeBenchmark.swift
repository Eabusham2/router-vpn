import Combine
import Foundation
@preconcurrency import NetworkExtension

/// One retained app owner survives dismissal until its exact native request
/// drains. It never connects a temporary candidate or changes the user's path.
@MainActor final class IOSExternalNodeBenchmark: ObservableObject {
    static let shared = IOSExternalNodeBenchmark()
    @Published private(set) var running = false
    @Published private(set) var progress = ""
    @Published private(set) var savedText = ""
    private var savedKey: String?
    private var task: Task<Void, Never>?
    private var transaction: IOSHopMeasurementTransaction?
    private var generation: UInt64 = 0

    static func supported(_ model: RouterVPNModel) -> Bool {
        model.connected && !model.tunnelTransitioning && model.activeEngine == "external-libbox" &&
            model.unifiedSelectedProfile?.normalizedNodeKind == "external"
    }

    func refreshSaved(model: RouterVPNModel) {
        savedKey = nil
        do {
            guard model.unifiedSelectedProfile?.normalizedNodeKind == "external" else { savedText = ""; return }
            let key = try IOSExternalNodeStatistics.selectedKey(model)
            savedKey = key
            savedText = try IOSExternalNodeStatistics.saved(key: key)?.detail ?? "No saved routed HTTPS benchmark for this exact path."
        } catch { savedText = "Saved routed measurements could not be read. Existing private history was kept." }
    }

    func history(for key: String?) -> String { key != nil && key == savedKey ? savedText : "" }

    func start(model: RouterVPNModel) {
        guard !running, Self.supported(model), !model.iosSpeedLabOwnership.active, !IOSMTUMeasurementGate.held else { return }
        let round = generation
        running = true; progress = "Capturing the selected external node and its proved native path…"
        task = Task { @MainActor [self] in
            defer { running = false; task = nil; transaction = nil }
            var published = false
            do {
                var initial = try IOSDNSMeasurementCapture(model: model)
                guard initial.identity.engine == "external-libbox",
                      let stored = IOSNodeBundleStore.shared.bundleData(containing: initial.nodeID, current: model.persistedNodeBundle) else { throw CancellationError() }
                let key = try IOSExternalNodeStatistics.key(node: initial.nodeID, bundle: initial.identity.bundleData,
                                                           entry: initial.identity.entryBundleData)
                let requested = try IOSExternalNodeStatistics.requestedExecution(node: initial.nodeID, bundle: initial.identity.bundleData)
                initial.network = try await IOSViaEntryNetwork.shared.snapshot()
                try Task.checkCancellation(); try initial.requireCurrent(model: model)
                guard round == generation, !model.iosSpeedLabOwnership.active, !IOSMTUMeasurementGate.held else { throw CancellationError() }
                let captured = initial
                let owner = try model.iosSpeedLabOwnership.begin { [weak self] in self?.cancel() }
                defer { model.iosSpeedLabOwnership.finish(owner) }
                try await IOSSpeedLabContext.$owner.withValue(owner) {
                    try await IOSMTUControl.withHold(model: model) {
                        let record = try await Self.measureHeld(model: model, owner: owner, captured: captured,
                            stored: stored, key: key, requested: requested, validate: {
                                guard round == self.generation else { throw CancellationError() }
                            }, progress: { self.progress = "Selected external path: \($0)" },
                            retained: { self.transaction = $0 })
                        published = true; savedKey = key; savedText = record.detail
                        progress = "All 50 routed HTTPS responses were proved, drained and saved to this exact path."
                    }
                }
            } catch is CancellationError {
                progress = published ? "The 50 responses were saved before cancellation; the MTU release was not confirmed." :
                    "Measurement cancelled or its node, saved source, network or native session changed. Previous statistics were kept."
            } catch {
                progress = (published ? "The 50 responses were saved; MTU release was not confirmed: " : "Measurement was not saved: ") + error.localizedDescription
            }
        }
    }

    /// Both selected-path tests and temporary comparisons use this exact
    /// native50 transaction. The batch supplies additional frozen-cohort checks
    /// and owns the already-held MTU request through native drain and save.
    static func measureHeld(model: RouterVPNModel, owner: UUID, captured: IOSDNSMeasurementCapture,
        stored: Data, key: String, requested: String, saveResult: Bool = true,
        validate: @escaping @MainActor () throws -> Void,
        progress: @escaping @MainActor (String) -> Void,
        retained: @MainActor (IOSHopMeasurementTransaction) -> Void) async throws -> IOSExternalNodeStatistics.Record {
        guard IOSMTUMeasurementGate.held, IOSSpeedLabContext.owner == owner else { throw CancellationError() }
        try Task.checkCancellation(); try validate(); try captured.requireCurrent(model: model)
        try model.iosSpeedLabOwnership.require(owner)
        let binding = try await IOSMTUControl.capture(model)
        try validate(); try captured.requireCurrent(model: model)
        guard binding.identity == captured.identity else { throw CancellationError() }
        let id = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
        let data = try await IOSMTUControl.send(binding.connection, operation: "hop-measure-info", request: id, session: "")
        let information = try IOSHopMeasurementBinding.decode(data, request: id, mtuSession: binding.session)
        guard information.node_id == captured.nodeID, let network = captured.network else { throw CancellationError() }
        let path = try IOSExternalNodeStatistics.PathReceipt(binding: information, requested: requested, network: network)
        let owned = try IOSHopMeasurementTransaction(id: id, session: information.session_id,
            startOperation: "hop-measure-latency-start", send: { operation in
                try await IOSMTUControl.send(binding.connection, operation: operation, request: id, session: information.session_id)
            })
        retained(owned)
        var completed: IOSHopMeasurementStatus?
        try await owned.run(current: {
            await model.refreshTunnelStatus()
            do { try validate() } catch { return false }
            do { try captured.requireCurrent(model: model); try model.iosSpeedLabOwnership.require(owner) }
            catch { return false }
            return IOSMTUControl.current(binding, model: model) &&
                storedSourceCurrent(node: captured.nodeID, stored: stored, model: model)
        }, update: { status in progress(status.stage); completed = status })
        let finalData = try await IOSMTUControl.send(binding.connection, operation: "hop-measure-info", request: id, session: "")
        let finalBinding = try IOSHopMeasurementBinding.decode(finalData, request: id, mtuSession: binding.session)
        try Task.checkCancellation(); try validate(); try captured.requireCurrent(model: model)
        try model.iosSpeedLabOwnership.require(owner)
        guard IOSMTUControl.current(binding, model: model),
              finalBinding.session_id == information.session_id, finalBinding.node_id == captured.nodeID,
              try IOSExternalNodeStatistics.PathReceipt(binding: finalBinding, requested: requested, network: network) == path,
              storedSourceCurrent(node: captured.nodeID, stored: stored, model: model),
              try IOSExternalNodeStatistics.selectedKey(model) == key,
              let status = completed, status.complete, status.drained, status.stage == "complete", status.failure == nil,
              status.results.count == 1, let result = status.results.first,
              result.node_id == captured.nodeID, result.role == "exit", result.kind == "public-path", result.ready,
              result.failure == nil, result.idle == nil, result.download == nil, result.upload == nil, result.response == nil,
              let benchmark = result.benchmark, benchmark.valid else { throw IOSExternalNodeStatistics.issue() }
        if saveResult { return try IOSExternalNodeStatistics.save(key: key, benchmark: benchmark, path: path) }
        // A temporary batch owns this uncommitted value until the original
        // session has drained/restored. Its caller then saves under that same
        // cohort and MTU lease; failed restoration cannot publish history.
        return IOSExternalNodeStatistics.Record(key: key, measuredAt: Date(), benchmark: benchmark, path: path)
    }

    private static func storedSourceCurrent(node: String, stored: Data, model: RouterVPNModel) -> Bool {
        guard let current = IOSNodeBundleStore.shared.bundleData(containing: node, current: model.persistedNodeBundle) else { return false }
        if current == stored { return true }
        guard let actual = try? IOSNodeUsage.canonicalJSON(current),
              let expected = try? IOSNodeUsage.canonicalJSON(stored) else { return false }
        return actual == expected
    }

    func cancel() {
        generation &+= 1
        guard running else { return }
        transaction?.cancel(); task?.cancel()
        progress = "Cancelling the 50-sample test; retaining its owner until native probes drain…"
    }
}
