import Combine
import Foundation
@preconcurrency import NetworkExtension

struct IOSSpeedResult: Hashable, Sendable {
    let downloadMbps: Double
    let uploadMbps: Double
    let bytes: Int
    let downloadMs: Double
    let uploadMs: Double
    let serverReceiveMs: Double?
    let measuredAt: Date

    var detail: String {
        var value = String(format: "Download %.1f Mbps • Upload %.1f Mbps\n%d MiB each way • %.0f ms down • %.0f ms up", downloadMbps, uploadMbps, bytes / (1 << 20), downloadMs, uploadMs)
        if let serverReceiveMs { value += String(format: " • server received upload in %.0f ms", serverReceiveMs) }
        return value + "\nMeasured through the captured PacketTunnel to its independently proved Router VPN node."
    }
}

private final class IOSNativeTelemetryReply: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<Data, Error>?
    init(_ value: CheckedContinuation<Data, Error>) { continuation = value }
    func finish(_ data: Data?) {
        lock.lock(); let pending = continuation; continuation = nil; lock.unlock()
        guard let pending else { return }
        guard let data, !data.isEmpty, data.count <= 8192 else {
            pending.resume(throwing: IOSTelemetryProtocol.issue("The captured VPN extension did not return its measurement acknowledgement.")); return
        }
        pending.resume(returning: data)
    }
}

@MainActor final class IOSUnifiedTelemetry: ObservableObject {
    // A dismissed/reopened sheet shares the outstanding native cleanup owner.
    static let shared = IOSUnifiedTelemetry()
    @Published private(set) var latencyByID: [String: Double] = [:]
    @Published private(set) var livePathMs: Double?
    @Published private(set) var isTestingFastest = false
    @Published private(set) var isSpeedTesting = false
    @Published private(set) var measuring = false
    @Published private(set) var cleanupPending = false
    @Published private(set) var progress = ""
    @Published private(set) var lastSpeedResult: IOSSpeedResult?
    @Published private(set) var lastError = ""
    private var cancelWork: (() -> Void)?
    private var transaction: IOSNativeTelemetryTransaction?
    private var directReceipt: IOSDirectTelemetryCapture?
    private var liveReceipt: IOSCurrentTelemetryCapture?
    private var speedReceipt: IOSCurrentTelemetryCapture?
    private var cancellationGeneration: UInt64 = 0
    private var performanceVisible = false
    private var backgroundRefresh = false
    private static let probePorts: [UInt16] = [443, 8388, 10443, 11443, 12443, 13443, 14443, 15443]

    func cached(_ id: String) -> Double? { latencyByID[id] }

    func showPerformance(_ visible: Bool) {
        performanceVisible = visible
        if !visible || backgroundRefresh { cancel() }
    }

    func cancel() {
        cancellationGeneration &+= 1
        if measuring { progress = "Cancelling measurement and waiting for native cleanup…" }
        transaction?.cancel(); cancelWork?()
    }

    func invalidateResults(model: RouterVPNModel) {
        if let capture = directReceipt, (try? capture.requireCurrent(model)) == nil {
            latencyByID = [:]; directReceipt = nil
        }
        if let capture = liveReceipt, (try? capture.requireCurrent(model)) == nil { livePathMs = nil; liveReceipt = nil }
        if let capture = speedReceipt, (try? capture.requireCurrent(model)) == nil { lastSpeedResult = nil; speedReceipt = nil }
        if !model.connected { livePathMs = nil; liveReceipt = nil; lastSpeedResult = nil; speedReceipt = nil }
    }

    func requireDirectResultCurrent(model: RouterVPNModel) throws {
        guard let capture = directReceipt else { throw CancellationError() }
        try capture.requireCurrent(model)
    }

    func measureAll(_ profiles: [RouterProfile], model: RouterVPNModel, samples: Int = 3) async -> [IOSLatencyResult] {
        do { return try await direct(profiles, model: model, samples: min(max(samples, 1), 10), durable: false) }
        catch { lastError = error.localizedDescription; return [] }
    }

    func measureOne(_ profile: RouterProfile, model: RouterVPNModel, samples: Int = 50) async throws -> IOSLatencyResult {
        guard samples == 50 else { throw IOSLatencyResult.issue("The durable node benchmark requires 50 samples.") }
        guard let value = try await direct([profile], model: model, samples: samples, durable: true).first else { throw URLError(.timedOut) }
        return value
    }

    private func direct(_ profiles: [RouterProfile], model: RouterVPNModel, samples: Int, durable: Bool) async throws -> [IOSLatencyResult] {
        try Task.checkCancellation()
        guard !measuring, !profiles.isEmpty, !IOSMTUMeasurementGate.held else {
            throw IOSTelemetryProtocol.issue("Wait for the active measurement and its native cleanup before measuring nodes.")
        }
        var capture = try IOSDirectTelemetryCapture(model: model, profiles: profiles)
        let generation = cancellationGeneration
        measuring = true; isTestingFastest = true; cleanupPending = false; lastError = ""; directReceipt = nil
        progress = durable ? "Collecting 50 direct TCP samples…" : "Measuring direct node responses…"
        defer { measuring = false; isTestingFastest = false; cleanupPending = false; cancelWork = nil }
        let worker = Task { @MainActor [self] in
            capture.network = try await IOSViaEntryNetwork.shared.snapshot()
            try Task.checkCancellation()
            guard generation == cancellationGeneration else { throw CancellationError() }
            await model.refreshTunnelStatus(); try capture.requireCurrent(model)
            let owner = try model.iosSpeedLabOwnership.begin { self.cancel() }
            defer { model.iosSpeedLabOwnership.finish(owner) }
            let probes = Task { @MainActor in
                var results: [IOSLatencyResult] = []
                for profile in profiles {
                    try Task.checkCancellation(); try capture.requireCurrent(model); try model.iosSpeedLabOwnership.require(owner)
                    do {
                        guard let network = capture.network else { throw CancellationError() }
                        let value = try await Self.measure(profile: profile, samples: samples, network: network) {
                            try capture.requireCurrent(model); try model.iosSpeedLabOwnership.require(owner)
                        }
                        results.append(value)
                    } catch is CancellationError { throw CancellationError() }
                    catch { if durable { throw error }; self.latencyByID.removeValue(forKey: profile.id) }
                }
                return results.sorted { $0.medianMs < $1.medianMs }
            }
            let watcher = Task { @MainActor in
                while !Task.isCancelled {
                    await model.refreshTunnelStatus()
                    if (try? capture.requireCurrent(model)) == nil || !model.iosSpeedLabOwnership.current(owner) { probes.cancel(); return }
                    do { try await Task.sleep(for: .milliseconds(150)) } catch { return }
                }
            }
            let values: [IOSLatencyResult]
            do {
                values = try await withTaskCancellationHandler { try await probes.value } onCancel: { probes.cancel() }
                watcher.cancel(); await watcher.value
            } catch {
                probes.cancel(); watcher.cancel(); _ = await probes.result; await watcher.value
                throw error
            }
            try Task.checkCancellation(); try capture.requireCurrent(model); try model.iosSpeedLabOwnership.require(owner)
            guard !values.isEmpty else { throw IOSLatencyResult.issue("No node returned a valid direct TCP response.") }
            if durable {
                guard values.count == 1, let value = values.first, let expected = capture.records[value.id] else { throw CancellationError() }
                try model.commitNodeLatency(value, expectedRecord: expected, expectedSelection: capture.selection, owner: owner)
                latencyByID.removeValue(forKey: value.id)
            } else {
                directReceipt = capture
                latencyByID = Dictionary(uniqueKeysWithValues: values.map { ($0.id, $0.medianMs) })
            }
            return values
        }
        cancelWork = { worker.cancel() }
        do {
            let result = try await withTaskCancellationHandler { try await worker.value } onCancel: { worker.cancel() }
            try Task.checkCancellation()
            progress = durable ? "All 50 samples and their statistics were saved to the measured node." : "Direct node measurement complete."
            return result
        } catch {
            lastError = error.localizedDescription
            progress = durable ? "Measurement ended; the previous saved statistics were kept." : "Direct measurement ended."
            throw error
        }
    }

    private static func measure(profile: RouterProfile, samples: Int, network: UInt64, current: () throws -> Void) async throws -> IOSLatencyResult {
        let host = IOSViaEntryTCP.endpointHost(profile.endpoint)
        guard !host.isEmpty else { throw URLError(.badURL) }
        var ports: [UInt16] = []
        if let parts = URLComponents(string: profile.endpoint.contains("://") ? profile.endpoint : "tcp://" + profile.endpoint),
           let port = parts.port, (1...65535).contains(port) { ports.append(UInt16(port)) }
        ports += probePorts
        var tried = Set<UInt16>(), selected: UInt16?
        for port in ports where tried.insert(port).inserted {
            try Task.checkCancellation(); try current()
            do { _ = try await IOSViaEntryTCP.probeDirect(host: host, port: port, timeoutMS: 500, network: network); selected = port; break }
            catch is CancellationError { throw CancellationError() }
            catch { }
        }
        guard let selected else { throw URLError(.cannotConnectToHost) }
        var values: [Double] = [], failed = 0
        for _ in 0..<samples {
            try Task.checkCancellation(); try current()
            do { values.append(try await IOSViaEntryTCP.probeDirect(host: host, port: selected, timeoutMS: 950, network: network)) }
            catch is CancellationError { throw CancellationError() }
            catch { failed += 1 }
            try Task.checkCancellation(); try current()
            try await Task.sleep(for: .milliseconds(25))
        }
        return try IOSLatencyResult.summarize(id: profile.id, name: profile.name.isEmpty ? profile.id : profile.name, values: values, failed: failed)
    }

    /// Periodic refresh never connects, changes selection, or pauses Auto MTU.
    /// It skips active experiments and holds only the read-only path owner.
    func refreshLivePath(model: RouterVPNModel) async {
        invalidateResults(model: model)
        guard !performanceVisible, model.connected, !model.tunnelTransitioning, model.unifiedSelectedProfile?.normalizedNodeKind == "router-vpn",
              !measuring, !model.iosSpeedLabOwnership.active, !IOSMTUMeasurementGate.held else { return }
        backgroundRefresh = true
        defer { backgroundRefresh = false }
        do { _ = try await measureCurrentRTT(model: model) }
        catch { livePathMs = nil; liveReceipt = nil }
    }

    func measureCurrentRTT(model: RouterVPNModel) async throws -> Double {
        let (result, capture) = try await native(model: model, kind: "rtt")
        try capture.requireCurrent(model)
        let value = IOSLatencyResult.percentile(result.response_ms.sorted(), 0.5)
        livePathMs = value; liveReceipt = capture
        return value
    }

    func speedTest(model: RouterVPNModel) async throws -> IOSSpeedResult {
        // The extension owns /api/benchmark/download and /api/benchmark/upload.
        // Authorization is emitted there only after an independent node proof.
        let (value, capture) = try await native(model: model, kind: "speed")
        try capture.requireCurrent(model)
        guard let download = value.download_seconds, let upload = value.upload_seconds else { throw URLError(.badServerResponse) }
        let mbits = Double(IOSTelemetryProtocol.bytes * 8) / 1_000_000
        let result = IOSSpeedResult(downloadMbps: mbits / download, uploadMbps: mbits / upload,
            bytes: IOSTelemetryProtocol.bytes, downloadMs: download * 1000, uploadMs: upload * 1000,
            serverReceiveMs: value.server_receive_ms, measuredAt: Date())
        lastSpeedResult = result; speedReceipt = capture
        return result
    }

    private func native(model: RouterVPNModel, kind: String) async throws -> (IOSTelemetryProtocol.Result, IOSCurrentTelemetryCapture) {
        try Task.checkCancellation()
        guard !measuring, !model.iosSpeedLabOwnership.active, !IOSMTUMeasurementGate.held else {
            throw IOSTelemetryProtocol.issue("Wait for the active measurement and its native cleanup.")
        }
        var initial = try IOSDNSMeasurementCapture(model: model)
        let generation = cancellationGeneration
        measuring = true; isSpeedTesting = kind == "speed"; cleanupPending = false; lastError = ""
        progress = kind == "speed" ? "Proving the selected node before the 8 MiB down/up transfer…" : "Measuring the proved current path…"
        defer { measuring = false; isSpeedTesting = false; cleanupPending = false; cancelWork = nil; transaction = nil }
        let worker = Task { @MainActor [self] in
            let network = try await IOSViaEntryNetwork.shared.snapshot()
            try Task.checkCancellation()
            guard generation == cancellationGeneration else { throw CancellationError() }
            await model.refreshTunnelStatus(); initial.network = network; try initial.requireCurrent(model: model)
            let capture = try IOSCurrentTelemetryCapture(model: model, network: network)
            let owner = try model.iosSpeedLabOwnership.begin { self.cancel() }
            defer { model.iosSpeedLabOwnership.finish(owner) }
            return try await IOSSpeedLabContext.$owner.withValue(owner) {
                let operation: @MainActor () async throws -> IOSTelemetryProtocol.Result = {
                    try model.iosSpeedLabOwnership.require(owner); try capture.requireCurrent(model)
                    try IOSDNSRetirementReceipts.shared.requireAvailable()
                    let connection = try await capture.connection(model)
                    let request = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
                    let data = try await Self.send(connection, operation: "telemetry-info", request: request, node: capture.source.nodeID)
                    let binding = try IOSTelemetryProtocol.Status.info(data, request: request, node: capture.source.nodeID).binding
                    // Install cleanup before checking cancellation: Info reserved
                    // this nonce even when a cancelled task never sends Start.
                    let owned = IOSNativeTelemetryTransaction(binding: binding, kind: kind, send: { operation in
                        try await Self.send(connection, operation: operation, request: request, node: capture.source.nodeID,
                            binding: binding, kind: operation == "telemetry-start" ? kind : "")
                    }, recovered: { IOSTelemetryProtocol.cleanupReceipt(binding) }, pending: {
                        self.cleanupPending = true
                        self.progress = "Native cleanup is pending. Keep the app available; it will retry the exact acknowledgement."
                    })
                    self.transaction = owned
                    if Task.isCancelled || generation != self.cancellationGeneration { owned.cancel() }
                    return try await owned.run {
                        await model.refreshTunnelStatus()
                        return model.iosSpeedLabOwnership.current(owner) && capture.current(model, connection: connection)
                    }
                }
                let result: IOSTelemetryProtocol.Result
                if kind == "speed" { result = try await IOSMTUControl.withHold(model: model, operation: operation) }
                else { result = try await operation() }
                try Task.checkCancellation(); try model.iosSpeedLabOwnership.require(owner); try capture.requireCurrent(model)
                return (result, capture)
            }
        }
        cancelWork = { worker.cancel() }
        do {
            let result = try await withTaskCancellationHandler { try await worker.value } onCancel: { worker.cancel() }
            try Task.checkCancellation(); progress = "Current-path measurement complete."
            return result
        } catch {
            lastError = error.localizedDescription; progress = "Measurement ended and native cleanup finished; no stale result was adopted."
            throw error
        }
    }

    private static func send(_ connection: NETunnelProviderSession, operation: String, request: String,
                             node: String, binding: IOSTelemetryProtocol.Binding? = nil, kind: String = "") async throws -> Data {
        let data = try JSONSerialization.data(withJSONObject: ["operation": operation, "request_id": request,
            "session_id": binding?.providerSession ?? "", "native_session_id": binding?.nativeSession ?? "", "node_id": node, "kind": kind])
        return try await withCheckedThrowingContinuation { continuation in
            let once = IOSNativeTelemetryReply(continuation)
            do { try connection.sendProviderMessage(data) { once.finish($0) } }
            catch { once.finish(nil) }
            DispatchQueue.global().asyncAfter(deadline: .now() + 3) { once.finish(nil) }
        }
    }
}
