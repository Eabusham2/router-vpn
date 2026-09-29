import SwiftUI
@preconcurrency import NetworkExtension

// HOP_RESULT_TYPES_BEGIN
struct IOSHopMeasurementStatus: Decodable {
    let request_id: String?
    let stage: String
    let complete: Bool
    let failure: String?
    let results: [IOSHopMeasurementResult]
}
struct IOSHopMeasurementResult: Decodable {
    struct Latency: Decodable {
        let samples: Int
        let min_ms: Double
        let median_ms: Double
        let average_ms: Double
        let p90_ms: Double
        let max_ms: Double
        let jitter_ms: Double
        var valid: Bool {
            guard (1...24).contains(samples) else { return false }
            let values: [Double] = [min_ms, median_ms, average_ms, p90_ms, max_ms, jitter_ms]
            return values.allSatisfy { $0.isFinite && $0 >= 0 }
        }
    }
    struct Transfer: Decodable {
        let bytes: Int64
        let seconds: Double
        let mbps: Double
        let loaded: Latency?
        let loaded_reason: String?
        let bufferbloat_ms: Double?
        var valid: Bool {
            guard (Int64(65536)...Int64(8388608)).contains(bytes), seconds.isFinite,
                  seconds > 0, mbps.isFinite, mbps > 0 else { return false }
            let calculated: Double = Double(bytes) * 8.0 / seconds / 1_000_000.0
            let tolerance: Double = max(0.000001, mbps * 0.000001)
            return abs(calculated - mbps) <= tolerance
        }
    }
    let node_id: String
    let role: String
    let ready: Bool
    let failure: String?
    let idle: Latency?
    let download: Transfer?
    let upload: Transfer?
    var summary: String {
        let label = "\(role.capitalized) • \(node_id)"
        guard ready, ["entry", "exit"].contains(role), let idle, idle.valid,
              let download, download.valid, let upload, upload.valid else {
            return "\(label): unavailable — \(failure ?? "unverified or incomplete result")"
        }
        var text = String(format: "%@\nIdle %.1f ms • median %.1f • p90 %.1f • jitter %.1f\nDownload %.2f Mbps • Upload %.2f Mbps", label, idle.average_ms, idle.median_ms, idle.p90_ms, idle.jitter_ms, download.mbps, upload.mbps)
        for (name, transfer) in [("Download", download), ("Upload", upload)] {
            if let loaded = transfer.loaded, loaded.valid, let delta = transfer.bufferbloat_ms, delta.isFinite {
                text += String(format: "\n%@ loaded %.1f ms • Δ %.1f ms (%d samples)", name, loaded.average_ms, delta, loaded.samples)
            } else { text += "\n\(name) loaded latency: unavailable — \(transfer.loaded_reason ?? "no complete sample")" }
        }
        return text
    }
}
// HOP_RESULT_TYPES_END

// A late reply or timeout resolves a continuation once, without capturing a
// SwiftUI object or a non-Sendable manager on Dispatch's background queue.
private final class IOSHopReply: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<Data, Error>?
    init(_ continuation: CheckedContinuation<Data, Error>) { self.continuation = continuation }
    func finish(_ data: Data?) {
        lock.lock(); let pending = continuation; continuation = nil; lock.unlock()
        guard let pending else { return }
        guard let data, data.count <= 16384 else {
            pending.resume(throwing: NSError(domain: "RouterVPN.HopMeasurement", code: 1, userInfo: [NSLocalizedDescriptionKey: "The owned VPN extension did not return a bounded measurement reply."]))
            return
        }
        pending.resume(returning: data)
    }
}

@MainActor final class IOSHopMeasurements: ObservableObject {
    @Published private(set) var running = false
    @Published private(set) var text = ""
    private var task: Task<Void, Never>?
    private var session: NETunnelProviderSession?
    private var requestID = ""
    private var generation = UUID()

    func start(model: RouterVPNModel) {
        guard !running,
              model.connected, model.activeEngine == "multihop-libbox" else { return }
        let round = UUID(); generation = round; requestID = round.uuidString.replacingOccurrences(of: "-", with: "").lowercased()
        let id = requestID, captured = model.activeSessionIdentity
        guard captured != nil else { text = "Current tunnel identity is unverified."; return }
        running = true; text = "Proving and measuring the entry and exit paths…"
        task = Task { @MainActor [weak self, weak model] in
            guard let self, let model else { return }
            defer { if self.generation == round { self.running = false; self.task = nil } }
            do {
                let managers = try await NETunnelProviderManager.loadAllFromPreferences()
                let owned = managers.filter { ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == "com.eabusham.routervpn.PacketTunnel" }
                guard owned.count == 1, let connection = owned[0].connection as? NETunnelProviderSession,
                      connection.status == .connected, let date = connection.connectedDate else { throw CancellationError() }
                self.session = connection
                let deadline = Date().addingTimeInterval(100)
                var operation = "hop-measure-start"
                while !Task.isCancelled, self.generation == round, Date() < deadline {
                    await model.refreshTunnelStatus()
                    guard model.connected, model.activeSessionIdentity == captured,
                          connection.status == .connected, connection.connectedDate == date else { throw CancellationError() }
                    let data = try await self.send(connection, operation: operation, id: id)
                    try Task.checkCancellation()
                    guard self.generation == round, model.activeSessionIdentity == captured,
                          connection.status == .connected, connection.connectedDate == date else { throw CancellationError() }
                    let status = try JSONDecoder().decode(IOSHopMeasurementStatus.self, from: data)
                    guard status.request_id == id, status.results.count <= 2 else { throw CancellationError() }
                    self.text = (["Routed hops: \(status.stage)"] + status.results.map(\.summary) + (status.failure.map { [$0] } ?? [])).joined(separator: "\n\n")
                    if status.complete { return }
                    operation = "hop-measure-status"
                    try await Task.sleep(for: .milliseconds(350))
                }
                throw CancellationError()
            } catch {
                if self.generation == round { self.cancelRequest(); self.text = "Measurement discarded: the request failed, timed out, or its tunnel changed." }
            }
        }
    }
    private func send(_ session: NETunnelProviderSession, operation: String, id: String) async throws -> Data {
        let request = try JSONSerialization.data(withJSONObject: ["operation": operation, "request_id": id])
        return try await withCheckedThrowingContinuation { continuation in
            let reply = IOSHopReply(continuation)
            DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + 3) { reply.finish(nil) }
            do { try session.sendProviderMessage(request) { reply.finish($0) } } catch { reply.finish(nil) }
        }
    }
    private func cancelRequest() {
        guard let session, !requestID.isEmpty,
              let data = try? JSONSerialization.data(withJSONObject: ["operation": "hop-measure-cancel", "request_id": requestID]) else { return }
        try? session.sendProviderMessage(data) { _ in }
    }
    func cancel() {
        cancelRequest(); generation = UUID(); task?.cancel(); task = nil; session = nil
        running = false; text = ""
    }
}

struct IOSHopMeasurementsCard: View {
    @EnvironmentObject private var model: RouterVPNModel
    @ObservedObject var probe: IOSHopMeasurements
    let otherTestRunning: Bool
    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Label("Routed hop measurements", systemImage: "point.3.connected.trianglepath.dotted").font(.headline)
            Text("Measures this device → entry and this device → entry → exit independently, using private node endpoints. These are cumulative path rates, not an inferred link speed between servers. The test transfers up to 32 MiB total and does not change your tunnel or saved profile.")
                .font(.caption).foregroundStyle(.secondary)
            Button(probe.running ? "Cancel hop measurements" : "Measure entry and exit") {
                if probe.running { probe.cancel() } else { probe.start(model: model) }
            }.disabled(otherTestRunning || (!probe.running && (!model.connected || model.activeEngine != "multihop-libbox")))
            if !probe.text.isEmpty { Text(probe.text).font(.caption.monospacedDigit()).textSelection(.enabled) }
        }
        .padding(16).background(.background, in: RoundedRectangle(cornerRadius: 18))
        .onChange(of: model.connected) { _ in probe.cancel() }
        .onChange(of: model.activeSessionIdentity) { _ in probe.cancel() }
        .onChange(of: model.multihopProgressText) { _ in if !model.connected { probe.cancel() } }
        .onChange(of: otherTestRunning) { active in if active { probe.cancel() } }
        .task {
            while !Task.isCancelled {
                await model.refreshTunnelStatus()
                try? await Task.sleep(for: .seconds(1))
            }
        }
        .onDisappear { probe.cancel() }
    }
}
