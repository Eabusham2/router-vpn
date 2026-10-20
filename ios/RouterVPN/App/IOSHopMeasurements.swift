import SwiftUI
@preconcurrency import NetworkExtension

// HOP_RESULT_TYPES_BEGIN
struct IOSHopMeasurementStatus: Decodable {
    let request_id: String?
    let session_id: String
    let drained: Bool
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
    let kind: String
    let label: String
    let ready: Bool
    let failure: String?
    let idle: Latency?
    let download: Transfer?
    let upload: Transfer?
    var summary: String {
        let safeLabel = !label.isEmpty && label.utf8.count <= 160 && !label.contains(where: { $0.isNewline || $0 == "\0" })
        let heading = "\(role.capitalized) • \(node_id) • \(safeLabel ? label : "unverified path")"
        guard ready, safeLabel, ["private-node", "public-path"].contains(kind),
              !node_id.isEmpty, node_id.utf8.count <= 128, ["entry", "exit"].contains(role), let idle, idle.valid,
              let download, download.valid, let upload, upload.valid else {
            return "\(heading): unavailable — \(failure ?? "unverified or incomplete result")"
        }
        let measurement = kind == "public-path" ? "HTTPS response" : "Private-node response"
        var text = String(format: "%@\n%@ %.1f ms • median %.1f • p90 %.1f • jitter %.1f\nDownload %.2f Mbps • Upload %.2f Mbps", heading, measurement, idle.average_ms, idle.median_ms, idle.p90_ms, idle.jitter_ms, download.mbps, upload.mbps)
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

// HOP_TRANSACTION_BEGIN
// This transaction owns the native request through late IPC and native drain.
// Cleanup runs in an uncancelled task; its caller retains the MTU hold until
// this function returns, including cancellation, timeout and changed tunnels.
@MainActor final class IOSHopMeasurementTransaction {
    typealias Send = @MainActor (String) async throws -> Data
    private let id: String, session: String
    private let send: Send
    private let pause: @MainActor () async -> Void
    private var cancelled = false
    private var cancellation: Task<IOSHopMeasurementStatus?, Never>?
    init(id: String, session: String, send: @escaping Send,
         pause: @escaping @MainActor () async -> Void = { try? await Task.sleep(for: .milliseconds(350)) }) throws {
        guard id.range(of: "^[0-9a-f]{32}$", options: .regularExpression) != nil,
              UUID(uuidString: session) != nil else { throw CancellationError() }
        self.id=id;self.session=session;self.send=send;self.pause=pause
    }
    private func status(_ operation: String) async throws -> IOSHopMeasurementStatus {
        let data = try await send(operation)
        guard !data.isEmpty, data.count <= 16384 else { throw CancellationError() }
        let status = try JSONDecoder().decode(IOSHopMeasurementStatus.self, from: data)
        guard status.request_id == id, status.session_id == session, status.results.count <= 2 else { throw CancellationError() }
        return status
    }
    func cancel() {
        cancelled = true
        guard cancellation == nil else { return }
        cancellation = Task { @MainActor in try? await self.status("hop-measure-cancel") }
    }
    private func drain() async {
        if let status = await cancellation?.value, status.complete && status.drained { return }
        while true {
            if let status = try? await status("hop-measure-cancel"), status.complete && status.drained { return }
            await pause()
        }
    }
    func run(current: @MainActor () async -> Bool, update: @MainActor (IOSHopMeasurementStatus) -> Void) async throws {
        do {
            var operation = "hop-measure-start"
            let deadline = ProcessInfo.processInfo.systemUptime + 100
            while !cancelled && !Task.isCancelled && ProcessInfo.processInfo.systemUptime < deadline {
                guard await current(), !cancelled, !Task.isCancelled else { throw CancellationError() }
                let result = try await status(operation)
                guard await current(), !cancelled, !Task.isCancelled else { throw CancellationError() }
                update(result)
                if result.complete && result.drained { return }
                operation = "hop-measure-status"
                await pause()
            }
            throw CancellationError()
        } catch {
            cancel()
            let cleanup = Task { @MainActor in await self.drain() }
            await cleanup.value
            throw error
        }
    }
}
// HOP_TRANSACTION_END

@MainActor final class IOSHopMeasurements: ObservableObject {
    @Published private(set) var running = false
    @Published private(set) var text = ""
    private var task: Task<Void, Never>?
    private var transaction: IOSHopMeasurementTransaction?
    private var generation = UUID()

    static func supported(_ model: RouterVPNModel) -> Bool {
        model.connected && ["multihop-libbox", "external-libbox"].contains(model.activeEngine)
    }
    func start(model: RouterVPNModel) {
        guard !running, Self.supported(model) else { return }
        let round = UUID(); generation = round
        let id = round.uuidString.replacingOccurrences(of: "-", with: "").lowercased()
        let captured = model.activeSessionIdentity
        guard captured != nil else { text = "Current tunnel identity is unverified."; return }
        running = true; text = "Proving and measuring the captured routed paths…"
        task = Task { @MainActor [weak self, weak model] in
            guard let self, let model else { return }
            defer { if self.generation == round { self.running = false; self.task = nil; self.transaction = nil } }
            do {
                try await IOSMTUControl.withHold(model: model) {
                    let binding = try await IOSMTUControl.capture(model)
                    guard binding.identity == captured else { throw CancellationError() }
                    let connection = binding.connection, date = binding.connectedDate
                    let owned = try IOSHopMeasurementTransaction(id: id, session: binding.session,
                        send: { operation in try await self.send(connection, operation: operation, id: id, session: binding.session) })
                    self.transaction = owned
                    try await owned.run(current: {
                        await model.refreshTunnelStatus()
                        return self.generation == round && model.connected && model.activeSessionIdentity == captured &&
                            connection.status == .connected && connection.connectedDate == date
                    }, update: { status in
                        self.text = (["Routed paths: \(status.stage)"] + status.results.map(\.summary) + (status.failure.map { [$0] } ?? [])).joined(separator: "\n\n")
                    })
                }
            } catch {
                if self.generation == round { self.text = "Measurement discarded: the request failed, timed out, or its tunnel changed." }
            }
        }
    }
    private func send(_ connection: NETunnelProviderSession, operation: String, id: String, session: String) async throws -> Data {
        let request = try JSONSerialization.data(withJSONObject: ["operation": operation, "request_id": id, "session_id": session])
        guard request.count <= 256 else { throw CancellationError() }
        return try await withCheckedThrowingContinuation { continuation in
            let reply = IOSHopReply(continuation)
            DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + 3) { reply.finish(nil) }
            do { try connection.sendProviderMessage(request) { reply.finish($0) } } catch { reply.finish(nil) }
        }
    }
    func cancel() {
        guard running else { return }
        transaction?.cancel(); task?.cancel()
        // Keep the owner, task and MTU hold alive until the exact native request
        // reports drained. A second test cannot overlap its cancelled workers.
        text = "Cancelling measurement; waiting for the captured probes to drain…"
    }
}

struct IOSHopMeasurementsCard: View {
    @EnvironmentObject private var model: RouterVPNModel
    @ObservedObject var probe: IOSHopMeasurements
    let otherTestRunning: Bool
    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Label("Routed hop measurements", systemImage: "point.3.connected.trianglepath.dotted").font(.headline)
            Text("Measures each captured cumulative route with actual transferred bytes. Router VPN hops use their private node API; external and Tor paths use the labelled Cloudflare HTTPS endpoint. These response times include the named path, and do not infer a server-to-server link speed. Up to 32 MiB is transferred while MTU adaptation is held.")
                .font(.caption).foregroundStyle(.secondary)
            Button(probe.running ? "Cancel hop measurements" : "Measure routed paths") {
                if probe.running { probe.cancel() } else { probe.start(model: model) }
            }.disabled(otherTestRunning || (!probe.running && !IOSHopMeasurements.supported(model)))
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
