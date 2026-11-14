import Foundation
import Combine
@preconcurrency import NetworkExtension

@MainActor struct IOSOrderedLatencyCapture {
    let identity: IOSSessionIdentity, selection: UUID
    let source: String, config: String, profile: String
    let snapshot: Data
    let ids: [String]
    let mode: String, logicalMode: String, automatic: Bool
    static func bytes(_ model: RouterVPNModel) throws -> Data {
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
        return try encoder.encode([model.bundle] + model.iosNodeChainBundles(for: model.bundle))
    }
    init(_ model: RouterVPNModel) throws {
        guard model.connected, let identity = model.activeSessionIdentity,
              let active = identity.nodeChainSource, let path = IOSNodeChainPresentation.active(identity), path.count == 3, path[1].mode == "socks5" else { throw CancellationError() }
        let captured = try model.captureIOSOrderedRoute(model.bundle)
        defer { try? captured.close() }
        guard case .socks(let socks) = captured, Data(socks.source.utf8) == active else { throw CancellationError() }
        self.identity = identity; selection = model.iosConnectGeneration
        source = socks.plan.sourceSHA256(); config = socks.plan.configSHA256(); ids = socks.members.map(\.id)
        snapshot = try Self.bytes(model); profile = RouterVPNModel.iosStrategyDigest(snapshot)
        mode = model.selectedMode; logicalMode = model.selectedLogicalMode; automatic = model.auto
    }
    func require(_ model: RouterVPNModel) throws {
        guard model.connected, model.activeSessionIdentity == identity, model.iosConnectGeneration == selection,
              model.selectedMode == mode, model.selectedLogicalMode == logicalMode, model.auto == automatic,
              try Self.bytes(model) == snapshot else { throw CancellationError() }
    }
}

private final class IOSOrderedLatencyReply: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<Data, Error>?
    init(_ continuation: CheckedContinuation<Data, Error>) { self.continuation = continuation }
    func finish(_ data: Data?) {
        lock.lock(); let pending = continuation; continuation = nil; lock.unlock()
        guard let pending else { return }
        if let data, !data.isEmpty, data.count <= 32768 { pending.resume(returning: data) }
        else { pending.resume(throwing: CancellationError()) }
    }
}

/// Owns the original request through pre-factory cancellation, late IPC,
/// worker drain and facade close. MTU release happens only after this returns.
@MainActor final class IOSOrderedLatencyTransaction {
    typealias Send = @MainActor (String) async throws -> [String: Any]
    private let send: Send
    private let pause: @MainActor () async -> Void
    private let request: String, source: String, config: String, node: String
    private let position: Int
    private var cancelled = false
    init(request: String, source: String, config: String, node: String, position: Int,
         send: @escaping Send, pause: @escaping @MainActor () async -> Void = { try? await Task.sleep(for: .milliseconds(300)) }) {
        self.request = request; self.source = source; self.config = config; self.node = node; self.position = position; self.send = send; self.pause = pause
    }
    func cancel() { cancelled = true }
    private func require(_ current: () throws -> Void) throws {
        guard !cancelled, !Task.isCancelled else { throw CancellationError() }; try current()
    }
    private func close() async -> Bool {
        var clean = true
        // Uncancelled cleanup keeps its exact Send closure/connection and never
        // consults a newly connected manager. A missing reply is not a receipt.
        while true {
            if let response = try? await send("ordered-latency-close"), response["closed"] as? Bool == true { return clean }
            clean = false
            await pause()
        }
    }
    func run(current: () throws -> Void, update: (String) -> Void) async throws -> IOSOrderedLatencyRecord {
        var receipt: IOSOrderedLatencyRecord?
        var failure: Error?
        do {
            try require(current)
            let opened = try await send("ordered-latency-open")
            try require(current)
            guard opened["opened"] as? Bool == true, opened["closed"] as? Bool == false else { throw CancellationError() }
            var operation = "ordered-latency-start"
            let deadline = ProcessInfo.processInfo.systemUptime + 100
            while ProcessInfo.processInfo.systemUptime < deadline {
                try require(current)
                let response = try await send(operation)
                try require(current)
                guard let raw = response["status"] as? String else { throw CancellationError() }
                let status = try IOSOrderedLatencyRecord.status(raw, request: request)
                update(status["stage"] as? String ?? "measuring")
                if try IOSOrderedLatencyRecord.boolean(status, "complete") {
                    guard let saved = response["saved"] as? String else { throw CancellationError() }
                    receipt = try IOSOrderedLatencyRecord.completed(status: raw, saved: saved, source: source, config: config, node: node, position: position, request: request)
                    break
                }
                operation = "ordered-latency-status"; await pause()
            }
            guard receipt != nil else { throw CancellationError() }
        } catch { failure = error; cancelled = true }
        // SavedJSON has been copied/validated before facade close. Close may
        // cancel native state, so nothing is read from the facade afterward.
        update("Joining original benchmark cleanup…")
        let cleanup = Task { @MainActor in await self.close() }
        let cleanClose = await cleanup.value
        if let failure { throw failure }
        guard cleanClose else { throw CancellationError() }
        try require(current)
        guard let receipt else { throw CancellationError() }
        return receipt
    }
}

@MainActor final class IOSOrderedLatency: ObservableObject {
    @Published private(set) var running = false
    @Published private(set) var text = ""
    @Published private(set) var ids: [String] = []
    @Published private(set) var history: [String: String] = [:]
    private var displayed: IOSOrderedLatencyCapture?
    private var transaction: IOSOrderedLatencyTransaction?
    private var task: Task<Void, Never>?
    private var cancelled = false
    static func supported(_ model: RouterVPNModel) -> Bool {
        guard model.connected, let path = IOSNodeChainPresentation.active(model.activeSessionIdentity) else { return false }
        return path.count == 3 && path[1].mode == "socks5"
    }
    func load(_ model: RouterVPNModel) {
        guard !running else { return }
        do {
            let capture = try IOSOrderedLatencyCapture(model)
            var saved: [String: String] = [:]
            for (position, id) in capture.ids.enumerated() {
                saved[id] = try IOSOrderedLatencyHistory.load(profile: capture.profile, source: capture.source, config: capture.config, position: position, node: id)?.detail
            }
            displayed = capture; ids = capture.ids; history = saved; text = "Select one node on this captured route."
        } catch { displayed = nil; ids = []; history = [:]; text = "Connect the selected saved SOCKS route to measure its captured nodes." }
    }
    private func send(_ connection: NETunnelProviderSession, operation: String, request: String, session: String,
                      owner: String, lease: String, source: String, config: String, node: String) async throws -> [String: Any] {
        let payload = try JSONSerialization.data(withJSONObject: ["operation": operation, "request_id": request, "session_id": session,
            "owner": owner, "lease": lease, "source_sha256": source, "config_sha256": config, "node_id": node])
        guard payload.count <= 1536 else { throw CancellationError() }
        let data = try await withCheckedThrowingContinuation { continuation in
            let reply = IOSOrderedLatencyReply(continuation)
            DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + 4) { reply.finish(nil) }
            do { try connection.sendProviderMessage(payload) { reply.finish($0) } } catch { reply.finish(nil) }
        }
        guard let raw = String(data: data, encoding: .utf8) else { throw CancellationError() }
        let body = try IOSOrderedLatencyRecord.object(raw, maximum: 32768)
        guard body["request_id"] as? String == request, body["session_id"] as? String == session, body["owner"] as? String == owner else { throw CancellationError() }
        return body
    }
    func start(_ model: RouterVPNModel, position: Int) {
        guard !running, !IOSMTUMeasurementGate.held, !model.iosSpeedLabOwnership.active,
              let capture = displayed, capture.ids.indices.contains(position) else { return }
        do { try capture.require(model) } catch { text = "The captured path changed. Reopen this panel."; return }
        let request = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
        let owner = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased(), node = capture.ids[position]
        let lease = IOSMTUMeasurementGate.acquire()
        running = true; cancelled = false; text = "Waiting for the original MTU work to drain…"
        task = Task { @MainActor [self, model] in
            var binding: IOSMTUControl.Binding?
            do {
                let original = try await IOSMTUControl.capture(model); binding = original
                try capture.require(model)
                guard original.identity == capture.identity, !cancelled else { throw CancellationError() }
                // Quiesce this exact captured connection before factory entry;
                // never use the benchmark to preempt a native MTU owner.
                var operation = "mtu-hold", ready = false
                let deadline = ProcessInfo.processInfo.systemUptime + 12
                while ProcessInfo.processInfo.systemUptime < deadline {
                    guard !cancelled else { throw CancellationError() }; try capture.require(model)
                    let data = try await IOSMTUControl.message(original, model: model, operation: operation, request: lease.request)
                    let body = try JSONSerialization.jsonObject(with: data) as? [String: Any]
                    guard body?["measurement_hold"] as? Bool == true, body?["measurement_lease"] as? String == lease.request else { throw CancellationError() }
                    if body?["measurement_ready"] as? Bool == true { ready = true; break }
                    operation = "mtu-status"; try await Task.sleep(for: .milliseconds(100))
                }
                guard ready, !cancelled else { throw CancellationError() }; try capture.require(model)
                let info = try await send(original.connection, operation: "ordered-latency-info", request: request, session: "", owner: owner, lease: "", source: "", config: "", node: "")
                guard info["source_sha256"] as? String == capture.source, info["config_sha256"] as? String == capture.config,
                      info["mtu_session_id"] as? String == original.session, let session = info["provider_session"] as? String,
                      UUID(uuidString: session) != nil, let nodes = info["nodes"] as? [[String: Any]], nodes.count == 3 else { throw CancellationError() }
                for (index, item) in nodes.enumerated() {
                    guard item["position"] as? Int == index, item["node_id"] as? String == capture.ids[index], item["kind"] as? String == (index == 1 ? "public-path" : "private-node") else { throw CancellationError() }
                }
                guard !cancelled else { throw CancellationError() }; try capture.require(model)
                let owned = IOSOrderedLatencyTransaction(request: request, source: capture.source, config: capture.config, node: node, position: position,
                    send: { [self] operation in try await send(original.connection, operation: operation, request: request, session: session, owner: owner, lease: lease.request, source: capture.source, config: capture.config, node: node) })
                transaction = owned
                let record = try await owned.run(current: {
                    guard !self.cancelled, IOSMTUMeasurementGate.current == lease.request, IOSMTUControl.current(original, model: model) else { throw CancellationError() }
                    try capture.require(model)
                }, update: { self.text = $0 })
                try IOSOrderedLatencyHistory.save(record, profile: capture.profile) {
                    guard !self.cancelled, IOSMTUMeasurementGate.current == lease.request, IOSMTUControl.current(original, model: model) else { throw CancellationError() }
                    try capture.require(model)
                }
                history[node] = record.detail; text = "Saved complete historical result for node \(position + 1)."
            } catch { text = "Benchmark discarded. The previous historical result is unchanged." }
            // Release only the original connection's matching lease. Never
            // discover a replacement VPN while cleaning up this request.
            if IOSMTUMeasurementGate.release(lease), let binding {
                _ = try? await IOSMTUControl.send(binding.connection, operation: "mtu-release", request: lease.request, session: binding.session)
            }
            transaction = nil; task = nil; running = false
            if model.activeSessionIdentity != capture.identity { load(model) }
        }
    }
    func cancel() {
        guard running else { return }
        cancelled = true; transaction?.cancel()
        // Do not cancel the retained cleanup task or release its MTU lease.
        text = "Cancelling; waiting for the original benchmark to close…"
    }
}
