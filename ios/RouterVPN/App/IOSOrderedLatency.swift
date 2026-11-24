import Foundation
import Combine
@preconcurrency import NetworkExtension

@MainActor struct IOSOrderedLatencyCapture {
    let identity: IOSSessionIdentity, selection: UUID
    let source: String, config: String, profile: String
    let snapshot: Data
    let ids: [String], kinds: [String]
    let extended: IOSOrderedLatencyExtendedLocal?
    let requestedExecution: String?
    let validateMultipleImported: (([String]) throws -> Void)?
    let mode: String, logicalMode: String, automatic: Bool
    static func bytes(_ model: RouterVPNModel) throws -> Data {
        guard let bundle = model.bundle else { throw CancellationError() }
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
        return try encoder.encode([bundle] + model.iosNodeChainBundles(for: bundle))
    }
    init(_ model: RouterVPNModel) throws {
        guard model.connected, let bundle = model.bundle, let identity = model.activeSessionIdentity,
              let active = identity.nodeChainSource ?? identity.nodeChainExecutionSource, let path = IOSNodeChainPresentation.active(identity), ((2...8).contains(path.count) || path.count > 8 && path.count == identity.hopMeasurementRows) else { throw CancellationError() }
        let captured = try model.captureIOSOrderedRoute(bundle)
        defer { try? captured.close() }
        var extendedCount = 0, pairedPrefixNodes = 0
        var requested: String?, validate: (([String]) throws -> Void)?
        switch captured {
        case .execution(let original):
            guard path.count == original.members.count, identity.nodeChainSource == nil,
                  Data(original.ordinaryLaunchInput.utf8) == active else { throw CancellationError() }
            source = original.sourceSHA256; config = original.configSHA256; ids = original.members.map(\.id)
            requested = original.requested
            if path.count > 8 { extendedCount = original.extendedOriginalNodeCount }
            validate = original.multipleImportedBenchmarkValidator
        case .socks(let original):
            guard path.count >= 3, path[path.count - 2].mode == "socks5", Data(original.source.utf8) == active else { throw CancellationError() }
            source = original.plan.sourceSHA256(); config = original.plan.configSHA256(); ids = original.members.map(\.id)
        case .connect(let original):
            guard path.count >= 3, ["http-connect", "https-connect"].contains(path[path.count - 2].mode), Data(original.source.utf8) == active else { throw CancellationError() }
            source = original.plan.sourceSHA256(); config = original.plan.configSHA256(); ids = original.members.map(\.id)
        case .ordinary(let original):
            guard original.members.count == path.count, original.selectionExecution == "local", Data(original.launchInput.utf8) == active else { throw CancellationError() }
            source = original.sourceSHA256; config = original.configSHA256; ids = original.members.map(\.id)
            if path.count > 8 {
                extendedCount = Int(original.plan.extendedLocalNodeCount())
                pairedPrefixNodes = Int(original.plan.extendedMixedLocalPacketCount())
            }
        }
        requestedExecution = requested; validateMultipleImported = validate
        kinds = captured.members.map { $0.profile["node_kind"] as? String == "external" ? "public-path" : "private-node" }
        if path.count > 8 {
            guard path.map(\.id) == ids else { throw CancellationError() }
            extended = try IOSOrderedLatencyExtendedLocal(source: source, config: config, ids: ids, kinds: kinds, provedCount: extendedCount, pairedPrefixNodes: pairedPrefixNodes)
        } else { extended = nil }
        self.identity = identity; selection = model.iosConnectGeneration
        snapshot = try Self.bytes(model); profile = RouterVPNModel.iosStrategyDigest(snapshot)
        mode = model.selectedMode; logicalMode = model.selectedLogicalMode; automatic = model.auto
    }
    func verifyExecution(_ execution: IOSOrderedLatencyExecution) throws {
        try verifyExecutions([execution])
    }
    func verifyHistory(_ records: [IOSOrderedLatencyRecord]) throws {
        try verifyExecutions(records.map { item in
            guard let execution = item.execution else { throw CancellationError() }
            return execution
        })
    }
    private func verifyExecutions(_ captures: [IOSOrderedLatencyExecution]) throws {
        guard !captures.isEmpty else { return }
        guard let validate = validateMultipleImported else {
            guard captures.allSatisfy({ $0.originalSource == nil }) else { throw CancellationError() }
            return
        }
        guard captures.allSatisfy({ $0.originalSource != nil }) else { throw CancellationError() }
        try validate(Array(Set(captures.map { $0.binding.capture })))
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
    private let maximumBytes: Int
    init(_ continuation: CheckedContinuation<Data, Error>, maximumBytes: Int) { self.continuation = continuation; self.maximumBytes = maximumBytes }
    func finish(_ data: Data?) {
        lock.lock(); let pending = continuation; continuation = nil; lock.unlock()
        guard let pending else { return }
        if let data, !data.isEmpty, data.count <= maximumBytes { pending.resume(returning: data) }
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
    private let requested: String?, ids: [String], kinds: [String]
    private let extended: IOSOrderedLatencyExtendedLocal?
    private let validateExecution: (IOSOrderedLatencyExecution) throws -> Void
    private var closedCapture: String?
    private var cancelled = false
    init(request: String, source: String, config: String, node: String, position: Int,
         requested: String? = nil, ids: [String] = [], kinds: [String] = [], extended: IOSOrderedLatencyExtendedLocal? = nil,
         validateExecution: @escaping (IOSOrderedLatencyExecution) throws -> Void = { if $0.originalSource != nil { throw CancellationError() } },
         send: @escaping Send, pause: @escaping @MainActor () async -> Void = { try? await Task.sleep(for: .milliseconds(300)) }) {
        self.request = request; self.source = source; self.config = config; self.node = node; self.position = position; self.send = send; self.pause = pause
        self.extended = extended; self.requested = requested; self.ids = ids; self.kinds = kinds; self.validateExecution = validateExecution
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
            if let response = try? await send("ordered-latency-close"), response["closed"] as? Bool == true {
                closedCapture = response["execution_capture"] as? String
                return clean
            }
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
            var execution: IOSOrderedLatencyExecution?
            if let requested {
                guard let raw = opened["execution_capture"] as? String else { throw CancellationError() }
                let captured = try IOSOrderedLatencyExecution(.init(preparation_source_sha256: source, preparation_config_sha256: config,
                                                                   requested_execution: requested, capture: raw), extended: extended)
                guard captured.ids == ids, captured.kinds == kinds, ids.indices.contains(position), ids[position] == node else { throw CancellationError() }
                try validateExecution(captured)
                execution = captured
            } else if opened["execution_capture"] != nil { throw CancellationError() }
            var operation = "ordered-latency-start"
            let deadline = ProcessInfo.processInfo.systemUptime + 100
            while ProcessInfo.processInfo.systemUptime < deadline {
                try require(current)
                let response = try await send(operation)
                try require(current)
                guard ProcessInfo.processInfo.systemUptime < deadline, let raw = response["status"] as? String else { throw CancellationError() }
                let status = try IOSOrderedLatencyRecord.status(raw, request: request)
                update(status["stage"] as? String ?? "measuring")
                if try IOSOrderedLatencyRecord.boolean(status, "complete") {
                    guard let saved = response["saved"] as? String else { throw CancellationError() }
                    receipt = try IOSOrderedLatencyRecord.completed(status: raw, saved: saved, source: execution?.source ?? source,
                        config: execution?.config ?? config, node: node, position: position, request: request, execution: execution, extended: execution == nil ? extended : nil)
                    break
                }
                operation = "ordered-latency-status"; await pause()
            }
            guard receipt != nil else { throw CancellationError() }
        } catch { failure = error; cancelled = true }
        // The completed receipt was copied before Close. The selected facade
        // additionally proves its exact captured generation after joining.
        update("Joining original benchmark cleanup…")
        let cleanup = Task { @MainActor in await self.close() }
        let cleanClose = await cleanup.value
        if let failure { throw failure }
        guard cleanClose else { throw CancellationError() }
        try require(current)
        guard let receipt else { throw CancellationError() }
        if let proof = receipt.execution?.binding.capture {
            guard let closedCapture, proof.utf8.elementsEqual(closedCapture.utf8) else { throw CancellationError() }
        } else if closedCapture != nil { throw CancellationError() }
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
        guard model.connected, (model.activeSessionIdentity?.nodeChainSource != nil || model.activeSessionIdentity?.nodeChainExecutionSource != nil), let path = IOSNodeChainPresentation.active(model.activeSessionIdentity) else { return false }
        return (2...8).contains(path.count) || path.count > 8 && path.count == model.activeSessionIdentity?.hopMeasurementRows
    }
    func load(_ model: RouterVPNModel) {
        guard !running else { return }
        do {
            let capture = try IOSOrderedLatencyCapture(model)
            var saved: [String: String] = [:]
            if let requested = capture.requestedExecution {
                let records = try IOSOrderedLatencyHistory.selected(profile: capture.profile, source: capture.source, config: capture.config,
                    requested: requested, ids: capture.ids, kinds: capture.kinds, extended: capture.extended)
                try capture.verifyHistory(records)
                saved = Dictionary(grouping: records, by: \.node).mapValues { $0.map(\.detail).joined(separator: "\n\n") }
            } else {
                let records = try IOSOrderedLatencyHistory.local(profile: capture.profile, source: capture.source, config: capture.config,
                    ids: capture.ids, kinds: capture.kinds, extended: capture.extended)
                for record in records { saved[record.node] = record.detail }
            }
            displayed = capture; ids = capture.ids; history = saved; text = "Select one node on this captured route."
        } catch { displayed = nil; ids = []; history = [:]; text = "Connect the selected saved ordered route to measure its captured nodes." }
    }
    private func send(_ connection: NETunnelProviderSession, operation: String, request: String, session: String,
                      owner: String, lease: String, source: String, config: String, node: String, maximumBytes: Int = 32768) async throws -> [String: Any] {
        let payload = try JSONSerialization.data(withJSONObject: ["operation": operation, "request_id": request, "session_id": session,
            "owner": owner, "lease": lease, "source_sha256": source, "config_sha256": config, "node_id": node])
        guard payload.count <= 1536 else { throw CancellationError() }
        let data = try await withCheckedThrowingContinuation { continuation in
            let reply = IOSOrderedLatencyReply(continuation, maximumBytes: maximumBytes)
            DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + 4) { reply.finish(nil) }
            do { try connection.sendProviderMessage(payload) { reply.finish($0) } } catch { reply.finish(nil) }
        }
        guard let raw = String(data: data, encoding: .utf8) else { throw CancellationError() }
        let body = try IOSOrderedLatencyRecord.object(raw, maximum: maximumBytes)
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
                      UUID(uuidString: session) != nil, let nodes = info["nodes"] as? [[String: Any]], nodes.count == capture.ids.count else { throw CancellationError() }
                for (index, item) in nodes.enumerated() {
                    guard item["position"] as? Int == index, item["node_id"] as? String == capture.ids[index], item["kind"] as? String == capture.kinds[index] else { throw CancellationError() }
                }
                guard !cancelled else { throw CancellationError() }; try capture.require(model)
                let owned = IOSOrderedLatencyTransaction(request: request, source: capture.source, config: capture.config, node: node, position: position,
                    requested: capture.requestedExecution, ids: capture.ids, kinds: capture.kinds, extended: capture.extended, validateExecution: capture.verifyExecution,
                    send: { [self] operation in try await send(original.connection, operation: operation, request: request, session: session, owner: owner, lease: lease.request, source: capture.source, config: capture.config, node: node, maximumBytes: ["ordered-latency-open", "ordered-latency-close"].contains(operation) ? max(32768, 1024 + 2 * (capture.extended?.statusLimit ?? 8192)) : 32768) })
                transaction = owned
                let record = try await owned.run(current: {
                    guard !self.cancelled, IOSMTUMeasurementGate.current == lease.request, IOSMTUControl.current(original, model: model) else { throw CancellationError() }
                    try capture.require(model)
                }, update: { self.text = $0 })
                guard record.count == capture.ids.count, record.kind == capture.kinds[position] else { throw CancellationError() }
                let saved = try IOSOrderedLatencyHistory.save(record, profile: capture.profile) {
                    guard !self.cancelled, IOSMTUMeasurementGate.current == lease.request, IOSMTUControl.current(original, model: model) else { throw CancellationError() }
                    try capture.require(model)
                }
                if record.execution != nil { try capture.verifyHistory(saved) }
                history[node] = saved.map(\.detail).joined(separator: "\n\n")
                text = "Saved complete historical result for node \(position + 1)."
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
