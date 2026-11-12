import SwiftUI
@preconcurrency import NetworkExtension

private final class IOSCandidateReply: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<Data, Error>?
    init(_ value: CheckedContinuation<Data, Error>) { continuation = value }
    func finish(_ data: Data?) {
        lock.lock(); let pending = continuation; continuation = nil; lock.unlock()
        guard let pending else { return }
        guard let data, !data.isEmpty, data.count <= 131072 else { pending.resume(throwing: IOSNodeCandidateResult.issue()); return }
        pending.resume(returning: data)
    }
}

// CANDIDATE_TRANSACTION_BEGIN
@MainActor final class IOSNodeCandidateTransaction {
    struct Envelope: Decodable {
        let session_id: String, owner_request: String, request_id: String
        let metadata: String?, status: String?, closed: Bool?
    }
    struct Progress: Decodable {
        let request_id: String; let complete: Bool; let drained: Bool
        let stage: String; let measurement: String; let capture_sha256: String
        let prefix_position: Int; let prefix_id: String
    }
    typealias Send = @MainActor (String, String, String, String) async throws -> Data
    let epoch: String, owner: String
    private let send: Send
    private let recovered: @MainActor () -> Bool
    private let pause: @MainActor () async -> Void
    private var cancelled = false
    init(epoch: String, owner: String, send: @escaping Send, recovered: @escaping @MainActor () -> Bool,
         pause: @escaping @MainActor () async -> Void = { try? await Task.sleep(for: .milliseconds(250)) }) throws {
        guard UUID(uuidString: epoch) != nil, IOSCandidateCatalogPublication.validRequest(owner) else { throw IOSNodeCandidateResult.issue() }
        self.epoch = epoch; self.owner = owner; self.send = send; self.recovered = recovered; self.pause = pause
    }
    func cancel() { cancelled = true }
    private func reply(_ operation: String, request: String, candidate: String = "", prefix: String = "") async throws -> Envelope {
        let raw = try await send(operation, request, candidate, prefix)
        guard raw.count <= 131072 else { throw IOSNodeCandidateResult.issue() }
        let value = try JSONDecoder().decode(Envelope.self, from: raw)
        guard value.session_id == epoch, value.owner_request == owner, value.request_id == request else { throw IOSNodeCandidateResult.issue() }
        return value
    }
    func open(prefix: Int) async throws -> IOSNodeCandidateMetadata {
        guard !cancelled, !Task.isCancelled else { throw CancellationError() }
        guard let raw = try await reply("candidate-open", request: owner, prefix: String(prefix)).metadata,
              raw.utf8.count <= 32768 else { throw IOSNodeCandidateResult.issue() }
        guard !cancelled, !Task.isCancelled else { throw CancellationError() }
        return try JSONDecoder().decode(IOSNodeCandidateMetadata.self, from: Data(raw.utf8))
    }
    func measure(request: String, candidate: String, current: @MainActor () throws -> Void) async throws -> Data {
        let deadline = ProcessInfo.processInfo.systemUptime + 150
        var operation = "candidate-start"
        while !cancelled && !Task.isCancelled && ProcessInfo.processInfo.systemUptime < deadline {
            try current()
            guard let raw = try await reply(operation, request: request, candidate: operation == "candidate-start" ? candidate : "").status,
                  raw.utf8.count <= 65536 else { throw IOSNodeCandidateResult.issue() }
            guard !cancelled, !Task.isCancelled else { throw CancellationError() }
            try current()
            let data = Data(raw.utf8), progress = try JSONDecoder().decode(Progress.self, from: data)
            guard progress.request_id == request else { throw IOSNodeCandidateResult.issue() }
            if progress.complete && progress.drained { return data }
            operation = "candidate-status"; await pause()
        }
        throw CancellationError()
    }
    func observe(request: String, metadata: IOSNodeCandidateMetadata) async throws {
        guard !cancelled, !Task.isCancelled,
              let raw = try await reply("candidate-status", request: request).status else { throw CancellationError() }
        guard !cancelled, !Task.isCancelled else { throw CancellationError() }
        let value = try JSONDecoder().decode(Progress.self, from: Data(raw.utf8))
        guard value.request_id == request, value.complete, value.drained, ["complete", "failed"].contains(value.stage),
              value.measurement == "routed-tcp-connect", value.capture_sha256 == metadata.capture_sha256,
              value.prefix_position == metadata.prefix_position, value.prefix_id == metadata.prefix_id else { throw IOSNodeCandidateResult.issue() }
    }
    /// A lost reply never releases the parent lease. Retain this transaction
    /// until exact native Close or its protected durable recovery receipt joins.
    func close() async {
        cancelled = true
        while true {
            if recovered() { return }
            if let value = try? await reply("candidate-close", request: owner), value.closed == true { return }
            await pause()
        }
    }
}
// CANDIDATE_TRANSACTION_END

@MainActor final class IOSNodeCandidates: ObservableObject {
    struct Info: Decodable {
        let session_id: String, request_id: String, mtu_session_id: String
        let source_sha256: String, config_sha256: String
        let proofs: [IOSNodeCandidatePrefix]
    }
    struct Score: Identifiable {
        let id: String, name: String
        let receipt: IOSNodeCandidateResult
        let benchmark: IOSNodeCandidateResult.Benchmark
    }
    @Published private(set) var running = false
    @Published private(set) var prefixes: [IOSNodeCandidatePrefix] = []
    @Published var selectedPrefix = 0
    @Published private(set) var scores: [Score] = []
    @Published private(set) var text = "Connect an ordered Local path to compare saved TCP candidates."
    private var task: Task<Void, Never>?
    private var transaction: IOSNodeCandidateTransaction?
    private var cancelled = false
    static func supported(_ model: RouterVPNModel) -> Bool { model.connected && model.activeEngine == "multihop-libbox" }
    private static func nonce() -> String { UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased() }
    private func send(_ connection: NETunnelProviderSession, operation: String, request: String,
                      epoch: String, owner: String = "", candidate: String = "", prefix: String = "") async throws -> Data {
        let raw = try JSONSerialization.data(withJSONObject: ["operation": operation, "request_id": request,
            "session_id": epoch, "owner_request": owner, "candidate": candidate, "prefix": prefix])
        guard raw.count <= 1024 else { throw IOSNodeCandidateResult.issue() }
        return try await withCheckedThrowingContinuation { continuation in
            let reply = IOSCandidateReply(continuation)
            DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + 3) { reply.finish(nil) }
            do { try connection.sendProviderMessage(raw) { reply.finish($0) } } catch { reply.finish(nil) }
        }
    }
    private func information(_ binding: IOSMTUControl.Binding) async throws -> Info {
        let request = Self.nonce()
        let raw = try await send(binding.connection, operation: "candidate-info", request: request, epoch: "")
        let info = try JSONDecoder().decode(Info.self, from: raw)
        guard info.request_id == request, UUID(uuidString: info.session_id) != nil, info.mtu_session_id == binding.session,
              IOSCandidateCatalogPublication.isDigest(info.source_sha256), IOSCandidateCatalogPublication.isDigest(info.config_sha256),
              (2...8).contains(info.proofs.count), info.proofs.enumerated().allSatisfy({ $0.offset == $0.element.position }) else { throw IOSNodeCandidateResult.issue() }
        return info
    }
    func refresh(model: RouterVPNModel) async {
        guard !running, Self.supported(model) else { if !running { prefixes = [] }; return }
        do {
            let binding = try await IOSMTUControl.capture(model), info = try await information(binding)
            guard IOSMTUControl.current(binding, model: model), !running else { return }
            prefixes = info.proofs.filter(\.supported)
            if !prefixes.contains(where: { $0.position == selectedPrefix }) { selectedPrefix = prefixes.first?.position ?? 0 }
            text = prefixes.isEmpty ? "This path has no supported packet prefix for TCP timing." : "Choose an original prefix. Each eligible candidate receives 50 fresh TCP connections."
        } catch { prefixes = []; text = "The original ordered prefix is unavailable." }
    }
    func start(model: RouterVPNModel) {
        guard !running, Self.supported(model), prefixes.contains(where: { $0.position == selectedPrefix }) else { return }
        let position = selectedPrefix, owner = Self.nonce()
        cancelled = false; running = true; scores = []; text = "Capturing original saved candidate sources…"
        task = Task { @MainActor [weak self, weak model] in
            guard let self, let model else { return }
            defer { self.running = false; self.transaction = nil; self.task = nil }
            do {
                try await IOSMTUControl.withHold(model: model) {
                    let binding = try await IOSMTUControl.capture(model), info = try await self.information(binding)
                    guard IOSMTUControl.current(binding, model: model), !self.cancelled else { throw CancellationError() }
                    let capture = try IOSNodeCandidateCapture.make(request: owner, prefixPosition: position, proofs: info.proofs,
                        chainSource: info.source_sha256, chainConfig: info.config_sha256)
                    let owned = try IOSNodeCandidateTransaction(epoch: info.session_id, owner: owner,
                        send: { op, request, candidate, prefix in
                            try await self.send(binding.connection, operation: op, request: request, epoch: info.session_id,
                                owner: owner, candidate: candidate, prefix: prefix)
                        }, recovered: { IOSCandidateCatalogPublication.shared.closed(epoch: info.session_id, request: owner) })
                    self.transaction = owned
                    var failure: Error?
                    do {
                        let current: @MainActor @Sendable () throws -> Void = {
                            guard !self.cancelled, !Task.isCancelled, self.selectedPrefix == position, IOSMTUControl.current(binding, model: model) else { throw CancellationError() }
                            try capture.requireCurrent()
                        }
                        let metadata = try await owned.open(prefix: position)
                        try current()
                        try metadata.validate(prefix: capture.prefix, source: capture.chainSource, config: capture.chainConfig,
                            ids: Set(capture.rows.filter { !$0.input.isEmpty }.map(\.id)))
                        let unsupported = capture.rows.filter { $0.input.isEmpty }.count
                        var lastRequest = ""
                        for target in metadata.targets {
                            try current()
                            let request = Self.nonce(), row = capture.rows.first { $0.id == target.id }!
                            self.text = "50 TCP connections through prefix \(position + 1): \(row.name.prefix(100)). \(unsupported) unsupported saved sources remain unscored."
                            let raw = try await owned.measure(request: request, candidate: target.id, current: current)
                            lastRequest = request
                            try current()
                            if let receipt = try? JSONDecoder().decode(IOSNodeCandidateResult.self, from: raw),
                               let benchmark = try? receipt.score(request: request, target: target, metadata: metadata,
                                   now: Int64(Date().timeIntervalSince1970 * 1000)) {
                                self.scores.append(Score(id: target.id, name: String(row.name.prefix(100)), receipt: receipt, benchmark: benchmark))
                            }
                            self.prune()
                        }
                        self.text = "TCP connection times through the retained prefix. Scores expire 120 seconds after each completion. Close results to release MTU. Unsupported or failed candidates have no score."
                        while !self.scores.isEmpty {
                            try current(); try await owned.observe(request: lastRequest, metadata: metadata); try current(); self.prune()
                            try await Task.sleep(for: .seconds(1))
                        }
                    } catch { failure = error; self.scores = [] }
                    self.text = "Closing the original candidate owner; waiting for native callbacks and sockets to drain…"
                    let cleanup = Task { @MainActor in await owned.close() }
                    await cleanup.value
                    try? IOSCandidateCatalogPublication.shared.remove(capture.source)
                    try? IOSCandidateCatalogPublication.shared.acknowledgeClosed(epoch: info.session_id, request: owner)
                    if let failure { throw failure }
                    self.text = "Candidate results expired; run a fresh comparison to measure again."
                }
            } catch { self.scores = []; self.text = "Candidate comparison closed or discarded because its original source, request or tunnel changed." }
        }
    }
    private func prune() {
        let now = Int64(Date().timeIntervalSince1970 * 1000)
        scores.removeAll { now < $0.receipt.measured_at || now >= $0.receipt.expires_at }
        scores.sort { $0.benchmark.trimmed_mean_ms < $1.benchmark.trimmed_mean_ms }
    }
    func cancel() {
        guard running else { return }
        cancelled = true; scores = []; transaction?.cancel(); task?.cancel()
        text = "Cancelling; MTU remains paused until the original native owner joins."
    }
}

struct IOSNodeCandidatesCard: View {
    @EnvironmentObject private var model: RouterVPNModel
    @ObservedObject var probe: IOSNodeCandidates
    let otherTestRunning: Bool
    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Label("Candidate TCP connection times", systemImage: "point.3.connected.trianglepath.dotted").font(.headline)
            Text("Compares original literal Shadowsocks 2022 endpoints through a retained WG/AWG prefix. Each score is the 10% trimmed mean of 50 successful TCP handshakes. This does not measure ICMP latency, authenticate the candidate proxy, or change your active route.")
                .font(.caption).foregroundStyle(.secondary)
            Picker("Retained prefix", selection: $probe.selectedPrefix) {
                ForEach(probe.prefixes, id: \.position) { prefix in Text("\(prefix.position + 1) • \(prefix.profile_id) • \(prefix.mode)").tag(prefix.position) }
            }.disabled(probe.running || otherTestRunning)
            Button(probe.running ? "Close candidate comparison" : "Compare saved candidates") {
                if probe.running { probe.cancel() } else { probe.start(model: model) }
            }.disabled(otherTestRunning || (!probe.running && (!IOSNodeCandidates.supported(model) || probe.prefixes.isEmpty)))
            ForEach(probe.scores) { row in
                Text(String(format: "%@ — %.2f ms (50 TCP connections)", row.name, row.benchmark.trimmed_mean_ms)).font(.caption.monospacedDigit())
            }
            Text(probe.text).font(.caption).foregroundStyle(.secondary)
        }
        .padding(16).background(.background, in: RoundedRectangle(cornerRadius: 18))
        .task { await probe.refresh(model: model) }
        .onChange(of: model.connected) { _ in probe.cancel(); Task { await probe.refresh(model: model) } }
        .onChange(of: model.activeSessionIdentity) { _ in probe.cancel(); Task { await probe.refresh(model: model) } }
        .onChange(of: probe.selectedPrefix) { _ in probe.cancel() }
        .onChange(of: otherTestRunning) { active in if active { probe.cancel() } }
        .onDisappear { probe.cancel() }
    }
}
