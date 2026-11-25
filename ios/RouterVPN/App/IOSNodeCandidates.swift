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
    typealias Send = @MainActor (String, String, String, String, TimeInterval?) async throws -> Data
    let epoch: String, owner: String
    private let send: Send
    private let recovered: @MainActor () -> Bool
    private let pause: @MainActor () async -> Void
    private var cancelled = false, observationActive = false
    init(epoch: String, owner: String, send: @escaping Send, recovered: @escaping @MainActor () -> Bool,
         pause: @escaping @MainActor () async -> Void = { try? await Task.sleep(for: .milliseconds(250)) }) throws {
        guard UUID(uuidString: epoch) != nil, IOSCandidateCatalogPublication.validRequest(owner) else { throw IOSNodeCandidateResult.issue() }
        self.epoch = epoch; self.owner = owner; self.send = send; self.recovered = recovered; self.pause = pause
    }
    func cancel() { cancelled = true }
    private func reply(_ operation: String, request: String, candidate: String = "", prefix: String = "", deadline: TimeInterval? = nil) async throws -> Envelope {
        let raw = try await send(operation, request, candidate, prefix, deadline)
        guard raw.count <= 131072 else { throw IOSNodeCandidateResult.issue() }
        let value = try JSONDecoder().decode(Envelope.self, from: raw)
        guard value.session_id == epoch, value.owner_request == owner, value.request_id == request else { throw IOSNodeCandidateResult.issue() }
        return value
    }
    func open(prefix: Int, inventoryBytes: Int = IOSCandidateCatalogPublication.maximumInventoryBytes,
              family: IOSCandidateMetadataPages.Family = .ordinary, selectedResponse: IOSNodeCandidatePrefix? = nil,
              current: @MainActor () throws -> Void = {}) async throws -> IOSNodeCandidateMetadata {
        let deadline = ProcessInfo.processInfo.systemUptime + 3
        func requireCurrent() throws {
            guard !cancelled, !Task.isCancelled, ProcessInfo.processInfo.systemUptime < deadline else { throw CancellationError() }
            try current()
        }
        try requireCurrent()
        guard let first = try await reply("candidate-open", request: owner, prefix: String(prefix), deadline: deadline).metadata else { throw IOSNodeCandidateResult.issue() }
        try requireCurrent()
        var pages = try IOSCandidateMetadataPages(first, inventoryBytes: inventoryBytes, legacyLimit: 32768, family: family,
            selectedResponse: selectedResponse.map { ($0.position, $0.profile_id) })
        while let offset = pages.nextOffset {
            try requireCurrent()
            guard let raw = try await reply("candidate-metadata-page", request: owner, candidate: String(offset), deadline: deadline).metadata else { throw IOSNodeCandidateResult.issue() }
            try requireCurrent(); try pages.append(raw)
        }
        let result = try JSONDecoder().decode(IOSNodeCandidateMetadata.self, from: pages.result())
        try requireCurrent(); return result
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
        let deadline = ProcessInfo.processInfo.systemUptime + 4
        while observationActive {
            guard !cancelled, !Task.isCancelled, ProcessInfo.processInfo.systemUptime < deadline else { throw CancellationError() }
            await pause()
        }
        observationActive = true
        defer { observationActive = false }
        guard !cancelled, !Task.isCancelled,
              let raw = try await reply("candidate-status", request: request).status else { throw CancellationError() }
        guard !cancelled, !Task.isCancelled else { throw CancellationError() }
        let value = try JSONDecoder().decode(Progress.self, from: Data(raw.utf8))
        guard value.request_id == request, value.complete, value.drained, ["complete", "failed"].contains(value.stage),
              value.measurement == metadata.metric, value.capture_sha256 == metadata.capture_sha256,
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
        let requested_execution: String?, execution: String?
        let candidate_positions: [Int]?
        let proposal_source_sha256: String?, proposal_config_sha256: String?
        var eligiblePrefixes: [IOSNodeCandidatePrefix] {
            proofs.filter { prefix in
                if let requested_execution, prefix.metric == "routed-candidate-response" {
                    return requested_execution == "auto" && execution == "local" && candidate_positions?.contains(prefix.position) == true &&
                        prefix.selectedResponse(in: proofs)
                }
                return prefix.supported(in: proofs) && (candidate_positions?.contains(prefix.position) ?? true)
            }
        }
    }
    struct Score: Identifiable {
        let id: String, name: String
        let token = UUID()
        let receipt: IOSNodeCandidateResult
        let benchmark: IOSNodeCandidateResult.Benchmark
    }
    @Published private(set) var running = false
    @Published private(set) var prefixes: [IOSNodeCandidatePrefix] = []
    @Published var selectedPrefix = 0
    @Published private(set) var independentPrefixes = Set<Int>()
    @Published private(set) var independentOnly = false
    var canTestIndependentPrefix: Bool { !running && independentPrefixes.contains(selectedPrefix) }
    @Published private(set) var scores: [Score] = []
    @Published private(set) var text = "Choose a complete saved Local path to compare candidates."
    @Published private(set) var preparing = false
    @Published private(set) var proposalDescription = ""
    @Published private(set) var profileMessage = ""
    private var proposalAction: ((Score) async throws -> IOSNodeCandidateProposal)?
    private var saveAction: ((Score, IOSNodeCandidateProposal, String) async throws -> String)?
    private var prepared: (score: Score, proposal: IOSNodeCandidateProposal)?
    private var proposalGeneration = UUID(), generation = UUID()
    var canPrepare: Bool { running && !preparing && proposalAction != nil }
    var canSave: Bool { canPrepare && prepared != nil }
    private var task: Task<Void, Never>?
    private var transaction: IOSNodeCandidateTransaction?
    private var cancelled = false
    private var preparation: IOSNodeCandidatePreparation?
    static func supported(_ model: RouterVPNModel) -> Bool {
        if model.connected { return model.activeEngine == "multihop-libbox" && !IOSNodeCandidatePreparation.busy }
        return !model.tunnelTransitioning && !model.iosSpeedLabOwnership.active &&
            model.selectedNodeProfile?.multihopExecution == "local" && model.iosVisibleOrderedNodePath != nil
    }
    private static func nonce() -> String { UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased() }
    private func send(_ connection: NETunnelProviderSession, operation: String, request: String,
                      epoch: String, owner: String = "", candidate: String = "", prefix: String = "", deadline: TimeInterval? = nil) async throws -> Data {
        let remaining = min(3, deadline.map { $0 - ProcessInfo.processInfo.systemUptime } ?? 3)
        guard remaining > 0 else { throw CancellationError() }
        let raw = try JSONSerialization.data(withJSONObject: ["operation": operation, "request_id": request,
            "session_id": epoch, "owner_request": owner, "candidate": candidate, "prefix": prefix])
        guard raw.count <= 1024 else { throw IOSNodeCandidateResult.issue() }
        return try await withCheckedThrowingContinuation { continuation in
            let reply = IOSCandidateReply(continuation)
            DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + remaining) { reply.finish(nil) }
            do { try connection.sendProviderMessage(raw) { reply.finish($0) } } catch { reply.finish(nil) }
        }
    }
    private func information(_ binding: IOSMTUControl.Binding) async throws -> Info {
        let request = Self.nonce()
        let raw = try await send(binding.connection, operation: "candidate-info", request: request, epoch: "")
        let info = try JSONDecoder().decode(Info.self, from: raw)
        guard info.request_id == request, UUID(uuidString: info.session_id) != nil, info.mtu_session_id == binding.session,
              IOSCandidateCatalogPublication.isDigest(info.source_sha256), IOSCandidateCatalogPublication.isDigest(info.config_sha256),
              (2...8).contains(info.proofs.count) || info.proofs.count == binding.identity.hopMeasurementRows && IOSMultihopNodeSelection.extendedOriginalModes(info.proofs.map(\.mode), execution: info.requested_execution ?? "local"), info.proofs.enumerated().allSatisfy({ $0.offset == $0.element.position }) else { throw IOSNodeCandidateResult.issue() }
        if let original = binding.identity.nodeChainExecutionSource {
            guard binding.identity.nodeChainSource == nil,
                  let launch = try JSONSerialization.jsonObject(with: original) as? [String: Any],
                  let source = launch["source"] as? String,
                  let preparation = try JSONSerialization.jsonObject(with: Data(source.utf8)) as? [String: Any],
                  let requested = info.requested_execution, ["server", "auto"].contains(requested),
                  requested == preparation["execution"] as? String,
                  let selected = info.execution, ["local", "server"].contains(selected), requested == "auto" || selected == requested,
                  info.proposal_source_sha256 == launch["source_sha256"] as? String,
                  info.proposal_source_sha256 == info.source_sha256,
                  let proposalConfig = info.proposal_config_sha256, proposalConfig == launch["config_sha256"] as? String,
                  IOSCandidateCatalogPublication.isDigest(proposalConfig) else { throw IOSNodeCandidateResult.issue() }
            let positions = try IOSNodeCandidateProposal.selectedPositions(input: original, bundle: binding.identity.bundleData,
                proofs: info.proofs, source: info.source_sha256, config: proposalConfig, winner: selected)
            guard info.candidate_positions == positions else { throw IOSNodeCandidateResult.issue() }
        } else {
            guard info.requested_execution == nil, info.execution == nil, info.candidate_positions == nil,
                  info.proposal_source_sha256 == nil, info.proposal_config_sha256 == nil else { throw IOSNodeCandidateResult.issue() }
            if IOSMultihopNodeSelection.extendedMixedPacketCount(info.proofs.map(\.mode), execution: "local") > 0 ||
               info.proofs.contains(where: { ($0.position >= IOSMultihopNodeSelection.maximumNodes - 1 || !$0.node_id.isEmpty) && $0.metric == "routed-candidate-response" }) {
                guard let original = binding.identity.nodeChainSource else { throw IOSNodeCandidateResult.issue() }
                try IOSNodeCandidateOriginalCapture.validateExtendedResponseInfo(input: original, bundle: binding.identity.bundleData,
                    proofs: info.proofs, sourceSHA256: info.source_sha256, configSHA256: info.config_sha256)
            }
        }
        return info
    }
    func refresh(model: RouterVPNModel) async {
        guard !running, Self.supported(model) else { if !running { prefixes = [] }; return }
        do {
            if !model.connected {
                guard let bundle = model.bundle else { throw CancellationError() }
                let capture = try model.captureIOSCandidateOriginal(bundle)
                defer { try? capture.close() }
                independentOnly = capture.requiresIndependentPrefix
                let originalPrefixes = capture.candidatePrefixes
                prefixes = originalPrefixes.filter { $0.supported(in: originalPrefixes) }
                independentPrefixes = Set(prefixes.filter { prefix in
                    prefix.position < capture.members.count - 1 &&
                        (prefix.metric == "routed-candidate-response" || capture.members.prefix(prefix.position + 1).allSatisfy { ["wg", "awg2-fast", "awg2-strong"].contains($0.mode) })
                }.map(\.position))
                if !prefixes.contains(where: { $0.position == selectedPrefix }) { selectedPrefix = prefixes.first?.position ?? 0 }
                text = independentOnly ? "Test the selected prefix. The saved proxy suffix stays unused, and the test returns to Disconnected before future-profile choices appear." : "Test only the selected prefix, or test the complete saved Local path. Both return to Disconnected before future-profile choices appear."
                return
            }
            let binding = try await IOSMTUControl.capture(model), info = try await information(binding)
            guard IOSMTUControl.current(binding, model: model), !running else { return }
            prefixes = info.eligiblePrefixes
            if !prefixes.contains(where: { $0.position == selectedPrefix }) { selectedPrefix = prefixes.first?.position ?? 0 }
            text = prefixes.isEmpty ? "This path has no supported prefix for candidate timing." : "Choose an original prefix. Each eligible candidate receives 50 fresh samples of the selected metric."
        } catch { prefixes = []; text = "The original ordered prefix is unavailable." }
    }
    func startPrefix(model: RouterVPNModel) { start(model: model, prefixOnly: true) }
    func start(model: RouterVPNModel, prefixOnly: Bool = false) {
        guard !running, Self.supported(model), prefixes.contains(where: { $0.position == selectedPrefix }),
              !prefixOnly || (!model.connected && canTestIndependentPrefix) else { return }
        let position = selectedPrefix, owner = Self.nonce()
        let temporary: IOSNodeCandidatePreparation?
        do { temporary = model.connected ? nil : try IOSNodeCandidatePreparation.reserve(model: model, prefixPosition: prefixOnly ? position : nil, request: prefixOnly ? owner : nil) { [weak self] in self?.cancel() } }
        catch { text = "The saved Local path could not acquire its temporary test owner."; return }
        begin(model: model, temporary: temporary, position: position, owner: owner)
    }

    private func begin(model: RouterVPNModel, temporary: IOSNodeCandidatePreparation?, position: Int, owner: String,
                       editor: Bool = false) {
        let round = UUID()
        preparation = temporary
        generation = round; prepared = nil; proposalDescription = ""; profileMessage = ""
        cancelled = false; running = true; scores = []; text = "Capturing original saved candidate sources…"
        // The task owns cleanup even if its view disappears before this first
        // actor turn. The terminal defer releases the task/controller cycle.
        task = Task { @MainActor [self, model] in
            defer {
                self.running = false; self.transaction = nil; self.task = nil
                self.proposalAction = nil; self.saveAction = nil; self.prepared = nil
                self.proposalDescription = ""; self.preparing = false; self.generation = UUID()
                temporary?.closeResults(); self.preparation = nil
            }
            await IOSSpeedLabContext.$owner.withValue(temporary?.owner) {
            if let temporary, temporary.prefixCapture != nil {
                do { try await self.runPrefix(temporary, model: model, position: position, owner: owner, round: round, editor: editor) }
                catch { self.scores = []; self.text = "Prefix comparison closed or discarded because its original source, request or physical path changed." }
                await Task { @MainActor in await temporary.retire() }.value
                return
            }
            var detachedScores: [Score] = [], detachedProposals: [UUID: IOSNodeCandidateProposal] = [:], detachedFailures: [UUID: String] = [:]
            do {
                if let temporary { try await temporary.start() }
                try await IOSMTUControl.withHold(model: model) {
                    let binding = try await IOSMTUControl.capture(model), info = try await self.information(binding)
                    guard IOSMTUControl.current(binding, model: model), !self.cancelled,
                          info.eligiblePrefixes.contains(where: { $0.position == position }) else { throw CancellationError() }
                    if let draft = temporary?.selectedDraft {
                        try draft.requireInformation(info, owner: owner, position: position)
                    } else if let temporary {
                        guard info.source_sha256 == temporary.sourceSHA256, info.config_sha256 == temporary.configSHA256,
                              info.proofs == temporary.prefixes else { throw CancellationError() }
                    }
                    let capture = try IOSNodeCandidateCapture.make(request: owner, prefixPosition: position, proofs: info.proofs,
                        chainSource: info.source_sha256, chainConfig: info.config_sha256, selectedResponse: info.requested_execution == "auto" && info.proofs[position].metric == "routed-candidate-response")
                    let owned = try IOSNodeCandidateTransaction(epoch: info.session_id, owner: owner,
                        send: { op, request, candidate, prefix, deadline in
                            try await self.send(binding.connection, operation: op, request: request, epoch: info.session_id,
                                owner: owner, candidate: candidate, prefix: prefix, deadline: deadline)
                        }, recovered: { IOSCandidateCatalogPublication.shared.closed(epoch: info.session_id, request: owner) })
                    self.transaction = owned
                    try temporary?.bind(owned)
                    var failure: Error?
                    do {
                        let current: @MainActor @Sendable () throws -> Void = {
                            guard self.generation == round, !self.cancelled, !Task.isCancelled, self.selectedPrefix == position, IOSMTUControl.current(binding, model: model) else { throw CancellationError() }
                            try capture.requireCurrent()
                            try temporary?.requireLive()
                        }
                        let response = info.eligiblePrefixes.first { $0.metric == "routed-candidate-response" }
                        let metadata = try await owned.open(prefix: position, inventoryBytes: capture.source.inventory.data.count,
                            family: info.requested_execution == nil ? .ordinary : .selected, selectedResponse: response, current: current)
                        try current()
                        guard metadata.targets.map(\.id) == capture.rows.filter({ !$0.input.isEmpty }).map(\.id) else { throw IOSNodeCandidateResult.issue() }
                        try metadata.validate(prefix: capture.prefix, source: capture.chainSource, config: capture.chainConfig,
                            ids: Set(capture.rows.filter { !$0.input.isEmpty }.map(\.id)),
                            requestedExecution: info.requested_execution, selectedExecution: info.execution, selectedPositions: info.candidate_positions ?? [],
                            selectedResponse: response)
                        let unsupported = capture.rows.filter { $0.input.isEmpty }.count
                        var lastRequest = ""
                        for target in metadata.targets {
                            try current()
                            let request = Self.nonce(), row = capture.rows.first { $0.id == target.id }!
                            self.text = "50 \(IOSNodeCandidateMetadata.label(metadata.metric)) through prefix \(position + 1): \(row.name.prefix(100)). \(unsupported) unsupported saved sources remain unscored."
                            let raw = try await owned.measure(request: request, candidate: target.id, current: current)
                            lastRequest = request
                            try current()
                            if let receipt = try? JSONDecoder().decode(IOSNodeCandidateResult.self, from: raw),
                               let benchmark = try? receipt.score(request: request, target: target, metadata: metadata,
                                   now: Int64(Date().timeIntervalSince1970 * 1000)) {
                                let score = Score(id: target.id, name: String(row.name.prefix(100)), receipt: receipt, benchmark: benchmark)
                                if temporary == nil { self.scores.append(score) } else { detachedScores.append(score) }
                            }
                            self.prune()
                        }
                        let capturedScores = temporary == nil ? self.scores : detachedScores
                        let currentResult: @MainActor @Sendable (Score) throws -> Void = { score in
                            try current()
                            guard (temporary == nil ? self.scores : capturedScores).contains(where: { $0.token == score.token }),
                                  let target = metadata.targets.first(where: { $0.id == score.id }) else { throw IOSNodeCandidateResult.issue() }
                            _ = try score.receipt.score(request: score.receipt.request_id, target: target, metadata: metadata,
                                now: Int64(Date().timeIntervalSince1970 * 1000))
                        }
                        let observedRequest = lastRequest
                        let compileProposal: (Score) async throws -> IOSNodeCandidateProposal = { score in
                            try currentResult(score)
                            try await owned.observe(request: observedRequest, metadata: metadata)
                            try currentResult(score)
                            guard let originalInput = binding.identity.nodeChainSource ?? binding.identity.nodeChainExecutionSource,
                                  let bundle = try JSONSerialization.jsonObject(with: binding.identity.bundleData) as? [String: Any],
                                  let id = bundle["selectedRouterID"] as? String,
                                  let profiles = bundle["routerProfiles"] as? [[String: Any]],
                                  profiles.filter({ $0["id"] as? String == id }).count == 1,
                                  let final = profiles.first(where: { $0["id"] as? String == id }),
                                  let row = capture.rows.first(where: { $0.id == score.id }) else { throw IOSNodeCandidateCapture.issue() }
                            let proposal: IOSNodeCandidateProposal
                            if binding.identity.nodeChainExecutionSource != nil {
                                guard let originalSource = info.proposal_source_sha256, let originalConfig = info.proposal_config_sha256 else { throw IOSNodeCandidateCapture.issue() }
                                proposal = try IOSNodeCandidateProposal.compileConnectedExecution(String(decoding: originalInput, as: UTF8.self), selectedProfile: final,
                                    sourceSHA256: originalSource, configSHA256: originalConfig, records: capture.records,
                                    position: position, candidateID: score.id, measuredInput: row.input, winner: info.execution ?? "")
                            } else {
                                let original = try IOSNodeCandidateOriginalCapture.reopenConnected(String(decoding: originalInput, as: UTF8.self), selectedProfile: final,
                                    sourceSHA256: capture.chainSource, configSHA256: capture.chainConfig)
                                defer { try? original.close() }
                                proposal = try IOSNodeCandidateProposal.compile(original: original, records: capture.records,
                                    position: position, candidateID: score.id, measuredInput: row.input)
                            }
                            try currentResult(score)
                            return proposal
                        }
                        if let temporary {
                            let now = Int64(Date().timeIntervalSince1970 * 1000)
                            detachedScores.removeAll { now < $0.receipt.measured_at || now >= $0.receipt.expires_at }
                            for score in detachedScores {
                                if Int64(Date().timeIntervalSince1970 * 1000) >= score.receipt.expires_at { continue }
                                if !editor || info.requested_execution == "auto" && metadata.metric == "routed-candidate-response" {
                                    do { detachedProposals[score.token] = try await compileProposal(score) }
                                    catch {
                                        try currentResult(score)
                                        detachedFailures[score.token] = error.localizedDescription
                                    }
                                }
                                try currentResult(score)
                                try temporary.seal(token: score.token, measured: score.receipt.measured_at, expires: score.receipt.expires_at)
                            }
                        } else {
                        self.proposalAction = compileProposal
                        self.saveAction = { score, proposal, name in
                            try currentResult(score)
                            let selected = self.proposalGeneration
                            try await owned.observe(request: observedRequest, metadata: metadata)
                            try currentResult(score)
                            guard selected == self.proposalGeneration, self.prepared?.score.token == score.token else { throw IOSNodeCandidateResult.issue() }
                            return try IOSCandidateConnectionProfiles.save(name: name, profiles: proposal.profiles) {
                                try currentResult(score)
                                guard selected == self.proposalGeneration, self.prepared?.score.token == score.token else { throw IOSNodeCandidateResult.issue() }
                            }
                        }
                        self.text = "50 \(IOSNodeCandidateMetadata.label(metadata.metric)) through the retained prefix. Scores expire 120 seconds after each completion. Close results to release MTU. Unsupported or failed candidates have no score."
                        while !self.scores.isEmpty {
                            try current(); try await owned.observe(request: lastRequest, metadata: metadata); try current(); self.prune()
                            try await Task.sleep(for: .seconds(1))
                        }
                        }
                    } catch { failure = error; self.scores = [] }
                    self.text = "Closing the original candidate owner; waiting for native callbacks and sockets to drain…"
                    let cleanup = Task { @MainActor in await owned.close() }
                    await cleanup.value
                    try? IOSCandidateCatalogPublication.shared.remove(capture.source)
                    try? IOSCandidateCatalogPublication.shared.acknowledgeClosed(epoch: info.session_id, request: owner)
                    if let failure { throw failure }
                    if temporary == nil { self.text = "Candidate results expired; run a fresh comparison to measure again." }
                }
                if let temporary {
                    self.text = "Returning the original temporary path to Disconnected…"
                    await Task { @MainActor in await temporary.retire() }.value
                    guard !self.cancelled, self.generation == round, !Task.isCancelled else { throw CancellationError() }
                    let proposals = detachedProposals, failures = detachedFailures
                    self.scores = detachedScores; self.prune()
                    for score in self.scores { try temporary.requireSaved(token: score.token) }
                    if editor && !self.scores.contains(where: { $0.benchmark.measurement == "routed-candidate-response" && temporary.selectedDraft != nil }) {
                        self.text = "Disconnected. Choose a measured node to update this draft."
                        while !self.scores.isEmpty {
                            self.prune()
                            for score in self.scores { try temporary.requireSaved(token: score.token) }
                            try await Task.sleep(for: .seconds(1))
                        }
                        return
                    }
                    self.proposalAction = { score in
                        try temporary.requireSaved(token: score.token)
                        guard self.scores.contains(where: { $0.token == score.token }) else { throw IOSNodeCandidateResult.issue() }
                        guard let proposal = proposals[score.token] else {
                            throw NSError(domain: "RouterVPN.CandidatePreparation", code: 1,
                                userInfo: [NSLocalizedDescriptionKey: failures[score.token] ?? "This timed source cannot form a supported future connection."])
                        }
                        return proposal
                    }
                    self.saveAction = { score, proposal, name in
                        try temporary.requireSaved(token: score.token)
                        let selected = self.proposalGeneration
                        guard self.prepared?.score.token == score.token,
                              proposals[score.token]?.profiles == proposal.profiles else { throw IOSNodeCandidateResult.issue() }
                        return try IOSCandidateConnectionProfiles.save(name: name, profiles: proposal.profiles) {
                            try temporary.requireSaved(token: score.token)
                            guard selected == self.proposalGeneration, self.prepared?.score.token == score.token else { throw IOSNodeCandidateResult.issue() }
                        }
                    }
                    self.text = "Disconnected. Choose an explicitly saved future profile; each original result still expires after 120 seconds."
                    while !self.scores.isEmpty {
                        self.prune()
                        for score in self.scores { try temporary.requireSaved(token: score.token) }
                        try await Task.sleep(for: .seconds(1))
                    }
                }
            } catch { self.scores = []; self.text = "Candidate comparison closed or discarded because its original source, request or tunnel changed." }
            if let temporary { await Task { @MainActor in await temporary.retire() }.value }
            }
        }
    }
    private func runPrefix(_ temporary: IOSNodeCandidatePreparation, model: RouterVPNModel,
                           position: Int, owner: String, round: UUID, editor: Bool) async throws {
        try await temporary.start()
        guard let prefix = temporary.prefixCapture, let capture = temporary.prefixCandidate,
              let binding = temporary.prefixBinding, capture.source.request == owner else { throw CancellationError() }
        let owned = try IOSNodeCandidateTransaction(epoch: temporary.prefixEpoch.uuidString, owner: owner,
            send: { op, request, candidate, selected, deadline in
                try await self.send(binding.connection, operation: "prefix-" + op, request: request,
                    epoch: temporary.prefixEpoch.uuidString, owner: owner, candidate: candidate, prefix: selected, deadline: deadline)
            }, recovered: { IOSCandidateCatalogPublication.shared.closed(epoch: temporary.prefixEpoch.uuidString, request: owner) })
        transaction = owned; try temporary.bind(owned)
        let current: @MainActor @Sendable () throws -> Void = {
            guard self.generation == round, !self.cancelled, !Task.isCancelled,
                  self.selectedPrefix == position else { throw CancellationError() }
            try temporary.requireLive(); try capture.requireCurrent()
        }
        let metadata = try await owned.open(prefix: position, inventoryBytes: capture.source.inventory.data.count, family: .preparation, current: current)
        try current()
        guard metadata.targets.map(\.id) == capture.rows.filter({ !$0.input.isEmpty }).map(\.id) else { throw IOSNodeCandidateResult.issue() }
        try metadata.validate(prefix: capture.prefix, source: prefix.sourceSHA256, config: prefix.configSHA256,
            ids: Set(capture.rows.filter { !$0.input.isEmpty }.map(\.id)))
        guard metadata.capture_sha256 == prefix.captureSHA256 else { throw IOSNodeCandidateResult.issue() }
        var detached: [Score] = [], proposals: [UUID: IOSNodeCandidateProposal] = [:], failures: [UUID: String] = [:]
        var last = ""
        for target in metadata.targets {
            try current()
            guard let row = capture.rows.first(where: { $0.id == target.id }) else { throw IOSNodeCandidateResult.issue() }
            let request = Self.nonce(); last = request
            text = "50 \(IOSNodeCandidateMetadata.label(metadata.metric)) through the selected prefix: \(row.name.prefix(100)). The saved suffix remains unused."
            let raw = try await owned.measure(request: request, candidate: target.id, current: current)
            try current()
            if let receipt = try? JSONDecoder().decode(IOSNodeCandidateResult.self, from: raw),
               let score = try? receipt.score(request: request, target: target, metadata: metadata,
                   now: Int64(Date().timeIntervalSince1970 * 1000)) {
                detached.append(Score(id: target.id, name: String(row.name.prefix(100)), receipt: receipt, benchmark: score))
            }
        }
        let offersNamedProfile = !editor || metadata.metric == "routed-candidate-response"
        var admitted: [Score] = []
        for score in detached {
            let now = Int64(Date().timeIntervalSince1970 * 1000)
            if now < score.receipt.measured_at || now >= score.receipt.expires_at { continue }
            try current(); try await owned.observe(request: last, metadata: metadata); try current()
            guard let target = metadata.targets.first(where: { $0.id == score.id }),
                  let row = capture.rows.first(where: { $0.id == score.id }) else { throw IOSNodeCandidateResult.issue() }
            _ = try score.receipt.score(request: score.receipt.request_id, target: target, metadata: metadata,
                now: Int64(Date().timeIntervalSince1970 * 1000))
            if offersNamedProfile {
                let original = try temporary.originalForProposal()
                defer { try? original.close() }
                guard original.sourceSHA256 == temporary.sourceSHA256, original.configSHA256 == temporary.configSHA256 else { throw IOSNodeCandidateResult.issue() }
                do { proposals[score.token] = try IOSNodeCandidateProposal.compile(original: original, records: capture.records,
                    position: position, candidateID: score.id, measuredInput: row.input) }
                catch { try current(); failures[score.token] = error.localizedDescription }
            }
            try current()
            try temporary.seal(token: score.token, measured: score.receipt.measured_at, expires: score.receipt.expires_at)
            admitted.append(score)
        }
        text = "Closing the prefix worker and original temporary tunnel before showing choices…"
        await Task { @MainActor in await temporary.retire() }.value
        guard generation == round, !cancelled, !Task.isCancelled else { throw CancellationError() }
        scores = admitted; prune()
        for score in scores { try temporary.requireSaved(token: score.token) }
        if !offersNamedProfile {
            text = scores.isEmpty ? "No candidate completed all 50 samples." : "Choose a next node. Scores expire two minutes after measurement."
        } else {
            let savedProposals = proposals, savedFailures = failures
            proposalAction = { score in
                try temporary.requireSaved(token: score.token)
                guard self.scores.contains(where: { $0.token == score.token }) else { throw IOSNodeCandidateResult.issue() }
                guard let proposal = savedProposals[score.token] else {
                    throw NSError(domain: "RouterVPN.PrefixCandidate", code: 1,
                        userInfo: [NSLocalizedDescriptionKey: savedFailures[score.token] ?? "This timed source cannot form a supported future connection."])
                }
                return proposal
            }
            saveAction = { score, proposal, name in
                try temporary.requireSaved(token: score.token)
                let selected = self.proposalGeneration
                guard self.prepared?.score.token == score.token,
                      savedProposals[score.token]?.profiles == proposal.profiles else { throw IOSNodeCandidateResult.issue() }
                return try IOSCandidateConnectionProfiles.save(name: name, profiles: proposal.profiles) {
                    try temporary.requireSaved(token: score.token)
                    guard selected == self.proposalGeneration, self.prepared?.score.token == score.token else { throw IOSNodeCandidateResult.issue() }
                }
            }
            text = "Disconnected. Prefix-only results expire 120 seconds after completion. Save explicitly to create a future profile."
        }
        while !scores.isEmpty {
            prune()
            for score in scores { try temporary.requireSaved(token: score.token) }
            try await Task.sleep(for: .seconds(1))
        }
    }

    func prepare(_ score: Score) {
        guard canPrepare, let action = proposalAction else { return }
        let selected = UUID(); proposalGeneration = selected
        preparing = true; prepared = nil; proposalDescription = ""; profileMessage = "Compiling the complete future connection…"
        Task { @MainActor in
            defer { if self.proposalGeneration == selected { self.preparing = false } }
            do {
                let proposal = try await action(score)
                guard self.proposalGeneration == selected, self.running, !self.cancelled else { throw CancellationError() }
                self.prepared = (score, proposal); self.proposalDescription = proposal.description
                self.profileMessage = preparation == nil ? "Name this complete future profile. The active connection will stay unchanged." : "Name this complete future profile. The temporary path is already disconnected."
            } catch { if self.proposalGeneration == selected { self.profileMessage = "Future profile could not be prepared: \(error.localizedDescription)" } }
        }
    }
    func save(name: String) {
        guard canSave, let prepared, let action = saveAction else { return }
        let selected = proposalGeneration
        preparing = true
        Task { @MainActor in
            defer { if self.proposalGeneration == selected { self.preparing = false } }
            do {
                let saved = try await action(prepared.score, prepared.proposal, name)
                guard selected == self.proposalGeneration else { return }
                self.profileMessage = "Saved \(saved) for a future connection. Use Profiles → Load while disconnected to revalidate it."
                self.prepared = nil; self.proposalDescription = ""
            } catch { if selected == self.proposalGeneration { self.profileMessage = "Profile was not saved: \(error.localizedDescription)" } }
        }
    }
    private func prune() {
        let now = Int64(Date().timeIntervalSince1970 * 1000)
        scores.removeAll { now < $0.receipt.measured_at || now >= $0.receipt.expires_at }
        scores.sort { $0.benchmark.trimmed_mean_ms < $1.benchmark.trimmed_mean_ms }
        if let prepared, !scores.contains(where: { $0.token == prepared.score.token }) {
            self.prepared = nil; proposalDescription = ""; proposalGeneration = UUID(); preparing = false
        }
    }
    func tunnelChanged(model: RouterVPNModel) {
        if preparation != nil { return }
        cancel(); Task { await refresh(model: model) }
    }
    func cancel() {
        guard running, !cancelled else { return }
        cancelled = true; preparation?.cancel(); scores = []; prepared = nil; proposalDescription = ""; proposalGeneration = UUID(); transaction?.cancel(); task?.cancel()
        text = "Cancelling; MTU remains paused until the original native owner joins."
    }
}

struct IOSNodeCandidatesCard: View {
    @EnvironmentObject private var model: RouterVPNModel
    @ObservedObject var probe: IOSNodeCandidates
    let otherTestRunning: Bool
    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Label("Candidate measurements", systemImage: "point.3.connected.trianglepath.dotted").font(.headline)
            Text(model.connected && !model.iosCandidateTesting ?
                 "WireGuard and AWG prefixes measure TCP connection time. A supported Local Shadowsocks 2022 prefix measures authenticated responses from each paired candidate’s private agent. Each score is the 10% trimmed mean of 50 samples of one metric." :
                 "Choose a selected-prefix test or a complete saved Local path test. Each measures 50 TCP connections or 50 private-agent responses, according to the captured prefix. The VPN returns to Disconnected before you choose a future profile.")
                .font(.caption).foregroundStyle(.secondary)
            Picker("Retained prefix", selection: $probe.selectedPrefix) {
                ForEach(probe.prefixes, id: \.position) { prefix in Text("\(prefix.position + 1) • \(prefix.profile_id) • \(prefix.mode)").tag(prefix.position) }
            }.disabled(probe.running || otherTestRunning)
            if !model.connected && !probe.running {
                Button("Test selected prefix only") { probe.startPrefix(model: model) }
                    .disabled(otherTestRunning || !IOSNodeCandidates.supported(model) || !probe.canTestIndependentPrefix)
                Text("Starts the selected prefix for the measurement. The saved suffix, application traffic and DNS stay closed.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            Button(probe.running ? "Close candidate comparison" : "Compare saved candidates") {
                if probe.running { probe.cancel() } else { probe.start(model: model) }
            }.disabled(otherTestRunning || (!probe.running && (!IOSNodeCandidates.supported(model) || probe.prefixes.isEmpty || !model.connected && probe.independentOnly)))
            IOSCandidateProfileChoices(probe: probe)
            Text(probe.text).font(.caption).foregroundStyle(.secondary)
        }
        .padding(16).background(.background, in: RoundedRectangle(cornerRadius: 18))
        .task { await probe.refresh(model: model) }
        .onChange(of: model.connected) { _ in probe.tunnelChanged(model: model) }
        .onChange(of: model.activeSessionIdentity) { _ in probe.tunnelChanged(model: model) }
        .onChange(of: probe.selectedPrefix) { _ in probe.cancel() }
        .onChange(of: otherTestRunning) { active in if active { probe.cancel() } }
        .onDisappear { probe.cancel() }
    }
}

struct IOSCandidateProfileChoices: View {
    @ObservedObject var probe: IOSNodeCandidates
    @State private var profileName = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            ForEach(probe.scores) { row in
                VStack(alignment: .leading) {
                    Text(String(format: "%@ — %.2f ms (50 %@)", row.name, row.benchmark.trimmed_mean_ms, IOSNodeCandidateMetadata.label(row.benchmark.measurement))).font(.caption.monospacedDigit())
                    Button("Prepare next connection") { probe.prepare(row) }.disabled(!probe.canPrepare)
                }
            }
            if !probe.proposalDescription.isEmpty {
                Text(probe.proposalDescription).font(.caption)
                TextField("Future connection profile name", text: $profileName)
                Button("Save future profile") { probe.save(name: profileName) }
                    .disabled(!probe.canSave || profileName.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            }
            if !probe.profileMessage.isEmpty { Text(probe.profileMessage).font(.caption) }
        }
    }
}

// The editor uses the same prefix-only provider and receipt lifecycle as
// Speed Lab, with a transient source compiled from its captured linked nodes.
@MainActor extension IOSNodeCandidates {
    func finishEditorComparison() async {
        cancel()
        await task?.value
    }

    func startEditorPrefix(model: RouterVPNModel, bundle: ClientBundle, position: Int) throws {
        guard !running else { throw CancellationError() }
        let request = Self.nonce()
        let temporary = try IOSNodeCandidatePreparation.reserve(model: model, prefixPosition: position,
            request: request, editorBundle: bundle) { [weak self] in self?.cancel() }
        selectedPrefix = position
        begin(model: model, temporary: temporary, position: position, owner: request, editor: true)
    }

    var editorMetricLabel: String {
        scores.first.map { IOSNodeCandidateMetadata.label($0.benchmark.measurement) } ?? ""
    }
    func editorScore(node: String, after position: Int) -> Double? {
        guard running, !cancelled, selectedPrefix == position, let preparation,
              let row = scores.first(where: { $0.id == node }),
              (try? preparation.requireSaved(token: row.token)) != nil else { return nil }
        return row.benchmark.trimmed_mean_ms
    }
}

@MainActor extension RouterVPNModel {
    /// Prefix measurement retains the same complete Local source union as
    /// ordinary selection, but never accepts an execution preparation.
    func captureIOSCandidateOriginal(_ selected: ClientBundle) throws -> IOSNodeCandidateOriginalCapture {
        let route = try captureIOSOrderedRoute(selected)
        do {
            _ = try IOSRuntimeSelector.selectNodeChain(route)
            let original: IOSNodeCandidateOriginalCapture
            switch route {
            case .ordinary(let value): original = .ordinary(value)
            case .socks(let value): original = .socks(value)
            case .connect(let value): original = .connect(value)
            case .execution: throw IOSNodeCandidatePrefixCapture.issue()
            }
            guard original.selectionExecution == "local" else { throw IOSNodeCandidatePrefixCapture.issue() }
            return original
        } catch { try? route.close(); throw error }
    }
}
