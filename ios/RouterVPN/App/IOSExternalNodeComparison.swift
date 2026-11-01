import Combine
import Foundation

struct IOSExternalComparisonRow: Identifiable, Sendable {
    let id: String
    let name: String
    let trimmedMeanMS: Double?
    let execution: String?
    let reason: String

    var detail: String {
        guard let trimmedMeanMS, let execution else { return name + " • no score\n" + reason }
        return String(format: "%@ • %.2f ms • 50 responses • %@", name, trimmedMeanMS, execution.capitalized)
    }
}

/// A selection revision is separate from the native session that restoration
/// renews. Only the joined restoration callback may advance the latter.
@MainActor private struct IOSExternalComparisonSelection: Equatable {
    let bundle: Data
    let mode: String
    let logicalMode: String
    let automatic: Bool
    let decision: UUID
    let identity: IOSSessionIdentity?
    let connected: Bool

    init(_ model: RouterVPNModel) throws {
        bundle = try IOSNodeUsage.canonical(model.bundle)
        mode = model.selectedMode; logicalMode = model.selectedLogicalMode; automatic = model.auto
        decision = model.iosConnectGeneration; identity = model.activeSessionIdentity; connected = model.connected
    }

    func sameChoices(_ other: Self) -> Bool {
        bundle == other.bundle && mode == other.mode && logicalMode == other.logicalMode && automatic == other.automatic
    }
}

@MainActor private final class IOSExternalComparisonCandidate {
    let id: String
    let name: String
    let stored: Data
    let runtime: Data?
    let entry: Data?
    let requested: String?
    let key: String?
    let failure: String?

    init(profile: RouterProfile, stored: Data, model: RouterVPNModel) {
        id = profile.id; name = profile.name.isEmpty ? profile.id : profile.name; self.stored = stored
        let prepared: (Data, Data?, String, String)?
        do {
            var source = try JSONDecoder().decode(ClientBundle.self, from: stored)
            guard source.routerProfiles.filter({ $0.id == profile.id }).count == 1,
                  source.routerProfiles.first(where: { $0.id == profile.id }) == profile,
                  profile.normalizedNodeKind == "external" else { throw CancellationError() }
            source.selectedRouterID = profile.id
            let raw = try model.externalRuntimeBundleData(source: source, profile: profile)
            let paired = try model.externalTorEntryData(source: source)
            prepared = (try IOSNodeUsage.canonicalJSON(raw), paired,
                try IOSExternalNodeStatistics.requestedExecution(node: profile.id, bundle: raw),
                try IOSExternalNodeStatistics.key(node: profile.id, bundle: raw, entry: paired))
        } catch { prepared = nil }
        runtime = prepared?.0; entry = prepared?.1; requested = prepared?.2; key = prepared?.3
        failure = prepared == nil ? "The saved transport, entry or policy could not be prepared. Edit this node before comparing it." : nil
    }

    func requireSelected(_ model: RouterVPNModel, connected: Bool) throws {
        guard let runtime, let source = model.bundle, let selected = model.selectedNodeProfile,
              selected.id == id, selected.normalizedNodeKind == "external",
              !model.tunnelTransitioning, !model.iosUserDisconnectInProgress,
              model.connected == connected,
              try IOSNodeUsage.canonicalJSON(model.externalRuntimeBundleData(source: source, profile: selected)) == runtime,
              try model.externalTorEntryData(source: source) == entry else { throw CancellationError() }
        if connected {
            guard let identity = model.activeSessionIdentity, identity.engine == "external-libbox",
                  try IOSNodeUsage.canonicalJSON(identity.bundleData) == runtime,
                  identity.entryBundleData == entry else { throw CancellationError() }
        }
    }
}

@MainActor private final class IOSExternalComparisonCohort {
    let candidates: [IOSExternalComparisonCandidate]
    private let initial: IOSExternalComparisonSelection
    private var returned: IOSExternalComparisonSelection
    private let savedBundle: ClientBundle?
    private let savedBytes: Data?
    private let lastRuntime: Data?
    private let sources: [String: (raw: Data, canonical: Data)]
    private let candidateIDs: Set<String>
    private var network: UInt64?
    private var original: IOSSpeedLabTunnel?
    private var invalidated = false

    init(model: RouterVPNModel) throws {
        guard !model.tunnelTransitioning, !model.iosUserDisconnectInProgress,
              !model.iosSpeedLabOwnership.active, !IOSMTUMeasurementGate.held,
              !IOSSpeedLabPersistenceJournal.active,
              !model.connected || model.activeSessionIdentity != nil else { throw CancellationError() }
        initial = try IOSExternalComparisonSelection(model); returned = initial
        savedBytes = UserDefaults.standard.data(forKey: "router-vpn.bundle")
        lastRuntime = UserDefaults.standard.data(forKey: "router-vpn.ios.last-runtime-v1")
        savedBundle = model.persistedNodeBundle
        let profiles = IOSNodeBundleStore.shared.profiles(current: savedBundle)
            .filter { $0.normalizedNodeKind == "external" }.sorted { $0.id < $1.id }
        guard !profiles.isEmpty, profiles.count <= 128, Set(profiles.map(\.id)).count == profiles.count else {
            throw IOSExternalNodeComparison.issue("Link between 1 and 128 distinct external nodes before comparing them.")
        }
        candidateIDs = Set(profiles.map(\.id))
        var captured: [String: (raw: Data, canonical: Data)] = [:], values: [IOSExternalComparisonCandidate] = []
        // Shared bundle records can contain many nodes. Intern their exact
        // source once and bound the entire immutable cohort before any stop,
        // rather than accepting 128 independent 32 MiB snapshots on a phone.
        let maximum = 64 * 1024 * 1024
        var retainedBytes = initial.bundle.count + (savedBytes?.count ?? 0) +
            (initial.identity?.bundleData.count ?? 0) + (initial.identity?.entryBundleData?.count ?? 0)
        var shared: [String: (Data, Data)] = [:]
        @MainActor func retain(_ count: Int) throws {
            guard retainedBytes <= maximum, count <= maximum - retainedBytes else {
                throw IOSExternalNodeComparison.issue("The saved paths exceed the 64 MiB comparison snapshot limit. Compare a smaller linked catalog.")
            }
            retainedBytes += count
        }
        @MainActor func retainSource(_ bytes: Data) throws -> (Data, Data) {
            guard !bytes.isEmpty, bytes.count <= 32 * 1024 * 1024 else { throw CancellationError() }
            let digest = IOSNodeUsage.digest(bytes)
            if let previous = shared[digest] {
                guard previous.0 == bytes else { throw CancellationError() }
                return previous
            }
            let canonical = try IOSNodeUsage.canonicalJSON(bytes)
            try retain(bytes.count + canonical.count)
            shared[digest] = (bytes, canonical)
            return (bytes, canonical)
        }
        try retain(0)
        for profile in profiles {
            guard let bytes = IOSNodeBundleStore.shared.bundleData(containing: profile.id, current: savedBundle),
                  !bytes.isEmpty, bytes.count <= 32 * 1024 * 1024 else { throw CancellationError() }
            captured[profile.id] = try retainSource(bytes)
            if profile.multihopEnabled == true, let entry = profile.multihopEntryID,
               let bytes = IOSNodeBundleStore.shared.bundleData(containing: entry, current: savedBundle) {
                captured[entry] = try retainSource(bytes)
            }
            let candidate = IOSExternalComparisonCandidate(profile: profile, stored: bytes, model: model)
            try retain((candidate.runtime?.count ?? 0) + (candidate.entry?.count ?? 0))
            values.append(candidate)
        }
        if let selected = model.selectedNodeProfile {
            for id in [selected.id, selected.multihopEnabled == true ? selected.multihopEntryID : nil].compactMap({ $0 }) {
                guard let bytes = IOSNodeBundleStore.shared.bundleData(containing: id, current: savedBundle) else { throw CancellationError() }
                captured[id] = try retainSource(bytes)
            }
        }
        sources = captured; candidates = values
    }

    func setNetwork(_ value: UInt64, model: RouterVPNModel) throws {
        guard network == nil, value > 0, try IOSExternalComparisonSelection(model) == initial,
              !model.iosSpeedLabOwnership.active else { throw CancellationError() }
        network = value; try requireFrozen(model: model)
    }

    func requireFrozen(model: RouterVPNModel, committing: Data? = nil) throws {
        guard !invalidated else { throw CancellationError() }
        do { try checkFrozen(model: model, committing: committing) }
        catch { invalidated = true; throw error }
    }

    private func checkFrozen(model: RouterVPNModel, committing: Data?) throws {
        guard let network, IOSViaEntryNetwork.shared.current == network,
              !model.iosUserDisconnectInProgress else { throw CancellationError() }
        let persisted = UserDefaults.standard.data(forKey: "router-vpn.bundle")
        guard persisted == savedBytes || (committing != nil && persisted == committing),
              UserDefaults.standard.data(forKey: "router-vpn.ios.last-runtime-v1") == lastRuntime,
              Set(IOSNodeBundleStore.shared.profiles(current: savedBundle)
                  .filter { $0.normalizedNodeKind == "external" }.map(\.id)) == candidateIDs else { throw CancellationError() }
        for (id, expected) in sources {
            guard let bytes = IOSNodeBundleStore.shared.bundleData(containing: id, current: savedBundle) else { throw CancellationError() }
            // Exact persisted bytes need no repeated JSON parse. Only the
            // legacy read-only projection may change key ordering on a read.
            if bytes != expected.raw {
                guard try IOSNodeUsage.canonicalJSON(bytes) == expected.canonical else { throw CancellationError() }
            }
        }
    }

    func observeSelection(_ expected: IOSExternalComparisonSelection, model: RouterVPNModel) throws {
        do {
            let current = try IOSExternalComparisonSelection(model)
            guard !invalidated, current.sameChoices(expected), current.decision == expected.decision else { throw CancellationError() }
        } catch { invalidated = true; throw error }
    }

    var networkGeneration: UInt64 { network ?? 0 }

    func requireReturned(model: RouterVPNModel) throws {
        try requireFrozen(model: model)
        guard !model.tunnelTransitioning, try IOSExternalComparisonSelection(model) == returned else { throw CancellationError() }
    }

    func captureOriginal(_ value: IOSSpeedLabTunnel, model: RouterVPNModel, owner: UUID) throws {
        try requireReturned(model: model)
        if let original { try value.requireSameRestorationSource(as: original, owner: owner) }
        else { original = value }
    }

    func restored(model: RouterVPNModel) throws {
        try requireFrozen(model: model)
        let next = try IOSExternalComparisonSelection(model)
        guard !model.tunnelTransitioning, next.sameChoices(initial), next.connected == initial.connected,
              next.identity?.engine == initial.identity?.engine,
              next.identity?.rawProfile == initial.identity?.rawProfile,
              next.identity?.bundleData == initial.identity?.bundleData,
              next.identity?.entryBundleData == initial.identity?.entryBundleData,
              next.identity?.entryMode == initial.identity?.entryMode else { throw CancellationError() }
        returned = next
    }
}

@MainActor private final class IOSExternalComparisonMeasured {
    let candidate: IOSExternalComparisonCandidate
    let record: IOSExternalNodeStatistics.Record
    let tunnel: IOSSpeedLabTunnel
    let selection: IOSExternalComparisonSelection
    init(_ candidate: IOSExternalComparisonCandidate, _ record: IOSExternalNodeStatistics.Record,
         _ tunnel: IOSSpeedLabTunnel, _ selection: IOSExternalComparisonSelection) {
        self.candidate = candidate; self.record = record; self.tunnel = tunnel; self.selection = selection
    }
}

/// One process owner keeps the batch, native drain, MTU lease and original
/// recovery together even if Performance is dismissed. Results have no later
/// Connect button: the explicit connect-fastest intent is captured at Start.
@MainActor final class IOSExternalNodeComparison: ObservableObject {
    static let shared = IOSExternalNodeComparison()
    @Published private(set) var running = false
    @Published private(set) var progress = ""
    @Published private(set) var error = ""
    @Published private(set) var rows: [IOSExternalComparisonRow] = []
    @Published private(set) var connectedWinner: String?
    private var task: Task<Void, Never>?
    private var transaction: IOSHopMeasurementTransaction?
    private var generation: UInt64 = 0

    static func available(_ model: RouterVPNModel) -> Bool {
        !model.tunnelTransitioning && !model.iosUserDisconnectInProgress &&
            !model.iosSpeedLabOwnership.active && !IOSMTUMeasurementGate.held && !IOSSpeedLabPersistenceJournal.active &&
            model.allNodeProfiles.contains { $0.normalizedNodeKind == "external" }
    }

    func start(model: RouterVPNModel, connectFastest: Bool) {
        guard !running, Self.available(model) else { return }
        rows = []; error = ""; connectedWinner = nil
        do {
            let cohort = try IOSExternalComparisonCohort(model: model)
            let round = generation
            running = true; progress = "Capturing one physical network and the saved external paths…"
            task = Task { @MainActor [self] in
                defer { running = false; task = nil; transaction = nil }
                await run(model: model, cohort: cohort, round: round, connectFastest: connectFastest)
            }
        } catch { self.error = error.localizedDescription }
    }

    func cancel() {
        generation &+= 1
        guard running else { return }
        transaction?.cancel(); task?.cancel()
        progress = "Cancelling the comparison; draining its exact native request and restoring the captured original…"
    }

    private func run(model: RouterVPNModel, cohort: IOSExternalComparisonCohort, round: UInt64, connectFastest: Bool) async {
        var committed: (adoption: IOSSpeedLabTunnel.Adoption, source: ClientBundle, usage: IOSNodeUsageOwner?, name: String)?
        var token: UUID?
        defer { if let token { model.iosSpeedLabOwnership.finish(token) } }
        do {
            let network = try await IOSViaEntryNetwork.shared.snapshot()
            try Task.checkCancellation(); guard generation == round else { throw CancellationError() }
            try cohort.setNetwork(network, model: model)
            let owner = try model.iosSpeedLabOwnership.begin { [weak self, weak model] in
                model?.iosConnectGeneration = UUID(); model?.iosStrategyTaskActive = false; self?.cancel()
            }
            token = owner
            try await IOSSpeedLabContext.$owner.withValue(owner) {
                try await IOSMTUControl.withHold(model: model) {
                    let lease = IOSMTUMeasurementGate.current
                    let lifecycle = IOSSpeedLabRunner()
                    @MainActor func current(committing: Data? = nil) throws {
                        try Task.checkCancellation(); try model.iosSpeedLabOwnership.require(owner)
                        guard self.generation == round, IOSMTUMeasurementGate.current == lease else { throw CancellationError() }
                        try cohort.requireFrozen(model: model, committing: committing)
                    }
                    // Retain only the best native restoration capability. All
                    // other results are public numbers, not private snapshots.
                    var winner: IOSExternalComparisonMeasured?
                    var validCount = 0
                    for candidate in cohort.candidates {
                        try current(); try cohort.requireReturned(model: model)
                        if let failure = candidate.failure {
                            rows.append(IOSExternalComparisonRow(id: candidate.id, name: candidate.name, trimmedMeanMS: nil, execution: nil, reason: failure))
                            continue
                        }
                        progress = "\(rows.count + 1)/\(cohort.candidates.count) • proving \(candidate.name)…"
                        do {
                            let value = try await lifecycle.withTemporaryProvedPath(model: model, borrowing: owner, lease: lease,
                                onSuperseded: { [weak self] in self?.cancel() },
                                validateBeforeStart: { try current(); try cohort.requireReturned(model: model) },
                                validateOriginal: { try cohort.captureOriginal($0, model: model, owner: owner) },
                                didRestore: { try current(); try cohort.restored(model: model) },
                                prepare: {
                                    try current()
                                    model.selectNode(candidate.id)
                                    try candidate.requireSelected(model, connected: false)
                                    await model.connectSelectedExternal()
                                    try current(); try candidate.requireSelected(model, connected: true)
                                }, measure: {
                                    try current(); try candidate.requireSelected(model, connected: true)
                                    let choice = try IOSExternalComparisonSelection(model)
                                    var captured = try IOSDNSMeasurementCapture(model: model)
                                    captured.network = cohort.networkGeneration
                                    guard let key = candidate.key, let requested = candidate.requested else { throw CancellationError() }
                                    let record = try await IOSExternalNodeBenchmark.measureHeld(model: model, owner: owner, captured: captured,
                                        stored: candidate.stored, key: key, requested: requested, saveResult: false, validate: {
                                            try cohort.observeSelection(choice, model: model)
                                            try current(); try candidate.requireSelected(model, connected: true)
                                        }, progress: { self.progress = candidate.name + " • " + $0 }, retained: { self.transaction = $0 })
                                    let selection = try IOSExternalComparisonSelection(model)
                                    let tunnel = try await IOSSpeedLabTunnel.capture(model: model, owner: owner)
                                    try cohort.observeSelection(choice, model: model)
                                    try current(); try captured.requireCurrent(model: model)
                                    guard try IOSExternalComparisonSelection(model) == selection else { throw CancellationError() }
                                    try tunnel.requireMeasuredExecution(requested: requested, selected: record.path.execution.selected)
                                    return IOSExternalComparisonMeasured(candidate, record, tunnel, selection)
                                })
                            try current(); try cohort.requireReturned(model: model)
                            _ = try IOSExternalNodeStatistics.save(key: value.record.key, benchmark: value.record.benchmark,
                                path: value.record.path, at: value.record.measuredAt)
                            try current(); try cohort.requireReturned(model: model)
                            validCount += 1
                            if winner == nil || value.record.benchmark.trimmed_mean_ms < winner!.record.benchmark.trimmed_mean_ms ||
                                value.record.benchmark.trimmed_mean_ms == winner!.record.benchmark.trimmed_mean_ms && value.candidate.id < winner!.candidate.id {
                                winner = value
                            }
                            rows.append(IOSExternalComparisonRow(id: candidate.id, name: candidate.name,
                                trimmedMeanMS: value.record.benchmark.trimmed_mean_ms, execution: value.record.path.execution.selected, reason: ""))
                        } catch {
                            // A failed candidate receives no score. A changed
                            // cohort or incomplete restoration aborts the batch.
                            try current(); try cohort.requireReturned(model: model)
                            rows.append(IOSExternalComparisonRow(id: candidate.id, name: candidate.name,
                                trimmedMeanMS: nil, execution: nil, reason: "The path could not retain a valid 50-response result after checked restoration, or its private result could not be saved."))
                        }
                    }
                    try current(); try cohort.requireReturned(model: model)
                    rows.sort { left, right in
                        if let a = left.trimmedMeanMS, let b = right.trimmedMeanMS { return a == b ? left.id < right.id : a < b }
                        if left.trimmedMeanMS != nil { return true }; if right.trimmedMeanMS != nil { return false }
                        return left.id < right.id
                    }
                    guard let winner else {
                        progress = "No external path earned a valid score. The original connection and selection were restored."
                        return
                    }
                    guard connectFastest else {
                        progress = "Compared \(validCount) valid external paths using the same 50-response metric. Fastest: \(winner.candidate.name). The original connection and selection were restored."
                        return
                    }
                    var adoption: IOSSpeedLabTunnel.Adoption?
                    progress = "Re-proving \(winner.candidate.name) with its measured \(winner.record.path.execution.selected) execution…"
                    try await lifecycle.withTemporaryProvedPath(model: model, borrowing: owner, lease: lease,
                        onSuperseded: { [weak self] in self?.cancel() },
                        validateBeforeStart: { try current(); try cohort.requireReturned(model: model) },
                        validateOriginal: { try cohort.captureOriginal($0, model: model, owner: owner) },
                        didRestore: { try current(); try cohort.restored(model: model) }, retainOnSuccess: true,
                        adoptionCommitted: { committed != nil },
                        retireAdoption: { try await adoption?.retire(model: model) },
                        prepare: {
                            try current()
                            try model.importBundle(winner.selection.bundle)
                            model.selectedMode = winner.selection.mode; model.selectedLogicalMode = winner.selection.logicalMode
                            model.auto = winner.selection.automatic
                            try winner.candidate.requireSelected(model, connected: false)
                            try await winner.tunnel.restore(model: model, owner: owner, reconnect: true)
                            try current(); try winner.candidate.requireSelected(model, connected: true)
                            guard model.activeSessionIdentity != winner.tunnel.identity else { throw CancellationError() }
                        }, measure: {
                            try current(); try winner.candidate.requireSelected(model, connected: true)
                            let selection = try IOSExternalComparisonSelection(model)
                            let fresh = try await IOSSpeedLabTunnel.capture(model: model, owner: owner)
                            try current()
                            try fresh.requireSameRestorationSource(as: winner.tunnel, owner: owner)
                            try fresh.requireMeasuredExecution(requested: winner.record.path.execution.requested,
                                                               selected: winner.record.path.execution.selected)
                            let binding = try await IOSMTUControl.capture(model)
                            let id = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
                            let reply = try await IOSMTUControl.send(binding.connection, operation: "hop-measure-info", request: id, session: "")
                            let info = try IOSHopMeasurementBinding.decode(reply, request: id, mtuSession: binding.session)
                            let path = try IOSExternalNodeStatistics.PathReceipt(binding: info,
                                requested: winner.record.path.execution.requested, network: cohort.networkGeneration)
                            try current(); try winner.candidate.requireSelected(model, connected: true)
                            guard IOSMTUControl.current(binding, model: model), info.node_id == winner.candidate.id,
                                  path.execution.selected == winner.record.path.execution.selected,
                                  path.sessionDigest != winner.record.path.sessionDigest,
                                  try IOSExternalComparisonSelection(model) == selection else { throw CancellationError() }
                            let captured = try await IOSSpeedLabTunnel.captureAdoption(model: model, owner: owner, expected: fresh)
                            adoption = captured
                            @MainActor func requireAdoption(committing: Data? = nil) throws {
                                try current(committing: committing); try captured.requireCurrent(model: model)
                                try winner.candidate.requireSelected(model, connected: true)
                                guard try IOSExternalComparisonSelection(model) == selection else { throw CancellationError() }
                            }
                            try requireAdoption()
                            try await captured.releaseTemporaryMarker(model: model) { try requireAdoption() }
                            try requireAdoption(); try captured.requireCurrent(model: model, released: true)
                            guard let source = model.bundle else { throw CancellationError() }
                            let saved = try IOSNodeUsage.canonical(source)
                            let usage = model.captureIOSNodeUsageOwner(captured.manager)
                            try IOSSpeedLabPersistenceJournal.commitSelection(owner: owner, bundle: saved, retainsOwnership: {
                                // Cancellation still permits repair of this
                                // same adoption; newer user/native ownership
                                // never permits reinstating an old receipt.
                                do {
                                    try captured.requireCurrent(model: model)
                                    try winner.candidate.requireSelected(model, connected: true)
                                    return try IOSExternalComparisonSelection(model) == selection
                                } catch { return false }
                            }) {
                                try requireAdoption(committing: saved); try captured.requireCurrent(model: model, released: true)
                            }
                            // No suspension or cancellation boundary between
                            // durable commit and this terminal receipt.
                            committed = (captured, source, usage, winner.candidate.name)
                            self.connectedWinner = winner.candidate.id
                        })
                }
            }
        } catch {
            if committed != nil {
                self.error = "The fastest path and selection were committed; final measurement-hold cleanup was not confirmed: " + error.localizedDescription
            } else if error is CancellationError {
                self.error = "Comparison cancelled or its captured source, network, user selection or native owner changed. No winner was adopted."
            } else { self.error = "Comparison did not adopt a winner: " + error.localizedDescription }
            if committed == nil, IOSSpeedLabPersistenceJournal.active {
                self.error += " Original-state recovery remains pending. Inspect the active connection or Disconnect before retrying."
            }
        }
        if let committed {
            if (try? committed.adoption.requireCurrent(model: model, released: true)) != nil {
                progress = "Connected to \(committed.name) after fresh path proof. Its measured execution and saved selection were retained."
            } else {
                progress = "\(committed.name) was proved and saved; a later action or native change replaced that connection."
            }
        }
        if let token { model.iosSpeedLabOwnership.finish(token) }
        if let committed {
            // Optional usage runs once after the temporary owner is gone. It
            // still requires this exact final manager, policy and generation;
            // a replacement cannot receive the old adoption's usage credit.
            await Task { @MainActor in
                model.recordIOSNodeUsage(manager: committed.adoption.manager, source: committed.source,
                    generation: committed.adoption.generation, expected: committed.usage)
            }.value
        }
    }

    static func issue(_ text: String) -> NSError {
        NSError(domain: "RouterVPN.ExternalComparison", code: 1, userInfo: [NSLocalizedDescriptionKey: text])
    }
}
