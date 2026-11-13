import Foundation

/// A disconnected comparison owns one complete saved Local graph. Its native
/// measurement authority ends before any future-profile choice is published.
/// The retained owner survives a disappearing view and holds MTU through DOWN.
@MainActor final class IOSNodeCandidatePreparation {
    private(set) static var retained: IOSNodeCandidatePreparation?
    static var busy: Bool { retained.map { !$0.retired } ?? false }
    static func testing(_ model: RouterVPNModel) -> Bool { retained.map { $0.model === model && !$0.retired } ?? false }
    static func cancel(_ model: RouterVPNModel) { if retained?.model === model { retained?.cancel() } }

    let owner = UUID()
    let bundle: ClientBundle
    let launchInput: String
    let sourceSHA256: String
    let configSHA256: String
    let prefixes: [IOSNodeCandidatePrefix]
    let prefixCapture: IOSNodeCandidatePrefixCapture?
    let prefixCandidate: IOSNodeCandidateCapture?
    let prefixEpoch = UUID()
    private(set) var prefixBinding: IOSNodeCandidatePrefixBinding?
    private let model: RouterVPNModel
    private let originalBundle: Data
    private let persistedBundle: Data?
    private let lastRuntime: Data?
    private let selection: Data
    private let records: [String: Data]
    private let stamp: IOSCandidateCatalogPublication.Stamp
    private let initialDecision: UUID
    private var returnedDecision: UUID?
    private var network: UInt64?
    private var original: IOSSpeedLabTunnel?
    private var candidate: IOSNodeCandidateTransaction?
    private var outerHold: IOSMTUMeasurementGate.Lease?
    private struct Sealed { let measured: Int64; let expires: Int64; let deadline: TimeInterval }
    private var sealed: [UUID: Sealed] = [:]
    private var invalidated = false
    private(set) var retired = false
    private var launching = false
    private let onCancelled: @MainActor () -> Void

    private init(model: RouterVPNModel, bundle: ClientBundle, capture: IOSNodeChainCapture,
                 prefixPosition: Int?, request: String?, onCancelled: @escaping @MainActor () -> Void) throws {
        self.model = model; self.bundle = bundle; self.onCancelled = onCancelled
        launchInput = capture.launchInput; sourceSHA256 = capture.sourceSHA256; configSHA256 = capture.configSHA256
        prefixes = capture.members.enumerated().map { position, member in
            IOSNodeCandidatePrefix(position: position, profile_id: member.id,
                node_id: member.profile["node_proof_id"] as? String ?? "", mode: member.mode)
        }
        originalBundle = try IOSNodeUsage.canonical(bundle)
        persistedBundle = UserDefaults.standard.data(forKey: "router-vpn.bundle")
        lastRuntime = UserDefaults.standard.data(forKey: "router-vpn.ios.last-runtime-v1")
        selection = try Self.selection(model); initialDecision = model.iosConnectGeneration
        let snapshot = try IOSNodeBundleStore.shared.candidateSnapshot()
        records = snapshot.records; stamp = snapshot.stamp
        if let position = prefixPosition, let request {
            let candidate = try IOSNodeCandidateCapture.make(request: request, prefixPosition: position,
                proofs: capture.members.enumerated().map { IOSNodeCandidatePrefix(position: $0.offset,
                    profile_id: $0.element.id, node_id: $0.element.profile["node_proof_id"] as? String ?? "", mode: $0.element.mode) },
                chainSource: capture.sourceSHA256, chainConfig: capture.configSHA256)
            do {
                let prefix = try IOSNodeCandidatePrefixCapture.compile(original: capture, position: position,
                    inventory: String(decoding: candidate.source.inventory.data, as: UTF8.self))
                prefixCapture = prefix
                prefixCandidate = IOSNodeCandidateCapture(source: candidate.source, records: candidate.records,
                    rows: candidate.rows, prefix: candidate.prefix, chainSource: prefix.sourceSHA256, chainConfig: prefix.configSHA256)
            } catch { try? IOSCandidateCatalogPublication.shared.remove(candidate.source); throw error }
        } else {
            guard prefixPosition == nil, request == nil else { throw CancellationError() }
            prefixCapture = nil; prefixCandidate = nil
        }
    }

    static func reserve(model: RouterVPNModel, prefixPosition: Int? = nil, request: String? = nil, onCancelled: @escaping @MainActor () -> Void) throws -> IOSNodeCandidatePreparation {
        guard retained == nil, !model.connected, !model.tunnelTransitioning,
              !model.iosUserDisconnectInProgress, !model.iosSpeedLabOwnership.active,
              !IOSMTUMeasurementGate.held, let bundle = model.bundle,
              let selected = IOSDNSRuntimePolicy.selectedProfile(in: bundle),
              selected.multihopNodes != nil, selected.multihopExecution == "local" else { throw CancellationError() }
        let capture = try model.captureIOSNodeChain(bundle)
        defer { try? capture.plan.close() }
        _ = try IOSRuntimeSelector.selectNodeChain(capture)
        let value = try Self(model: model, bundle: bundle, capture: capture, prefixPosition: prefixPosition, request: request, onCancelled: onCancelled)
        do { _ = try model.iosSpeedLabOwnership.begin(owner: value.owner) { [weak value] in value?.cancel() } }
        catch {
            try? value.prefixCapture?.native.close()
            if let candidate = value.prefixCandidate { try? IOSCandidateCatalogPublication.shared.remove(candidate.source) }
            throw error
        }
        value.outerHold = IOSMTUMeasurementGate.acquire()
        retained = value; model.objectWillChange.send()
        return value
    }

    private static func selection(_ model: RouterVPNModel) throws -> Data {
        try JSONSerialization.data(withJSONObject: [
            "mode": model.selectedMode, "logical": model.selectedLogicalMode, "auto": model.auto,
            "base": model.basePreference, "fallback": model.baseFallback, "lan": model.homeLANAccess,
            "cidrs": model.homeLANCIDRs, "daita": model.daita, "jumbo": model.jumbo,
            "name": model.routerName, "endpoint": model.endpoint, "api": model.routerAPI,
            "token": model.apiToken, "socks_host": model.socksHost, "socks_port": model.socksPort,
            "socks_user": model.socksUsername, "socks_secret": model.socksPassword
        ], options: [.sortedKeys])
    }

    private func requireFrozen() throws {
        guard !invalidated else { throw CancellationError() }
        do {
            guard Self.retained === self, try Self.selection(model) == selection,
                  try IOSNodeUsage.canonical(model.bundle) == originalBundle,
                  UserDefaults.standard.data(forKey: "router-vpn.bundle") == persistedBundle,
                  UserDefaults.standard.data(forKey: "router-vpn.ios.last-runtime-v1") == lastRuntime,
                  network == nil || IOSViaEntryNetwork.shared.current == network else { throw CancellationError() }
            let now = try IOSNodeBundleStore.shared.candidateSnapshot()
            guard now.records == records, now.stamp == stamp else { throw CancellationError() }
            if !retired { try prefixCandidate?.requireCurrent() }
        } catch { invalidated = true; throw error }
    }

    func start() async throws {
        try requireFrozen(); try model.iosSpeedLabOwnership.require(owner)
        guard !launching, !retired, model.iosConnectGeneration == initialDecision,
              !model.connected, !model.tunnelTransitioning else { throw CancellationError() }
        network = try await IOSViaEntryNetwork.shared.snapshot()
        try requireFrozen(); try model.iosSpeedLabOwnership.require(owner)
        original = try await IOSSpeedLabTunnel.capture(model: model, owner: owner)
        guard original?.identity == nil else { throw CancellationError() }
        try requireFrozen(); launching = true
        if let prefixCapture, let candidate = prefixCandidate {
            prefixBinding = try await model.connectCandidatePrefix(prefixCapture, bundle: bundle,
                owner: owner, epoch: prefixEpoch, request: candidate.source.request) { [self] in
                try requireFrozen(); try model.iosSpeedLabOwnership.require(owner)
            }
            try requireLive()
            return
        }
        let capture = try IOSNodeChainCapture.reopen(launchInput, selectedProfile: try selectedProfile())
        defer { try? capture.plan.close() }
        try await model.connectCandidatePreparation(capture, bundle: bundle) { [self] in
            try requireFrozen(); try model.iosSpeedLabOwnership.require(owner)
        }
        try requireLive()
    }

    private func selectedProfile() throws -> [String: Any] {
        guard let root = try JSONSerialization.jsonObject(with: originalBundle) as? [String: Any],
              let id = root["selectedRouterID"] as? String,
              let profiles = root["routerProfiles"] as? [[String: Any]],
              profiles.filter({ $0["id"] as? String == id }).count == 1,
              let value = profiles.first(where: { $0["id"] as? String == id }) else { throw CancellationError() }
        return value
    }

    func requireLive() throws {
        try requireFrozen(); try model.iosSpeedLabOwnership.require(owner)
        guard !retired, launching, outerHold != nil else { throw CancellationError() }
        if prefixCapture != nil {
            guard let prefixBinding else { throw CancellationError() }
            try prefixBinding.require(model)
        } else {
            guard model.connected, !model.tunnelTransitioning,
                  let identity = model.activeSessionIdentity, identity.engine == "multihop-libbox",
                  identity.nodeChainSource == Data(launchInput.utf8) else { throw CancellationError() }
        }
    }

    func originalForProposal() throws -> IOSNodeChainCapture {
        try requireLive()
        return try IOSNodeChainCapture.reopen(launchInput, selectedProfile: selectedProfile())
    }

    func bind(_ value: IOSNodeCandidateTransaction) throws {
        try requireLive()
        guard candidate == nil else { throw CancellationError() }
        candidate = value
    }

    /// Called only after live result validation and the complete proposal attempt.
    /// Unsupported future routes keep timing identity without gaining Save.
    func seal(token: UUID, measured: Int64, expires: Int64) throws {
        try requireLive()
        let now = Int64(Date().timeIntervalSince1970 * 1000)
        guard measured > 0, measured <= now, expires > now, expires - measured == 120000, sealed[token] == nil else { throw CancellationError() }
        sealed[token] = Sealed(measured: measured, expires: expires, deadline: ProcessInfo.processInfo.systemUptime + Double(expires - now) / 1000)
    }

    func requireSaved(token: UUID) throws {
        try requireFrozen()
        guard retired, let decision = returnedDecision, model.iosConnectGeneration == decision,
              !model.connected, !model.tunnelTransitioning, !model.iosUserDisconnectInProgress,
              model.activeSessionIdentity == nil, !model.iosSpeedLabOwnership.active,
              let value = sealed[token], Int64(Date().timeIntervalSince1970 * 1000) >= value.measured,
              Int64(Date().timeIntervalSince1970 * 1000) < value.expires,
              ProcessInfo.processInfo.systemUptime < value.deadline else { throw CancellationError() }
    }

    func cancel() {
        guard !invalidated else { return }
        invalidated = true; sealed.removeAll(); onCancelled()
    }

    /// Run in an uncancelled task. Failed or unknown shutdown retains this
    /// exact owner and outer MTU lease; neither a timeout nor Cancel is DOWN.
    func retire() async {
        if retired { return }
        if let candidate { await candidate.close() }
        while model.iosSpeedLabOwnership.owns(owner) {
            do {
                if model.iosSpeedLabOwnership.userDisconnected(owner) {
                    await model.refreshTunnelStatus()
                    guard !model.connected, !model.tunnelTransitioning, !model.iosUserDisconnectInProgress else { throw CancellationError() }
                } else {
                    try await IOSSpeedLabTunnel.stopTemporary(model: model, owner: owner)
                }
                guard !model.connected, !model.tunnelTransitioning, model.activeSessionIdentity == nil else { throw CancellationError() }
                if let original, model.iosSpeedLabOwnership.mayRestoreSelection(owner) {
                    try await original.restore(model: model, owner: owner, reconnect: false)
                }
                guard !model.connected, !model.tunnelTransitioning, model.activeSessionIdentity == nil else { throw CancellationError() }
                returnedDecision = model.iosConnectGeneration
                retired = true
                try? prefixCapture?.native.close()
                if let candidate = prefixCandidate {
                    try? IOSCandidateCatalogPublication.shared.remove(candidate.source)
                    try? IOSCandidateCatalogPublication.shared.acknowledgeClosed(epoch: prefixEpoch.uuidString, request: candidate.source.request)
                }
                if let hold = outerHold { _ = IOSMTUMeasurementGate.release(hold); outerHold = nil }
                model.iosSpeedLabOwnership.finish(owner); model.objectWillChange.send()
                return
            } catch {
                model.message = "Testing cleanup is still pending. Disconnect remains available."
                try? await Task.sleep(for: .milliseconds(150))
            }
        }
    }

    func closeResults() {
        guard retired, Self.retained === self else { return }
        invalidated = true; sealed.removeAll(); Self.retained = nil; model.objectWillChange.send()
    }
}

@MainActor extension RouterVPNModel {
    var iosCandidateTesting: Bool { IOSNodeCandidatePreparation.testing(self) }
    func cancelCandidateTesting() { IOSNodeCandidatePreparation.cancel(self) }
}
