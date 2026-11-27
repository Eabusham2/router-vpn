import Foundation

/// A disconnected comparison owns one complete saved Local graph. Its native
/// measurement authority ends before any future-profile choice is published.
/// The retained owner survives a disappearing view and holds MTU through DOWN.
@MainActor final class IOSNodeCandidatePreparation {
    private(set) static var retained: IOSNodeCandidatePreparation?
    static var busy: Bool { retained.map { !$0.retired } ?? false }
    static func testing(_ model: RouterVPNModel) -> Bool { retained.map { $0.model === model && !$0.retired } ?? false }
    static func testingNodeIDs(_ model: RouterVPNModel) -> Set<String>? {
        guard let value = retained, value.model === model, !value.retired else { return nil }
        let count = value.prefixCandidate.map { $0.prefix.position + 1 } ?? value.prefixes.count
        return Set(value.prefixes.prefix(count).map(\.profile_id))
    }
    static func cancel(_ model: RouterVPNModel) { if retained?.model === model { retained?.cancel() } }

    let owner = UUID()
    let bundle: ClientBundle
    let launchInput: String
    let sourceSHA256: String
    let configSHA256: String
    let prefixes: [IOSNodeCandidatePrefix]
    let selectedDraft: IOSNodeCandidateDraftExecution?
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
    private let appendCurrent: (@MainActor () throws -> Void)?
    private let appendDeviceMTU: IOSDeviceMTUPreference?

    private enum Purpose {
        case local(IOSNodeCandidateOriginalCapture)
        case selected(IOSNodeCandidateDraftExecution)
    }

    private init(model: RouterVPNModel, bundle: ClientBundle, purpose: Purpose,
                 prefixPosition: Int?, request: String?, completeFinalSource: Bool = false,
                 appendCurrent: (@MainActor () throws -> Void)? = nil, onCancelled: @escaping @MainActor () -> Void) throws {
        self.model = model; self.bundle = bundle; self.onCancelled = onCancelled; self.appendCurrent = appendCurrent
        if case .local(let capture) = purpose { appendDeviceMTU = capture.appendSource?.deviceMTU }
        else { appendDeviceMTU = nil }
        switch purpose {
        case .local(let capture):
            selectedDraft = nil
            launchInput = capture.launchInput; sourceSHA256 = capture.sourceSHA256; configSHA256 = capture.configSHA256
            prefixes = prefixPosition != nil && (completeFinalSource || capture.isAppend) ? capture.preparedCandidatePrefixes : capture.candidatePrefixes
        case .selected(let draft):
            selectedDraft = draft
            launchInput = draft.launchInput; sourceSHA256 = draft.sourceSHA256; configSHA256 = draft.configSHA256
            prefixes = draft.prefixes
        }
        originalBundle = try IOSNodeUsage.canonical(model.bundle)
        persistedBundle = UserDefaults.standard.data(forKey: "router-vpn.bundle")
        lastRuntime = UserDefaults.standard.data(forKey: "router-vpn.ios.last-runtime-v1")
        selection = try Self.selection(model); initialDecision = model.iosConnectGeneration
        let snapshot = try IOSNodeBundleStore.shared.candidateSnapshot()
        records = snapshot.records; stamp = snapshot.stamp
        if case .local(let capture) = purpose, let position = prefixPosition, let request {
            let candidate = try IOSNodeCandidateCapture.make(request: request, prefixPosition: position,
                proofs: prefixes, chainSource: sourceSHA256, chainConfig: configSHA256,
                originalLaunch: Data(capture.launchInput.utf8), preparedResponse: true)
            do {
                let prefix = try IOSNodeCandidatePrefixCapture.compile(original: capture, position: position,
                    inventory: String(decoding: candidate.source.inventory.data, as: UTF8.self))
                prefixCapture = prefix
                prefixCandidate = IOSNodeCandidateCapture(source: candidate.source, records: candidate.records,
                    rows: candidate.rows, prefix: candidate.prefix, chainSource: prefix.sourceSHA256, chainConfig: prefix.configSHA256)
            } catch { try? IOSCandidateCatalogPublication.shared.remove(candidate.source); throw error }
        } else {
            guard selectedDraft != nil || prefixPosition == nil && request == nil else { throw CancellationError() }
            prefixCapture = nil; prefixCandidate = nil
        }
    }

    static func reserve(model: RouterVPNModel, prefixPosition: Int? = nil, request: String? = nil, editorBundle: ClientBundle? = nil, editorNodes: [IOSMultihopNodeSelection]? = nil, onCancelled: @escaping @MainActor () -> Void) throws -> IOSNodeCandidatePreparation {
        guard retained == nil, !model.connected, !model.tunnelTransitioning,
              !model.iosUserDisconnectInProgress, !model.iosSpeedLabOwnership.active,
              !IOSMTUMeasurementGate.held, let selection = model.bundle,
              editorBundle == nil || prefixPosition != nil && request != nil,
              let bundle = editorBundle ?? model.bundle, bundle.selectedRouterID == selection.selectedRouterID,
              let selected = IOSDNSRuntimePolicy.selectedProfile(in: bundle),
              selected.multihopNodes != nil else { throw CancellationError() }
        let value: IOSNodeCandidatePreparation
        if selected.multihopExecution == "local" {
            let capture = try model.captureIOSCandidateOriginal(bundle)
            defer { try? capture.close() }
            guard !capture.requiresIndependentPrefix || prefixPosition != nil && request != nil else { throw CancellationError() }
            value = try Self(model: model, bundle: bundle, purpose: .local(capture), prefixPosition: prefixPosition, request: request,
                completeFinalSource: editorBundle == nil || selected.multihopNodes == editorNodes, onCancelled: onCancelled)
        } else {
            guard editorBundle != nil, ["server", "auto"].contains(selected.multihopExecution ?? ""),
                  let position = prefixPosition, let request else { throw CancellationError() }
            let draft = try IOSNodeCandidateDraftExecution(model: model, bundle: bundle, position: position, request: request)
            value = try Self(model: model, bundle: bundle, purpose: .selected(draft), prefixPosition: position, request: request, onCancelled: onCancelled)
        }
        return try publishReservation(value, model: model)
    }

    static func reserveAppend(model: RouterVPNModel, nodes: [IOSMultihopNodeSelection],
                              editorOwner: IOSNodeChainEditorOwner, nextKind: String, nextMode: String, draftRevision: String,
                              request: String, current: @escaping @MainActor () throws -> Void,
                              onCancelled: @escaping @MainActor () -> Void) throws -> IOSNodeCandidatePreparation {
        guard retained == nil, !model.connected, !model.tunnelTransitioning,
              !model.iosUserDisconnectInProgress, !model.iosSpeedLabOwnership.active,
              !IOSMTUMeasurementGate.held, let bundle = model.bundle else { throw CancellationError() }
        try current()
        try model.requireIOSNodeChainAppendSources(editorOwner, nodes: nodes)
        let snapshot = try IOSNodeBundleStore.shared.candidateSnapshot()
        guard snapshot.stamp.ready, let control = editorOwner.fingerprints[editorOwner.controlID] else { throw CancellationError() }
        let deviceRevision = "ios-device-" + IOSCandidateCatalogPublication.digest(Data((control + ":" + snapshot.stamp.revision).utf8))
        let capture = try IOSNodeCandidateAppendSource.compile(deviceBundle: IOSNodeUsage.canonical(bundle),
            records: snapshot.records, nodes: nodes, nextKind: nextKind, nextMode: nextMode, draftRevision: draftRevision,
            deviceRevision: deviceRevision, deviceMTU: IOSDeviceMTUPreference.current())
        let value = try Self(model: model, bundle: bundle, purpose: .local(.append(capture)),
            prefixPosition: nodes.count - 1, request: request, appendCurrent: current, onCancelled: onCancelled)
        do {
            try current()
            try model.requireIOSNodeChainAppendSources(editorOwner, nodes: nodes)
        } catch {
            try? value.prefixCapture?.native.close()
            if let candidate = value.prefixCandidate { try? IOSCandidateCatalogPublication.shared.remove(candidate.source) }
            throw error
        }
        return try publishReservation(value, model: model)
    }

    private static func publishReservation(_ value: IOSNodeCandidatePreparation, model: RouterVPNModel) throws -> IOSNodeCandidatePreparation {
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
            try appendCurrent?()
            try appendDeviceMTU?.requireCurrent()
            try selectedDraft?.requireOriginal()
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
        if let selectedDraft {
            try await selectedDraft.start(model: model, bundle: bundle) { [self] in
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
        guard let root = try JSONSerialization.jsonObject(with: IOSNodeUsage.canonical(bundle)) as? [String: Any],
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
        } else if let selectedDraft {
            try selectedDraft.requireLive(model)
        } else {
            guard model.connected, !model.tunnelTransitioning,
                  let identity = model.activeSessionIdentity, identity.engine == "multihop-libbox",
                  identity.nodeChainSource == Data(launchInput.utf8) else { throw CancellationError() }
        }
    }

    func originalForProposal() throws -> IOSNodeCandidateOriginalCapture {
        try requireLive()
        guard selectedDraft == nil else { throw CancellationError() }
        return try IOSNodeCandidateOriginalCapture.reopen(launchInput, selectedProfile: selectedProfile())
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
                    if let selectedDraft {
                        try await original.retireNewCandidateManager(model: model, owner: owner, input: selectedDraft.launchInput)
                    }
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
    var iosCandidateTestingNodeIDs: Set<String>? { IOSNodeCandidatePreparation.testingNodeIDs(self) }
    func cancelCandidateTesting() { IOSNodeCandidatePreparation.cancel(self) }
}
