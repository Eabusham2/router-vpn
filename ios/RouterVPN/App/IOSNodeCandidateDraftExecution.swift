import Foundation

/// The editor's full Server or Compare trial has its own complete source and
/// eligible packet stop. It never opens the Local prefix-only provider.
@MainActor final class IOSNodeCandidateDraftExecution {
    let launchInput: String, sourceSHA256: String, configSHA256: String
    let prefixes: [IOSNodeCandidatePrefix]
    let position: Int
    private let request: String, requested: String, positions: [Int]
    private let deviceMTU: IOSDeviceMTUPreference
    private let originalLast: Data?
    private let draftBundle: Data
    private var session: IOSSessionIdentity?
    private var winner: String?
    private var liveInvalidated = false

    init(model: RouterVPNModel, bundle: ClientBundle, position: Int, request: String) throws {
        let route = try model.captureIOSOrderedRoute(bundle)
        defer { try? route.close() }
        guard case .execution(let execution) = route,
              IOSCandidateCatalogPublication.validRequest(request),
              execution.candidatePositions(for: execution.requested == "server" ? "server" : "local").contains(position),
              execution.launchInput == execution.ordinaryLaunchInput else { throw CancellationError() }
        _ = try IOSRuntimeSelector.selectNodeChain(route)
        launchInput = execution.launchInput; sourceSHA256 = execution.sourceSHA256; configSHA256 = execution.configSHA256
        let responses = execution.responsePositions(for: execution.requested == "server" ? "server" : "local")
        prefixes = execution.members.enumerated().map { position, member in
            IOSNodeCandidatePrefix(position: position, profile_id: member.id,
                node_id: member.profile["node_proof_id"] as? String ?? "", mode: member.mode,
                measurement: responses.contains(position) ? "routed-candidate-response" : nil)
        }
        draftBundle = try IOSNodeUsage.canonical(bundle)
        self.position = position; self.request = request
        requested = execution.requested; positions = execution.candidatePositions(for: execution.requested == "server" ? "server" : "local")
        deviceMTU = try .current(); originalLast = try IOSNodeChainExecutionLastStore.snapshot()
    }

    /// Ordinary Connect still requires equality with the saved form. A temporary
    /// draft may reach preference readback only through its retained operation.
    func requireStaged(model: RouterVPNModel, bundle: ClientBundle, input: String) throws {
        guard let owner = IOSNodeCandidatePreparation.retained, owner.selectedDraft === self,
              IOSSpeedLabContext.owner == owner.owner, model.iosSpeedLabOwnership.current(owner.owner),
              input == launchInput, model.bundle?.selectedRouterID == bundle.selectedRouterID,
              try IOSNodeUsage.canonical(bundle) == draftBundle else { throw CancellationError() }
        try requireOriginal()
    }

    func requireOriginal() throws {
        try deviceMTU.requireCurrent()
        guard try IOSNodeChainExecutionLastStore.snapshot() == originalLast else { throw CancellationError() }
    }

    func start(model: RouterVPNModel, bundle: ClientBundle,
               current: @escaping @MainActor @Sendable () throws -> Void) async throws {
        try current()
        let route = try model.captureIOSOrderedRoute(bundle)
        defer { try? route.close() }
        guard case .execution(let execution) = route, execution.launchInput == launchInput,
              execution.requested == requested, execution.sourceSHA256 == sourceSHA256,
              execution.configSHA256 == configSHA256, execution.candidatePositions(for: execution.requested == "server" ? "server" : "local") == positions else { throw CancellationError() }
        try await model.connectCandidatePreparation(route, bundle: bundle, draft: self, current: current)
        try requireLive(model)
    }

    func requireLive(_ model: RouterVPNModel) throws {
        guard !liveInvalidated, model.connected, !model.tunnelTransitioning, let identity = model.activeSessionIdentity,
              identity.engine == "multihop-libbox", identity.nodeChainSource == nil,
              identity.nodeChainExecutionSource == Data(launchInput.utf8),
              let observed = model.orderedExecutionObservation, observed.identity == identity,
              observed.requested == requested, ["local", "server"].contains(observed.selected),
              requested == "auto" || requested == observed.selected,
              session == nil || session == identity, winner == nil || winner == observed.selected else {
            liveInvalidated = true
            throw CancellationError()
        }
        session = identity; winner = observed.selected
    }

    func requireInformation(_ info: IOSNodeCandidates.Info, owner: String, position: Int) throws {
        guard !liveInvalidated, session != nil, let winner, owner == request, position == self.position,
              info.proofs == prefixes, info.candidate_positions == positions,
              info.requested_execution == requested, info.execution == winner,
              info.source_sha256 == sourceSHA256, info.proposal_source_sha256 == sourceSHA256,
              info.proposal_config_sha256 == configSHA256,
              IOSCandidateCatalogPublication.isDigest(info.config_sha256) else { throw CancellationError() }
    }
}
