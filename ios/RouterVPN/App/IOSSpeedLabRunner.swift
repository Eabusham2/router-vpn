import Foundation

struct IOSSpeedLabRunRequest: Hashable {
    enum Scope: String, CaseIterable, Identifiable {
        case current
        case temporary
        var id: String { rawValue }
    }

    enum Topology: String, CaseIterable, Identifiable {
        case systemDirect = "system-direct"
        case router
        case external
        case multihop
        var id: String { rawValue }
    }

    var scope: Scope = .current
    var topology: Topology = .systemDirect
    var nodeID: String = ""
    var mode: String = "smart-auto"
    var customLayers: [String] = []
    var requireEncrypted = false
    var requireObfuscation = false
    var duration: IOSSpeedLabDuration = .automatic
}

struct IOSSpeedLabRunResult: Hashable {
    let path: String
    let temporary: Bool
    let measurement: IOSSpeedLabMeasurement

    var detail: String { "Path: \(path)\n\(measurement.detailedSummary)" }
}

@MainActor
final class IOSSpeedLabRunner: ObservableObject {
    @Published private(set) var running = false
    @Published private(set) var progress = "Ready"
    @Published private(set) var lastResult: IOSSpeedLabRunResult?
    @Published private(set) var lastError = ""
    private var activeTask: Task<IOSSpeedLabRunResult, Error>?

    private struct ModelSnapshot {
        let bundleData: Data?
        let selectedLogicalMode: String
        let selectedMode: String
        let auto: Bool
        let message: String
    }

    private struct PathToken: Equatable {
        let connected: Bool
        let nodeID: String
        let engine: String
        let rawProfile: String
        let transitioning: Bool
        let sessionIdentity: IOSSessionIdentity?
    }

    func run(_ request: IOSSpeedLabRunRequest, model: RouterVPNModel) async {
        guard !running else { lastError = "Another Speed Lab test is already running."; return }
        running = true
        lastError = ""
        lastResult = nil
        defer { activeTask = nil; running = false }
        let worker = Task { @MainActor in
            switch request.scope {
            case .current:
                return try await IOSMTUControl.withHold(model: model) {
                    try await self.runCurrent(request, model: model)
                }
            case .temporary:
                return try await self.runTemporary(request, model: model)
            }
        }
        activeTask = worker
        do {
            let result = try await withTaskCancellationHandler { try await worker.value } onCancel: { worker.cancel() }
            try Task.checkCancellation()
            lastResult = result
            progress = "Complete"
        } catch is CancellationError {
            lastError = "Speed Lab was cancelled because the tested path changed."
            progress = "Cancelled"
        } catch {
            lastError = error.localizedDescription
            progress = "Failed"
        }
    }

    func cancel() {
        guard running else { return }
        progress = "Cancelling measurements and restoring the captured path…"
        activeTask?.cancel()
    }

    private func runCurrent(_ request: IOSSpeedLabRunRequest, model: RouterVPNModel) async throws -> IOSSpeedLabRunResult {
        await model.refreshTunnelStatus()
        guard !model.tunnelTransitioning else { throw error("Wait for the VPN transition to finish before testing the current path.") }
        let token = pathToken(model)
        guard !token.connected || token.sessionIdentity != nil else {
            throw error("Current VPN session identity could not be verified.")
        }
        let path: String
        if token.connected {
            let node = model.selectedNodeProfile
            path = "Current VPN • \(node?.name ?? token.nodeID) • \(model.selectedLogicalMode) • \(token.engine) / \(token.rawProfile)"
        } else {
            path = "Current system direct • Router VPN disconnected"
        }
        progress = token.connected ? "Measuring current proven VPN path…" : "Measuring current system-direct path…"
        let measurement = try await guardedMeasurement(request.duration, model: model, token: token)
        return IOSSpeedLabRunResult(path: path, temporary: false, measurement: measurement)
    }

    private func runTemporary(_ request: IOSSpeedLabRunRequest, model: RouterVPNModel) async throws -> IOSSpeedLabRunResult {
        await model.refreshTunnelStatus()
        try Task.checkCancellation()
        guard !model.tunnelTransitioning else { throw error("Wait for the current VPN transition before a temporary Speed Lab test.") }
        let owner = try model.iosSpeedLabOwnership.begin { [weak self, weak model] in
            model?.iosConnectGeneration = UUID()
            model?.iosStrategyTaskActive = false
            self?.activeTask?.cancel()
        }
        defer { model.iosSpeedLabOwnership.finish(owner) }
        let snapshot = ModelSnapshot(
            bundleData: try model.bundle.map { try JSONEncoder().encode($0) },
            selectedLogicalMode: model.selectedLogicalMode,
            selectedMode: model.selectedMode,
            auto: model.auto,
            message: model.message
        )
        // Capture before MTU quiescence; a reconnected session with identical
        // node/mode labels is a different owner and cannot be restored by this test.
        return try await IOSSpeedLabContext.$owner.withValue(owner) {
            let original = try await IOSSpeedLabTunnel.capture(model: model, owner: owner)
            let originalToken = pathToken(model)
            return try await IOSMTUControl.withHold(model: model) {
                try model.iosSpeedLabOwnership.require(owner)
                guard pathToken(model) == originalToken else { throw CancellationError() }
                return try await runTemporaryHeld(request, model: model, owner: owner, snapshot: snapshot, original: original)
            }
        }
    }

    private func runTemporaryHeld(_ request: IOSSpeedLabRunRequest, model: RouterVPNModel, owner: UUID,
                                  snapshot: ModelSnapshot, original: IOSSpeedLabTunnel) async throws -> IOSSpeedLabRunResult {
        try IOSSpeedLabPersistenceJournal.begin(owner: owner)
        var path = ""
        let outcome: Result<IOSSpeedLabRunResult, Error>
        do {
            try Task.checkCancellation()
            progress = "Pausing the exact original VPN path…"
            // This stop must drain even when Cancel arrives during teardown.
            // A newer user action is still checked inside every native boundary.
            try await Task { @MainActor in try await original.stopOriginal(model: model, owner: owner) }.value
            try model.iosSpeedLabOwnership.require(owner)
            try Task.checkCancellation()
            switch request.topology {
            case .systemDirect:
                path = "Temporary system direct • Router VPN disconnected"
            case .multihop:
                guard !request.nodeID.isEmpty else { throw error("Choose an exit with a saved multihop graph.") }
                model.selectNode(request.nodeID)
                try IOSSpeedLabPersistenceJournal.reassertOriginalPersistentState()
                guard let selected = model.selectedNodeProfile, selected.id == request.nodeID,
                      selected.multihopEnabled == true, let saved = model.bundle else {
                    throw error("Save an entry/exit graph in Multihop before testing it temporarily.")
                }
                let external = selected.normalizedNodeKind == "external"
                if external && !model.selectedExternalSupportedOnIOS {
                    throw error("The saved external graph's transport is unavailable in this build.")
                }
                _ = try model.iosMultihopEntryBundle(for: saved)
                progress = "Proving temporary entry and exit through the owned PacketTunnel…"
                try Task.checkCancellation()
                if external { await model.connectSelectedExternal() }
                else { await model.connect() }
                try model.iosSpeedLabOwnership.require(owner)
                try IOSSpeedLabPersistenceJournal.reassertOriginalPersistentState()
                try Task.checkCancellation()
                guard model.connected, model.activeEngine == (external ? "external-libbox" : "multihop-libbox") else {
                    throw error("Temporary multihop failed both-node path proof: \(model.message)")
                }
                path = "Temporary multihop • \(selected.multihopEntryID ?? "") / \(selected.multihopEntryMode ?? "wg") → \(selected.id) • \(selected.multihopExecution ?? "local") • \(model.activeRawProfile)"
            case .router:
                guard !request.nodeID.isEmpty else { throw error("Choose a Router VPN node for the temporary test.") }
                model.selectNode(request.nodeID)
                try IOSSpeedLabPersistenceJournal.reassertOriginalPersistentState()
                try applyTemporaryAutoRequirements(request, model: model)
                guard let selected = model.selectedNodeProfile, selected.id == request.nodeID, selected.normalizedNodeKind == "router-vpn" else {
                    throw error("The requested temporary Router VPN node could not be selected.")
                }
                guard selected.multihopEnabled != true else {
                    throw error("This node has multihop enabled; choose the Multihop topology to test its saved graph.")
                }
                progress = "Starting temporary Router VPN path…"
                try await connectTemporaryRouter(request, model: model)
                try model.iosSpeedLabOwnership.require(owner)
                try IOSSpeedLabPersistenceJournal.reassertOriginalPersistentState()
                let filters = "encrypted=\(request.requireEncrypted ? "required" : "off") • obfuscation=\(request.requireObfuscation ? "required" : "off")"
                path = "Temporary Router VPN • \(selected.name) • \(request.mode) • \(filters) • \(model.activeEngine) / \(model.activeRawProfile)"
            case .external:
                guard !request.nodeID.isEmpty else { throw error("Choose an external node for the temporary test.") }
                model.selectNode(request.nodeID)
                try IOSSpeedLabPersistenceJournal.reassertOriginalPersistentState()
                guard let selected = model.selectedNodeProfile, selected.id == request.nodeID, selected.normalizedNodeKind == "external" else {
                    throw error("The requested temporary external node could not be selected.")
                }
                guard selected.multihopEnabled != true else {
                    throw error("This external node has multihop enabled; choose Multihop to test its captured entry and exit.")
                }
                guard model.selectedExternalSupportedOnIOS else {
                    throw error("That external transport is unavailable in this build.")
                }
                progress = "Starting temporary external \(model.selectedExternalProtocol) exit…"
                await model.connectSelectedExternal()
                try model.iosSpeedLabOwnership.require(owner)
                try IOSSpeedLabPersistenceJournal.reassertOriginalPersistentState()
                try Task.checkCancellation()
                guard model.connected else { throw error("Temporary external path failed selected exit proof: \(model.message)") }
                path = "Temporary external direct • \(selected.name) • \(model.selectedExternalProtocol)"
            }

            await model.refreshTunnelStatus()
            try model.iosSpeedLabOwnership.require(owner)
            try Task.checkCancellation()
            let token = pathToken(model)
            if request.topology == .systemDirect {
                guard !token.connected else { throw error("Router VPN connected while the system-direct test was being prepared.") }
            } else {
                guard token.connected, token.sessionIdentity != nil, !token.transitioning else {
                    throw error("Temporary VPN path/session is not verified after proof.")
                }
            }
            progress = "Running idle, download-loaded and upload-loaded measurements…"
            let measurement = try await guardedMeasurement(request.duration, model: model, token: token)
            try Task.checkCancellation()
            try model.iosSpeedLabOwnership.require(owner)
            outcome = .success(IOSSpeedLabRunResult(path: path, temporary: true, measurement: measurement))
        } catch { outcome = .failure(error) }
        do {
            // Cleanup has its own uncancelled task and is joined. The UI worker
            // retains its MTU lease until HTTP work, native teardown and the
            // original path's fresh proof have actually completed.
            try await Task { @MainActor in
                try await restore(snapshot, original: original, model: model, owner: owner)
            }.value
        } catch {
            let failure = (try? outcome.get()).map { _ in "Measurement completed" } ?? "Measurement was cancelled or failed"
            throw self.error("\(failure); temporary-path cleanup failed: \(error.localizedDescription). Recovery journal retained for next launch.")
        }
        try Task.checkCancellation()
        try model.iosSpeedLabOwnership.require(owner)
        return try outcome.get()
    }

    private func applyTemporaryAutoRequirements(_ request: IOSSpeedLabRunRequest, model: RouterVPNModel) throws {
        guard var current = model.bundle, current.selectedRouterID == request.nodeID,
              current.routerProfiles.filter({ $0.id == current.selectedRouterID }).count == 1,
              let index = current.routerProfiles.firstIndex(where: { $0.id == current.selectedRouterID }) else {
            throw error("Temporary Speed Lab Router node has no mutable profile.")
        }
        guard current.routerProfiles[index].normalizedNodeKind == "router-vpn" else {
            throw error("AUTO requirement overrides apply only to Router VPN nodes.")
        }
        current.routerProfiles[index].autoRequireEncrypted = request.requireEncrypted
        current.routerProfiles[index].autoRequireObfuscation = request.requireObfuscation
        try model.importBundle(JSONEncoder().encode(current))
        try IOSSpeedLabPersistenceJournal.reassertOriginalPersistentState()
    }

    private func connectTemporaryRouter(_ request: IOSSpeedLabRunRequest, model: RouterVPNModel) async throws {
        switch request.mode.lowercased() {
        case "smart-auto":
            await model.runIOSSmartAuto()
        case "auto":
            model.auto = true
            await model.connect()
        case "custom":
            guard !request.customLayers.isEmpty else { throw error("CUSTOM Speed Lab requires at least one layer.") }
            await model.runIOSCustom(layers: request.customLayers)
        default:
            model.auto = false
            model.selectedLogicalMode = request.mode
            model.selectedMode = request.mode
            await model.connect()
        }
        guard model.connected else { throw error("Temporary Router VPN path did not pass selected-node proof: \(model.message)") }
    }

    private func guardedMeasurement(_ duration: IOSSpeedLabDuration, model: RouterVPNModel, token: PathToken) async throws -> IOSSpeedLabMeasurement {
        guard IOSMTUMeasurementGate.held else { throw error("MTU measurement lease is missing") }
        try await IOSMTUControl.holdCurrent(model, request: IOSMTUMeasurementGate.current)
        guard pathToken(model) == token else { throw CancellationError() }
        let measurementTask = Task { try await IOSSpeedLabEngine.run(duration: duration) }
        let watcher = Task { @MainActor in
            while !Task.isCancelled {
                try? await Task.sleep(for: .milliseconds(300))
                if Task.isCancelled { return }
                await model.refreshTunnelStatus()
                if self.pathToken(model) != token {
                    measurementTask.cancel()
                    return
                }
            }
        }
        do {
            let value = try await withTaskCancellationHandler {
                try await measurementTask.value
            } onCancel: {
                measurementTask.cancel()
                watcher.cancel()
            }
            watcher.cancel()
            _ = await watcher.result
            await model.refreshTunnelStatus()
            try Task.checkCancellation()
            guard pathToken(model) == token else { throw CancellationError() }
            return value
        } catch {
            watcher.cancel()
            _ = await watcher.result
            throw error
        }
    }

    private func restore(_ snapshot: ModelSnapshot, original: IOSSpeedLabTunnel,
                         model: RouterVPNModel, owner: UUID) async throws {
        progress = "Draining the temporary path and restoring the original selection…"
        while true {
            if model.iosSpeedLabOwnership.userDisconnected(owner) {
                await model.refreshTunnelStatus()
                if !model.connected && !model.tunnelTransitioning && !model.iosUserDisconnectInProgress { break }
                // Disconnect can outlive the ordinary native stop timeout.
                // This uncancelled cleanup task retains the lease until the
                // actual captured stop finishes; Cancel is never fake drain.
                progress = "Waiting for your Disconnect to finish before releasing the measurement hold…"
            } else {
                do {
                    try await IOSSpeedLabTunnel.stopTemporary(model: model, owner: owner)
                    break
                } catch {
                    if model.iosSpeedLabOwnership.userDisconnected(owner) { continue }
                    guard IOSSpeedLabTunnel.retirementPending(error) else { throw error }
                    progress = "Waiting for the captured temporary VPN to finish shutdown; Disconnect remains available…"
                }
            }
            guard model.iosSpeedLabOwnership.owns(owner) else { throw CancellationError() }
            try await Task.sleep(for: .milliseconds(150))
        }
        guard model.iosSpeedLabOwnership.mayRestoreSelection(owner) else {
            // Newer node/profile/connection intent owns persistence. The
            // original journal must not overwrite that user's selected state.
            try IOSSpeedLabPersistenceJournal.abandon()
            return
        }
        try IOSSpeedLabContext.$restoringSelection.withValue(true) {
            try model.restoreIOSSpeedLabBundle(snapshot.bundleData)
        }
        try IOSSpeedLabPersistenceJournal.reassertOriginalPersistentState()
        var reconnect = model.iosSpeedLabOwnership.current(owner)
        progress = reconnect && original.identity != nil ? "Re-proving the exact original VPN runtime…" : "Restoring the saved selection; staying disconnected…"
        do { try await original.restore(model: model, owner: owner, reconnect: reconnect) }
        catch {
            guard model.iosSpeedLabOwnership.userDisconnected(owner) else { throw error }
            // Disconnect may arrive during the original's fresh proof or
            // reconnect-rule save. Join that stop, then confirm the captured
            // original preferences with On Demand disabled.
            while true {
                await model.refreshTunnelStatus()
                if !model.connected && !model.tunnelTransitioning && !model.iosUserDisconnectInProgress { break }
                try await Task.sleep(for: .milliseconds(100))
            }
            guard model.iosSpeedLabOwnership.mayRestoreSelection(owner) else { throw CancellationError() }
            reconnect = false
            try await original.restore(model: model, owner: owner, reconnect: false)
        }
        guard model.iosSpeedLabOwnership.mayRestoreSelection(owner) else { throw CancellationError() }
        model.selectedLogicalMode = snapshot.selectedLogicalMode
        model.selectedMode = snapshot.selectedMode
        model.auto = snapshot.auto
        model.message = reconnect ? snapshot.message : "Disconnected • original Speed Lab selection restored"
        try IOSSpeedLabPersistenceJournal.finish()
    }

    private func pathToken(_ model: RouterVPNModel) -> PathToken {
        PathToken(
            connected: model.connected,
            nodeID: model.connected ? (model.selectedNodeProfile?.id ?? "") : "",
            engine: model.connected ? model.activeEngine : "none",
            rawProfile: model.connected ? model.activeRawProfile : "",
            transitioning: model.tunnelTransitioning,
            sessionIdentity: model.connected ? model.activeSessionIdentity : nil
        )
    }

    private func error(_ message: String) -> NSError {
        NSError(domain: "RouterVPN.SpeedLab", code: 20, userInfo: [NSLocalizedDescriptionKey: message])
    }
}
