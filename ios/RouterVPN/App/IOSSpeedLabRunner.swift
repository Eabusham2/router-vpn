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
    }

    func run(_ request: IOSSpeedLabRunRequest, model: RouterVPNModel) async {
        guard !running else { lastError = "Another Speed Lab test is already running."; return }
        running = true
        lastError = ""
        lastResult = nil
        defer { running = false }

        do {
            let result: IOSSpeedLabRunResult
            switch request.scope {
            case .current:
                result = try await runCurrent(request, model: model)
            case .temporary:
                result = try await runTemporary(request, model: model)
            }
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

    private func runCurrent(_ request: IOSSpeedLabRunRequest, model: RouterVPNModel) async throws -> IOSSpeedLabRunResult {
        await model.refreshTunnelStatus()
        guard !model.tunnelTransitioning else { throw error("Wait for the VPN transition to finish before testing the current path.") }
        let token = pathToken(model)
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
        guard !model.connected, !model.tunnelTransitioning else {
            throw error("Disconnect before a temporary Speed Lab configuration. Current-path testing remains available while connected.")
        }
        let snapshot = ModelSnapshot(
            bundleData: model.bundle.flatMap { try? JSONEncoder().encode($0) },
            selectedLogicalMode: model.selectedLogicalMode,
            selectedMode: model.selectedMode,
            auto: model.auto,
            message: model.message
        )

        var path = ""
        var startedTemporaryTunnel = false
        do {
            switch request.topology {
            case .systemDirect:
                path = "Temporary system direct • Router VPN disconnected"
            case .multihop:
                throw error("iOS/iPadOS Speed Lab does not fake desktop-equivalent multihop. Use Windows, macOS, Linux or Android for temporary multihop tests until an Apple PacketTunnel multihop dataplane is shipped.")
            case .router:
                guard !request.nodeID.isEmpty else { throw error("Choose a Router VPN node for the temporary test.") }
                model.selectNode(request.nodeID)
                guard let selected = model.selectedNodeProfile, selected.id == request.nodeID, selected.normalizedNodeKind == "router-vpn" else {
                    throw error("The requested temporary Router VPN node could not be selected.")
                }
                progress = "Starting temporary Router VPN path…"
                try await connectTemporaryRouter(request, model: model)
                startedTemporaryTunnel = true
                path = "Temporary Router VPN • \(selected.name) • \(request.mode) • \(model.activeEngine) / \(model.activeRawProfile)"
            case .external:
                guard !request.nodeID.isEmpty else { throw error("Choose an external node for the temporary test.") }
                model.selectNode(request.nodeID)
                guard let selected = model.selectedNodeProfile, selected.id == request.nodeID, selected.normalizedNodeKind == "external" else {
                    throw error("The requested temporary external node could not be selected.")
                }
                guard model.selectedExternalSupportedOnIOS else {
                    throw error(model.selectedExternalProtocol == "openvpn" ? "OpenVPN temporary testing is unavailable on iOS until a pinned native Apple OpenVPN dataplane ships." : "That external transport is unavailable on iOS.")
                }
                progress = "Starting temporary external \(model.selectedExternalProtocol) exit…"
                await model.connectSelectedExternal()
                guard model.connected else { throw error("Temporary external path failed selected exit proof: \(model.message)") }
                startedTemporaryTunnel = true
                path = "Temporary external direct • \(selected.name) • \(model.selectedExternalProtocol)"
            }

            await model.refreshTunnelStatus()
            let token = pathToken(model)
            if request.topology == .systemDirect {
                guard !token.connected else { throw error("Router VPN connected while the system-direct test was being prepared.") }
            } else {
                guard token.connected else { throw error("Temporary VPN path is not connected after proof.") }
            }
            progress = "Running idle, download-loaded and upload-loaded measurements…"
            let measurement = try await guardedMeasurement(request.duration, model: model, token: token)
            try await restore(snapshot, model: model, stopTunnel: startedTemporaryTunnel)
            return IOSSpeedLabRunResult(path: path, temporary: true, measurement: measurement)
        } catch let operationError {
            do { try await restore(snapshot, model: model, stopTunnel: startedTemporaryTunnel || model.connected) }
            catch let cleanupError {
                throw self.error("\(operationError.localizedDescription); temporary-path cleanup also failed: \(cleanupError.localizedDescription)")
            }
            throw operationError
        }
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
            let value = try await measurementTask.value
            watcher.cancel()
            _ = await watcher.result
            await model.refreshTunnelStatus()
            guard pathToken(model) == token else { throw CancellationError() }
            return value
        } catch {
            watcher.cancel()
            _ = await watcher.result
            throw error
        }
    }

    private func restore(_ snapshot: ModelSnapshot, model: RouterVPNModel, stopTunnel: Bool) async throws {
        if stopTunnel || model.connected || model.tunnelTransitioning {
            if !model.tunnelTransitioning { model.disconnect() }
            for _ in 0..<40 {
                await model.refreshTunnelStatus()
                if !model.connected && !model.tunnelTransitioning { break }
                try? await Task.sleep(for: .milliseconds(150))
            }
            await model.refreshTunnelStatus()
            guard !model.connected, !model.tunnelTransitioning else { throw error("Temporary Speed Lab tunnel did not fully stop.") }
        }
        if let data = snapshot.bundleData {
            try model.importBundle(data)
        }
        model.selectedLogicalMode = snapshot.selectedLogicalMode
        model.selectedMode = snapshot.selectedMode
        model.auto = snapshot.auto
        model.message = snapshot.message
    }

    private func pathToken(_ model: RouterVPNModel) -> PathToken {
        PathToken(
            connected: model.connected,
            nodeID: model.connected ? (model.selectedNodeProfile?.id ?? "") : "",
            engine: model.connected ? model.activeEngine : "none",
            rawProfile: model.connected ? model.activeRawProfile : ""
        )
    }

    private func error(_ message: String) -> NSError {
        NSError(domain: "RouterVPN.SpeedLab", code: 20, userInfo: [NSLocalizedDescriptionKey: message])
    }
}
