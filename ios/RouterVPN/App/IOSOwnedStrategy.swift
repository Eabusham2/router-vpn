import CryptoKit
import Foundation
import Libbox
@preconcurrency import NetworkExtension

/// All candidate assets are frozen before PacketTunnel starts. Later IPC can
/// reference this catalog, but cannot replace credentials, DNS or node policy.
@MainActor extension RouterVPNModel {
    static func iosStrategyDigest(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    private func iosStrategySource(_ value: ClientBundle) throws -> Data {
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
        return try encoder.encode(value)
    }

    func iosStrategySelections(kind: IOSStrategyPlan.Kind, rawProfileID: String? = nil) throws -> [IOSRuntimeSelection] {
        guard let bundle, let profile = IOSDNSRuntimePolicy.selectedProfile(in: bundle),
              profile.normalizedNodeKind == "router-vpn", profile.multihopEnabled != true else {
            throw IOSStrategyWire.failure("Owned mode selection requires one selected Router VPN node.")
        }
        if kind == .manual {
            guard let rawProfileID else { throw IOSStrategyWire.failure("Choose an exact native mode.") }
            return [try IOSRuntimeSelector.selectRaw(bundle: bundle, rawProfileID: rawProfileID)]
        }
        if kind == .logical || kind == .all {
            return try IOSRuntimeSelector.candidates(bundle: bundle, logicalModeID: kind == .all ? "all" : selectedLogicalMode)
        }
        var seen = Set<String>()
        var candidates = IOSRuntimeSelector.runnableModes(in: bundle).flatMap {
            (try? IOSRuntimeSelector.candidates(bundle: bundle, logicalModeID: $0.id)) ?? []
        }.filter { seen.insert($0.rawProfileID).inserted }
        if kind == .automatic || kind == .smart {
            candidates = candidates.filter { IOSStrategyCatalog.autoRequirementFailure(rawID: $0.rawProfileID, profile: profile) == nil }
        }
        guard !candidates.isEmpty else {
            throw IOSStrategyWire.failure("AUTO failed closed: no iOS-runnable candidate satisfies the saved requirements.")
        }
        return candidates
    }

    private func requireIOSStrategyPreparation(_ generation: UUID, source: ClientBundle,
                                                manager: NETunnelProviderManager, disconnected: Bool) throws {
        try Task.checkCancellation()
        guard iosConnectGeneration == generation, !iosUserDisconnectInProgress,
              let current = bundle, try iosStrategySource(current) == iosStrategySource(source),
              manager.protocolConfiguration == nil ||
                (manager.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == "com.eabusham.routervpn.PacketTunnel" else {
            throw CancellationError()
        }
        if disconnected && manager.connection.status != .disconnected && manager.connection.status != .invalid {
            throw IOSStrategyWire.failure("The VPN owner changed while candidate assets were being prepared.")
        }
    }

    private func prepareIOSStrategyCandidate(_ selection: IOSRuntimeSelection, source: ClientBundle) async throws -> [String: Data] {
        var files = selection.files
        guard selection.engine != .multihop else { throw IOSStrategyWire.failure("A single-node strategy cannot replace the captured multihop owner.") }
        if IOSNativeMAXProfile.modeIDs.contains(selection.rawProfileID) {
            var captured = source
            captured.profiles[selection.rawProfileID] = files.mapValues { $0.base64EncodedString() }
            let configuration: [String: Any] = ["engine": "libbox", "rawProfileID": selection.rawProfileID,
                                               "bundle": try JSONEncoder().encode(captured)]
            _ = try IOSMAXSourceSelection.sourceHashes(provider: configuration) { mode, assets, metadata in
                var failure: NSError?
                let digest: String? = LibboxRouterCheckMAXProfile(mode, assets, metadata, &failure)
                if let failure { throw failure }
                guard let digest else { throw IOSMAXSourceSelection.issue() }; return digest
            }
            return files
        }
        guard let originalData = files["xray.json"] else { return files }
        guard let wrapperData = files["sing-box.json"], let wrapper = String(data: wrapperData, encoding: .utf8),
              let original = String(data: originalData, encoding: .utf8) else {
            throw IOSStrategyWire.failure("The native Xray candidate lost its exact compiled wrapper.")
        }
        let mode = selection.rawProfileID
        let startLayer = try IOSRuntimeSelector.normalizedStartLayer(in: source)
        var aesInput: String?, policyInput: String?
        if startLayer != "off" {
            guard let profile = IOSDNSRuntimePolicy.selectedProfile(in: source),
                  let encoded = source.profiles["shadowsocks"]?["sing-box.json"], encoded.utf8.count <= 6 * 1024 * 1024,
                  let bytes = Data(base64Encoded: encoded), !bytes.isEmpty, bytes.count <= 4 * 1024 * 1024,
                  bytes.base64EncodedString() == encoded, let text = String(data: bytes, encoding: .utf8) else {
                throw IOSStrategyWire.failure("Xray Start Layer requires its captured authenticated AES profile.")
            }
            aesInput = text
            let metadata = ["mode": startLayer, "raw_mode": mode, "node_kind": profile.nodeKind ?? "router-vpn", "router_api": profile.routerAPI]
            policyInput = String(decoding: try JSONSerialization.data(withJSONObject: metadata), as: UTF8.self)
        }
        let capturedAES = aesInput, capturedPolicy = policyInput
        let resolved = try await Task.detached(priority: .userInitiated) {
            var failure: NSError?
            let output: String?
            if let capturedAES, let capturedPolicy {
                output = LibboxRouterResolveXrayStartLayerProfile(mode, wrapper, original, capturedAES, capturedPolicy, &failure)
            } else {
                output = LibboxRouterResolveXrayProfile(mode, wrapper, original, &failure)
            }
            if let failure { throw failure }
            guard let output, !output.isEmpty, output.utf8.count <= 12 * 1024 * 1024 else {
                throw IOSStrategyWire.failure("The native Xray endpoint preparation returned no bounded asset set.")
            }
            return output
        }.value
        try Task.checkCancellation()
        let replacements = try JSONDecoder().decode([String: Data].self, from: Data(resolved.utf8))
        let required: Set<String> = startLayer == "off" ? ["sing-box.json", "xray.json"] : ["sing-box.json", "xray.json", "start-layer-source.json"]
        guard Set(replacements.keys) == required,
              replacements.values.allSatisfy({ !$0.isEmpty && $0.count <= 4 * 1024 * 1024 }) else {
            throw IOSStrategyWire.failure("Xray endpoint preparation changed its allowed asset set.")
        }
        // Per-candidate AES capture avoids changing another candidate's source
        // when the same hostname resolves differently between preparations.
        for (name, bytes) in replacements { files[name] = bytes }
        return files
    }

    private func prepareIOSStrategyCatalog(source: ClientBundle, selections: [IOSRuntimeSelection],
                                           generation: UUID, manager: NETunnelProviderManager) async throws -> (ClientBundle, [IOSStrategyCandidate]) {
        var launch = source, catalog: [IOSStrategyCandidate] = [], seen = Set<String>()
        let ids = selections.map(\.rawProfileID) + source.modes.map(\.id)
        for raw in ids where seen.insert(raw).inserted {
            try requireIOSStrategyPreparation(generation, source: source, manager: manager, disconnected: true)
            guard IOSStrategyCatalog.layers[raw] != nil,
                  let selection = try? IOSRuntimeSelector.selectRaw(bundle: source, rawProfileID: raw) else { continue }
            do {
                message = "Preparing captured \(raw) assets before VPN startup…"
                let files = try await prepareIOSStrategyCandidate(selection, source: source)
                try requireIOSStrategyPreparation(generation, source: source, manager: manager, disconnected: true)
                launch.profiles[raw] = files.mapValues { $0.base64EncodedString() }
                catalog.append(IOSStrategyCandidate(raw: raw, logical: selection.logicalModeID))
            } catch is CancellationError { throw CancellationError() }
            catch {
                // A failed candidate cannot enter the frozen runnable catalog.
                // Other independently validated candidates remain available.
                try requireIOSStrategyPreparation(generation, source: source, manager: manager, disconnected: true)
            }
        }
        guard !catalog.isEmpty, catalog.count <= 32 else { throw IOSStrategyWire.failure("No candidate completed native endpoint preparation.") }
        return (try IOSDNSRuntimePolicy.patch(launch), catalog)
    }

    @discardableResult
    func runIOSOwnedStrategy(kind: IOSStrategyPlan.Kind, selections: [IOSRuntimeSelection], preferredRaw: String? = nil) async -> Bool {
        guard !iosStrategyTaskActive, !iosUserDisconnectInProgress else {
            message = "Another owned VPN operation is still running."; return false
        }
        guard let source = bundle, let profile = IOSDNSRuntimePolicy.selectedProfile(in: source),
              profile.multihopEnabled != true, !selections.isEmpty else {
            message = "Choose a captured single-node native strategy."; return false
        }
        let generation = UUID(); iosConnectGeneration = generation
        iosStrategyTaskActive = true; tunnelTransitioning = true
        defer { if iosConnectGeneration == generation { iosStrategyTaskActive = false } }
        do {
            let managers = try await NETunnelProviderManager.loadAllFromPreferences().filter {
                ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == "com.eabusham.routervpn.PacketTunnel"
            }
            guard managers.count <= 1 else { throw IOSStrategyWire.failure("Multiple Router VPN managers make strategy ownership ambiguous.") }
            let manager = managers.first ?? NETunnelProviderManager()
            try requireIOSStrategyPreparation(generation, source: source, manager: manager, disconnected: false)
            let configuration: [String: Any]
            let data: Data, catalog: [IOSStrategyCandidate]
            var currentStatus: IOSStrategyStatus?
            if manager.connection.status == .connected {
                guard [.automatic, .smart, .custom, .all].contains(kind),
                      let proto = manager.protocolConfiguration as? NETunnelProviderProtocol,
                      let existing = proto.providerConfiguration, let frozen = existing["bundle"] as? Data,
                      existing["strategy_source_digest"] as? String == Self.iosStrategyDigest(try iosStrategySource(source)),
                      let connection = manager.connection as? NETunnelProviderSession else {
                    throw IOSStrategyWire.failure("This connection has different saved policy or no owned strategy catalog; reconnect before replacing its mode.")
                }
                catalog = try IOSStrategyWire.catalog(existing); data = frozen; configuration = existing
                let reply = try await IOSStrategyTransport.send(connection, request: ["operation": "strategy-status", "bundle_digest": Self.iosStrategyDigest(frozen)])
                try requireIOSStrategyPreparation(generation, source: source, manager: manager, disconnected: false)
                currentStatus = try IOSStrategyWire.status(reply, bundleDigest: Self.iosStrategyDigest(frozen), catalog: catalog)
                guard currentStatus?.isRunning == false else { throw IOSStrategyWire.failure("The VPN is already proving a strategy candidate.") }
            } else {
                guard manager.connection.status == .disconnected || manager.connection.status == .invalid else {
                    throw IOSStrategyWire.failure("Wait for the current system VPN transition or press Disconnect.")
                }
                let prepared = try await prepareIOSStrategyCatalog(source: source, selections: selections, generation: generation, manager: manager)
                catalog = prepared.1; data = try JSONEncoder().encode(prepared.0)
                guard !data.isEmpty, data.count <= 32 * 1024 * 1024 else { throw IOSStrategyWire.failure("The frozen strategy bundle exceeds its bound.") }
                configuration = ["engine": "libbox", "bundle": data,
                                 "strategy_source_digest": Self.iosStrategyDigest(try iosStrategySource(source)),
                                 "strategy_catalog": ["version": 1, "candidates": catalog.map { ["raw": $0.raw, "logical": $0.logical] }]]
            }
            let refs = selections.map { IOSStrategyCandidate(raw: $0.rawProfileID, logical: $0.logicalModeID) }.filter { catalog.contains($0) }
            let preferred = preferredRaw.flatMap { raw in refs.contains(where: { $0.raw == raw }) ? raw : nil }
            let plan = try IOSStrategyPlan(kind: kind, candidates: refs, preferredRaw: preferred)
            let digest = Self.iosStrategyDigest(data)
            iosInvalidateStrategyIdentity()
            if let currentStatus, let connection = manager.connection as? NETunnelProviderSession {
                let reply = try await IOSStrategyTransport.send(connection, request: ["operation": "strategy-run",
                    "provider_session": currentStatus.providerSession, "request_id": currentStatus.requestID, "strategy": try plan.object()])
                try requireIOSStrategyPreparation(generation, source: source, manager: manager, disconnected: false)
                _ = try IOSStrategyWire.status(reply, bundleDigest: digest, catalog: catalog,
                                               requestID: plan.requestID, providerSession: currentStatus.providerSession)
            } else {
                try requireIOSStrategyPreparation(generation, source: source, manager: manager, disconnected: true)
                let proto = NETunnelProviderProtocol()
                proto.providerBundleIdentifier = "com.eabusham.routervpn.PacketTunnel"
                proto.serverAddress = source.endpoint
                var captured = configuration
                captured["strategy"] = try plan.object()
                captured["mode"] = refs[0].raw; captured["rawProfileID"] = refs[0].raw
                captured["logicalMode"] = refs[0].logical; captured["modeCandidates"] = refs.map(\.raw)
                let maxSources = try IOSMAXSourceSelection.sourceHashes(provider: captured) { mode, assets, metadata in
                    var failure: NSError?
                    let digest: String? = LibboxRouterCheckMAXProfile(mode, assets, metadata, &failure)
                    if let failure { throw failure }
                    guard let digest else { throw IOSMAXSourceSelection.issue() }
                    return digest
                }
                if !maxSources.isEmpty { captured["max_source_sha256"] = maxSources }
                proto.providerConfiguration = captured
                let strict = iosStrategyStrictLockdown
                proto.includeAllNetworks = strict; proto.enforceRoutes = strict
                proto.excludeLocalNetworks = strict && (profile.homeLANAccess ?? true)
                proto.excludeAPNs = false; proto.excludeCellularServices = false
                manager.protocolConfiguration = proto; manager.localizedDescription = profile.name
                manager.isEnabled = true; manager.isOnDemandEnabled = strict
                manager.onDemandRules = strict ? [NEOnDemandRuleConnect()] : []
                try await manager.saveToPreferences()
                try requireIOSStrategyPreparation(generation, source: source, manager: manager, disconnected: true)
                try await manager.loadFromPreferences()
                try requireIOSStrategyPreparation(generation, source: source, manager: manager, disconnected: true)
                guard let saved = (manager.protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration,
                      saved["bundle"] as? Data == data,
                      saved["max_source_sha256"] as? [String: String] == (maxSources.isEmpty ? nil : maxSources),
                      (saved["strategy"] as? [String: Any])?["request_id"] as? String == plan.requestID,
                      manager.isEnabled, manager.isOnDemandEnabled == strict else {
                    throw IOSStrategyWire.failure("Saved VPN preferences did not preserve the captured strategy owner.")
                }
                let hold = IOSMTUMeasurementGate.current
                let options: [String: NSObject]? = hold.isEmpty ? nil : ["routervpn_mtu_hold": hold as NSString]
                try manager.connection.startVPNTunnel(options: options)
            }
            let result = try await waitForIOSStrategy(manager, source: source, generation: generation,
                data: data, catalog: catalog, plan: plan, providerSession: currentStatus?.providerSession)
            if iosConnectGeneration == generation { await refreshTunnelStatus() }
            return result
        } catch {
            guard iosConnectGeneration == generation, !iosUserDisconnectInProgress else { return false }
            await refreshTunnelStatus()
            if iosConnectGeneration == generation { message = "Strategy was not completed: \(error.localizedDescription)" }
            return false
        }
    }

    private func waitForIOSStrategy(_ manager: NETunnelProviderManager, source: ClientBundle, generation: UUID,
                                    data: Data, catalog: [IOSStrategyCandidate], plan: IOSStrategyPlan,
                                    providerSession: String?) async throws -> Bool {
        guard let connection = manager.connection as? NETunnelProviderSession else { throw IOSStrategyWire.failure("The VPN has no owned provider session.") }
        var owner = providerSession, sawTransition = false, missedReplies = 0
        let deadline = ContinuousClock.now.advanced(by: .seconds(900))
        while ContinuousClock.now < deadline {
            try requireIOSStrategyPreparation(generation, source: source, manager: manager, disconnected: false)
            if [.connecting, .reasserting, .connected].contains(connection.status) { sawTransition = true }
            if connection.status == .disconnecting || (sawTransition && [.disconnected, .invalid].contains(connection.status)) {
                throw IOSStrategyWire.failure("The owned VPN stopped before both strategy proofs completed.")
            }
            if connection.status == .connected {
                do {
                    var request: [String: Any] = ["operation": "strategy-status", "request_id": plan.requestID]
                    if let owner { request["provider_session"] = owner }
                    let reply = try await IOSStrategyTransport.send(connection, request: request)
                    try requireIOSStrategyPreparation(generation, source: source, manager: manager, disconnected: false)
                    let status = try IOSStrategyWire.status(reply, bundleDigest: Self.iosStrategyDigest(data), catalog: catalog,
                        requestID: plan.requestID, providerSession: owner)
                    guard status.kind == plan.kind,
                          status.outcome != .success || plan.candidates.contains(IOSStrategyCandidate(raw: status.provenRaw, logical: status.provenLogical)) else {
                        throw IOSStrategyWire.failure("The completed strategy did not prove a requested candidate.")
                    }
                    owner = status.providerSession; missedReplies = 0
                    try iosAdoptStrategyStatus(status, manager: manager, bundleData: data)
                    if !status.isRunning { return status.isProven && status.outcome == .success }
                } catch is CancellationError { throw CancellationError() }
                catch { missedReplies += 1; if missedReplies >= 3 { throw error } }
            }
            try await Task.sleep(for: .milliseconds(250))
        }
        if let owner {
            _ = try? await IOSStrategyTransport.send(connection, request: ["operation": "strategy-cancel", "request_id": plan.requestID, "provider_session": owner])
        }
        throw IOSStrategyWire.failure("Strategy progress exceeded its bounded wait; inspect the protected VPN status or Disconnect.")
    }
}
