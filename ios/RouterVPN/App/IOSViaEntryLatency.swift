import Combine
import Foundation

struct IOSViaEntryValue: Identifiable, Sendable {
    let id: String
    let name: String
    let medianMS: Double?
    let samples: Int
    let failed: Int
    let reason: String

    var eligible: Bool { samples >= 3 && failed == 0 && medianMS.map { $0.isFinite && $0 > 0 } == true }
    var label: String {
        guard let medianMS else { return "\(name) • unavailable" }
        return String(format: "%@ • %.1f ms • %d/%d responses", name, medianMS, samples, samples + failed)
    }
}

@MainActor
private struct IOSViaEntrySelection: Equatable {
    let decision: UUID
    let bundle: Data
    let mode: String
    let logicalMode: String
    let auto: Bool

    init(_ model: RouterVPNModel) throws {
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
        bundle = try encoder.encode(model.bundle)
        decision = model.iosConnectGeneration; mode = model.selectedMode
        logicalMode = model.selectedLogicalMode; auto = model.auto
    }
}

@MainActor
final class IOSViaEntryCapture {
    let entryID: String
    let entryMode: String
    let entryName: String
    let entryBundle: ClientBundle
    let candidates: [RouterProfile]
    let excludedHosts: Set<String>
    let allowsIPv6: Bool
    private let sources: [String: Data]
    private let initialSelection: IOSViaEntrySelection

    init(model: RouterVPNModel, entryID: String, mode: String, candidates: [RouterProfile]) throws {
        guard !model.profileMutationBlocked, !model.iosSpeedLabOwnership.active,
              IOSRuntimeSelector.multihopModeIDs.contains(mode),
              let bytes = IOSNodeBundleStore.shared.bundleData(containing: entryID, current: model.persistedNodeBundle) else {
            throw Self.issue("Disconnect and select a linked Router VPN entry before measuring its exit candidates.")
        }
        initialSelection = try IOSViaEntrySelection(model)
        var entry = try JSONDecoder().decode(ClientBundle.self, from: bytes)
        guard entry.routerProfiles.filter({ $0.id == entryID }).count == 1,
              let index = entry.routerProfiles.firstIndex(where: { $0.id == entryID }),
              entry.routerProfiles[index].normalizedNodeKind == "router-vpn",
              entry.routerProfiles[index].nodeProofID?.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil else {
            throw Self.issue("The selected entry needs its exact paired Router VPN identity.")
        }
        let profile = entry.routerProfiles[index]
        allowsIPv6 = (profile.ipv6Mode ?? "on").trimmingCharacters(in: .whitespacesAndNewlines).lowercased() != "off"
        self.entryID = entryID; entryMode = mode
        entryName = profile.name.isEmpty ? profile.id : profile.name
        var captured = [entryID: try Self.canonical(bytes)]
        let selected = candidates.filter { $0.id != entryID }
        guard !selected.isEmpty, selected.count <= 128, Set(selected.map(\.id)).count == selected.count else {
            throw Self.issue("Choose a bounded list of distinct linked exit candidates.")
        }
        for candidate in selected {
            guard let data = IOSNodeBundleStore.shared.bundleData(containing: candidate.id, current: model.persistedNodeBundle),
                  let saved = try JSONDecoder().decode(ClientBundle.self, from: data).routerProfiles.first(where: { $0.id == candidate.id }),
                  saved == candidate else { throw Self.issue("A candidate changed before measurement. Reopen Multihop.") }
            captured[candidate.id] = try Self.canonical(data)
        }
        sources = captured; self.candidates = selected
        // The temporary single entry preserves saved DNS, LAN, encryption,
        // MTU and transport assets. Its saved multihop graph is never rewritten.
        entry.selectedRouterID = entryID
        entry.routerProfiles[index].multihopEnabled = false
        entry.nodeProofID = profile.nodeProofID ?? ""
        entry.endpoint = profile.endpoint; entry.routerAPI = profile.routerAPI; entry.apiToken = profile.apiToken
        entry.adGuardIPv4 = profile.adGuardIPv4; entry.adGuardIPv6 = profile.adGuardIPv6
        entry.socks5Host = profile.socksHost; entry.socks5Port = profile.socksPort
        _ = try IOSRuntimeSelector.selectRaw(bundle: entry, rawProfileID: mode)
        entryBundle = entry
        var excluded = Set([IOSViaEntryTCP.endpointHost(profile.endpoint)])
        // Native engines can exclude their physical transport endpoints from
        // TUN routing. Such an address cannot be presented as a routed sample.
        var endpointAssets = Array((entry.profiles[mode] ?? [:]).values)
        let profileObject = try JSONSerialization.jsonObject(with: JSONEncoder().encode(profile)) as! [String: Any]
        if try IOSMultihopStartLayer.selected(profileObject) != "off" {
            endpointAssets += (entry.profiles["shadowsocks"] ?? [:]).values
        }
        for encoded in endpointAssets {
            guard let data = Data(base64Encoded: encoded) else { continue }
            if let object = try? JSONSerialization.jsonObject(with: data) { Self.collectEndpoints(object, into: &excluded) }
            else if let text = String(data: data, encoding: .utf8) {
                for line in text.components(separatedBy: .newlines) {
                    let pair = line.split(separator: "=", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespaces) }
                    if pair.count == 2 && pair[0].lowercased() == "endpoint" { excluded.insert(IOSViaEntryTCP.endpointHost(pair[1])) }
                }
            }
        }
        excludedHosts = excluded
    }

    func requireInitialSelection(model: RouterVPNModel) throws {
        guard !model.profileMutationBlocked, !model.iosSpeedLabOwnership.active,
              try IOSViaEntrySelection(model) == initialSelection else {
            throw Self.issue("The selection or VPN state changed before measurement could start. Retest the entry.")
        }
        try requireSources(model: model)
    }

    func requireSources(model: RouterVPNModel) throws {
        for (id, expected) in sources {
            // Reading the saved catalog must not persist the in-memory
            // temporary bundle or promote temporary policy into a saved node.
            guard let data = IOSNodeBundleStore.shared.bundleData(containing: id, current: model.persistedNodeBundle),
                  try Self.canonical(data) == expected else {
                throw Self.issue("A captured entry or candidate changed. Retest before selecting a result.")
            }
        }
    }

    private static func collectEndpoints(_ value: Any, into hosts: inout Set<String>) {
        if let object = value as? [String: Any] {
            for (key, child) in object {
                if ["server", "address", "server_address"].contains(key), let text = child as? String {
                    hosts.insert(IOSViaEntryTCP.endpointHost(text))
                }
                collectEndpoints(child, into: &hosts)
            }
        } else if let values = value as? [Any] { for child in values { collectEndpoints(child, into: &hosts) } }
    }

    private static func canonical(_ data: Data) throws -> Data {
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
        return try encoder.encode(JSONDecoder().decode(ClientBundle.self, from: data))
    }

    static func issue(_ text: String) -> NSError {
        NSError(domain: "RouterVPN.ViaEntry", code: 1, userInfo: [NSLocalizedDescriptionKey: text])
    }
}

@MainActor
final class IOSViaEntryReceipt {
    let capture: IOSViaEntryCapture
    let values: [IOSViaEntryValue]
    private let created = ProcessInfo.processInfo.systemUptime
    private let network: UInt64
    private let selection: IOSViaEntrySelection

    init(capture: IOSViaEntryCapture, values: [IOSViaEntryValue], model: RouterVPNModel, network: UInt64) throws {
        self.capture = capture; self.values = values; self.network = network
        selection = try IOSViaEntrySelection(model)
    }

    func requireCurrent(model: RouterVPNModel, entryID: String, entryMode: String) throws {
        guard !model.profileMutationBlocked, !model.iosSpeedLabOwnership.active,
              try IOSViaEntrySelection(model) == selection, capture.entryID == entryID, capture.entryMode == entryMode,
              ProcessInfo.processInfo.systemUptime - created < 120,
              IOSViaEntryNetwork.shared.current == network else {
            throw IOSViaEntryCapture.issue("The measured path, network or selection changed. Retest before selecting a result.")
        }
        try capture.requireSources(model: model)
    }

    var fastest: IOSViaEntryValue? {
        values.filter(\.eligible).min { $0.medianMS! < $1.medianMS! }
    }
}

@MainActor
final class IOSViaEntryLatency: ObservableObject {
    @Published private(set) var running = false
    @Published private(set) var progress = ""
    @Published private(set) var receipt: IOSViaEntryReceipt?
    @Published private(set) var error = ""
    private var task: Task<[IOSViaEntryValue], Error>?
    private var cancellationGeneration: UInt64 = 0

    func cancel() {
        cancellationGeneration &+= 1
        receipt = nil
        if running { progress = "Cancelling responses and draining the captured entry…"; task?.cancel() }
    }

    func invalidateIfStale(model: RouterVPNModel, entryID: String, mode: String) {
        guard let receipt, !running else { return }
        do { try receipt.requireCurrent(model: model, entryID: entryID, entryMode: mode) }
        catch { self.receipt = nil; self.error = error.localizedDescription }
    }

    /// Capture cancellation before enqueuing a UI task, so dismissing the
    /// sheet can revoke work even before the async method has begun.
    @discardableResult
    func start(model: RouterVPNModel, entryID: String, mode: String, candidates: [RouterProfile]) -> Task<Void, Never> {
        let generation = cancellationGeneration
        return Task { @MainActor in
            await measure(model: model, entryID: entryID, mode: mode, candidates: candidates, expectedGeneration: generation)
        }
    }

    func measure(model: RouterVPNModel, entryID: String, mode: String, candidates: [RouterProfile], expectedGeneration: UInt64? = nil) async {
        guard !running, expectedGeneration == nil || expectedGeneration == cancellationGeneration else { return }
        let generation = cancellationGeneration
        receipt = nil; error = ""; running = true
        defer { task = nil; running = false }
        do {
            let capture = try IOSViaEntryCapture(model: model, entryID: entryID, mode: mode, candidates: candidates)
            let network = try await IOSViaEntryNetwork.shared.snapshot()
            try Task.checkCancellation()
            guard cancellationGeneration == generation else { throw CancellationError() }
            let lifecycle = IOSSpeedLabRunner()
            let worker = Task { @MainActor in
                try await lifecycle.withTemporaryProvedPath(model: model, onSuperseded: { [weak self] in self?.task?.cancel() }, validateBeforeStart: {
                    try capture.requireInitialSelection(model: model)
                    guard IOSViaEntryNetwork.shared.current == network else { throw CancellationError() }
                }, prepare: {
                    try capture.requireSources(model: model)
                    guard IOSViaEntryNetwork.shared.current == network else { throw CancellationError() }
                    self.progress = "Proving temporary \(capture.entryName) / \(mode)…"
                    try model.importBundle(JSONEncoder().encode(capture.entryBundle))
                    try IOSSpeedLabPersistenceJournal.reassertOriginalPersistentState()
                    model.auto = false; model.selectedMode = mode; model.selectedLogicalMode = mode
                    await model.connect(rawProfileID: mode)
                    try Task.checkCancellation()
                    guard model.connected, model.selectedNodeProfile?.id == entryID, model.activeRawProfile == mode,
                          let identity = model.activeSessionIdentity, identity.entryBundleData == nil else {
                        throw IOSViaEntryCapture.issue("The temporary entry did not prove the exact selected single-hop transport.")
                    }
                }, measure: {
                    guard IOSViaEntryNetwork.shared.current == network else { throw CancellationError() }
                    self.progress = "Measuring candidate TCP responses through \(capture.entryName)…"
                    let deadline = ProcessInfo.processInfo.systemUptime + 120
                    var values: [IOSViaEntryValue] = []
                    for candidate in capture.candidates {
                        try Task.checkCancellation(); try capture.requireSources(model: model)
                        guard IOSViaEntryNetwork.shared.current == network,
                              ProcessInfo.processInfo.systemUptime < deadline else { throw CancellationError() }
                        self.progress = "\(capture.entryName) → \(candidate.name.isEmpty ? candidate.id : candidate.name) • \(values.count + 1)/\(capture.candidates.count)"
                        let value = try await IOSViaEntryTCP.measure(candidate, excluding: capture.excludedHosts, allowIPv6: capture.allowsIPv6)
                        try Task.checkCancellation()
                        guard IOSViaEntryNetwork.shared.current == network,
                              ProcessInfo.processInfo.systemUptime < deadline else { throw CancellationError() }
                        values.append(value)
                    }
                    try capture.requireSources(model: model)
                    self.progress = "Responses drained; stopping the temporary entry and restoring selection…"
                    return values
                })
            }
            task = worker
            let values = try await withTaskCancellationHandler { try await worker.value } onCancel: { worker.cancel() }
            try Task.checkCancellation(); try capture.requireSources(model: model)
            guard IOSViaEntryNetwork.shared.current == network else { throw CancellationError() }
            guard !model.profileMutationBlocked else { throw IOSViaEntryCapture.issue("The temporary entry has not finished teardown.") }
            receipt = try IOSViaEntryReceipt(capture: capture, values: values, model: model, network: network)
            progress = "Measured through \(capture.entryName); temporary entry stopped. Select an exit, then Connect separately."
        } catch is CancellationError {
            error = "Measurement cancelled or its captured path changed. No routed result was selected."
        } catch { self.error = error.localizedDescription }
    }
}
