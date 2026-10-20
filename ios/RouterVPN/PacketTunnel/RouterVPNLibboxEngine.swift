import Foundation
import Libbox

final class RouterVPNLibboxEngine {
    static let proofProxyPort = 1099
    private weak var tunnel: PacketTunnelProvider?
    private let platform: RouterVPNLibboxPlatform
    private var server: LibboxCommandServer?
    private var configContent = ""
    private var runtimeRoot: URL?
    private var multihop: LibboxRouterMultihop?
    private var hopMeasurement: LibboxRouterHopMeasurement?
    private var multihopHealth: DispatchSourceTimer?
    private var performanceHealth: DispatchSourceTimer?
    private let ownershipLock = NSLock()
    private var ownershipGeneration = UUID()
    private var starting = false
    let settingsEpoch: String
    private let strategyOwned: Bool
    private var nativeCloseFailure: Error?
    private var measurementLease = ""
    private var permanentlyStopped = false
    private var stopInProgress = false
    private var torOwned = false
    private var torProofDelivery: TorProofDelivery?
    private var torHealth: DispatchSourceTimer?
    private var externalPolicy: RouterVPNExternalPolicy?
    private var externalProofDelivery: ExternalProofDelivery?
    private var externalHealth: DispatchSourceTimer?
    private static let torRetirement = NativeRuntimeRetirement(label: "Tor")
    private static let externalRetirement = NativeRuntimeRetirement(label: "External VPN")
    private static let measurementRetirement = NativeRuntimeRetirement(label: "VPN measurement")
    private static let retiredMeasurements = RetiredHopMeasurements()

    init(tunnel: PacketTunnelProvider, strategyEpoch: String? = nil) {
        self.tunnel = tunnel
        let capturedEpoch = strategyEpoch ?? UUID().uuidString
        self.settingsEpoch = capturedEpoch
        self.strategyOwned = strategyEpoch != nil
        self.platform = RouterVPNLibboxPlatform(tunnel: tunnel, settingsEpoch: capturedEpoch)
        if strategyEpoch == nil { tunnel.beginLibboxSettings(epoch: capturedEpoch) }
        platform.onLog = { [weak tunnel] message in tunnel?.writeLibboxLog(message) }
        platform.onStopService = { [weak self] in try self?.closeService() }
        platform.onReloadService = { [weak self] in try self?.reloadService() }
    }

    func start(files: [String: Data], strict: Bool) throws {
        try start(files: files, strict: strict, multihopMetadata: nil)
    }

    func start(files: [String: Data], strict: Bool, externalPolicy: RouterVPNExternalPolicy) throws {
        try start(files: files, strict: strict, multihopMetadata: nil, externalPolicy: externalPolicy)
    }

    func start(files: [String: Data], strict: Bool, multihopMetadata: String?, entryStartLayerSource: String? = nil, exitStartLayerSource: String? = nil, externalPolicy: RouterVPNExternalPolicy? = nil) throws {
        try Self.torRetirement.requireAvailable()
        try Self.externalRetirement.requireAvailable()
        try Self.measurementRetirement.requireAvailable()
        let capturedLayer = try IOSMultihopStartLayer.requiredSource(metadata: multihopMetadata, source: entryStartLayerSource)
        let capturedExit = try IOSMultihopStartLayer.requiredExitSource(metadata: multihopMetadata, source: exitStartLayerSource)
        try RouterVPNLibboxCompileProbe.verifyPinnedRuntime()
        ownershipLock.lock()
        guard server == nil, !starting, !permanentlyStopped else { ownershipLock.unlock(); throw error("Libbox service is already running or retired") }
        starting = true
        self.externalPolicy = externalPolicy
        let generation = ownershipGeneration
        ownershipLock.unlock()
        var adopted = false
        defer {
            ownershipLock.lock()
            if ownershipGeneration == generation { starting = false }
            ownershipLock.unlock()
            if !adopted { _ = stopGeneration(generation) }
        }
        // Factory registration owns no peer or socket. Native PQ endpoints
        // create independent protocol handles only under this captured runtime.
        try RouterVPNPQFactory.install()
        guard externalPolicy == nil || (multihopMetadata == nil && entryStartLayerSource == nil && exitStartLayerSource == nil) else { throw error("External policy cannot replace another native graph owner") }
        var safeFiles = try validateAndInjectProof(files, externalPolicy: externalPolicy)
        let tor = try prepareTorState(safeFiles)
        ownershipLock.lock(); torOwned = tor; ownershipLock.unlock()
        if let multihopMetadata {
            guard let raw = safeFiles["sing-box.json"], let text = String(data: raw, encoding: .utf8) else { throw error("Missing multihop graph") }
            var failure: NSError?
            let prepared: LibboxRouterMultihop?
            if let capturedExit {
                prepared = LibboxNewRouterMultihopWithStartLayers(text, multihopMetadata, capturedLayer ?? "", capturedExit, &failure)
            } else if let capturedLayer {
                prepared = LibboxNewRouterMultihopWithEntryStartLayer(text, multihopMetadata, capturedLayer, &failure)
            } else {
                prepared = LibboxNewRouterMultihop(text, multihopMetadata, &failure)
            }
            guard let plan = prepared, failure == nil else { throw failure ?? error("Multihop controller could not be constructed") }
            ownershipLock.lock()
            guard ownershipGeneration == generation else { ownershipLock.unlock(); try? plan.close(); throw error("Libbox startup was cancelled") }
            multihop = plan
            ownershipLock.unlock()
            safeFiles["sing-box.json"] = Data(plan.config().utf8)
        }
        guard let config = safeFiles["sing-box.json"], let text = String(data: config, encoding: .utf8) else { throw error("Libbox profile is missing UTF-8 sing-box.json") }
        ownershipLock.lock()
        guard ownershipGeneration == generation else { ownershipLock.unlock(); throw error("Libbox startup was cancelled") }
        configContent = text
        ownershipLock.unlock()
        platform.includeAllNetworksRequested = strict
        let fm = FileManager.default
        let base = fm.temporaryDirectory.appendingPathComponent("routervpn-libbox-\(UUID().uuidString)", isDirectory: true)
        try fm.createDirectory(at: base, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        ownershipLock.lock()
        guard ownershipGeneration == generation else { ownershipLock.unlock(); try? fm.removeItem(at: base); throw error("Libbox startup was cancelled") }
        runtimeRoot = base
        ownershipLock.unlock()
        let work = base.appendingPathComponent("working", isDirectory: true), temp = base.appendingPathComponent("temp", isDirectory: true)
        try fm.createDirectory(at: work, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700]); try fm.createDirectory(at: temp, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        for (name, data) in safeFiles { let destination = base.appendingPathComponent(name); try data.write(to: destination, options: [.atomic]); try fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: destination.path) }
        let setup = LibboxSetupOptions(); setup.basePath = base.path; setup.workingPath = work.path; setup.tempPath = temp.path; setup.logMaxLines = 1000; setup.oomKillerEnabled = true; setup.commandServerSecret = UUID().uuidString
        var setupError: NSError?; LibboxSetup(setup, &setupError); if let setupError { throw error("Libbox setup failed: \(setupError.localizedDescription)") }
        var createError: NSError?; let created = LibboxNewCommandServer(platform, platform, &createError)
        if let createError { throw error("Libbox command server creation failed: \(createError.localizedDescription)") }
        guard let created else { throw error("Libbox command server creation returned nil") }
        ownershipLock.lock()
        guard ownershipGeneration == generation else { ownershipLock.unlock(); created.close(); throw error("Libbox startup was cancelled") }
        server = created
        ownershipLock.unlock()
        do {
            try created.start(); try startService()
            ownershipLock.lock()
            adopted = ownershipGeneration == generation && server === created
            ownershipLock.unlock()
            if !adopted { throw error("Libbox startup was cancelled") }
        } catch { _ = stopGeneration(generation); throw error }
    }

    func stop() { _ = stopGeneration(nil) }
    func stopCheckedForStrategy() throws {
        if let failure = stopGeneration(nil) { throw failure }
    }
    private func stopGeneration(_ expected: UUID?) -> Error? {
        ownershipLock.lock()
        if let expected, expected != ownershipGeneration { ownershipLock.unlock(); return nil }
        if permanentlyStopped {
            let failure = nativeCloseFailure ?? (stopInProgress ? error("Native shutdown is still in progress") : nil)
            ownershipLock.unlock(); return failure
        }
        stopInProgress = true
        permanentlyStopped = true
        ownershipGeneration = UUID()
        let plan = multihop, owned = server, health = multihopHealth, directory = runtimeRoot, probe = hopMeasurement, paddingHealth = performanceHealth, torDelivery = torProofDelivery, capturedTor = torOwned, torHealth = self.torHealth
        let externalDelivery = externalProofDelivery, externalHealth = self.externalHealth, capturedExternal = externalPolicy != nil
        hopMeasurement = nil; multihop = nil; server = nil; multihopHealth = nil; performanceHealth = nil; runtimeRoot = nil; configContent = ""; starting = false
        torProofDelivery = nil
        self.torHealth = nil
        externalProofDelivery = nil; self.externalHealth = nil; externalPolicy = nil
        ownershipLock.unlock()
        torDelivery?.cancel()
        torHealth?.cancel()
        externalDelivery?.cancel()
        externalHealth?.cancel()
        var mtuCloseFailure: Error?
        do { try platform.mtu.stopChecked() } catch { mtuCloseFailure = error }
        let mtuOwned = platform.mtu.hasOwner
        health?.cancel()
        paddingHealth?.cancel()
        if let owned { LibboxRouterInvalidatePerformance(owned) }
        // Keep the request reachable by its opaque ID while native shutdown
        // drains. An application cancellation must not release its MTU hold
        // merely because the provider replaced its current engine pointer.
        if let probe { Self.retiredMeasurements.retain(probe, session: settingsEpoch) }
        var measurementCloseFailure: Error?
        do { try probe?.close() } catch { measurementCloseFailure = error }
        if let plan {
            do { try plan.close() }
            catch { tunnel?.writeLibboxLog("Server multihop cleanup was not confirmed; its bounded lease expiry remains in force.") }
        }
        var closeFailure: Error?
        if let owned {
            if strategyOwned || capturedTor || capturedExternal || probe != nil || mtuOwned {
                var failure: NSError?
                let closed = LibboxRouterStrategyCloseService(owned, &failure)
                if !closed || failure != nil { closeFailure = failure ?? error("Native strategy teardown was not verified") }
            } else { try? owned.closeService() }
            if probe != nil {
                do { try probe?.close(); measurementCloseFailure = nil }
                catch { measurementCloseFailure = error }
            }
            if mtuOwned {
                // Closing the exact Box releases its blocked native I/O.
                // Retry only the controller retained by this MTU session.
                do { try platform.mtu.stopChecked(); mtuCloseFailure = nil }
                catch { mtuCloseFailure = error }
            }
            if closeFailure == nil { closeFailure = measurementCloseFailure }
            if closeFailure == nil { closeFailure = mtuCloseFailure }
            if capturedTor, let closeFailure {
                // The C runtime must not lose its last native/TUN/file owners
                // after an unconfirmed close. A new runtime in this extension
                // process is rejected; an OS process restart releases it.
                Self.torRetirement.retain(server: owned, platform: platform, directory: directory, failure: closeFailure, measurement: probe)
            } else if capturedExternal, let closeFailure {
                Self.externalRetirement.retain(server: owned, platform: platform, directory: directory, failure: closeFailure, measurement: probe)
            } else if probe != nil || mtuOwned, let closeFailure {
                Self.measurementRetirement.retain(server: owned, platform: platform, directory: directory, failure: closeFailure, measurement: probe)
            } else { owned.close() }
        }
        if !((capturedTor || capturedExternal || probe != nil || mtuOwned) && closeFailure != nil) {
            platform.reset()
            if let directory { try? FileManager.default.removeItem(at: directory) }
        }
        ownershipLock.lock()
        if let closeFailure { nativeCloseFailure = closeFailure }
        stopInProgress = false
        let result = nativeCloseFailure
        ownershipLock.unlock()
        return result
    }

    /// DNS and both node identities are proved by the captured native Box.
    /// This path never substitutes URLSession/system DNS for selected DNS.
    func proveExternal(completion: @escaping (Error?) -> Void) {
        ownershipLock.lock()
        guard let owned = server, let policy = externalPolicy, externalProofDelivery == nil, !permanentlyStopped else {
            ownershipLock.unlock(); completion(error("External proof has no captured native session")); return
        }
        let generation = ownershipGeneration, sessionID = UUID().uuidString.lowercased()
        var failure: NSError?
        let request = LibboxRouterExternalCreateProof(owned, policy.sourceConfig, policy.capture, sessionID, &failure)
        guard let request, failure == nil else { ownershipLock.unlock(); completion(failure ?? error("External proof could not capture its native owner")); return }
        let delivery = ExternalProofDelivery(owner: self, server: owned, generation: generation,
            policy: policy, sessionID: sessionID, request: request, completion: completion)
        externalProofDelivery = delivery
        ownershipLock.unlock()
        DispatchQueue.global(qos: .userInitiated).async { delivery.run() }
    }

    private final class ExternalProofDelivery: @unchecked Sendable {
        private weak var owner: RouterVPNLibboxEngine?
        private let server: LibboxCommandServer
        private let generation: UUID
        private let policy: RouterVPNExternalPolicy
        private let sessionID: String
        private let request: LibboxRouterExternalProofRequest
        private let lock = NSLock()
        private var callback: ((Error?) -> Void)?
        private var started = false
        private var cancelled = false
        init(owner: RouterVPNLibboxEngine, server: LibboxCommandServer, generation: UUID,
             policy: RouterVPNExternalPolicy, sessionID: String, request: LibboxRouterExternalProofRequest,
             completion: @escaping (Error?) -> Void) {
            self.owner = owner; self.server = server; self.generation = generation; self.policy = policy
            self.sessionID = sessionID; self.request = request; self.callback = completion
        }
        private func current(_ owner: RouterVPNLibboxEngine) -> Bool {
            owner.ownershipLock.lock(); defer { owner.ownershipLock.unlock() }
            return owner.server === server && owner.ownershipGeneration == generation && owner.externalProofDelivery === self && !owner.permanentlyStopped
        }
        private func finish(_ error: Error?) {
            lock.lock(); let callback = self.callback; self.callback = nil; lock.unlock()
            callback?(error)
        }
        func cancel() {
            lock.lock(); cancelled = true; lock.unlock()
            request.cancel()
            finish(retired())
        }
        func run() {
            lock.lock()
            guard !started, !cancelled else { lock.unlock(); return }
            started = true; lock.unlock()
            do {
                guard let owner, current(owner) else { throw retired() }
                let began = Date()
                let result = try request.run()
                try policy.validateProof(result, sessionID: sessionID, began: began)
                guard current(owner), request.healthy() else { throw retired() }
                lock.lock(); let usable = !cancelled; lock.unlock()
                guard usable else { throw retired() }
                let timer = DispatchSource.makeTimerSource(queue: DispatchQueue.global(qos: .utility))
                timer.schedule(deadline: .now() + 1, repeating: 1)
                timer.setEventHandler { [self] in checkHealth() }
                owner.ownershipLock.lock()
                let retained = owner.server === server && owner.ownershipGeneration == generation && owner.externalProofDelivery === self && !owner.permanentlyStopped
                if retained { owner.externalHealth?.cancel(); owner.externalHealth = timer; timer.resume() }
                owner.ownershipLock.unlock()
                guard retained else { timer.setEventHandler {}; timer.resume(); timer.cancel(); throw retired() }
                finish(nil)
            } catch { finish(error) }
        }
        private func checkHealth() {
            guard let owner, current(owner), !request.healthy(), current(owner) else { return }
            owner.tunnel?.nativeLibboxFailure(owner, error: retired())
        }
        func makeHopMeasurement() throws -> LibboxRouterHopMeasurement {
            guard let owner, current(owner), request.healthy() else { throw retired() }
            var failure: NSError?
            guard let probe = LibboxRouterExternalCreateHopMeasurement(server, request, policy.sourceConfig, policy.capture, sessionID, &failure), failure == nil else {
                throw failure ?? retired()
            }
            guard current(owner), request.healthy() else { try probe.close(); throw retired() }
            return probe
        }
        func activateMTU() throws {
            guard let owner, current(owner), request.healthy() else { throw retired() }
            let delivery = MTUFailureDelivery(owner: owner, generation: generation)
            try owner.platform.mtu.activateExternal(server: server, proof: request, source: policy.sourceConfig, capture: policy.capture) { message in delivery.fail(message) }
            guard current(owner), request.healthy() else { owner.platform.mtu.stop(); throw retired() }
        }
        private func retired() -> NSError {
            NSError(domain: "RouterVPN.ExternalProof", code: 1, userInfo: [NSLocalizedDescriptionKey: "External DNS and node proof was cancelled or belongs to a retired native session."])
        }
    }

    private func prepareTorState(_ files: [String: Data]) throws -> Bool {
        guard let data = files["sing-box.json"],
              let root = try JSONSerialization.jsonObject(with: data) as? [String: Any] else { throw error("Missing captured native configuration") }
        let tor = (root["outbounds"] as? [[String: Any]] ?? []).filter { $0["type"] as? String == "routervpn-tor" }
        guard !tor.isEmpty else { return false }
        guard tor.count == 1 else { throw error("A VPN session must own one Tor runtime") }
        let manager = FileManager.default
        guard let support = manager.urls(for: .applicationSupportDirectory, in: .userDomainMask).first else { throw error("Private Tor state storage is unavailable") }
        try manager.createDirectory(at: support, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        // Resolve only the trusted container parent (including Apple's /var
        // alias). The native setter rejects a linked/replaced child directory.
        var directory = support.resolvingSymlinksInPath().appendingPathComponent("RouterVPN-Tor", isDirectory: true)
        var failure: NSError?
        LibboxRouterTorSetStateDirectory(directory.path, &failure)
        if let failure { throw failure }
        var resources = URLResourceValues(); resources.isExcludedFromBackup = true
        try directory.setResourceValues(resources)
        return true
    }

    func proveTor(sessionID: String, predecessorProfile: String? = nil, completion: @escaping (Error?) -> Void) {
        ownershipLock.lock()
        guard let owned = server, torOwned, torProofDelivery == nil, !permanentlyStopped else {
            ownershipLock.unlock(); completion(error("Tor proof has no captured native session")); return
        }
        let generation = ownershipGeneration
        var failure: NSError?
        let request: LibboxRouterTorProofRequest?
        if let predecessorProfile {
            request = LibboxRouterTorCreateProofWithPredecessor(owned, "routervpn-tor-exit", sessionID, predecessorProfile, &failure)
        } else {
            request = LibboxRouterTorCreateProof(owned, "routervpn-tor-exit", sessionID, &failure)
        }
        guard let request, failure == nil else { ownershipLock.unlock(); completion(failure ?? error("Tor proof could not capture its native owner")); return }
        let delivery = TorProofDelivery(owner: self, server: owned, generation: generation, sessionID: sessionID, request: request, completion: completion)
        torProofDelivery = delivery
        ownershipLock.unlock()
        DispatchQueue.global(qos: .userInitiated).async { delivery.run() }
    }

    // Only the locked delivery crosses Swift's Sendable boundary. Native Run
    // and Cancel act on the same captured Box/outbound; no newer server is read
    // to interrupt an older proof, and its callback is consumed exactly once.
    private final class TorProofDelivery: @unchecked Sendable {
        private weak var owner: RouterVPNLibboxEngine?
        private let server: LibboxCommandServer
        private let generation: UUID
        private let sessionID: String
        private let request: LibboxRouterTorProofRequest
        private let lock = NSLock()
        private var callback: ((Error?) -> Void)?
        private var started = false
        private var cancelled = false
        init(owner: RouterVPNLibboxEngine, server: LibboxCommandServer, generation: UUID, sessionID: String,
             request: LibboxRouterTorProofRequest, completion: @escaping (Error?) -> Void) {
            self.owner = owner; self.server = server; self.generation = generation; self.sessionID = sessionID
            self.request = request; self.callback = completion
        }
        private func current(_ owner: RouterVPNLibboxEngine) -> Bool {
            owner.ownershipLock.lock(); defer { owner.ownershipLock.unlock() }
            return owner.server === server && owner.ownershipGeneration == generation && owner.torProofDelivery === self && !owner.permanentlyStopped
        }
        private func finish(_ error: Error?) {
            lock.lock(); let callback = self.callback; self.callback = nil; lock.unlock()
            callback?(error)
        }
        func cancel() {
            lock.lock(); cancelled = true; lock.unlock()
            request.cancel()
            finish(NSError(domain: "RouterVPN.Tor", code: 1, userInfo: [NSLocalizedDescriptionKey: "Tor connection was cancelled."]))
        }
        func run() {
            lock.lock()
            guard !started, !cancelled else { lock.unlock(); return }
            started = true
            lock.unlock()
            do {
                guard let owner, current(owner) else { throw retired() }
                let began = Date()
                let text = try request.run()
                guard text.utf8.count <= 4096, let data = text.data(using: .utf8),
                      let value = try JSONSerialization.jsonObject(with: data) as? [String: Any],
                      Set(value.keys) == Set(["session_id", "ip", "is_tor", "checked_at"]),
                      value["session_id"] as? String == sessionID, value["is_tor"] as? Bool == true,
                      let ip = value["ip"] as? String, !ip.isEmpty, ip.utf8.count <= 64,
                      let timestamp = value["checked_at"] as? String else { throw retired() }
                let clock = ISO8601DateFormatter(); clock.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
                var checked = clock.date(from: timestamp)
                if checked == nil { clock.formatOptions = [.withInternetDateTime]; checked = clock.date(from: timestamp) }
                guard let checked, checked >= began.addingTimeInterval(-2), checked <= Date().addingTimeInterval(5), current(owner) else { throw retired() }
                lock.lock(); let usable = !cancelled; lock.unlock()
                guard usable else { throw retired() }
                var dnsFailure: NSError?
                let dnsProved = LibboxRouterStrategyDNSProof(server, &dnsFailure)
                if let dnsFailure { throw dnsFailure }
                guard dnsProved, current(owner) else { throw retired() }
                guard request.healthy() else { throw retired() }
                let timer = DispatchSource.makeTimerSource(queue: DispatchQueue.global(qos: .utility))
                timer.schedule(deadline: .now() + 1, repeating: 1)
                timer.setEventHandler { [self] in checkHealth() }
                owner.ownershipLock.lock()
                let retained = owner.server === server && owner.ownershipGeneration == generation && owner.torProofDelivery === self && !owner.permanentlyStopped
                if retained {
                    owner.torHealth?.cancel(); owner.torHealth = timer
                    timer.resume()
                }
                owner.ownershipLock.unlock()
                guard retained else { timer.setEventHandler {}; timer.resume(); timer.cancel(); throw retired() }
                finish(nil)
            } catch { finish(error) }
        }
        private func checkHealth() {
            guard let owner, current(owner), !request.healthy(), current(owner) else { return }
            owner.tunnel?.nativeLibboxFailure(owner, error: retired())
        }
        func makeHopMeasurement(exitID: String) throws -> LibboxRouterHopMeasurement {
            guard let owner, current(owner), request.healthy() else { throw retired() }
            var failure: NSError?
            guard let probe = LibboxRouterTorCreateHopMeasurement(server, request, exitID, &failure), failure == nil else {
                throw failure ?? retired()
            }
            guard current(owner), request.healthy() else { try probe.close(); throw retired() }
            return probe
        }
        private func retired() -> NSError {
            NSError(domain: "RouterVPN.Tor", code: 2, userInfo: [NSLocalizedDescriptionKey: "Tor exit proof is invalid or belongs to a retired session."])
        }
    }

    private final class NativeRuntimeRetirement: @unchecked Sendable {
        private let lock = NSLock()
        private let label: String
        private var retired: [(LibboxCommandServer, RouterVPNLibboxPlatform, URL?, LibboxRouterHopMeasurement?)] = []
        init(label: String) { self.label = label }
        func retain(server: LibboxCommandServer, platform: RouterVPNLibboxPlatform, directory: URL?, failure: Error, measurement: LibboxRouterHopMeasurement? = nil) {
            lock.lock(); retired.append((server, platform, directory, measurement)); lock.unlock()
        }
        func requireAvailable() throws {
            lock.lock(); let blocked = !retired.isEmpty; lock.unlock()
            if blocked { throw NSError(domain: "RouterVPN.NativeRetirement", code: 3, userInfo: [NSLocalizedDescriptionKey: "\(label) shutdown was not confirmed. Restart the VPN extension before starting another connection."]) }
        }
    }

    func proveStrategyDNS() throws {
        ownershipLock.lock()
        let owned = server, generation = ownershipGeneration
        ownershipLock.unlock()
        guard strategyOwned, let owned else { throw error("Strategy DNS proof has no owned native runtime") }
        var failure: NSError?
        let proved = LibboxRouterStrategyDNSProof(owned, &failure)
        if let failure { throw failure }
        guard proved else { throw error("The selected native DNS route did not pass proof") }
        ownershipLock.lock()
        let current = server === owned && ownershipGeneration == generation
        ownershipLock.unlock()
        guard current else { throw error("Strategy DNS proof belongs to a replaced native runtime") }
    }
    /// Activate only after the final selected path is proved. The services
    /// remain owned by this native instance and are closed with it.
    func prepareMTUHold(_ lease: String) throws {
        try platform.mtu.initialMeasurementHold(lease)
        ownershipLock.lock(); measurementLease = lease; ownershipLock.unlock()
    }
    var strategyMTUHold: String {
        ownershipLock.lock(); defer { ownershipLock.unlock() }; return measurementLease
    }

    func activateMTU(profile: [String: Any]) {
        guard let data = try? JSONSerialization.data(withJSONObject: profile), data.count <= 65536,
              let metadata = String(data: data, encoding: .utf8) else { return }
        ownershipLock.lock()
        guard let owned = server else { ownershipLock.unlock(); return }
        let generation = ownershipGeneration, config = configContent
        let delivery = MTUFailureDelivery(owner: self, generation: generation)
        ownershipLock.unlock()
        platform.mtu.activate(server: owned, config: config, profile: metadata) { message in delivery.fail(message) }
        ownershipLock.lock(); let current = server === owned && ownershipGeneration == generation; ownershipLock.unlock()
        if !current { platform.mtu.stop() }
    }
    func activateExternalMTU() throws {
        ownershipLock.lock()
        let delivery = externalProofDelivery
        let current = server != nil && !starting && !permanentlyStopped && torProofDelivery == nil
        ownershipLock.unlock()
        guard current, let delivery else { throw error("External MTU requires the captured ordinary native proof") }
        try delivery.activateMTU()
    }
    func mtuRequest(operation: String, request: String, session: String) -> Data? {
        ownershipLock.lock(); let generation = ownershipGeneration; ownershipLock.unlock()
        let result = platform.mtu.request(operation: operation, request: request, session: session)
        ownershipLock.lock(); defer { ownershipLock.unlock() }
        guard ownershipGeneration == generation else { return nil }
        if result != nil {
            if operation == "mtu-hold" { measurementLease = request }
            if operation == "mtu-release" { measurementLease = "" }
        }
        return result
    }
    private final class MTUFailureDelivery: @unchecked Sendable {
        private weak var owner: RouterVPNLibboxEngine?
        private let generation: UUID
        init(owner: RouterVPNLibboxEngine, generation: UUID) { self.owner = owner; self.generation = generation }
        func fail(_ message: String) {
            guard let owner else { return }
            owner.ownershipLock.lock()
            let current = owner.ownershipGeneration == generation && owner.server != nil
            owner.ownershipLock.unlock()
            if current { owner.tunnel?.nativeLibboxFailure(owner, error: owner.error(message)) }
        }
    }

    func activatePerformance() throws {
        ownershipLock.lock()
        let owned = server, generation = ownershipGeneration
        ownershipLock.unlock()
        guard let owned else { throw error("Native performance owner is missing") }
        var count: Int64 = 0
        var failure: NSError?
        let success = LibboxRouterStartPerformance(owned, &count, &failure)
        if let failure { throw failure }
        guard success, (0...2).contains(count) else { throw error("Native performance activation returned an invalid result") }
        guard count > 0 else { return }
        let watcher = PerformanceWatch(owner: self, server: owned, generation: generation)
        let timer = DispatchSource.makeTimerSource(queue: DispatchQueue.global(qos: .utility))
        timer.schedule(deadline: .now() + .milliseconds(500), repeating: .milliseconds(500))
        timer.setEventHandler { watcher.check() }
        ownershipLock.lock()
        let current = ownershipGeneration == generation && server === owned
        if current { performanceHealth?.cancel(); performanceHealth = timer; timer.resume() }
        ownershipLock.unlock()
        if !current { timer.setEventHandler {}; timer.resume(); timer.cancel(); LibboxRouterInvalidatePerformance(owned); throw error("Native performance activation became stale") }
    }
    private final class PerformanceWatch: @unchecked Sendable {
        private weak var owner: RouterVPNLibboxEngine?
        private let server: LibboxCommandServer
        private let generation: UUID
        init(owner: RouterVPNLibboxEngine, server: LibboxCommandServer, generation: UUID) { self.owner = owner; self.server = server; self.generation = generation }
        func check() {
            guard let owner else { return }
            owner.ownershipLock.lock()
            let current = owner.server === server && owner.ownershipGeneration == generation
            owner.ownershipLock.unlock()
            guard current else { return }
            let failure = LibboxRouterPerformanceFailure(server)
            guard failure == nil || failure != "" else { return }
            owner.ownershipLock.lock()
            let stillCurrent = owner.server === server && owner.ownershipGeneration == generation
            owner.ownershipLock.unlock()
            if stillCurrent { owner.tunnel?.nativeLibboxFailure(owner, error: owner.error("Requested padding stopped or its private path changed.")) }
        }
    }

    func completeMultihopExecution(_ completion: @escaping (Error?) -> Void) {
        ownershipLock.lock()
        let capturedPlan = multihop, capturedServer = server, generation = ownershipGeneration
        ownershipLock.unlock()
        guard let plan = capturedPlan, let owned = capturedServer else { completion(nil); return }
        let delivery = MultihopDelivery(owner: self, plan: plan, server: owned,
                                        generation: generation, completion: completion)
        DispatchQueue.global(qos: .userInitiated).async { delivery.run() }
    }

    /// Only this delivery object crosses Dispatch's Sendable boundary. The
    /// generated Objective-C handles predate Sendable: the Go controller locks
    /// its state and Close cancels/waits for Run before the command server closes.
    /// Swift ownership is checked under ownershipLock. The callback is consumed
    /// once under callbackLock; the timer retains delivery, never the engine.
    /// Do not mark all Libbox handles or the whole engine unchecked Sendable.
    private final class MultihopDelivery: @unchecked Sendable {
        private weak var owner: RouterVPNLibboxEngine?
        private let plan: LibboxRouterMultihop
        private let server: LibboxCommandServer
        private let generation: UUID
        private let callbackLock = NSLock()
        private var callback: ((Error?) -> Void)?
        private var started = false

        init(owner: RouterVPNLibboxEngine, plan: LibboxRouterMultihop,
             server: LibboxCommandServer, generation: UUID,
             completion: @escaping (Error?) -> Void) {
            self.owner = owner; self.plan = plan; self.server = server
            self.generation = generation; self.callback = completion
        }
        private func finish(_ error: Error?) {
            callbackLock.lock()
            let completion = callback
            callback = nil
            callbackLock.unlock()
            completion?(error)
        }
        private func isCurrent(_ owner: RouterVPNLibboxEngine) -> Bool {
            owner.ownershipLock.lock()
            defer { owner.ownershipLock.unlock() }
            return owner.ownershipGeneration == generation && owner.multihop === plan && owner.server === server
        }
        func run() {
            callbackLock.lock()
            guard !started else { callbackLock.unlock(); return }
            started = true
            callbackLock.unlock()
            do {
                guard let owner, isCurrent(owner) else { throw staleOwner() }
                try plan.run(server)
                guard isCurrent(owner) else { throw staleOwner() }
                let timer = DispatchSource.makeTimerSource(queue: DispatchQueue.global(qos: .utility))
                timer.schedule(deadline: .now() + 1, repeating: 1)
                timer.setEventHandler { [self] in checkHealth() }
                owner.ownershipLock.lock()
                let current = owner.ownershipGeneration == generation && owner.server === server && owner.multihop === plan
                if current {
                    owner.multihopHealth?.cancel()
                    owner.multihopHealth = timer
                    // Resume before releasing ownership: Stop cannot cancel a
                    // suspended timer or leave a newly resumed orphan behind.
                    timer.resume()
                }
                owner.ownershipLock.unlock()
                guard current else {
                    timer.setEventHandler {}; timer.resume(); timer.cancel()
                    throw staleOwner()
                }
                finish(nil)
            } catch { finish(error) }
        }
        private func checkHealth() {
            guard let owner, isCurrent(owner) else { return }
            let healthy = plan.healthy()
            guard !healthy, isCurrent(owner) else { return }
            owner.tunnel?.cancelTunnelWithError(owner.error("Multihop lease or network proof expired; reconnect to compare again."))
        }
        private func staleOwner() -> NSError {
            NSError(domain: "RouterVPN.Multihop", code: 1,
                    userInfo: [NSLocalizedDescriptionKey: "Multihop runtime changed before completion."])
        }
    }
    // Installed only after both hop identities are proved. Metadata comes from
    // the captured bundles, never from application IPC or an edited selection.
    func enableHopMeasurement(metadata: String) throws {
        ownershipLock.lock()
        defer { ownershipLock.unlock() }
        guard let server, !starting, hopMeasurement == nil else { throw error("Hop measurement owner is unavailable") }
        var failure: NSError?
        guard let probe = LibboxNewRouterHopMeasurement(server, metadata, &failure), failure == nil else {
            throw failure ?? error("Cannot bind hop measurement to the native tunnel")
        }
        hopMeasurement = probe
    }
    func enableExternalHopMeasurement(exitID: String) throws {
        ownershipLock.lock()
        let external = externalProofDelivery, tor = torProofDelivery, generation = ownershipGeneration
        let available = server != nil && !starting && !permanentlyStopped && hopMeasurement == nil
        ownershipLock.unlock()
        guard available, (external != nil) != (tor != nil) else { throw error("External measurement requires one captured native proof") }
        let probe: LibboxRouterHopMeasurement
        if let external { probe = try external.makeHopMeasurement() }
        else if let tor { probe = try tor.makeHopMeasurement(exitID: exitID) }
        else { throw error("External measurement proof was lost") }
        ownershipLock.lock()
        let current = ownershipGeneration == generation && !permanentlyStopped && hopMeasurement == nil &&
            externalProofDelivery === external && torProofDelivery === tor
        if current { hopMeasurement = probe }
        ownershipLock.unlock()
        guard current else { try probe.close(); throw error("External measurement belongs to a retired native generation") }
    }
    func hopMeasurementRequest(operation: String, request: String, session: String) -> Data? {
        ownershipLock.lock()
        defer { ownershipLock.unlock() }
        guard session == settingsEpoch, let probe = hopMeasurement, !permanentlyStopped else { return nil }
        if operation == "hop-measure-start" {
            guard !platform.mtu.hasOwner || platform.mtu.measurementReady else { return nil }
            return Self.retiredMeasurements.start(probe, request: request, session: session)
        }
        return Self.retiredMeasurements.reply(operation: operation, request: request, session: session)
    }
    static func retiredHopMeasurementRequest(operation: String, request: String, session: String) -> Data? {
        retiredMeasurements.reply(operation: operation, request: request, session: session)
    }
    // Every request is registered before native Start. A cancel that overtakes
    // Start creates a receipt and prevents that late message from doing work.
    // The immutable settings epoch also rejects an old start on a new tunnel.
    private final class RetiredHopMeasurements: @unchecked Sendable {
        private let lock = NSLock()
        private var owners: [String: LibboxRouterHopMeasurement] = [:]
        private var receipts: [String: Data] = [:]
        private var order: [String] = []
        private func key(_ request: String, _ session: String) -> String { session + ":" + request }
        private func data(_ probe: LibboxRouterHopMeasurement, request: String, session: String) -> Data? {
            let raw = Data(probe.statusJSON().utf8)
            guard raw.count <= 16384,
                  var value = try? JSONSerialization.jsonObject(with: raw) as? [String: Any],
                  value["request_id"] as? String == request else { return nil }
            value["session_id"] = session
            guard let data = try? JSONSerialization.data(withJSONObject: value), data.count <= 16384 else { return nil }
            return data
        }
        func start(_ probe: LibboxRouterHopMeasurement, request: String, session: String) -> Data? {
            lock.lock(); defer { lock.unlock() }
            let id = key(request, session)
            guard owners[id] == nil, receipts[id] == nil, !owners.values.contains(where: { $0 === probe }) else { return nil }
            do { try probe.start(request, bytes: 8388608) } catch { return nil }
            owners[id] = probe
            return data(probe, request: request, session: session)
        }
        func retain(_ probe: LibboxRouterHopMeasurement, session: String) {
            let raw = Data(probe.statusJSON().utf8)
            guard raw.count <= 16384,
                  let value = try? JSONSerialization.jsonObject(with: raw) as? [String: Any],
                  let request = value["request_id"] as? String,
                  request.range(of: "^[0-9a-f]{32}$", options: .regularExpression) != nil else { return }
            let id = key(request, session)
            lock.lock(); if receipts[id] == nil { owners[id] = probe }; lock.unlock()
        }
        private func save(_ data: Data, key: String) {
            if receipts[key] == nil { order.append(key) }
            receipts[key] = data
            while order.count > 128 { receipts.removeValue(forKey: order.removeFirst()) }
        }
        func reply(operation: String, request: String, session: String) -> Data? {
            guard operation == "hop-measure-status" || operation == "hop-measure-cancel" else { return nil }
            lock.lock(); defer { lock.unlock() }
            let id = key(request, session)
            guard let probe = owners[id] else {
                if let receipt = receipts[id] { return receipt }
                guard operation == "hop-measure-cancel",
                      let receipt = try? JSONSerialization.data(withJSONObject: ["request_id": request,
                        "session_id": session, "stage": "cancelled", "complete": true,
                        "drained": true, "results": [], "failure": "Measurement cancelled before activation."]) else { return nil }
                save(receipt, key: id)
                return receipt
            }
            if operation == "hop-measure-cancel" { probe.cancel(request) }
            guard let response = data(probe, request: request, session: session),
                  let value = try? JSONSerialization.jsonObject(with: response) as? [String: Any] else { return nil }
            if value["drained"] as? Bool == true {
                owners.removeValue(forKey: id); save(response, key: id)
            }
            return response
        }
    }
    func multihopProgress() -> Data? {
        ownershipLock.lock(); let plan = multihop; ownershipLock.unlock()
        guard let plan else { return nil }
        let data = Data(plan.progressJSON().utf8)
        return data.count <= 16384 ? data : nil
    }
    func invalidateMultihop() {
        platform.mtu.invalidate()
        ownershipLock.lock(); let plan = multihop, probe = hopMeasurement, owned = server, torDelivery = torProofDelivery, externalDelivery = externalProofDelivery; ownershipLock.unlock()
        torDelivery?.cancel()
        externalDelivery?.cancel()
        if let owned { LibboxRouterInvalidatePerformance(owned) }
        probe?.networkChanged(); plan?.networkChanged()
    }
    func pause() {
        platform.mtu.invalidate()
        ownershipLock.lock(); let plan = multihop, owned = server, probe = hopMeasurement, torDelivery = torProofDelivery, externalDelivery = externalProofDelivery; ownershipLock.unlock()
        torDelivery?.cancel()
        externalDelivery?.cancel()
        if let owned { LibboxRouterInvalidatePerformance(owned) }
        probe?.networkChanged(); plan?.networkChanged(); owned?.pause()
    }
    func wake() { ownershipLock.lock(); let owned = server; ownershipLock.unlock(); owned?.wake() }
    private func startService() throws {
        ownershipLock.lock(); let owned = server, content = configContent; ownershipLock.unlock()
        guard let server = owned, !content.isEmpty else { throw error("Libbox service is not configured") }
        if strategyOwned || torOwned || externalPolicy != nil {
            var failure: NSError?
            let started = LibboxRouterStrategyStartService(server, content, &failure)
            if let failure { throw failure }
            guard started else { throw error("The fresh native strategy runtime did not start") }
        } else { try server.startOrReloadService(content, options: LibboxOverrideOptions()) }
    }
    private func closeService() throws {
        if strategyOwned || torOwned || externalPolicy != nil || platform.mtu.hasOwner {
            tunnel?.nativeLibboxFailure(self, error: error("The owned native strategy requested service stop."))
            return
        }
        try platform.mtu.stopChecked(); ownershipLock.lock(); let owned = server; ownershipLock.unlock(); try owned?.closeService()
    }
    private func reloadService() throws {
        guard !strategyOwned, !torOwned, externalPolicy == nil else { throw error("Provider strategies, Tor and external policies require a fresh owned native generation") }
        ownershipLock.lock(); let comparing = multihop != nil || hopMeasurement != nil || performanceHealth != nil; ownershipLock.unlock()
        guard !comparing, !platform.mtu.hasOwner else { throw error("Native reload requires a fresh owned comparison and MTU session") }
        try startService()
    }

    private func validateAndInjectProof(_ files: [String: Data], externalPolicy: RouterVPNExternalPolicy? = nil) throws -> [String: Data] {
        guard !files.isEmpty, files.count <= 64 else { throw error("Libbox profile file count is invalid") }
        let regex = try NSRegularExpression(pattern: "^[A-Za-z0-9._-]{1,128}$"); var total = 0; var result = files
        for (name, data) in files {
            let range = NSRange(name.startIndex..<name.endIndex, in: name)
            guard regex.firstMatch(in: name, range: range)?.range == range, name != ".", name != "..", !name.contains("..") else { throw error("Unsafe Libbox asset name: \(name)") }
            guard data.count <= 4 * 1024 * 1024 else { throw error("Libbox asset too large: \(name)") }
            total += data.count; guard total <= 12 * 1024 * 1024 else { throw error("Libbox profile exceeds total size limit") }
        }
        guard let config = files["sing-box.json"], var object = try JSONSerialization.jsonObject(with: config) as? [String: Any] else { throw error("Libbox sing-box.json is not a JSON object") }
        if let externalPolicy {
            guard config == Data(externalPolicy.config.utf8) else { throw error("External native graph differs from its compiled policy") }
            // The native proof request uses the captured outbounds directly.
            // Preserve exact compiler bytes and add no localhost bypass owner.
            return result
        }
        var inbounds = object["inbounds"] as? [[String: Any]] ?? []
        for inbound in inbounds {
            if (inbound["tag"] as? String) == "routervpn-proof" { throw error("Libbox profile reserves inbound tag routervpn-proof") }
            if (inbound["listen"] as? String) == "127.0.0.1", (inbound["listen_port"] as? Int) == Self.proofProxyPort { throw error("Libbox profile already uses Router VPN proof port \(Self.proofProxyPort)") }
        }
        inbounds.append(["type": "mixed", "tag": "routervpn-proof", "listen": "127.0.0.1", "listen_port": Self.proofProxyPort])
        object["inbounds"] = inbounds
        let patched = try JSONSerialization.data(withJSONObject: object, options: [.prettyPrinted, .sortedKeys])
        guard patched.count <= 4 * 1024 * 1024 else { throw error("Patched Libbox sing-box.json exceeds safety limit") }
        result["sing-box.json"] = patched
        return result
    }
    private func error(_ message: String) -> NSError { NSError(domain: "RouterVPN.LibboxEngine", code: 1, userInfo: [NSLocalizedDescriptionKey: message]) }
}
