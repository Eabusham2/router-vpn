import Libbox
import CFNetwork
import CryptoKit
import Foundation
@preconcurrency import Network
import NetworkExtension
import WireGuardKit

final class PacketTunnelProvider: NEPacketTunnelProvider {
    private static let maxBundleBytes = 32 * 1024 * 1024
    private static let maxProfileBytes = 4 * 1024 * 1024
    private static let maxLayeredBytes = 12 * 1024 * 1024
    private static let maxProofBytes = 16 * 1024
    private static let proofKind = "router-vpn-private-agent-v1"
    private static let nodeProofDomain = "router-vpn-node-proof-v1\n"

    private final class NetworkProofGuard: @unchecked Sendable {
        private let lock = NSLock()
        private var sawInitialPath = false
        private var fingerprint: String?
        private var invalidated = false
        weak var owner: PacketTunnelProvider?

        init(owner: PacketTunnelProvider) { self.owner = owner }

        func handle(_ path: NWPath) {
            let current = RouterVPNPhysicalPath.snapshot(path)?.signature
            lock.lock()
            if !sawInitialPath {
                sawInitialPath = true
                fingerprint = current
                lock.unlock()
                return
            }
            if let current, current == fingerprint { lock.unlock(); return }
            if invalidated {
                lock.unlock()
                return
            }
            invalidated = true
            lock.unlock()
            owner?.invalidateSelectedPathProof(self)
        }
    }

    private var initialMTUHold = ""
    private var multihopExecutionSource: IOSMultihopExecution.Source?
    private var restoredMultihopExecution: String?
    private var restoredMultihopIdentityPins: IOSMultihopExecution.ServerIdentityPins?
    private var forwardingChannel: RouterVPNForwardingChannel?
    private let telemetryLock = NSLock()
    private var telemetryChannel: RouterVPNTelemetryChannel?
    private var telemetryProof: NetworkProofGuard?
    private var networkSettingsOwner: RouterVPNSettingsQueue<NEPacketTunnelNetworkSettings>?
    private let strategyOwnerLock = NSLock()
    private var providerStrategy: RouterVPNProviderStrategy?
    private var strategyDriver: StrategyRuntimeDriver?
    private let maxStartOwnerLock = NSLock()
    private var maxStartOwner: RouterVPNMAXStart?
    private var maxStartGeneration = UUID()
    private var maxStartDraining = false

    override init() {
        super.init()
        forwardingChannel = RouterVPNForwardingChannel(provider: self)
        networkSettingsOwner = RouterVPNSettingsQueue { [weak self] settings, completion in
            guard let self else { completion(NSError(domain: "RouterVPN.NetworkSettings", code: 1)); return }
            self.setTunnelNetworkSettings(settings, completionHandler: completion)
        }
    }

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)? = nil) {
        guard let completionHandler else { return }
        if messageData.count <= 1024, (try? IOSTelemetryProtocol.command(messageData)) != nil {
            completionHandler(currentTelemetryChannel()?.handle(messageData)); return
        }
        if messageData.count <= 8192,
           let request = try? JSONSerialization.jsonObject(with: messageData) as? [String: Any],
           let operation = request["operation"] as? String, operation.hasPrefix("strategy-") {
            completionHandler(currentProviderStrategy()?.handle(messageData)); return
        }
        if messageData.count <= 128,
           let request = try? JSONSerialization.jsonObject(with: messageData) as? [String: String],
           request == ["operation": "multihop-progress"] {
            completionHandler(libboxEngine?.multihopProgress()); return
        }
        if messageData.count <= 256,
           let request = try? JSONSerialization.jsonObject(with: messageData) as? [String: String],
           Set(request.keys) == Set(["operation", "request_id", "session_id"]),
           request["operation"] == "speed-lab-execution", request["session_id"] == "",
           let id = request["request_id"], id.range(of: "^[0-9a-f]{32}$", options: .regularExpression) != nil {
            guard let engine = libboxEngine, let guardState = currentPathProofGuard() else { completionHandler(nil); return }
            let reply = engine.multihopExecutionSnapshot(request: id)
            guard libboxEngine === engine, currentPathProofGuard() === guardState else { completionHandler(nil); return }
            completionHandler(reply); return
        }
        if messageData.count <= 256,
           let request = try? JSONSerialization.jsonObject(with: messageData) as? [String: String],
           request.count == 3, let operation = request["operation"],
           ["hop-measure-info", "hop-measure-start", "hop-measure-status", "hop-measure-cancel"].contains(operation),
           let id = request["request_id"], id.range(of: "^[0-9a-f]{32}$", options: .regularExpression) != nil,
           let session = request["session_id"], (operation == "hop-measure-info" && session.isEmpty) || UUID(uuidString: session) != nil {
            completionHandler(libboxEngine?.hopMeasurementRequest(operation: operation, request: id, session: session) ??
                RouterVPNLibboxEngine.retiredHopMeasurementRequest(operation: operation, request: id, session: session)); return
        }
        if messageData.count <= 512,
           let request = try? JSONSerialization.jsonObject(with: messageData) as? [String: String],
           Set(request.keys) == Set(["operation", "request_id", "session_id", "native_session_id", "transport"]),
           let operation = request["operation"],
           ["dns-measure-info", "dns-measure-start", "dns-measure-status", "dns-measure-cancel", "dns-measure-drain"].contains(operation),
           let id = request["request_id"], id.range(of: "^[0-9a-f]{32}$", options: .regularExpression) != nil,
           let session = request["session_id"], let nativeSession = request["native_session_id"], let transport = request["transport"],
           (operation == "dns-measure-info" && session.isEmpty && nativeSession.isEmpty && transport.isEmpty) ||
             (UUID(uuidString: session) != nil && UUID(uuidString: nativeSession) != nil &&
              (operation == "dns-measure-start" ? ["tcp", "tls", "https"].contains(transport) : transport.isEmpty)) {
            completionHandler(libboxEngine?.dnsMeasurementRequest(operation: operation, request: id,
                session: session, nativeSession: nativeSession, transport: transport) ??
                RouterVPNDNSMeasurementRegistry.shared.reply(operation: operation, request: id,
                    session: session, nativeSession: nativeSession, transport: transport)); return
        }
        if messageData.count <= 256,
           let request = try? JSONSerialization.jsonObject(with: messageData) as? [String: String],
           request.count == 3, let operation = request["operation"],
           ["mtu-status", "mtu-start", "mtu-cancel", "mtu-hold", "mtu-release"].contains(operation),
           let id = request["request_id"], id.range(of: "^[0-9a-f]{32}$", options: .regularExpression) != nil,
           let session = request["session_id"], session.isEmpty || UUID(uuidString: session) != nil {
            completionHandler(libboxEngine?.mtuRequest(operation: operation, request: id, session: session)); return
        }
        forwardingChannel?.handle(messageData, completion: completionHandler)
    }

    private func currentProviderStrategy() -> RouterVPNProviderStrategy? {
        strategyOwnerLock.lock(); defer { strategyOwnerLock.unlock() }; return providerStrategy
    }

    func beginLibboxSettings(epoch: String) { networkSettingsOwner?.begin(epoch: epoch) }
    func retireLibboxSettings(epoch: String) { networkSettingsOwner?.retire(epoch: epoch) }
    func isStrategySettings(epoch: String) -> Bool { currentProviderStrategy()?.isCurrent(epoch) == true }

    func applyLibboxSettings(_ settings: NEPacketTunnelNetworkSettings, epoch: String) throws {
        guard let owner = networkSettingsOwner else { throw tunnelError(70, "The provider has no network settings owner.") }
        let result = RouterVPNSettingsResult()
        owner.submit(settings, epoch: epoch) { error in result.finish(error) }
        guard result.completed.wait(timeout: .now() + 10) != .timedOut else {
            owner.retire(epoch: epoch)
            throw tunnelError(70, "Timed out applying owned PacketTunnel network settings.")
        }
        if let error = result.error { throw error }
        guard owner.current(epoch) else { throw tunnelError(70, "The native network settings owner changed during application.") }
    }

    func nativeLibboxSettingsInvalidated(epoch: String) {
        if let strategy = currentProviderStrategy() {
            strategy.invalidate(epoch: epoch)
        } else if let engine = libboxEngine, engine.settingsEpoch == epoch {
            nativeLibboxFailure(engine, error: tunnelError(70, "Native DNS/TUN settings invalidated their path proof."))
        }
    }

    func nativeLibboxFailure(_ engine: RouterVPNLibboxEngine, error: Error) {
        if let strategy = currentProviderStrategy() {
            strategy.invalidate(epoch: engine.settingsEpoch)
            return
        }
        guard libboxEngine === engine else { return }
        cancelTunnelWithError(error)
    }

    private func beginProviderStrategy(provider: [String: Any], bundleData: Data, root: [String: Any],
                                       selectedProfile: [String: Any], strict: Bool,
                                       maxSources: [String: String],
                                       completionHandler: @escaping (Error?) -> Void) throws {
        guard let catalog = provider["strategy_catalog"] as? [String: Any],
              let request = provider["strategy"] as? [String: Any] else {
            throw tunnelError(70, "A provider strategy requires its immutable catalog and initial request.")
        }
        let policy = try RouterVPNStrategyPolicy(catalog: catalog, root: root, profile: selectedProfile)
        let plan = try policy.plan(request, initial: true)
        var nodeID = try suppliedNodeProof(root: root, selectedProfile: selectedProfile)
        if nodeID.isEmpty {
            let normal = try RouterVPNWireGuardConfig.parse(wireGuardLikeProfile(root, rawProfileID: "wg"), name: "Router VPN")
            guard normal.peers.count == 1, let peer = normal.peers.first else { throw tunnelError(70, "Strategy node identity is missing.") }
            nodeID = deriveNodeProof(from: peer.publicKey.base64Key)
        }
        var profile = selectedProfile
        profile["node_proof_id"] = nodeID
        let digest = SHA256.hash(data: bundleData).map { String(format: "%02x", $0) }.joined()
        let driver = StrategyRuntimeDriver(provider: self, bundle: bundleData,
            profile: try JSONSerialization.data(withJSONObject: profile), strict: strict, initialHold: initialMTUHold,
            maxSources: maxSources)
        let strategy = try RouterVPNProviderStrategy(policy: policy, plan: plan, bundleDigest: digest, nodeID: nodeID, driver: driver)
        strategyOwnerLock.lock()
        guard providerStrategy == nil else { strategyOwnerLock.unlock(); throw tunnelError(70, "This provider already owns a strategy session.") }
        providerStrategy = strategy; strategyDriver = driver
        strategyOwnerLock.unlock()
        // The OS may consider this provider connected while it is a protected
        // packet sink. Only the epoch-bound status can report a proved runtime.
        // No nil settings or system VPN stop occurs between candidate attempts.
        let hold = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
        hold.mtu = 1280
        let ipv4 = NEIPv4Settings(addresses: ["198.18.0.1"], subnetMasks: ["255.255.255.252"])
        ipv4.includedRoutes = [NEIPv4Route.default()]; hold.ipv4Settings = ipv4
        let ipv6 = NEIPv6Settings(addresses: ["fd00:726f:7574::1"], networkPrefixLengths: [126])
        ipv6.includedRoutes = [NEIPv6Route.default()]; hold.ipv6Settings = ipv6
        let dns = NEDNSSettings(servers: ["198.18.0.2"])
        dns.matchDomains = [""]; dns.matchDomainsNoSearch = true; hold.dnsSettings = dns
        beginLibboxSettings(epoch: strategy.currentEpoch)
        do { try applyLibboxSettings(hold, epoch: strategy.currentEpoch) }
        catch { strategy.stop(); throw error }
        reasserting = true
        completionHandler(nil)
        strategy.start()
    }

    /// All native creation, teardown, proof adoption and final activation run
    /// on this one queue. Only this delivery box crosses Sendable boundaries;
    /// generated Libbox handles remain confined to their captured generation.
    private final class StrategyRuntimeDriver: RouterVPNStrategyDriver, @unchecked Sendable {
        private weak var provider: PacketTunnelProvider?
        private let bundle: Data
        private let profile: Data
        private let strict: Bool
        private let maxSources: [String: String]
        private let maxPreparationLock = NSLock()
        private var maxPreparation: RouterVPNMAXPreparation?
        private let queue = DispatchQueue(label: "routervpn.provider.strategy", qos: .userInitiated)
        private var measurementLease: String
        private var compiled: LibboxCompilation?
        private var capturedGuard: NetworkProofGuard?
        private var deadline: DispatchWorkItem?
        private var quarantined = false

        init(provider: PacketTunnelProvider, bundle: Data, profile: Data, strict: Bool, initialHold: String,
             maxSources: [String: String]) {
            self.provider = provider; self.bundle = bundle; self.profile = profile
            self.strict = strict; self.maxSources = maxSources; measurementLease = initialHold
        }

        private func current(_ attempt: RouterVPNStrategyAttempt) -> PacketTunnelProvider? {
            guard let provider, provider.currentProviderStrategy()?.isCurrent(attempt.epoch) == true else { return nil }
            return provider
        }

        private func provedOwner(_ attempt: RouterVPNStrategyAttempt) -> (PacketTunnelProvider, RouterVPNLibboxEngine)? {
            guard let provider = current(attempt), let engine = provider.libboxEngine,
                  engine.settingsEpoch == attempt.epoch, let capturedGuard,
                  provider.currentPathProofGuard() === capturedGuard else { return nil }
            return (provider, engine)
        }

        func replace(_ attempt: RouterVPNStrategyAttempt, proving: @escaping @Sendable () -> Void,
                     completion: @escaping @Sendable (Result<RouterVPNStrategyProof, Error>) -> Void) {
            cancelMAXPreparation()
            queue.async { [self] in begin(attempt, proving: proving, completion: completion) }
        }

        private func cancelMAXPreparation() {
            maxPreparationLock.lock(); let captured = maxPreparation; maxPreparationLock.unlock()
            captured?.cancel()
        }

        private func retireMAXPreparation(_ captured: RouterVPNMAXPreparation?) {
            captured?.close()
            maxPreparationLock.lock()
            if maxPreparation === captured { maxPreparation = nil }
            maxPreparationLock.unlock()
        }

        private final class DrainDelivery: @unchecked Sendable {
            let completion: () -> Void
            init(_ completion: @escaping () -> Void) { self.completion = completion }
        }

        func drain(_ completion: @escaping () -> Void) {
            cancelMAXPreparation()
            let delivery = DrainDelivery(completion)
            queue.async { [self] in
                maxPreparationLock.lock(); let captured = maxPreparation; maxPreparationLock.unlock()
                retireMAXPreparation(captured)
                delivery.completion()
            }
        }

        private func begin(_ attempt: RouterVPNStrategyAttempt, proving: @escaping @Sendable () -> Void,
                           completion: @escaping @Sendable (Result<RouterVPNStrategyProof, Error>) -> Void) {
            guard let provider = current(attempt), let strategy = provider.currentProviderStrategy() else { return }
            deadline?.cancel(); deadline = nil
            guard strategy.withCurrentEpoch(attempt.epoch, {
                provider.reasserting = true
                provider.beginLibboxSettings(epoch: attempt.epoch)
            }) else { return }
            provider.clearPathProofGuard(); provider.cancelActiveProof()
            capturedGuard = nil; compiled = nil
            if let old = provider.libboxEngine {
                measurementLease = old.strategyMTUHold
                provider.libboxEngine = nil
                do { try old.stopCheckedForStrategy() }
                catch { quarantined = true }
            }
            guard !quarantined else { strategy.teardownFailed(epoch: attempt.epoch); return }
            let expiry = StrategyExpiry(provider: provider, epoch: attempt.epoch)
            let timeout = DispatchWorkItem { expiry.expire() }
            deadline = timeout
            DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + 45, execute: timeout)
            var preparation: RouterVPNMAXPreparation?
            defer { retireMAXPreparation(preparation) }
            do {
                var capturedBundle = bundle
                if IOSNativeMAXProfile.modeIDs.contains(attempt.candidate.raw) {
                    var source: [String: Any] = ["engine": "libbox", "bundle": bundle, "rawProfileID": attempt.candidate.raw]
                    let key = "bundle/" + attempt.candidate.raw
                    guard let digest = maxSources[key] else { throw RouterVPNMAXPreparation.issue() }
                    source["max_source_sha256"] = [key: digest]
                    let pending = try RouterVPNMAXPreparation(provider: source)
                    preparation = pending
                    maxPreparationLock.lock(); maxPreparation = pending; maxPreparationLock.unlock()
                    guard current(attempt) != nil else { pending.cancel(); return }
                    let launch = try pending.run()
                    guard current(attempt) != nil, pending.healthy(), let data = launch["bundle"] as? Data else {
                        throw RouterVPNMAXPreparation.issue()
                    }
                    capturedBundle = data
                }
                guard let root = try JSONSerialization.jsonObject(with: capturedBundle) as? [String: Any],
                      let originalProfile = try JSONSerialization.jsonObject(with: profile) as? [String: Any] else {
                    throw RouterVPNStrategyPolicy.error("The immutable strategy capture is invalid.")
                }
                var profile = preparation == nil ? originalProfile : try IOSMAXSourceSelection.profile(root)
                profile["node_proof_id"] = originalProfile["node_proof_id"]
                let compiled = try provider.compileLibbox(provider: ["rawProfileID": attempt.candidate.raw], root: root, selectedProfile: profile)
                guard current(attempt) != nil else { return }
                self.compiled = compiled
                let engine = RouterVPNLibboxEngine(tunnel: provider, strategyEpoch: attempt.epoch)
                guard strategy.withCurrentEpoch(attempt.epoch, { provider.libboxEngine = engine }) else { engine.stop(); return }
                try engine.prepareMTUHold(measurementLease)
                try engine.start(files: compiled.files, strict: strict)
                guard current(attempt) != nil, provider.libboxEngine === engine else { engine.stop(); return }
                capturedGuard = provider.armNetworkProofGuard()
                guard preparation?.healthy() != false, current(attempt) != nil else {
                    engine.stop(); throw RouterVPNMAXPreparation.issue()
                }
                retireMAXPreparation(preparation); preparation = nil
                proving()
                provider.proveSelectedNode(url: compiled.proofURL, expectedNodeID: compiled.nodeID,
                                          proxyPort: RouterVPNLibboxEngine.proofProxyPort) { [weak self] error in
                    guard let self else { return }
                    self.queue.async { [self] in finishNodeProof(attempt, error: error, completion: completion) }
                }
            } catch {
                completion(.failure(error))
            }
        }

        private func finishNodeProof(_ attempt: RouterVPNStrategyAttempt, error: Error?,
                                     completion: @escaping @Sendable (Result<RouterVPNStrategyProof, Error>) -> Void) {
            guard current(attempt) != nil else { return }
            if let error { completion(.failure(error)); return }
            guard let (_, engine) = provedOwner(attempt), let compiled else {
                completion(.failure(RouterVPNStrategyPolicy.error("The native path changed during node proof."))); return
            }
            do {
                try engine.proveStrategyDNS()
                guard provedOwner(attempt) != nil else { throw RouterVPNStrategyPolicy.error("The native path changed during DNS proof.") }
                try engine.activatePerformance()
                guard provedOwner(attempt) != nil else { throw RouterVPNStrategyPolicy.error("The native path changed during performance activation.") }
                completion(.success(RouterVPNStrategyProof(nodeID: compiled.nodeID, dns: true)))
            } catch { completion(.failure(error)) }
        }

        func activate(_ attempt: RouterVPNStrategyAttempt, completion: @escaping @Sendable (Error?) -> Void) {
            queue.async { [self] in
                guard let (provider, engine) = provedOwner(attempt), let compiled, let capturedGuard,
                      let profile = try? JSONSerialization.jsonObject(with: compiled.profile) as? [String: Any] else {
                    completion(RouterVPNStrategyPolicy.error("The final native strategy owner was replaced.")); return
                }
                engine.activateMTU(profile: profile)
                guard provedOwner(attempt) != nil else { completion(RouterVPNStrategyPolicy.error("The native path changed during MTU activation.")); return }
                provider.enableForwarding(profileData: compiled.profile, proofID: compiled.nodeID, captured: capturedGuard)
                guard provedOwner(attempt) != nil else {
                    provider.forwardingChannel?.invalidate()
                    completion(RouterVPNStrategyPolicy.error("The native path changed during forwarding activation.")); return
                }
                deadline?.cancel(); deadline = nil
                completion(nil)
                provider.currentProviderStrategy()?.withCurrentEpoch(attempt.epoch) { provider.reasserting = false }
            }
        }

        func protect(epoch: String) {
            // This signal must precede queue admission: that queue may be
            // inside the very DNS callback/native request being canceled.
            cancelMAXPreparation()
            queue.async { [self] in
                guard let provider, let strategy = provider.currentProviderStrategy(), strategy.isCurrent(epoch) else { return }
                deadline?.cancel(); deadline = nil
                strategy.withCurrentEpoch(epoch) { provider.reasserting = true; provider.beginLibboxSettings(epoch: epoch) }
                provider.clearPathProofGuard(); provider.cancelActiveProof()
                capturedGuard = nil; compiled = nil
                if let engine = provider.libboxEngine {
                    measurementLease = engine.strategyMTUHold; provider.libboxEngine = nil
                    do { try engine.stopCheckedForStrategy() } catch { quarantined = true }
                }
            }
        }
    }

    private final class StrategyExpiry: @unchecked Sendable {
        private weak var provider: PacketTunnelProvider?
        private let epoch: String
        init(provider: PacketTunnelProvider, epoch: String) { self.provider = provider; self.epoch = epoch }
        func expire() { provider?.currentProviderStrategy()?.invalidate(epoch: epoch) }
    }

    private func enableForwarding(profileData: Data, proofID: String, captured proof: NetworkProofGuard) {
        guard currentPathProofGuard() === proof,
              let profile = try? JSONSerialization.jsonObject(with: profileData) as? [String: Any] else { return }
        forwardingChannel?.activate(profile: profile, proofID: proofID)
        guard let channel = try? RouterVPNTelemetryChannel(profile: profile, proofID: proofID,
                factory: RouterVPNTelemetryNativeConnection.factory(self, current: {
                    proof.owner?.currentPathProofGuard() === proof
                })) else { return }
        telemetryLock.lock()
        guard currentPathProofGuard() === proof else { telemetryLock.unlock(); channel.close(); return }
        let previous = telemetryChannel; telemetryChannel = channel; telemetryProof = proof
        telemetryLock.unlock()
        previous?.close()
    }

    private func currentTelemetryChannel() -> RouterVPNTelemetryChannel? {
        telemetryLock.lock(); defer { telemetryLock.unlock() }
        guard let proof = telemetryProof, currentPathProofGuard() === proof else { return nil }
        return telemetryChannel
    }

    private func retireTelemetry(_ proof: NetworkProofGuard? = nil) {
        telemetryLock.lock()
        guard proof == nil || telemetryProof === proof else { telemetryLock.unlock(); return }
        let captured = telemetryChannel; telemetryChannel = nil; telemetryProof = nil
        telemetryLock.unlock(); captured?.close()
    }

    private var wireGuardAdapter: WireGuardAdapter?
    private var libboxEngine: RouterVPNLibboxEngine?
    private var proofTask: URLSessionDataTask?
    private var proofSession: URLSession?
    private var pathMonitor: NWPathMonitor?
    private var pathProofGuard: NetworkProofGuard?
    private let proofOwnerLock = NSLock()
    private let pathProofOwnerLock = NSLock()
    private let pathMonitorQueue = DispatchQueue(label: "com.eabusham.routervpn.path-proof", qos: .utility)

    override func startTunnel(options: [String: NSObject]? = nil, completionHandler: @escaping (Error?) -> Void) {
        forwardingChannel?.invalidate()
        retireTelemetry()
        do {
            maxStartOwnerLock.lock()
            guard maxStartOwner == nil, !maxStartDraining else { maxStartOwnerLock.unlock(); throw RouterVPNMAXPreparation.issue() }
            let generation = UUID(); maxStartGeneration = generation
            maxStartOwnerLock.unlock()
            initialMTUHold = options?["routervpn_mtu_hold"] as? String ?? ""
            guard initialMTUHold.isEmpty || initialMTUHold.range(of: "^[0-9a-f]{32}$", options: .regularExpression) != nil else { throw tunnelError(60, "Invalid MTU comparison lease") }
            guard let tunnelProtocol = protocolConfiguration as? NETunnelProviderProtocol, let provider = tunnelProtocol.providerConfiguration else { throw tunnelError(1, "Router VPN PacketTunnel configuration is missing.") }
            guard let bundleData = provider["bundle"] as? Data, !bundleData.isEmpty, bundleData.count <= Self.maxBundleBytes else { throw tunnelError(2, "Router VPN private bundle is missing or exceeds the 32 MiB safety limit.") }
            guard let root = try JSONSerialization.jsonObject(with: bundleData) as? [String: Any] else { throw tunnelError(3, "Router VPN private bundle is invalid JSON.") }
            let selectedProfile = try selectedRouterProfile(root)
            let strict = strictKillSwitchRequested(selectedProfile)
            if strict {
                guard tunnelProtocol.includeAllNetworks, tunnelProtocol.enforceRoutes else { throw tunnelError(4, "strict Apple kill switch requested but NetworkExtension route lockdown is not enabled") }
                let allowLAN = selectedProfile["home_lan_access"] as? Bool ?? true
                // The two-node validator below checks the intersection of both
                // LAN policies. Comparing only the exit here rejects a valid
                // entry-LAN-Off / exit-LAN-On graph before that check can run.
                guard (provider["engine"] as? String) == "multihop-libbox" ||
                    ((provider["engine"] as? String) == "external-libbox" && (provider["tor_entry_bundle"] != nil || provider["external_entry_bundle"] != nil)) ||
                    tunnelProtocol.excludeLocalNetworks == allowLAN else { throw tunnelError(5, "strict Apple kill switch LAN exclusion does not match the imported node policy") }
            }

            let engine = (provider["engine"] as? String ?? "wireguard").lowercased()
            multihopExecutionSource = nil; restoredMultihopExecution = nil; restoredMultihopIdentityPins = nil
            if try IOSMultihopExecution.requiresCapture(configuration: provider) {
                let source = try IOSMultihopExecution.Source(configuration: provider) {
                    SHA256.hash(data: $0).map { String(format: "%02x", $0) }.joined()
                }
                let restored = try IOSMultihopExecution.restoredCapture(
                    option: options?[IOSMultihopExecution.launchKey], source: source, mtuHold: initialMTUHold)
                let startup = try IOSMultihopExecution.restoredStartupChoice(
                    option: options?[IOSMultihopExecution.startupLaunchKey], source: source)
                guard restored == nil || startup == nil else { throw IOSMultihopExecution.issue() }
                restoredMultihopExecution = restored?.execution ?? startup?.execution
                restoredMultihopIdentityPins = restored?.pins ?? startup?.pins
                multihopExecutionSource = source
            } else if options?[IOSMultihopExecution.launchKey] != nil || options?[IOSMultihopExecution.startupLaunchKey] != nil { throw IOSMultihopExecution.issue() }
            // This complete validation is socket-free. The app's exact source
            // stamps are checked again for every later strategy attempt.
            let maxCapture = try RouterVPNMAXPreparation(provider: provider)
            if provider["strategy"] != nil || provider["strategy_catalog"] != nil {
                defer { maxCapture.close() }
                guard engine == "libbox" else { throw tunnelError(70, "Owned strategies require the single native Libbox dataplane.") }
                guard currentMAXGeneration(generation) else { throw RouterVPNMAXPreparation.issue() }
                try beginProviderStrategy(provider: provider, bundleData: bundleData, root: root,
                                          selectedProfile: selectedProfile, strict: strict, maxSources: maxCapture.sourceHashes,
                                          completionHandler: completionHandler)
                return
            }
            if maxCapture.requiresResolution {
                try beginMAXStart(maxCapture, generation: generation, strict: strict, completion: completionHandler)
                return
            }
            maxCapture.close()
            guard currentMAXGeneration(generation) else { throw RouterVPNMAXPreparation.issue() }
            try startCapturedProvider(provider, root: root, profile: selectedProfile, strict: strict, completion: completionHandler)
        } catch { completionHandler(error) }
    }

    private func currentMAXGeneration(_ generation: UUID) -> Bool {
        maxStartOwnerLock.lock(); defer { maxStartOwnerLock.unlock() }
        return !maxStartDraining && maxStartGeneration == generation
    }

    private func beginMAXStart(_ preparation: RouterVPNMAXPreparation, generation: UUID, strict: Bool,
                               completion: @escaping (Error?) -> Void) throws {
        let owner = RouterVPNMAXStart(preparation: preparation) { [weak self] captured, error in
            guard let self else { completion(RouterVPNMAXPreparation.issue()); return }
            self.maxStartOwnerLock.lock()
            let current = self.maxStartOwner === captured && self.maxStartGeneration == generation && !self.maxStartDraining
            // A queued Stop keeps the owner until its actual cleanup returns.
            if current, error == nil { self.maxStartOwner = nil }
            if current, error != nil { self.maxStartDraining = true }
            self.maxStartOwnerLock.unlock()
            if current, error != nil {
                self.clearPathProofGuard(); self.cancelActiveProof()
                if let engine = self.libboxEngine { self.libboxEngine = nil; engine.stop() }
                self.maxStartOwnerLock.lock()
                if self.maxStartOwner === captured, self.maxStartGeneration == generation {
                    self.maxStartOwner = nil; self.maxStartDraining = false
                }
                self.maxStartOwnerLock.unlock()
            }
            completion(current ? error : RouterVPNMAXPreparation.issue())
        }
        maxStartOwnerLock.lock()
        guard maxStartOwner == nil, !maxStartDraining, maxStartGeneration == generation else {
            maxStartOwnerLock.unlock(); preparation.close(); throw RouterVPNMAXPreparation.issue()
        }
        maxStartOwner = owner
        maxStartOwnerLock.unlock()
        owner.start { [weak self, weak owner] launch, captured, complete in
            guard let self, let owner, owner.current, self.currentMAXGeneration(generation), captured.healthy(),
                  let data = launch["bundle"] as? Data else { throw RouterVPNMAXPreparation.issue() }
            let root = try IOSMAXSourceSelection.object(data), profile = try IOSMAXSourceSelection.profile(root)
            try self.startCapturedProvider(launch, root: root, profile: profile, strict: strict, completion: complete)
            // Existing start paths have installed their native path guard now.
            // DNS ownership is released only after this handover is checked.
            guard owner.current, self.currentMAXGeneration(generation), captured.healthy() else { throw RouterVPNMAXPreparation.issue() }
        }
    }

    private func startCapturedProvider(_ provider: [String: Any], root: [String: Any], profile: [String: Any], strict: Bool,
                                       completion: @escaping (Error?) -> Void) throws {
        switch (provider["engine"] as? String ?? "wireguard").lowercased() {
        case "wireguard": try startWireGuard(provider: provider, root: root, selectedProfile: profile, completionHandler: completion)
        case "multihop-libbox": try startMultihop(provider: provider, root: root, selectedProfile: profile, completionHandler: completion)
        case "libbox": try startLibbox(provider: provider, root: root, selectedProfile: profile, strict: strict, completionHandler: completion)
        case "external-libbox": try startExternalLibbox(provider: provider, selectedProfile: profile, strict: strict, completionHandler: completion)
        default: throw tunnelError(6, "Unsupported Router VPN iOS engine.")
        }
    }

    private func startWireGuard(provider: [String: Any], root: [String: Any], selectedProfile: [String: Any], completionHandler: @escaping (Error?) -> Void) throws {
        let requestedMode = (provider["mode"] as? String ?? "wg").lowercased()
        let nativeModes: Set<String> = ["wg", "awg2-fast", "awg2-strong"]
        guard nativeModes.contains(requestedMode) else { throw tunnelError(7, "Native WireGuard-family engine received unsupported mode \(requestedMode).") }
        try IOSStartLayer.validateWireGuard(profile: selectedProfile)
        guard try !RouterVPNMTUPolicy.requiresAdaptiveOwner(profile: selectedProfile) else { throw tunnelError(60, "Auto-MTU requires the Libbox TUN owner. Reconnect from Router VPN to refresh this saved native selection.") }
        let profileText = try RouterVPNMTUPolicy.wireGuard(wireGuardLikeProfile(root, rawProfileID: requestedMode), profile: selectedProfile)
        let tunnelConfiguration = try RouterVPNWireGuardConfig.parse(profileText, name: requestedMode == "wg" ? "Router VPN" : "Router VPN AmneziaWG", amnezia: requestedMode != "wg")
        guard tunnelConfiguration.peers.count == 1 else { throw tunnelError(8, "Router VPN iOS node proof requires exactly one generated WireGuard-family server peer.") }
        let suppliedNodeID = try suppliedNodeProof(root: root, selectedProfile: selectedProfile)
        let expectedNodeID: String
        if requestedMode == "wg" {
            let derivedNodeID = deriveNodeProof(from: tunnelConfiguration.peers[0].publicKey.base64Key)
            if !suppliedNodeID.isEmpty && suppliedNodeID != derivedNodeID { throw tunnelError(9, "Router bundle node identity does not match its WireGuard server public key.") }
            expectedNodeID = suppliedNodeID.isEmpty ? derivedNodeID : suppliedNodeID
        } else {
            // Durable Router VPN identity is anchored to the normal WG server key.
            // AWG has a distinct peer key, so prove the same private node after
            // the AWG tunnel is live instead of equating unrelated server keys.
            guard !suppliedNodeID.isEmpty else { throw tunnelError(9, "Native AmneziaWG requires the imported Router VPN node proof identity.") }
            expectedNodeID = suppliedNodeID
        }
        guard expectedNodeID.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil else { throw tunnelError(10, "Router VPN node proof id is invalid.") }
        let proofURL = try selectedProofURL(selectedProfile)
        let forwardingProfileData = try JSONSerialization.data(withJSONObject: selectedProfile)
        let adapter = WireGuardAdapter(with: self) { level, message in if level == .error { NSLog("RouterVPN WireGuard/AWG: %@", message) } }
        wireGuardAdapter = adapter
        adapter.start(tunnelConfiguration: tunnelConfiguration) { [weak self] adapterError in
            guard let self else { completionHandler(NSError(domain: "RouterVPN.PacketTunnel", code: 11, userInfo: [NSLocalizedDescriptionKey: "Router VPN PacketTunnel was released during startup."])); return }
            guard self.wireGuardAdapter === adapter else { adapter.stop { _ in completionHandler(self.tunnelError(40, "A newer iOS WireGuard runtime replaced this startup attempt.")) }; return }
            if let adapterError { self.wireGuardAdapter = nil; completionHandler(self.tunnelError(12, "WireGuard-family engine failed to start: \(adapterError.localizedDescription)")); return }
            let rawPathGuard = self.armNetworkProofGuard()
            self.proveSelectedNode(url: proofURL, expectedNodeID: expectedNodeID, proxyPort: nil) { proofError in
                guard self.wireGuardAdapter === adapter else { adapter.stop { _ in completionHandler(self.tunnelError(41, "A newer iOS WireGuard runtime replaced this proof attempt.")) }; return }
                if let proofError {
                    self.releasePathProofGuard(rawPathGuard)
                    adapter.stop { _ in if self.wireGuardAdapter === adapter { self.wireGuardAdapter = nil }; completionHandler(proofError) }
                    return
                }
                guard self.currentPathProofGuard() === rawPathGuard else {
                    adapter.stop { _ in if self.wireGuardAdapter === adapter { self.wireGuardAdapter = nil }; completionHandler(self.tunnelError(57, "WireGuard path changed during node proof.")) }
                    return
                }
                self.enableForwarding(profileData: forwardingProfileData, proofID: expectedNodeID, captured: rawPathGuard)
                guard self.currentPathProofGuard() === rawPathGuard else {
                    adapter.stop { _ in if self.wireGuardAdapter === adapter { self.wireGuardAdapter = nil }; completionHandler(self.tunnelError(57, "WireGuard path changed during forwarding activation.")) }
                    return
                }
                completionHandler(nil)
            }
        }
    }

    private func multihopMAX(root: [String: Any], mode: String, profile: [String: Any], nodeID: String, layer: String) throws -> IOSNativeMAXMultihop.Capture? {
        guard IOSNativeMAXProfile.modeIDs.contains(mode) else { return nil }
        guard let profiles = root["profiles"] as? [String: Any], let assets = profiles[mode] as? [String: String] else {
            throw tunnelError(58, "Complete MAX multihop assets are missing.")
        }
        return try IOSNativeMAXMultihop.capture(mode: mode, encoded: assets, nodeID: nodeID, profile: profile, startLayer: layer,
            compiler: { mode, assets, metadata in
                var failure: NSError?
                let result: String? = LibboxRouterCompileMAXProfile(mode, assets, metadata, &failure)
                if let failure { throw failure }
                guard let result else { throw self.tunnelError(58, "Complete MAX source compilation returned no graph.") }
                return result
            }, baseCompiler: { config, mode, node, layer in
                var failure: NSError?
                let result: String? = LibboxRouterMAXMultihopBase(config, mode, node, layer, &failure)
                if let failure { throw failure }
                guard let result else { throw self.tunnelError(58, "Complete MAX graph-construction input is missing.") }
                return result
            })
    }

    private func startMultihop(provider: [String: Any], root: [String: Any], selectedProfile: [String: Any], completionHandler: @escaping (Error?) -> Void) throws {
        guard selectedProfile["multihop_enabled"] as? Bool == true,
              let entryID = selectedProfile["multihop_entry_id"] as? String,
              let exitID = selectedProfile["multihop_exit_id"] as? String,
              selectedProfile["id"] as? String == exitID,
              root["selectedRouterID"] as? String == exitID,
              let exitMode = selectedProfile["multihop_exit_mode"] as? String,
              provider["rawProfileID"] as? String == exitMode,
              (RouterVPNMultihopGraph.supportedExitModes.contains(exitMode) || IOSNativeMAXProfile.modeIDs.contains(exitMode)),
              let entryData = provider["entryBundle"] as? Data, !entryData.isEmpty,
              entryData.count <= Self.maxBundleBytes,
              let entryRoot = try JSONSerialization.jsonObject(with: entryData) as? [String: Any],
              entryRoot["selectedRouterID"] as? String == entryID else {
            throw tunnelError(50, "Multihop handoff does not match the frozen entry/exit selection.")
        }
        var entryProfile = try selectedRouterProfile(entryRoot)
        var exitProfile = selectedProfile
        guard entryProfile["id"] as? String == entryID else { throw tunnelError(51, "The captured entry bundle belongs to another node.") }
        let entryProofID = try suppliedNodeProof(root: entryRoot, selectedProfile: entryProfile)
        let exitProofID = try suppliedNodeProof(root: root, selectedProfile: selectedProfile)
        entryProfile["node_proof_id"] = entryProofID
        exitProfile["node_proof_id"] = exitProofID
        let entryMode = selectedProfile["multihop_entry_mode"] as? String ?? "wg"
        guard ["wg","awg2-fast","awg2-strong","wg-pq","awg2-pq","shadowsocks","hysteria2","reality-vision","reality-pq-vision","reality-xhttp","max-tls-wg","max-tls-awg","max-quic-wg","max-quic-awg","naive-h2","naive-h3","ss-v2ray","split","max"].contains(entryMode) else { throw tunnelError(58,"Unknown captured entry transport.") }
        let entryLayerMode = try IOSMultihopStartLayer.selected(entryProfile)
        let exitLayerMode = try IOSMultihopStartLayer.selected(exitProfile)
        let entryMAX = try multihopMAX(root: entryRoot, mode: entryMode, profile: entryProfile, nodeID: entryProofID, layer: entryLayerMode)
        let exitMAX = try multihopMAX(root: root, mode: exitMode, profile: exitProfile, nodeID: exitProofID, layer: exitLayerMode)
        let compositeCompiler: (String, String, String, String) throws -> String = { mode, assets, policy, layer in
            var failure: NSError?
            let compiled: String? = LibboxRouterCompileCompositeProfile(mode, assets, policy, layer, &failure)
            if let failure { throw failure }
            guard let compiled else { throw self.tunnelError(58, "Composite profile did not compile.") }
            return compiled
        }
        let compositeBase: (String, String, String, String) throws -> String = { config, mode, node, layer in
            var failure: NSError?
            let compiled: String? = LibboxRouterCompositeMultihopBase(config, mode, node, layer, &failure)
            if let failure { throw failure }
            guard let compiled else { throw self.tunnelError(58, "Composite construction lost its captured owner.") }
            return compiled
        }
        let entryComposite = try IOSNativeCompositeMultihop.capture(root: entryRoot, mode: entryMode, profile: entryProfile,
            nodeID: entryProofID, layer: entryLayerMode, compiler: compositeCompiler, baseCompiler: compositeBase)
        let exitComposite = try IOSNativeCompositeMultihop.capture(root: root, mode: exitMode, profile: exitProfile,
            nodeID: exitProofID, layer: exitLayerMode, compiler: compositeCompiler, baseCompiler: compositeBase)
        let endpoint: [String: Any]
        if let entryMAX {
            endpoint = try entryMAX.endpoint()
        } else if let entryComposite {
            endpoint = try entryComposite.outbound()
        } else if entryMode == "wg" {
            endpoint = try multihopWireGuardEndpoint(root: entryRoot, expectedProofID: entryProofID, name: "Router VPN entry").endpoint
        } else if ["awg2-fast", "awg2-strong"].contains(entryMode) {
            endpoint = try nativeAmneziaEndpoint(root: entryRoot, expectedProofID: entryProofID, mode: entryMode).endpoint
        } else if IOSNativePQProfile.modeIDs.contains(entryMode) {
            guard let profiles = entryRoot["profiles"] as? [String: Any],
                  let assets = profiles[entryMode] as? [String: String] else {
                throw tunnelError(58, "The captured entry has no complete native PQ assets.")
            }
            endpoint = try IOSNativePQProfile.entryEndpoint(mode: entryMode, encoded: assets, nodeID: entryProofID) { mode, input, node in
                var failure: NSError?
                let compiled: String? = LibboxRouterCompilePQProfile(mode, input, node, &failure)
                if let failure { throw failure }
                guard let compiled else { throw self.tunnelError(58, "Native PQ entry compilation returned no graph.") }
                return compiled
            }
        } else {
            guard let profiles = entryRoot["profiles"] as? [String: Any], let files = profiles[entryMode] as? [String: String] else {
                throw tunnelError(58, "The selected entry has no self-contained proxy profile.")
            }
            let profileData = try JSONSerialization.data(withJSONObject: files)
            guard profileData.count <= 8 * 1024 * 1024 else { throw tunnelError(58, "Entry profile exceeds its native bound.") }
            var failure: NSError?
            let compiled: String? = LibboxRouterCompileProxyEntry(String(decoding: profileData, as: UTF8.self), entryMode, &failure)
            if let failure { throw failure }
            guard let compiled, !compiled.isEmpty, compiled.utf8.count <= Self.maxProfileBytes,
                  let parsed = try JSONSerialization.jsonObject(with: Data(compiled.utf8)) as? [String: Any] else {
                throw tunnelError(58, "Native entry compilation did not return an owned outbound.")
            }
            endpoint = parsed
        }
        let rawFiles: [String: Data]
        if let exitMAX {
            rawFiles = try RouterVPNMultihopGraph.pqDNSPolicy(exitMAX.baseFiles, profile: exitProfile)
        } else if let exitComposite {
            rawFiles = try RouterVPNMultihopGraph.compositeDNSPolicy(exitComposite.baseFiles, profile: exitProfile)
        } else if exitMode == "wg" {
            let exit = try multihopWireGuardEndpoint(root: root, expectedProofID: exitProofID, name: "Router VPN exit")
            rawFiles = try RouterVPNMultihopGraph.wireGuardFiles(endpoint: exit.endpoint, profile: exitProfile, dnsServers: exit.dns)
        } else if ["awg2-fast", "awg2-strong"].contains(exitMode) {
            let exit = try nativeAmneziaEndpoint(root: root, expectedProofID: exitProofID, mode: exitMode)
            rawFiles = try RouterVPNMultihopGraph.wireGuardFiles(endpoint: exit.endpoint, profile: exitProfile, dnsServers: exit.dns)
        } else if IOSNativePQProfile.modeIDs.contains(exitMode) {
            guard let profiles = root["profiles"] as? [String: Any],
                  let assets = profiles[exitMode] as? [String: String] else {
                throw tunnelError(58, "The captured exit has no complete native PQ assets.")
            }
            let compiled = try IOSNativePQProfile.compile(mode: exitMode, encoded: assets, nodeID: exitProofID) { mode, input, node in
                var failure: NSError?
                let result: String? = LibboxRouterCompilePQProfile(mode, input, node, &failure)
                if let failure { throw failure }
                guard let result else { throw self.tunnelError(58, "Native PQ exit compilation returned no graph.") }
                return result
            }
            rawFiles = try RouterVPNMultihopGraph.pqDNSPolicy(compiled, profile: exitProfile)
        } else if RouterVPNMultihopGraph.nativeXrayModes.contains(exitMode) {
            guard let profiles = root["profiles"] as? [String: Any],
                  let assets = profiles[exitMode] as? [String: String] else {
                throw tunnelError(58, "The captured exit has no exact native Xray assets.")
            }
            rawFiles = try RouterVPNMultihopGraph.xrayFiles(assets: assets, mode: exitMode, profile: exitProfile) { payload, mode in
                var failure: NSError?
                let compiled: String? = LibboxRouterCompileXrayExit(payload, mode, &failure)
                if let failure { throw failure }
                guard let compiled else { throw self.tunnelError(58, "Native Xray exit compilation returned no graph.") }
                return compiled
            }
        } else {
            rawFiles = try layeredProfile(root, rawProfileID: exitMode)
        }
        // Complete MAX already contains its selected outermost Start Layer.
        // Only ordinary hops pass a separate AES source to the runtime factory.
        var entryConstruction = entryProfile, exitConstruction = exitProfile
        entryConstruction["start_layer"] = "off"; exitConstruction["start_layer"] = "off"
        let entryLayer = try entryMAX == nil && entryComposite == nil ? IOSMultihopStartLayer.capture(profile: entryProfile,
            profiles: entryRoot["profiles"] as? [String: [String: String]] ?? [:]) :
            IOSMultihopStartLayer.Capture(mode: entryLayerMode, source: nil, graphProfile: entryConstruction)
        let exitLayer = try exitMAX == nil && exitComposite == nil ? IOSMultihopStartLayer.capture(profile: exitProfile,
            profiles: root["profiles"] as? [String: [String: String]] ?? [:]) :
            IOSMultihopStartLayer.Capture(mode: exitLayerMode, source: nil, graphProfile: exitConstruction)
        var constructionExitProfile = exitLayer.graphProfile
        if let entryMAX { constructionExitProfile["multihop_entry_mode"] = entryMAX.baseMode }
        var baseFiles = rawFiles
        if (exitLayer.source != nil && exitMode == "hysteria2") || RouterVPNMultihopGraph.nativeNaiveModes.contains(exitMode) {
            guard let profiles = root["profiles"] as? [String: [String: String]], let assets = profiles[exitMode] else {
                throw tunnelError(58, "Exit TLS source is missing.")
            }
            baseFiles = try IOSMultihopStartLayer.inlineExitTLS(files: rawFiles, assets: assets, mode: exitMode) { profile, mode in
                var failure: NSError?
                let result: String? = LibboxRouterCompileProxyEntry(profile, mode, &failure)
                if let failure { throw failure }
                guard let result else { throw self.tunnelError(58, "Exit TLS source did not compile.") }
                return result
            }
        }
        var metadata: [String: String] = ["entry_id": entryID, "exit_id": selectedProfile["id"] as? String ?? "",
            "entry_node_id": entryProofID, "exit_node_id": exitProofID,
            "entry_api": entryProfile["router_api"] as? String ?? "", "exit_api": selectedProfile["router_api"] as? String ?? "",
            "entry_token": entryProfile["api_token"] as? String ?? "", "exit_token": selectedProfile["api_token"] as? String ?? "",
            "entry_tag": RouterVPNMultihopGraph.entryTag, "entry_mode": entryMode, "exit_mode": exitMode, "execution": restoredMultihopExecution ?? selectedProfile["multihop_execution"] as? String ?? "local"]
        if entryLayer.mode != "off" { metadata["entry_start_layer"] = entryLayer.mode }
        if exitLayer.mode != "off" { metadata["exit_start_layer"] = exitLayer.mode }
        if let pins = restoredMultihopIdentityPins {
            guard let source = multihopExecutionSource else { throw IOSMultihopExecution.issue() }
            metadata = try pins.applying(to: metadata, source: source)
        }
        let encoded = try JSONSerialization.data(withJSONObject: metadata)
        guard encoded.count <= 16384 else { throw tunnelError(58, "Captured multihop metadata exceeds its bound.") }
        let hopMetadata = String(decoding: encoded, as: UTF8.self)
        var files = try RouterVPNMultihopGraph.build(entryEndpoint: endpoint, entryProfile: entryLayer.graphProfile,
            exitProfile: constructionExitProfile, exitMode: exitMAX?.baseMode ?? exitMode, files: baseFiles)
        if entryMAX != nil || exitMAX != nil {
            files = try IOSNativeMAXMultihop.compose(files: files, metadata: hopMetadata, entry: entryMAX, exit: exitMAX) { config, metadata, entry, exit in
                var failure: NSError?
                let result: String? = LibboxRouterComposeMAXMultihop(config, metadata, entry, exit, &failure)
                if let failure { throw failure }
                guard let result else { throw self.tunnelError(58, "Complete MAX multihop returned no restored encryption graph.") }
                return result
            }
        }
        let policy = try JSONSerialization.data(withJSONObject: ["entry": entryProfile, "exit": exitProfile])
        if entryComposite != nil || exitComposite != nil {
            files = try IOSNativeCompositeMultihop.compose(files: files, metadata: hopMetadata, entry: entryComposite, exit: exitComposite) { config, metadata, entry, exit in
                var failure: NSError?
                let result: String? = LibboxRouterComposeCompositeMultihop(config, metadata, entry, exit, &failure)
                if let failure { throw failure }
                guard let result else { throw self.tunnelError(58, "Composite multihop did not restore both transport lanes.") }
                return result
            }
        }
        let mtuFiles: [String: Data]
        if entryMAX != nil || exitMAX != nil || entryComposite != nil || exitComposite != nil {
            guard let source = files["sing-box.json"], let config = String(data: source, encoding: .utf8) else { throw tunnelError(58, "Missing complete MAX graph.") }
            var failure: NSError?
            let sized: String? = LibboxRouterApplyMultihopMTUPolicy(config, String(decoding: policy, as: UTF8.self), &failure)
            if let failure { throw failure }
            guard let sized, !sized.isEmpty, sized.utf8.count <= Self.maxProfileBytes else { throw tunnelError(58, "Complete MAX MTU ownership failed.") }
            var output = files; output["sing-box.json"] = Data(sized.utf8); mtuFiles = output
        } else {
            mtuFiles = try RouterVPNMTUPolicy.multihop(files, entryProfile: entryProfile, exitProfile: exitProfile)
        }
        guard let source = mtuFiles["sing-box.json"], let text = String(data: source, encoding: .utf8) else { throw tunnelError(58, "Missing multihop LAN-policy graph") }
        var mtuFailure: NSError?
        let mtuProfileText: String? = LibboxRouterMultihopMTUProfile(text, String(decoding: policy, as: UTF8.self), &mtuFailure)
        if let mtuFailure { throw mtuFailure }
        guard let mtuProfileText, !mtuProfileText.isEmpty, mtuProfileText.utf8.count <= 256 * 1024 else {
            throw tunnelError(58, "Native multihop MTU ownership was not captured.")
        }
        let mtuProfileData = Data(mtuProfileText.utf8)
        var failure: NSError?
        let filtered: String? = LibboxRouterApplyMultihopLANPolicy(text, String(decoding: policy, as: UTF8.self), &failure)
        if let failure { throw failure }
        guard let filtered, !filtered.isEmpty, filtered.utf8.count <= Self.maxProfileBytes else { throw tunnelError(58, "Native multihop LAN policy was not compiled") }
        var finalFiles = mtuFiles
        finalFiles["sing-box.json"] = Data(filtered.utf8)
        finalFiles = try performanceFiles(finalFiles, entryProfile: entryProfile, exitProfile: exitProfile)
        let strict = strictKillSwitchRequested(selectedProfile) || strictKillSwitchRequested(entryProfile)
        if strict {
            guard let proto = protocolConfiguration as? NETunnelProviderProtocol, proto.includeAllNetworks, proto.enforceRoutes,
                  proto.excludeLocalNetworks == ((entryProfile["home_lan_access"] as? Bool ?? true) && (exitProfile["home_lan_access"] as? Bool ?? true)) else {
                throw tunnelError(53, "Multihop cannot weaken either node's strict route-lockdown or LAN policy.")
            }
        }
        let entryURL = try selectedProofURL(entryProfile), exitURL = try selectedProofURL(selectedProfile)
        let forwardingProfileData = try JSONSerialization.data(withJSONObject: selectedProfile)
        let engine = RouterVPNLibboxEngine(tunnel: self)
        try engine.prepareMTUHold(initialMTUHold)
        libboxEngine = engine
        do {
            let execution = restoredMultihopExecution ?? selectedProfile["multihop_execution"] as? String ?? "local"
            guard ["local", "server", "auto"].contains(execution) else { throw tunnelError(56, "Unknown multihop execution choice") }
            if entryLayer.source != nil || exitLayer.source != nil || entryMAX != nil || exitMAX != nil || entryComposite != nil || exitComposite != nil {
                try engine.start(files: finalFiles, strict: strict, multihopMetadata: hopMetadata,
                                 entryStartLayerSource: entryLayer.source, exitStartLayerSource: exitLayer.source)
            } else { try engine.start(files: finalFiles, strict: strict, multihopMetadata: hopMetadata) }
        }
        catch { engine.stop(); libboxEngine = nil; throw error }
        // One guard spans the comparison and both node proofs. Rearming after
        // a long comparison would erase an intervening network invalidation.
        let comparisonGuard = self.armNetworkProofGuard()
        engine.completeMultihopExecution { [weak self] comparisonError in
            guard let self, self.libboxEngine === engine else { engine.stop(); completionHandler(RouterVPNMultihopGraph.issue("Multihop comparison belongs to an old runtime.")); return }
            if let comparisonError { engine.stop(); self.libboxEngine = nil; completionHandler(comparisonError); return }
            guard self.currentPathProofGuard() === comparisonGuard else { engine.stop(); completionHandler(self.tunnelError(57, "Multihop network changed during comparison.")); return }
        // These are separately routed proofs, not a direct ping cache or a
        // repeated exit response. Completion stays pending until BOTH succeed.
        proveSelectedNode(url: entryURL, expectedNodeID: entryProofID, proxyPort: RouterVPNMultihopGraph.entryProofPort) { [weak self] entryError in
            guard let self else { engine.stop(); completionHandler(RouterVPNMultihopGraph.issue("Multihop provider was released.")); return }
            guard self.libboxEngine === engine else { engine.stop(); completionHandler(self.tunnelError(54, "Multihop entry proof belongs to an old runtime.")); return }
            if let entryError { engine.stop(); self.libboxEngine = nil; completionHandler(entryError); return }
            guard self.currentPathProofGuard() === comparisonGuard else { engine.stop(); completionHandler(self.tunnelError(57, "Multihop network changed during entry proof.")); return }
            self.proveSelectedNode(url: exitURL, expectedNodeID: exitProofID, proxyPort: RouterVPNLibboxEngine.proofProxyPort) { [weak self] exitError in
                guard let self else { engine.stop(); completionHandler(RouterVPNMultihopGraph.issue("Multihop provider was released.")); return }
                guard self.libboxEngine === engine else { engine.stop(); completionHandler(self.tunnelError(55, "Multihop exit proof belongs to an old runtime.")); return }
                if let exitError { engine.stop(); self.libboxEngine = nil; completionHandler(exitError); return }
                guard self.currentPathProofGuard() === comparisonGuard else { engine.stop(); completionHandler(self.tunnelError(57, "Multihop network changed during exit proof.")); return }
                do { try engine.activatePerformance(); try engine.enableHopMeasurement(metadata: hopMetadata) }
                catch { engine.stop(); self.libboxEngine = nil; completionHandler(error); return }
                guard self.currentPathProofGuard() === comparisonGuard else { engine.stop(); completionHandler(self.tunnelError(57,"Multihop changed during performance activation.")); return }
                do {
                    guard var mtuProfile = try JSONSerialization.jsonObject(with: mtuProfileData) as? [String: Any] else {
                        throw self.tunnelError(58, "Captured multihop MTU profile is invalid.")
                    }
                    mtuProfile["node_proof_id"] = exitProofID
                    engine.activateMTU(profile: mtuProfile)
                    guard let source = self.multihopExecutionSource else { throw IOSMultihopExecution.issue() }
                    try engine.bindMultihopExecutionSource(source, metadata: hopMetadata)
                } catch { engine.stop(); self.libboxEngine = nil; completionHandler(error); return }
                self.enableForwarding(profileData: forwardingProfileData, proofID: exitProofID, captured: comparisonGuard)
                completionHandler(nil)
            }
        }
        }
    }

    /// Prove each WG server key against its own captured node identity. In
    /// particular, an exit label can never certify a reused entry peer key.
    private func multihopWireGuardEndpoint(root: [String: Any], expectedProofID: String, name: String) throws -> (endpoint: [String: Any], dns: [String]) {
        let wg = try RouterVPNWireGuardConfig.parse(wireGuardLikeProfile(root, rawProfileID: "wg"), name: name)
        guard wg.peers.count == 1, let peer = wg.peers.first, let remote = peer.endpoint,
              deriveNodeProof(from: peer.publicKey.base64Key) == expectedProofID,
              let address = URLComponents(string: "udp://" + remote.stringRepresentation),
              let rawHost = address.host, let port = address.port else {
            throw tunnelError(52, "Multihop WireGuard server key does not match its paired node identity.")
        }
        let host = rawHost.trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
        var peerJSON: [String: Any] = ["address": host, "port": port,
            "public_key": peer.publicKey.base64Key, "allowed_ips": peer.allowedIPs.map(\.stringRepresentation)]
        if let psk = peer.preSharedKey { peerJSON["pre_shared_key"] = psk.base64Key }
        if let keepalive = peer.persistentKeepAlive, let value = Int(keepalive) { peerJSON["persistent_keepalive_interval"] = value }
        let endpoint: [String: Any] = ["type": "wireguard", "address": wg.interface.addresses.map(\.stringRepresentation),
            "private_key": wg.interface.privateKey.base64Key, "mtu": Int(wg.interface.mtu ?? 1280), "peers": [peerJSON]]
        return (endpoint, wg.interface.dns.map(\.stringRepresentation))
    }

    /// The Amnezia peer key is not the node's standard WG identity anchor.
    /// The compiler preserves all AWG options; the existing private node proof
    /// after startup must validate the captured durable identity independently.
    private func nativeAmneziaEndpoint(root: [String: Any], expectedProofID: String, mode: String) throws -> (endpoint: [String: Any], dns: [String]) {
        guard ["awg2-fast", "awg2-strong"].contains(mode), expectedProofID.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil else { throw tunnelError(58,"Native AWG requires the captured paired node identity and exact mode.") }
        let text = try wireGuardLikeProfile(root, rawProfileID: mode)
        var failure: NSError?
        let compiled: String? = LibboxRouterCompileAmneziaProfile(text, expectedProofID, &failure)
        if let failure { throw failure }
        guard let compiled, !compiled.isEmpty, compiled.utf8.count <= Self.maxProfileBytes,
              let object = try JSONSerialization.jsonObject(with: Data(compiled.utf8)) as? [String: Any],
              let endpoint = object["endpoint"] as? [String: Any], endpoint["type"] as? String == "routervpn-amneziawg",
              let dns = object["dns"] as? [String] else { throw tunnelError(58,"Native AWG compiler did not return its owned endpoint.") }
        return (endpoint, dns)
    }

    private func startLibbox(provider: [String: Any], root: [String: Any], selectedProfile: [String: Any], strict: Bool, completionHandler: @escaping (Error?) -> Void) throws {
        let compiled = try compileLibbox(provider: provider, root: root, selectedProfile: selectedProfile)
        let files = compiled.files, provenNodeID = compiled.nodeID
        let proofURL = compiled.proofURL, forwardingProfileData = compiled.profile
        let engine = RouterVPNLibboxEngine(tunnel: self); libboxEngine = engine
        try engine.prepareMTUHold(initialMTUHold)
        do { try engine.start(files: files, strict: strict) } catch { libboxEngine = nil; throw tunnelError(15, "Libbox engine failed to start: \(error.localizedDescription)") }
        let singlePathGuard = self.armNetworkProofGuard()
        proveSelectedNode(url: proofURL, expectedNodeID: provenNodeID, proxyPort: RouterVPNLibboxEngine.proofProxyPort) { [weak self] proofError in
            guard let self else { completionHandler(NSError(domain: "RouterVPN.PacketTunnel", code: 16, userInfo: [NSLocalizedDescriptionKey: "Router VPN PacketTunnel was released during Libbox proof."])); return }
            guard self.libboxEngine === engine else { engine.stop(); completionHandler(self.tunnelError(42, "A newer iOS Libbox runtime replaced this proof attempt.")); return }
            if let proofError { engine.stop(); if self.libboxEngine === engine { self.libboxEngine = nil }; completionHandler(proofError); return }
            guard self.currentPathProofGuard() === singlePathGuard else { engine.stop(); completionHandler(self.tunnelError(57,"Native path changed during node proof.")); return }
            do { try engine.activatePerformance() } catch { engine.stop(); if self.libboxEngine === engine { self.libboxEngine = nil }; completionHandler(error); return }
            guard self.currentPathProofGuard() === singlePathGuard else { engine.stop(); completionHandler(self.tunnelError(57,"Native path changed during performance activation.")); return }
            var mtuProfile = selectedProfile
            mtuProfile["node_proof_id"] = provenNodeID
            engine.activateMTU(profile: mtuProfile)
            self.enableForwarding(profileData: forwardingProfileData, proofID: provenNodeID, captured: singlePathGuard)
            completionHandler(nil)
        }
    }

    private struct LibboxCompilation {
        let files: [String: Data]
        let nodeID: String
        let proofURL: URL
        let profile: Data
    }

    private func compileLibbox(provider: [String: Any], root: [String: Any], selectedProfile: [String: Any]) throws -> LibboxCompilation {
        let rawProfileID = (provider["rawProfileID"] as? String ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        guard rawProfileID.range(of: "^[A-Za-z0-9._-]{1,96}$", options: .regularExpression) != nil, !rawProfileID.contains("..") else { throw tunnelError(13, "iOS Libbox raw profile id is invalid.") }
        var expectedNodeID = try suppliedNodeProof(root: root, selectedProfile: selectedProfile)
        var rawFiles: [String: Data]
        if IOSNativeMAXProfile.modeIDs.contains(rawProfileID) {
            guard let profiles = root["profiles"] as? [String: Any],
                  let encoded = profiles[rawProfileID] as? [String: String] else { throw tunnelError(58, "Complete MAX captured assets are missing.") }
            let start = try IOSStartLayer.selectedMode(profile: selectedProfile)
            rawFiles = try IOSNativeMAXProfile.compile(mode: rawProfileID, encoded: encoded, nodeID: expectedNodeID,
                                                       profile: selectedProfile, startLayer: start) { mode, assets, metadata in
                var failure: NSError?
                let result: String? = LibboxRouterCompileMAXProfile(mode, assets, metadata, &failure)
                if let failure { throw failure }
                guard let result else { throw tunnelError(58, "Complete MAX compiler returned no graph.") }
                return result
            }
            rawFiles = try RouterVPNMultihopGraph.singlePQPolicy(rawFiles, profile: selectedProfile)
        } else if IOSNativeCompositeMultihop.modeIDs.contains(rawProfileID) {
            let layer = try IOSStartLayer.selectedMode(profile: selectedProfile)
            guard let captured = try IOSNativeCompositeMultihop.capture(root: root, mode: rawProfileID,
                profile: selectedProfile, nodeID: expectedNodeID, layer: layer, compiler: { mode, assets, policy, start in
                    var failure: NSError?
                    let compiled: String? = LibboxRouterCompileCompositeProfile(mode, assets, policy, start, &failure)
                    if let failure { throw failure }
                    guard let compiled else { throw self.tunnelError(58, "Composite entry did not compile.") }
                    return compiled
                }, baseCompiler: { source, mode, node, start in
                    var failure: NSError?
                    let compiled: String? = LibboxRouterCompositeMultihopBase(source, mode, node, start, &failure)
                    if let failure { throw failure }
                    guard let compiled else { throw self.tunnelError(58, "Composite entry lost its captured owner.") }
                    return compiled
                }) else { throw tunnelError(58, "The selected composite entry was not captured.") }
            // Apply the saved DNS policy to the validated owner, then retain the
            // complete source's TCP/UDP lanes and its already composed Start Layer.
            let policyFiles = try RouterVPNMultihopGraph.compositeDNSPolicy(captured.baseFiles, profile: selectedProfile)
            guard let policyData = policyFiles["sing-box.json"],
                  let policyGraph = try JSONSerialization.jsonObject(with: policyData) as? [String: Any],
                  let dns = policyGraph["dns"] as? [String: Any],
                  var complete = try JSONSerialization.jsonObject(with: Data(captured.source.utf8)) as? [String: Any] else {
                throw tunnelError(58, "Composite entry lost its captured resolver or complete graph.")
            }
            complete["dns"] = dns
            rawFiles = ["sing-box.json": try JSONSerialization.data(withJSONObject: complete, options: [.sortedKeys])]
        } else if IOSNativePQProfile.modeIDs.contains(rawProfileID) {
            guard let profiles = root["profiles"] as? [String: Any],
                  let encoded = profiles[rawProfileID] as? [String: String] else { throw tunnelError(58, "Native PQ captured assets are missing.") }
            rawFiles = try IOSNativePQProfile.compile(mode: rawProfileID, encoded: encoded, nodeID: expectedNodeID) { mode, assets, nodeID in
                var failure: NSError?
                let result: String? = LibboxRouterCompilePQProfile(mode, assets, nodeID, &failure)
                if let failure { throw failure }
                guard let result else { throw tunnelError(58, "Native PQ compiler returned no graph.") }
                return result
            }
            rawFiles = try RouterVPNMultihopGraph.singlePQPolicy(rawFiles, profile: selectedProfile)
        } else if ["wg", "awg2-fast", "awg2-strong"].contains(rawProfileID) {
            // Raw WireGuardKit still rejects Start Layer. This branch composes
            // the validated WG/AWG endpoint through the pinned native compiler.
            _ = try IOSStartLayer.selectedMode(profile: selectedProfile)
            if expectedNodeID.isEmpty && rawProfileID == "wg" {
                let parsed = try RouterVPNWireGuardConfig.parse(wireGuardLikeProfile(root, rawProfileID: "wg"), name: "Router VPN")
                guard parsed.peers.count == 1, let peer = parsed.peers.first else { throw tunnelError(58, "Native WG requires exactly one owned peer.") }
                expectedNodeID = deriveNodeProof(from: peer.publicKey.base64Key)
            }
            let native = rawProfileID == "wg"
                ? try multihopWireGuardEndpoint(root: root, expectedProofID: expectedNodeID, name: "Router VPN")
                : try nativeAmneziaEndpoint(root: root, expectedProofID: expectedNodeID, mode: rawProfileID)
            rawFiles = try RouterVPNMultihopGraph.wireGuardFiles(endpoint: native.endpoint, profile: selectedProfile, dnsServers: native.dns)
            rawFiles = try RouterVPNMultihopGraph.singleWireGuardPolicy(rawFiles, profile: selectedProfile)
        } else {
            rawFiles = try layeredProfile(root, rawProfileID: rawProfileID)
            if ["shadowsocks", "hysteria2", "naive-h2", "naive-h3"].contains(rawProfileID) {
                guard let profiles = root["profiles"] as? [String: Any], let assets = profiles[rawProfileID] as? [String: String],
                      let source = rawFiles["sing-box.json"],
                      var graph = try JSONSerialization.jsonObject(with: source) as? [String: Any],
                      var outputs = graph["outbounds"] as? [[String: Any]] else { throw tunnelError(58, "Native proxy lost its captured assets.") }
                let input = try JSONSerialization.data(withJSONObject: assets, options: [.sortedKeys])
                var failure: NSError?
                let result: String? = LibboxRouterCompileProxyEntry(String(decoding: input, as: UTF8.self), rawProfileID, &failure)
                if let failure { throw failure }
                guard let result, !result.isEmpty, result.utf8.count <= Self.maxProfileBytes,
                      var outbound = try JSONSerialization.jsonObject(with: Data(result.utf8)) as? [String: Any],
                      outbound["tag"] as? String == "routervpn-hop-entry" else { throw tunnelError(58, "Native proxy validation did not preserve its owner.") }
                let positions = outputs.indices.filter { outputs[$0]["tag"] as? String == "proxy" }
                guard positions.count == 1 else { throw tunnelError(58, "Native proxy final owner is ambiguous.") }
                // Only its own validated certificate is inlined. DNS, routes,
                // interface and all selected transport fields remain captured.
                outbound["tag"] = "proxy"; outputs[positions[0]] = outbound; graph["outbounds"] = outputs
                rawFiles["sing-box.json"] = try JSONSerialization.data(withJSONObject: graph, options: [.sortedKeys])
            }
        }
        if let original = rawFiles["xray.json"] {
            guard let wrapper = rawFiles["sing-box.json"], let wrapperText = String(data: wrapper, encoding: .utf8), let xrayText = String(data: original, encoding: .utf8) else { throw tunnelError(58, "Native Xray requires its exact UTF-8 imported graph.") }
            var failure: NSError?
            let compiled: String? = LibboxRouterCompileXrayProfile(rawProfileID, wrapperText, xrayText, &failure)
            if let failure { throw failure }
            guard let compiled, !compiled.isEmpty, compiled.utf8.count <= Self.maxProfileBytes else { throw tunnelError(58, "Native Xray graph validation failed.") }
            rawFiles["sing-box.json"] = Data(compiled.utf8)
        }
        // Complete-chain compilers already own their selected outer layer.
        var compositionRoot = root
        if let source = rawFiles["start-layer-source.json"] {
            guard rawFiles["xray.json"] != nil, !source.isEmpty, source.count <= Self.maxProfileBytes,
                  var profiles = root["profiles"] as? [String: Any],
                  var shadowsocks = profiles["shadowsocks"] as? [String: Any] else {
                throw tunnelError(58, "A frozen Xray Start Layer source has no matching captured graph.")
            }
            shadowsocks["sing-box.json"] = source.base64EncodedString()
            profiles["shadowsocks"] = shadowsocks; compositionRoot["profiles"] = profiles
        }
        let completeChain = IOSNativeMAXProfile.modeIDs.contains(rawProfileID) || IOSNativeCompositeMultihop.modeIDs.contains(rawProfileID)
        let composedFiles = try completeChain ? rawFiles
            : IOSStartLayer.apply(root: compositionRoot, selectedProfile: selectedProfile, files: rawFiles, rawProfileID: rawProfileID)
        var files = try RouterVPNMTUPolicy.libbox(composedFiles, profile: selectedProfile)
        if rawFiles["xray.json"] != nil {
            files = try IOSXrayDevicePolicy.apply(files: files, profile: selectedProfile)
        }
        let proxyEntry = ["shadowsocks", "hysteria2", "naive-h2", "naive-h3"].contains(rawProfileID)
        if completeChain || proxyEntry || ["wg", "awg2-fast", "awg2-strong", "wg-pq", "awg2-pq"].contains(rawProfileID) {
            guard let data = files["sing-box.json"], let text = String(data: data, encoding: .utf8) else { throw tunnelError(58, "Native WG lost its compiled graph.") }
            let policies = try JSONSerialization.data(withJSONObject: ["entry": selectedProfile, "exit": selectedProfile])
            var failure: NSError?
            let protected: String? = LibboxRouterApplyMultihopLANPolicy(text, String(decoding: policies, as: UTF8.self), &failure)
            if let failure { throw failure }
            guard let protected, !protected.isEmpty, protected.utf8.count <= Self.maxProfileBytes else { throw tunnelError(58, "Native WG LAN policy was not compiled.") }
            files["sing-box.json"] = Data(protected.utf8)
        }
        if proxyEntry || IOSNativeCompositeMultihop.modeIDs.contains(rawProfileID) {
            if let value = selectedProfile["ipv6_mode"], !(value is String) { throw tunnelError(58, "Proxy IPv6 policy must be a saved selection.") }
            let ipv6 = (selectedProfile["ipv6_mode"] as? String ?? "on").trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            guard ["", "on", "auto", "off"].contains(ipv6) else { throw tunnelError(58, "Proxy IPv6 policy is invalid.") }
            if ipv6 == "off" {
                guard let data = files["sing-box.json"], var graph = try JSONSerialization.jsonObject(with: data) as? [String: Any],
                      var inputs = graph["inbounds"] as? [[String: Any]], inputs.count == 1,
                      inputs[0]["type"] as? String == "tun", let tag = inputs[0]["tag"] as? String,
                      var addresses = inputs[0]["address"] as? [String], !addresses.isEmpty,
                      var route = graph["route"] as? [String: Any], route["final"] as? String == "proxy",
                      let rules = route["rules"] as? [[String: Any]], var dns = graph["dns"] as? [String: Any] else { throw tunnelError(58, "Proxy IPv6 policy lost its owned interface.") }
                // Capture IPv6 before rejecting it; removing its system route
                // would allow the underlying connection to carry that traffic.
                if !addresses.contains(where: { $0.contains(":") }) { addresses.append("fd00:5256:504e:1::1/126") }
                inputs[0]["address"] = addresses
                if inputs[0]["route_address"] == nil { inputs[0]["route_address"] = ["0.0.0.0/0", "::/0"] }
                route["rules"] = [["inbound": [tag], "ip_version": 6, "action": "reject"]] + rules
                dns["strategy"] = "ipv4_only"
                graph["route"] = route; graph["dns"] = dns; graph["inbounds"] = inputs
                files["sing-box.json"] = try JSONSerialization.data(withJSONObject: graph, options: [.sortedKeys])
            }
        }
        guard expectedNodeID.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil else { throw tunnelError(14, "Layered iOS modes require the imported node's exact node proof id.") }
        var performanceProfile = selectedProfile
        performanceProfile["node_proof_id"] = expectedNodeID
        files = try performanceFiles(files, entryProfile: performanceProfile, exitProfile: performanceProfile)
        return LibboxCompilation(files: files, nodeID: expectedNodeID,
                                 proofURL: try selectedProofURL(selectedProfile),
                                 profile: try JSONSerialization.data(withJSONObject: selectedProfile))
    }

    private func performanceFiles(_ files: [String: Data], entryProfile: [String: Any], exitProfile: [String: Any]) throws -> [String: Data] {
        guard let source = files["sing-box.json"], let text = String(data: source, encoding: .utf8) else { throw tunnelError(58,"Native performance graph is missing.") }
        let profiles = try JSONSerialization.data(withJSONObject: ["entry": entryProfile, "exit": exitProfile])
        var failure: NSError?
        let compiled: String? = LibboxRouterApplyPerformancePolicy(text, String(decoding: profiles, as: UTF8.self), &failure)
        if let failure { throw failure }
        guard let compiled, !compiled.isEmpty, compiled.utf8.count <= Self.maxProfileBytes else { throw tunnelError(58,"Native performance graph is invalid.") }
        var result = files; result["sing-box.json"] = Data(compiled.utf8); return result
    }

    private func startExternalLibbox(provider: [String: Any], selectedProfile: [String: Any], strict: Bool, completionHandler: @escaping (Error?) -> Void) throws {
        try IOSStartLayer.validateExternal(profile: selectedProfile)
        var entryFiles: [String: Data] = [:]
        var entryProfile: [String: Any]?
        var effectiveStrict = strict
        let externalProtocol = (selectedProfile["external"] as? [String: Any])?["protocol"] as? String ?? ""
        if let entryData = provider["tor_entry_bundle"] {
            guard ["tor", "tor-bridge"].contains(externalProtocol), provider["external_entry_bundle"] == nil, provider["external_entry_mode"] == nil,
                  let data = entryData as? Data, !data.isEmpty, data.count <= Self.maxBundleBytes,
                  selectedProfile["multihop_enabled"] as? Bool == true,
                  let entryRoot = try JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let mode = provider["tor_entry_mode"] as? String,
                  mode == (selectedProfile["multihop_entry_mode"] as? String ?? "wg"),
                  RouterVPNExternalExitBuilder.torEntryModes.contains(mode) else { throw tunnelError(58, "Tor lost its captured entry bundle or transport.") }
            let entry = try selectedRouterProfile(entryRoot)
            guard entry["id"] as? String == selectedProfile["multihop_entry_id"] as? String,
                  entry["node_kind"] as? String == "router-vpn" else { throw tunnelError(58, "Tor entry bundle selected another node.") }
            let compiled = try compileLibbox(provider: ["rawProfileID": mode], root: entryRoot, selectedProfile: entry)
            entryFiles = compiled.files; entryProfile = entry
            effectiveStrict = strict || strictKillSwitchRequested(entry)
            guard let tunnelProtocol = protocolConfiguration as? NETunnelProviderProtocol,
                  !effectiveStrict || (tunnelProtocol.includeAllNetworks && tunnelProtocol.enforceRoutes &&
                  tunnelProtocol.excludeLocalNetworks == ((entry["home_lan_access"] as? Bool ?? true) && (selectedProfile["home_lan_access"] as? Bool ?? true))) else { throw tunnelError(58, "Tor entry and exit route lockdown was not preserved.") }
        } else if let entryData = provider["external_entry_bundle"] {
            guard RouterVPNExternalExitBuilder.ordinaryProtocols.contains(externalProtocol), provider["tor_entry_mode"] == nil,
                  let data = entryData as? Data, !data.isEmpty, data.count <= Self.maxBundleBytes,
                  selectedProfile["multihop_enabled"] as? Bool == true,
                  let entryRoot = try JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let mode = provider["external_entry_mode"] as? String,
                  mode == selectedProfile["multihop_entry_mode"] as? String else { throw tunnelError(58, "External startup lost its captured entry bundle or transport.") }
            let entry = try selectedRouterProfile(entryRoot)
            guard entry["id"] as? String == selectedProfile["multihop_entry_id"] as? String else { throw tunnelError(58, "External entry bundle selected another node.") }
            if entry["node_kind"] as? String == "external" {
                guard RouterVPNExternalExitBuilder.ordinaryProtocols.contains(mode),
                      (entry["external"] as? [String: Any])?["protocol"] as? String == mode else { throw tunnelError(58, "External entry protocol differs from its captured node.") }
                try IOSStartLayer.validateExternal(profile: entry)
            } else {
                guard entry["node_kind"] as? String == "router-vpn", RouterVPNExternalExitBuilder.torEntryModes.contains(mode) else {
                    throw tunnelError(58, "The captured Router VPN entry transport is invalid.")
                }
                let compiled = try compileLibbox(provider: ["rawProfileID": mode], root: entryRoot, selectedProfile: entry)
                entryFiles = compiled.files
            }
            entryProfile = entry
            effectiveStrict = strict || strictKillSwitchRequested(entry)
            guard let tunnelProtocol = protocolConfiguration as? NETunnelProviderProtocol,
                  !effectiveStrict || (tunnelProtocol.includeAllNetworks && tunnelProtocol.enforceRoutes &&
                  tunnelProtocol.excludeLocalNetworks == ((entry["home_lan_access"] as? Bool ?? true) && (selectedProfile["home_lan_access"] as? Bool ?? true))) else { throw tunnelError(58, "External entry and exit route lockdown was not preserved.") }
        } else if provider["tor_entry_mode"] != nil || provider["external_entry_mode"] != nil || selectedProfile["multihop_enabled"] as? Bool == true {
            throw tunnelError(58, "Saved external multihop cannot start without its captured entry.")
        }
        let runtime = try RouterVPNExternalExitBuilder.build(profile: selectedProfile, predecessorFiles: entryFiles, predecessorProfile: entryProfile,
                                                            restoredExecution: restoredMultihopExecution)
        guard (runtime.policy?.executionRequested != nil) == (multihopExecutionSource != nil) else {
            throw IOSMultihopExecution.issue()
        }
        let engine = RouterVPNLibboxEngine(tunnel: self); libboxEngine = engine
        try engine.prepareMTUHold(initialMTUHold)
        let files = runtime.torSessionID == nil && runtime.policy == nil ? try RouterVPNMTUPolicy.libbox(runtime.files, profile: selectedProfile) : runtime.files
        do {
            if let policy = runtime.policy { try engine.start(files: files, strict: effectiveStrict, externalPolicy: policy) }
            else { try engine.start(files: files, strict: effectiveStrict) }
        } catch { libboxEngine = nil; throw tunnelError(17, "External Libbox engine failed to start: \(error.localizedDescription)") }
        let externalPathGuard = self.armNetworkProofGuard()
        let prove: (@escaping (Error?) -> Void) -> Void
        if let sessionID = runtime.torSessionID {
            guard let profile = runtime.torProfileJSON else {
                engine.stop(); if libboxEngine === engine { libboxEngine = nil }
                releasePathProofGuard(externalPathGuard)
                throw tunnelError(58, "Tor proof lost its exact compiled profile.")
            }
            prove = { engine.proveTor(sessionID: sessionID, profile: profile, predecessorProfile: runtime.torPredecessorProfile, completion: $0) }
        } else if runtime.policy != nil {
            prove = { engine.proveExternal(completion: $0) }
        } else {
            prove = { self.proveExternalExit(expectedPublicIP: runtime.expectedPublicIP, proxyPort: RouterVPNLibboxEngine.proofProxyPort, completion: $0) }
        }
        prove { [weak self] proofError in
            guard let self else { completionHandler(NSError(domain: "RouterVPN.PacketTunnel", code: 18, userInfo: [NSLocalizedDescriptionKey: "Router VPN PacketTunnel was released during external-exit proof."])); return }
            guard self.libboxEngine === engine else { engine.stop(); completionHandler(self.tunnelError(43, "A newer iOS external runtime replaced this proof attempt.")); return }
            if let proofError {
                self.releasePathProofGuard(externalPathGuard)
                engine.stop(); if self.libboxEngine === engine { self.libboxEngine = nil }; completionHandler(proofError)
                return
            }
            guard self.currentPathProofGuard() === externalPathGuard else {
                engine.stop(); if self.libboxEngine === engine { self.libboxEngine = nil }
                completionHandler(self.tunnelError(57, "External path changed during native DNS and exit proof."))
                return
            }
            do {
                if runtime.policy != nil || runtime.torSessionID != nil {
                    guard let exitID = selectedProfile["id"] as? String else { throw self.tunnelError(58, "External measurement lost its captured exit identity.") }
                    try engine.enableExternalHopMeasurement(exitID: exitID)
                    try engine.enableExternalDNSMeasurement(exitID: exitID)
                    guard self.libboxEngine === engine, self.currentPathProofGuard() === externalPathGuard else {
                        throw self.tunnelError(57, "External path changed during measurement activation.")
                    }
                }
                if runtime.policy != nil {
                    try engine.activateExternalMTU()
                    guard self.libboxEngine === engine, self.currentPathProofGuard() === externalPathGuard else {
                        throw self.tunnelError(57, "External path changed during MTU owner activation.")
                    }
                    if runtime.policy?.executionRequested != nil {
                        guard let source = self.multihopExecutionSource else { throw IOSMultihopExecution.issue() }
                        try engine.bindExternalExecutionSource(source)
                        guard self.libboxEngine === engine, self.currentPathProofGuard() === externalPathGuard else {
                            throw self.tunnelError(57, "External path changed during execution receipt activation.")
                        }
                    }
                } else if runtime.torSessionID != nil {
                    try engine.activateTorMTU()
                    guard self.libboxEngine === engine, self.currentPathProofGuard() === externalPathGuard else {
                        throw self.tunnelError(57, "Tor path changed during MTU owner activation.")
                    }
                }
            } catch {
                self.releasePathProofGuard(externalPathGuard)
                engine.stop(); if self.libboxEngine === engine { self.libboxEngine = nil }
                completionHandler(error); return
            }
            completionHandler(nil)
        }
    }

    @discardableResult
    private func armNetworkProofGuard() -> NetworkProofGuard {
        let monitor = NWPathMonitor()
        let guardState = NetworkProofGuard(owner: self)
        pathProofOwnerLock.lock()
        let previous = pathMonitor
        let previousProof = pathProofGuard
        pathProofGuard = guardState
        pathMonitor = monitor
        pathProofOwnerLock.unlock()
        if let previousProof { retireTelemetry(previousProof) }
        previous?.cancel()
        monitor.pathUpdateHandler = { path in guardState.handle(path) }
        monitor.start(queue: pathMonitorQueue)
        return guardState
    }

    private func invalidateSelectedPathProof(_ guardState: NetworkProofGuard) {
        pathProofOwnerLock.lock()
        guard pathProofGuard === guardState else { pathProofOwnerLock.unlock(); return }
        let monitor = pathMonitor
        pathMonitor = nil
        pathProofGuard = nil
        pathProofOwnerLock.unlock()
        monitor?.cancel()
        libboxEngine?.invalidateMultihop()
        forwardingChannel?.invalidate()
        retireTelemetry(guardState)
        if let strategy = currentProviderStrategy() {
            strategy.invalidate(epoch: libboxEngine?.settingsEpoch ?? strategy.currentEpoch)
            return
        }
        cancelTunnelWithError(tunnelError(19, "Underlying network changed; selected-node/public-exit proof was invalidated. Reconnect must establish and prove the selected path again."))
    }

    /// Failed proof cleanup belongs to its captured guard, never a newer path.
    private func releasePathProofGuard(_ captured: NetworkProofGuard) {
        pathProofOwnerLock.lock()
        guard pathProofGuard === captured else { pathProofOwnerLock.unlock(); return }
        let monitor = pathMonitor
        pathMonitor = nil
        pathProofGuard = nil
        pathProofOwnerLock.unlock()
        monitor?.cancel()
        retireTelemetry(captured)
    }

    private func clearPathProofGuard() {
        forwardingChannel?.invalidate()
        pathProofOwnerLock.lock()
        let monitor = pathMonitor
        let captured = pathProofGuard
        pathMonitor = nil
        pathProofGuard = nil
        pathProofOwnerLock.unlock()
        monitor?.cancel()
        if let captured { retireTelemetry(captured) }
    }

    private func currentPathProofGuard() -> NetworkProofGuard? {
        pathProofOwnerLock.lock()
        let guardState = pathProofGuard
        pathProofOwnerLock.unlock()
        return guardState
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        maxStartOwnerLock.lock()
        maxStartGeneration = UUID(); maxStartDraining = true
        let pending = maxStartOwner
        maxStartOwnerLock.unlock()
        if let pending {
            pending.cancelAndDrain { [weak self] in
                guard let self else { completionHandler(); return }
                self.finishOwnedStop(completion: completionHandler)
            }
            return
        }
        finishOwnedStop(completion: completionHandler)
    }

    private func finishOwnedStop(completion: @escaping () -> Void) {
        if let strategy = currentProviderStrategy() {
            let epoch = strategy.currentEpoch
            strategy.stop()
            retireLibboxSettings(epoch: epoch)
            if let driver = strategyDriver {
                driver.drain { [weak self] in
                    guard let self else { completion(); return }
                    self.finishNativeStop(completion: completion)
                }
                return
            }
        }
        finishNativeStop(completion: completion)
    }

    private func finishNativeStop(completion: @escaping () -> Void) {
        clearPathProofGuard()
        cancelActiveProof()
        if let engine = libboxEngine { libboxEngine = nil; engine.stop() }
        strategyOwnerLock.lock(); providerStrategy = nil; strategyDriver = nil; strategyOwnerLock.unlock()
        let finished = { [self] in
            maxStartOwnerLock.lock(); maxStartOwner = nil; maxStartDraining = false; maxStartOwnerLock.unlock()
            completion()
        }
        guard let adapter = wireGuardAdapter else { finished(); return }
        wireGuardAdapter = nil
        adapter.stop { _ in finished() }
    }

    override func sleep(completionHandler: @escaping () -> Void) {
        forwardingChannel?.invalidate()
        retireTelemetry()
        maxStartOwnerLock.lock(); let pending = maxStartOwner
        if pending != nil { maxStartGeneration = UUID(); maxStartDraining = true }
        maxStartOwnerLock.unlock()
        if let pending {
            pending.cancelAndDrain { [weak self] in
                guard let self else { completionHandler(); return }
                self.finishOwnedStop(completion: completionHandler)
            }
        } else { libboxEngine?.pause(); completionHandler() }
    }
    override func wake() {
        libboxEngine?.wake()
        // Sleep is a path-proof lifetime boundary even when iOS resumes onto a
        // cached NWPath that does not emit a second update. Force this proved
        // path invalid; every reconnect must re-prove the selected node/public
        // exit. An owned strategy retains this provider and creates a fresh
        // native generation; legacy sessions use their existing reconnect path.
        if let guardState = currentPathProofGuard() { invalidateSelectedPathProof(guardState) }
    }
    func writeLibboxLog(_ message: String) { if !message.isEmpty { NSLog("RouterVPN Libbox: %@", message) } }

    private func installProof(session: URLSession, task: URLSessionDataTask) {
        proofOwnerLock.lock()
        let previousTask = proofTask
        let previousSession = proofSession
        proofTask = task
        proofSession = session
        proofOwnerLock.unlock()
        previousTask?.cancel()
        previousSession?.invalidateAndCancel()
    }

    private func finishProof(session: URLSession) {
        proofOwnerLock.lock()
        if proofSession === session {
            proofTask = nil
            proofSession = nil
        }
        proofOwnerLock.unlock()
        session.finishTasksAndInvalidate()
    }

    private func cancelActiveProof() {
        proofOwnerLock.lock()
        let task = proofTask
        let session = proofSession
        proofTask = nil
        proofSession = nil
        proofOwnerLock.unlock()
        task?.cancel()
        session?.invalidateAndCancel()
    }

    private func proveSelectedNode(url: URL, expectedNodeID: String, proxyPort: Int?, completion: @escaping (Error?) -> Void) {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = 5; configuration.timeoutIntervalForResource = 6; configuration.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        if let proxyPort { configuration.connectionProxyDictionary = [kCFNetworkProxiesHTTPEnable as String: 1, kCFNetworkProxiesHTTPProxy as String: "127.0.0.1", kCFNetworkProxiesHTTPPort as String: proxyPort] }
        let session = URLSession(configuration: configuration)
        var request = URLRequest(url: url); request.timeoutInterval = 5; request.cachePolicy = .reloadIgnoringLocalAndRemoteCacheData; request.setValue("application/json", forHTTPHeaderField: "Accept")
        let task = session.dataTask(with: request) { [weak self] data, response, error in
            guard let self else { session.finishTasksAndInvalidate(); return }
            defer { self.finishProof(session: session) }
            if let error { completion(self.tunnelError(20, "Selected-node private path proof failed: \(error.localizedDescription)")); return }
            guard let http = response as? HTTPURLResponse, http.statusCode == 200, let data, !data.isEmpty, data.count <= Self.maxProofBytes else { completion(self.tunnelError(21, "Selected-node private path proof returned an invalid response.")); return }
            do {
                guard let body = try JSONSerialization.jsonObject(with: data) as? [String: Any], body["ok"] as? Bool == true, body["node_id"] as? String == expectedNodeID, body["proof"] as? String == Self.proofKind else { throw self.tunnelError(22, "Selected-node private path proof identity did not match the imported router bundle.") }
                completion(nil)
            } catch { completion(error) }
        }
        installProof(session: session, task: task)
        task.resume()
    }

    private func proveExternalExit(expectedPublicIP: String, proxyPort: Int, completion: @escaping (Error?) -> Void) {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = 5; configuration.timeoutIntervalForResource = 6; configuration.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        configuration.connectionProxyDictionary = [kCFNetworkProxiesHTTPEnable as String: 1, kCFNetworkProxiesHTTPProxy as String: "127.0.0.1", kCFNetworkProxiesHTTPPort as String: proxyPort]
        let session = URLSession(configuration: configuration)
        let endpoint = expectedPublicIP.contains(":") ? "https://api64.ipify.org" : "https://api.ipify.org"
        var request = URLRequest(url: URL(string: endpoint)!); request.timeoutInterval = 5; request.cachePolicy = .reloadIgnoringLocalAndRemoteCacheData; request.setValue("text/plain", forHTTPHeaderField: "Accept")
        let task = session.dataTask(with: request) { [weak self] data, response, error in
            guard let self else { session.finishTasksAndInvalidate(); return }
            defer { self.finishProof(session: session) }
            if let error { completion(self.tunnelError(23, "External public-exit proof failed: \(error.localizedDescription)")); return }
            guard let http = response as? HTTPURLResponse, http.statusCode == 200, let data, !data.isEmpty, data.count <= 256, let text = String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) else { completion(self.tunnelError(24, "External public-exit proof returned an invalid response.")); return }
            let matches: Bool
            if let wanted = IPv4Address(expectedPublicIP), let seen = IPv4Address(text) { matches = wanted == seen }
            else if let wanted = IPv6Address(expectedPublicIP), let seen = IPv6Address(text) { matches = wanted == seen }
            else { matches = false }
            guard matches else { completion(self.tunnelError(25, "External exit reached \(text), expected \(expectedPublicIP).")); return }
            completion(nil)
        }
        installProof(session: session, task: task)
        task.resume()
    }

    private func selectedRouterProfile(_ root: [String: Any]) throws -> [String: Any] {
        guard let profiles = root["routerProfiles"] as? [[String: Any]], !profiles.isEmpty else { throw tunnelError(30, "Router VPN bundle has no routerProfiles.") }
        let selectedID = root["selectedRouterID"] as? String ?? ""
        if selectedID.isEmpty && profiles.count == 1 { return profiles[0] }
        let matches = profiles.filter { ($0["id"] as? String ?? "") == selectedID }
        guard !selectedID.isEmpty, matches.count == 1 else { throw tunnelError(30, "Selected Router VPN identity is missing or ambiguous.") }
        return matches[0]
    }
    private func wireGuardLikeProfile(_ root: [String: Any], rawProfileID: String) throws -> String {
        let asset = rawProfileID == "wg" ? "wg.conf" : "awg.conf"
        guard ["wg", "awg2-fast", "awg2-strong"].contains(rawProfileID),
              let profiles = root["profiles"] as? [String: Any],
              let raw = profiles[rawProfileID] as? [String: Any],
              let encoded = raw[asset] as? String, !encoded.isEmpty,
              let data = Data(base64Encoded: encoded, options: []),
              !data.isEmpty, data.count <= Self.maxProfileBytes,
              let text = String(data: data, encoding: .utf8) else {
            throw tunnelError(31, "Router VPN bundle has no valid bounded native \(rawProfileID == "wg" ? "WireGuard" : "AmneziaWG") profile.")
        }
        return text
    }
    private func layeredProfile(_ root: [String: Any], rawProfileID: String) throws -> [String: Data] {
        guard let profiles = root["profiles"] as? [String: Any], let raw = profiles[rawProfileID] as? [String: Any], raw["sing-box.json"] != nil else { throw tunnelError(32, "Selected iOS raw profile does not contain sing-box.json.") }
        var result: [String: Data] = [:], total = 0
        let assetPattern = try NSRegularExpression(pattern: "^[A-Za-z0-9._-]{1,128}$")
        for (name, value) in raw {
            guard let encoded = value as? String else { throw tunnelError(33, "Libbox asset \(name) is not an encoded string.") }
            let range = NSRange(name.startIndex..<name.endIndex, in: name)
            guard assetPattern.firstMatch(in: name, range: range)?.range == range, name != ".", name != "..", !name.contains("..") else { throw tunnelError(34, "Unsafe Libbox asset name \(name).") }
            guard let data = Data(base64Encoded: encoded, options: []), data.count <= Self.maxProfileBytes else { throw tunnelError(35, "Libbox asset \(name) is invalid or too large.") }
            total += data.count; guard total <= Self.maxLayeredBytes else { throw tunnelError(36, "Libbox raw profile exceeds the 12 MiB safety limit.") }
            result[name] = data
        }
        return result
    }
    private func strictKillSwitchRequested(_ profile: [String: Any]) -> Bool {
        if profile["kill_switch"] as? Bool == true { return true }
        let value = (profile["kill_switch_policy"] as? String ?? "").trimmingCharacters(in: .whitespacesAndNewlines).lowercased(); return ["strict", "always", "enabled", "on", "lockdown"].contains(value)
    }
    private func suppliedNodeProof(root: [String: Any], selectedProfile: [String: Any]) throws -> String {
        let top = (root["nodeProofId"] as? String ?? "").trimmingCharacters(in: .whitespacesAndNewlines), nested = (selectedProfile["node_proof_id"] as? String ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        for value in [top, nested] where !value.isEmpty { guard value.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil else { throw tunnelError(37, "Router bundle contains an invalid node proof id.") } }
        if !top.isEmpty && !nested.isEmpty && top != nested { throw tunnelError(38, "Router bundle node proof ids disagree.") }
        return top.isEmpty ? nested : top
    }
    private func deriveNodeProof(from serverPublicKey: String) -> String { SHA256.hash(data: Data((Self.nodeProofDomain + serverPublicKey).utf8)).map { String(format: "%02x", $0) }.joined() }
    private func selectedProofURL(_ profile: [String: Any]) throws -> URL {
        let raw = (profile["path_probe_url"] as? String ?? "http://10.77.0.1:8787/health").trimmingCharacters(in: .whitespacesAndNewlines)
        guard let url = URL(string: raw), url.scheme?.lowercased() == "http", let host = url.host, privateLiteralHost(host) else { throw tunnelError(39, "Selected-node proof URL must use a literal private IPv4/IPv6 HTTP address.") }
        return url
    }
    private func privateLiteralHost(_ host: String) -> Bool {
        if let ipv4 = IPv4Address(host) { let b = [UInt8](ipv4.rawValue); guard b.count == 4 else { return false }; return b[0] == 10 || (b[0] == 172 && b[1] >= 16 && b[1] <= 31) || (b[0] == 192 && b[1] == 168) || (b[0] == 169 && b[1] == 254) }
        if let ipv6 = IPv6Address(host) { let b = [UInt8](ipv6.rawValue); guard b.count == 16 else { return false }; return (b[0] & 0xfe) == 0xfc || (b[0] == 0xfe && (b[1] & 0xc0) == 0x80) }
        return false
    }
    private func tunnelError(_ code: Int, _ message: String) -> NSError { NSError(domain: "RouterVPN.PacketTunnel", code: code, userInfo: [NSLocalizedDescriptionKey: message]) }
}
