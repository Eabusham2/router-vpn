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
        private var invalidated = false
        weak var owner: PacketTunnelProvider?

        init(owner: PacketTunnelProvider) { self.owner = owner }

        func handle(_ path: NWPath) {
            _ = path.status
            lock.lock()
            if !sawInitialPath {
                sawInitialPath = true
                lock.unlock()
                return
            }
            if invalidated {
                lock.unlock()
                return
            }
            invalidated = true
            lock.unlock()
            owner?.invalidateSelectedPathProof(self)
        }
    }

    private var forwardingChannel: RouterVPNForwardingChannel?

    override init() {
        super.init()
        forwardingChannel = RouterVPNForwardingChannel(provider: self)
    }

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)? = nil) {
        guard let completionHandler else { return }
        if messageData.count <= 128,
           let request = try? JSONSerialization.jsonObject(with: messageData) as? [String: String],
           request == ["operation": "multihop-progress"] {
            completionHandler(libboxEngine?.multihopProgress()); return
        }
        forwardingChannel?.handle(messageData, completion: completionHandler)
    }

    private func enableForwarding(profileData: Data, proofID: String) {
        guard let profile = try? JSONSerialization.jsonObject(with: profileData) as? [String: Any] else { return }
        forwardingChannel?.activate(profile: profile, proofID: proofID)
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
        do {
            guard let tunnelProtocol = protocolConfiguration as? NETunnelProviderProtocol, let provider = tunnelProtocol.providerConfiguration else { throw tunnelError(1, "Router VPN PacketTunnel configuration is missing.") }
            guard let bundleData = provider["bundle"] as? Data, !bundleData.isEmpty, bundleData.count <= Self.maxBundleBytes else { throw tunnelError(2, "Router VPN private bundle is missing or exceeds the 32 MiB safety limit.") }
            guard let root = try JSONSerialization.jsonObject(with: bundleData) as? [String: Any] else { throw tunnelError(3, "Router VPN private bundle is invalid JSON.") }
            let selectedProfile = try selectedRouterProfile(root)
            let strict = strictKillSwitchRequested(selectedProfile)
            if strict {
                guard tunnelProtocol.includeAllNetworks, tunnelProtocol.enforceRoutes else { throw tunnelError(4, "strict Apple kill switch requested but NetworkExtension route lockdown is not enabled") }
                let allowLAN = selectedProfile["home_lan_access"] as? Bool ?? true
                guard tunnelProtocol.excludeLocalNetworks == !allowLAN else { throw tunnelError(5, "strict Apple kill switch LAN exclusion does not match the imported node policy") }
            }

            let engine = (provider["engine"] as? String ?? "wireguard").lowercased()
            switch engine {
            case "wireguard": try startWireGuard(provider: provider, root: root, selectedProfile: selectedProfile, completionHandler: completionHandler)
            case "multihop-libbox": try startMultihop(provider: provider, root: root, selectedProfile: selectedProfile, completionHandler: completionHandler)
            case "libbox": try startLibbox(provider: provider, root: root, selectedProfile: selectedProfile, strict: strict, completionHandler: completionHandler)
            case "external-libbox": try startExternalLibbox(selectedProfile: selectedProfile, strict: strict, completionHandler: completionHandler)
            default: throw tunnelError(6, "Unsupported Router VPN iOS engine \(engine).")
            }
        } catch { completionHandler(error) }
    }

    private func startWireGuard(provider: [String: Any], root: [String: Any], selectedProfile: [String: Any], completionHandler: @escaping (Error?) -> Void) throws {
        let requestedMode = (provider["mode"] as? String ?? "wg").lowercased()
        let nativeModes: Set<String> = ["wg", "awg2-fast", "awg2-strong"]
        guard nativeModes.contains(requestedMode) else { throw tunnelError(7, "Native WireGuard-family engine received unsupported mode \(requestedMode).") }
        try IOSStartLayer.validateWireGuard(profile: selectedProfile)
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
            self.proveSelectedNode(url: proofURL, expectedNodeID: expectedNodeID, proxyPort: nil) { proofError in
                guard self.wireGuardAdapter === adapter else { adapter.stop { _ in completionHandler(self.tunnelError(41, "A newer iOS WireGuard runtime replaced this proof attempt.")) }; return }
                if let proofError { adapter.stop { _ in if self.wireGuardAdapter === adapter { self.wireGuardAdapter = nil }; completionHandler(proofError) }; return }
                self.enableForwarding(profileData: forwardingProfileData, proofID: expectedNodeID)
                self.armNetworkProofGuard()
                completionHandler(nil)
            }
        }
    }

    private func startMultihop(provider: [String: Any], root: [String: Any], selectedProfile: [String: Any], completionHandler: @escaping (Error?) -> Void) throws {
        guard selectedProfile["multihop_enabled"] as? Bool == true,
              let entryID = selectedProfile["multihop_entry_id"] as? String,
              let exitID = selectedProfile["multihop_exit_id"] as? String,
              selectedProfile["id"] as? String == exitID,
              root["selectedRouterID"] as? String == exitID,
              let exitMode = selectedProfile["multihop_exit_mode"] as? String,
              provider["rawProfileID"] as? String == exitMode,
              RouterVPNMultihopGraph.supportedExitModes.contains(exitMode),
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
        let endpoint = try multihopWireGuardEndpoint(root: entryRoot, expectedProofID: entryProofID, name: "Router VPN entry").endpoint
        let rawFiles: [String: Data]
        if exitMode == "wg" {
            let exit = try multihopWireGuardEndpoint(root: root, expectedProofID: exitProofID, name: "Router VPN exit")
            rawFiles = try RouterVPNMultihopGraph.wireGuardFiles(endpoint: exit.endpoint, profile: exitProfile, dnsServers: exit.dns)
        } else {
            rawFiles = try layeredProfile(root, rawProfileID: exitMode)
        }
        let files = try RouterVPNMultihopGraph.build(entryEndpoint: endpoint, entryProfile: entryProfile,
            exitProfile: exitProfile, exitMode: exitMode, files: rawFiles)
        let finalFiles = try RouterVPNMTUPolicy.multihop(files, entryProfile: entryProfile, exitProfile: exitProfile)
        let strict = strictKillSwitchRequested(selectedProfile) || strictKillSwitchRequested(entryProfile)
        if strict {
            guard let proto = protocolConfiguration as? NETunnelProviderProtocol, proto.includeAllNetworks, proto.enforceRoutes else {
                throw tunnelError(53, "Multihop cannot weaken either node's strict route-lockdown policy.")
            }
        }
        let entryURL = try selectedProofURL(entryProfile), exitURL = try selectedProofURL(selectedProfile)
        let forwardingProfileData = try JSONSerialization.data(withJSONObject: selectedProfile)
        let engine = RouterVPNLibboxEngine(tunnel: self)
        libboxEngine = engine
        do {
            let execution = selectedProfile["multihop_execution"] as? String ?? "local"
            guard ["local", "server", "auto"].contains(execution) else { throw tunnelError(56, "Unknown multihop execution choice") }
            if execution == "local" { try engine.start(files: finalFiles, strict: strict) }
            else {
                let metadata: [String: String] = ["entry_id": entryID, "exit_id": selectedProfile["id"] as? String ?? "",
                    "entry_node_id": entryProofID, "exit_node_id": exitProofID,
                    "entry_api": entryProfile["router_api"] as? String ?? "", "exit_api": selectedProfile["router_api"] as? String ?? "",
                    "entry_token": entryProfile["api_token"] as? String ?? "", "exit_token": selectedProfile["api_token"] as? String ?? "",
                    "entry_tag": RouterVPNMultihopGraph.entryTag, "exit_mode": exitMode, "execution": execution]
                let encoded = try JSONSerialization.data(withJSONObject: metadata)
                try engine.start(files: finalFiles, strict: strict, multihopMetadata: String(decoding: encoded, as: UTF8.self))
            }
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
                self.enableForwarding(profileData: forwardingProfileData, proofID: exitProofID)
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

    private func startLibbox(provider: [String: Any], root: [String: Any], selectedProfile: [String: Any], strict: Bool, completionHandler: @escaping (Error?) -> Void) throws {
        let rawProfileID = (provider["rawProfileID"] as? String ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        guard rawProfileID.range(of: "^[A-Za-z0-9._-]{1,96}$", options: .regularExpression) != nil, !rawProfileID.contains("..") else { throw tunnelError(13, "iOS Libbox raw profile id is invalid.") }
        var rawFiles = try layeredProfile(root, rawProfileID: rawProfileID)
        if let original = rawFiles["xray.json"] {
            guard let wrapper = rawFiles["sing-box.json"], let wrapperText = String(data: wrapper, encoding: .utf8), let xrayText = String(data: original, encoding: .utf8) else { throw tunnelError(58, "Native Xray requires its exact UTF-8 imported graph.") }
            var failure: NSError?
            let compiled: String? = LibboxRouterCompileXrayProfile(rawProfileID, wrapperText, xrayText, &failure)
            if let failure { throw failure }
            guard let compiled, !compiled.isEmpty, compiled.utf8.count <= Self.maxProfileBytes else { throw tunnelError(58, "Native Xray graph validation failed.") }
            rawFiles["sing-box.json"] = Data(compiled.utf8)
        }
        let composedFiles = try IOSStartLayer.apply(root: root, selectedProfile: selectedProfile, files: rawFiles, rawProfileID: rawProfileID)
        let files = try RouterVPNMTUPolicy.libbox(composedFiles, profile: selectedProfile)
        let expectedNodeID = try suppliedNodeProof(root: root, selectedProfile: selectedProfile)
        guard expectedNodeID.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil else { throw tunnelError(14, "Layered iOS modes require the imported node's exact node proof id.") }
        let proofURL = try selectedProofURL(selectedProfile)
        let forwardingProfileData = try JSONSerialization.data(withJSONObject: selectedProfile)
        let engine = RouterVPNLibboxEngine(tunnel: self); libboxEngine = engine
        do { try engine.start(files: files, strict: strict) } catch { libboxEngine = nil; throw tunnelError(15, "Libbox engine failed to start: \(error.localizedDescription)") }
        proveSelectedNode(url: proofURL, expectedNodeID: expectedNodeID, proxyPort: RouterVPNLibboxEngine.proofProxyPort) { [weak self] proofError in
            guard let self else { completionHandler(NSError(domain: "RouterVPN.PacketTunnel", code: 16, userInfo: [NSLocalizedDescriptionKey: "Router VPN PacketTunnel was released during Libbox proof."])); return }
            guard self.libboxEngine === engine else { engine.stop(); completionHandler(self.tunnelError(42, "A newer iOS Libbox runtime replaced this proof attempt.")); return }
            if let proofError { engine.stop(); if self.libboxEngine === engine { self.libboxEngine = nil }; completionHandler(proofError); return }
            self.enableForwarding(profileData: forwardingProfileData, proofID: expectedNodeID)
            self.armNetworkProofGuard()
            completionHandler(nil)
        }
    }

    private func startExternalLibbox(selectedProfile: [String: Any], strict: Bool, completionHandler: @escaping (Error?) -> Void) throws {
        try IOSStartLayer.validateExternal(profile: selectedProfile)
        let runtime = try RouterVPNExternalExitBuilder.build(profile: selectedProfile)
        let engine = RouterVPNLibboxEngine(tunnel: self); libboxEngine = engine
        do { try engine.start(files: RouterVPNMTUPolicy.libbox(runtime.files, profile: selectedProfile), strict: strict) } catch { libboxEngine = nil; throw tunnelError(17, "External Libbox engine failed to start: \(error.localizedDescription)") }
        proveExternalExit(expectedPublicIP: runtime.expectedPublicIP, proxyPort: RouterVPNLibboxEngine.proofProxyPort) { [weak self] proofError in
            guard let self else { completionHandler(NSError(domain: "RouterVPN.PacketTunnel", code: 18, userInfo: [NSLocalizedDescriptionKey: "Router VPN PacketTunnel was released during external-exit proof."])); return }
            guard self.libboxEngine === engine else { engine.stop(); completionHandler(self.tunnelError(43, "A newer iOS external runtime replaced this proof attempt.")); return }
            if let proofError { engine.stop(); if self.libboxEngine === engine { self.libboxEngine = nil }; completionHandler(proofError); return }
            self.armNetworkProofGuard()
            completionHandler(nil)
        }
    }

    @discardableResult
    private func armNetworkProofGuard() -> NetworkProofGuard {
        let monitor = NWPathMonitor()
        let guardState = NetworkProofGuard(owner: self)
        pathProofOwnerLock.lock()
        let previous = pathMonitor
        pathProofGuard = guardState
        pathMonitor = monitor
        pathProofOwnerLock.unlock()
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
        cancelTunnelWithError(tunnelError(19, "Underlying network changed; selected-node/public-exit proof was invalidated. Reconnect must establish and prove the selected path again."))
    }

    private func clearPathProofGuard() {
        forwardingChannel?.invalidate()
        pathProofOwnerLock.lock()
        let monitor = pathMonitor
        pathMonitor = nil
        pathProofGuard = nil
        pathProofOwnerLock.unlock()
        monitor?.cancel()
    }

    private func currentPathProofGuard() -> NetworkProofGuard? {
        pathProofOwnerLock.lock()
        let guardState = pathProofGuard
        pathProofOwnerLock.unlock()
        return guardState
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        clearPathProofGuard()
        cancelActiveProof()
        if let engine = libboxEngine { libboxEngine = nil; engine.stop() }
        guard let adapter = wireGuardAdapter else { completionHandler(); return }
        wireGuardAdapter = nil
        adapter.stop { _ in completionHandler() }
    }

    override func sleep(completionHandler: @escaping () -> Void) { forwardingChannel?.invalidate(); libboxEngine?.pause(); completionHandler() }
    override func wake() {
        libboxEngine?.wake()
        // Sleep is a path-proof lifetime boundary even when iOS resumes onto a
        // cached NWPath that does not emit a second update. Force this proved
        // tunnel down; strict on-demand may reconnect, but every reconnect must
        // start a new PacketTunnel and re-prove the selected node/public exit.
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
        if let selected = profiles.first(where: { ($0["id"] as? String ?? "") == selectedID }) { return selected }
        return profiles[0]
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
